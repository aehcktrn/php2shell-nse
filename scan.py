#!/usr/bin/env python3
"""Run a scoped PHP2Shell Nmap campaign and reconcile every requested hostname.

Python standard library only. Nmap performs service discovery; the NSE uses
ordinary bounded HTTP requests. Discovery imports local DNS/application exports.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote
import uuid

from report import build_campaign_report, write_campaign_report


VERSION = "0.3.0"
ROOT = Path(__file__).resolve().parent
QUICK_PORTS = "80,443,8000,8008,8080,8081,8443,8888,9000,9443"
MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_TARGETS = 100000
PROFILES = {"rapide": "quick", "quick": "quick", "complet": "complete",
            "complete": "complete", "recontrole": "recheck", "recheck": "recheck"}
HOST_FIELDS = ("hostname", "fqdn", "name", "domain", "host")


class InputError(ValueError):
    """Invalid campaign input; no target should be silently expanded."""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".campaign-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_text(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> str:
    try:
        if path.stat().st_size > max_bytes:
            raise InputError(f"Fichier trop volumineux ({max_bytes // (1024 * 1024)} Mio maximum): {path}")
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise InputError(f"Impossible de lire {path}: {exc}") from exc


def hostname(value: object) -> str:
    if not isinstance(value, str):
        raise InputError("Nom DNS attendu.")
    value = value.strip()
    if value.endswith("."):
        value = value[:-1]
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise InputError("Nom DNS vide ou contenant des espaces/controles.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise InputError("Le lanceur attend des noms DNS; utiliser Nmap directement pour les IP/CIDR.")
    try:
        result = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InputError("Nom DNS/IDN invalide.") from exc
    if len(result) > 253 or not re.search(r"[a-z]", result):
        raise InputError("Nom DNS invalide.")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in result.split(".")):
        raise InputError("Nom DNS invalide: pas d'URL, port, chemin, CIDR ou joker.")
    return result


def lines(path: Path):
    for number, line in enumerate(read_text(path).splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if value:
            yield number, value


def exact_hosts(path: Path) -> list[tuple[str, str]]:
    result = []
    for number, value in lines(path):
        try:
            result.append((hostname(value), f"input:{path.name}:{number}"))
        except InputError as exc:
            raise InputError(f"{path}:{number}: {exc}") from exc
    if len(result) > MAX_TARGETS:
        raise InputError("Trop de cibles (100000 maximum).")
    return result


def is_within(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def scope_rules(scope: Path | None, exclusions: Path | None) -> dict:
    domains = sorted({name for name, _ in exact_hosts(scope)}) if scope else []
    if scope and not domains:
        raise InputError("Le fichier de perimetre autorise est vide.")
    exact, subdomains = set(), set()
    if exclusions:
        for number, value in lines(exclusions):
            try:
                if value.startswith("*."):
                    subdomains.add(hostname(value[2:]))
                else:
                    exact.add(hostname(value))
            except InputError as exc:
                raise InputError(f"{exclusions}:{number}: {exc}") from exc
    return {"mode": "domains" if scope else "exact", "domains": domains,
            "excluded_hosts": sorted(exact), "excluded_subdomains": sorted(subdomains)}


def exclusion_reason(name: str, rules: dict) -> str | None:
    if name in rules["excluded_hosts"] or any(name.endswith("." + suffix)
                                               for suffix in rules["excluded_subdomains"]):
        return "EXCLUDED_BY_OPERATOR"
    if rules["domains"] and not any(is_within(name, domain) for domain in rules["domains"]):
        return "OUTSIDE_AUTHORIZED_DOMAINS"
    return None


def discovery_records(path: Path):
    """Yield raw host, source and optional exclusion reason from local exports."""
    suffix = path.suffix.lower()
    if suffix in (".csv", ".tsv"):
        text = read_text(path)
        try:
            dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel_tab if suffix == ".tsv" else csv.excel
        reader = csv.DictReader(text.splitlines(), dialect=dialect)
        if not reader.fieldnames:
            raise InputError(f"Export CSV sans en-tete: {path}")
        headers = [key.strip().lower() for key in reader.fieldnames]
        if not any(key in headers for key in HOST_FIELDS):
            raise InputError(f"{path}: colonne hostname, fqdn, name, domain ou host attendue.")
        records = ({str(key).strip().lower(): val for key, val in row.items() if key is not None}
                   for row in reader)
        first = 2
    elif suffix == ".json":
        try:
            payload = json.loads(read_text(path))
        except (json.JSONDecodeError, RecursionError) as exc:
            raise InputError(f"Export JSON invalide: {path}") from exc
        records = payload.get("records", payload.get("targets")) if isinstance(payload, dict) else payload
        if not isinstance(records, list):
            raise InputError(f"{path}: liste JSON ou objet records/targets attendu.")
        first = 1
    else:
        for number, value in lines(path):
            yield value, f"inventory:{path.name}:{number}", None
        return
    for number, record in enumerate(records, first):
        source = f"inventory:{path.name}:{number}"
        if isinstance(record, str):
            yield record, source, None
            continue
        if not isinstance(record, dict):
            yield "", source, "INVALID_INVENTORY_RECORD"
            continue
        record = {str(key).lower(): value for key, value in record.items()}
        values = [record[key] for key in HOST_FIELDS if record.get(key)]
        if len(set(str(value) for value in values)) > 1:
            yield str(values[0]), source, "AMBIGUOUS_HOST_FIELDS"
            continue
        value = values[0] if values else ""
        record_type = record.get("type", record.get("record_type"))
        if record_type and str(record_type).upper() not in ("A", "AAAA", "CNAME"):
            yield value, source, "NOT_AN_ADDRESS_RECORD"
            continue
        yield value, source, None


def read_previous(path: Path | None) -> dict | None:
    if path is None:
        return None
    try:
        result = json.loads(read_text(path, 128 * 1024 * 1024))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise InputError("Rapport precedent JSON invalide.") from exc
    if not isinstance(result, dict) or str(result.get("schema_version")) != "1" or not isinstance(result.get("rows"), list):
        raise InputError("Un report.json de campagne schema_version=1 est requis.")
    if any(not isinstance(row, dict) for row in result["rows"]):
        raise InputError("Lignes invalides dans le rapport precedent.")
    return result


def recheck_targets(previous: dict) -> tuple[dict[str, set[int]], dict[str, list[str]]]:
    ports, paths = {}, {}
    for row in previous["rows"]:
        if not isinstance(row, dict) or row.get("inventory_patch_status") == "PATCH_CONFIRMED":
            continue
        raw_name = row.get("hostname")
        if not raw_name:
            continue
        name = hostname(raw_name)
        ports.setdefault(name, set())
        paths.setdefault(name, [])
        if str(row.get("port", "")).isdigit() and 1 <= int(row["port"]) <= 65535:
            ports[name].add(int(row["port"]))
        values = [row.get("path")]
        for key in ("observations", "evidence"):
            observations = row.get(key, [])
            if not isinstance(observations, list):
                raise InputError(f"Tableau {key} invalide dans le rapport precedent.")
            values.extend(item.get("path") for item in observations if isinstance(item, dict))
        for value in values:
            if not isinstance(value, str) or not value:
                continue
            try:
                path = valid_path(value)
            except InputError:
                continue
            if path not in paths[name]:
                paths[name].append(path)
    return ports, paths


def collect_targets(args, rules: dict, previous: dict | None) -> tuple[list[dict], list[dict]]:
    imports = args.discover_from or []
    if imports and not args.scope:
        raise InputError("--discover-from exige --scope pour filtrer les domaines autorises.")
    recheck_ports, recheck_paths = recheck_targets(previous) if args.profile == "recheck" else ({}, {})
    if args.targets:
        inputs = exact_hosts(args.targets)
    elif args.profile == "recheck":
        inputs = [(name, "previous-report") for name in recheck_ports]
    else:
        inputs = []
    candidates = [(name, source, None) for name, source in inputs]
    for path in imports:
        candidates.extend(discovery_records(path))
        if len(candidates) > MAX_TARGETS:
            raise InputError("Trop de candidats (100000 maximum).")
    targets, rejected = {}, []
    for raw, source, reject in candidates:
        try:
            name = hostname(raw)
        except InputError:
            if not reject:
                reject = "INVALID_HOSTNAME"
            name = str(raw)[:253]
        if not reject:
            reject = exclusion_reason(name, rules)
        if not reject and args.profile == "recheck" and name not in recheck_ports:
            reject = "NOT_IN_PREVIOUS_REPORT"
        if reject:
            rejected.append({"hostname": name, "source": source, "reason": reject})
            continue
        target = targets.setdefault(name, {"hostname": name, "sources": [],
                                          "dns_status": "NOT_RESOLVED", "addresses": [], "endpoints": []})
        if source not in target["sources"]:
            target["sources"].append(source)
        if args.profile == "recheck":
            target["recheck_ports"] = sorted(recheck_ports[name])
            target["recheck_paths"] = recheck_paths[name]
    if not targets:
        raise InputError("Aucune cible retenue. Verifier les noms, le perimetre, les exclusions et le rapport precedent.")
    return list(targets.values()), rejected


def valid_path(value: str) -> str:
    if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
            or len(value) > 2048 or any(c.isspace() or ord(c) < 32 for c in value)
            or any(c in value for c in ("\\", "#", '"'))):
        raise InputError("Chemin HTTP local invalide: /chemin attendu, sans espace, fragment ou controle.")
    # NSE's argument parser does not interpret JSON \u escapes. Encode paths as
    # HTTP URI bytes before quoting them in an argument file.
    encoded = quote(value, safe="/:@?&=+$,;~!*'()-._%")
    if len(encoded) > 2048:
        raise InputError("Chemin HTTP encode trop long (2048 caracteres maximum).")
    return encoded


def public_path(value: str) -> str:
    return value.split("?", 1)[0] + ("?[redacted]" if "?" in value else "")


def port_expression(value: str) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise InputError("Liste de ports invalide.")
    selected = set()
    for item in value.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", item):
            raise InputError("Ports attendus: 80,443,8000-8100 (TCP 1 a 65535).")
        numbers = [int(number) for number in item.split("-")]
        start, end = numbers[0], numbers[-1]
        if not 1 <= start <= end <= 65535:
            raise InputError("Ports hors limites (1 a 65535).")
        selected.update(range(start, end + 1))
    ordered = sorted(selected)
    spans, start, end = [], ordered[0], ordered[0]
    for number in ordered[1:]:
        if number == end + 1:
            end = number
        else:
            spans.append(str(start) if start == end else f"{start}-{end}")
            start = end = number
    spans.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(spans)


_RESOLVER_CODE = """
import ipaddress,json,socket,sys
name=sys.argv[1]; result={'addresses': [], 'families': {}}
for label in sys.argv[2].split(','):
    family=socket.AF_INET if label=='ipv4' else socket.AF_INET6
    try:
        values=sorted({str(ipaddress.ip_address(item[4][0])) for item in socket.getaddrinfo(name,None,family,socket.SOCK_STREAM,socket.IPPROTO_TCP) if '%' not in item[4][0]})
        result['addresses'].extend(values)
        result['families'][label]={'status':'RESOLVED' if values else 'NO_ADDRESS','addresses':values}
    except socket.gaierror as exc:
        absent=exc.errno in (socket.EAI_NONAME,getattr(socket,'EAI_NODATA',socket.EAI_NONAME))
        result['families'][label]={'status':'NO_ADDRESS' if absent else 'ERROR','addresses':[]}
        if not absent: result['families'][label]['error']=str(exc)
    except (OSError,ValueError) as exc:
        result['families'][label]={'status':'ERROR','addresses':[],'error':str(exc)}
    print(json.dumps(result),flush=True)
"""


def resolve_target(name: str, families: list[str], timeout: float) -> dict:
    def finish(value: dict) -> dict:
        addresses = list(dict.fromkeys(str(ipaddress.ip_address(item)) for item in value["addresses"]))
        errors = "; ".join(f"{family}: {item.get('error', item['status'])}"
                           for family, item in value["families"].items()
                           if item["status"] in ("ERROR", "TIMEOUT"))
        return {"dns_status": "RESOLVED" if addresses else "DNS_ERROR" if errors else "NO_ADDRESS",
                "addresses": addresses, "dns_families": value["families"],
                "dns_partial": bool(addresses and errors),
                "dns_error": errors, "resolved_at": utcnow()}

    try:
        child = subprocess.run([sys.executable, "-c", _RESOLVER_CODE, name, ",".join(families)],
                               capture_output=True, text=True, timeout=timeout, check=False)
        if child.returncode:
            raise ValueError("Echec du processus de resolution DNS.")
        return finish(json.loads(child.stdout.splitlines()[-1]))
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or b""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        value = {"addresses": [], "families": {}}
        for line in partial.splitlines():
            try:
                candidate = json.loads(line)
                if isinstance(candidate, dict) and "addresses" in candidate and "families" in candidate:
                    value = candidate
            except ValueError:
                pass
        for family in families:
            value["families"].setdefault(family, {"status": "TIMEOUT", "addresses": [], "error": "DNS_TIMEOUT"})
        return finish(value)
    except (ValueError, KeyError, IndexError, OSError) as exc:
        return {"dns_status": "DNS_ERROR", "addresses": [], "dns_error": str(exc), "resolved_at": utcnow()}


def nse_arguments(name: str, paths: list[str], args) -> str:
    # NSE argument files support quoted strings and Lua-style arrays. JSON string
    # escaping is used as data here, never interpolated into a shell command.
    quoted = lambda value: json.dumps(value, ensure_ascii=True)
    values = {"vhost": quoted(name), "path": quoted(paths[0]),
              "paths": "{" + ",".join(quoted(path) for path in paths[1:]) + "}",
              "timeout": str(args.http_timeout), "budget": str(args.http_budget),
              "max_requests": str(args.max_requests), "redirects": str(args.redirects),
              "samples": str(args.samples)}
    return ",\n".join(f"http-php2shell.{key}={value}" for key, value in values.items()) + "\n"


def command_for(nmap: str, endpoint: dict, args_file: Path, prefix: Path, args) -> list[str]:
    command = [nmap, "-sT", "-sV", "-Pn", "-n", "-p", endpoint["ports"],
               "--script", str(ROOT / "http-php2shell.nse"), "--script-args-file", str(args_file),
               "--script-timeout", f"{args.http_budget / 1000 + 2:g}s",
               "--stats-every", "30s", "-oA", str(prefix)]
    if endpoint["family"] == "ipv6":
        command.append("-6")
    if args.nmap_datadir:
        command.extend(["--datadir", str(Path(args.nmap_datadir).resolve())])
    if args.max_rate:
        command.extend(["--max-rate", str(args.max_rate)])
    # Numeric IP from a DNS snapshot; the original DNS name travels only as Host/SNI.
    command.append(str(ipaddress.ip_address(endpoint["ip"])))
    return command


class Processes:
    def __init__(self):
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.active = set()

    @staticmethod
    def terminate(process):
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except OSError:
                pass

    def stop(self):
        self.cancel.set()
        with self.lock:
            active = list(self.active)
        for process in active:
            self.terminate(process)

    def run(self, command: list[str], endpoint: dict, base: Path, timeout: float) -> dict:
        result = dict(endpoint)
        if self.cancel.is_set():
            result.update(status="SKIPPED", error="CAMPAIGN_INTERRUPTED")
            return result
        result["started_at"] = utcnow()
        process = None
        try:
            with (base / result["stdout"]).open("w", encoding="utf-8") as out, (base / result["stderr"]).open("w", encoding="utf-8") as err:
                process = subprocess.Popen(command, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                           start_new_session=(os.name == "posix"))
                with self.lock:
                    self.active.add(process)
                if self.cancel.is_set():
                    self.terminate(process)
                try:
                    code = process.wait(timeout=timeout)
                    result.update(status="COMPLETED" if code == 0 else "FAILED", returncode=code)
                    if code:
                        result["error"] = "NMAP_EXIT_ERROR"
                except subprocess.TimeoutExpired:
                    self.terminate(process)
                    result.update(status="TIMEOUT", returncode=process.poll(), error="TARGET_TIMEOUT")
                if self.cancel.is_set():
                    result.update(status="SKIPPED", error="CAMPAIGN_INTERRUPTED")
        except OSError as exc:
            result.update(status="FAILED", error=str(exc), returncode=None)
        finally:
            if process is not None:
                with self.lock:
                    self.active.discard(process)
            result["finished_at"] = utcnow()
        return result


def bounded_int(low: int, high: int):
    def parse(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("Entier attendu.") from exc
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Valeur attendue de {low} a {high}.")
        return number
    return parse


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    result.add_argument("targets", nargs="?", type=Path, help="Fichier de noms DNS exacts, un par ligne")
    result.add_argument("--version", action="version", version=f"php2shell-scanner {VERSION}")
    result.add_argument("--profile", choices=PROFILES, default="complet", help="Complet, rapide ou recontrole")
    result.add_argument("--scope", type=Path, help="Domaines autorises, sous-domaines inclus")
    result.add_argument("--discover-from", action="append", type=Path, default=[], help="Import local TXT/CSV/TSV/JSON, repetable; exige --scope")
    result.add_argument("--exclude", type=Path, help="Noms exacts ou *.domaine exclus")
    result.add_argument("--output", type=Path, help="Nouveau dossier de campagne (doit etre vide)")
    result.add_argument("--families", choices=("ipv4", "ipv6", "both"), default="both")
    result.add_argument("--ports", help="Liste/ranges TCP explicites; remplace les ports du profil")
    result.add_argument("--workers", type=bounded_int(1, 32), default=4, help="Processus Nmap simultanes")
    result.add_argument("--dns-timeout", type=bounded_int(1, 120), default=15, help="Delai DNS par domaine en secondes")
    result.add_argument("--target-timeout", type=bounded_int(1, 86400), default=900, help="Delai maximal par processus Nmap en secondes")
    result.add_argument("--max-rate", type=bounded_int(1, 100000), help="Plafond Nmap par processus (ne borne pas toutes les requetes HTTP)")
    result.add_argument("--path", default="/", help="Premier chemin HTTP")
    result.add_argument("--paths-file", type=Path, help="Chemins HTTP supplementaires, un par ligne")
    result.add_argument("--http-timeout", type=bounded_int(1, 60000), default=5000, help="Delai socket HTTP en ms")
    result.add_argument("--http-budget", type=bounded_int(1, 60000), default=20000, help="Budget du parcours HTTP en ms")
    result.add_argument("--max-requests", type=bounded_int(1, 20), default=5)
    result.add_argument("--redirects", type=bounded_int(0, 5), default=2, help="Redirections dans la meme origine")
    result.add_argument("--samples", type=bounded_int(1, 3), default=1, help="Observations par chemin, budget commun")
    result.add_argument("--inventory", type=Path, help="Preuves de runtimes authentifies au format JSON")
    result.add_argument("--inventory-max-age-hours", type=bounded_int(1, 8760), default=24)
    result.add_argument("--previous", type=Path, help="report.json precedent pour comparaison/recontrole")
    result.add_argument("--dry-run", action="store_true", help="Resoudre et exporter le plan sans lancer Nmap")
    result.add_argument("--nmap", default=os.environ.get("NMAP", "nmap"), help="Executable Nmap")
    result.add_argument("--nmap-datadir", default=os.environ.get("NMAP_DATADIR"), help="Repertoire des donnees Nmap")
    return result


def run_campaign(args) -> int:
    args.profile = PROFILES[args.profile]
    previous = read_previous(args.previous)
    if args.profile == "recheck" and previous is None:
        raise InputError("Le profil recontrole exige --previous report.json.")
    if not args.targets and not args.discover_from and args.profile != "recheck":
        raise InputError("Fournir un fichier de domaines ou --discover-from avec --scope.")
    paths = [valid_path(args.path)]
    if args.paths_file:
        for line in read_text(args.paths_file).splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                paths.append(valid_path(value))
    paths = list(dict.fromkeys(paths))
    if len(paths) > 11:
        raise InputError("11 chemins maximum (chemin initial + 10 supplementaires); budget de requetes partage.")
    rules = scope_rules(args.scope, args.exclude)
    targets, excluded = collect_targets(args, rules, previous)
    request_paths = {}
    for target in targets:
        selected = list(paths)
        for old_path in target.get("recheck_paths", []):
            if "?" in old_path:
                # Do not invent values that were deliberately removed from the
                # previous report, or silently omit the original suspect route.
                base_path = old_path.split("?", 1)[0]
                if not any("?" in supplied and supplied.split("?", 1)[0] == base_path for supplied in paths):
                    raise InputError(f"{target['hostname']}: parametres de {base_path} masques dans le rapport precedent; fournir le chemin complet via --path ou --paths-file.")
            elif old_path not in selected:
                selected.append(old_path)
        if len(selected) > 11:
            raise InputError("Trop de chemins de recontrole combines (11 maximum); preciser un perimetre plus petit.")
        request_paths[target["hostname"]] = selected
        target["requested_paths"] = [public_path(path) for path in selected]
    default_ports = args.ports or (QUICK_PORTS if args.profile == "quick" else "1-65535")
    if args.profile == "recheck" and not args.ports:
        default_ports = (previous.get("campaign") or {}).get("ports") or "1-65535"
    default_ports = port_expression(default_ports)
    if args.inventory:
        # Validate before any scan, including a malformed evidence file.
        from runtime_inventory import load_inventory
        load_inventory(args.inventory)
    nmap = shutil.which(args.nmap)
    if not args.dry_run and not nmap:
        raise InputError("Nmap est introuvable. Installez Nmap ou renseignez --nmap.")
    campaign_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = (args.output or Path("results") / campaign_id).resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise InputError("Le dossier de sortie doit etre nouveau ou vide; aucun resultat ne sera ecrase.")
    output.mkdir(parents=True, exist_ok=True)
    (output / "raw").mkdir(exist_ok=True)
    families = ["ipv4", "ipv6"] if args.families == "both" else [args.families]
    manifest = {"schema_version": "1", "tool_version": VERSION, "campaign_id": campaign_id,
                "started_at": utcnow(), "finished_at": None, "status": "PLANNED", "profile": args.profile,
                "ports": default_ports, "address_families": families, "scope": rules,
                "http": {"paths": [public_path(path) for path in paths], "max_requests": args.max_requests, "budget_ms": args.http_budget,
                         "timeout_ms": args.http_timeout, "redirects": args.redirects, "samples": args.samples},
                "limits": {"workers": args.workers, "target_timeout_seconds": args.target_timeout,
                           "dns_timeout_seconds": args.dns_timeout, "nmap_max_rate": args.max_rate},
                "targets": targets, "excluded_candidates": excluded, "inputs": []}
    for path in [args.targets, args.scope, args.exclude, args.paths_file, args.inventory, args.previous, *args.discover_from]:
        if path:
            manifest["inputs"].append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    (output / "targets.txt").write_text("\n".join(item["hostname"] for item in targets) + "\n", encoding="utf-8")
    atomic_json(output / "manifest.json", manifest)
    print(f"Campagne {campaign_id}: {len(targets)} domaines; profil {args.profile}; familles {', '.join(families)}.", flush=True)
    print(f"Resultats: {output}", flush=True)
    resolution_interrupted = False
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        resolutions = {executor.submit(resolve_target, target["hostname"], families, args.dns_timeout): target
                       for target in targets}
        try:
            for future in as_completed(resolutions):
                resolutions[future].update(future.result())
        except KeyboardInterrupt:
            resolution_interrupted = True
            print("Interruption de la resolution DNS; conservation du bilan partiel.", file=sys.stderr)
            for future in resolutions:
                future.cancel()
    if resolution_interrupted:
        for target in targets:
            if target["dns_status"] == "NOT_RESOLVED":
                target.update(dns_status="DNS_ERROR", dns_error="CAMPAIGN_INTERRUPTED")
    jobs, index = [], 0
    for target in targets:
        selected_ports = default_ports
        if args.profile == "recheck" and not args.ports and target.get("recheck_ports"):
            selected_ports = port_expression(",".join(str(port) for port in target["recheck_ports"]))
        target_paths = request_paths[target["hostname"]]
        for address in target["addresses"]:
            index += 1
            stem = f"raw/{index:06d}"
            endpoint = {"ip": address, "family": "ipv4" if ipaddress.ip_address(address).version == 4 else "ipv6",
                        "status": "PLANNED", "ports": selected_ports, "xml": stem + ".xml",
                        "stdout": stem + ".stdout.log", "stderr": stem + ".stderr.log",
                        "started_at": None, "finished_at": None, "returncode": None}
            arguments = output / (stem + ".args")
            with os.fdopen(os.open(arguments, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
                stream.write(nse_arguments(target["hostname"], target_paths, args))
            endpoint["command"] = command_for(nmap or args.nmap, endpoint, arguments, output / stem, args)
            target["endpoints"].append(endpoint)
            jobs.append((target, endpoint))
    atomic_json(output / "manifest.json", manifest)
    print(f"DNS: {sum(bool(item['addresses']) for item in targets)}/{len(targets)} domaines resolus; {len(jobs)} cibles nom/IP; {len(excluded)} candidats exclus.", flush=True)
    if args.dry_run:
        for arguments in (output / "raw").glob("*.args"):
            arguments.unlink()
        print("Plan enregistre. Aucun processus Nmap lance.")
        return 130 if resolution_interrupted else 0
    manifest["status"] = "RUNNING"
    atomic_json(output / "manifest.json", manifest)
    control, interrupted = Processes(), resolution_interrupted
    executor = ThreadPoolExecutor(max_workers=args.workers)
    futures = {}
    try:
        for target, endpoint in jobs if not resolution_interrupted else []:
            endpoint["status"] = "RUNNING"
            futures[executor.submit(control.run, endpoint["command"], endpoint, output, args.target_timeout)] = endpoint
        atomic_json(output / "manifest.json", manifest)
        pending, done_count, last_progress = set(futures), 0, time.monotonic()
        while pending:
            ready = [future for future in pending if future.done()]
            for future in ready:
                original = futures[future]
                try:
                    original.update(future.result())
                except Exception as exc:
                    original.update(status="FAILED", error=f"RUNNER_ERROR: {type(exc).__name__}", finished_at=utcnow())
                pending.remove(future)
                done_count += 1
                atomic_json(output / "manifest.json", manifest)
                print(f"[{done_count}/{len(jobs)}] {original['ip']} {original['status']}", flush=True)
            if time.monotonic() - last_progress >= 30:
                print(f"Progression: {done_count}/{len(jobs)} cibles terminees; {len(pending)} en attente/en cours.", flush=True)
                last_progress = time.monotonic()
            if pending:
                time.sleep(0.2)
    except KeyboardInterrupt:
        interrupted = True
        print("Interruption: arret des processus et conservation du bilan partiel.", file=sys.stderr, flush=True)
        control.stop()
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        for future, endpoint in futures.items():
            if future.cancelled():
                endpoint.update(status="SKIPPED", error="CAMPAIGN_INTERRUPTED", finished_at=utcnow())
            elif future.done():
                try:
                    endpoint.update(future.result())
                except Exception:
                    endpoint.update(status="FAILED", error="RUNNER_ERROR", finished_at=utcnow())
        for arguments in (output / "raw").glob("*.args"):
            arguments.unlink()
    failures = any(item["dns_status"] != "RESOLVED" or item.get("dns_partial") for item in targets) or any(
        endpoint["status"] != "COMPLETED" for _, endpoint in jobs)
    manifest["status"] = "PARTIAL" if failures or interrupted else "COMPLETED"
    manifest["finished_at"] = utcnow()
    atomic_json(output / "manifest.json", manifest)
    report = build_campaign_report(manifest, output, inventory=args.inventory, previous=args.previous,
                                   max_inventory_age_hours=args.inventory_max_age_hours)
    if not report["summary"].get("processing_complete", True):
        manifest["status"] = "PARTIAL"
        atomic_json(output / "manifest.json", manifest)
        report["campaign"]["status"] = "PARTIAL"
        failures = True
    write_campaign_report(report, output)
    summary = report["summary"]
    print(f"Domaines: {summary.get('targets_total', len(targets))} retenus, "
          f"{summary.get('targets_resolved', 0)} resolus, {summary.get('targets_attempted', 0)} tentes, "
          f"{summary.get('targets_evaluated', 0)} avec evaluation PHP2Shell.")
    for state, count in summary.get("assessment_counts", {}).items():
        print(f"  {state}: {count}")
    print(f"Rapports: {output / 'report.csv'} et {output / 'report.json'}")
    if args.previous:
        print(f"Comparaison: {output / 'changes.csv'}")
    print("Une absence d'evaluation ou de service observe ne prouve pas la correction.")
    return 130 if interrupted else 2 if failures else 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run_campaign(args)
    except (InputError, OSError, ValueError) as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrompu.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
