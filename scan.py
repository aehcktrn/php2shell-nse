#!/usr/bin/env python3
"""Run a scoped PHP2Shell Nmap campaign and reconcile every requested hostname.

Python standard library only. Nmap performs service discovery; the NSE uses
ordinary bounded HTTP requests. Optional passive crt.sh discovery and local
DNS/application imports feed the same explicit scope checks.
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

from report import (ReportError, build_campaign_report, compact_rows,
                    load_campaign_report, write_campaign_report)
from discovery import discover_root


VERSION = "0.4.4"
ROOT = Path(__file__).resolve().parent
QUICK_PORTS = "80,443,8000,8008,8080,8081,8443,8888,9000,9443"
MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_TARGETS = 100000
MAX_DISCOVERY_ROOTS = 1000
DISCOVERY_RESPONSE_BYTES = 8 * 1024 * 1024
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
        return load_campaign_report(path)
    except ReportError as exc:
        raise InputError(str(exc)) from exc


def recheck_targets(previous: dict) -> tuple[dict[str, set[int]], dict[str, list[str]]]:
    ports, paths = {}, {}
    for row in previous["rows"]:
        if not isinstance(row, dict) or row.get("inventory_patch_status") == "PATCH_CONFIRMED":
            continue
        # A failed passive-source query names a namespace, not a scan target.
        # Rechecking that coverage row could reintroduce an excluded apex.
        if row.get("protocol") == "discovery":
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


def collect_targets(args, rules: dict, previous: dict | None,
                    extra_candidates: list[tuple] | None = None,
                    allow_empty: bool = False) -> tuple[list[dict], list[dict]]:
    imports = args.discover_from or []
    if imports and rules.get("mode") != "domains":
        raise InputError("--discover-from exige --scope ou une decouverte (--discover / --discover-subdomains) pour filtrer les domaines autorises.")
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
    candidates.extend(extra_candidates or [])
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
    if len(targets) > MAX_TARGETS:
        raise InputError("Trop de cibles distinctes (100000 maximum).")
    if not targets and not allow_empty:
        raise InputError("Aucune cible retenue. Verifier les noms, le perimetre, les exclusions et le rapport precedent.")
    return list(targets.values()), rejected


def read_discovery_roots(path: Path | None) -> list[tuple[str, str]]:
    """Read the file selected for discovery as authorized DNS namespaces."""
    if path is None:
        return []
    roots = {}
    for name, source in exact_hosts(path):
        if len(name.split(".")) < 2:
            raise InputError(f"{path}: domaine de decouverte complet attendu (au moins deux labels DNS).")
        roots.setdefault(name, source.replace("input:", "root:", 1))
        if len(roots) > MAX_DISCOVERY_ROOTS:
            raise InputError(f"{MAX_DISCOVERY_ROOTS} domaines racines maximum par campagne.")
    if not roots:
        raise InputError("Le fichier des domaines de decouverte est vide.")
    return list(roots.items())


def prepare_request_paths(targets: list[dict], paths: list[str]) -> dict[str, list[str]]:
    request_paths = {}
    for target in targets:
        selected = list(paths)
        for old_path in target.get("recheck_paths", []):
            if "?" in old_path:
                base_path = old_path.split("?", 1)[0]
                if not any("?" in supplied and supplied.split("?", 1)[0] == base_path for supplied in paths):
                    raise InputError(f"{target['hostname']}: parametres de {base_path} masques dans le rapport precedent; fournir le chemin complet via --path ou --paths-file.")
            elif old_path not in selected:
                selected.append(old_path)
        if len(selected) > 11:
            raise InputError("Trop de chemins de recontrole combines (11 maximum); preciser un perimetre plus petit.")
        request_paths[target["hostname"]] = selected
        target["requested_paths"] = [public_path(path) for path in selected]
    return request_paths


def persist_discovery(output: Path, manifest: dict) -> None:
    atomic_json(output / "discovery.json", manifest["discovery"])
    atomic_json(output / "manifest.json", manifest)


def interrupt_discovery(discovery: dict, roots: list[tuple[str, str]], rules: dict) -> None:
    """Finish the local ledger without issuing any further source requests."""
    finished = utcnow()
    recorded = {query["root"] for query in discovery["queries"]}
    excluded = {item["root"] for item in discovery["skipped_roots"]}
    for query in discovery["queries"]:
        if query["status"] == "RUNNING":
            query.update(status="FAILED", reason_code="CAMPAIGN_INTERRUPTED",
                         processing_complete=False, finished_at=finished)
    for root, _ in roots:
        if root in recorded or root in excluded:
            continue
        if any(root == zone or root.endswith("." + zone) for zone in rules["excluded_subdomains"]):
            discovery["skipped_roots"].append({"root": root, "reason": "SUBDOMAINS_EXCLUDED_BY_OPERATOR"})
        else:
            discovery["queries"].append({"root": root, "source": "crt.sh", "status": "SKIPPED",
                "reason_code": "CAMPAIGN_INTERRUPTED", "processing_complete": False,
                "exhaustive": False, "candidate_count": 0, "started_at": None, "finished_at": finished})
    partial = discovery["candidates"] or any(query["status"] == "COMPLETED" for query in discovery["queries"])
    discovery.update(status="PARTIAL" if partial else "FAILED", reason_code="CAMPAIGN_INTERRUPTED",
                     processing_complete=False, exhaustive=False, finished_at=finished)


def run_discovery(args, roots: list[tuple[str, str]], rules: dict,
                  output: Path, manifest: dict) -> tuple[list[tuple], list[dict], bool]:
    """Keep a query ledger even when the source fails before returning names."""
    discovery = manifest["discovery"]
    started = time.monotonic()
    effective_limit = min(args.discovery_max_names, MAX_TARGETS - len(manifest["targets"]))
    discovery["limits"]["effective_max_names"] = effective_limit
    limit_reason = "NAME_LIMIT_REACHED" if effective_limit == args.discovery_max_names else "TARGET_LIMIT_REACHED"
    names: dict[str, list[str]] = {}
    interrupted, stop_reason, query = False, None, None
    try:
        for root, _ in roots:
            if any(root == zone or root.endswith("." + zone) for zone in rules["excluded_subdomains"]):
                discovery["skipped_roots"].append({"root": root, "reason": "SUBDOMAINS_EXCLUDED_BY_OPERATOR"})
                continue
            query = {"root": root, "source": "crt.sh", "status": "RUNNING",
                     "reason_code": "QUERY_PENDING", "processing_complete": False,
                     "exhaustive": False, "candidate_count": 0,
                     "started_at": None, "finished_at": None}
            discovery["queries"].append(query)
            remaining = args.discovery_budget - (time.monotonic() - started)
            if stop_reason is None and remaining <= 0:
                stop_reason = "DISCOVERY_BUDGET_EXHAUSTED"
            if stop_reason is None and len(names) >= effective_limit:
                stop_reason = limit_reason
            if stop_reason is not None:
                query.update(status="SKIPPED", reason_code=stop_reason, finished_at=utcnow())
                persist_discovery(output, manifest)
                query = None
                continue
            query["started_at"] = utcnow()
            persist_discovery(output, manifest)
            print(f"Decouverte crt.sh: {root}...", flush=True)
            try:
                result = discover_root(root, timeout=min(args.discovery_timeout, remaining),
                                       max_names=effective_limit,
                                       max_bytes=DISCOVERY_RESPONSE_BYTES)
            except Exception as exc:
                result = {"status": "FAILED", "reason_code": "PROVIDER_ERROR", "candidates": [],
                          "processing_complete": False, "finished_at": utcnow(),
                          "error_type": type(exc).__name__}
            query.update({key: value for key, value in result.items() if key != "candidates"})
            query.update(root=root, source="crt.sh", exhaustive=False)
            source = "crt.sh:" + root
            for name in result.get("candidates", []):
                if name not in names:
                    if len(names) >= effective_limit:
                        query.update(status="PARTIAL", reason_code=limit_reason, processing_complete=False)
                        stop_reason = limit_reason
                        break
                    names[name] = [source]
                elif source not in names[name]:
                    names[name].append(source)
            if query.get("reason_code") == "RATE_LIMITED":
                # A rate limit is a request to stop, not an invitation to hammer the
                # same public source with all remaining root names.
                stop_reason = "RATE_LIMITED"
            discovery["candidates_count"] = len(names)
            discovery["candidates"] = [{"hostname": name, "sources": sources}
                                       for name, sources in sorted(names.items())]
            print(f"  {query['status']}: {query.get('candidate_count', 0)} noms; {query.get('reason_code', '')}", flush=True)
            persist_discovery(output, manifest)
            query = None
        complete = all(item.get("status") == "COMPLETED" and item.get("processing_complete", True)
                       for item in discovery["queries"])
        discovery["processing_complete"] = complete
        discovery["status"] = "COMPLETED" if complete else "PARTIAL" if names or any(
            item.get("status") == "COMPLETED" for item in discovery["queries"]) else "FAILED"
        discovery["finished_at"] = utcnow()
        persist_discovery(output, manifest)
    except KeyboardInterrupt:
        interrupted = True
        # A received response may still have been only partly merged or saved.
        if query is not None and query.get("status") == "COMPLETED":
            query.update(status="PARTIAL", reason_code="CAMPAIGN_INTERRUPTED",
                         processing_complete=False, finished_at=utcnow())
        discovery["candidates_count"] = len(names)
        discovery["candidates"] = [{"hostname": name, "sources": sources}
                                   for name, sources in sorted(names.items())]
        interrupt_discovery(discovery, roots, rules)
        print("Interruption de la decouverte; conservation du bilan partiel.", file=sys.stderr)
        persist_discovery(output, manifest)
    candidates = [(name, source, None) for name, sources in sorted(names.items()) for source in sources]
    # Retain bounded provider rejection samples, never as resolvable targets.
    rejected = [item for entry in discovery["queries"] for item in entry.get("excluded_candidates", [])]
    return candidates, rejected, interrupted


def record_discovered_targets(output: Path, manifest: dict, targets: list[dict]) -> None:
    discovery = manifest["discovery"]
    by_name = {target["hostname"]: target for target in targets}
    retained = []
    for candidate in discovery["candidates"]:
        target = by_name.get(candidate["hostname"])
        candidate["retained"] = target is not None
        if target is not None:
            retained.append(candidate["hostname"])
            for key in ("dns_status", "addresses", "dns_error", "dns_partial", "resolved_at"):
                if key in target:
                    candidate[key] = target[key]
    discovery["retained_count"] = len(retained)
    discovery["resolved_count"] = sum(item.get("retained") and item.get("dns_status") == "RESOLVED"
                                      for item in discovery["candidates"])
    discovery["unresolved_count"] = sum(item.get("retained") and item.get("dns_status") in ("NO_ADDRESS", "DNS_ERROR")
                                        for item in discovery["candidates"])
    (output / "discovered.txt").write_text("\n".join(retained) + ("\n" if retained else ""), encoding="utf-8")
    persist_discovery(output, manifest)


def merge_discovered_targets(targets: list[dict], excluded: list[dict], candidates: list[tuple],
                             rules: dict) -> list[dict]:
    """Merge into the validated input snapshot without rereading operator files."""
    by_name = {target["hostname"]: target for target in targets}
    for raw, source, _ in candidates:
        try:
            name = hostname(raw)
            reason = exclusion_reason(name, rules)
        except InputError:
            name, reason = str(raw)[:253], "INVALID_HOSTNAME"
        if reason:
            excluded.append({"hostname": name, "source": source, "reason": reason})
            continue
        target = by_name.setdefault(name, {"hostname": name, "sources": [],
                                          "dns_status": "NOT_RESOLVED", "addresses": [], "endpoints": []})
        if source not in target["sources"]:
            target["sources"].append(source)
    return list(by_name.values())


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
        values=set()
        for item in socket.getaddrinfo(name,None,family,socket.SOCK_STREAM,socket.IPPROTO_TCP):
            if '%' in item[4][0]: continue
            address=ipaddress.ip_address(item[4][0])
            if address.version != (4 if label=='ipv4' else 6): continue
            if address.version == 6 and address.ipv4_mapped is not None: continue
            values.add(str(address))
        values=sorted(values)
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
        cleaned_families = {}
        for family, item in value["families"].items():
            expected_version = 4 if family == "ipv4" else 6
            cleaned = []
            for raw_address in item.get("addresses", []):
                address = ipaddress.ip_address(raw_address)
                if address.version != expected_version or (
                        address.version == 6 and address.ipv4_mapped is not None):
                    continue
                cleaned.append(str(address))
            normalized = dict(item)
            normalized["addresses"] = sorted(dict.fromkeys(cleaned))
            if normalized.get("status") == "RESOLVED" and not normalized["addresses"]:
                normalized["status"] = "NO_ADDRESS"
            cleaned_families[family] = normalized
        value["families"] = cleaned_families
        addresses = list(dict.fromkeys(
            address for item in cleaned_families.values() for address in item["addresses"]))
        errors = "; ".join(f"{family}: {item.get('error', item['status'])}"
                           for family, item in cleaned_families.items()
                           if item["status"] in ("ERROR", "TIMEOUT"))
        return {"dns_status": "RESOLVED" if addresses else "DNS_ERROR" if errors else "NO_ADDRESS",
                "addresses": addresses, "dns_families": cleaned_families,
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
              "timeout": str(args.http_timeout), "budget": str(args.http_budget),
              "max_requests": str(args.max_requests), "redirects": str(args.redirects),
              "samples": str(args.samples)}
    # Nmap parses an empty {} argument as a table with an empty string on
    # some versions. Omit optional paths instead of generating invalid input.
    if paths[1:]:
        values["paths"] = "{" + ",".join(quoted(path) for path in paths[1:]) + "}"
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
    result = argparse.ArgumentParser(
        description="Scanner PHP2Shell : un seul fichier de domaines, scan rapide par defaut.",
        usage="%(prog)s [DOMAINES] [--discover] [options]",
        epilog="Exemples : python3 scan.py domaines.txt ; python3 scan.py domaines.txt --discover. Les fichiers de resultats sont crees automatiquement.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    result.add_argument("targets", nargs="?", type=Path, metavar="DOMAINES", help="Un nom DNS par ligne ; sert aussi de perimetre avec --discover")
    result.add_argument("--version", action="version", version=f"php2shell-scanner {VERSION}")
    discovery_flags = result.add_mutually_exclusive_group()
    discovery_flags.add_argument("--discover", action="store_true", help="Trouver et scanner les sous-domaines de DOMAINES ; enregistrer les noms dans discovered.txt")
    result.add_argument("--profile", choices=PROFILES, default="rapide", help="Rapide (10 ports web), complet (tous les ports TCP) ou recontrole")
    result.add_argument("--scope", type=Path, help="Domaines autorises, sous-domaines inclus")
    discovery_flags.add_argument("--discover-subdomains", type=Path, metavar="ROOTS_FILE", help="Compatibilite : utiliser un fichier de racines distinct a la place de DOMAINES --discover")
    result.add_argument("--discovery-timeout", type=bounded_int(1, 120), default=30, help="Delai total par requete crt.sh en secondes")
    result.add_argument("--discovery-budget", type=bounded_int(1, 3600), default=300, help="Budget total de la phase de decouverte en secondes")
    result.add_argument("--discovery-max-names", type=bounded_int(1, 100000), default=10000, help="Maximum de noms uniques issus de crt.sh par campagne")
    result.add_argument("--discover-from", action="append", type=Path, default=[], help="Import local TXT/CSV/TSV/JSON, repetable; exige --scope ou une decouverte activee")
    result.add_argument("--exclude", type=Path, help="Noms exacts ou *.domaine exclus")
    result.add_argument("--output", type=Path, help="Dossier de campagne facultatif ; sinon creation automatique sous results/")
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
    result.add_argument("--dry-run", action="store_true", help="Decouverte crt.sh si activee, resolution DNS et plan sans lancer Nmap")
    result.add_argument("--nmap", default=os.environ.get("NMAP", "nmap"), help="Executable Nmap")
    result.add_argument("--nmap-datadir", default=os.environ.get("NMAP_DATADIR"), help="Repertoire des donnees Nmap")
    return result


def run_campaign(args) -> int:
    args.profile = PROFILES[args.profile]
    if args.discover and not args.targets:
        raise InputError("--discover exige le fichier de domaines : python3 scan.py domaines.txt --discover.")
    discovery_file = args.targets if args.discover else args.discover_subdomains
    if discovery_file and args.profile == "recheck":
        raise InputError("La decouverte (--discover / --discover-subdomains) est incompatible avec le profil recontrole; utiliser une campagne normale avec --previous.")
    previous = read_previous(args.previous)
    if args.profile == "recheck" and previous is None:
        raise InputError("Le profil recontrole exige --previous report.json.")
    if not args.targets and not args.discover_from and not args.discover_subdomains and args.profile != "recheck":
        raise InputError("Fournir un fichier de domaines : python3 scan.py domaines.txt [--discover].")
    paths = [valid_path(args.path)]
    if args.paths_file:
        for line in read_text(args.paths_file).splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                paths.append(valid_path(value))
    paths = list(dict.fromkeys(paths))
    if len(paths) > 11:
        raise InputError("11 chemins maximum (chemin initial + 10 supplementaires); budget de requetes partage.")
    roots = read_discovery_roots(discovery_file)
    rules = scope_rules(args.scope or discovery_file, args.exclude)
    for root, _ in roots:
        if not any(is_within(root, allowed) for allowed in rules["domains"]):
            raise InputError(f"Domaine de decouverte hors du perimetre autorise: {root}")
    seed_candidates = [(name, source, None) for name, source in roots]
    targets, excluded = collect_targets(args, rules, previous, seed_candidates, allow_empty=bool(roots))
    request_paths = prepare_request_paths(targets, paths)
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
    for path in [args.targets, args.scope, args.discover_subdomains, args.exclude, args.paths_file, args.inventory, args.previous, *args.discover_from]:
        if path:
            manifest["inputs"].append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    (output / "targets.txt").write_text("\n".join(item["hostname"] for item in targets) + "\n", encoding="utf-8")
    atomic_json(output / "manifest.json", manifest)
    print(f"Campagne {campaign_id}: profil {args.profile}; familles {', '.join(families)}.", flush=True)
    if args.profile == "recheck" and not args.ports:
        print(f"Ports TCP: selection par cible du rapport precedent; repli {default_ports}.", flush=True)
    else:
        print(f"Ports TCP demandes par cible: {default_ports}.", flush=True)
    print(f"Resultats: {output}", flush=True)
    resolution_interrupted = False
    discovery_incomplete = False
    if roots:
        manifest["discovery"] = {"schema_version": "1", "enabled": True, "mode": "passive", "source": "crt.sh",
            "roots": [name for name, _ in roots], "queries": [], "skipped_roots": [],
            "started_at": utcnow(), "finished_at": None, "status": "RUNNING",
            "processing_complete": False, "exhaustive": False,
            "candidates": [], "candidates_count": 0, "retained_count": 0,
            "resolved_count": 0, "unresolved_count": 0,
            "limits": {"timeout_seconds": args.discovery_timeout, "budget_seconds": args.discovery_budget,
                       "max_names": args.discovery_max_names, "max_response_bytes": DISCOVERY_RESPONSE_BYTES,
                       "max_roots": MAX_DISCOVERY_ROOTS},
            "limitations": ["Source publique de certificats; inventaire non exhaustif.",
                "Un certificat generique ne revele pas les noms concrets qu'il peut couvrir.",
                "Un nom historique peut ne plus resoudre; une adresse partagee ou un DNS generique ne prouve pas une application distincte."]}
        initial_excluded_count = len(excluded)
        try:
            persist_discovery(output, manifest)
            (output / "discovered.txt").write_text("", encoding="utf-8")
            candidates, source_rejected, resolution_interrupted = run_discovery(args, roots, rules, output, manifest)
            excluded.extend(source_rejected)
            targets = merge_discovered_targets(targets, excluded, candidates, rules)
            manifest["targets"] = targets
            request_paths = prepare_request_paths(targets, paths)
            record_discovered_targets(output, manifest, targets)
        except KeyboardInterrupt:
            resolution_interrupted = True
            discovery = manifest["discovery"]
            interrupt_discovery(discovery, roots, rules)
            # Rebuild only the local merge from the retained ledger. This also
            # recovers an interrupt during persistence without repeating I/O to
            # the public source, DNS or targets, or duplicating exclusions.
            candidates = [(item["hostname"], source, None) for item in discovery["candidates"]
                          for source in item["sources"]]
            del excluded[initial_excluded_count:]
            excluded.extend(item for query in discovery["queries"] for item in query.get("excluded_candidates", []))
            targets = merge_discovered_targets(targets, excluded, candidates, rules)
            manifest["targets"] = targets
            request_paths = prepare_request_paths(targets, paths)
            record_discovered_targets(output, manifest, targets)
            print("Interruption de la decouverte; conservation du bilan partiel.", file=sys.stderr)
        discovery_incomplete = not manifest["discovery"]["processing_complete"]
        print(f"Decouverte: {manifest['discovery']['status']}; {manifest['discovery']['retained_count']} noms retenus; couverture non exhaustive.", flush=True)
        print(f"Noms decouverts: {output / 'discovered.txt'}", flush=True)
    (output / "targets.txt").write_text("\n".join(item["hostname"] for item in targets) + ("\n" if targets else ""), encoding="utf-8")
    atomic_json(output / "manifest.json", manifest)
    if not resolution_interrupted:
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
    if roots:
        try:
            record_discovered_targets(output, manifest, targets)
        except KeyboardInterrupt:
            resolution_interrupted = True
            discovery_incomplete = True
            interrupt_discovery(manifest["discovery"], roots, rules)
            record_discovered_targets(output, manifest, targets)
            print("Interruption de la decouverte; conservation du bilan partiel.", file=sys.stderr)
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
        manifest["finished_at"] = utcnow()
        if discovery_incomplete or resolution_interrupted:
            manifest["status"] = "PARTIAL"
        atomic_json(output / "manifest.json", manifest)
        return 130 if resolution_interrupted else 2 if discovery_incomplete else 0
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
    failures = discovery_incomplete or any(item["dns_status"] != "RESOLVED" or item.get("dns_partial") for item in targets) or any(
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
    results = compact_rows(report["rows"])
    print(f"Resultats par cible ({len(results)} lignes): " + ", ".join(
        f"{verdict}={sum(row['vulnerable'] == verdict for row in results)}"
        for verdict in ("OUI", "NON", "INDETERMINE")))
    print(f"Rapports: {output / 'report.csv'} et {output / 'report.json'}")
    if args.previous:
        print(f"Comparaison: {output / 'changes.csv'}")
    print("OUI/NON selon les versions observees ou les preuves serveur; INDETERMINE si la conclusion reste impossible.")
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
