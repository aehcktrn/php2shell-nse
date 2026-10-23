#!/usr/bin/env python3
"""Run a scoped PHP2Shell Nmap campaign and reconcile every requested hostname.

Python standard library only. Nmap performs service discovery; the NSE uses
ordinary bounded HTTP requests. Optional passive crt.sh discovery and local
DNS/application imports feed the same explicit scope checks.
"""
from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
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
import xml.etree.ElementTree as ET

from report import (ReportError, build_campaign_report, compact_rows,
                    load_campaign_report, parse_report, write_campaign_report)
from discovery import discover_root
from campaign_state import CampaignLock, EventLedger, StateError
from http_campaign import discovery_command, run_collection, _private_write


VERSION = "0.6.1"
ROOT = Path(__file__).resolve().parent
QUICK_PORTS = "80,443,8000,8008,8080,8081,8443,8888,9000,9443"
MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_TARGETS = 100000
MAX_DISCOVERY_ROOTS = 1000
DISCOVERY_RESPONSE_BYTES = 8 * 1024 * 1024
DISCOVERY_CACHE_SCHEMA = "1"
DISCOVERY_BUDGET_FLOOR = 300
DISCOVERY_SECONDS_PER_ROOT = 8
DISCOVERY_BUDGET_CAP = 7200
PROFILES = {"rapide": "quick", "quick": "quick", "complet": "complete",
            "complete": "complete", "recontrole": "recheck", "recheck": "recheck"}
HOST_FIELDS = ("hostname", "fqdn", "name", "domain", "host")


class DiscoveryXML(ET.TreeBuilder):
    """Discard raw response fingerprints before building any saved artifact."""

    def start(self, tag, attributes):
        attributes = {key: value for key, value in attributes.items() if key != "servicefp"}
        return super().start(tag, attributes)


def consume_discovery_xml(stream, captured):
    """Parse bounded chunks in memory; never spool raw Nmap output to disk."""
    parser = ET.XMLParser(target=DiscoveryXML())
    invalid = False
    try:
        while chunk := stream.read(65536):
            if not invalid:
                try:
                    parser.feed(chunk)
                except ET.ParseError:
                    invalid = True
        if not invalid:
            root = parser.close()
            if root.tag == "nmaprun":
                captured["root"] = root
    except (ET.ParseError, OSError, ValueError):
        pass
    finally:
        stream.close()


def automatic_discovery_budget(root_count: int) -> int:
    """Return a useful bounded session budget without operator configuration."""
    return min(DISCOVERY_BUDGET_CAP,
               max(DISCOVERY_BUDGET_FLOOR, root_count * DISCOVERY_SECONDS_PER_ROOT))


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


def read_manifest(path: Path) -> dict:
    """Parse a campaign snapshot without retaining a second full byte copy."""
    try:
        def invalid_constant(value):
            raise ValueError("constante JSON invalide: " + value)
        with Path(path).open("r", encoding="utf-8-sig") as stream:
            return json.load(stream, parse_constant=invalid_constant)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise InputError("Manifeste de reprise JSON invalide.") from exc


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


def discovery_cache_path(output: Path, root: str) -> Path:
    digest = hashlib.sha256(root.encode("ascii")).hexdigest()
    return output.parent / ".discovery-cache" / (digest + ".json")


def load_discovery_cache(output: Path, root: str, max_age_seconds: float) -> tuple[dict, float] | None:
    path = discovery_cache_path(output, root)
    if not path.is_file():
        return None
    try:
        payload = json.loads(read_text(path, DISCOVERY_RESPONSE_BYTES))
        saved_at = datetime.fromisoformat(str(payload["saved_at"]).replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - saved_at).total_seconds()
        result = payload["result"]
        candidates = result["candidates"]
        if (payload.get("schema_version") != DISCOVERY_CACHE_SCHEMA or payload.get("root") != root
                or saved_at.tzinfo is None or age < -300 or age > max_age_seconds
                or not isinstance(result, dict) or result.get("status") != "COMPLETED"
                or not result.get("processing_complete") or not isinstance(candidates, list)
                or len(candidates) > MAX_TARGETS
                or any(hostname(name) != name or not is_within(name, root) for name in candidates)
                or len(candidates) != len(set(candidates))):
            return None
        return result, max(0.0, age)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, RecursionError):
        return None


def save_discovery_cache(output: Path, root: str, result: dict) -> None:
    if result.get("status") != "COMPLETED" or not result.get("processing_complete"):
        return
    cached = {key: value for key, value in result.items()
              if key not in ("started_at", "finished_at", "cache_age_seconds", "cache_mode", "attempts")}
    atomic_json(discovery_cache_path(output, root), {
        "schema_version": DISCOVERY_CACHE_SCHEMA,
        "root": root,
        "saved_at": utcnow(),
        "result": cached,
    })


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


def discovery_progress(discovery: dict) -> dict[str, int]:
    roots = set(discovery.get("roots", []))
    excluded = {item.get("root") for item in discovery.get("skipped_roots", [])
                if isinstance(item, dict)}
    queries = [item for item in discovery.get("queries", []) if isinstance(item, dict)]
    queried = {item.get("root") for item in queries if item.get("started_at")}
    completed = {item.get("root") for item in queries
                 if item.get("status") == "COMPLETED" and item.get("processing_complete") is True}
    failures = {item.get("root") for item in queries
                if item.get("started_at") and item.get("status") != "COMPLETED"}
    return {"roots": len(roots), "queried": len(queried), "remaining": len(roots - completed - excluded),
            "failures": len(failures), "excluded": len(excluded)}


def print_discovery_progress(discovery: dict) -> None:
    counts = discovery_progress(discovery)
    print(f"Racines: {counts['queried']}/{counts['roots']} interrogées; "
          f"{counts['remaining']} à reprendre; {counts['failures']} en échec; "
          f"{counts['excluded']} exclues.", flush=True)


def run_discovery(args, roots: list[tuple[str, str]], rules: dict,
                  output: Path, manifest: dict, ledger: EventLedger | None = None
                  ) -> tuple[list[tuple], list[dict], bool]:
    """Keep a query ledger even when the source fails before returning names."""
    discovery = manifest["discovery"]
    started = time.monotonic()
    effective_limit = min(args.discovery_max_names, MAX_TARGETS - len(manifest["targets"]))
    discovery["limits"]["effective_max_names"] = effective_limit
    limit_reason = "NAME_LIMIT_REACHED" if effective_limit == args.discovery_max_names else "TARGET_LIMIT_REACHED"
    names: dict[str, list[str]] = {
        item["hostname"]: list(item.get("sources", []))
        for item in discovery.get("candidates", [])
        if isinstance(item, dict) and isinstance(item.get("hostname"), str)
    }
    previous_queries = list(discovery.get("queries", []))
    completed_roots = {
        item.get("root") for item in previous_queries
        if isinstance(item, dict) and item.get("status") == "COMPLETED"
        and item.get("processing_complete") is True
    }
    incomplete_history = [item for item in previous_queries
                          if isinstance(item, dict) and item.get("root") not in completed_roots]
    if incomplete_history:
        discovery.setdefault("query_history", []).extend(incomplete_history)
    discovery["queries"] = [item for item in previous_queries
                            if isinstance(item, dict) and item.get("root") in completed_roots]
    interrupted, stop_reason, query = False, None, None
    try:
        for root, _ in roots:
            if root in completed_roots:
                continue
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
                if ledger:
                    ledger.append("discovery", root, {"query": dict(query), "candidates": []})
                query = None
                continue
            query["started_at"] = utcnow()
            print(f"Decouverte crt.sh: {root}...", flush=True)
            fresh_cache = None if args.refresh_discovery else load_discovery_cache(
                output, root, args.discovery_cache_ttl_minutes * 60)
            if fresh_cache is not None:
                result, cache_age = fresh_cache
                result = dict(result)
                result.update(status="COMPLETED", reason_code="CACHE_FRESH",
                              processing_complete=True, started_at=query["started_at"],
                              finished_at=utcnow(), cache_mode="FRESH",
                              cache_age_seconds=round(cache_age, 3), attempts=[])
            else:
                attempts = []
                result = None
                for attempt in range(args.discovery_retries + 1):
                    remaining = args.discovery_budget - (time.monotonic() - started)
                    if remaining <= 0:
                        result = {"status": "FAILED", "reason_code": "DISCOVERY_BUDGET_EXHAUSTED",
                                  "candidates": [], "processing_complete": False,
                                  "finished_at": utcnow()}
                        break
                    try:
                        result = discover_root(root, timeout=min(args.discovery_timeout, remaining),
                                               max_names=effective_limit,
                                               max_bytes=DISCOVERY_RESPONSE_BYTES)
                    except Exception as exc:
                        result = {"status": "FAILED", "reason_code": "PROVIDER_ERROR", "candidates": [],
                                  "processing_complete": False, "finished_at": utcnow(),
                                  "error_type": type(exc).__name__}
                    attempts.append({key: result.get(key) for key in
                                     ("status", "reason_code", "http_status", "started_at", "finished_at")
                                     if result.get(key) is not None})
                    retryable = (result.get("status") == "FAILED"
                                 and result.get("reason_code") == "HTTP_ERROR"
                                 and result.get("http_status") in (502, 503, 504)
                                 and attempt < args.discovery_retries)
                    if not retryable:
                        break
                    base_delay = args.discovery_backoff_seconds * (2 ** attempt)
                    delay = min(60.0, base_delay + random.uniform(0, min(1.0, base_delay * 0.25)))
                    remaining = args.discovery_budget - (time.monotonic() - started)
                    if remaining <= delay:
                        break
                    print(f"  HTTP {result.get('http_status')}; nouvelle tentative dans {delay:.1f}s.",
                          flush=True)
                    time.sleep(delay)
                result["attempts"] = attempts
                if result.get("status") == "COMPLETED" and result.get("processing_complete"):
                    save_discovery_cache(output, root, result)
                elif not args.refresh_discovery:
                    fallback = load_discovery_cache(
                        output, root, args.discovery_cache_max_age_hours * 3600)
                    if fallback is not None:
                        cached, cache_age = fallback
                        failed_attempts = result["attempts"]
                        result = dict(cached)
                        result.update(status="COMPLETED", reason_code="CACHE_FALLBACK",
                                      processing_complete=True, started_at=query["started_at"],
                                      finished_at=utcnow(), cache_mode="FALLBACK",
                                      cache_age_seconds=round(cache_age, 3),
                                      attempts=failed_attempts,
                                      warnings=list(dict.fromkeys(
                                          [*cached.get("warnings", []), "PROVIDER_FAILED_CACHE_USED"])))
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
            if ledger:
                ledger.append("discovery", root, {
                    "query": dict(query), "candidates": list(result.get("candidates", [])),
                })
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
    discovery["unresolved_count"] = sum(item.get("retained") and item.get("dns_status") in ("NO_ADDRESS", "NO_PUBLIC_ADDRESS", "DNS_ERROR")
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
name=sys.argv[1]; allow_non_global=sys.argv[3]=='1'; result={'addresses': [], 'families': {}}
for label in sys.argv[2].split(','):
    family=socket.AF_INET if label=='ipv4' else socket.AF_INET6
    try:
        values=set(); excluded=set()
        for item in socket.getaddrinfo(name,None,family,socket.SOCK_STREAM,socket.IPPROTO_TCP):
            if '%' in item[4][0]: continue
            address=ipaddress.ip_address(item[4][0])
            if address.version != (4 if label=='ipv4' else 6): continue
            if address.version == 6 and address.ipv4_mapped is not None: continue
            if not allow_non_global and not address.is_global:
                excluded.add(str(address)); continue
            values.add(str(address))
        values=sorted(values)
        result['addresses'].extend(values)
        excluded=sorted(excluded)
        result['families'][label]={'status':'RESOLVED' if values else 'NO_PUBLIC_ADDRESS' if excluded else 'NO_ADDRESS','addresses':values}
        if excluded: result['families'][label]['excluded_addresses']=excluded
    except socket.gaierror as exc:
        absent=exc.errno in (socket.EAI_NONAME,getattr(socket,'EAI_NODATA',socket.EAI_NONAME))
        result['families'][label]={'status':'NO_ADDRESS' if absent else 'ERROR','addresses':[]}
        if not absent: result['families'][label]['error']=str(exc)
    except (OSError,ValueError) as exc:
        result['families'][label]={'status':'ERROR','addresses':[],'error':str(exc)}
    print(json.dumps(result),flush=True)
"""


def resolve_target(name: str, families: list[str], timeout: float,
                   allow_non_global: bool = False) -> dict:
    def finish(value: dict) -> dict:
        cleaned_families = {}
        all_excluded = []
        for family, item in value["families"].items():
            expected_version = 4 if family == "ipv4" else 6
            cleaned, excluded = [], []
            for raw_address in item.get("addresses", []):
                address = ipaddress.ip_address(raw_address)
                if address.version != expected_version or (
                        address.version == 6 and address.ipv4_mapped is not None):
                    continue
                if not allow_non_global and not address.is_global:
                    excluded.append(str(address))
                else:
                    cleaned.append(str(address))
            for raw_address in item.get("excluded_addresses", []):
                address = ipaddress.ip_address(raw_address)
                if (address.version == expected_version and not allow_non_global
                        and not address.is_global):
                    excluded.append(str(address))
            normalized = dict(item)
            normalized["addresses"] = sorted(dict.fromkeys(cleaned))
            excluded = sorted(dict.fromkeys(excluded))
            if excluded:
                normalized["excluded_addresses"] = excluded
                all_excluded.extend(excluded)
            if normalized.get("status") == "RESOLVED" and not normalized["addresses"]:
                normalized["status"] = "NO_PUBLIC_ADDRESS" if excluded else "NO_ADDRESS"
            cleaned_families[family] = normalized
        value["families"] = cleaned_families
        addresses = list(dict.fromkeys(
            address for item in cleaned_families.values() for address in item["addresses"]))
        errors = "; ".join(f"{family}: {item.get('error', item['status'])}"
                           for family, item in cleaned_families.items()
                           if item["status"] in ("ERROR", "TIMEOUT"))
        excluded_addresses = sorted(dict.fromkeys(all_excluded))
        status = ("RESOLVED" if addresses else "DNS_ERROR" if errors else
                  "NO_PUBLIC_ADDRESS" if excluded_addresses else "NO_ADDRESS")
        excluded_error = ("Adresses DNS non globales exclues: " + ", ".join(excluded_addresses)
                          if excluded_addresses else "")
        return {"dns_status": status,
                "addresses": addresses, "dns_families": cleaned_families,
                "dns_partial": bool(addresses and errors),
                "dns_error": errors or excluded_error,
                "excluded_addresses": excluded_addresses, "resolved_at": utcnow()}

    try:
        child = subprocess.run([sys.executable, "-c", _RESOLVER_CODE, name, ",".join(families),
                                "1" if allow_non_global else "0"],
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


def resolve_targets_bounded(targets: list[dict], families: list[str], timeout: float,
                            allow_non_global: bool, workers: int, ledger: EventLedger
                            ) -> bool:
    """Resolve with at most ``workers`` submitted futures and durable results."""
    pending_targets = deque(target for target in targets if target.get("dns_status") == "NOT_RESOLVED")
    futures = {}
    interrupted = False

    def resolve(target):
        target.update(dns_status="RUNNING", dns_started_at=utcnow())
        ledger.append("dns", target["hostname"], {
            "dns_status": "RUNNING", "dns_started_at": target["dns_started_at"],
        })
        result = resolve_target(target["hostname"], families, timeout, allow_non_global)
        ledger.append("dns", target["hostname"], result)
        return result

    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        while pending_targets and len(futures) < workers:
            target = pending_targets.popleft()
            futures[executor.submit(resolve, target)] = target
        while futures:
            completed, _ = wait(tuple(futures), return_when=FIRST_COMPLETED)
            for future in completed:
                target = futures.pop(future)
                try:
                    target.update(future.result())
                except Exception as exc:
                    failure = {"dns_status": "DNS_ERROR", "addresses": [],
                               "dns_error": f"RUNNER_ERROR: {type(exc).__name__}", "resolved_at": utcnow()}
                    target.update(failure)
                    ledger.append("dns", target["hostname"], failure)
                if pending_targets:
                    next_target = pending_targets.popleft()
                    futures[executor.submit(resolve, next_target)] = next_target
    except KeyboardInterrupt:
        interrupted = True
        for future in futures:
            future.cancel()
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        if interrupted:
            unfinished = []
            for future, target in futures.items():
                if future.done() and not future.cancelled():
                    try:
                        target.update(future.result())
                        continue
                    except Exception:
                        pass
                unfinished.append(target)
            unfinished.extend(pending_targets)
            for target in unfinished:
                failure = {"dns_status": "DNS_ERROR", "addresses": [],
                           "dns_error": "CAMPAIGN_INTERRUPTED", "resolved_at": utcnow()}
                target.update(failure)
                ledger.append("dns", target["hostname"], failure)
    return interrupted


def nse_arguments(name: str, paths: list[str], args) -> str:
    # NSE argument files support quoted strings and Lua-style arrays. JSON string
    # escaping is used as data here, never interpolated into a shell command.
    quoted = lambda value: json.dumps(value, ensure_ascii=False)
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
    if getattr(args, "managed_http", True):
        return discovery_command(nmap, endpoint, prefix, args)
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


def collection_inputs(output: Path, manifest: dict, raw_paths: dict | None = None) -> dict:
    """Keep replayable query values in a private companion, never in reports."""
    private = output / "state" / "private"
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private, 0o700)
    path = private / "inputs.json"
    if raw_paths is not None:
        _private_write(path, json.dumps(raw_paths, ensure_ascii=True))
        return raw_paths
    if path.is_file() and not path.is_symlink():
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise InputError("Entrées HTTP privées invalides ; paramètres non rejoués.") from exc
        if not isinstance(stored, dict):
            raise InputError("Entrées HTTP privées invalides.")
        for target in manifest["targets"]:
            values = stored.get(target["hostname"])
            expected = target.get("requested_paths") or manifest["http"]["paths"]
            defaults = stored.get("__default__")
            if values is None and isinstance(defaults, list) and list(map(public_path, defaults)) == expected:
                values = defaults
                stored[target["hostname"]] = values
            if values is None and not any("?[redacted]" in value for value in expected):
                continue
            if (not isinstance(values, list) or not values
                    or any(not isinstance(value, str) for value in values)
                    or [public_path(valid_path(value)) for value in values] != expected):
                raise InputError("Entrées HTTP privées incohérentes avec la campagne.")
        return stored
    values = {target["hostname"]: target.get("requested_paths") or manifest["http"]["paths"]
              for target in manifest["targets"]}
    if any("?[redacted]" in path for paths in values.values() for path in paths):
        raise InputError("Paramètres HTTP expurgés et entrées privées absentes ; nouvelle campagne nécessaire.")
    return values


def collect_http(manifest, output, args, control, ledger, request_paths=None):
    print("Collecte HTTP : contrôles de base, redirections exactes, puis liens facultatifs ; quotas communs par service.", flush=True)
    try:
        return run_collection(manifest, output, args, control, ledger,
                              resolve=resolve_target, validate_hostname=hostname, exclusion=exclusion_reason,
                              save=atomic_json, endpoint_identity=endpoint_task_id,
                              request_paths=collection_inputs(output, manifest, request_paths))
    except KeyboardInterrupt:
        # DNS and discovery of a newly authorized redirect name run outside
        # phase worker batches too. Preserve a partial report at that boundary.
        control.stop()
        manifest.setdefault("http_collection", {})["status"] = "INTERRUPTED"
        return True


def endpoint_task_id(name: str, endpoint: dict, paths: list[str], http: dict) -> str:
    identity = {
        "hostname": name, "ip": str(ipaddress.ip_address(endpoint["ip"])),
        "family": endpoint["family"], "ports": port_expression(endpoint["ports"]),
        "paths": paths,
        "http": {key: http[key] for key in
                 ("timeout_ms", "budget_ms", "max_requests", "redirects", "samples")},
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def run_endpoint_jobs(jobs: list[tuple[dict, dict]], *, workers: int, workers_per_ip: int,
                      control: "Processes", output: Path, timeout: float,
                      ledger: EventLedger, max_attempts: int, progress_label: str = "Progression",
                      measurements: dict | None = None,
                      ) -> tuple[bool, int]:
    """Run a bounded fair queue and durably record actual task transitions."""
    queues: dict[str, deque] = {}
    for target, endpoint in jobs:
        queues.setdefault(endpoint["ip"], deque()).append((target, endpoint))
    ip_order = deque(queues)
    active_by_ip = {ip: 0 for ip in queues}
    futures = {}
    interrupted, done_count = False, 0
    started_at = time.monotonic()
    positive_targets = set()
    progress_interval = max(100, max(1, len(jobs) // 100))
    max_submitted = 0

    def current_statuses() -> dict[str, int]:
        statuses = {}
        for _, endpoint in jobs:
            status = endpoint.get("status", "PLANNED")
            statuses[status] = statuses.get(status, 0) + 1
        return statuses

    def write_progress() -> None:
        atomic_json(output / "progress.json", {
            "schema_version": "1", "provisional": True, "updated_at": utcnow(),
            "tasks_total": len(jobs), "tasks_completed": done_count,
            "status_counts": current_statuses(), "positive_targets": sorted(positive_targets),
            "note": "Résultat provisoire: aucun NON n'est publié avant la consolidation finale.",
        })

    def print_progress() -> None:
        statuses = current_statuses()
        queued = sum(len(queue) for queue in queues.values())
        elapsed = max(time.monotonic() - started_at, 0.001)
        summary = ", ".join(f"{status}={count}" for status, count in sorted(statuses.items()))
        print(f"{progress_label}: {done_count}/{len(jobs)} couples nom/IP terminés; "
              f"{len(futures)} actifs; {queued} en attente; {done_count / elapsed:.2f}/s; "
              f"{summary}.", flush=True)

    def execute(target: dict, endpoint: dict) -> dict:
        attempts = list(endpoint.get("attempts", []))
        if len(attempts) >= max_attempts:
            endpoint.update(status="FAILED", error="ATTEMPT_LIMIT_REACHED", finished_at=utcnow())
            ledger.append("endpoint", endpoint["task_id"], dict(endpoint))
            return dict(endpoint)
        attempt = {"number": len(attempts) + 1, "status": "RUNNING",
                   "started_at": utcnow(), "finished_at": None, "error": None}
        attempts.append(attempt)
        endpoint.update(status="RUNNING", started_at=attempt["started_at"], finished_at=None,
                        error=None, returncode=None, attempts=attempts)
        ledger.append("endpoint", endpoint["task_id"], dict(endpoint))
        try:
            result = control.run(endpoint["command"], endpoint, output, timeout)
        except Exception as exc:
            result = {**endpoint, "status": "FAILED", "returncode": None,
                      "error": f"RUNNER_ERROR: {type(exc).__name__}", "finished_at": utcnow()}
        attempt.update(status=result.get("status", "FAILED"), finished_at=result.get("finished_at") or utcnow(),
                       error=result.get("error"), returncode=result.get("returncode"))
        result["attempts"] = attempts
        ledger.append("endpoint", endpoint["task_id"], result)
        return result

    def mark_interrupted(endpoint: dict) -> None:
        attempts = list(endpoint.get("attempts", []))
        if attempts and attempts[-1].get("status") == "RUNNING":
            attempts[-1].update(status="INTERRUPTED", finished_at=utcnow(),
                                error="CAMPAIGN_INTERRUPTED")
        endpoint.update(status="INTERRUPTED", error="CAMPAIGN_INTERRUPTED",
                        finished_at=utcnow(), attempts=attempts)
        ledger.append("endpoint", endpoint["task_id"], dict(endpoint))

    def submit_available(executor) -> None:
        nonlocal ip_order, max_submitted
        while len(futures) < workers and ip_order:
            submitted = False
            for _ in range(len(ip_order)):
                ip = ip_order.popleft()
                queue = queues[ip]
                if queue and active_by_ip[ip] < workers_per_ip:
                    target, endpoint = queue.popleft()
                    active_by_ip[ip] += 1
                    future = executor.submit(execute, target, endpoint)
                    futures[future] = (target, endpoint, ip)
                    max_submitted = max(max_submitted, len(futures))
                    submitted = True
                if queue:
                    ip_order.append(ip)
                if len(futures) >= workers:
                    break
            if not submitted:
                break

    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        write_progress()
        submit_available(executor)
        last_progress = time.monotonic()
        while futures:
            completed, _ = wait(tuple(futures), timeout=1, return_when=FIRST_COMPLETED)
            for future in completed:
                target, endpoint, ip = futures.pop(future)
                active_by_ip[ip] -= 1
                try:
                    endpoint.update(future.result())
                except KeyboardInterrupt:
                    mark_interrupted(endpoint)
                    raise
                except Exception as exc:
                    endpoint.update(status="FAILED", error=f"RUNNER_ERROR: {type(exc).__name__}",
                                    finished_at=utcnow())
                    ledger.append("endpoint", endpoint["task_id"], dict(endpoint))
                done_count += 1
                if endpoint.get("status") == "COMPLETED" and endpoint.get("returncode") == 0:
                    try:
                        rows = parse_report(_campaign_file(output, endpoint.get("xml"), ".xml"))
                        for row in rows:
                            row["hostname"] = target["hostname"]
                        if any(row["vulnerable"] == "OUI" for row in compact_rows(rows)):
                            positive_targets.add(target["hostname"])
                    except (InputError, ReportError):
                        pass
                if done_count % progress_interval == 0 or done_count == len(jobs):
                    print_progress()
                    write_progress()
            submit_available(executor)
            if time.monotonic() - last_progress >= 30:
                print_progress()
                write_progress()
                last_progress = time.monotonic()
    except KeyboardInterrupt:
        interrupted = True
        control.stop()
    finally:
        if interrupted:
            for future in futures:
                future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        if interrupted:
            for future, (_, endpoint, _) in futures.items():
                if not future.cancelled() and future.done():
                    try:
                        endpoint.update(future.result())
                        done_count += 1
                        continue
                    except BaseException:
                        pass
                mark_interrupted(endpoint)
            for queue in queues.values():
                for _, endpoint in queue:
                    mark_interrupted(endpoint)
            write_progress()
    if measurements is not None:
        elapsed = max(time.monotonic() - started_at, 0.0)
        measurements.update({
            "tasks_total": len(jobs), "tasks_completed": done_count,
            "max_submitted_unfinished": max_submitted,
            "elapsed_seconds": round(elapsed, 3),
            "throughput_tasks_per_second": round(done_count / elapsed, 3) if elapsed else None,
            "status_counts": current_statuses(),
        })
    return interrupted, done_count


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
        reader = None
        captured = {}
        sanitized_discovery = "-oX" in command and command[command.index("-oX") + 1] == "-"
        try:
            with (base / result["stdout"]).open("w", encoding="utf-8") as out, (base / result["stderr"]).open("w", encoding="utf-8") as err:
                process = subprocess.Popen(command,
                                           stdout=subprocess.PIPE if sanitized_discovery else out,
                                           stderr=subprocess.DEVNULL if sanitized_discovery else err,
                                           stdin=subprocess.DEVNULL,
                                           start_new_session=(os.name == "posix"))
                if sanitized_discovery:
                    reader = threading.Thread(target=consume_discovery_xml, args=(process.stdout, captured), daemon=True)
                    reader.start()
                    out.write("Service discovery XML sanitized; raw response fingerprints are not retained.\n")
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
                if reader is not None:
                    reader.join()
                    root = captured.get("root")
                    if root is not None:
                        ET.ElementTree(root).write(base / result["xml"], encoding="utf-8", xml_declaration=True)
                    elif result["status"] == "COMPLETED":
                        result.update(status="FAILED", error="INVALID_DISCOVERY_XML")
                    if result["status"] != "COMPLETED":
                        err.write("Nmap discovery did not complete; raw diagnostic output is not retained.\n")
        except KeyboardInterrupt:
            self.stop()
            if reader is not None:
                reader.join()
            raise
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
    result.add_argument("--discovery-budget", type=bounded_int(1, 86400),
                        help="Budget de cette session de découverte; automatique selon le nombre de racines")
    result.add_argument("--discovery-max-names", type=bounded_int(1, 100000), default=10000, help="Maximum de noms uniques issus de crt.sh par campagne")
    result.add_argument("--discovery-retries", type=bounded_int(0, 5), default=2,
                        help="Nouvelles tentatives pour les erreurs transitoires HTTP 502/503/504")
    result.add_argument("--discovery-backoff-seconds", type=bounded_int(1, 60), default=5,
                        help="Attente initiale avant nouvelle tentative crt.sh (backoff exponentiel)")
    result.add_argument("--discovery-cache-ttl-minutes", type=bounded_int(1, 1440), default=30,
                        help="Cooldown : reutiliser directement un resultat crt.sh recent")
    result.add_argument("--discovery-cache-max-age-hours", type=bounded_int(1, 168), default=24,
                        help="Age maximal du cache de secours si crt.sh reste indisponible")
    result.add_argument("--refresh-discovery", action="store_true",
                        help="Ignorer le cache et interroger crt.sh immediatement")
    result.add_argument("--discover-from", action="append", type=Path, default=[], help="Import local TXT/CSV/TSV/JSON, repetable; exige --scope ou une decouverte activee")
    result.add_argument("--exclude", type=Path, help="Noms exacts ou *.domaine exclus")
    result.add_argument("--output", type=Path, help="Dossier de campagne facultatif ; sinon creation automatique sous results/")
    result.add_argument("--families", choices=("ipv4", "ipv6", "both"), default="both")
    result.add_argument("--allow-non-global", action="store_true",
                        help="Laboratoire uniquement : autoriser les IP privées/réservées résolues")
    result.add_argument("--ports", help="Liste/ranges TCP explicites; remplace les ports du profil")
    result.add_argument("--workers", type=bounded_int(1, 32), default=4, help="Processus Nmap simultanes")
    result.add_argument("--workers-per-ip", type=bounded_int(1, 32), default=2,
                        help="Processus Nmap simultanés maximum vers une même adresse IP")
    result.add_argument("--max-attempts", type=bounded_int(1, 10), default=3,
                        help="Tentatives cumulées maximum par couple nom/IP lors des reprises")
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
    result.add_argument("--resume", type=Path, metavar="CAMPAIGN_DIR",
                        help="Reprendre les endpoints incomplets d'une campagne existante")
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
    # The simple launcher must assess both request targets explicitly. The NSE
    # fallback alone is insufficient: once / advertises a usable version it
    # can stop before /index.php, leaving an HTTP-to-HTTPS redirect to that
    # exact path uncovered in the campaign-level verdict.
    if paths[0] == "/" and "/index.php" not in paths and len(paths) < 11:
        paths.insert(1, "/index.php")
    roots = read_discovery_roots(discovery_file)
    discovery_budget_automatic = args.discovery_budget is None
    if roots and args.discovery_budget is None:
        args.discovery_budget = automatic_discovery_budget(len(roots))
    elif args.discovery_budget is None:
        args.discovery_budget = DISCOVERY_BUDGET_FLOOR
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
    campaign_lock = CampaignLock(output)
    campaign_lock.acquire()
    ledger = EventLedger(output)
    (output / "raw").mkdir(exist_ok=True)
    metrics = {"discovery_seconds": 0.0, "dns_seconds": 0.0, "nmap_seconds": 0.0,
               "report_seconds": 0.0}
    families = ["ipv4", "ipv6"] if args.families == "both" else [args.families]
    manifest = {"schema_version": "1", "tool_version": VERSION, "campaign_id": campaign_id,
                "started_at": utcnow(), "finished_at": None, "status": "PLANNED", "profile": args.profile,
                "ports": default_ports, "address_families": families, "scope": rules,
                "http": {"paths": [public_path(path) for path in paths], "max_requests": args.max_requests, "budget_ms": args.http_budget,
                         "timeout_ms": args.http_timeout, "redirects": args.redirects, "samples": args.samples},
                "limits": {"workers": args.workers, "workers_per_ip": args.workers_per_ip,
                           "max_attempts": args.max_attempts, "target_timeout_seconds": args.target_timeout,
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
        phase_started = time.monotonic()
        budget_mode = "automatique" if discovery_budget_automatic else "explicite"
        print(f"Budget de découverte {budget_mode}: {args.discovery_budget}s pour {len(roots)} racines.",
              flush=True)
        manifest["discovery"] = {"schema_version": "1", "enabled": True, "mode": "passive", "source": "crt.sh",
            "roots": [name for name, _ in roots], "queries": [], "skipped_roots": [],
            "started_at": utcnow(), "finished_at": None, "status": "RUNNING",
            "processing_complete": False, "exhaustive": False,
            "candidates": [], "candidates_count": 0, "retained_count": 0,
            "resolved_count": 0, "unresolved_count": 0,
            "limits": {"timeout_seconds": args.discovery_timeout, "budget_seconds": args.discovery_budget,
                       "budget_automatic": discovery_budget_automatic,
                       "max_names": args.discovery_max_names, "max_response_bytes": DISCOVERY_RESPONSE_BYTES,
                       "max_roots": MAX_DISCOVERY_ROOTS, "retries": args.discovery_retries,
                       "backoff_seconds": args.discovery_backoff_seconds,
                       "cache_ttl_minutes": args.discovery_cache_ttl_minutes,
                       "cache_max_age_hours": args.discovery_cache_max_age_hours},
            "limitations": ["Source publique de certificats; inventaire non exhaustif.",
                "Un certificat generique ne revele pas les noms concrets qu'il peut couvrir.",
                "Un nom historique peut ne plus resoudre; une adresse partagee ou un DNS generique ne prouve pas une application distincte."]}
        initial_excluded_count = len(excluded)
        try:
            persist_discovery(output, manifest)
            (output / "discovered.txt").write_text("", encoding="utf-8")
            candidates, source_rejected, resolution_interrupted = run_discovery(
                args, roots, rules, output, manifest, ledger)
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
        print_discovery_progress(manifest["discovery"])
        print(f"Noms decouverts: {output / 'discovered.txt'}", flush=True)
        metrics["discovery_seconds"] = round(time.monotonic() - phase_started, 3)
    (output / "targets.txt").write_text("\n".join(item["hostname"] for item in targets) + ("\n" if targets else ""), encoding="utf-8")
    atomic_json(output / "manifest.json", manifest)
    phase_started = time.monotonic()
    if not resolution_interrupted:
        resolution_interrupted = resolve_targets_bounded(
            targets, families, args.dns_timeout, args.allow_non_global, args.workers, ledger)
        if resolution_interrupted:
            print("Interruption de la resolution DNS; conservation du bilan partiel.", file=sys.stderr)
    metrics["dns_seconds"] = round(time.monotonic() - phase_started, 3)
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
    collection_inputs(output, manifest, {**request_paths, "__default__": paths})
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
                        "started_at": None, "finished_at": None, "returncode": None,
                        "attempts": []}
            endpoint["task_id"] = endpoint_task_id(
                target["hostname"], endpoint, target["requested_paths"], manifest["http"])
            arguments = output / "state" / "private" / f"discovery-{index:06d}.args"
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
        campaign_lock.release()
        return 130 if resolution_interrupted else 2 if discovery_incomplete else 0
    manifest["status"] = "RUNNING"
    atomic_json(output / "manifest.json", manifest)
    control, interrupted = Processes(), resolution_interrupted
    phase_started = time.monotonic()
    scheduler_metrics = {}
    if not resolution_interrupted:
        interrupted, _ = run_endpoint_jobs(
            jobs, workers=args.workers, workers_per_ip=min(args.workers_per_ip, args.workers),
            control=control, output=output, timeout=args.target_timeout, ledger=ledger,
            max_attempts=args.max_attempts, measurements=scheduler_metrics)
        if interrupted:
            print("Interruption: arrêt des processus et conservation du bilan partiel.",
                  file=sys.stderr, flush=True)
    for arguments in (output / "raw").glob("*.args"):
        arguments.unlink()
    metrics["nmap_seconds"] = round(time.monotonic() - phase_started, 3)
    metrics["scheduler"] = scheduler_metrics
    if not interrupted:
        interrupted = collect_http(manifest, output, args, control, ledger)
    failures = discovery_incomplete or any(item["dns_status"] != "RESOLVED" or item.get("dns_partial") for item in targets) or any(
        endpoint["status"] != "COMPLETED" for _, endpoint in jobs)
    manifest["status"] = "PARTIAL" if failures or interrupted else "COMPLETED"
    manifest["finished_at"] = utcnow()
    manifest["metrics"] = {**metrics, "state_events": ledger.events_written,
                           "state_bytes_written": ledger.bytes_written}
    atomic_json(output / "manifest.json", manifest)
    phase_started = time.monotonic()
    report = build_campaign_report(manifest, output, inventory=args.inventory, previous=args.previous,
                                   max_inventory_age_hours=args.inventory_max_age_hours)
    if not report["summary"].get("processing_complete", True):
        manifest["status"] = "PARTIAL"
        atomic_json(output / "manifest.json", manifest)
        report["campaign"]["status"] = "PARTIAL"
        failures = True
    write_campaign_report(report, output)
    atomic_json(output / "progress.json", {
        "schema_version": "1", "provisional": False, "updated_at": utcnow(),
        "campaign_status": manifest["status"], "report": "report.json",
    })
    metrics["report_seconds"] = round(time.monotonic() - phase_started, 3)
    manifest["metrics"].update(metrics)
    atomic_json(output / "manifest.json", manifest)
    summary = report["summary"]
    print(f"Domaines: {summary.get('targets_total', len(targets))} retenus, "
          f"{summary.get('targets_resolved', 0)} resolus, {summary.get('targets_attempted', 0)} tentes, "
          f"{summary.get('targets_evaluated', 0)} avec evaluation PHP2Shell.")
    results = compact_rows(report["rows"])
    display_verdicts = (("VULNERABLE", "OUI"), ("NON-VULNERABLE", "NON"),
                        ("INDETERMINE", "INDETERMINE"))
    print(f"Resultats par cible ({len(results)} lignes): " + ", ".join(
        f"{label}={sum(row['vulnerable'] == stored for row in results)}"
        for label, stored in display_verdicts))
    print(f"Rapports: {output / 'report.csv'} et {output / 'report.json'}")
    print(f"Arborescence: {output / 'report-tree.txt'}")
    if args.previous:
        print(f"Comparaison: {output / 'changes.csv'}")
    print("VULNERABLE/NON-VULNERABLE selon les versions observees ou les preuves serveur; "
          "INDETERMINE si la conclusion reste impossible.")
    campaign_lock.release()
    return 130 if interrupted else 2 if failures else 0


def _campaign_file(base: Path, relative: object, suffix: str | None = None) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise InputError("Chemin de campagne invalide dans le manifeste.")
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise InputError("Chemin de campagne hors du dossier de reprise.") from exc
    if suffix is not None and candidate.suffix != suffix:
        raise InputError("Extension de fichier de campagne invalide.")
    return candidate


def _completed_endpoint_is_reusable(output: Path, endpoint: dict, expected_hostname: str | None = None) -> bool:
    if endpoint.get("status") != "COMPLETED" or endpoint.get("returncode") != 0:
        return False
    try:
        xml = _campaign_file(output, endpoint.get("xml"), ".xml")
        rows = parse_report(xml)
        if not rows or any(row.get("ip") != endpoint.get("ip") for row in rows):
            return False
        if expected_hostname and any(
                row.get("row_type") == "ASSESSMENT"
                and row.get("hostname") not in ("", expected_hostname, endpoint.get("ip"))
                for row in rows):
            return False
        return True
    except (InputError, ReportError):
        return False


def _legacy_http_cost_unknown(manifest: dict, endpoint: dict) -> bool:
    """Old combined Nmap/NSE attempts cannot recover a failed GET count."""
    command = endpoint.get("command")
    if (isinstance(command, list) and command and all(isinstance(argument, str) for argument in command)
            and not any(argument.startswith("--script") or argument in ("-sC", "-A")
                        or "http-php2shell" in argument for argument in command)):
        # A migrated campaign retains its original version label. Newly added
        # discovery-only endpoints in that campaign still have a known zero
        # collection cost; the explicit command distinguishes them safely.
        return False
    match = re.match(r"^(\d+)\.(\d+)", str(manifest.get("tool_version", "")))
    if match is not None:
        legacy = tuple(map(int, match.groups())) < (0, 6)
    else:
        legacy = isinstance(command, list) and any(
            "http-php2shell" in argument for argument in command if isinstance(argument, str))
    attempted = (bool(endpoint.get("attempts")) or bool(endpoint.get("started_at"))
                 or endpoint.get("returncode") is not None
                 or endpoint.get("status") in ("RUNNING", "INTERRUPTED", "FAILED", "TIMEOUT"))
    return legacy and attempted


def resume_campaign(args) -> int:
    """Resume only unfinished endpoints from a persisted, validated snapshot."""
    if args.targets or args.discover or args.discover_subdomains or args.discover_from or args.output:
        raise InputError("--resume s'utilise seul, avec seulement les options d'execution/inventaire necessaires.")
    output = args.resume.resolve()
    campaign_lock = CampaignLock(output)
    campaign_lock.acquire()
    ledger = EventLedger(output)
    manifest_path = output / "manifest.json"
    manifest = read_manifest(manifest_path)
    if (not isinstance(manifest, dict) or str(manifest.get("schema_version")) != "1"
            or not isinstance(manifest.get("targets"), list)
            or not isinstance(manifest.get("http"), dict)):
        raise InputError("Manifeste de reprise invalide.")
    manifest = ledger.replay(manifest)
    nmap = shutil.which(args.nmap)
    if not nmap:
        raise InputError("Nmap est introuvable. Installez Nmap ou renseignez --nmap.")
    http = manifest["http"]
    try:
        args.http_timeout = int(http["timeout_ms"])
        args.http_budget = int(http["budget_ms"])
        args.max_requests = int(http["max_requests"])
        args.redirects = int(http["redirects"])
        args.samples = int(http["samples"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InputError("Parametres HTTP absents ou invalides dans le manifeste de reprise.") from exc
    saved_http_inputs = collection_inputs(output, manifest)
    default_raw_paths = saved_http_inputs.get("__default__") or http.get("paths") or ["/"]
    if (not isinstance(default_raw_paths, list) or not default_raw_paths
            or any("?[redacted]" in str(path) for path in default_raw_paths)):
        raise InputError("Paramètres HTTP expurgés ou invalides; lancer une nouvelle campagne avec les chemins complets.")
    for path in default_raw_paths:
        valid_path(path)

    discovery_interrupted = False
    discovery = manifest.get("discovery")
    if isinstance(discovery, dict) and discovery.get("enabled") and not discovery.get("processing_complete"):
        roots = [(hostname(root), "resume") for root in discovery.get("roots", [])]
        rules = manifest.get("scope")
        if not roots or not isinstance(rules, dict):
            raise InputError("État de découverte incomplet ou invalide dans la campagne.")
        limits = discovery.get("limits", {})
        args.discovery_timeout = int(limits.get("timeout_seconds", args.discovery_timeout))
        args.discovery_max_names = int(limits.get("max_names", args.discovery_max_names))
        args.discovery_retries = int(limits.get("retries", args.discovery_retries))
        args.discovery_backoff_seconds = int(limits.get("backoff_seconds", args.discovery_backoff_seconds))
        args.discovery_cache_ttl_minutes = int(limits.get("cache_ttl_minutes", args.discovery_cache_ttl_minutes))
        args.discovery_cache_max_age_hours = int(
            limits.get("cache_max_age_hours", args.discovery_cache_max_age_hours))
        completed = {query.get("root") for query in discovery.get("queries", [])
                     if isinstance(query, dict) and query.get("status") == "COMPLETED"
                     and query.get("processing_complete") is True}
        remaining_roots = max(1, len(roots) - len(completed))
        if args.discovery_budget is None:
            args.discovery_budget = automatic_discovery_budget(remaining_roots)
        print(f"Reprise de la découverte: {remaining_roots} racines restantes; "
              f"nouveau budget de session {args.discovery_budget}s.", flush=True)
        candidates, source_rejected, discovery_interrupted = run_discovery(
            args, roots, rules, output, manifest, ledger)
        print_discovery_progress(manifest["discovery"])
        excluded = manifest.setdefault("excluded_candidates", [])
        excluded.extend(source_rejected)
        manifest["targets"] = merge_discovered_targets(
            manifest["targets"], excluded, candidates, rules)
        for target in manifest["targets"]:
            target.setdefault("requested_paths", list(default_raw_paths))
        record_discovered_targets(output, manifest, manifest["targets"])

    families = manifest.get("address_families")
    if (not isinstance(families, list) or not families
            or any(family not in ("ipv4", "ipv6") for family in families)):
        raise InputError("Familles IP absentes ou invalides dans le manifeste de reprise.")
    for target in manifest["targets"]:
        if target.get("dns_status") in ("NOT_RESOLVED", "RUNNING", "DNS_ERROR"):
            target.update(dns_status="NOT_RESOLVED", addresses=[])
    if not discovery_interrupted:
        dns_interrupted = resolve_targets_bounded(
            manifest["targets"], families, args.dns_timeout, args.allow_non_global,
            args.workers, ledger)
    else:
        dns_interrupted = True

    existing_numbers = []
    for target in manifest["targets"]:
        for endpoint in target.get("endpoints", []):
            match = re.fullmatch(r"raw/(\d+)\.xml", str(endpoint.get("xml", "")))
            if match:
                existing_numbers.append(int(match.group(1)))
    next_number = max(existing_numbers, default=0)
    for target in manifest["targets"]:
        paths_for_target = saved_http_inputs.get(target["hostname"]) or target.get("requested_paths") or default_raw_paths
        if (not isinstance(paths_for_target, list) or not paths_for_target
                or any("?[redacted]" in str(path) for path in paths_for_target)):
            raise InputError(f"{target.get('hostname')}: paramètres HTTP expurgés; lancer une nouvelle campagne.")
        target["requested_paths"] = [public_path(valid_path(path)) for path in paths_for_target]
        existing_ips = {endpoint.get("ip") for endpoint in target.get("endpoints", [])
                        if isinstance(endpoint, dict)}
        for address_text in target.get("addresses", []):
            if address_text in existing_ips:
                continue
            next_number += 1
            address = ipaddress.ip_address(address_text)
            stem = f"raw/{next_number:06d}"
            endpoint = {
                "ip": str(address), "family": "ipv4" if address.version == 4 else "ipv6",
                "status": "PLANNED", "ports": port_expression(str(manifest.get("ports") or "1-65535")),
                "xml": stem + ".xml", "stdout": stem + ".stdout.log", "stderr": stem + ".stderr.log",
                "started_at": None, "finished_at": None, "returncode": None, "attempts": [],
            }
            endpoint["task_id"] = endpoint_task_id(
                target["hostname"], endpoint, target["requested_paths"], http)
            target.setdefault("endpoints", []).append(endpoint)
    atomic_json(manifest_path, manifest)
    jobs: list[tuple[dict, dict]] = []
    reusable = 0
    for target in manifest["targets"]:
        if not isinstance(target, dict) or not isinstance(target.get("hostname"), str):
            raise InputError("Cible invalide dans le manifeste de reprise.")
        name = hostname(target["hostname"])
        raw_paths = saved_http_inputs.get(name) or target.get("requested_paths") or default_raw_paths
        if not isinstance(raw_paths, list) or not raw_paths:
            raise InputError(f"{name}: chemins de reprise invalides.")
        if any("?[redacted]" in str(path) for path in raw_paths):
            raise InputError(f"{name}: parametres HTTP expurges; fournir une nouvelle campagne avec les chemins complets.")
        paths = [valid_path(path) for path in raw_paths]
        endpoints = target.get("endpoints", [])
        if not isinstance(endpoints, list):
            raise InputError("Endpoints invalides dans le manifeste de reprise.")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or not isinstance(endpoint.get("ip"), str):
                raise InputError("Endpoint invalide dans le manifeste de reprise.")
            address = ipaddress.ip_address(endpoint["ip"])
            if not address.is_global and not args.allow_non_global:
                endpoint.update(status="SKIPPED", error="NON_GLOBAL_ADDRESS",
                                finished_at=utcnow(), returncode=None)
                excluded = target.setdefault("excluded_addresses", [])
                if str(address) not in excluded:
                    excluded.append(str(address))
                continue
            endpoint["family"] = "ipv4" if address.version == 4 else "ipv6"
            endpoint["ports"] = port_expression(str(endpoint.get("ports") or manifest.get("ports") or "1-65535"))
            expected_task_id = endpoint_task_id(name, endpoint, target.get("requested_paths") or raw_paths, http)
            if endpoint.get("task_id") not in (None, expected_task_id):
                raise InputError(f"{name}: identité de tâche incompatible dans le manifeste de reprise.")
            endpoint["task_id"] = expected_task_id
            if endpoint.get("status") == "RUNNING":
                endpoint.update(status="INTERRUPTED", error="PREVIOUS_PROCESS_STOPPED",
                                finished_at=utcnow())
                ledger.append("endpoint", endpoint["task_id"], dict(endpoint))
            completed_reusable = _completed_endpoint_is_reusable(output, endpoint, name)
            if (not completed_reusable and _legacy_http_cost_unknown(manifest, endpoint)
                    and not endpoint.get("legacy_http_budget_uncertain")):
                # Persist before replacing the old combined Nmap/NSE command
                # and XML with discovery-only work. Unknown earlier GET costs
                # must not turn into a fresh HTTP allowance after migration.
                endpoint["legacy_http_budget_uncertain"] = True
                ledger.append("endpoint", endpoint["task_id"], dict(endpoint))
            if completed_reusable:
                reusable += 1
                continue
            if len(endpoint.get("attempts", [])) >= args.max_attempts:
                endpoint.update(status="FAILED", error="ATTEMPT_LIMIT_REACHED", finished_at=utcnow())
                ledger.append("endpoint", endpoint["task_id"], dict(endpoint))
                continue
            xml = _campaign_file(output, endpoint.get("xml"), ".xml")
            stdout = _campaign_file(output, endpoint.get("stdout"))
            stderr = _campaign_file(output, endpoint.get("stderr"))
            arguments = output / "state" / "private" / ("discovery-" + xml.stem + ".args")
            arguments.unlink(missing_ok=True)
            with os.fdopen(os.open(arguments, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                           "w", encoding="utf-8") as stream:
                stream.write(nse_arguments(name, paths, args))
            endpoint["stdout"] = str(stdout.relative_to(output))
            endpoint["stderr"] = str(stderr.relative_to(output))
            endpoint["command"] = command_for(nmap, endpoint, arguments, xml.with_suffix(""), args)
            endpoint.update(status="PLANNED", error=None, started_at=None, finished_at=None, returncode=None)
            jobs.append((target, endpoint))
    resumed = {"started_at": utcnow(), "finished_at": None, "tool_version": VERSION,
               "reused_endpoints": reusable, "retried_endpoints": len(jobs)}
    manifest.setdefault("resumes", []).append(resumed)
    manifest["status"] = "RUNNING"
    atomic_json(manifest_path, manifest)
    print(f"Reprise {manifest.get('campaign_id', output.name)}: {reusable} endpoints valides reutilises; "
          f"{len(jobs)} a relancer.", flush=True)
    control, interrupted = Processes(), dns_interrupted
    scheduler_metrics = {}
    if jobs and not interrupted:
        interrupted, _ = run_endpoint_jobs(
            jobs, workers=args.workers, workers_per_ip=min(args.workers_per_ip, args.workers),
            control=control, output=output, timeout=args.target_timeout, ledger=ledger,
            max_attempts=args.max_attempts, progress_label="Progression reprise",
            measurements=scheduler_metrics)
    if interrupted:
        print("Interruption de la reprise; conservation du bilan partiel.", file=sys.stderr, flush=True)
    else:
        interrupted = collect_http(manifest, output, args, control, ledger)
    for arguments in (output / "raw").glob("*.args"):
        arguments.unlink()
    discovery_incomplete = bool(manifest.get("discovery", {}).get("enabled")
                                and not manifest["discovery"].get("processing_complete"))
    failures = (discovery_incomplete
                or any(target.get("dns_status") != "RESOLVED" or target.get("dns_partial")
                       for target in manifest["targets"])
                or any(not _completed_endpoint_is_reusable(
                    output, endpoint, target["hostname"])
                    for target in manifest["targets"] for endpoint in target.get("endpoints", [])))
    manifest["status"] = "PARTIAL" if failures or interrupted else "COMPLETED"
    manifest["finished_at"] = utcnow()
    resumed["finished_at"] = manifest["finished_at"]
    resumed["scheduler"] = scheduler_metrics
    atomic_json(manifest_path, manifest)
    report = build_campaign_report(manifest, output, inventory=args.inventory, previous=args.previous,
                                   max_inventory_age_hours=args.inventory_max_age_hours)
    # The saved manifest describes the original scan; its regenerated compact
    # report must identify the renderer actually used for companion validation.
    report["tool_version"] = VERSION
    if not report["summary"].get("processing_complete", True):
        manifest["status"] = "PARTIAL"
        atomic_json(manifest_path, manifest)
        report["campaign"]["status"] = "PARTIAL"
        failures = True
    write_campaign_report(report, output)
    atomic_json(output / "progress.json", {
        "schema_version": "1", "provisional": False, "updated_at": utcnow(),
        "campaign_status": manifest["status"], "report": "report.json",
    })
    results = compact_rows(report["rows"])
    display_verdicts = (("VULNERABLE", "OUI"), ("NON-VULNERABLE", "NON"),
                        ("INDETERMINE", "INDETERMINE"))
    print(f"Reprise terminee: " + ", ".join(
        f"{label}={sum(row['vulnerable'] == stored for row in results)}"
        for label, stored in display_verdicts))
    print(f"Rapports: {output / 'report.csv'} et {output / 'report.json'}")
    print(f"Arborescence: {output / 'report-tree.txt'}")
    campaign_lock.release()
    return 130 if interrupted else 2 if failures else 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return resume_campaign(args) if args.resume else run_campaign(args)
    except (InputError, StateError, OSError, ValueError) as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrompu.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
