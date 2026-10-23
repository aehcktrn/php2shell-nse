"""Bounded HTTP collection after Nmap discovery, using the existing NSE engine.

Only private inputs retain query values. Public state contains identities and
redacted paths. Every NSE invocation spends a reservation on the same service.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import time
from urllib.parse import urlsplit

from report import NON_WEB_SERVICES, ReportError, parse_report
from service_budget import ServiceBudgets, identity_key, service_identity


COMMON_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443}
HALTS = {"AUTHENTICATION_REQUIRED", "HTTP_ACCESS_DENIED", "RATE_LIMITED"}
MAX_REDIRECT_DESTINATIONS = 100000
MAX_CAMPAIGN_TARGETS = 100000


def public_path(value: str) -> str:
    return value.split("?", 1)[0] + ("?[redacted]" if "?" in value else "")


def url_identity(scheme: str, hostname: str, port: int, target: str) -> str:
    authority = hostname.lower().rstrip(".")
    if ":" in authority:
        authority = "[" + authority + "]"
    value = f"{scheme.lower()}://{authority}:{int(port)}{target.split('#', 1)[0]}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_destination(value: str) -> dict:
    if not isinstance(value, str) or len(value) > 2048 or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise ValueError("INVALID_REDIRECT_URL")
    value = value.split("#", 1)[0]
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("INVALID_REDIRECT_URL")
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("INVALID_REDIRECT_PORT")
    target = parsed.path or "/"
    if "?" in value:
        target += "?" + parsed.query
    if target.startswith("//"):
        raise ValueError("INVALID_REDIRECT_PATH")
    return {"hostname": parsed.hostname.lower().rstrip("."), "scheme": scheme,
            "port": port, "target": target,
            "path_identity": url_identity(scheme, parsed.hostname, port, target)}


def port_allowed(port: int, expression: str) -> bool:
    for item in expression.split(","):
        bounds = item.split("-")
        if len(bounds) == 1 and port == int(bounds[0]):
            return True
        if len(bounds) == 2 and int(bounds[0]) <= port <= int(bounds[1]):
            return True
    return False


def _elapsed(value, limit):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError("INVALID_ELAPSED_COUNTER")
    return min(math.ceil(number), limit)


def _halt_reason(row: dict) -> str | None:
    """A published version must not erase an access/rate-limit stop."""
    statuses = {"401": "AUTHENTICATION_REQUIRED", "403": "HTTP_ACCESS_DENIED", "429": "RATE_LIMITED"}
    for observation in [*row.get("observations", []), row]:
        condition = observation.get("http_condition")
        if condition not in HALTS:
            condition = statuses.get(str(observation.get("http_status", "")))
        if condition in HALTS:
            return condition
    reason = row.get("traversal_reason_code") or row.get("reason_code")
    return reason if reason in HALTS else None


def discovery_command(nmap: str, endpoint: dict, prefix: Path, args) -> list[str]:
    # Unknown-service fingerprints may embed complete HTTP responses. Stream
    # XML through the launcher's sanitizer instead of letting Nmap write them.
    command = [nmap, "-sT", "-sV", "-Pn", "-n", "-p", endpoint["ports"],
               "--stats-every", "30s", "-oX", "-"]
    if endpoint["family"] == "ipv6":
        command.append("-6")
    if args.nmap_datadir:
        command.extend(["--datadir", str(Path(args.nmap_datadir).resolve())])
    if args.max_rate:
        command.extend(["--max-rate", str(args.max_rate)])
    command.append(str(ipaddress.ip_address(endpoint["ip"])))
    return command


def _private_write(path: Path, value: str) -> None:
    if path.is_symlink():
        raise ValueError("PRIVATE_INPUT_SYMLINK")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def run_collection(manifest: dict, output: Path, args, control, ledger, *,
                   resolve, validate_hostname, exclusion, save,
                   endpoint_identity, request_paths: dict | None = None) -> bool:
    """Collect required paths, exact redirect chains, then optional navigation.

    Complete phase XML settles a reservation. An interrupted phase cannot
    establish its exact cost and keeps its reserved requests and time charged.
    """
    output = Path(output).resolve()
    private = output / "state" / "private"
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private, 0o700)
    (output / "raw" / "http").mkdir(parents=True, exist_ok=True)
    collection = manifest.setdefault("http_collection", {"schema_version": "1", "services": {}, "status": "RUNNING"})
    services = collection.setdefault("services", {})
    budgets = ServiceBudgets(manifest, ledger)
    nmap = shutil.which(args.nmap)
    if not nmap:
        raise ValueError("Nmap est introuvable pour la collecte HTTP.")
    targets = {target["hostname"]: target for target in manifest["targets"]}
    parsed_cache: dict[str, list[dict]] = {}

    def record(service):
        ledger.append("http_collection", service["service_key"], dict(service))

    def read_rows(xml):
        if xml not in parsed_cache:
            parsed_cache[xml] = parse_report(output / xml)
        return parsed_cache[xml]

    def rows_for(service):
        result = []
        for job in service["phase_jobs"]:
            if job.get("status") != "COMPLETED":
                continue
            try:
                result.extend(row for row in read_rows(job["xml"])
                              if row.get("row_type") == "ASSESSMENT"
                              and row.get("ip") == service["ip"]
                              and str(row.get("port")) == str(service["port"])
                              and row.get("scheme") == service["scheme"])
            except (ReportError, OSError):
                continue
        return result

    def ensure_service(name, ip, port, scheme, *, available=True):
        identity = service_identity(name, ip, port, scheme)
        key = budgets.ensure(identity, max_requests=args.max_requests, budget_ms=args.http_budget)
        if key not in services:
            services[key] = {"service_key": key, "identity": identity, **identity,
                             "available": available, "candidate_paths": [], "phase_jobs": [],
                             "required_destinations": [], "redirect_results": []}
            record(services[key])
        return services[key]

    def import_endpoints(target):
        for endpoint in target.get("endpoints", []):
            if not args.allow_non_global and not ipaddress.ip_address(endpoint["ip"]).is_global:
                continue
            if endpoint.get("status") != "COMPLETED":
                continue
            try:
                rows = read_rows(endpoint["xml"])
            except (ReportError, OSError):
                continue
            for row in rows:
                if row.get("ip") != endpoint["ip"] or not row.get("port"):
                    continue
                port, name = int(row["port"]), str(row.get("service", "")).lower()
                bare = name.removeprefix("ssl/")
                if bare in NON_WEB_SERVICES and row.get("service_method") == "probed":
                    continue
                if row.get("row_type") != "ASSESSMENT" and not (
                        "http" in bare or port in COMMON_PORTS and (
                            row.get("service_method") != "probed" or bare in ("", "unknown", "tcpwrapped"))):
                    continue
                scheme = row.get("scheme") or ("https" if name.startswith("ssl/") or name == "https" or port == 443 else "http")
                service = ensure_service(target["hostname"], endpoint["ip"], port, scheme)
                if endpoint.get("legacy_http_budget_uncertain"):
                    if not service["phase_jobs"]:
                        quota = budgets.remaining(service["service_key"])
                        token = (budgets.reserve(service["service_key"], quota["requests"], quota["budget_ms"])
                                 if quota["requests"] and quota["budget_ms"] and not quota["halted_reason"] else None)
                        service["phase_jobs"].append({"job_id": "legacy-uncertain-" + service["service_key"],
                            "phase": "base", "xml": endpoint["xml"], "status": "INTERRUPTED",
                            "paths": target.get("requested_paths", []), "reservation": token,
                            "error": "HTTP_BUDGET_UNCERTAIN", "imported": True})
                        service["error"] = "HTTP_BUDGET_UNCERTAIN"
                        record(service)
                    continue
                if row.get("row_type") == "ASSESSMENT" and not service["phase_jobs"]:
                    # Earlier campaigns already contain collection in their discovery XML.
                    token = budgets.reserve(service["service_key"], args.max_requests, args.http_budget)
                    raw_requests, raw_elapsed = row.get("requests_made"), row.get("elapsed_ms")
                    requests = int(args.max_requests if raw_requests in (None, "") else raw_requests)
                    elapsed = _elapsed(args.http_budget if raw_elapsed in (None, "") else raw_elapsed, args.http_budget)
                    budgets.settle(token, min(requests, args.max_requests), min(elapsed, args.http_budget))
                    service["phase_jobs"].append({"job_id": "import-" + service["service_key"], "phase": "base",
                        "xml": endpoint["xml"], "status": "COMPLETED", "paths": target.get("requested_paths", []),
                        "requests_made": requests, "elapsed_ms": elapsed, "imported": True})
                    halt = _halt_reason(row)
                    if halt in HALTS:
                        budgets.halt(service["service_key"], halt)
                        service["halted_reason"] = halt
                    record(service)

    for target in list(targets.values()):
        import_endpoints(target)

    def make_job(service, phase, paths, hops=0, chain=None):
        identities = [url_identity(service["scheme"], service["hostname"], service["port"], path) for path in paths]
        digest = hashlib.sha256(json.dumps([service["service_key"], phase, identities, hops], separators=(",", ":")).encode()).hexdigest()
        existing = next((job for job in service["phase_jobs"] if job["job_id"] == digest
                         or phase == "redirect" and job["phase"] == "redirect"
                         and job.get("path_identities") == identities), None)
        if existing:
            return existing
        job = {"job_id": digest, "phase": phase, "status": "PLANNED", "paths": list(map(public_path, paths)),
               "path_identities": identities, "chain_hops": hops, "chain": list(chain or []),
               "xml": f"raw/http/{digest}.xml", "stdout": f"raw/http/{digest}.stdout.log",
               "stderr": f"raw/http/{digest}.stderr.log"}
        _private_write(private / (digest + ".json"), json.dumps(paths))
        service["phase_jobs"].append(job)
        record(service)
        return job

    def execute(pair):
        service, job = pair
        if job["status"] != "PLANNED":
            return
        # A newly discovered destination runs its mandatory base paths first.
        # Those observations can satisfy a redirect queued before that phase.
        if job["phase"] == "redirect" and set(job["path_identities"]) <= observed(service):
            job.update(status="REUSED", reused_observations=list(job["path_identities"]))
            record(service)
            return
        if not args.allow_non_global and not ipaddress.ip_address(service["ip"]).is_global:
            job.update(status="FAILED", error="NON_GLOBAL_ADDRESS")
            record(service)
            return
        quota = budgets.remaining(service["service_key"])
        if quota["halted_reason"] or not quota["requests"] or not quota["budget_ms"]:
            job.update(status="BUDGET_EXHAUSTED", error=quota["halted_reason"] or "REQUEST_BUDGET_EXHAUSTED")
            record(service)
            return
        try:
            paths = json.loads((private / (job["job_id"] + ".json")).read_text())
            if not isinstance(paths, list) or any(not isinstance(path, str) or not path.startswith("/") for path in paths):
                raise ValueError()
        except (OSError, ValueError):
            job.update(status="INPUT_UNAVAILABLE", error="PRIVATE_INPUT_UNAVAILABLE")
            record(service)
            return
        token = budgets.reserve(service["service_key"], quota["requests"], quota["budget_ms"])
        job.update(status="RUNNING", reservation=token)
        record(service)
        plan = private / (job["job_id"] + ".redirects")
        _private_write(plan, "")
        options = {"vhost": service["hostname"], "path": paths[0], "paths": paths[1:],
                   "timeout": min(args.http_timeout, quota["budget_ms"]), "budget": quota["budget_ms"],
                   "max_requests": quota["requests"], "samples": args.samples if job["phase"] != "links" else 1,
                   "redirects": args.redirects, "chain_hops": job["chain_hops"], "phase": job["phase"],
                   "scheme": service["scheme"], "fallback": False, "enrich": False, "private_plan": str(plan)}
        if not options["paths"]:
            del options["paths"]
        argfile = private / (job["job_id"] + ".args")
        def lua(value):
            if isinstance(value, list):
                return "{" + ",".join(map(lua, value)) + "}"
            # Nmap accepts quoted UTF-8 but does not decode JSON \u escapes.
            return json.dumps(value, ensure_ascii=False)
        _private_write(argfile, ",\n".join("http-php2shell." + key + "=" + lua(value) for key, value in options.items()))
        command = [nmap, "-sT", "-Pn", "-n", "-p", str(service["port"]), "--script",
                   "+" + str(Path(__file__).resolve().parent / "http-php2shell.nse"), "--script-args-file", str(argfile),
                   "--script-timeout", f"{quota['budget_ms'] / 1000 + 2:g}s", "-oA", str((output / job["xml"]).with_suffix(""))]
        if ":" in service["ip"]:
            command.append("-6")
        if args.nmap_datadir:
            command.extend(["--datadir", str(Path(args.nmap_datadir).resolve())])
        if args.max_rate:
            command.extend(["--max-rate", str(args.max_rate)])
        command.append(service["ip"])
        request = {**job, "ip": service["ip"], "command": command, "identity": service["identity"], "collection_phase": job["phase"]}
        try:
            result = control.run(command, request, output, args.target_timeout)
            job.update({key: result.get(key) for key in ("status", "error", "returncode", "started_at", "finished_at")})
            if job["status"] == "COMPLETED":
                parsed_cache.pop(job["xml"], None)
                rows = [row for row in read_rows(job["xml"]) if row.get("row_type") == "ASSESSMENT"
                        and row.get("ip") == service["ip"] and str(row.get("port")) == str(service["port"])
                        and row.get("hostname") == service["hostname"] and row.get("scheme") == service["scheme"]]
                if len(rows) != 1:
                    raise ValueError("INVALID_HTTP_PHASE_RESULT")
                row = rows[0]
                requests, elapsed = int(row["requests_made"]), _elapsed(row["elapsed_ms"], quota["budget_ms"])
                budgets.settle(token, requests, elapsed)
                job.update(requests_made=requests, elapsed_ms=elapsed)
                if job["phase"] == "base":
                    service["candidate_paths"] = row.get("candidate_paths", [])[:32]
                halt = _halt_reason(row)
                if halt in HALTS:
                    budgets.halt(service["service_key"], halt)
                    service["halted_reason"] = halt
        except (OSError, ValueError, ReportError, KeyError) as exc:
            job.update(status="FAILED", error=type(exc).__name__)
        finally:
            record(service)

    def batch(pairs):
        queue = deque(pair for pair in pairs if pair[1]["status"] == "PLANNED")
        active, by_ip, active_services = {}, {}, set()
        pool = ThreadPoolExecutor(max_workers=args.workers)
        interrupted = False
        total, completed_count, last_progress = len(queue), 0, time.monotonic()
        try:
            while queue or active:
                for _ in range(len(queue)):
                    if len(active) >= args.workers:
                        break
                    pair = queue.popleft()
                    ip = pair[0]["ip"]
                    if (pair[0]["service_key"] in active_services
                            or by_ip.get(ip, 0) >= min(args.workers_per_ip, args.workers)):
                        queue.append(pair)
                        continue
                    by_ip[ip] = by_ip.get(ip, 0) + 1
                    active_services.add(pair[0]["service_key"])
                    active[pool.submit(execute, pair)] = pair
                if active:
                    finished, _ = wait(tuple(active), timeout=1, return_when=FIRST_COMPLETED)
                    for future in finished:
                        service, _ = active.pop(future)
                        by_ip[service["ip"]] -= 1
                        active_services.remove(service["service_key"])
                        future.result()
                        completed_count += 1
                if time.monotonic() - last_progress >= 30:
                    print(f"Collecte HTTP : {completed_count}/{total} phases terminées ; {len(active)} actives.", flush=True)
                    last_progress = time.monotonic()
        except KeyboardInterrupt:
            interrupted = True
            control.stop()
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        return interrupted

    # Any in-flight phase from a previous process keeps its full reservation.
    for service in services.values():
        for job in service["phase_jobs"]:
            if job["status"] == "RUNNING":
                job.update(status="INTERRUPTED", error="HTTP_BUDGET_UNCERTAIN")
                record(service)

    def base_jobs():
        jobs = []
        for service in list(services.values()):
            if service.get("available", True) and not any(job["phase"] == "base" for job in service["phase_jobs"]):
                paths = (request_paths or {}).get(service["hostname"]) or targets[service["hostname"]].get("requested_paths") or manifest["http"]["paths"]
                if any("?[redacted]" in path for path in paths):
                    defaults = (request_paths or {}).get("__default__")
                    if defaults and list(map(public_path, defaults)) == paths:
                        paths = defaults
                    else:
                        raise ValueError("PRIVATE_INPUT_UNAVAILABLE")
                jobs.append((service, make_job(service, "base", paths)))
        jobs.extend((service, job) for service in services.values() for job in service["phase_jobs"]
                    if job["phase"] == "base" and job["status"] == "PLANNED" and (service, job) not in jobs)
        return jobs

    if batch(base_jobs()):
        collection["status"] = "INTERRUPTED"
        return True

    def resolve_destination(name):
        if name in targets:
            return targets[name]
        if len(targets) >= MAX_CAMPAIGN_TARGETS:
            raise ValueError("REDIRECT_PLAN_LIMIT")
        target = {"hostname": name, "sources": ["http-redirect"], "requested_paths": list(manifest["http"]["paths"]), "endpoints": []}
        target.update(resolve(name, manifest["address_families"], args.dns_timeout, args.allow_non_global))
        if not args.allow_non_global:
            excluded = [ip for ip in target.get("addresses", []) if not ipaddress.ip_address(ip).is_global]
            target["addresses"] = [ip for ip in target.get("addresses", []) if ipaddress.ip_address(ip).is_global]
            if excluded:
                target.setdefault("excluded_addresses", []).extend(excluded)
            if not target["addresses"] and excluded:
                target["dns_status"] = "NO_PUBLIC_ADDRESS"
        targets[name] = target
        manifest["targets"].append(target)
        numbers = [int(Path(e["xml"]).stem) for t in targets.values() for e in t.get("endpoints", []) if Path(e["xml"]).stem.isdecimal()]
        number = max(numbers, default=0)
        for ip in target.get("addresses", []):
            number += 1
            stem = f"raw/{number:06d}"
            endpoint = {"ip": ip, "family": "ipv6" if ":" in ip else "ipv4", "ports": manifest["ports"],
                        "xml": stem + ".xml", "stdout": stem + ".stdout.log", "stderr": stem + ".stderr.log",
                        "status": "PLANNED", "attempts": []}
            endpoint["task_id"] = endpoint_identity(name, endpoint, target["requested_paths"], manifest["http"])
            target["endpoints"].append(endpoint)
        save(output / "manifest.json", manifest)
        _private_write(output / "targets.txt", "\n".join(targets) + "\n")
        for endpoint in target["endpoints"]:
            attempt = {"number": 1, "status": "RUNNING"}
            endpoint.update(status="RUNNING", attempts=[attempt])
            ledger.append("endpoint", endpoint["task_id"], endpoint)
            command = discovery_command(nmap, endpoint, (output / endpoint["xml"]).with_suffix(""), args)
            endpoint.update(control.run(command, endpoint, output, args.target_timeout))
            attempt.update(status=endpoint["status"], finished_at=endpoint.get("finished_at"))
            ledger.append("endpoint", endpoint["task_id"], endpoint)
        import_endpoints(target)
        return target

    def observed(service):
        return {item.get("path_identity") for row in rows_for(service) for item in row.get("observations", [])
                if item.get("path_identity") and str(item.get("http_status", "")).isdecimal()}

    redirect_count = sum(len(service["redirect_results"]) for service in services.values())
    while True:
        pending = []
        changed = False
        for source in list(services.values()):
            for job in list(source["phase_jobs"]):
                if job.get("status") != "COMPLETED" or job["phase"] == "links" or job.get("redirects_planned"):
                    continue
                plan = private / (job["job_id"] + ".redirects")
                if not plan.exists():
                    if any(item.get("redirect_identity") for row in rows_for(source)
                           for item in row.get("observations", [])):
                        job["error"] = "PRIVATE_INPUT_UNAVAILABLE"
                    job["redirects_planned"] = True
                    record(source)
                    continue
                if plan.stat().st_size > 262144:
                    raise ValueError("PRIVATE_REDIRECT_PLAN_TOO_LARGE")
                for line in plan.read_text().splitlines()[:64]:
                    fields = line.split("\t")
                    if len(fields) < 4:
                        continue
                    origin_id, destination_id, raw_url, hop_text = fields[:4]
                    result = {"source_path_identity": origin_id, "redirect_identity": destination_id,
                              "destination_ips": [], "destination_service_keys": [], "status": "UNASSESSED"}
                    if redirect_count >= MAX_REDIRECT_DESTINATIONS:
                        result["reason_code"] = "REDIRECT_PLAN_LIMIT"
                        source["redirect_results"].append(result)
                        break
                    source["redirect_results"].append(result)
                    redirect_count += 1
                    try:
                        destination = parse_destination(raw_url)
                        name = validate_hostname(destination["hostname"])
                        rules = manifest.get("scope", {})
                        reason = exclusion(name, rules)
                        if reason or rules.get("mode") == "exact" and name not in targets:
                            raise ValueError(reason or "OUTSIDE_AUTHORIZED_DOMAINS")
                        if not port_allowed(destination["port"], manifest["ports"]):
                            raise ValueError("UNAUTHORIZED_PORT")
                        hops = int(hop_text)
                        chain = list(job.get("chain", [])) + [origin_id]
                        if destination["path_identity"] != destination_id:
                            raise ValueError("INVALID_REDIRECT_IDENTITY")
                        if destination_id in chain:
                            raise ValueError("REDIRECT_LOOP")
                        if hops > args.redirects:
                            raise ValueError("CHAIN_LIMIT")
                        target = resolve_destination(name)
                        addresses = [ip for ip in target.get("addresses", [])
                                     if args.allow_non_global or ipaddress.ip_address(ip).is_global]
                        if not addresses:
                            raise ValueError("NO_PUBLIC_ADDRESS" if target.get("excluded_addresses") else "NO_DNS_ADDRESS")
                        for ip in addresses:
                            key = identity_key(service_identity(name, ip, destination["port"], destination["scheme"]))
                            target_service = services.get(key)
                            if target_service is None:
                                target_service = ensure_service(name, ip, destination["port"], destination["scheme"], available=False)
                            result["destination_ips"].append(ip)
                            result["destination_service_keys"].append(key)
                            requirement = {"path_identity": destination_id, "path": public_path(destination["target"]),
                                           "source_service_key": source["service_key"], "source_path_identity": origin_id,
                                           "source_redirect_identity": destination_id, "chain_hops": hops, "status": "PLANNED"}
                            if not any(r["path_identity"] == destination_id and r["source_service_key"] == source["service_key"]
                                       for r in target_service["required_destinations"]):
                                target_service["required_destinations"].append(requirement)
                            if destination_id in observed(target_service):
                                requirement["status"] = "COMPLETED"
                            elif not target_service.get("available", True):
                                requirement.update(status="NO_HTTP_SERVICE", reason_code="NO_HTTP_RESPONSE")
                            else:
                                task = make_job(target_service, "redirect", [destination["target"]], hops, chain)
                                if task["status"] == "PLANNED" and not any(p[1]["job_id"] == task["job_id"] for p in pending):
                                    pending.append((target_service, task))
                            record(target_service)
                        result["status"] = "PLANNED"
                    except (ValueError, KeyError) as exc:
                        result.update(status="UNASSESSED", reason_code=str(exc))
                job["redirects_planned"] = True
                record(source)
                changed = True
        new_base = base_jobs()
        if new_base:
            if batch(new_base):
                collection["status"] = "INTERRUPTED"
                return True
        pending.extend((service, job) for service in services.values() for job in service["phase_jobs"]
                       if job["phase"] == "redirect" and job["status"] == "PLANNED"
                       and not any(p[1]["job_id"] == job["job_id"] for p in pending))
        if pending and batch(pending):
            collection["status"] = "INTERRUPTED"
            return True
        if not pending and not new_base and not changed:
            break

    optional = []
    for service in services.values():
        usable = any(item.get("state") in ("POTENTIALLY_VULNERABLE", "PATCHED_VERSION_ADVERTISED")
                     for row in rows_for(service) for item in row.get("evidence", []))
        quota = budgets.remaining(service["service_key"])
        if usable or quota["halted_reason"] or not quota["requests"] or not quota["budget_ms"]:
            continue
        candidates = service.get("candidate_paths", [])[:2]
        if candidates and not any(job["phase"] == "links" for job in service["phase_jobs"]):
            optional.append((service, make_job(service, "links", candidates)))
        optional.extend((service, job) for job in service["phase_jobs"] if job["phase"] == "links"
                        and job["status"] == "PLANNED" and not any(p[1]["job_id"] == job["job_id"] for p in optional))
    interrupted = batch(optional)
    for service in services.values():
        seen = observed(service)
        for requirement in service["required_destinations"]:
            if requirement["path_identity"] in seen:
                requirement["status"] = "COMPLETED"
            elif requirement["status"] == "PLANNED":
                quota = budgets.remaining(service["service_key"])
                requirement.update(status="BUDGET_EXHAUSTED" if not quota["requests"] or not quota["budget_ms"] else "FAILED",
                                   reason_code=quota["halted_reason"] or "REDIRECT_NOT_ASSESSED")
        record(service)
    unfinished = any(job.get("status") not in ("COMPLETED", "REUSED")
                     for service in services.values() for job in service["phase_jobs"])
    collection["status"] = "INTERRUPTED" if interrupted else "PARTIAL" if unfinished else "COMPLETED"
    return interrupted
