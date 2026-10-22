"""Bounded passive subdomain discovery through the public crt.sh JSON interface.

Certificate names are candidates, not proof of a live service or of exhaustive
coverage. The subprocess deadline includes source DNS, TLS, response reads and
JSON parsing. This module does not resolve or scan the candidate names.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from http.client import HTTPException, IncompleteRead
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


SOURCE = "crt.sh"
ENDPOINT = "https://crt.sh/"
PROVIDER_RESULT_LIMIT = 10000
MAX_EXCLUDED_SAMPLES = 100
MAX_RECORDS = 100000
MAX_NAME_LENGTH = 253
USER_AGENT = "php2shell-scanner/0.4.1 (passive certificate discovery)"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_name(value: object) -> str:
    """Accept a concrete DNS name only; return its canonical ASCII spelling."""
    if not isinstance(value, str):
        raise ValueError("DNS name must be a string.")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("DNS names must not contain control characters.")
    value = value.strip()
    if value.endswith("."):
        value = value[:-1]
    if (not value or len(value) > 1024 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("Invalid DNS name.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("An IP address is not a DNS name.")
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid IDNA name.") from exc
    if len(name) > MAX_NAME_LENGTH or not re.search(r"[a-z]", name):
        raise ValueError("Invalid DNS name.")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in name.split(".")):
        raise ValueError("Invalid DNS label.")
    return name


def _within(name: str, root: str) -> bool:
    return name == root or name.endswith("." + root)


def _new_result(root: str, timeout: float, max_names: int, max_bytes: int) -> dict:
    return {
        "root": root, "source": SOURCE, "status": "FAILED", "reason_code": "SOURCE_NOT_RUN",
        "started_at": _utcnow(), "finished_at": None, "exhaustive": False,
        "processing_complete": False, "candidates": [], "candidate_count": 0,
        "excluded_candidates": [], "rejected_count": 0, "rejection_counts": {},
        "excluded_samples_truncated": False, "records_received": 0, "records_processed": 0,
        "raw_names_count": 0, "duplicate_count": 0, "wildcard_count": 0,
        "provider_result_count": 0, "provider_count_complete": True,
        "response_bytes": 0,
        "warnings": ["PASSIVE_SOURCE_NOT_EXHAUSTIVE"],
        "limits": {"timeout_seconds": timeout, "max_names": max_names,
                   "max_response_bytes": max_bytes, "max_excluded_samples": MAX_EXCLUDED_SAMPLES,
                   "max_records": MAX_RECORDS, "provider_result_limit": PROVIDER_RESULT_LIMIT},
    }


def _finish(result: dict, status: str, reason: str) -> dict:
    result.update(status=status, reason_code=reason, finished_at=_utcnow(),
                  processing_complete=(status == "COMPLETED"))
    return result


def _public_sample(value: object) -> str:
    # Untrusted certificate data must never inject terminal control sequences.
    if not isinstance(value, str):
        return "<invalid record>"
    return "".join(c if c.isprintable() else "?" for c in value)[:MAX_NAME_LENGTH]


def _parse_payload(payload: object, result: dict, max_names: int) -> dict:
    if not isinstance(payload, list):
        return _finish(result, "FAILED", "INVALID_RESPONSE")
    result["records_received"] = len(payload)
    accepted = set()
    rejected = Counter()
    partial_reasons = []

    def mark_partial(reason: str) -> None:
        if reason not in partial_reasons:
            partial_reasons.append(reason)

    def reject(value: object, reason: str) -> None:
        rejected[reason] += 1
        if len(result["excluded_candidates"]) < MAX_EXCLUDED_SAMPLES:
            result["excluded_candidates"].append({"hostname": _public_sample(value),
                "source": f"{SOURCE}:{result['root']}", "reason": reason})

    for record in payload[:MAX_RECORDS]:
        result["records_processed"] += 1
        if not isinstance(record, dict):
            reject(None, "INVALID_SOURCE_RECORD")
            result["provider_count_complete"] = False
            mark_partial("INVALID_SOURCE_RECORDS")
            continue
        count = record.get("result_count")
        if isinstance(count, int) and not isinstance(count, bool) and count > 0:
            result["provider_result_count"] += count
        else:
            # Older/alternative source output may omit result_count. This
            # removes our ability to detect its limit, never a guarantee.
            result["provider_count_complete"] = False
        values = record.get("name_value")
        if not isinstance(values, str) or not values.strip():
            reject(None, "INVALID_SOURCE_RECORD")
            mark_partial("INVALID_SOURCE_RECORDS")
            continue
        for raw in values.split("\n"):
            # A CRLF is a source SAN separator; other controls must not be
            # erased into a plausible target by general whitespace trimming.
            value = raw.removesuffix("\r").strip(" ")
            if not value:
                continue
            result["raw_names_count"] += 1
            if value.startswith("*."):
                try:
                    suffix = normalize_name(value[2:])
                except ValueError:
                    reject(value, "INVALID_HOSTNAME")
                    continue
                if not _within(suffix, result["root"]):
                    reject(value, "OUTSIDE_QUERY_ROOT")
                    continue
                result["wildcard_count"] += 1
                reject("*." + suffix, "CERTIFICATE_WILDCARD")
                continue
            try:
                name = normalize_name(value)
            except ValueError:
                reject(value, "INVALID_HOSTNAME")
                continue
            if not _within(name, result["root"]):
                reject(name, "OUTSIDE_QUERY_ROOT")
                continue
            if name in accepted:
                result["duplicate_count"] += 1
                continue
            if len(accepted) >= max_names:
                reject(name, "NAME_LIMIT_REACHED")
                mark_partial("NAME_LIMIT_REACHED")
                continue
            accepted.add(name)
    if len(payload) > MAX_RECORDS:
        mark_partial("RECORD_LIMIT_REACHED")
    if result["provider_result_count"] >= PROVIDER_RESULT_LIMIT:
        mark_partial("PROVIDER_LIMIT_REACHED")
    if not result["provider_count_complete"]:
        result["warnings"].append("PROVIDER_TRUNCATION_UNKNOWN")
    result["candidates"] = sorted(accepted)
    result["candidate_count"] = len(accepted)
    result["rejection_counts"] = dict(rejected)
    result["rejected_count"] = sum(rejected.values())
    result["excluded_samples_truncated"] = result["rejected_count"] > len(result["excluded_candidates"])
    result["warnings"].extend(partial_reasons)
    if partial_reasons:
        # The provider cap is especially important: JSON has no separate
        # truncation marker although the upstream SQL applies this limit.
        reason = "PROVIDER_LIMIT_REACHED" if "PROVIDER_LIMIT_REACHED" in partial_reasons else partial_reasons[0]
        return _finish(result, "PARTIAL", reason)
    return _finish(result, "COMPLETED", "OK" if accepted else "EMPTY_RESULT")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        # Leave the redirect as an HTTPError; never transmit the query root to
        # a different endpoint or downgrade from HTTPS.
        return None


def _fetch_root(root: str, timeout: float, max_names: int, max_bytes: int) -> dict:
    result = _new_result(root, timeout, max_names, max_bytes)
    query = urlencode({"q": "%." + root, "output": "json", "match": "ILIKE"})
    request = Request(ENDPOINT + "?" + query,
                      headers={"Accept": "application/json", "Accept-Encoding": "identity",
                               "User-Agent": USER_AGENT})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
            result["http_status"] = response.status
            if response.status != 200:
                return _finish(result, "FAILED", "HTTP_ERROR")
            content_type = response.headers.get_content_type().lower()
            if content_type != "application/json":
                return _finish(result, "FAILED", "INVALID_CONTENT_TYPE")
            encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
            if encoding not in ("", "identity"):
                return _finish(result, "FAILED", "UNSUPPORTED_CONTENT_ENCODING")
            length = response.headers.get("Content-Length", "")
            if length.isdigit() and int(length) > max_bytes:
                return _finish(result, "FAILED", "RESPONSE_TOO_LARGE")
            chunks, total = [], 0
            while True:
                part = response.read(min(65536, max_bytes + 1 - total))
                if not part:
                    break
                chunks.append(part)
                total += len(part)
                result["response_bytes"] = total
                if total > max_bytes:
                    return _finish(result, "FAILED", "RESPONSE_TOO_LARGE")
            if length.isdigit() and total != int(length):
                return _finish(result, "FAILED", "INCOMPLETE_RESPONSE")
        try:
            payload = json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError):
            return _finish(result, "FAILED", "INVALID_RESPONSE")
        return _parse_payload(payload, result, max_names)
    except HTTPError as exc:
        result["http_status"] = exc.code
        if exc.code == 429:
            reason = "RATE_LIMITED"
            retry = exc.headers.get("Retry-After", "") if exc.headers else ""
            if retry.isdigit() and len(retry) <= 9:
                result["retry_after_seconds"] = min(int(retry), 86400)
        elif 300 <= exc.code < 400:
            reason = "REDIRECT_REFUSED"
        else:
            reason = "HTTP_ERROR"
        exc.close()
        return _finish(result, "FAILED", reason)
    except (TimeoutError, socket.timeout):
        return _finish(result, "FAILED", "TIMEOUT")
    except URLError as exc:
        reason = "TIMEOUT" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "NETWORK_ERROR"
        return _finish(result, "FAILED", reason)
    except IncompleteRead:
        return _finish(result, "FAILED", "INCOMPLETE_RESPONSE")
    except HTTPException:
        return _finish(result, "FAILED", "NETWORK_ERROR")
    except (OSError, ValueError):
        return _finish(result, "FAILED", "NETWORK_ERROR")


def discover_root(root: str, timeout: float = 30, max_names: int = 10000,
                  max_bytes: int = 8 * 1024 * 1024) -> dict:
    """Retrieve concrete certificate names beneath one validated root.

    The caller must apply its effective scope and exclusions before resolving
    or scanning any candidate. Input errors raise ValueError before networking;
    source failures are recorded in the returned result.
    """
    root = normalize_name(root)
    if "." not in root:
        raise ValueError("A discovery root must contain at least two DNS labels.")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 300):
        raise ValueError("Invalid discovery timeout.")
    for value, minimum, maximum, label in ((max_names, 1, 100000, "max_names"),
            (max_bytes, 1024, 64 * 1024 * 1024, "max_bytes")):
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"Invalid discovery {label}.")
    result = _new_result(root, timeout, max_names, max_bytes)
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", root,
               "--timeout", str(timeout), "--max-names", str(max_names), "--max-bytes", str(max_bytes)]
    process = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
        output, _ = process.communicate(timeout=timeout)
        if process.returncode != 0:
            return _finish(result, "FAILED", "SOURCE_WORKER_ERROR")
        try:
            received = json.loads(output)
            candidates = received["candidates"]
            if (not isinstance(received, dict) or received.get("root") != root
                    or received.get("source") != SOURCE or received.get("status") not in ("COMPLETED", "PARTIAL", "FAILED")
                    or not isinstance(candidates, list) or len(candidates) > max_names
                    or any(normalize_name(name) != name or not _within(name, root) for name in candidates)
                    or len(set(candidates)) != len(candidates)
                    or not isinstance(received.get("excluded_candidates"), list)
                    or len(received["excluded_candidates"]) > MAX_EXCLUDED_SAMPLES):
                raise ValueError("Invalid worker response.")
        except (ValueError, TypeError, KeyError, RecursionError):
            return _finish(result, "FAILED", "SOURCE_WORKER_ERROR")
        received["started_at"] = result["started_at"]
        received["finished_at"] = _utcnow()
        received["exhaustive"] = False
        received["processing_complete"] = received["status"] == "COMPLETED"
        return received
    except subprocess.TimeoutExpired:
        if process is not None:
            process.kill()
            process.communicate()
        return _finish(result, "FAILED", "TIMEOUT")
    except KeyboardInterrupt:
        if process is not None:
            process.kill()
            process.communicate()
        raise
    except OSError:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        return _finish(result, "FAILED", "SOURCE_WORKER_ERROR")


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--max-names", type=int, required=True)
    parser.add_argument("--max-bytes", type=int, required=True)
    args = parser.parse_args()
    # This entry point is private to discover_root; the fixed endpoint cannot
    # be replaced through a command-line argument or environment variable.
    result = _fetch_root(args.worker, args.timeout, args.max_names, args.max_bytes)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
