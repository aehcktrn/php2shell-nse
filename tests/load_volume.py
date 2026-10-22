#!/usr/bin/env python3
"""Offline load measurement for the bounded scheduler and report pipeline."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import gc
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import report
import scan
from campaign_state import EventLedger


class MeasuringLedger:
    """In-memory double that measures the journal's linear encoded volume."""

    def __init__(self):
        self.events_written = 0
        self.bytes_written = 0
        self.lock = threading.Lock()

    def append(self, kind, key, value):
        encoded = (json.dumps({"schema_version": "1", "kind": kind, "key": key,
                               "value": value}, ensure_ascii=False,
                              separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        with self.lock:
            self.events_written += 1
            self.bytes_written += len(encoded)


class MeasuringControl:
    def __init__(self):
        self.active = 0
        self.maximum_active = 0
        self.active_by_ip = {}
        self.maximum_by_ip = 0
        self.lock = threading.Lock()

    def run(self, _command, endpoint, _output, _timeout):
        with self.lock:
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            count = self.active_by_ip.get(endpoint["ip"], 0) + 1
            self.active_by_ip[endpoint["ip"]] = count
            self.maximum_by_ip = max(self.maximum_by_ip, count)
        time.sleep(0.0002)
        with self.lock:
            self.active -= 1
            self.active_by_ip[endpoint["ip"]] -= 1
        timeout = int(endpoint["task_id"].rsplit("-", 1)[-1]) % 1000 == 0
        return {**endpoint, "status": "TIMEOUT" if timeout else "FAILED", "returncode": 1,
                "error": "TARGET_TIMEOUT" if timeout else "LOAD_TEST_FIXTURE",
                "finished_at": scan.utcnow()}

    def stop(self):
        pass


def jobs_for(size):
    jobs = []
    for index in range(size):
        group = index // 100
        ip = f"93.{group // 64516}.{(group // 254) % 254}.{group % 254 + 1}"
        endpoint = {
            "task_id": f"load-{index}", "ip": ip, "status": "PLANNED",
            "command": ["fixture"], "stdout": "", "stderr": "", "attempts": [],
        }
        jobs.append(({"hostname": f"host-{index}.example.test"}, endpoint))
    return jobs


def report_rows(size):
    return [{
        "row_type": "COVERAGE", "hostname": f"host-{index}.example.test",
        "ip": "192.0.2.1", "port": "", "protocol": "dns", "state": "NOT_ASSESSED",
        "reason": "Résolution simulée indisponible.", "reason_code": "DNS_ERROR",
        "versions": "",
    } for index in range(size)]


def measure(size, *, durable_journal=False):
    with tempfile.TemporaryDirectory(prefix=f"php2shell-load-{size}-") as temporary:
        base = Path(temporary)
        tracemalloc.start()
        jobs = jobs_for(size)
        ledger = EventLedger(base) if durable_journal else MeasuringLedger()
        control, scheduler = MeasuringControl(), {}
        started = time.monotonic()
        with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(sink):
            interrupted, completed = scan.run_endpoint_jobs(
                jobs, workers=8, workers_per_ip=2, control=control, output=base,
                timeout=1, ledger=ledger, max_attempts=3, measurements=scheduler)
        scheduler_seconds = time.monotonic() - started
        _, scheduler_peak = tracemalloc.get_traced_memory()
        status_counts = scheduler["status_counts"]
        if (interrupted or completed != size
                or status_counts.get("TIMEOUT") != (size + 999) // 1000
                or sum(status_counts.values()) != size):
            raise RuntimeError("cardinalité ou état du planificateur incorrect")
        del jobs
        gc.collect()
        tracemalloc.reset_peak()

        details = {"schema_version": "1", "tool_version": scan.VERSION,
                   "campaign": {}, "summary": {}, "rows": report_rows(size)}
        started = time.monotonic()
        report.write_campaign_report(details, base)
        export_seconds = time.monotonic() - started
        started = time.monotonic()
        loaded = report.load_campaign_report(base / "report.json")
        read_seconds = time.monotonic() - started
        _, report_peak = tracemalloc.get_traced_memory()
        compact = json.loads((base / "report.json").read_text(encoding="utf-8"))
        if len(loaded["rows"]) != size or len(compact) != size:
            raise RuntimeError("cardinalité du rapport incorrecte")
        tracemalloc.stop()
        return {
            "targets": size,
            "scheduler_seconds": round(scheduler_seconds, 3),
            "scheduler_peak_mib": round(scheduler_peak / 1024 / 1024, 2),
            "max_submitted_unfinished": scheduler["max_submitted_unfinished"],
            "max_active": control.maximum_active,
            "max_active_per_ip": control.maximum_by_ip,
            "journal_events": ledger.events_written,
            "journal_mib": round(ledger.bytes_written / 1024 / 1024, 2),
            "journal_durable": durable_journal,
            "status_counts": status_counts,
            "export_seconds": round(export_seconds, 3),
            "read_seconds": round(read_seconds, 3),
            "report_peak_mib": round(report_peak / 1024 / 1024, 2),
            "report_details_mib": round((base / "raw" / "report-details.json").stat().st_size / 1024 / 1024, 2),
            "compact_rows": len(compact),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sizes", nargs="*", type=int, default=[10000, 100000])
    parser.add_argument("--durable-journal", action="store_true",
                        help="write and fsync the real incremental journal")
    args = parser.parse_args()
    for size in args.sizes:
        print(json.dumps(measure(size, durable_journal=args.durable_journal),
                         ensure_ascii=False, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
