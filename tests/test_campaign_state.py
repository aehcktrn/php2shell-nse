"""Incremental state and bounded scheduling contracts."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from campaign_state import CampaignLock, EventLedger, StateError
import scan


class CampaignStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="php2shell-state-")
        self.base = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def manifest():
        return {
            "targets": [{"hostname": "app.example.com", "dns_status": "NOT_RESOLVED",
                         "addresses": [], "endpoints": [{"task_id": "task-1", "status": "PLANNED"}]}],
            "discovery": {"roots": ["example.com"], "queries": [], "candidates": []},
        }

    def test_event_replay_restores_dns_endpoint_and_discovery(self):
        ledger = EventLedger(self.base)
        ledger.append("dns", "app.example.com", {"dns_status": "RESOLVED", "addresses": ["192.0.2.10"]})
        ledger.append("endpoint", "task-1", {"status": "COMPLETED", "returncode": 0})
        ledger.append("discovery", "example.com", {
            "query": {"root": "example.com", "status": "COMPLETED", "processing_complete": True},
            "candidates": ["app.example.com"],
        })
        restored = ledger.replay(self.manifest())
        target = restored["targets"][0]
        self.assertEqual((target["dns_status"], target["addresses"]),
                         ("RESOLVED", ["192.0.2.10"]))
        self.assertEqual(target["endpoints"][0]["status"], "COMPLETED")
        self.assertEqual(restored["discovery"]["candidates"][0]["hostname"], "app.example.com")

    def test_only_an_incomplete_final_event_is_ignored(self):
        ledger = EventLedger(self.base)
        ledger.append("endpoint", "task-1", {"status": "COMPLETED"})
        with ledger.path.open("ab") as stream:
            stream.write(b'{"schema_version":"1"')
        restored = ledger.replay(self.manifest())
        self.assertEqual(restored["targets"][0]["endpoints"][0]["status"], "COMPLETED")

    def test_campaign_lock_refuses_a_second_process(self):
        first = CampaignLock(self.base)
        first.acquire()
        try:
            with self.assertRaisesRegex(StateError, "déjà ouverte"):
                CampaignLock(self.base).acquire()
        finally:
            first.release()

    def test_scheduler_bounds_total_and_per_ip_activity(self):
        active = 0
        active_by_ip = {}
        maximum = 0
        maximum_by_ip = {}
        lock = threading.Lock()

        class Control:
            def run(self, _command, endpoint, _output, _timeout):
                nonlocal active, maximum
                with lock:
                    self.assert_running(endpoint)
                    active += 1
                    active_by_ip[endpoint["ip"]] = active_by_ip.get(endpoint["ip"], 0) + 1
                    maximum = max(maximum, active)
                    maximum_by_ip[endpoint["ip"]] = max(
                        maximum_by_ip.get(endpoint["ip"], 0), active_by_ip[endpoint["ip"]])
                time.sleep(0.002)
                with lock:
                    active -= 1
                    active_by_ip[endpoint["ip"]] -= 1
                return {**endpoint, "status": "FAILED", "returncode": 1,
                        "error": "fixture", "finished_at": scan.utcnow()}

            @staticmethod
            def assert_running(endpoint):
                if endpoint["status"] != "RUNNING" or not endpoint["started_at"]:
                    raise AssertionError("task was not marked RUNNING at actual start")

            def stop(self):
                pass

        jobs = []
        for index in range(240):
            ip = "192.0.2.1" if index < 200 else f"192.0.2.{index - 198}"
            endpoint = {"task_id": f"task-{index}", "ip": ip, "status": "PLANNED",
                        "command": ["fixture"], "stdout": "", "stderr": "", "attempts": []}
            jobs.append(({"hostname": f"app-{index}.example.com"}, endpoint))
        measurements = {}
        with redirect_stdout(io.StringIO()):
            interrupted, completed = scan.run_endpoint_jobs(
                jobs, workers=8, workers_per_ip=2, control=Control(), output=self.base,
                timeout=1, ledger=EventLedger(self.base), max_attempts=3,
                measurements=measurements)
        self.assertFalse(interrupted)
        self.assertEqual(completed, len(jobs))
        self.assertLessEqual(maximum, 8)
        self.assertLessEqual(measurements["max_submitted_unfinished"], 8)
        self.assertLessEqual(max(maximum_by_ip.values()), 2)
        self.assertTrue(all(endpoint["status"] == "FAILED" for _, endpoint in jobs))
        self.assertTrue(all(len(endpoint["attempts"]) == 1 for _, endpoint in jobs))
        progress = json.loads((self.base / "progress.json").read_text())
        self.assertTrue(progress["provisional"])
        self.assertEqual(progress["positive_targets"], [])
        self.assertNotIn("results", progress)
        self.assertNotIn("verdicts", progress)

    def test_one_worker_never_activates_more_than_one_of_hundreds_of_tasks(self):
        active = maximum = 0
        lock = threading.Lock()

        class Control:
            def run(inner_self, _command, endpoint, _output, _timeout):
                nonlocal active, maximum
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                time.sleep(0.0002)
                with lock:
                    active -= 1
                return {**endpoint, "status": "FAILED", "returncode": 1,
                        "error": "fixture", "finished_at": scan.utcnow()}

            def stop(self):
                pass

        jobs = []
        for index in range(400):
            endpoint = {"task_id": f"one-{index}", "ip": f"192.0.2.{index % 250 + 1}",
                        "status": "PLANNED", "command": ["fixture"], "stdout": "",
                        "stderr": "", "attempts": []}
            jobs.append(({"hostname": f"one-{index}.example.com"}, endpoint))
        with redirect_stdout(io.StringIO()):
            interrupted, completed = scan.run_endpoint_jobs(
                jobs, workers=1, workers_per_ip=1, control=Control(), output=self.base,
                timeout=1, ledger=EventLedger(self.base), max_attempts=3)
        self.assertFalse(interrupted)
        self.assertEqual(completed, 400)
        self.assertEqual(maximum, 1)

    def test_interruption_is_durable_and_never_leaves_a_false_running_task(self):
        class Control:
            def run(self, _command, _endpoint, _output, _timeout):
                raise KeyboardInterrupt

            def stop(self):
                pass

        jobs = []
        manifest = {"targets": [], "discovery": {"roots": [], "queries": [], "candidates": []}}
        for index in range(25):
            endpoint = {"task_id": f"interrupt-{index}", "ip": "192.0.2.1",
                        "status": "PLANNED", "command": ["fixture"], "stdout": "",
                        "stderr": "", "attempts": []}
            target = {"hostname": f"interrupt-{index}.example.com", "endpoints": [endpoint]}
            jobs.append((target, endpoint))
            manifest["targets"].append(target)
        ledger = EventLedger(self.base)
        with redirect_stdout(io.StringIO()):
            interrupted, _ = scan.run_endpoint_jobs(
                jobs, workers=1, workers_per_ip=1, control=Control(), output=self.base,
                timeout=1, ledger=ledger, max_attempts=3)
        self.assertTrue(interrupted)
        self.assertTrue(all(endpoint["status"] == "INTERRUPTED" for _, endpoint in jobs))
        restored = ledger.replay(manifest)
        statuses = [endpoint["status"] for target in restored["targets"]
                    for endpoint in target["endpoints"]]
        self.assertEqual(set(statuses), {"INTERRUPTED"})


if __name__ == "__main__":
    unittest.main()
