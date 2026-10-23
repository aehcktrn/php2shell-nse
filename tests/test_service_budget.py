"""Campaign-wide HTTP reservations remain bounded across phases and crashes."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from campaign_state import EventLedger, StateError
from service_budget import ServiceBudgets, identity_key, service_identity


class ServiceBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="php2shell-budget-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.manifest = {"targets": []}
        self.ledger = EventLedger(self.directory)
        self.budgets = ServiceBudgets(self.manifest, self.ledger)
        self.identity = service_identity("app.example.com", "192.0.2.10", 443, "https")
        self.key = self.budgets.ensure(self.identity)

    def restart(self):
        self.manifest = EventLedger(self.directory).replay({"targets": []})
        self.ledger = EventLedger(self.directory)
        self.budgets = ServiceBudgets(self.manifest, self.ledger)

    def test_three_completed_gets_leave_two_across_a_restart(self):
        token = self.budgets.reserve(self.key, 5, 20000)
        self.assertEqual(self.budgets.remaining(self.key)["requests"], 0)
        self.budgets.settle(token, actual_requests=3, actual_elapsed_ms=6400)
        self.restart()
        remaining = self.budgets.remaining(self.key)
        self.assertEqual((remaining["requests"], remaining["budget_ms"]), (2, 13600))
        token = self.budgets.reserve(self.key, 2, 13600)
        self.budgets.settle(token, 2, 3600)
        self.assertEqual(self.budgets.remaining(self.key)["charged_requests"], 5)
        with self.assertRaises(StateError):
            self.budgets.reserve(self.key, 1, 100)

    def test_unknown_crashed_phase_keeps_its_full_allowance_charged(self):
        self.budgets.reserve(self.key, 5, 20000)
        self.restart()
        remaining = self.budgets.remaining(self.key)
        self.assertEqual((remaining["requests"], remaining["budget_ms"],
                          remaining["open_reservations"]), (0, 0, 1))
        self.assertEqual(self.budgets.ensure(self.identity), self.key)
        with self.assertRaises(StateError):
            self.budgets.reserve(self.key, 1, 1)

    def test_restart_or_stopped_wall_time_never_spends_extra_http_time(self):
        token = self.budgets.reserve(self.key, 5, 20000)
        self.budgets.settle(token, 1, 250)
        before = self.budgets.remaining(self.key)
        # No timestamp is used in the quota schema; stopping or replaying later
        # cannot consume the 19750 ms of traversal work still available.
        for _ in range(3):
            self.restart()
            self.assertEqual(self.budgets.remaining(self.key), before)

    def test_settlement_is_idempotent_and_cannot_create_extra_quota(self):
        token = self.budgets.reserve(self.key, 5, 20000)
        first = self.budgets.settle(token, 3, 5000)
        events = self.ledger.events_written
        self.assertEqual(self.budgets.settle(token, 3, 5000), first)
        self.assertEqual(self.ledger.events_written, events)
        for requests, elapsed in ((2, 5000), (3, 1), (6, 20000), (-1, 0), (True, 1)):
            with self.assertRaises(StateError):
                self.budgets.settle(token, requests, elapsed)
        self.assertEqual(self.budgets.remaining(self.key)["requests"], 2)

    def test_invalid_completed_counts_leave_the_conservative_reservation(self):
        token = self.budgets.reserve(self.key, 5, 20000)
        for requests, elapsed in ((6, 1), (1, 20001), (1.5, 10), (1, float("nan"))):
            with self.assertRaises(StateError):
                self.budgets.settle(token, requests, elapsed)
        self.assertEqual(self.budgets.remaining(self.key)["requests"], 0)
        self.assertEqual(self.budgets.remaining(self.key)["open_reservations"], 1)

    def test_identity_distinguishes_name_ip_port_and_protocol(self):
        keys = {self.key}
        for field, value in (("hostname", "other.example.com"), ("ip", "192.0.2.11"),
                             ("port", 8443), ("scheme", "http")):
            identity = {**self.identity, field: value}
            key = self.budgets.ensure(identity)
            self.assertNotIn(key, keys)
            keys.add(key)
        same = service_identity("APP.EXAMPLE.COM.", "192.0.2.10", 443, "HTTPS")
        self.assertEqual(identity_key(same), self.key)
        ipv6a = service_identity("app.example.com", "2001:0db8:0:0::1", 443, "https")
        ipv6b = service_identity("app.example.com", "2001:db8::1", 443, "https")
        self.assertEqual(identity_key(ipv6a), identity_key(ipv6b))

    def test_limits_cannot_be_reset_by_a_later_phase(self):
        for requests, budget in ((6, 20000), (5, 30000), (True, 20), (0, 20)):
            with self.assertRaises(StateError):
                self.budgets.ensure(self.identity, requests, budget)

    def test_authentication_and_rate_limit_halts_survive_restart(self):
        for reason in ("AUTHENTICATION_REQUIRED", "HTTP_ACCESS_DENIED", "RATE_LIMITED"):
            with self.subTest(reason=reason):
                identity = {**self.identity, "port": 444 + len(self.manifest["http_services"])}
                key = self.budgets.ensure(identity)
                self.budgets.halt(key, reason)
                self.restart()
                self.assertEqual(self.budgets.remaining(key)["halted_reason"], reason)
                with self.assertRaises(StateError):
                    self.budgets.reserve(key, 1, 1)

    def test_parallel_reservations_cannot_overdraw_the_shared_service(self):
        def reserve_one(_):
            try:
                return self.budgets.reserve(self.key, 1, 1000)
            except StateError:
                return None

        with ThreadPoolExecutor(max_workers=12) as pool:
            tokens = [token for token in pool.map(reserve_one, range(40)) if token]
        self.assertEqual(len(tokens), 5)
        self.assertEqual(self.budgets.remaining(self.key)["requests"], 0)
        self.restart()
        self.assertEqual(self.budgets.remaining(self.key)["charged_requests"], 5)

    def test_failed_durable_append_does_not_publish_a_reservation(self):
        def fail(*_args):
            raise OSError("fixture fsync failed")

        self.ledger.append = fail
        with self.assertRaises(OSError):
            self.budgets.reserve(self.key, 5, 20000)
        self.assertEqual(self.budgets.remaining(self.key)["requests"], 5)

    def test_loaded_snapshots_reject_overdrawn_or_wrong_service_identity(self):
        for field, value in (("charged_requests", 6), ("schema_version", "2"),
                             ("identity", {**self.identity, "port": 80})):
            bad = copy.deepcopy(self.manifest)
            bad["http_services"][self.key][field] = value
            with self.subTest(field=field), self.assertRaises(StateError):
                ServiceBudgets(bad, self.ledger)


if __name__ == "__main__":
    unittest.main()
