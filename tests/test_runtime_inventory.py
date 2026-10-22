"""Contract tests for local runtime attestations; no network or commands."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import runtime_inventory as runtime

NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
ROW = {"hostname": "application.example.com", "ip": "192.0.2.10", "port": "443", "scheme": "https"}


def record():
    return {"hostname": ROW["hostname"], "port": 443, "scheme": "https", "authenticated": True,
            "source": "authenticated-test-inventory", "evidence_reference": "evidence/runtime-and-advisories.txt",
            "observed_at": NOW.isoformat(), "covers_all_backends": True,
            "instances": [{"id": "web-1", "runtime": "php-fpm", "version": "8.3.36",
                           "package": "php8.3-fpm 8.3.36", "active_runtime_verified": True,
                           "cves": {cve: "fixed" for cve in runtime.CVES}}]}


def assess(*records, row=None, **options):
    return runtime.assess_runtime(row or ROW, {"records": list(records)}, now=NOW, **options)


class RuntimeInventoryTests(unittest.TestCase):
    def test_complete_active_authenticated_evidence_confirms_both_fixes(self):
        result = assess(record())
        self.assertEqual(result["inventory_patch_status"], "PATCH_CONFIRMED")
        self.assertIn("conditionnelle", result["inventory_trust_note"])
        self.assertEqual(result["inventory_instances"][0]["cves"], {cve: "fixed" for cve in runtime.CVES})

    def test_version_alone_and_disk_package_are_not_confirmation(self):
        for field in ("authenticated", "evidence_reference", "source", "observed_at"):
            sample = record()
            del sample[field]
            with self.subTest(field=field):
                self.assertEqual(assess(sample)["inventory_patch_status"], "UNVERIFIED")
        sample = record()
        sample["instances"][0]["active_runtime_verified"] = False
        self.assertEqual(assess(sample)["inventory_patch_status"], "UNVERIFIED")
        sample = record()
        del sample["instances"][0]["package"]
        self.assertEqual(assess(sample)["inventory_patch_status"], "UNVERIFIED")

    def test_vendor_backport_can_be_attested_without_new_upstream_number(self):
        sample = record()
        sample["instances"][0].update(version="7.4.33", package="vendor-php 7.4.33-patched-build")
        self.assertEqual(assess(sample)["inventory_patch_status"], "PATCH_CONFIRMED")

    def test_both_cves_required(self):
        sample = record()
        del sample["instances"][0]["cves"][runtime.CVES[1]]
        self.assertEqual(assess(sample)["inventory_patch_status"], "UNVERIFIED")
        sample["instances"][0]["cves"][runtime.CVES[1]] = "unknown"
        self.assertEqual(assess(sample)["inventory_patch_status"], "PARTIAL")

    def test_any_active_affected_instance_is_actionable_even_with_partial_coverage(self):
        sample = record()
        sample["covers_all_backends"] = False
        second = deepcopy(sample["instances"][0])
        second["id"] = "web-2"
        second["cves"][runtime.CVES[1]] = "affected"
        sample["instances"].append(second)
        self.assertEqual(assess(sample)["inventory_patch_status"], "PATCH_MISSING_CONFIRMED")

    def test_all_fixed_but_partial_coverage_stays_partial(self):
        sample = record()
        sample["covers_all_backends"] = False
        self.assertEqual(assess(sample)["inventory_patch_status"], "PARTIAL")

    def test_stale_future_and_timezone_free_evidence_do_not_confirm(self):
        for value, expected in [((NOW - timedelta(days=2)).isoformat(), "STALE"),
                                ((NOW + timedelta(hours=1)).isoformat(), "UNVERIFIED"),
                                ("2026-10-22T12:00:00", "UNVERIFIED")]:
            sample = record()
            sample["observed_at"] = value
            with self.subTest(value=value):
                self.assertEqual(assess(sample)["inventory_patch_status"], expected)

    def test_invalid_age_is_rejected(self):
        for value in (0, -1, float("inf"), float("nan"), True):
            with self.subTest(value=value), self.assertRaises(runtime.InventoryError):
                assess(record(), max_age_hours=value)

    def test_duplicate_instance_and_conflicting_records_fail_closed(self):
        sample = record()
        sample["instances"].append(deepcopy(sample["instances"][0]))
        self.assertEqual(assess(sample)["inventory_patch_status"], "CONFLICT")
        old, new = record(), record()
        old["instances"][0]["cves"][runtime.CVES[0]] = "affected"
        self.assertEqual(assess(old, new)["inventory_patch_status"], "CONFLICT")

    def test_incompatible_exhaustive_backend_sets_are_conflicting(self):
        one, two = record(), record()
        two["instances"][0]["id"] = "different-runtime"
        self.assertEqual(assess(one, two)["inventory_patch_status"], "CONFLICT")

    def test_bad_or_stale_matching_record_cannot_be_hidden_by_good_one(self):
        one, two = record(), record()
        two["authenticated"] = False
        self.assertEqual(assess(one, two)["inventory_patch_status"], "UNVERIFIED")
        two = record()
        two["observed_at"] = (NOW - timedelta(days=2)).isoformat()
        self.assertEqual(assess(one, two)["inventory_patch_status"], "STALE")

    def test_binding_respects_name_port_scheme_and_optional_ip(self):
        for key, value in (("hostname", "other.example.com"), ("port", 8443), ("scheme", "http"),
                           ("ip", "192.0.2.11")):
            sample = record()
            sample[key] = value
            with self.subTest(key=key):
                self.assertEqual(assess(sample)["inventory_patch_status"], "NOT_PROVIDED")
        sample = record()
        sample["hostname"] = "APPLICATION.EXAMPLE.COM."
        sample["ip"] = "192.0.2.10"
        self.assertEqual(assess(sample)["inventory_patch_status"], "PATCH_CONFIRMED")

    def test_no_evidence_does_not_overwrite_network_fields(self):
        row = {**ROW, "state": "POTENTIALLY_VULNERABLE"}
        self.assertEqual(runtime.assess_runtime(row, None)["inventory_patch_status"], "NOT_PROVIDED")
        self.assertEqual(row["state"], "POTENTIALLY_VULNERABLE")

    def test_duplicate_json_assertions_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text('{"schema_version":"1","records":[],"records":[]}')
            with self.assertRaises(runtime.InventoryError):
                runtime.load_inventory(path)

    def test_load_preserves_hash_and_rejects_bad_envelopes_and_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text(json.dumps({"schema_version": "1", "records": [record()]}))
            loaded = runtime.load_inventory(path)
            self.assertEqual(len(loaded["sha256"]), 64)
            self.assertEqual(loaded["filename"], path.name)
            for data in ({}, {"schema_version": "1", "records": [{}]},
                         {"schema_version": "1", "records": [{**record(), "port": True}]},
                         {"schema_version": "1", "records": [{**record(), "hostname": "bad.example.com/other"}]}):
                path.write_text(json.dumps(data))
                with self.subTest(data=data), self.assertRaises(runtime.InventoryError):
                    runtime.load_inventory(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
