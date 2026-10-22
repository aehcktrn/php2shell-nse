"""Offline end-to-end report reconciliation and comparison contracts."""
from __future__ import annotations

from copy import deepcopy
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

import report
from runtime_inventory import CVES


def put(parent, tag, text=None, **attributes):
    node = ET.SubElement(parent, tag, attributes)
    node.text = text
    return node


def xml_file(path, name="application.example.com", ip="192.0.2.10", state="POTENTIALLY_VULNERABLE",
             version="8.3.35", *, empty=False, complete=True, port=443):
    root = ET.Element("nmaprun")
    if not empty:
        host = put(root, "host")
        put(host, "status", state="up")
        put(host, "address", addr=ip, addrtype="ipv6" if ":" in ip else "ipv4")
        names = put(host, "hostnames")
        put(names, "hostname", name=name, type="user")
        ports = put(host, "ports")
        service = put(ports, "port", portid=str(port), protocol="tcp")
        put(service, "state", state="open")
        put(service, "service", name="http", tunnel="ssl")
        script = put(service, "script", id="http-php2shell")
        for key, value in {"state": state, "reason": "Version evidence", "reason_code": "VERSION_BELOW_FIX",
                           "vhost": name, "scheme": "https", "path": "/index.php", "http_status": "200",
                           "exploitability": "NOT_TESTED", "php_detected": "YES", "requests_made": "2"}.items():
            put(script, "elem", value, key=key)
        versions = put(script, "table", key="versions")
        put(versions, "elem", version)
        observations = put(script, "table", key="observations")
        observation = put(observations, "table")
        put(observation, "elem", "/index.php", key="path")
        put(observation, "elem", "200", key="http_status")
        evidence = put(observation, "table", key="evidence")
        record = put(evidence, "table")
        put(record, "elem", "x-powered-by", key="source")
        put(record, "elem", version, key="version")
    if complete:
        stats = put(root, "runstats")
        put(stats, "finished", exit="success", time=str(int(datetime.now(timezone.utc).timestamp())))
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def target(name="application.example.com", ip="192.0.2.10", xml="raw/one.xml"):
    return {"hostname": name, "sources": ["input:domaines.txt"], "dns_status": "RESOLVED", "addresses": [ip],
            "endpoints": [{"ip": ip, "family": "ipv4", "status": "COMPLETED", "returncode": 0,
                           "xml": xml, "ports": "1-65535"}]}


def manifest(*targets):
    now = datetime.now(timezone.utc).isoformat()
    return {"schema_version": "1", "tool_version": "0.3.0", "campaign_id": "fixture", "started_at": now,
            "finished_at": now, "status": "COMPLETED", "profile": "complete", "ports": "1-65535",
            "address_families": ["ipv4", "ipv6"], "targets": list(targets)}


def discovery(root="example.com"):
    now = datetime.now(timezone.utc).isoformat()
    return {"enabled": True, "mode": "passive", "source": "crt.sh", "roots": [root],
            "status": "COMPLETED", "processing_complete": True, "exhaustive": False,
            "started_at": now, "finished_at": now,
            "candidates_count": 1, "retained_count": 1, "resolved_count": 1, "unresolved_count": 0,
            "candidates": [{"hostname": "application.example.com", "sources": ["crt.sh:example.com"],
                            "dns_status": "RESOLVED", "addresses": ["192.0.2.10"]}],
            "queries": [{"root": root, "source": "crt.sh", "status": "COMPLETED",
                         "processing_complete": True, "exhaustive": False, "candidate_count": 1,
                         "rejected_count": 0, "rejection_counts": {}, "excluded_candidates": [],
                         "warnings": [], "started_at": now, "finished_at": now}]}


class CampaignReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        xml_file(self.base / "raw/one.xml")

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, data=None, **kwargs):
        return report.build_campaign_report(data or manifest(target()), self.base, **kwargs)

    def test_counts_distinguish_domains_addresses_and_assessments(self):
        one = target()
        ip6 = "2001:db8::10"
        xml_file(self.base / "raw/ipv6.xml", ip=ip6)
        one["addresses"].append(ip6)
        one["endpoints"].append({"ip": ip6, "family": "ipv6", "status": "COMPLETED", "xml": "raw/ipv6.xml", "returncode": 0})
        broken = {"hostname": "broken.example.com", "dns_status": "DNS_ERROR", "dns_error": "NXDOMAIN", "endpoints": []}
        result = self.build(manifest(one, broken))
        summary = result["summary"]
        self.assertEqual((summary["targets_total"], summary["targets_resolved"], summary["targets_attempted"],
                          summary["targets_evaluated"]), (2, 1, 1, 1))
        self.assertEqual(summary["endpoints_completed"], 2)
        self.assertEqual(summary["assessments"], 2)
        self.assertFalse(summary["processing_complete"])
        self.assertEqual(result["rows"][-1]["reason_code"], "DNS_ERROR")
        self.assertEqual(result["rows"][-1]["state"], "NOT_ASSESSED")

    def test_partial_dualstack_dns_failure_is_visible_but_no_aaaa_is_normal(self):
        for status in ("ERROR", "TIMEOUT", "NO_ADDRESS"):
            item = target()
            item["dns_families"] = {
                "ipv4": {"status": "RESOLVED", "addresses": ["192.0.2.10"]},
                "ipv6": {"status": status, "addresses": [], "error": "resolver fixture"},
            }
            item["dns_partial"] = status in ("ERROR", "TIMEOUT")
            with self.subTest(status=status):
                result = self.build(manifest(item))
                gaps = [row for row in result["rows"] if row["reason_code"] == "DNS_FAMILY_ERROR"]
                self.assertEqual(len(gaps), 0 if status == "NO_ADDRESS" else 1)
                self.assertEqual(result["summary"]["assessments"], 1)
                self.assertEqual(result["summary"]["processing_complete"], status == "NO_ADDRESS")
                if gaps:
                    self.assertEqual(gaps[0]["address_family"], "ipv6")
                    self.assertEqual(gaps[0]["state"], "NOT_ASSESSED")
        item = {"hostname": "broken.example.com", "dns_status": "DNS_ERROR", "endpoints": [],
                "dns_families": {"ipv4": {"status": "ERROR"}, "ipv6": {"status": "TIMEOUT"}}}
        result = self.build(manifest(item))
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["reason_code"], "DNS_ERROR")

    def test_resolved_address_without_a_job_is_reported(self):
        item = target()
        item["addresses"].append("192.0.2.11")
        result = self.build(manifest(item))
        missing = [row for row in result["rows"] if row["ip"] == "192.0.2.11"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["reason_code"], "ADDRESS_NOT_ATTEMPTED")
        self.assertFalse(result["summary"]["processing_complete"])

    def test_failed_skipped_incomplete_and_unattempted_jobs_are_kept(self):
        for status, expected in [("TIMEOUT", "SCAN_TIMEOUT"), ("FAILED", "SCAN_FAILED"),
                                 ("RUNNING", "SCAN_INCOMPLETE"), ("SKIPPED", "SCAN_SKIPPED"),
                                 ("PLANNED", "SCAN_NOT_ATTEMPTED")]:
            item = target()
            item["endpoints"][0]["status"] = status
            with self.subTest(status=status):
                result = self.build(manifest(item))
                self.assertEqual(result["rows"][0]["reason_code"], expected)
                self.assertEqual(result["summary"]["assessments"], 0)
                self.assertEqual(result["rows"][0]["hostname"], item["hostname"])

    def test_empty_or_incomplete_xml_does_not_hide_target(self):
        for options, code in [({"empty": True}, "TARGET_MISSING_FROM_XML"),
                              ({"complete": False}, "INVALID_SCAN_XML")]:
            xml_file(self.base / "raw/one.xml", **options)
            with self.subTest(code=code):
                result = self.build()
                self.assertEqual(result["rows"][0]["reason_code"], code)
                self.assertEqual(result["summary"]["targets_total"], 1)
                self.assertEqual(result["summary"]["targets_evaluated"], 0)

    def test_same_ip_vhosts_are_distinct_and_provenance_survives(self):
        other = "other.example.com"
        xml_file(self.base / "raw/two.xml", name=other, state="PATCHED_VERSION_ADVERTISED", version="8.3.36")
        result = self.build(manifest(target(), target(other, xml="raw/two.xml")))
        self.assertEqual(len(result["rows"]), 2)
        self.assertNotEqual(result["rows"][0]["hostname"], result["rows"][1]["hostname"])
        self.assertEqual(result["summary"]["targets_evaluated"], 2)
        row = result["rows"][0]
        self.assertEqual(row["path"], "/index.php")
        self.assertEqual(row["source_xml"], "raw/one.xml")
        self.assertEqual(row["observations"][0]["evidence"][0]["version"], "8.3.35")
        self.assertEqual(row["target_sources"], ["input:domaines.txt"])

    def test_successful_scan_cannot_hide_discovery_failure(self):
        data = manifest(target())
        data["tool_version"] = "0.4.0"
        data["discovery"] = discovery()
        data["discovery"]["queries"][0].update(status="FAILED", processing_complete=False,
                                               reason_code="HTTP_429", error="Source rate limited")
        original = deepcopy(data)
        result = self.build(data)
        self.assertEqual(result["tool_version"], "0.4.0")
        self.assertEqual(result["summary"]["assessments"], 1)
        self.assertEqual(result["summary"]["endpoints_completed"], 1)
        self.assertFalse(result["summary"]["processing_complete"])
        self.assertFalse(result["summary"]["discovery_processing_complete"])
        self.assertEqual(result["summary"]["discovery_status"], "PARTIAL")
        self.assertEqual(result["summary"]["discovery_queries_incomplete"], 1)
        gap = next(row for row in result["rows"] if row["protocol"] == "discovery")
        self.assertEqual((gap["row_type"], gap["state"], gap["reason_code"]),
                         ("COVERAGE", "NOT_ASSESSED", "DISCOVERY_HTTP_429"))
        self.assertEqual((gap["hostname"], gap["service"], gap["port"], gap["ip"]),
                         ("example.com", "crt.sh", "", ""))
        self.assertEqual(gap["exploitability"], "NOT_TESTED")
        self.assertEqual(gap["inventory_patch_status"], "NOT_PROVIDED")
        self.assertIn("Relancer", gap["next_action"])
        self.assertEqual(data, original)

    def test_discovery_ledger_and_candidate_provenance_are_written(self):
        item = target()
        item["sources"].append("crt.sh:example.com")
        data = manifest(item)
        data["discovery"] = discovery()
        result = self.build(data)
        self.assertEqual(result["discovery"], data["discovery"])
        self.assertEqual(result["summary"]["discovery_candidates_count"], 1)
        self.assertEqual(result["summary"]["discovery_retained_count"], 1)
        self.assertEqual(result["summary"]["discovery_resolved_count"], 1)
        self.assertEqual(result["summary"]["discovery_unresolved_count"], 0)
        self.assertEqual(result["rows"][0]["target_sources"], item["sources"])
        self.assertNotIn("queries", result["campaign"]["discovery"])
        self.assertNotIn("candidates", result["campaign"]["discovery"])
        destination = self.base / "output"
        report.write_campaign_report(result, destination)
        saved = json.loads((destination / "report.json").read_text())
        self.assertEqual(saved["discovery"]["queries"], data["discovery"]["queries"])
        self.assertEqual(saved["discovery"]["candidates"], data["discovery"]["candidates"])

    def test_zero_discovery_results_are_processed_but_never_exhaustive(self):
        data = manifest(target())
        data["discovery"] = discovery()
        data["discovery"].update(candidates=[], candidates_count=0, retained_count=0,
                                 resolved_count=0, unresolved_count=0)
        data["discovery"]["queries"][0]["candidate_count"] = 0
        result = self.build(data)
        self.assertTrue(result["summary"]["processing_complete"])
        self.assertTrue(result["summary"]["discovery_processing_complete"])
        self.assertFalse(result["summary"]["discovery_exhaustive"])
        self.assertFalse(result["discovery"]["exhaustive"])
        self.assertEqual(result["summary"]["discovery_candidates_count"], 0)
        self.assertEqual(result["summary"]["coverage_rows"], 0)
        self.assertTrue(any("Aucun nom trouve ne signifie pas aucun sous-domaine" in text
                            for text in result["limitations"]))

    def test_limited_skipped_and_pending_discovery_queries_reach_csv(self):
        for status, code in (("PARTIAL", "RESPONSE_SIZE_LIMIT"),
                             ("PARTIAL", "CANDIDATE_LIMIT"),
                             ("SKIPPED", "DISCOVERY_INTERRUPTED"),
                             ("RUNNING", "")):
            with self.subTest(status=status, code=code):
                data = manifest(target())
                data["discovery"] = discovery()
                data["discovery"]["queries"][0].update(status=status, processing_complete=False, reason_code=code)
                result = self.build(data)
                destination = self.base / "output"
                report.write_campaign_report(result, destination)
                with (destination / "report.csv").open(newline="") as stream:
                    gap = next(row for row in csv.DictReader(stream) if row["protocol"] == "discovery")
                expected = code if code.startswith("DISCOVERY_") else "DISCOVERY_" + (code or status)
                self.assertEqual(gap["reason_code"], expected)
                self.assertEqual(gap["state"], "NOT_ASSESSED")
                self.assertFalse(result["summary"]["processing_complete"])
                self.assertEqual(result["summary"]["discovery_queries_incomplete"], 1)

    def test_unattempted_discovery_roots_remain_visible(self):
        data = manifest(target())
        data["discovery"] = discovery()
        data["discovery"]["roots"].append("example.org")
        result = self.build(data)
        gap = next(row for row in result["rows"] if row.get("protocol") == "discovery")
        self.assertEqual(gap["hostname"], "example.org")
        self.assertEqual(gap["reason_code"], "DISCOVERY_NOT_ATTEMPTED")
        self.assertEqual(result["summary"]["discovery_queries_unattempted"], 1)
        self.assertFalse(result["summary"]["processing_complete"])

    def test_deliberately_excluded_roots_are_not_unattempted_failures(self):
        data = manifest(target())
        data["discovery"] = discovery()
        data["discovery"].update(queries=[], skipped_roots=[
            {"root": "example.com", "reason": "SUBDOMAINS_EXCLUDED_BY_OPERATOR"}])
        result = self.build(data)
        self.assertTrue(result["summary"]["discovery_processing_complete"])
        self.assertTrue(result["summary"]["processing_complete"])
        self.assertEqual(result["summary"]["discovery_roots_excluded"], 1)
        self.assertEqual(result["summary"]["discovery_queries_unattempted"], 0)
        self.assertEqual(result["summary"]["discovery_coverage_rows"], 0)

    def test_aggregate_discovery_limit_cannot_be_hidden_by_complete_queries(self):
        data = manifest(target())
        data["discovery"] = discovery()
        data["discovery"].update(status="PARTIAL", processing_complete=False, reason_code="TOTAL_BUDGET_EXHAUSTED")
        result = self.build(data)
        self.assertFalse(result["summary"]["processing_complete"])
        self.assertEqual(result["summary"]["discovery_queries_completed"], 1)
        self.assertEqual(result["summary"]["discovery_queries_incomplete"], 0)
        self.assertEqual(result["summary"]["discovery_coverage_rows"], 1)
        self.assertEqual(result["rows"][-1]["reason_code"], "DISCOVERY_TOTAL_BUDGET_EXHAUSTED")

    def test_old_manifests_and_disabled_discovery_keep_existing_results(self):
        old = self.build()
        self.assertTrue(old["summary"]["processing_complete"])
        self.assertNotIn("discovery", old)
        self.assertNotIn("discovery_status", old["summary"])
        data = manifest(target())
        data["discovery"] = {"enabled": False}
        disabled = self.build(data)
        self.assertEqual(disabled["rows"], old["rows"])
        self.assertNotIn("discovery_status", disabled["summary"])
        self.assertEqual(disabled["limitations"], old["limitations"])

    def test_malformed_discovery_ledgers_fail_explicitly(self):
        for invalid in ([], {"enabled": "true"}, {"enabled": True, "roots": [], "queries": []},
                        {**discovery(), "candidates_count": -1},
                        {**discovery(), "queries": [{"root": "foreign.example.org"}]},
                        {**discovery(), "skipped_roots": [{"root": "example.com", "reason": "TIMEOUT"}]}):
            with self.subTest(invalid=invalid):
                data = manifest(target())
                data["discovery"] = invalid
                with self.assertRaises(report.ReportError):
                    self.build(data)

    def test_recheck_reports_actual_ports_and_preserves_scope_and_exclusions(self):
        first = target()
        first["endpoints"][0]["ports"] = "443"
        second_name = "other.example.com"
        second = target(second_name, xml="raw/two.xml")
        second["endpoints"][0]["ports"] = "8443"
        xml_file(self.base / "raw/two.xml", name=second_name, port=8443)
        third = target("timeout.example.com", xml="raw/timeout.xml")
        third["endpoints"][0].update(ports="8080", status="TIMEOUT")
        data = manifest(first, second, third)
        data.update(profile="recheck", http={"path": "/", "max_requests": 5},
                    limits={"jobs": 2}, scope={"domains": ["example.com"]},
                    excluded_candidates=[{"hostname": "foreign.example.org", "reason": "OUTSIDE_SCOPE", "sources": ["inventory.csv"]}])
        result = self.build(data)
        self.assertEqual({row["hostname"]: row["scan_ports"] for row in result["rows"]},
                         {"application.example.com": "443", second_name: "8443", "timeout.example.com": "8080"})
        self.assertEqual(result["campaign"]["ports"], "1-65535")
        for key in ("http", "limits", "scope"):
            self.assertEqual(result["campaign"][key], data[key])
        self.assertEqual(result["excluded_candidates"], data["excluded_candidates"])
        destination = self.base / "output"
        report.write_campaign_report(result, destination)
        with (destination / "report.csv").open(newline="") as stream:
            self.assertEqual([row["scan_ports"] for row in csv.DictReader(stream)], ["443", "8443", "8080"])
        self.assertEqual(json.loads((destination / "report.json").read_text())["excluded_candidates"], data["excluded_candidates"])

    def test_foreign_address_or_vhost_xml_is_not_relabelled_as_target(self):
        for options in ({"ip": "192.0.2.99"}, {"name": "foreign.example.com"}):
            xml_file(self.base / "raw/one.xml", **options)
            with self.subTest(options=options):
                result = self.build()
                self.assertEqual(result["rows"][0]["reason_code"], "INVALID_SCAN_XML")
                self.assertEqual(result["summary"]["assessments"], 0)

    def test_xml_cannot_escape_campaign_directory(self):
        item = target(xml="../../outside.xml")
        result = self.build(manifest(item))
        self.assertEqual(result["rows"][0]["reason_code"], "INVALID_SCAN_XML")
        (self.base / "raw/link.xml").symlink_to("/etc/passwd")
        item["endpoints"][0]["xml"] = "raw/link.xml"
        self.assertEqual(self.build(manifest(item))["rows"][0]["reason_code"], "INVALID_SCAN_XML")

    def test_disappearance_is_not_reported_as_corrected(self):
        before = self.build()
        current = {"schema_version": "1", "rows": []}
        changes = report.compare_reports(current, before)
        self.assertEqual(changes[0]["change"], "NO_LONGER_OBSERVED")
        self.assertEqual(changes[0]["previous_state"], "POTENTIALLY_VULNERABLE")
        self.assertEqual(changes[0]["current_state"], "")
        self.assertIn("correction non etablie", changes[0]["reason"])

    def test_comparison_tracks_version_state_path_and_inventory_changes(self):
        before = self.build()
        self.assertEqual(report.compare_reports(before, before)[0]["change"], "UNCHANGED")
        after = deepcopy(before)
        after["rows"][0].update(state="PATCHED_VERSION_ADVERTISED", versions="8.3.36", inventory_patch_status="PATCH_CONFIRMED")
        change = report.compare_reports(after, before)[0]
        self.assertEqual(change["change"], "CHANGED")
        self.assertEqual(change["current_state"], "PATCHED_VERSION_ADVERTISED")
        self.assertEqual(change["current_inventory_patch_status"], "PATCH_CONFIRMED")
        after = deepcopy(before)
        after["rows"][0]["path"] = "/new-path"
        self.assertEqual(report.compare_reports(after, before)[0]["change"], "CHANGED")
        after["rows"][0]["port"] = "8443"
        self.assertEqual({item["change"] for item in report.compare_reports(after, before)}, {"NEW", "NO_LONGER_OBSERVED"})

    def test_previous_report_import_and_json_csv_outputs(self):
        before = self.build()
        previous = self.base / "previous.json"
        previous.write_text(json.dumps(before))
        result = self.build(previous=previous)
        self.assertEqual(result["comparison"]["counts"], {"UNCHANGED": 1})
        destination = self.base / "output"
        report.write_campaign_report(result, destination)
        parsed = json.loads((destination / "report.json").read_text())
        self.assertEqual(parsed["rows"][0]["observations"], result["rows"][0]["observations"])
        self.assertTrue((destination / "changes.csv").is_file())
        with (destination / "report.csv").open(newline="") as stream:
            self.assertEqual(next(csv.DictReader(stream))["path"], "/index.php")

    def test_csv_source_and_reason_are_formula_safe(self):
        item = target()
        item["endpoints"][0].update(status="FAILED", error="=HYPERLINK(\"https://example.invalid\")")
        result = self.build(manifest(item))
        destination = self.base / "output"
        report.write_campaign_report(result, destination)
        with (destination / "report.csv").open(newline="") as stream:
            self.assertTrue(next(csv.DictReader(stream))["reason"].startswith("'="))

    def test_runtime_evidence_is_separate_and_network_state_unchanged(self):
        inventory = {"schema_version": "1", "records": [{
            "hostname": "application.example.com", "port": 443, "scheme": "https", "authenticated": True,
            "source": "authenticated-runtime-export", "evidence_reference": "evidence/current-workers.txt",
            "observed_at": datetime.now(timezone.utc).isoformat(), "covers_all_backends": True,
            "instances": [{"id": "pool-1", "runtime": "php-fpm", "version": "8.3.35", "package": "vendor-backport",
                           "active_runtime_verified": True, "cves": {cve: "fixed" for cve in CVES}}]}]}
        path = self.base / "runtime.json"
        path.write_text(json.dumps(inventory))
        result = self.build(inventory=path)
        row = result["rows"][0]
        self.assertEqual(row["state"], "POTENTIALLY_VULNERABLE")
        self.assertEqual(row["inventory_patch_status"], "PATCH_CONFIRMED")
        self.assertEqual(result["summary"]["inventory_counts"], {"PATCH_CONFIRMED": 1})
        self.assertEqual(len(result["inventory"]["sha256"]), 64)

    def test_bad_inventory_previous_or_manifest_fails_explicitly(self):
        bad = self.base / "bad.json"
        bad.write_text('{"schema_version":"1","records":[{}]}')
        with self.assertRaises(report.ReportError):
            self.build(inventory=bad)
        bad.write_text('{}')
        with self.assertRaises(report.ReportError):
            self.build(previous=bad)
        with self.assertRaises(report.ReportError):
            self.build(manifest(target(), target()))
        with self.assertRaises(report.ReportError):
            report.build_campaign_report({}, self.base)

    def test_serialization_failure_does_not_replace_existing_artifacts(self):
        result = self.build()
        destination = self.base / "output"
        report.write_campaign_report(result, destination)
        initial = (destination / "report.json").read_bytes()
        initial_csv = (destination / "report.csv").read_bytes()
        result["invalid"] = float("nan")
        with self.assertRaises(ValueError):
            report.write_campaign_report(result, destination)
        self.assertEqual((destination / "report.json").read_bytes(), initial)
        self.assertEqual((destination / "report.csv").read_bytes(), initial_csv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
