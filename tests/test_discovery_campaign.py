"""Offline contracts for discovery, authorized scope and campaign accounting.

All public-source, DNS and Nmap boundaries are replaced with deterministic
fixtures. The separate loopback suite exercises the real Nmap executable.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scan
from test_campaign_report import xml_file


def source_result(*names, status="COMPLETED", reason=None):
    return {"status": status, "reason_code": reason or ("OK" if names else "EMPTY_RESULT"),
            "processing_complete": status == "COMPLETED", "exhaustive": False,
            "candidates": list(names), "candidate_count": len(names),
            "excluded_candidates": [], "rejected_count": 0, "rejection_counts": {},
            "warnings": ["PASSIVE_SOURCE_NOT_EXHAUSTIVE"], "finished_at": scan.utcnow()}


class DiscoveryCampaignTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="php2shell-discovery-campaign-")
        self.base = Path(self.temporary.name)
        self.counter = 0

    def tearDown(self):
        self.temporary.cleanup()

    def file(self, name, content):
        path = self.base / name
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def resolved(*_args):
        return {"dns_status": "RESOLVED", "addresses": ["192.0.2.10"], "dns_error": "",
                "dns_families": {"ipv4": {"status": "RESOLVED", "addresses": ["192.0.2.10"]}}}

    @staticmethod
    def completed_scan(command, endpoint, output, _timeout):
        arguments = Path(command[command.index("--script-args-file") + 1]).read_text()
        line = next(line for line in arguments.splitlines() if line.startswith("http-php2shell.vhost="))
        name = json.loads(line.split("=", 1)[1].rstrip(","))
        xml_file(output / endpoint["xml"], name=name, ip=endpoint["ip"],
                 state="PATCHED_VERSION_ADVERTISED", version="8.3.36")
        return {**endpoint, "status": "COMPLETED", "returncode": 0, "finished_at": scan.utcnow()}

    def execute(self, *options, roots="example.com\n", source=None, resolver=None, dry_run=True):
        self.counter += 1
        output = self.base / f"campaign-{self.counter}"
        argv = [str(option) for option in options]
        if roots is not None:
            root_file = self.file(f"roots-{self.counter}.txt", roots)
            argv += ["--discover-subdomains", str(root_file)]
        argv += ["--output", str(output), "--families", "ipv4", "--ports", "443"]
        if dry_run:
            argv += ["--dry-run"]
        if source is None:
            source = source_result("app.example.com")
        source_effect = (lambda *_a, **_k: deepcopy(source)) if isinstance(source, dict) else source
        with patch.object(scan, "discover_root", side_effect=source_effect) as provider, \
             patch.object(scan, "resolve_target", side_effect=resolver or self.resolved) as dns, \
             patch.object(scan.shutil, "which", return_value="/fixture/nmap"), \
             patch.object(scan.Processes, "run", side_effect=self.completed_scan) as runner, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = scan.run_campaign(scan.parser().parse_args(argv))
        data = json.loads((output / "manifest.json").read_text())
        return code, output, data, provider, dns, runner

    def test_one_option_seeds_roots_discovers_and_deduplicates(self):
        exact = self.file("known.txt", "APP.EXAMPLE.COM.\n")
        code, output, data, provider, dns, runner = self.execute(
            exact, roots="EXAMPLE.COM.\nexample.com # duplicate\n",
            source=source_result("app.example.com", "example.com", "deep.api.example.com"))
        self.assertEqual(code, 0)
        provider.assert_called_once()
        self.assertEqual(provider.call_args.args, ("example.com",))
        self.assertEqual(data["scope"]["domains"], ["example.com"])
        by_name = {item["hostname"]: item for item in data["targets"]}
        self.assertEqual(set(by_name), {"example.com", "app.example.com", "deep.api.example.com"})
        self.assertEqual(by_name["app.example.com"]["sources"], ["input:known.txt:1", "crt.sh:example.com"])
        self.assertEqual(by_name["example.com"]["sources"], ["root:roots-1.txt:1", "crt.sh:example.com"])
        self.assertEqual(dns.call_count, 3)
        runner.assert_not_called()
        self.assertEqual((output / "discovered.txt").read_text().splitlines(), sorted(by_name))
        self.assertEqual(set((output / "targets.txt").read_text().splitlines()), set(by_name))
        self.assertFalse(data["discovery"]["exhaustive"])
        self.assertEqual(data["discovery"]["resolved_count"], 3)
        self.assertEqual(json.loads((output / "discovery.json").read_text()), data["discovery"])
        self.assertEqual(list((output / "raw").glob("*.args")), [])

    def test_idna_roots_reach_source_and_scope_in_canonical_form(self):
        code, _, data, provider, dns, _ = self.execute(
            roots="CAFÉ.EXAMPLE.\n", source=source_result("app.xn--caf-dma.example"))
        self.assertEqual(code, 0)
        self.assertEqual(provider.call_args.args, ("xn--caf-dma.example",))
        self.assertEqual(data["scope"]["domains"], ["xn--caf-dma.example"])
        self.assertEqual({call.args[0] for call in dns.call_args_list},
                         {"xn--caf-dma.example", "app.xn--caf-dma.example"})

    def test_scope_exclusions_and_invalid_names_never_reach_dns(self):
        exclude = self.file("exclude.txt", "private.example.com\n*.legacy.example.com\n")
        names = ("app.example.com", "private.example.com", "x.legacy.example.com",
                 "evilexample.com", "example.com.evil.test", "*.example.com", "https://app.example.com")
        code, _, data, _, dns, _ = self.execute("--exclude", exclude, source=source_result(*names))
        self.assertEqual(code, 0)
        self.assertEqual({call.args[0] for call in dns.call_args_list}, {"example.com", "app.example.com"})
        self.assertEqual({item["reason"] for item in data["excluded_candidates"]},
                         {"EXCLUDED_BY_OPERATOR", "OUTSIDE_AUTHORIZED_DOMAINS", "INVALID_HOSTNAME"})
        self.assertEqual(data["discovery"]["retained_count"], 1)

    def test_root_scope_filters_combined_exact_targets_and_local_imports(self):
        exact = self.file("known.txt", "known.example.com\noutside.example.org\n")
        inventory = self.file("inventory.csv", "hostname,type\nimported.example.com,A\nforeign.example.org,A\n")
        code, _, data, _, dns, _ = self.execute(exact, "--discover-from", inventory)
        self.assertEqual(code, 0)
        self.assertEqual({call.args[0] for call in dns.call_args_list},
                         {"example.com", "known.example.com", "imported.example.com", "app.example.com"})
        self.assertEqual({item["hostname"] for item in data["excluded_candidates"]},
                         {"outside.example.org", "foreign.example.org"})

    def test_exact_target_mode_does_not_implicitly_query_public_source(self):
        exact = self.file("known.txt", "example.com\n")
        code, _, data, provider, dns, _ = self.execute(exact, roots=None)
        self.assertEqual(code, 0)
        provider.assert_not_called()
        self.assertEqual(dns.call_args.args[0], "example.com")
        self.assertNotIn("discovery", data)

    def test_empty_success_keeps_roots_and_never_claims_exhaustive_inventory(self):
        code, output, data, _, _, _ = self.execute(source=source_result(), dry_run=False)
        self.assertEqual(code, 0)
        self.assertEqual([item["hostname"] for item in data["targets"]], ["example.com"])
        self.assertEqual((output / "discovered.txt").read_text(), "")
        report = json.loads((output / "report.json").read_text())
        self.assertTrue(report["summary"]["discovery_processing_complete"])
        self.assertFalse(report["summary"]["discovery_exhaustive"])
        self.assertEqual(report["summary"]["discovery_candidates_count"], 0)

    def test_source_failure_keeps_successful_scans_but_campaign_and_csv_are_partial(self):
        code, output, data, _, _, runner = self.execute(
            source=source_result(status="FAILED", reason="TIMEOUT"), dry_run=False)
        self.assertEqual(code, 2)
        runner.assert_called_once()
        self.assertEqual(data["status"], "PARTIAL")
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["summary"]["assessments"], 1)
        self.assertFalse(report["summary"]["processing_complete"])
        discovery_rows = [row for row in report["rows"] if row["protocol"] == "discovery"]
        self.assertEqual(len(discovery_rows), 1)
        self.assertEqual(discovery_rows[0]["reason_code"], "DISCOVERY_TIMEOUT")
        self.assertEqual(discovery_rows[0]["state"], "NOT_ASSESSED")
        self.assertEqual(discovery_rows[0]["port"], "")
        with (output / "report.csv").open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        self.assertTrue(any(row["reason_code"] == "DISCOVERY_TIMEOUT" for row in rows))

    def test_useful_names_from_partial_source_still_get_assessed(self):
        code, output, data, _, _, runner = self.execute(
            source=source_result("app.example.com", status="PARTIAL", reason="PROVIDER_LIMIT_REACHED"),
            dry_run=False)
        self.assertEqual(code, 2)
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(data["discovery"]["resolved_count"], 1)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["summary"]["assessments"], 2)
        self.assertEqual(report["summary"]["discovery_status"], "PARTIAL")
        self.assertIn("DISCOVERY_PROVIDER_LIMIT_REACHED", {row["reason_code"] for row in report["rows"]})

    def test_rate_limit_stops_source_queries_and_records_remaining_roots(self):
        code, _, data, provider, _, _ = self.execute(
            roots="example.com\nexample.org\nexample.net\n",
            source=source_result(status="FAILED", reason="RATE_LIMITED"))
        self.assertEqual(code, 2)
        provider.assert_called_once()
        self.assertEqual([item["status"] for item in data["discovery"]["queries"]],
                         ["FAILED", "SKIPPED", "SKIPPED"])
        self.assertTrue(all(item["reason_code"] == "RATE_LIMITED" for item in data["discovery"]["queries"]))

    def test_budget_bounds_query_timeout_and_retains_unattempted_roots(self):
        clock = [100.0]

        def first_source(*_args, **_kwargs):
            clock[0] += 2
            return source_result("app.example.com")

        with patch.object(scan.time, "monotonic", side_effect=lambda: clock[0]):
            code, _, data, provider, _, _ = self.execute(
                "--discovery-budget", "1", "--discovery-timeout", "30",
                roots="example.com\nexample.org\n", source=first_source)
        self.assertEqual(code, 2)
        provider.assert_called_once()
        self.assertEqual(provider.call_args.kwargs["timeout"], 1)
        self.assertEqual(data["discovery"]["queries"][1]["reason_code"], "DISCOVERY_BUDGET_EXHAUSTED")

    def test_global_name_cap_prevents_queries_after_capacity_is_reached(self):
        code, output, data, provider, _, _ = self.execute(
            "--discovery-max-names", "2", roots="example.com\nexample.org\n",
            source=source_result("a.example.com", "b.example.com"))
        self.assertEqual(code, 2)
        provider.assert_called_once()
        self.assertEqual(data["discovery"]["candidates_count"], 2)
        self.assertEqual(data["discovery"]["queries"][1]["reason_code"], "NAME_LIMIT_REACHED")
        self.assertEqual(len((output / "discovered.txt").read_text().splitlines()), 2)

    def test_existing_targets_reduce_discovery_capacity_without_overflow(self):
        exact = self.file("known.txt", "known.example.com\n")
        with patch.object(scan, "MAX_TARGETS", 3):
            code, _, data, provider, dns, _ = self.execute(
                exact, source=source_result("a.example.com", "b.example.com"))
        self.assertEqual(code, 2)
        self.assertEqual(provider.call_args.kwargs["max_names"], 1)
        self.assertEqual(data["discovery"]["limits"]["effective_max_names"], 1)
        self.assertEqual(len(data["targets"]), 3)
        self.assertEqual(dns.call_count, 3)
        self.assertEqual(data["discovery"]["queries"][0]["reason_code"], "TARGET_LIMIT_REACHED")

    def test_overlapping_roots_keep_all_source_provenance_and_one_dns_lookup(self):
        code, _, data, provider, dns, _ = self.execute(
            roots="example.com\nzone.example.com\n",
            source=source_result("app.zone.example.com"))
        self.assertEqual(code, 0)
        self.assertEqual(provider.call_count, 2)
        target = next(item for item in data["targets"] if item["hostname"] == "app.zone.example.com")
        self.assertEqual(target["sources"], ["crt.sh:example.com", "crt.sh:zone.example.com"])
        self.assertEqual(sum(call.args[0] == "app.zone.example.com" for call in dns.call_args_list), 1)
        self.assertEqual(data["discovery"]["candidates_count"], 1)

    def test_exact_root_exclusion_keeps_child_discovery_enabled(self):
        exclude = self.file("exclude.txt", "example.com\n")
        code, _, data, provider, dns, _ = self.execute("--exclude", exclude)
        self.assertEqual(code, 0)
        provider.assert_called_once()
        self.assertEqual([call.args[0] for call in dns.call_args_list], ["app.example.com"])
        self.assertEqual(data["discovery"]["skipped_roots"], [])

    def test_excluded_descendant_namespace_skips_source_but_keeps_apex(self):
        exclude = self.file("exclude.txt", "*.example.com\n")
        code, output, data, provider, dns, _ = self.execute("--exclude", exclude, dry_run=False)
        self.assertEqual(code, 0)
        provider.assert_not_called()
        self.assertEqual(dns.call_args.args[0], "example.com")
        self.assertEqual(data["discovery"]["skipped_roots"],
                         [{"root": "example.com", "reason": "SUBDOMAINS_EXCLUDED_BY_OPERATOR"}])
        report = json.loads((output / "report.json").read_text())
        self.assertTrue(report["summary"]["discovery_processing_complete"])
        self.assertEqual(report["summary"]["discovery_roots_excluded"], 1)
        self.assertEqual(report["summary"]["discovery_coverage_rows"], 0)

    def test_wholly_excluded_scope_neither_queries_resolves_nor_scans(self):
        exclude = self.file("exclude.txt", "example.com\n*.example.com\n")
        code, _, data, provider, dns, runner = self.execute("--exclude", exclude, dry_run=False)
        self.assertEqual(code, 0)
        provider.assert_not_called()
        dns.assert_not_called()
        runner.assert_not_called()
        self.assertEqual(data["targets"], [])

    def test_historical_names_stay_in_artifacts_after_dns_absence(self):
        def lookup(name, *_args):
            if name == "old.example.com":
                return {"dns_status": "NO_ADDRESS", "addresses": [], "dns_error": ""}
            return self.resolved()

        code, output, data, _, _, runner = self.execute(
            source=source_result("old.example.com"), resolver=lookup, dry_run=False)
        self.assertEqual(code, 2)
        runner.assert_called_once()
        self.assertEqual((output / "discovered.txt").read_text(), "old.example.com\n")
        candidate = data["discovery"]["candidates"][0]
        self.assertTrue(candidate["retained"])
        self.assertEqual(candidate["dns_status"], "NO_ADDRESS")
        self.assertEqual(data["discovery"]["unresolved_count"], 1)
        self.assertTrue(data["discovery"]["processing_complete"])
        report = json.loads((output / "report.json").read_text())
        self.assertIn("NO_DNS_ADDRESS", {row["reason_code"] for row in report["rows"]})

    def test_interruption_persists_discovery_and_report_without_further_network(self):
        code, output, data, provider, dns, runner = self.execute(
            roots="example.com\nexample.org\n", source=KeyboardInterrupt, dry_run=False)
        self.assertEqual(code, 130)
        provider.assert_called_once()
        dns.assert_not_called()
        runner.assert_not_called()
        self.assertEqual(data["status"], "PARTIAL")
        self.assertEqual([item["status"] for item in data["discovery"]["queries"]], ["FAILED", "SKIPPED"])
        self.assertTrue(all(item["reason_code"] == "CAMPAIGN_INTERRUPTED"
                            for item in data["discovery"]["queries"]))
        self.assertEqual(json.loads((output / "discovery.json").read_text()), data["discovery"])
        self.assertTrue((output / "report.json").is_file())

    def test_interrupt_after_source_response_keeps_names_and_finishes_remaining_roots(self):
        original = scan.persist_discovery
        interrupted = False

        def persist(output, manifest):
            nonlocal interrupted
            discovery = manifest["discovery"]
            if not interrupted and discovery["candidates"]:
                interrupted = True
                raise KeyboardInterrupt
            original(output, manifest)

        exclude = self.file("exclude.txt", "private.example.com\n*.example.net\n")
        with patch.object(scan, "persist_discovery", side_effect=persist):
            code, output, data, provider, dns, runner = self.execute(
                "--exclude", exclude, roots="example.com\nexample.org\nexample.net\n",
                source=source_result("app.example.com", "private.example.com"), dry_run=False)
        self.assertTrue(interrupted)
        self.assertEqual(code, 130)
        provider.assert_called_once()
        dns.assert_not_called()
        runner.assert_not_called()
        self.assertEqual(data["status"], "PARTIAL")
        discovery = data["discovery"]
        self.assertEqual([query["status"] for query in discovery["queries"]], ["PARTIAL", "SKIPPED"])
        self.assertTrue(all(query["reason_code"] == "CAMPAIGN_INTERRUPTED" for query in discovery["queries"]))
        self.assertEqual(discovery["skipped_roots"],
                         [{"root": "example.net", "reason": "SUBDOMAINS_EXCLUDED_BY_OPERATOR"}])
        self.assertEqual(discovery["candidates_count"], 2)
        self.assertEqual(discovery["retained_count"], 1)
        self.assertEqual(discovery["unresolved_count"], 1)
        self.assertEqual((output / "discovered.txt").read_text(), "app.example.com\n")
        self.assertEqual(json.loads((output / "discovery.json").read_text()), discovery)
        self.assertTrue(discovery["finished_at"])
        report = json.loads((output / "report.json").read_text())
        self.assertFalse(report["summary"]["processing_complete"])
        with (output / "report.csv").open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(sum(row["reason_code"] == "DISCOVERY_CAMPAIGN_INTERRUPTED" for row in rows), 2)

    def test_interrupt_during_merge_or_snapshot_finishes_report_without_duplicate_exclusions(self):
        exclude = self.file("exclude.txt", "private.example.com\n")
        for function_name, interrupt_call, dns_completed in (
                ("merge_discovered_targets", 1, False),
                ("record_discovered_targets", 1, False),
                ("record_discovered_targets", 2, True)):
            original = getattr(scan, function_name)
            calls = 0

            def interrupt_once(*args, **kwargs):
                nonlocal calls
                calls += 1
                result = original(*args, **kwargs)
                if calls == interrupt_call:
                    raise KeyboardInterrupt
                return result

            with self.subTest(function=function_name, call=interrupt_call), \
                 patch.object(scan, function_name, side_effect=interrupt_once):
                code, output, data, provider, dns, runner = self.execute(
                    "--exclude", exclude, source=source_result("app.example.com", "private.example.com"),
                    dry_run=False)
            self.assertEqual(code, 130)
            provider.assert_called_once()
            self.assertEqual(dns.call_count, 2 if dns_completed else 0)
            runner.assert_not_called()
            self.assertEqual(data["status"], "PARTIAL")
            self.assertEqual(data["discovery"]["reason_code"], "CAMPAIGN_INTERRUPTED")
            self.assertFalse(data["discovery"]["processing_complete"])
            self.assertEqual(data["discovery"]["queries"][0]["status"], "COMPLETED")
            self.assertEqual({target["hostname"] for target in data["targets"]},
                             {"example.com", "app.example.com"})
            self.assertEqual(data["excluded_candidates"], [{"hostname": "private.example.com",
                "source": "crt.sh:example.com", "reason": "EXCLUDED_BY_OPERATOR"}])
            self.assertEqual((output / "discovered.txt").read_text(), "app.example.com\n")
            self.assertEqual(json.loads((output / "discovery.json").read_text()), data["discovery"])
            report = json.loads((output / "report.json").read_text())
            self.assertFalse(report["summary"]["processing_complete"])
            self.assertEqual(report["summary"]["assessments"], 0)
            self.assertTrue((output / "report.csv").is_file())

    def test_provider_exception_is_visible_and_root_scan_remains_available(self):
        code, _, data, _, dns, _ = self.execute(source=RuntimeError("fixture adapter failure"))
        self.assertEqual(code, 2)
        self.assertEqual(dns.call_count, 1)
        self.assertEqual(data["discovery"]["queries"][0]["reason_code"], "PROVIDER_ERROR")
        self.assertEqual(data["discovery"]["queries"][0]["error_type"], "RuntimeError")

    def test_recheck_does_not_turn_failed_source_namespace_into_a_scan_target(self):
        exact = self.file("known.txt", "app.example.com\n")
        exclude = self.file("exclude.txt", "example.com\n")
        code, output, _, _, _, _ = self.execute(
            exact, "--exclude", exclude, source=source_result(status="FAILED", reason="TIMEOUT"),
            dry_run=False)
        self.assertEqual(code, 2)
        # A source coverage row still names example.com. A normal recheck must
        # select the observed app only, even without repeating the exclusions.
        code, _, data, provider, dns, _ = self.execute(
            "--profile", "recontrole", "--previous", output / "report.json", roots=None)
        self.assertEqual(code, 0)
        provider.assert_not_called()
        self.assertEqual([target["hostname"] for target in data["targets"]], ["app.example.com"])
        self.assertEqual([call.args[0] for call in dns.call_args_list], ["app.example.com"])

    def test_invalid_local_inputs_fail_before_any_public_request(self):
        roots = self.file("roots.txt", "example.com\n")
        foreign = self.file("foreign-scope.txt", "example.org\n")
        bad_paths = self.file("bad-paths.txt", "/check#fragment\n")
        bad_inventory = self.file("bad-inventory.json", "{}")
        previous = self.file("previous.json", '{"schema_version":"1","rows":[]}')
        occupied = self.base / "occupied"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("keep")
        cases = [
            ["--scope", foreign], ["--paths-file", bad_paths], ["--inventory", bad_inventory],
            ["--output", occupied], ["--profile", "recontrole", "--previous", previous],
            ["--ports", "443;command"], ["--previous", self.file("bad-previous.json", "{}")],
        ]
        for options in cases:
            argv = ["--discover-subdomains", str(roots), "--dry-run", *map(str, options)]
            with self.subTest(options=options), patch.object(scan, "discover_root") as provider, \
                 patch.object(scan, "resolve_target") as dns, self.assertRaises(ValueError):
                scan.run_campaign(scan.parser().parse_args(argv))
            provider.assert_not_called()
            dns.assert_not_called()
        self.assertEqual((occupied / "keep.txt").read_text(), "keep")

    def test_missing_nmap_is_detected_before_discovery(self):
        roots = self.file("roots.txt", "example.com\n")
        with patch.object(scan.shutil, "which", return_value=None), \
             patch.object(scan, "discover_root") as provider, \
             self.assertRaisesRegex(scan.InputError, "Nmap"):
            scan.run_campaign(scan.parser().parse_args(["--discover-subdomains", str(roots)]))
        provider.assert_not_called()

    def test_invalid_empty_and_excess_root_files_never_start_discovery(self):
        for content in ("", "com\n", "*.example.com\n", "https://example.com\n", "192.0.2.1\n"):
            roots = self.file("roots.txt", content)
            with self.subTest(content=content), patch.object(scan, "discover_root") as provider, \
                 self.assertRaises(scan.InputError):
                scan.run_campaign(scan.parser().parse_args(["--discover-subdomains", str(roots), "--dry-run"]))
            provider.assert_not_called()
        roots = self.file("roots.txt", "example.com\nexample.org\n")
        with patch.object(scan, "MAX_DISCOVERY_ROOTS", 1), self.assertRaises(scan.InputError):
            scan.read_discovery_roots(roots)


if __name__ == "__main__":
    unittest.main()
