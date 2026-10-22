"""Offline campaign contracts: scope, DNS accounting and safe command construction."""
from __future__ import annotations

from contextlib import redirect_stdout
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scan
from test_campaign_report import xml_file


EXPECTED_QUICK_PORTS = "80,443,8000,8008,8080-8081,8443,8888,9000,9443"


class CampaignInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="php2shell-input-tests-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def file(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def args(self, *options):
        return scan.parser().parse_args([str(item) for item in options])

    def collect(self, args):
        args.profile = scan.PROFILES.get(args.profile, args.profile)
        return scan.collect_targets(args, scan.scope_rules(args.scope, args.exclude), scan.read_previous(args.previous))

    def resolved(self, *_args):
        return {"dns_status": "RESOLVED", "addresses": ["192.0.2.10"], "dns_error": "",
                "dns_families": {"ipv4": {"status": "RESOLVED", "addresses": ["192.0.2.10"]}}}

    def assert_indeterminate_report(self, output, hostname):
        compact = json.loads((output / "report.json").read_text())
        self.assertIsInstance(compact, list)
        self.assertEqual(len(compact), 1)
        row = compact[0]
        fields = ("cible", "php", "vulnerable", "explication")
        self.assertEqual(set(row), set(fields))
        self.assertEqual((row["cible"], row["php"], row["vulnerable"]),
                         (hostname, "INCONNUE", "INDETERMINE"))
        self.assertTrue(row["explication"])
        with (output / "report.csv").open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(tuple(reader.fieldnames), fields)
            self.assertEqual(list(reader), compact)

    def test_single_file_runs_quick_scan_and_creates_results_without_setup(self):
        targets = self.file("domains.txt", "app.example.com\n")

        def completed(_command, endpoint, output, _timeout):
            xml_file(output / endpoint["xml"], name="app.example.com", ip=endpoint["ip"],
                     state="PATCHED_VERSION_ADVERTISED", version="8.3.36")
            return {**endpoint, "status": "COMPLETED", "returncode": 0,
                    "finished_at": scan.utcnow()}

        original_directory = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.object(scan, "resolve_target", side_effect=self.resolved), \
                 patch.object(scan, "discover_root") as provider, \
                 patch.object(scan.shutil, "which", return_value="/fixture/nmap"), \
                 patch.object(scan.Processes, "run", side_effect=completed) as runner, \
                 redirect_stdout(io.StringIO()):
                code = scan.run_campaign(self.args(targets))
        finally:
            os.chdir(original_directory)
        self.assertEqual(code, 0)
        provider.assert_not_called()
        runner.assert_called_once()
        outputs = list((self.root / "results").iterdir())
        self.assertEqual(len(outputs), 1)
        output = outputs[0]
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["profile"], "quick")
        self.assertEqual(manifest["ports"], EXPECTED_QUICK_PORTS)
        self.assertEqual(manifest["targets"][0]["endpoints"][0]["ports"], EXPECTED_QUICK_PORTS)
        command = runner.call_args.args[0]
        self.assertEqual(command[command.index("-p") + 1], EXPECTED_QUICK_PORTS)
        self.assertEqual([item["file"] for item in manifest["inputs"]], ["domains.txt"])
        self.assertEqual(manifest["scope"]["mode"], "exact")
        self.assertEqual((output / "targets.txt").read_text(), "app.example.com\n")
        compact = json.loads((output / "report.json").read_text())
        self.assertEqual(len(compact), 1)
        self.assertEqual((compact[0]["cible"], compact[0]["php"], compact[0]["vulnerable"]),
                         ("app.example.com", "8.3.36", "NON"))
        self.assertTrue((output / "report.csv").is_file())
        self.assertFalse((output / "discovered.txt").exists())
        self.assertEqual({item.name for item in self.root.iterdir()}, {"domains.txt", "results"})
        self.assertEqual(targets.read_text(), "app.example.com\n")

    def test_explicit_profiles_and_custom_ports_still_control_the_plan(self):
        targets = self.file("domains.txt", "app.example.com\n")
        cases = (
            (("--profile", "complet"), "complete", "1-65535"),
            (("--profile", "complete"), "complete", "1-65535"),
            (("--profile", "rapide"), "quick", EXPECTED_QUICK_PORTS),
            (("--profile", "quick"), "quick", EXPECTED_QUICK_PORTS),
            (("--ports", "8443,443"), "quick", "443,8443"),
            (("--profile", "complet", "--ports", "8443"), "complete", "8443"),
        )
        for index, (options, profile, ports) in enumerate(cases):
            output = self.root / f"plan-{index}"
            with self.subTest(options=options), \
                 patch.object(scan, "resolve_target", side_effect=self.resolved), \
                 patch.object(scan, "discover_root") as provider, \
                 patch.object(scan.Processes, "run") as runner, redirect_stdout(io.StringIO()):
                code = scan.run_campaign(self.args(targets, *options, "--dry-run", "--output", output))
            self.assertEqual(code, 0)
            provider.assert_not_called()
            runner.assert_not_called()
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["profile"], profile)
            self.assertEqual(manifest["ports"], ports)
            self.assertEqual(manifest["targets"][0]["endpoints"][0]["ports"], ports)

    def test_hostname_normalization_and_idna(self):
        self.assertEqual(scan.hostname("WWW.Example.COM."), "www.example.com")
        self.assertEqual(scan.hostname("café.example"), "xn--caf-dma.example")

    def test_target_syntax_cannot_expand_into_networks_or_flags(self):
        for value in ("https://app.example/", "app.example:443", "*.example.com", "example.com/8",
                      "--script=all", "127.0.0.1", "::1", "foo..example", "a.example b.example",
                      "a.example\n--script", "a.example;id", "@example.com"):
            with self.subTest(value=value), self.assertRaises(scan.InputError):
                scan.hostname(value)

    def test_exact_input_rejects_invalid_line_with_location(self):
        source = self.file("domains.txt", "app.example.com\n*.example.com\n")
        with self.assertRaisesRegex(scan.InputError, "domains.txt:2"):
            scan.exact_hosts(source)

    def test_scope_checks_dns_label_boundary(self):
        scope = self.file("scope.txt", "example.com\n")
        rules = scan.scope_rules(scope, None)
        self.assertIsNone(scan.exclusion_reason("example.com", rules))
        self.assertIsNone(scan.exclusion_reason("old.app.example.com", rules))
        for foreign in ("evilexample.com", "example.com.evil.test", "example.org"):
            self.assertEqual(scan.exclusion_reason(foreign, rules), "OUTSIDE_AUTHORIZED_DOMAINS")

    def test_exact_and_subdomain_exclusions_are_distinct(self):
        exclusions = self.file("exclude.txt", "portal.example.com\n*.legacy.example.com\n")
        rules = scan.scope_rules(None, exclusions)
        self.assertEqual(scan.exclusion_reason("portal.example.com", rules), "EXCLUDED_BY_OPERATOR")
        self.assertEqual(scan.exclusion_reason("x.legacy.example.com", rules), "EXCLUDED_BY_OPERATOR")
        self.assertIsNone(scan.exclusion_reason("legacy.example.com", rules))
        self.assertIsNone(scan.exclusion_reason("sub.portal.example.com", rules))

    def test_discovery_requires_explicit_scope(self):
        source = self.file("inventory.txt", "app.example.com\n")
        with self.assertRaisesRegex(scan.InputError, "exige --scope"):
            self.collect(self.args("--discover-from", source))

    def test_discovery_filters_foreign_names_and_dns_record_types(self):
        source = self.file("dns.csv", "name,type,value\nold.example.com,CNAME,provider.example.net\n"
                           "example.com,TXT,ignored\nforeign.example.net,A,192.0.2.2\n"
                           "*.example.com,A,192.0.2.3\n")
        scope = self.file("scope.txt", "example.com\n")
        targets, rejected = self.collect(self.args("--scope", scope, "--discover-from", source))
        self.assertEqual([item["hostname"] for item in targets], ["old.example.com"])
        self.assertEqual({item["reason"] for item in rejected},
                         {"NOT_AN_ADDRESS_RECORD", "OUTSIDE_AUTHORIZED_DOMAINS", "INVALID_HOSTNAME"})

    def test_duplicate_names_preserve_provenance(self):
        exact = self.file("domains.txt", "app.example.com\nAPP.EXAMPLE.COM. # comment\n")
        source = self.file("inventory.json", json.dumps({"records": [{"hostname": "app.example.com"}]}))
        scope = self.file("scope.txt", "example.com")
        targets, rejected = self.collect(self.args(exact, "--scope", scope, "--discover-from", source))
        self.assertEqual(len(targets), 1)
        self.assertEqual(len(targets[0]["sources"]), 3)
        self.assertEqual(rejected, [])

    def test_json_and_tsv_import_formats(self):
        for name, contents in (("list.json", '["app.example.com"]'),
                               ("export.json", '{"targets":[{"fqdn":"app.example.com"}]}'),
                               ("export.tsv", "hostname\ttype\napp.example.com\tA\n")):
            path = self.file(name, contents)
            self.assertEqual(list(scan.discovery_records(path))[0][0], "app.example.com")

    def test_ambiguous_inventory_columns_are_rejected(self):
        source = self.file("ambiguous.json", '[{"hostname":"a.example.com","domain":"b.example.com"}]')
        self.assertEqual(list(scan.discovery_records(source))[0][2], "AMBIGUOUS_HOST_FIELDS")

    def test_ports_are_normalized_and_cannot_inject_arguments(self):
        self.assertEqual(scan.port_expression("443,80,8000-8002,8001"), "80,443,8000-8002")
        self.assertEqual(scan.port_expression("1-65535"), "1-65535")
        for value in ("", "0", "65536", "80 --script all", "T:80", "443-80", "80,", "*", "80;id"):
            with self.subTest(value=value), self.assertRaises(scan.InputError):
                scan.port_expression(value)

    def test_unicode_path_is_uri_encoded_before_nse_arguments(self):
        value = scan.valid_path("/café?q=été")
        self.assertEqual(value, "/caf%C3%A9?q=%C3%A9t%C3%A9")
        arguments = scan.nse_arguments("app.example.com", [value], self.args())
        self.assertNotIn("\\u", arguments)
        self.assertIn("/caf%C3%A9", arguments)

    def test_single_path_omits_empty_optional_nse_array(self):
        arguments = scan.nse_arguments("app.example.com", ["/"], self.args())
        self.assertIn('http-php2shell.path="/"', arguments)
        self.assertNotIn("http-php2shell.paths=", arguments)
        multiple = scan.nse_arguments("app.example.com", ["/", "/legacy"], self.args())
        self.assertIn('http-php2shell.paths={"/legacy"}', multiple)

    def test_paths_reject_foreign_origins_fragments_and_controls(self):
        for value in ("https://app.example/path", "//app.example/path", "/a#fragment", "/a\nb", "/a b", "/a\\b"):
            with self.subTest(value=value), self.assertRaises(scan.InputError):
                scan.valid_path(value)

    def test_fragment_in_paths_file_is_not_silently_removed(self):
        targets = self.file("domains.txt", "app.example.com")
        paths = self.file("paths.txt", "/index.php#fragment\n")
        with self.assertRaises(scan.InputError), patch.object(scan, "resolve_target") as resolver:
            scan.run_campaign(self.args(targets, "--paths-file", paths, "--dry-run"))
        resolver.assert_not_called()

    def test_excess_paths_fail_before_dns_or_scanning(self):
        targets = self.file("domains.txt", "app.example.com")
        paths = self.file("paths.txt", "\n".join(f"/path-{i}" for i in range(11)))
        with self.assertRaisesRegex(scan.InputError, "11 chemins"), patch.object(scan, "resolve_target") as resolver:
            scan.run_campaign(self.args(targets, "--paths-file", paths, "--dry-run"))
        resolver.assert_not_called()

    def test_command_pins_dns_ip_and_keeps_hostname_out_of_target_arguments(self):
        args = self.args("--families", "ipv6", "--ports", "443")
        args.nmap_datadir = None
        endpoint = {"ip": "2001:db8::10", "family": "ipv6", "ports": "443"}
        command = scan.command_for("/usr/bin/nmap", endpoint, self.root / "file.args", self.root / "raw", args)
        self.assertEqual(command[-1], "2001:db8::10")
        self.assertIn("-6", command)
        self.assertNotIn("--resolve-all", command)
        self.assertEqual(command[command.index("--script-timeout") + 1], "22s")

    def test_dns_normal_absence_of_aaaa_is_not_partial_failure(self):
        payload = {"addresses": ["192.0.2.10"], "families": {
            "ipv4": {"status": "RESOLVED", "addresses": ["192.0.2.10"]},
            "ipv6": {"status": "NO_ADDRESS", "addresses": []}}}
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload) + "\n", "")
        with patch.object(scan.subprocess, "run", return_value=completed):
            result = scan.resolve_target("app.example.com", ["ipv4", "ipv6"], 1)
        self.assertEqual(result["dns_status"], "RESOLVED")
        self.assertFalse(result["dns_partial"])

    def test_dns_timeout_preserves_successful_family(self):
        partial = {"addresses": ["192.0.2.10"], "families": {
            "ipv4": {"status": "RESOLVED", "addresses": ["192.0.2.10"]}}}
        error = subprocess.TimeoutExpired([], 1, output=(json.dumps(partial) + "\n").encode())
        with patch.object(scan.subprocess, "run", side_effect=error):
            result = scan.resolve_target("app.example.com", ["ipv4", "ipv6"], 1)
        self.assertEqual(result["addresses"], ["192.0.2.10"])
        self.assertTrue(result["dns_partial"])
        self.assertEqual(result["dns_families"]["ipv6"]["status"], "TIMEOUT")

    def test_dns_total_timeout_retains_both_family_failures(self):
        with patch.object(scan.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 1)):
            result = scan.resolve_target("app.example.com", ["ipv4", "ipv6"], 1)
        self.assertEqual(result["dns_status"], "DNS_ERROR")
        self.assertEqual(set(result["dns_families"]), {"ipv4", "ipv6"})

    def test_recheck_preserves_suspect_paths_from_observations(self):
        previous = {"rows": [{"hostname": "app.example.com", "port": "443", "path": "/",
                     "state": "UNKNOWN", "observations": [{"path": "/"}, {"path": "/legacy"}],
                     "evidence": [{"path": "/another-app"}]}]}
        ports, paths = scan.recheck_targets(previous)
        self.assertEqual(ports["app.example.com"], {443})
        self.assertEqual(paths["app.example.com"], ["/", "/legacy", "/another-app"])

    def test_recheck_skips_only_confirmed_inventory_rows(self):
        previous = {"rows": [{"hostname": "fixed.example.com", "port": "443", "inventory_patch_status": "PATCH_CONFIRMED"},
                              {"hostname": "banner.example.com", "port": "443", "state": "PATCHED_VERSION_ADVERTISED"}]}
        ports, _ = scan.recheck_targets(previous)
        self.assertNotIn("fixed.example.com", ports)
        self.assertIn("banner.example.com", ports)

    def test_recheck_requires_explicit_query_values_before_any_network_activity(self):
        previous = self.file("previous.json", json.dumps({"schema_version": "1", "rows": [
            {"hostname": "app.example.com", "port": "443", "path": "/legacy?[redacted]"}]}))
        with self.assertRaisesRegex(scan.InputError, "parametres"), patch.object(scan, "resolve_target") as resolver:
            scan.run_campaign(self.args("--profile", "recontrole", "--previous", previous, "--dry-run"))
        resolver.assert_not_called()

    def test_compact_previous_without_details_fails_before_network_activity(self):
        targets = self.file("domains.txt", "app.example.com")
        previous = self.file("previous.json", json.dumps([{
            "cible": "app.example.com", "php": "8.3.35", "vulnerable": "OUI",
            "explication": "Version anterieure au correctif.",
        }]))
        output = self.root / "unstarted"
        with patch.object(scan, "resolve_target") as resolver, \
             patch.object(scan, "discover_root") as provider, \
             patch.object(scan.Processes, "run") as runner, self.assertRaises(scan.InputError):
            scan.run_campaign(self.args(targets, "--previous", previous, "--dry-run", "--output", output))
        resolver.assert_not_called()
        provider.assert_not_called()
        runner.assert_not_called()
        self.assertFalse(output.exists())

    def test_dry_run_keeps_all_targets_and_redacts_arguments(self):
        targets = self.file("domains.txt", "app.example.com\n")
        output = self.root / "preview"
        with patch.object(scan, "resolve_target", side_effect=self.resolved), \
             patch.object(scan.Processes, "run") as runner, redirect_stdout(io.StringIO()):
            result = scan.run_campaign(self.args(targets, "--dry-run", "--path", "/check?token=SECRET",
                                                "--output", output, "--nmap", "does-not-exist"))
        self.assertEqual(result, 0)
        runner.assert_not_called()
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["targets"][0]["hostname"], "app.example.com")
        self.assertEqual(manifest["targets"][0]["endpoints"][0]["ip"], "192.0.2.10")
        self.assertNotIn("SECRET", json.dumps(manifest))
        self.assertEqual(list((output / "raw").glob("*.args")), [])
        self.assertFalse((output / "report.json").exists())

    def test_output_directory_is_never_overwritten(self):
        targets = self.file("domains.txt", "app.example.com")
        output = self.root / "already"
        output.mkdir()
        preserved = output / "report.json"
        preserved.write_text("preserve me")
        with self.assertRaisesRegex(scan.InputError, "vide"), patch.object(scan, "resolve_target") as resolver:
            scan.run_campaign(self.args(targets, "--dry-run", "--output", output))
        resolver.assert_not_called()
        self.assertEqual(preserved.read_text(), "preserve me")

    def test_dns_failure_produces_report_and_nonzero_completion(self):
        targets = self.file("domains.txt", "missing.example.com")
        output = self.root / "missing"
        failure = {"dns_status": "DNS_ERROR", "dns_error": "fixture DNS failure", "addresses": []}
        with patch.object(scan, "resolve_target", return_value=failure), \
             patch.object(scan.shutil, "which", return_value="/fixture/nmap"), \
             patch.object(scan.Processes, "run") as runner, redirect_stdout(io.StringIO()):
            code = scan.run_campaign(self.args(targets, "--output", output))
        runner.assert_not_called()
        self.assertEqual(code, 2)
        report = json.loads((output / "raw" / "report-details.json").read_text())
        self.assertEqual(report["summary"]["targets_total"], 1)
        self.assertEqual(report["summary"]["targets_evaluated"], 0)
        self.assertEqual(report["rows"][0]["reason_code"], "DNS_ERROR")
        self.assertEqual(report["campaign"]["status"], "PARTIAL")
        self.assert_indeterminate_report(output, "missing.example.com")

    def test_nmap_failure_is_retained_and_temporary_arguments_removed(self):
        targets = self.file("domains.txt", "app.example.com")
        output = self.root / "failed"
        def failed(_command, endpoint, _base, _timeout):
            return {**endpoint, "status": "FAILED", "returncode": 1, "error": "fixture failure"}
        with patch.object(scan, "resolve_target", side_effect=self.resolved), \
             patch.object(scan.shutil, "which", return_value="/fixture/nmap"), \
             patch.object(scan.Processes, "run", side_effect=failed), redirect_stdout(io.StringIO()):
            code = scan.run_campaign(self.args(targets, "--output", output))
        self.assertEqual(code, 2)
        report = json.loads((output / "raw" / "report-details.json").read_text())
        self.assertEqual(report["rows"][0]["reason_code"], "SCAN_FAILED")
        self.assertEqual(list((output / "raw").glob("*.args")), [])
        self.assert_indeterminate_report(output, "app.example.com")

    def test_dns_interruption_preserves_manifest_and_report(self):
        targets = self.file("domains.txt", "app.example.com")
        output = self.root / "interrupted"
        with patch.object(scan, "resolve_target", side_effect=self.resolved), \
             patch.object(scan.shutil, "which", return_value="/fixture/nmap"), \
             patch.object(scan, "as_completed", side_effect=KeyboardInterrupt), \
             patch.object(scan.Processes, "run") as runner, redirect_stdout(io.StringIO()):
            code = scan.run_campaign(self.args(targets, "--output", output))
        self.assertEqual(code, 130)
        runner.assert_not_called()
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "PARTIAL")
        self.assertTrue((output / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
