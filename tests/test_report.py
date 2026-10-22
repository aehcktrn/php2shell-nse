"""Offline report contracts; no Nmap installation or network access is needed."""
from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("php2shell_report", ROOT / "report.py")
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


def element(parent, tag, text=None, **attributes):
    child = ET.SubElement(parent, tag, attributes)
    child.text = text
    return child


def host(root, ip="192.0.2.10", name="app.example.test", status="up"):
    item = element(root, "host")
    element(item, "status", state=status)
    element(item, "address", addr=ip, addrtype="ipv4")
    names = element(item, "hostnames")
    if name:
        element(names, "hostname", name=name, type="user")
    element(names, "hostname", name="ptr.example.test", type="PTR")
    return item


def port(host_item, number=443, service="http", state="open", protocol="tcp", tunnel="ssl"):
    ports = host_item.find("ports")
    if ports is None:
        ports = element(host_item, "ports")
    item = element(ports, "port", portid=str(number), protocol=protocol)
    element(item, "state", state=state)
    element(item, "service", name=service, tunnel=tunnel)
    return item


def script(port_item, state="POTENTIALLY_VULNERABLE", versions=("8.3.35",), suspect=False):
    item = element(port_item, "script", id="http-php2shell", output="human-readable output")
    element(item, "elem", state, key="state")
    element(item, "elem", "NOT_TESTED", key="exploitability")
    element(item, "elem", "Version-based fixture.", key="reason")
    element(item, "elem", "200", key="http_status")
    values = element(item, "table", key="versions")
    for value in versions:
        element(values, "elem", value)
    fixed = element(item, "table", key="fixed_versions")
    element(fixed, "elem", "8.3.36")
    element(item, "elem", str(suspect).lower(), key="potentially_vulnerable_evidence")
    return item


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="php2shell-report-tests-")
        self.path = Path(self.temp.name)
        self.source = self.path / "scan.xml"
        self.destination = self.path / "report.csv"
        self.root = ET.Element("nmaprun")

    def tearDown(self):
        self.temp.cleanup()

    def save(self, *, complete=True, exit_status="success"):
        if complete:
            stats = element(self.root, "runstats")
            element(stats, "finished", exit=exit_status)
        ET.ElementTree(self.root).write(self.source, encoding="utf-8", xml_declaration=True)
        return self.source

    def test_assessment_preserves_exact_fields_and_patch_guidance(self):
        item = script(port(host(self.root)))
        element(item, "elem", "CORRIGER OU VERIFIER LE BACKPORT", key="verdict")
        element(item, "elem", "Installer PHP >= 8.3.36.", key="remediation")
        element(item, "elem", "Verifier les workers actifs.", key="verification")
        observations = element(item, "table", key="observations")
        observation = element(observations, "table")
        element(observation, "elem", "REDIRECT_NOT_ASSESSED", key="reason_code")
        element(observation, "elem", "https://outside.example.test/path?[redacted]", key="redirect_to")
        rows = report.parse_report(self.save())
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["row_type"], "ASSESSMENT")
        self.assertEqual(row["state"], "POTENTIALLY_VULNERABLE")
        self.assertEqual(row["priority"], "PATCH_OR_VERIFY_BACKPORT")
        self.assertEqual(row["hostname"], "app.example.test")
        self.assertEqual(row["service"], "ssl/http")
        self.assertEqual(row["fixed_versions"], "8.3.36")
        self.assertEqual(row["remediation"], "Installer PHP >= 8.3.36.")
        self.assertEqual(row["redirect_destinations"], "https://outside.example.test/path?[redacted]")
        self.assertEqual(row["redirect_evaluation_scope"], "HORS_PERIMETRE_DU_CONTROLE")
        report.write_report(rows, self.destination, self.source, detailed=True)
        with self.destination.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(tuple(reader.fieldnames), report.FIELDS)
            exported = next(reader)
            self.assertEqual(exported["verification"], "Verifier les workers actifs.")
            self.assertEqual(exported["redirect_evaluation_scope"], "HORS_PERIMETRE_DU_CONTROLE")

    def test_open_nonweb_and_web_ports_without_nse_are_coverage(self):
        item = host(self.root)
        port(item, 22, service="ssh", tunnel="")
        port(item, 8443)
        rows = report.parse_report(self.save())
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["port"] for row in rows}, {"22", "8443"})
        for row in rows:
            self.assertEqual(row["row_type"], "COVERAGE")
            self.assertEqual(row["state"], "NOT_ASSESSED")

    def test_down_and_no_open_tcp_hosts_still_have_coverage_rows(self):
        host(self.root, ip="192.0.2.20", status="down")
        item = host(self.root, ip="192.0.2.21")
        port(item, 443, state="filtered")
        port(item, 53, protocol="udp", service="domain", tunnel="")
        rows = report.parse_report(self.save())
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["ip"] for row in rows}, {"192.0.2.20", "192.0.2.21"})
        self.assertTrue(all(row["state"] == "NOT_ASSESSED" for row in rows))
        self.assertTrue(all(not row.get("port") for row in rows))

    def test_same_ip_virtual_hosts_are_not_merged(self):
        script(port(host(self.root, name="first.example.test")))
        script(port(host(self.root, name="second.example.test")), state="PATCHED_VERSION_ADVERTISED",
               versions=("8.3.36",))
        rows = report.parse_report(self.save())
        self.assertEqual(len(rows), 2)
        self.assertEqual([row["hostname"] for row in rows], ["first.example.test", "second.example.test"])
        self.assertEqual(rows[0]["ip"], rows[1]["ip"])
        self.assertNotEqual(rows[0]["state"], rows[1]["state"])

    def test_explicit_vhost_names_the_assessed_application(self):
        item = script(port(host(self.root, name="scanned.example.test")))
        element(item, "elem", "requested.example.test", key="vhost")
        row = report.parse_report(self.save())[0]
        self.assertEqual(row["hostname"], "requested.example.test")
        self.assertEqual(row["ip"], "192.0.2.10")

    def test_unknown_with_suspect_evidence_retains_priority(self):
        item = script(port(host(self.root)), state="UNKNOWN", versions=("8.3.35", "8.3.36"))
        evidence = element(item, "table", key="evidence")
        record = element(evidence, "table")
        element(record, "elem", "POTENTIALLY_VULNERABLE", key="state")
        element(record, "elem", "8.3.36", key="fixed_version")
        row = report.parse_report(self.save())[0]
        self.assertEqual(row["state"], "UNKNOWN")
        self.assertEqual(row["priority"], "VERIFY_PRIORITY")
        self.assertEqual(row["versions"], "8.3.35 | 8.3.36")

    def test_suspect_boolean_alone_is_enough_for_priority(self):
        script(port(host(self.root)), state="UNKNOWN", suspect=True)
        self.assertEqual(report.parse_report(self.save())[0]["priority"], "VERIFY_PRIORITY")

    def test_hidden_version_requires_runtime_verification(self):
        script(port(host(self.root)), state="UNKNOWN", versions=())
        row = report.parse_report(self.save())[0]
        self.assertEqual(row["priority"], "VERIFY_RUNTIME")
        self.assertEqual(row["versions"], "")

    def test_script_error_without_structured_output_is_not_assessed(self):
        element(port(host(self.root)), "script", id="http-php2shell", output="ERROR: Script execution failed")
        self.assertEqual(report.parse_report(self.save())[0]["state"], "NOT_ASSESSED")

    def test_structured_script_error_is_not_assessed(self):
        item = script(port(host(self.root)), state="UNKNOWN", versions=())
        element(item, "elem", "Invalid script argument.", key="error")
        self.assertEqual(report.parse_report(self.save())[0]["state"], "NOT_ASSESSED")

    def test_invalid_or_duplicate_state_is_not_assessed(self):
        script(port(host(self.root)), state="NOT_VULNERABLE")
        other = script(port(host(self.root, name="other.example.test")))
        element(other, "elem", "PATCHED_VERSION_ADVERTISED", key="state")
        rows = report.parse_report(self.save())
        self.assertTrue(all(row["state"] == "NOT_ASSESSED" for row in rows))

    def test_conflicting_patched_claim_is_not_assessed(self):
        script(port(host(self.root)), state="PATCHED_VERSION_ADVERTISED", suspect=True)
        self.assertEqual(report.parse_report(self.save())[0]["state"], "NOT_ASSESSED")

    def test_missing_or_wrongly_typed_versions_cannot_establish_patched_state(self):
        script(port(host(self.root)), state="PATCHED_VERSION_ADVERTISED", versions=())
        item = script(port(host(self.root, name="second.example.test")),
                      state="PATCHED_VERSION_ADVERTISED", versions=("8.3.36",))
        item.remove(item.find("table[@key='versions']"))
        element(item, "elem", "8.3.36", key="versions")
        self.assertTrue(all(row["state"] == "NOT_ASSESSED" for row in report.parse_report(self.save())))

    def test_duplicate_script_outputs_are_not_assessed(self):
        item = port(host(self.root))
        script(item)
        script(item)
        rows = report.parse_report(self.save())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "NOT_ASSESSED")

    def test_legacy_result_can_derive_fixed_version_from_evidence(self):
        item = script(port(host(self.root)))
        item.remove(item.find("table[@key='fixed_versions']"))
        evidence = element(item, "table", key="evidence")
        record = element(evidence, "table")
        element(record, "elem", "8.3.36", key="fixed_version")
        row = report.parse_report(self.save())[0]
        self.assertEqual(row["fixed_versions"], "8.3.36")
        self.assertTrue(row["remediation"])

    def test_formula_and_control_prefixed_cells_are_text(self):
        malicious = ["=1+1", "+cmd", "-cmd", "@SUM(A1)", "  =1+1", "\t=1+1",
                     "\r=1+1", "\n=1+1", "\x00=1+1", "\ufeff=1+1", "\ttext"]
        for value in malicious:
            with self.subTest(value=value):
                self.assertEqual(report.safe_cell(value), "'" + value)
        self.assertEqual(report.safe_cell("8.3.36"), "8.3.36")
        self.assertEqual(report.safe_cell("normal host"), "normal host")
        script(port(host(self.root, name="=HYPERLINK(\"https://example.invalid\")")),
               versions=("+cmd",))
        report.write_report(report.parse_report(self.save()), self.destination, self.source, detailed=True)
        with self.destination.open(encoding="utf-8", newline="") as stream:
            row = next(csv.DictReader(stream))
            self.assertTrue(row["hostname"].startswith("'="))
            self.assertTrue(row["versions"].startswith("'+"))

    def test_csv_escaping_and_unicode_are_preserved(self):
        item = script(port(host(self.root)))
        item.find("elem[@key='reason']").text = 'Version "ancienne", vérification\nrequise.'
        report.write_report(report.parse_report(self.save()), self.destination, self.source, detailed=True)
        with self.destination.open(encoding="utf-8", newline="") as stream:
            self.assertEqual(next(csv.DictReader(stream))["reason"], 'Version "ancienne", vérification\nrequise.')

    def test_malformed_or_incomplete_scan_never_replaces_existing_report(self):
        self.destination.write_text("existing report", encoding="utf-8")
        inputs = ["<nmaprun>", "<notnmap />", "<nmaprun />",
                  '<nmaprun><runstats><finished exit="error" /></runstats></nmaprun>']
        for content in inputs:
            with self.subTest(content=content):
                self.source.write_text(content, encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(report.main([str(self.source), "-o", str(self.destination)]), 2)
                self.assertEqual(self.destination.read_text(encoding="utf-8"), "existing report")

    def test_input_cannot_be_overwritten_directly_or_through_aliases(self):
        self.save()
        initial = self.source.read_bytes()
        aliases = [self.source, self.path / "hardlink.xml", self.path / "symlink.xml"]
        os.link(self.source, aliases[1])
        aliases[2].symlink_to(self.source)
        for output in aliases:
            with self.subTest(output=output):
                with self.assertRaises(report.ReportError):
                    report.write_report([], output, self.source)
        self.assertEqual(self.source.read_bytes(), initial)

    def test_cli_summary_counts_assessments_and_coverage_separately(self):
        item = host(self.root)
        script(port(item))
        port(item, 22, service="ssh", tunnel="")
        self.save()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(report.main([str(self.source), "-o", str(self.destination), "--detailed"]), 0)
        self.assertIn("Evaluations PHP2Shell: 1", output.getvalue())
        self.assertIn("Lignes de couverture sans evaluation: 1", output.getvalue())
        self.assertIn("ne signifie pas vulnerable", output.getvalue())
        self.assertTrue(self.destination.is_file())

    def test_successful_empty_scan_produces_header_only(self):
        rows = report.parse_report(self.save())
        self.assertEqual(rows, [])
        report.write_report(rows, self.destination, self.source)
        with self.destination.open(encoding="utf-8", newline="") as stream:
            self.assertEqual(list(csv.reader(stream)), [["cible", "php", "vulnerable", "explication"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
