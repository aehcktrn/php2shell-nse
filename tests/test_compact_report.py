"""Compact operator reports, with offline fixtures and no network access."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import csv
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import report


def assessment(hostname="app.example.com", *, state="PATCHED_VERSION_ADVERTISED",
               version="8.3.36", ip="192.0.2.10", port="443", **extra):
    return {
        "hostname": hostname, "ip": ip, "port": port, "protocol": "tcp",
        "service": "ssl/http", "row_type": "ASSESSMENT", "state": state,
        "versions": version, "fixed_versions": "8.3.36",
        "reason": "Version observation", "reason_code": "FIXED_VERSION_ADVERTISED",
        "php_detected": "YES", "traversal_complete": "true", "budget_exhausted": "false",
        "inventory_patch_status": "NOT_PROVIDED", "exploitability": "NOT_TESTED",
        **extra,
    }


def coverage(hostname="app.example.com", *, code="SCAN_FAILED", ip="192.0.2.11", **extra):
    return {"hostname": hostname, "ip": ip, "protocol": "tcp", "row_type": "COVERAGE",
            "state": "NOT_ASSESSED", "reason_code": code, "reason": "Fixture coverage failure", **extra}


def details(rows):
    return {"schema_version": "1", "tool_version": "0.4.1", "rows": rows,
            "campaign": {"campaign_id": "fixture"}, "changes": [], "summary": {"processing_complete": True}}


class CompactReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="php2shell-compact-")
        self.base = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def save(self, name, value):
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return path

    def compact(self, *rows):
        result = report.compact_rows(list(rows))
        self.assertEqual(len(result), 1)
        self.assertEqual(tuple(result[0]), report.COMPACT_FIELDS)
        self.assertTrue(all(isinstance(value, str) for value in result[0].values()))
        self.assertTrue(all(value == report._single_line(value) for value in result[0].values()))
        return result[0]

    def cli(self, source, output, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = report.main([str(source), "-o", str(output), *extra])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_one_target_aggregates_all_ips_ports_and_distinct_php_versions(self):
        rows = [assessment(ip="192.0.2.10"), assessment(ip="2001:db8::10", port="8443", version="8.4.23"),
                assessment(ip="192.0.2.11", port="8080", state="POTENTIALLY_VULNERABLE", version="8.3.35"),
                assessment(ip="192.0.2.10")]
        result = self.compact(*rows)
        self.assertEqual(result["cible"], "app.example.com")
        self.assertEqual(result["php"], "8.3.36 | 8.4.23 | 8.3.35")
        self.assertEqual(result["vulnerable"], "OUI")
        self.assertIn("annoncée", result["explication"])
        self.assertIn("192.0.2.11:8080", result["explication"])
        self.assertIn("8.3.36", result["explication"])
        self.assertIn("mettre à jour", result["explication"])
        self.assertTrue(result["explication"].startswith("Ports évalués : 443,8080,8443."))

    def test_port_80_does_not_hide_other_assessed_ports_in_the_explanation(self):
        rows = [assessment(port="80", state="POTENTIALLY_VULNERABLE", version="8.3.35"),
                assessment(port="443", state="POTENTIALLY_VULNERABLE", version="8.3.35"),
                assessment(port="8443"), assessment(port="443", ip="2001:db8::10")]
        result = self.compact(*rows)
        self.assertEqual(result["vulnerable"], "OUI")
        self.assertEqual(result["php"], "8.3.35 | 8.3.36")
        self.assertTrue(result["explication"].startswith("Ports évalués : 80,443,8443."))
        self.assertIn("mettre à jour PHP", result["explication"])

    def test_hidden_versions_still_show_each_assessed_port(self):
        result = self.compact(assessment(port="80", state="UNKNOWN", version="", reason_code="PHP_VERSION_HIDDEN"),
                              assessment(port="443", state="UNKNOWN", version="", reason_code="PHP_VERSION_HIDDEN"))
        self.assertEqual((result["php"], result["vulnerable"]), ("INCONNUE", "INDETERMINE"))
        self.assertTrue(result["explication"].startswith("Ports évalués : 80,443."))
        self.assertIn("2 contrôles indéterminés", result["explication"])

    def test_same_ip_http_to_https_redirect_is_covered_by_assessed_destination(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://app.example.com:443/"}],
        )
        for destination_state, version, expected in (
                ("PATCHED_VERSION_ADVERTISED", "8.3.36", "NON"),
                ("POTENTIALLY_VULNERABLE", "8.3.35", "OUI")):
            with self.subTest(destination_state=destination_state):
                result = self.compact(
                    redirect,
                    assessment(port="443", scheme="https", state=destination_state, version=version,
                               reason_code=("FIXED_VERSION_ADVERTISED" if expected == "NON"
                                            else "AFFECTED_VERSION_ADVERTISED")),
                )
                self.assertEqual(result["vulnerable"], expected)
                self.assertTrue(result["explication"].startswith("Ports évalués : 80,443."))

    def test_redirect_requires_conclusive_destination_on_same_ip_and_name(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://app.example.com/"}],
        )
        for destination in (
                assessment(port="443", scheme="https", state="UNKNOWN", version="",
                           reason_code="PHP_VERSION_HIDDEN"),
                assessment(port="443", scheme="https", ip="192.0.2.11")):
            with self.subTest(destination=destination):
                self.assertEqual(self.compact(redirect, destination)["vulnerable"], "INDETERMINE")
        foreign_redirect = deepcopy(redirect)
        foreign_redirect["observations"][0]["redirect_to"] = "https://other.example.com/"
        result = self.compact(foreign_redirect, assessment(port="443", scheme="https"))
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertIn("HORS PÉRIMÈTRE DU CONTRÔLE", result["explication"])
        self.assertIn("https://other.example.com/", result["explication"])

    def test_unassessed_redirect_destinations_are_deduplicated_and_bounded(self):
        row = assessment(
            state="UNKNOWN", version="", reason_code="REDIRECT_NOT_ASSESSED",
            observations=[
                {"reason_code": "REDIRECT_NOT_ASSESSED", "redirect_to": "https://one.example.net/"},
                {"reason_code": "REDIRECT_NOT_ASSESSED", "redirect_to": "https://one.example.net/"},
                {"reason_code": "REDIRECT_NOT_ASSESSED", "redirect_to": "https://two.example.net/path"},
                {"reason_code": "REDIRECT_NOT_ASSESSED", "redirect_to": "https://three.example.net/"},
            ],
        )
        result = self.compact(row)
        self.assertIn("destinations non évaluées", result["explication"])
        self.assertEqual(result["explication"].count("https://one.example.net/"), 1)
        self.assertIn("https://two.example.net/path", result["explication"])
        self.assertIn("(+1 autre)", result["explication"])
        self.assertLessEqual(len(result["explication"]), 360)

    def test_out_of_scope_redirect_remains_visible_when_source_has_version_evidence(self):
        result = self.compact(assessment(observations=[{
            "reason_code": "FIXED_VERSION_ADVERTISED",
            "redirect_to": "https://outside.example.net/",
            "redirect_followed": "false",
            "redirect_reason": "Redirect leaves the current origin.",
        }]))
        self.assertEqual(result["vulnerable"], "NON")
        self.assertIn("HORS PÉRIMÈTRE DU CONTRÔLE", result["explication"])
        self.assertIn("https://outside.example.net/", result["explication"])

    def test_old_compact_redirect_explanation_remains_accepted(self):
        old = details([assessment(
            state="UNKNOWN", version="", reason_code="REDIRECT_NOT_ASSESSED",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://outside.example.net/"}],
        )])
        compact = report.compact_rows(old["rows"], include_redirect_destinations=False)
        self.save("report.json", compact)
        self.save("raw/report-details.json", old)
        self.assertEqual(report.load_campaign_report(self.base / "report.json"), old)

    def test_port_summary_preserves_mixed_service_versions_and_verdicts(self):
        for unknown_https in (False, True):
            with self.subTest(unknown_https=unknown_https):
                rows = [assessment(port="80", state="POTENTIALLY_VULNERABLE", version="8.3.35"),
                        assessment(port="443", state="UNKNOWN" if unknown_https else "PATCHED_VERSION_ADVERTISED",
                                   version="" if unknown_https else "8.3.36", reason_code="PHP_VERSION_HIDDEN"),
                        assessment(port="8080")]
                result = self.compact(*rows)
                previous = report.compact_rows(rows, legacy_explanation=True)[0]
                self.assertEqual({key: result[key] for key in ("cible", "php", "vulnerable")},
                                 {key: previous[key] for key in ("cible", "php", "vulnerable")})
                self.assertEqual((result["php"], result["vulnerable"]), ("8.3.35 | 8.3.36", "OUI"))
                self.assertTrue(result["explication"].startswith("Ports évalués : 80,443,8080."))
                self.assertIn("mettre à jour PHP", result["explication"])
                if unknown_https:
                    self.assertIn("Contrôles incomplets : 1", result["explication"])

    def test_all_ten_quick_profile_ports_fit_in_the_summary(self):
        ports = (80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443)
        result = self.compact(*(assessment(port=str(port)) for port in reversed(ports)))
        self.assertTrue(result["explication"].startswith(
            "Ports évalués : 80,443,8000,8008,8080,8081,8443,8888,9000,9443."))
        self.assertNotIn("autres", result["explication"])

    def test_open_ports_without_nse_are_distinct_from_assessed_and_requested_ports(self):
        result = self.compact(assessment(port="80", scan_ports="22,80,443,8443"),
                              coverage(port="443", code="SERVICE_NOT_ASSESSED", service="ssl/http"),
                              coverage(port="22", code="SERVICE_NOT_ASSESSED", service="ssh", service_method="probed"))
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertTrue(result["explication"].startswith(
            "Ports évalués : 80. Ports ouverts sans évaluation PHP : 443."))
        self.assertNotIn("22", result["explication"])
        self.assertNotIn("8443", result["explication"])

    def test_same_port_with_an_unassessed_address_retains_both_coverage_categories(self):
        result = self.compact(assessment(port="443"),
                              coverage(port="443", code="SERVICE_NOT_ASSESSED", ip="2001:db8::10"))
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertTrue(result["explication"].startswith(
            "Ports évalués : 443. Ports ouverts sans évaluation PHP : 443."))
        self.assertIn("[2001:db8::10]:443", result["explication"])

    def test_large_port_lists_stay_visible_and_bounded_with_an_explicit_remainder(self):
        rows = [assessment(port=str(port), state="UNKNOWN", version="", reason_code="CUSTOM", reason="failure " * 100)
                for port in range(10000, 10014)]
        rows.extend(coverage(port=str(port), code="SERVICE_NOT_ASSESSED", reason="failure " * 100)
                    for port in range(20000, 20014))
        result = self.compact(*rows)
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertLessEqual(len(result["explication"]), 360)
        self.assertTrue(result["explication"].startswith(
            "Ports évalués : 10000,10001,10002,10003,10004,10005,10006,10007,10008,10009 (+4 autres). "
            "Ports ouverts sans évaluation PHP : 20000,20001,20002,20003,20004,20005,20006,20007,20008,20009 (+4 autres)."))
        self.assertIn("Service ouvert sans évaluation PHP exploitable", result["explication"])

    def test_port_summary_is_reserved_when_the_explanation_reaches_its_limit(self):
        rows = [assessment(port=str(port), state="UNKNOWN", version="8.3.35", reason_code="CUSTOM",
                           reason="failure " * 100, potentially_vulnerable_evidence=True,
                           inventory_patch_status="UNVERIFIED", ip="2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
                for port in range(10000, 10014)]
        rows.append(assessment(port="10000", ip="192.0.2.10"))
        result = self.compact(*rows)
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertEqual(len(result["explication"]), 360)
        self.assertTrue(result["explication"].startswith(
            "Ports évalués : 10000,10001,10002,10003,10004,10005,10006,10007,10008,10009 (+4 autres)."))
        self.assertIn("failure", result["explication"])
        self.assertTrue(result["explication"].endswith("…"))

    def test_failed_scan_never_turns_requested_ports_into_assessments(self):
        result = self.compact(coverage(code="SCAN_FAILED", scan_ports="80,443,8443"))
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertNotIn("Ports évalués", result["explication"])
        self.assertNotIn("Ports ouverts", result["explication"])

    def test_virtual_hosts_sharing_an_ip_remain_separate(self):
        result = report.compact_rows([assessment("a.example.com"), assessment("b.example.com")])
        self.assertEqual([row["cible"] for row in result], ["a.example.com", "b.example.com"])
        self.assertEqual([row["vulnerable"] for row in result], ["NON", "NON"])

    def test_xml_without_hostname_uses_ip(self):
        result = self.compact(assessment(hostname="", ip="2001:db8::10"))
        self.assertEqual(result["cible"], "2001:db8::10")

    def test_cardinality_465_domains_with_duplicate_endpoints_and_discovery(self):
        rows = []
        for index in range(465):
            name = f"app{index}.example.com"
            rows.extend([assessment(name), assessment(name), assessment(name, ip="2001:db8::1", port="8443")])
        rows.extend([coverage("example.com", protocol="discovery"), coverage("", protocol="discovery")])
        result = report.compact_rows(rows)
        self.assertEqual(len(result), 465)
        self.assertEqual(len({row["cible"] for row in result}), 465)
        self.assertTrue(all(row["vulnerable"] == "NON" for row in result))
        self.assertNotIn("example.com", {row["cible"] for row in result})

    def test_discovery_only_produces_no_php_target(self):
        self.assertEqual(report.compact_rows([coverage("example.com", protocol="discovery")]), [])

    def test_hidden_version_and_php_not_identified_are_indeterminate(self):
        for code in ("PHP_VERSION_HIDDEN", "PHP_NOT_IDENTIFIED", "UNRECOGNIZED_BUILD"):
            with self.subTest(code=code):
                result = self.compact(assessment(state="UNKNOWN", version="", reason_code=code))
                self.assertEqual((result["php"], result["vulnerable"]), ("INCONNUE", "INDETERMINE"))
                self.assertTrue(result["explication"])

    def test_unknown_service_keeps_suspicious_observed_versions_without_false_certainty(self):
        result = self.compact(assessment(state="UNKNOWN", version="8.3.35 | 8.3.36",
                                        reason_code="CONFLICTING_VERSIONS", potentially_vulnerable_evidence=True))
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertEqual(result["php"], "8.3.35 | 8.3.36")
        self.assertIn("contradictoires", result["explication"])
        self.assertIn("concernée observée", result["explication"])

    def test_unknown_php_on_one_endpoint_cannot_be_hidden_by_a_corrected_one(self):
        result = self.compact(assessment(), assessment(ip="2001:db8::10", state="UNKNOWN", version="",
                                                     reason_code="PHP_VERSION_HIDDEN"))
        self.assertEqual(result["php"], "8.3.36")
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertIn("[2001:db8::10]:443", result["explication"])

    def test_dns_and_nmap_gaps_never_become_non(self):
        for code in ("DNS_ERROR", "DNS_FAMILY_ERROR", "NO_DNS_ADDRESS", "ADDRESS_NOT_ATTEMPTED",
                     "SCAN_FAILED", "SCAN_TIMEOUT", "SCAN_INCOMPLETE", "SCAN_SKIPPED", "SCAN_NOT_ATTEMPTED",
                     "INVALID_SCAN_XML", "TARGET_MISSING_FROM_XML", "NO_OPEN_TCP_PORT"):
            with self.subTest(code=code):
                result = self.compact(assessment(), coverage(code=code))
                self.assertEqual(result["vulnerable"], "INDETERMINE")
                self.assertEqual(result["php"], "8.3.36")

    def test_http_gaps_remain_indeterminate_even_with_server_patch_attestation(self):
        gaps = [{"traversal_complete": False}, {"budget_exhausted": True}]
        gaps.extend({"reason_code": code} for code in report.HTTP_GAP_CODES)
        for gap in gaps:
            with self.subTest(gap=gap):
                result = self.compact(assessment(inventory_patch_status="PATCH_CONFIRMED", **gap))
                self.assertEqual(result["vulnerable"], "INDETERMINE")
                self.assertIn("attestés", result["explication"])

    def test_real_positive_survives_other_coverage_gaps_and_mentions_them(self):
        result = self.compact(assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35"), coverage())
        self.assertEqual(result["vulnerable"], "OUI")
        self.assertIn("incomplets", result["explication"])

    def test_ssh_is_ignored_only_when_nmap_actually_probed_it(self):
        for method, expected in (("probed", "NON"), ("table", "INDETERMINE"), ("", "INDETERMINE")):
            with self.subTest(method=method):
                ssh = coverage(code="SERVICE_NOT_ASSESSED", service="ssh", port="22", service_method=method)
                self.assertEqual(self.compact(assessment(), ssh)["vulnerable"], expected)

    def test_unknown_and_web_services_are_not_treated_as_non_web(self):
        for service in ("", "unknown", "tcpwrapped", "http", "http-proxy", "ssl/http", "https-alt"):
            with self.subTest(service=service):
                row = coverage(code="SERVICE_NOT_ASSESSED", service=service, service_method="probed", port="8443")
                self.assertEqual(self.compact(assessment(), row)["vulnerable"], "INDETERMINE")

    def test_only_non_web_services_does_not_prove_php_is_corrected(self):
        result = self.compact(coverage(code="SERVICE_NOT_ASSESSED", service="ssh", service_method="probed", port="22"))
        self.assertEqual((result["php"], result["vulnerable"]), ("INCONNUE", "INDETERMINE"))

    def test_non_web_detection_cannot_hide_missing_patch_or_conflicting_inventory(self):
        for proof, expected in (("PATCH_MISSING_CONFIRMED", "OUI"), ("CONFLICT", "INDETERMINE")):
            with self.subTest(proof=proof):
                ssh = coverage(code="SERVICE_NOT_ASSESSED", service="ssh", service_method="probed", port="22",
                               inventory_patch_status=proof)
                result = self.compact(assessment(), ssh)
                self.assertEqual(result["vulnerable"], expected)
                self.assertIn("attesté" if expected == "OUI" else "contradictoires", result["explication"])

    def test_parser_retains_nmap_service_detection_method(self):
        xml = self.base / "ssh.xml"
        xml.write_text('<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/>'
                       '<ports><port portid="22" protocol="tcp"><state state="open"/>'
                       '<service name="ssh" method="probed"/></port></ports></host>'
                       '<runstats><finished exit="success"/></runstats></nmaprun>')
        self.assertEqual(report.parse_report(xml)[0]["service_method"], "probed")

    def test_comparison_detects_service_identification_change_affecting_compact_verdict(self):
        old = details([assessment(), coverage(code="SERVICE_NOT_ASSESSED", service="ssh", service_method="table", port="22")])
        new = deepcopy(old)
        new["rows"][1]["service_method"] = "probed"
        self.assertEqual(report.compact_rows(old["rows"])[0]["vulnerable"], "INDETERMINE")
        self.assertEqual(report.compact_rows(new["rows"])[0]["vulnerable"], "NON")
        change = next(row for row in report.compare_reports(new, old) if row["port"] == "22")
        self.assertEqual(change["change"], "CHANGED")

    def test_runtime_patch_attestation_can_resolve_an_old_banner(self):
        result = self.compact(assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35",
                                        inventory_patch_status="PATCH_CONFIRMED"))
        self.assertEqual((result["php"], result["vulnerable"]), ("8.3.35", "NON"))
        self.assertIn("attestés", result["explication"])
        self.assertIn("malgré la version annoncée", result["explication"])

    def test_server_patch_attestation_can_resolve_hidden_banner_on_completed_service(self):
        result = self.compact(assessment(state="UNKNOWN", version="", reason_code="PHP_VERSION_HIDDEN",
                                        inventory_patch_status="PATCH_CONFIRMED"))
        self.assertEqual((result["php"], result["vulnerable"]), ("INCONNUE", "NON"))
        self.assertIn("attestés", result["explication"])

    def test_confirmed_missing_patch_remains_positive_with_hidden_version(self):
        result = self.compact(assessment(state="UNKNOWN", version="", inventory_patch_status="PATCH_MISSING_CONFIRMED"))
        self.assertEqual((result["php"], result["vulnerable"]), ("INCONNUE", "OUI"))
        self.assertIn("manquant attesté", result["explication"])
        self.assertNotIn("8.3.36", result["explication"])
        self.assertIn("redémarrer", result["explication"])

    def test_unusable_inventory_does_not_clear_an_affected_banner(self):
        for proof in ("STALE", "UNVERIFIED", "PARTIAL"):
            with self.subTest(proof=proof):
                result = self.compact(assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35", inventory_patch_status=proof))
                self.assertEqual(result["vulnerable"], "OUI")

    def test_conflicting_inventory_is_indeterminate_and_retains_observation(self):
        result = self.compact(assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35", inventory_patch_status="CONFLICT"))
        self.assertEqual((result["php"], result["vulnerable"]), ("8.3.35", "INDETERMINE"))
        self.assertIn("Preuves serveur contradictoires", result["explication"])
        self.assertIn("concernée observée", result["explication"])

    def test_false_boolean_strings_and_null_evidence_are_not_truthy_signals(self):
        result = self.compact(assessment(evidence=None, potentially_vulnerable_evidence="false", budget_exhausted="false"))
        self.assertEqual(result["vulnerable"], "NON")

    def test_explanation_is_bounded_even_with_many_endpoints_and_large_reasons(self):
        rows = [assessment()]
        rows.extend(coverage(ip=f"192.0.2.{index}", reason="failure " * 100) for index in range(1, 100))
        result = self.compact(*rows)
        self.assertLessEqual(len(result["explication"]), 360)
        self.assertIn("99 contrôles", result["explication"])
        self.assertNotIn("192.0.2.98", result["explication"])

    def test_writer_has_exact_four_fields_and_n_plus_two_json_lines(self):
        rows = [assessment(f"app{index}.example.com") for index in range(465)]
        report.write_campaign_report(details(rows), self.base)
        raw = (self.base / "report.json").read_text(encoding="utf-8")
        compact = json.loads(raw)
        self.assertEqual(len(compact), 465)
        self.assertEqual(len(raw.splitlines()), 467)
        self.assertTrue(all(tuple(row) == report.COMPACT_FIELDS for row in compact))
        with (self.base / "report.csv").open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(tuple(reader.fieldnames), report.COMPACT_FIELDS)
            self.assertEqual(list(reader), compact)
        self.assertEqual(len((self.base / "report.csv").read_text().splitlines()), 466)
        self.assertEqual(json.loads((self.base / "raw/report-details.json").read_text())["rows"], rows)
        self.assertTrue((self.base / "changes.csv").exists())
        self.assertFalse((self.base / "raw/report-details.csv").exists())

    def test_empty_campaign_json_has_only_two_structural_lines(self):
        report.write_campaign_report(details([]), self.base)
        self.assertEqual((self.base / "report.json").read_text(), "[\n]\n")
        self.assertEqual(len((self.base / "report.csv").read_text().splitlines()), 1)

    def test_formula_safety_and_one_physical_csv_line_per_target(self):
        rows = [assessment(hostname=" =HYPERLINK(\"fixture\")\r\n.example.com", state="UNKNOWN",
                           version="+8.3.35\nfixture", reason_code="CUSTOM", reason="@formula\n\r\t\u2028\x00entry")]
        report.write_campaign_report(details(rows), self.base)
        compact = json.loads((self.base / "report.json").read_text())
        self.assertEqual(len((self.base / "report.json").read_text().splitlines()), 3)
        self.assertEqual(len((self.base / "report.csv").read_text().splitlines()), 2)
        with (self.base / "report.csv").open(newline="", encoding="utf-8") as stream:
            exported = list(csv.DictReader(stream))[0]
        for field in report.COMPACT_FIELDS:
            self.assertEqual(exported[field], report.safe_cell(compact[0][field]))
        self.assertTrue(exported["cible"].startswith("'="))
        self.assertTrue(exported["php"].startswith("'+"))
        self.assertIn("@formula", exported["explication"])
        self.assertTrue(exported["explication"].startswith("Ports évalués : 443."))

    def test_legacy_previous_report_is_still_accepted(self):
        old = details([assessment()])
        source = self.save("old.json", old)
        self.assertEqual(report.load_campaign_report(source), old)

    def test_compact_previous_loads_only_matching_companion(self):
        old = details([assessment()])
        report.write_campaign_report(old, self.base)
        self.assertEqual(report.load_campaign_report(self.base / "report.json"), old)
        self.assertEqual(report.load_campaign_report(self.base / "raw/report-details.json"), old)

    def test_v042_compact_previous_accepts_exact_legacy_explanation(self):
        old = {**details([assessment(port="80", state="POTENTIALLY_VULNERABLE", version="8.3.35"),
                          assessment(port="443", state="POTENTIALLY_VULNERABLE", version="8.3.35"),
                          assessment(port="8443")]), "tool_version": "0.4.2"}
        compact = [{"cible": "app.example.com", "php": "8.3.35 | 8.3.36", "vulnerable": "OUI",
                    "explication": "Version annoncée concernée (port 80); mettre à jour PHP vers 8.3.36 ou vérifier le correctif fournisseur."}]
        source = self.save("report.json", compact)
        self.save("raw/report-details.json", old)
        self.assertEqual(report.load_campaign_report(source), old)
        self.assertNotEqual(report.compact_rows(old["rows"]), compact)
        compact[0]["explication"] += " Texte altéré."
        self.save("report.json", compact)
        with self.assertRaisesRegex(report.ReportError, "incohérent"):
            report.load_campaign_report(source)

    def test_current_compact_explanation_cannot_be_ignored_during_companion_validation(self):
        old = details([assessment(port="80"), assessment(port="443")])
        report.write_campaign_report(old, self.base)
        compact = json.loads((self.base / "report.json").read_text())
        compact[0]["explication"] = compact[0]["explication"].replace("80,443", "80,8443")
        source = self.save("report.json", compact)
        with self.assertRaisesRegex(report.ReportError, "incohérent"):
            report.load_campaign_report(source)

    def test_compact_previous_missing_companion_fails_explicitly(self):
        source = self.save("report.json", report.compact_rows([assessment()]))
        with self.assertRaisesRegex(report.ReportError, "compagnon détaillé"):
            report.load_campaign_report(source)

    def test_compact_previous_mismatched_companion_fails_explicitly(self):
        report.write_campaign_report(details([assessment()]), self.base)
        self.save("raw/report-details.json", details([assessment(version="8.3.35", state="POTENTIALLY_VULNERABLE")]))
        with self.assertRaisesRegex(report.ReportError, "incohérent"):
            report.load_campaign_report(self.base / "report.json")

    def test_companion_is_fixed_and_rejects_non_detailed_structure(self):
        source = self.save("report.json", report.compact_rows([assessment()]))
        self.save("raw/report-details.json", report.compact_rows([assessment()]))
        with self.assertRaisesRegex(report.ReportError, "compagnon détaillé"):
            report.load_campaign_report(source)

    def test_previous_structure_and_compact_values_are_validated(self):
        compact = report.compact_rows([assessment()])
        invalid = [{}, {"schema_version": "2", "rows": []}, {"schema_version": "1", "rows": ["bad"]},
                   [{**compact[0], "extra": "field"}], [{**compact[0], "php": 8.3}],
                   [{**compact[0], "vulnerable": "SAFE"}], [{**compact[0], "explication": "two\nlines"}],
                   compact + compact]
        for index, value in enumerate(invalid):
            with self.subTest(value=value):
                with self.assertRaises(report.ReportError):
                    report.load_campaign_report(self.save(f"bad{index}.json", value))

    def test_compact_rows_disguised_as_legacy_details_are_rejected(self):
        source = self.save("disguised.json", details(report.compact_rows([assessment()])))
        with self.assertRaisesRegex(report.ReportError, "ligne compacte"):
            report.load_campaign_report(source)

    def test_legacy_rows_require_identity_except_discovery_metadata(self):
        for row in ({}, {"port": "443", "hostname": "   "}):
            with self.subTest(row=row):
                source = self.save("bad-identity.json", details([row]))
                with self.assertRaisesRegex(report.ReportError, "sans cible"):
                    report.load_campaign_report(source)
        discovery = details([coverage("", ip="", protocol="discovery")])
        self.assertEqual(report.load_campaign_report(self.save("discovery.json", discovery)), discovery)

    def test_json_file_size_limits_apply_to_primary_and_companion(self):
        source = self.save("report.json", report.compact_rows([assessment()]))
        self.save("raw/report-details.json", {**details([assessment()]), "padding": "x" * 1000})
        with patch.object(report, "MAX_REPORT_BYTES", 16):
            with self.assertRaisesRegex(report.ReportError, "volumineux"):
                report.load_campaign_report(source)
        with patch.object(report, "MAX_REPORT_BYTES", source.stat().st_size):
            with self.assertRaisesRegex(report.ReportError, "volumineux"):
                report.load_campaign_report(source)

    def test_io_unicode_and_json_errors_are_report_errors(self):
        paths = [self.base / "missing.json", self.base / "invalid-utf8.json", self.base / "bad-json.json"]
        paths[1].write_bytes(b"\xff")
        paths[2].write_text("{incomplete")
        for path in paths:
            with self.subTest(path=path):
                with self.assertRaises(report.ReportError):
                    report.load_campaign_report(path)

    def test_build_previous_uses_new_loader_and_preserves_comparison(self):
        previous = details([assessment()])
        report.write_campaign_report(previous, self.base / "before")
        manifest = {"schema_version": "1", "targets": [], "status": "COMPLETED"}
        with patch.object(report, "load_campaign_report", wraps=report.load_campaign_report) as loader:
            current = report.build_campaign_report(manifest, self.base, previous=self.base / "before/report.json")
        loader.assert_called_once_with(self.base / "before/report.json")
        self.assertEqual(current["changes"][0]["change"], "NO_LONGER_OBSERVED")

    def test_compact_json_alone_converts_to_csv_without_xml_or_rescan(self):
        compact = report.compact_rows([assessment()])
        source = self.save("only-compact.json", compact)
        output = self.base / "converted.csv"
        with patch.object(report, "parse_report", side_effect=AssertionError("XML must not be read")):
            status, stdout, stderr = self.cli(source, output)
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Cibles: 1", stdout)
        with output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), compact)

    def test_legacy_json_converts_to_default_compact_or_explicit_detailed_csv(self):
        source = self.save("legacy.json", details([assessment()]))
        for arguments, fields in (((), report.COMPACT_FIELDS), (("--detailed",), report.FIELDS)):
            with self.subTest(arguments=arguments):
                output = self.base / ("detailed.csv" if arguments else "compact.csv")
                with patch.object(report, "parse_report", side_effect=AssertionError("No XML conversion")):
                    self.assertEqual(self.cli(source, output, *arguments)[0], 0)
                with output.open(newline="", encoding="utf-8") as stream:
                    self.assertEqual(tuple(csv.DictReader(stream).fieldnames), fields)

    def test_compact_detailed_export_requires_matching_companion(self):
        source = self.save("report.json", report.compact_rows([assessment()]))
        output = self.base / "debug.csv"
        self.assertEqual(self.cli(source, output, "--detailed")[0], 2)
        self.assertFalse(output.exists())
        self.save("raw/report-details.json", details([assessment()]))
        self.assertEqual(self.cli(source, output, "--detailed")[0], 0)
        with output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(tuple(csv.DictReader(stream).fieldnames), report.FIELDS)

    def test_json_sources_symlinks_hardlinks_and_companion_cannot_be_overwritten(self):
        source = self.save("report.json", report.compact_rows([assessment()]))
        original = source.read_bytes()
        symlink, hardlink = self.base / "alias.json", self.base / "hardlink.json"
        symlink.symlink_to(source)
        os.link(source, hardlink)
        for destination in (source, symlink, hardlink):
            with self.subTest(destination=destination):
                self.assertEqual(self.cli(source, destination)[0], 2)
                self.assertEqual(source.read_bytes(), original)
        companion = self.save("raw/report-details.json", details([assessment()]))
        before = companion.read_bytes()
        self.assertEqual(self.cli(source, companion, "--detailed")[0], 2)
        self.assertEqual(companion.read_bytes(), before)

    def test_invalid_compact_input_never_replaces_existing_output(self):
        source = self.save("bad.json", [{"cible": "app.example.com"}])
        output = self.base / "keep.csv"
        output.write_text("keep")
        self.assertEqual(self.cli(source, output)[0], 2)
        self.assertEqual(output.read_text(), "keep")

    def test_write_report_defaults_to_compact_without_mutating_details(self):
        rows = [assessment(), assessment(ip="2001:db8::10")]
        original = deepcopy(rows)
        report.write_report(rows, self.base / "compact.csv", self.base / "source.xml")
        self.assertEqual(rows, original)
        self.assertEqual(len((self.base / "compact.csv").read_text().splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
