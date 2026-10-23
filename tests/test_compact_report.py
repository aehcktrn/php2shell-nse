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
    return {"schema_version": "1", "tool_version": "0.5.5", "rows": rows,
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
                                            else "AFFECTED_VERSION_ADVERTISED"),
                               observations=[{"path": "/", "state": destination_state,
                                              "versions": [version]}]),
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

    def test_cross_hostname_redirect_assessed_in_campaign_is_not_reported_out_of_scope(self):
        redirect = assessment(
            hostname="www.sygestim.foncia.com", ip="163.172.183.180", port="443",
            state="UNKNOWN", version="", scheme="https",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"path": "/index.php", "reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://sygestim.foncia.com/index.php"}],
        )
        destination = assessment(
            hostname="sygestim.foncia.com", ip="163.172.183.180", port="443",
            state="UNKNOWN", version="", scheme="https", reason_code="PHP_NOT_IDENTIFIED",
            php_detected="UNKNOWN",
            observations=[{"path": "/index.php", "state": "UNKNOWN",
                           "reason_code": "PHP_NOT_IDENTIFIED", "versions": []}],
        )
        compact = {row["cible"]: row for row in report.compact_rows([redirect, destination])}
        alias = compact["www.sygestim.foncia.com"]
        self.assertEqual(alias["vulnerable"], "INDETERMINE")
        self.assertNotIn("HORS PÉRIMÈTRE DU CONTRÔLE", alias["explication"])
        self.assertIn("évaluée séparément", alias["explication"])
        self.assertIn("https://sygestim.foncia.com/index.php", alias["explication"])

        http_redirect = deepcopy(redirect)
        http_redirect.update(port="80", scheme="http")
        http_redirect["observations"][0]["redirect_to"] = (
            "https://www.sygestim.foncia.com/index.php")
        alias = {row["cible"]: row for row in report.compact_rows(
            [http_redirect, redirect, destination])}["www.sygestim.foncia.com"]
        self.assertIn("https://sygestim.foncia.com/index.php", alias["explication"])

        destination["observations"][0]["path"] = "/"
        alias = {row["cible"]: row for row in report.compact_rows([redirect, destination])}[
            "www.sygestim.foncia.com"]
        self.assertIn("HORS PÉRIMÈTRE DU CONTRÔLE", alias["explication"])

    def test_v050_cross_hostname_redirect_rendering_remains_readable(self):
        redirect = assessment(
            hostname="www.sygestim.foncia.com", ip="163.172.183.180", port="443",
            state="UNKNOWN", version="", scheme="https",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"path": "/index.php", "reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://sygestim.foncia.com/index.php"}],
        )
        destination = assessment(
            hostname="sygestim.foncia.com", ip="163.172.183.180", port="443",
            state="UNKNOWN", version="", scheme="https", reason_code="PHP_NOT_IDENTIFIED",
            observations=[{"path": "/index.php", "state": "UNKNOWN",
                           "reason_code": "PHP_NOT_IDENTIFIED", "versions": []}],
        )
        old = {**details([redirect, destination]), "tool_version": "0.5.0"}
        historical = report.compact_rows(old["rows"], redirect_coverage="current")
        self.assertIn("HORS PÉRIMÈTRE DU CONTRÔLE", historical[0]["explication"])
        self.save("report.json", historical)
        self.save("raw/report-details.json", old)
        self.assertEqual(report.load_campaign_report(self.base / "report.json"), old)

    def test_requested_https_failure_takes_priority_over_navigation_redirect(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"path": "/", "reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://app.example.com/"}],
        )
        for code, reason in (("HTTP_ACCESS_DENIED", "HTTP 403 : accès refusé (port 443)"),
                             ("PHP_NOT_IDENTIFIED", "PHP non identifié ; absence de vulnérabilité non établie (port 443)")):
            with self.subTest(code=code):
                destination = assessment(
                    port="443", scheme="https", state="UNKNOWN", version="", php_detected="UNKNOWN",
                    reason_code=code, traversal_complete="false" if code == "HTTP_ACCESS_DENIED" else "true",
                    observations=[{"path": "/", "state": "UNKNOWN", "reason_code": code, "versions": []}],
                )
                rows = [redirect, destination]
                result = self.compact(*rows)
                self.assertEqual(result["vulnerable"], "INDETERMINE")
                self.assertIn(reason, result["explication"])
                self.assertNotIn("Destination de redirection évaluée séparément dans la campagne (port 80)",
                                 result["explication"])
                historical = report.compact_rows(rows, historical_semantics=True)[0]
                self.assertIn("Destination de redirection évaluée séparément dans la campagne (port 80)",
                              historical["explication"])

    def test_redirect_requires_the_exact_destination_path(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://app.example.com/legacy/index.php"}],
        )
        destination = assessment(
            port="443", scheme="https",
            observations=[{"path": "/", "state": "PATCHED_VERSION_ADVERTISED",
                           "versions": ["8.3.36"]}],
        )
        self.assertEqual(self.compact(redirect, destination)["vulnerable"], "INDETERMINE")
        destination["observations"].append(
            {"path": "/legacy/index.php", "state": "PATCHED_VERSION_ADVERTISED",
             "versions": ["8.3.36"]})
        self.assertEqual(self.compact(redirect, destination)["vulnerable"], "NON")

    def test_version_from_one_page_qualifies_other_reached_pages_on_same_service(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[
                {"reason_code": "REDIRECT_NOT_ASSESSED",
                 "redirect_to": "https://app.example.com/"},
                {"reason_code": "REDIRECT_NOT_ASSESSED",
                 "redirect_to": "https://app.example.com/index.php"},
            ],
        )
        destination = assessment(
            port="443", scheme="https",
            observations=[
                {"path": "/", "state": "UNKNOWN", "reason_code": "PHP_NOT_IDENTIFIED",
                 "versions": []},
                {"path": "/index.php", "state": "PATCHED_VERSION_ADVERTISED",
                 "reason_code": "FIXED_VERSION_ADVERTISED", "versions": ["8.3.36"]},
            ],
        )
        self.assertEqual(self.compact(redirect, destination)["vulnerable"], "NON")

        destination["traversal_complete"] = "false"
        destination["reason_code"] = "HTTP_ACCESS_DENIED"
        self.assertEqual(self.compact(redirect, destination)["vulnerable"], "INDETERMINE")

    def test_redacted_redirect_parameters_never_prove_path_identity(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://app.example.com/login?[redacted]"}],
        )
        destination = assessment(
            port="443", scheme="https",
            observations=[{"path": "/login?[redacted]", "state": "PATCHED_VERSION_ADVERTISED",
                           "versions": ["8.3.36"]}],
        )
        self.assertEqual(self.compact(redirect, destination)["vulnerable"], "INDETERMINE")

    def test_every_redirect_destination_must_be_assessed(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[
                {"reason_code": "REDIRECT_NOT_ASSESSED",
                 "redirect_to": "https://app.example.com/covered"},
                {"reason_code": "REDIRECT_NOT_ASSESSED",
                 "redirect_to": "https://app.example.com/missing"},
            ],
        )
        destination = assessment(
            port="443", scheme="https",
            observations=[{"path": "/covered", "state": "PATCHED_VERSION_ADVERTISED",
                           "versions": ["8.3.36"]}],
        )
        self.assertEqual(self.compact(redirect, destination)["vulnerable"], "INDETERMINE")

    def test_covered_redirect_keeps_independent_inventory_evidence(self):
        destination = assessment(
            port="443", scheme="https",
            observations=[{"path": "/", "state": "PATCHED_VERSION_ADVERTISED",
                           "versions": ["8.3.36"]}],
        )
        for proof, expected in (("PATCH_MISSING_CONFIRMED", "OUI"), ("CONFLICT", "INDETERMINE")):
            with self.subTest(proof=proof):
                redirect = assessment(
                    port="80", state="UNKNOWN", version="", service="http", scheme="http",
                    reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
                    inventory_patch_status=proof,
                    observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                                   "redirect_to": "https://app.example.com/"}],
                )
                self.assertEqual(self.compact(redirect, destination)["vulnerable"], expected)

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
        old = {**details([assessment(
            state="UNKNOWN", version="", reason_code="REDIRECT_NOT_ASSESSED",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://outside.example.net/"}],
        )]), "tool_version": "0.4.5"}
        compact = report.compact_rows(
            old["rows"], include_redirect_destinations=False, redirect_coverage="legacy")
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
                           reason="failure " * 100, potentially_vulnerable_evidence=False,
                           inventory_patch_status="UNVERIFIED", ip="2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
                for port in range(10000, 10014)]
        rows.append(assessment(port="10000", ip="192.0.2.10"))
        result = self.compact(*rows)
        self.assertEqual(result["vulnerable"], "INDETERMINE")
        self.assertLessEqual(len(result["explication"]), 360)
        self.assertTrue(result["explication"].startswith(
            "Ports évalués : 10000,10001,10002,10003,10004,10005,10006,10007,10008,10009 (+4 autres)."))
        self.assertIn("failure", result["explication"])
        self.assertIn("…", result["explication"])

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

    def test_any_observed_affected_version_makes_the_service_vulnerable(self):
        result = self.compact(assessment(state="UNKNOWN", version="8.3.35 | 8.3.36",
                                        reason_code="CONFLICTING_VERSIONS", potentially_vulnerable_evidence=True))
        self.assertEqual(result["vulnerable"], "OUI")
        self.assertEqual(result["php"], "8.3.35 | 8.3.36")
        self.assertIn("Version annoncée concernée", result["explication"])

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

    def test_conflicting_inventory_does_not_hide_an_affected_observation(self):
        result = self.compact(assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35", inventory_patch_status="CONFLICT"))
        self.assertEqual((result["php"], result["vulnerable"]), ("8.3.35", "OUI"))
        self.assertIn("Preuves serveur contradictoires", result["explication"])
        self.assertIn("Version annoncée concernée", result["explication"])

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

    def test_tree_report_groups_subdomains_without_inventing_assessments(self):
        rows = [
            assessment(hostname="example.com"),
            assessment(hostname="api.example.com"),
            assessment(hostname="admin.fr.example.com"),
            coverage(hostname="www.fr.example.com", code="NO_DNS_ADDRESS"),
        ]
        payload = details(rows)
        payload["campaign"]["scope"] = {"domains": ["example.com"]}
        payload["discovery"] = {"enabled": True, "roots": ["example.com"]}
        report.write_campaign_report(payload, self.base)
        tree = (self.base / "report-tree.txt").read_text(encoding="utf-8")
        self.assertIn("1. INVENTAIRE INTERNET DÉCOUVERT — 4 cibles", tree)
        self.assertIn("Verdicts PHP2Shell selon les versions observées ; parcours représentatif des pages et backends.", tree)
        self.assertIn("2. DOMAINES ET SOUS-DOMAINES HÉBERGEANT DU PHP — 3 hôtes", tree)
        self.assertIn("3. ÉLÉMENTS VULNÉRABLES — 0 hôte", tree)
        self.assertIn("4. ÉLÉMENTS NON CONCLUSIFS — 1 hôte", tree)
        self.assertIn("example.com [PHP 8.3.36 | NON-VULNERABLE] — 4 cibles", tree)
        self.assertIn("├── api [PHP 8.3.36 | NON-VULNERABLE]", tree)
        self.assertIn("└── fr [regroupement]", tree)
        self.assertIn("├── admin [PHP 8.3.36 | NON-VULNERABLE]", tree)
        self.assertIn("└── www [PHP INCONNUE | INDETERMINE | Aucune adresse IP résolue", tree)
        self.assertIn("Aucun élément vulnérable n'a été établi", tree)

    def test_tree_report_lists_vulnerable_component_evidence(self):
        rows = [assessment(
            hostname="legacy.example.com", state="POTENTIALLY_VULNERABLE", version="8.3.35",
            reason_code="AFFECTED_VERSION_ADVERTISED", scheme="https", path="/",
            evidence=[{"state": "POTENTIALLY_VULNERABLE", "version": "8.3.35",
                       "scheme": "https", "port": "443", "path": "/index.php"}],
        )]
        payload = details(rows)
        payload["campaign"]["scope"] = {"domains": ["example.com"]}
        report.write_campaign_report(payload, self.base)
        tree = (self.base / "report-tree.txt").read_text(encoding="utf-8")
        self.assertIn("3. ÉLÉMENTS VULNÉRABLES — 1 hôte", tree)
        self.assertIn("legacy [PHP 8.3.35 | VULNERABLE | PREUVE "
                      "https://legacy.example.com/index.php — PHP 8.3.35]", tree)

    def test_tree_report_explains_common_indeterminate_causes(self):
        rows = [
            assessment(hostname="blocked.example.com", state="UNKNOWN", version="",
                       reason_code="HTTP_ACCESS_DENIED", traversal_complete="false", php_detected="UNKNOWN"),
            assessment(hostname="hidden.example.com", state="UNKNOWN", version="",
                       reason_code="PHP_NOT_IDENTIFIED", php_detected="UNKNOWN"),
            coverage(hostname="missing.example.com", code="NO_DNS_ADDRESS"),
        ]
        payload = details(rows)
        payload["campaign"]["scope"] = {"domains": ["example.com"]}
        report.write_campaign_report(payload, self.base)
        tree = (self.base / "report-tree.txt").read_text(encoding="utf-8")
        self.assertIn("4. ÉLÉMENTS NON CONCLUSIFS — 3 hôtes", tree)
        self.assertIn("blocked [PHP INCONNUE | INDETERMINE | HTTP 403 : accès refusé (port 443)]", tree)
        self.assertIn("hidden [PHP INCONNUE | INDETERMINE | PHP non identifié ; absence de vulnérabilité non établie", tree)
        self.assertIn("missing [PHP INCONNUE | INDETERMINE | Aucune adresse IP résolue", tree)

    def test_tree_php_hosts_require_observed_php_or_valid_attestation(self):
        rows = [assessment(hostname=proof.lower() + ".example.com", state="UNKNOWN", version="",
                           php_detected="UNKNOWN", inventory_patch_status=proof)
                for proof in ("NOT_PROVIDED", "UNVERIFIED", "STALE", "PARTIAL", "CONFLICT",
                              "PATCH_CONFIRMED", "PATCH_MISSING_CONFIRMED")]
        rows.append(assessment(hostname="hidden.example.com", state="UNKNOWN", version="",
                               reason_code="PHP_VERSION_HIDDEN", php_detected="YES"))
        self.assertEqual(report._report_php_targets(details(rows)),
                         {"patch_confirmed.example.com", "patch_missing_confirmed.example.com",
                          "hidden.example.com"})

    def test_tree_vulnerable_proof_excludes_runtime_with_attested_backport(self):
        rows = [assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35", scheme="https",
                           inventory_patch_status="PATCH_CONFIRMED",
                           evidence=[{"state": "POTENTIALLY_VULNERABLE", "version": "8.3.35",
                                      "path": "/backported.php"}]),
                assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35", scheme="https", port="8443",
                           evidence=[{"state": "POTENTIALLY_VULNERABLE", "version": "8.3.35",
                                      "path": "/affected.php"}]),
                assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35", scheme="https", port="9443",
                           path="/other.php")]
        proofs = report._report_vulnerability_proofs(details(rows))["app.example.com"]
        self.assertEqual(proofs, ["https://app.example.com:8443/affected.php — PHP 8.3.35",
                                  "https://app.example.com:9443/other.php — PHP 8.3.35"])
        payload = details(rows)
        payload["campaign"]["scope"] = {"domains": ["example.com"]}
        tree = report._report_tree_text(payload, report.compact_rows(rows))
        self.assertIn("app [PHP 8.3.35 | VULNERABLE | PREUVE https://app.example.com:8443/affected.php — PHP 8.3.35]", tree)
        self.assertIn("\n    PREUVE https://app.example.com:9443/other.php — PHP 8.3.35\n", tree)
        self.assertNotIn("backported.php", tree)
        self.assertNotIn("(+1 autre)", tree)

    def test_tree_vulnerable_root_shows_additional_ipv6_service_proof(self):
        rows = [assessment(hostname="2001:db8::10", state="POTENTIALLY_VULNERABLE", version="8.3.35",
                           scheme="https", port="443", path="/first.php"),
                assessment(hostname="2001:db8::10", state="POTENTIALLY_VULNERABLE", version="8.3.35",
                           scheme="https", port="8443", path="/second.php")]
        payload = details(rows)
        tree = report._report_tree_text(payload, report.compact_rows(rows))
        self.assertIn("PREUVE https://[2001:db8::10]/first.php — PHP 8.3.35", tree)
        self.assertIn("\n    PREUVE https://[2001:db8::10]:8443/second.php — PHP 8.3.35\n", tree)
        self.assertEqual(report._tree_endpoint("[2001:db8::10]", "https", "443", "/"),
                         "https://[2001:db8::10]/")

    def test_tree_preserves_all_detailed_causes_and_outside_destination(self):
        rows = [assessment(state="UNKNOWN", version="8.3.36", reason_code="CONFLICTING_VERSIONS"),
                assessment(state="UNKNOWN", version="8.3.36", port="8443", reason_code="UNRECOGNIZED_BUILD"),
                assessment(state="UNKNOWN", version="", port="8080", reason_code="REDIRECT_NOT_ASSESSED",
                           php_detected="UNKNOWN", observations=[{
                               "reason_code": "REDIRECT_NOT_ASSESSED", "redirect_to": "https://outside.example.net/"}]),
                assessment(state="PATCHED_VERSION_ADVERTISED", version="8.3.36", port="9443",
                           traversal_complete="false", traversal_reason_code="HTTP_ACCESS_DENIED",
                           crawl_gap_path="/restricted-component.php")]
        payload = details(rows)
        compact = report.compact_rows(rows)
        compact[0]["explication"] = "Une explication compacte volontairement tronquée."
        tree = report._report_tree_text(payload, compact)
        self.assertIn("Versions PHP contradictoires sur le même service (port 443)", tree)
        self.assertIn("Build PHP non reconnu ; correctif à vérifier côté serveur (port 8443)", tree)
        self.assertIn("HTTP 403 : accès refusé sur /restricted-component.php (port 9443)", tree)
        self.assertIn("HORS PÉRIMÈTRE DU CONTRÔLE", tree)
        self.assertIn("https://outside.example.net/", tree)
        self.assertNotIn("VERSION VUE, COUVERTURE INCOMPLÈTE", tree)

    def test_tree_groups_same_reason_across_addresses_and_ports(self):
        rows = []
        for number in range(1, 13):
            ip = f"192.0.2.{number}"
            rows.extend([
                assessment(hostname="campus.example.com", ip=ip, port="80", scheme="http", state="UNKNOWN",
                           version="", php_detected="UNKNOWN", reason_code="REDIRECT_NOT_ASSESSED",
                           observations=[{"path": "/", "reason_code": "REDIRECT_NOT_ASSESSED",
                                          "redirect_to": "https://campus.example.com/"}]),
                assessment(hostname="campus.example.com", ip=ip, scheme="https", state="UNKNOWN", version="",
                           php_detected="UNKNOWN", reason_code="PHP_NOT_IDENTIFIED",
                           observations=[{"path": "/", "reason_code": "PHP_NOT_IDENTIFIED", "state": "UNKNOWN"}]),
            ])
        for number in range(1, 4):
            for port in ("443", "80"):
                rows.append(assessment(hostname="blocked.example.com", ip=f"192.0.2.{number}", port=port,
                                       state="UNKNOWN", version="", php_detected="UNKNOWN",
                                       reason_code="HTTP_ACCESS_DENIED", crawl_gap_path="/restricted.php"))
        rows.append(assessment(hostname="blocked.example.com", ip="192.0.2.1", port="443", state="UNKNOWN",
                               version="", php_detected="UNKNOWN", reason_code="HTTP_ACCESS_DENIED",
                               crawl_gap_path="/other.php"))
        causes = report._report_indeterminate_causes(details(rows))
        self.assertEqual(causes["campus.example.com"], [
            "Dans la campagne — destination évaluée séparément : https://campus.example.com/",
            "PHP non identifié ; absence de vulnérabilité non établie (port 443 ; 12 adresses)",
        ])
        self.assertEqual(causes["blocked.example.com"], [
            "HTTP 403 : accès refusé sur /restricted.php (ports 80,443 ; 3 adresses)",
            "HTTP 403 : accès refusé sur /other.php (port 443)",
        ])

    def test_tree_redirect_only_reason_describes_unknown_status_and_keeps_all_destinations(self):
        destinations = [f"https://destination.example.com/page{number}" for number in range(4)]
        alias = assessment(hostname="alias.example.com", state="UNKNOWN", version="", php_detected="UNKNOWN",
                           reason_code="REDIRECT_NOT_ASSESSED", observations=[
                               {"path": "/", "reason_code": "REDIRECT_NOT_ASSESSED", "redirect_to": destination}
                               for destination in destinations])
        destination = assessment(hostname="destination.example.com", scheme="https", state="UNKNOWN", version="",
                                 php_detected="UNKNOWN", reason_code="PHP_NOT_IDENTIFIED", observations=[
                                     {"path": f"/page{number}", "state": "UNKNOWN", "reason_code": "PHP_NOT_IDENTIFIED"}
                                     for number in range(4)])
        payload = details([alias, destination])
        causes = report._report_indeterminate_causes(payload)["alias.example.com"]
        self.assertEqual(causes[-1], "Statut PHP de la destination non établi (port 443)")
        for url in destinations:
            self.assertIn(url, causes[0])
        self.assertNotIn("(+", causes[0])
        # The same complete listing is retained when destinations were not requested.
        outside = report._report_indeterminate_causes(details([alias]))["alias.example.com"][0]
        self.assertIn("HORS PÉRIMÈTRE DU CONTRÔLE", outside)
        for url in destinations:
            self.assertIn(url, outside)

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
        original = deepcopy(old)
        report.write_campaign_report(old, self.base)
        expected = {**old, "tool_version": report.RENDERER_VERSION}
        self.assertEqual(report.load_campaign_report(self.base / "report.json"), expected)
        self.assertEqual(report.load_campaign_report(self.base / "raw/report-details.json"), expected)
        self.assertEqual(old, original)

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

    def test_v053_silent_root_versioned_index_report_loads_then_recomputes(self):
        redirect = assessment(
            hostname="www.constatimmo.com", port="80", state="UNKNOWN", version="", fixed_versions="",
            service="http", scheme="http", reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED", "redirect_to": "https://www.constatimmo.com/"},
                          {"reason_code": "REDIRECT_NOT_ASSESSED", "redirect_to": "https://www.constatimmo.com/index.php"}],
        )
        destination = assessment(
            hostname="www.constatimmo.com", port="443", version="8.2.35", fixed_versions="", scheme="https",
            observations=[{"path": "/", "state": "UNKNOWN", "reason_code": "PHP_NOT_IDENTIFIED", "versions": []},
                          {"path": "/index.php", "state": "PATCHED_VERSION_ADVERTISED",
                           "reason_code": "FIXED_VERSION_ADVERTISED", "versions": ["8.2.35"]}],
        )
        old = {**details([redirect, destination]), "tool_version": "0.5.3"}
        historical = [{"cible": "www.constatimmo.com", "php": "8.2.35", "vulnerable": "INDETERMINE",
                       "explication": "Ports évalués : 80,443. Dans la campagne — destinations évaluées séparément : "
                       "https://www.constatimmo.com/, https://www.constatimmo.com/index.php. "
                       "Destination de redirection évaluée séparément dans la campagne (port 80)."}]
        self.save("raw/report-details.json", old)
        source = self.save("report.json", historical)
        loaded = report.load_campaign_report(source)
        self.assertEqual(loaded, old)
        self.assertEqual(report.compact_rows(loaded["rows"])[0]["vulnerable"], "NON")
        historical[0]["explication"] += " Texte altéré."
        self.save("report.json", historical)
        with self.assertRaisesRegex(report.ReportError, "incohérent"):
            report.load_campaign_report(source)

    def test_historical_affected_version_with_gap_loads_then_recomputes_positive(self):
        row = assessment(state="POTENTIALLY_VULNERABLE", version="8.3.35",
                         reason_code="HTTP_ACCESS_DENIED", traversal_complete="false")
        reason = "HTTP 403 : accès refusé (port 443); version concernée observée, correctif à vérifier."
        for version in ("0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6", "0.5.0", "0.5.1", "0.5.2", "0.5.3"):
            with self.subTest(version=version):
                old = {**details([row]), "tool_version": version}
                historical = [{"cible": "app.example.com", "php": "8.3.35", "vulnerable": "INDETERMINE",
                               "explication": ("" if version == "0.4.2" else "Ports évalués : 443. ") + reason}]
                self.save("raw/report-details.json", old)
                source = self.save("report.json", historical)
                loaded = report.load_campaign_report(source)
                self.assertEqual(loaded, old)
                self.assertEqual(report.compact_rows(loaded["rows"])[0]["vulnerable"], "OUI")

    def test_v054_redirect_first_cause_remains_readable_then_recomputes_https_failure(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"path": "/", "reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://app.example.com/"}],
        )
        destination = assessment(
            port="443", scheme="https", state="UNKNOWN", version="", php_detected="UNKNOWN",
            reason_code="HTTP_ACCESS_DENIED", traversal_complete="false",
            observations=[{"path": "/", "state": "UNKNOWN", "reason_code": "HTTP_ACCESS_DENIED", "versions": []}],
        )
        old = {**details([redirect, destination]), "tool_version": "0.5.4"}
        historical = [{"cible": "app.example.com", "php": "INCONNUE", "vulnerable": "INDETERMINE",
                       "explication": "Ports évalués : 80,443. Dans la campagne — destination évaluée séparément : "
                       "https://app.example.com/. Destination de redirection évaluée séparément dans la campagne "
                       "(port 80); 2 contrôles indéterminés."}]
        self.save("raw/report-details.json", old)
        source = self.save("report.json", historical)
        loaded = report.load_campaign_report(source)
        self.assertEqual(loaded, old)
        self.assertIn("HTTP 403 : accès refusé (port 443)", report.compact_rows(loaded["rows"])[0]["explication"])
        # v0.5.4 already used positive-evidence precedence; only its cause order is historical.
        destination.update(state="POTENTIALLY_VULNERABLE", versions="8.3.35")
        self.assertEqual(report._historical_compact_rows(old)[0]["vulnerable"], "OUI")

    def test_v043_compact_previous_accepts_its_port_aware_redirect_rendering(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://app.example.com/legacy"}],
        )
        destination = assessment(port="443", scheme="https")
        old = {**details([redirect, destination]), "tool_version": "0.4.3"}
        historical = report.compact_rows(
            old["rows"], include_redirect_destinations=False, redirect_coverage="none")
        self.assertEqual(historical[0]["vulnerable"], "INDETERMINE")
        self.assertIn("80,443", historical[0]["explication"])
        self.save("report.json", historical)
        self.save("raw/report-details.json", old)
        self.assertEqual(report.load_campaign_report(self.base / "report.json"), old)

    def test_v044_false_non_redirect_report_remains_readable_but_recomputes_indeterminate(self):
        redirect = assessment(
            port="80", state="UNKNOWN", version="", service="http", scheme="http",
            reason_code="REDIRECT_NOT_ASSESSED", php_detected="UNKNOWN",
            observations=[{"reason_code": "REDIRECT_NOT_ASSESSED",
                           "redirect_to": "https://app.example.com/legacy/index.php"}],
        )
        destination = assessment(
            port="443", scheme="https",
            observations=[{"path": "/", "state": "PATCHED_VERSION_ADVERTISED",
                           "versions": ["8.3.36"]}],
        )
        old = {**details([redirect, destination]), "tool_version": "0.4.4"}
        historical = report.compact_rows(
            old["rows"], include_redirect_destinations=False, redirect_coverage="legacy")
        self.assertEqual(historical[0]["vulnerable"], "NON")
        self.save("report.json", historical)
        self.save("raw/report-details.json", old)
        loaded = report.load_campaign_report(self.base / "report.json")
        self.assertEqual(report.compact_rows(loaded["rows"])[0]["vulnerable"], "INDETERMINE")
        self.save("report.json", report.compact_rows(old["rows"]))
        with self.assertRaisesRegex(report.ReportError, "incohérent"):
            report.load_campaign_report(self.base / "report.json")

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

    def test_report_larger_than_the_old_128_mib_limit_is_readable(self):
        source = self.save("report.json", [])
        companion = self.base / "raw" / "report-details.json"
        companion.parent.mkdir(parents=True, exist_ok=True)
        prefix = json.dumps(details([]), ensure_ascii=False)[:-1] + ', "padding": "'
        with companion.open("w", encoding="utf-8") as stream:
            stream.write(prefix)
            chunk = "x" * (1024 * 1024)
            for _ in range(129):
                stream.write(chunk)
            stream.write('"}')
        self.assertGreater(companion.stat().st_size, 128 * 1024 * 1024)
        loaded = report.load_campaign_report(source)
        self.assertEqual(loaded["rows"], [])
        self.assertEqual(len(loaded["padding"]), 129 * 1024 * 1024)

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
