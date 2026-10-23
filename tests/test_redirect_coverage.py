"""A visited redirect destination is distinct from a conclusive PHP verdict.

All responses are local XML fixtures. No DNS, network or public scan is used.
"""
from __future__ import annotations

from copy import deepcopy
import unicodedata
import unittest

import report
import scan
import test_collection_report as fixtures


identity, url_identity = fixtures.identity, fixtures.url_identity


HOST = "cdn.emr.example.com"


def plain(value):
    return "".join(character for character in unicodedata.normalize("NFD", value.casefold())
                   if not unicodedata.combining(character))


def answer(service, path="/", status=200, reason="PHP_NOT_IDENTIFIED"):
    return {"path": path, "path_identity": url_identity(service, path),
            "http_status": str(status), "reason_code": reason}


class RedirectCoverageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CollectionReportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.service = self.fixture.service
        self.phase = self.fixture.phase
        self.redirect = self.fixture.redirect

    def rows(self):
        return self.fixture.merged()

    @staticmethod
    def by_key(rows):
        return {row["collection_service_key"]: row for row in rows}

    @staticmethod
    def compact(rows):
        return {row["cible"]: row for row in report.compact_rows(rows)}

    def tree(self, rows):
        data = {"rows": rows, "campaign": {"campaign_id": "redirect-coverage-fixture",
                "scope": {"domains": ["emr.example.com"]}}}
        return report._report_tree_text(data, report.compact_rows(rows))

    def assert_visited_in_scope(self, row, *, status):
        observation = row["observations"][0]
        self.assertTrue(report._true(observation.get("redirect_evaluated")))
        self.assertFalse(report._true(observation.get("redirect_conclusive")))
        self.assertEqual(observation.get("redirect_scope"), "IN_SCOPE")
        self.assertIn(str(status), observation.get("redirect_destination_http_statuses", []))
        self.assertNotIn("HORS", row.get("redirect_evaluation_scope", ""))

    def test_four_pinned_ips_with_http_301_to_https_404_are_visited_and_in_scope(self):
        sources, destinations = [], []
        addresses = [f"192.0.2.{index}" for index in range(10, 14)]
        for index, address in enumerate(addresses):
            sources.append(self.service(f"http-{index}", host=HOST, ip=address, port=80, scheme="http"))
            destinations.append(self.service(f"https-{index}", host=HOST, ip=address))
        for source in sources:
            observation = self.redirect(source, destinations[0], "/")
            observation["http_status"] = "301"
            requirement = destinations[0]["required_destinations"][-1]
            for destination in destinations[1:]:
                destination["required_destinations"].append(deepcopy(requirement))
            source["redirect_results"][-1].update(destination_ips=addresses,
                destination_service_keys=[destination["service_key"] for destination in destinations])
            self.phase(source, observations=[observation])
        for destination in destinations:
            self.phase(destination, "redirect", observations=[answer(destination, status=404)])
        rows = self.rows()
        by_key = self.by_key(rows)
        for source in sources:
            self.assert_visited_in_scope(by_key[source["service_key"]], status=404)
        compact = self.compact(rows)[HOST]
        self.assertEqual((compact["php"], compact["vulnerable"]), ("INCONNUE", "INDETERMINE"))
        for text in (compact["explication"], self.tree(rows)):
            normalized = plain(text)
            self.assertIn("404", normalized)
            self.assertNotIn("hors perimetre", normalized)
            self.assertNotIn("non visit", normalized)
        # The tree's generic legend legitimately describes unassessed DNS
        # grouping branches; only the destination-specific explanation matters.
        self.assertNotIn("non evaluee", plain(compact["explication"]))

    def test_visited_403_destination_keeps_fixed_source_indeterminate_and_explains_403(self):
        source = self.service("source", host=HOST, port=80, scheme="http")
        destination = self.service("destination", host=HOST)
        self.phase(source, version="8.3.36", observations=[self.redirect(source, destination, "/app.php")])
        denied = answer(destination, "/app.php", 403, "HTTP_ACCESS_DENIED")
        denied["http_condition"] = "HTTP_ACCESS_DENIED"
        self.phase(destination, "redirect", path="/app.php", observations=[denied])
        rows = self.rows()
        self.assert_visited_in_scope(self.by_key(rows)["source"], status=403)
        compact = self.compact(rows)[HOST]
        self.assertEqual(compact["vulnerable"], "INDETERMINE")
        self.assertIn("403", compact["explication"])
        self.assertNotIn("hors perimetre", plain(compact["explication"]))
        self.assertNotIn("non visit", plain(compact["explication"]))
        self.assertIn("403", self.tree(rows))

    def test_fixed_source_and_visited_200_without_php_version_never_produce_non_vulnerable(self):
        source = self.service("source", host=HOST, port=80, scheme="http")
        destination = self.service("destination", host=HOST)
        self.phase(source, version="8.3.36", observations=[self.redirect(source, destination, "/app.php")])
        self.phase(destination, "redirect", path="/app.php", observations=[answer(destination, "/app.php")])
        rows = self.rows()
        self.assert_visited_in_scope(self.by_key(rows)["source"], status=200)
        self.assertEqual(self.compact(rows)[HOST]["vulnerable"], "INDETERMINE")
        self.assertNotIn("hors perimetre", plain(self.tree(rows)))

    def test_visited_fixed_redirect_in_a_chain_does_not_hide_a_blocked_external_final_hop(self):
        source = self.service("source", host=HOST, port=80, scheme="http")
        middle = self.service("middle", host=HOST)
        external = identity(host="outside.example.invalid")
        first = self.redirect(source, middle, "/middle")
        final_identity = url_identity(external, "/final")
        second = {"path": "/middle", "path_identity": url_identity(middle, "/middle"),
                  "http_status": "302", "reason_code": "REDIRECT_NOT_ASSESSED",
                  "redirect_to": "https://outside.example.invalid/final", "redirect_identity": final_identity,
                  "redirect_followed": "false", "redirect_scope": "HORS_PERIMETRE_DU_CONTROLE"}
        middle["redirect_results"].append({"source_path_identity": second["path_identity"],
            "redirect_identity": final_identity, "destination_ips": [], "destination_service_keys": [],
            "status": "UNASSESSED", "reason_code": "OUTSIDE_AUTHORIZED_DOMAINS"})
        self.phase(source, version="8.3.36", observations=[first])
        self.phase(middle, "redirect", "8.3.36", path="/middle", observations=[second])
        rows = self.rows()
        by_key = self.by_key(rows)
        original = by_key["source"]["observations"][0]
        self.assertTrue(report._true(original.get("redirect_evaluated")))
        self.assertFalse(report._true(original.get("redirect_conclusive")))
        self.assertEqual(original.get("redirect_scope"), "IN_SCOPE")
        final = by_key["middle"]["observations"][0]
        self.assertFalse(report._true(final.get("redirect_evaluated")))
        self.assertFalse(report._true(final.get("redirect_conclusive")))
        self.assertIn(final.get("redirect_scope"), ("OUTSIDE_AUTHORIZED_DOMAINS", "HORS_PERIMETRE_DU_CONTROLE"))
        compact = self.compact(rows)[HOST]
        self.assertEqual(compact["vulnerable"], "INDETERMINE")
        text = compact["explication"] + "\n" + self.tree(rows)
        self.assertIn("hors perimetre", plain(text))
        self.assertIn("outside.example.invalid", text)
        source_label = " ".join(report._redirect_coverage_summaries([by_key["source"]]))
        self.assertIn("DANS LE PÉRIMÈTRE", source_label)
        self.assertIn("suite de la chaîne", source_label)
        self.assertNotIn("Nom de destination hors", source_label)

    def test_missing_or_budget_exhausted_destination_is_not_visited_but_remains_in_scope(self):
        for exhausted in (False, True):
            with self.subTest(exhausted=exhausted):
                self.fixture.services.clear()
                source = self.service("source", host=HOST, port=80, scheme="http")
                destination = self.service("destination", host=HOST)
                self.phase(source, version="8.3.36", observations=[self.redirect(source, destination, "/app.php")])
                if exhausted:
                    destination["phase_jobs"].append({"job_id": "exhausted", "phase": "redirect",
                        "status": "BUDGET_EXHAUSTED", "error": "REQUEST_BUDGET_EXHAUSTED"})
                    destination["required_destinations"][0].update(status="BUDGET_EXHAUSTED",
                        reason_code="REQUEST_BUDGET_EXHAUSTED")
                rows = self.rows()
                observation = self.by_key(rows)["source"]["observations"][0]
                self.assertFalse(report._true(observation.get("redirect_evaluated")))
                self.assertFalse(report._true(observation.get("redirect_conclusive")))
                self.assertEqual(observation.get("redirect_scope"), "IN_SCOPE")
                compact = self.compact(rows)[HOST]
                self.assertEqual(compact["vulnerable"], "INDETERMINE")
                self.assertIn("non visit", plain(compact["explication"]))
                self.assertNotIn("hors perimetre", plain(compact["explication"]))
                if exhausted:
                    self.assertIn("budget", plain(compact["explication"]))

    def test_other_query_or_ip_cannot_claim_an_exact_destination_was_visited(self):
        source = self.service("source", host=HOST, port=80, scheme="http")
        destination = self.service("destination", host=HOST)
        other_ip = self.service("other-ip", host=HOST, ip="192.0.2.11")
        self.phase(source, version="8.3.36", observations=[self.redirect(source, destination, "/app.php?a=1")])
        self.phase(destination, "redirect", "8.3.36", path="/app.php?a=2")
        self.phase(other_ip, "redirect", "8.3.36", path="/app.php?a=1")
        rows = self.rows()
        observation = self.by_key(rows)["source"]["observations"][0]
        self.assertFalse(report._true(observation.get("redirect_evaluated")))
        self.assertFalse(report._true(observation.get("redirect_conclusive")))
        self.assertEqual(self.compact(rows)[HOST]["vulnerable"], "INDETERMINE")
        self.phase(destination, "redirect", "8.3.36", path="/app.php?a=1")
        rows = self.rows()
        observation = self.by_key(rows)["source"]["observations"][0]
        self.assertTrue(report._true(observation.get("redirect_evaluated")))
        self.assertTrue(report._true(observation.get("redirect_conclusive")))
        self.assertEqual(self.compact(rows)[HOST]["vulnerable"], "NON")

    def test_all_pinned_destination_ips_must_have_answered_before_claiming_visited(self):
        source = self.service("source", host=HOST, port=80, scheme="http")
        destination = self.service("destination", host=HOST)
        missing = self.service("missing-ip", host=HOST, ip="192.0.2.11")
        observation = self.redirect(source, destination, "/app.php")
        source["redirect_results"][0]["destination_ips"] = [destination["ip"], missing["ip"]]
        source["redirect_results"][0]["destination_service_keys"] = [destination["service_key"], missing["service_key"]]
        missing["required_destinations"].append(deepcopy(destination["required_destinations"][0]))
        self.phase(source, observations=[observation])
        self.phase(destination, "redirect", path="/app.php", observations=[answer(destination, "/app.php", 404)])
        rows = self.rows()
        self.assertFalse(report._true(self.by_key(rows)["source"]["observations"][0].get("redirect_evaluated")))
        self.phase(missing, "redirect", path="/app.php", observations=[answer(missing, "/app.php", 404)])
        rows = self.rows()
        self.assert_visited_in_scope(self.by_key(rows)["source"], status=404)


class DomainScopeDepthTests(unittest.TestCase):
    def test_apex_and_subdomains_at_one_two_and_four_levels_stay_in_scope(self):
        for name in ("emr.example.com", "one.emr.example.com", "one.two.emr.example.com",
                     "one.two.three.four.emr.example.com"):
            with self.subTest(name=name):
                self.assertTrue(scan.is_within(name, "emr.example.com"))

    def test_lookalike_suffixes_and_unrelated_names_are_outside_scope(self):
        for name in ("evilemr.example.com", "emr.example.com.evil.test", "one.emr-example.com", "example.com"):
            with self.subTest(name=name):
                self.assertFalse(scan.is_within(name, "emr.example.com"))


if __name__ == "__main__":
    unittest.main()
