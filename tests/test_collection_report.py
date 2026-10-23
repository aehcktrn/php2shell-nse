"""Offline reconciliation of bounded HTTP phases and collection measurements."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

import report


def identity(host="app.example.com", ip="192.0.2.10", port=443, scheme="https"):
    return {"hostname": host, "ip": ip, "port": port, "scheme": scheme}


def url_identity(service, path):
    value = f"{service['scheme']}://{service['hostname']}:{service['port']}{path}"
    return hashlib.sha256(value.encode()).hexdigest()


def structured(parent, value, key=None):
    attributes = {} if key is None else {"key": key}
    if isinstance(value, dict):
        table = ET.SubElement(parent, "table", attributes)
        for item_key, item in value.items():
            structured(table, item, item_key)
    elif isinstance(value, list):
        table = ET.SubElement(parent, "table", attributes)
        for item in value:
            structured(table, item)
    else:
        element = ET.SubElement(parent, "elem", attributes)
        element.text = str(value)


def xml(path, service, data=None):
    root = ET.Element("nmaprun")
    host = ET.SubElement(root, "host")
    ET.SubElement(host, "status", state="up")
    ET.SubElement(host, "address", addr=service["ip"], addrtype="ipv4")
    ET.SubElement(ET.SubElement(host, "hostnames"), "hostname", name=service["hostname"], type="user")
    port = ET.SubElement(ET.SubElement(host, "ports"), "port", portid=str(service["port"]), protocol="tcp")
    ET.SubElement(port, "state", state="open")
    ET.SubElement(port, "service", name="http", **({"tunnel": "ssl"} if service["scheme"] == "https" else {}))
    if data is not None:
        script = ET.SubElement(port, "script", id="http-php2shell")
        for key, value in data.items():
            structured(script, value, key)
    ET.SubElement(ET.SubElement(root, "runstats"), "finished", exit="success", time="1792756800")
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


class CollectionReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="php2shell-collection-report-")
        self.base = Path(self.temporary.name)
        self.services = {}

    def tearDown(self):
        self.temporary.cleanup()

    def service(self, key="app", **options):
        result = identity(**options)
        self.services[key] = {**result, "identity": result.copy(), "service_key": key,
                              "phase_jobs": [], "required_destinations": [], "redirect_results": []}
        return self.services[key]

    def phase(self, service, phase="base", version="", *, path="/", source="x-powered-by",
              state=None, observations=None, requests=1, elapsed=5):
        state = state or ("PATCHED_VERSION_ADVERTISED" if version else "UNKNOWN")
        evidence = ([{"source": source, "version": version, "state": state, "path": path,
                     "collection_phase": phase, "scheme": service["scheme"], "port": service["port"]}]
                    if version else [])
        observation = {"path": path, "path_identity": url_identity(service, path), "http_status": "200",
                       "state": state, "versions": [version] if version else [],
                       "collection_phase": phase, "evidence": evidence}
        job_id = service["service_key"] + "-" + str(len(service["phase_jobs"]))
        filename = "raw/http/" + job_id + ".xml"
        data = {"state": state, "reason": "Local fixture", "reason_code": "FIXED_VERSION_ADVERTISED"
                if version else "PHP_NOT_IDENTIFIED", "vhost": service["hostname"], "scheme": service["scheme"],
                "path": path, "exploitability": "NOT_TESTED", "php_detected": "YES" if version else "UNKNOWN",
                "versions": [version] if version else [], "fixed_versions": ["8.3.36"] if version else [],
                "requests_made": requests, "elapsed_ms": elapsed, "traversal_complete": "true",
                "budget_exhausted": "false", "evidence": evidence,
                "observations": observations or [observation], "collection_phase": phase}
        xml(self.base / filename, service, data)
        service["phase_jobs"].append({"job_id": job_id, "phase": phase, "xml": filename,
                                      "status": "COMPLETED", "requests_made": requests,
                                      "elapsed_ms": elapsed, "paths": [path],
                                      "path_identities": [url_identity(service, path)]})
        return service["phase_jobs"][-1]

    def collection(self):
        return {"schema_version": "1", "status": "COMPLETED", "services": deepcopy(self.services)}

    def merged(self):
        return report.merge_collection_rows([], self.collection(), self.base, "fixture", "2026-10-23T12:00:00+00:00")

    def redirect(self, source, destination, path="/portail/index.php?a=1", *, source_path="/"):
        destination_hash = url_identity(destination, path)
        public = f"{destination['scheme']}://{destination['hostname']}:{destination['port']}{path}"
        if "?" in public:
            public = public.split("?", 1)[0] + "?a=[redacted]"
        observation = {"path": source_path, "path_identity": url_identity(source, source_path),
                       "http_status": "302", "reason_code": "REDIRECT_NOT_ASSESSED",
                       "redirect_to": public, "redirect_identity": destination_hash,
                       "redirect_followed": "false", "redirect_scope": "HORS_PERIMETRE_DU_CONTROLE"}
        destination["required_destinations"].append({"path_identity": destination_hash, "path": path.split("?")[0],
            "source_service_key": source["service_key"], "source_path_identity": observation["path_identity"],
            "chain_hops": 1, "status": "PLANNED"})
        source["redirect_results"].append({"source_path_identity": observation["path_identity"],
            "redirect_identity": destination_hash, "destination_service_keys": [destination["service_key"]],
            "destination_ips": [destination["ip"]], "status": "PLANNED"})
        return observation

    def test_service_phases_merge_without_duplicating_samples_or_compact_targets(self):
        service = self.service()
        self.phase(service, requests=2, elapsed=8)
        self.phase(service, "links", "8.3.36", path="/application.php", requests=1, elapsed=4)
        rows = self.merged()
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["observations"]), 2)
        self.assertEqual([item["collection_phase"] for item in rows[0]["observations"]], ["base", "links"])
        compact = report.compact_rows(rows)
        self.assertEqual(len(compact), 1)
        self.assertEqual(tuple(compact[0]), report.COMPACT_FIELDS)
        self.assertEqual((compact[0]["php"], compact[0]["vulnerable"]), ("8.3.36", "NON"))
        self.assertIn("lien applicatif", compact[0]["explication"])
        metrics = report.collection_metrics(rows, self.collection())
        self.assertEqual((metrics["services_assessed"], metrics["services_version_base"],
                          metrics["services_version_links"], metrics["total_get_requests"],
                          metrics["additional_elapsed_ms"]), (1, 0, 1, 3, 4))

    def test_discovery_service_coverage_is_replaced_and_all_four_tree_views_survive(self):
        service = self.service()
        self.phase(service, version="8.3.36")
        xml(self.base / "raw/discovery.xml", service)
        data = {"schema_version": "1", "tool_version": "0.6.0", "campaign_id": "fixture",
                "status": "COMPLETED", "scope": {"domains": ["example.com"]},
                "targets": [{"hostname": service["hostname"], "dns_status": "RESOLVED",
                             "sources": ["input:fixture.txt"],
                             "addresses": [service["ip"]], "endpoints": [{"ip": service["ip"],
                             "status": "COMPLETED", "returncode": 0, "xml": "raw/discovery.xml"}]}],
                "http_collection": self.collection()}
        result = report.build_campaign_report(data, self.base)
        self.assertEqual(result["summary"]["assessments"], 1)
        self.assertEqual(result["summary"]["coverage_rows"], 0)
        self.assertEqual(result["summary"]["targets_evaluated"], 1)
        self.assertEqual(result["summary"]["collection_metrics"]["services_version_base"], 1)
        self.assertEqual(result["rows"][0]["target_sources"], ["input:fixture.txt"])
        report.write_campaign_report(result, self.base)
        tree = (self.base / "report-tree.txt").read_text()
        self.assertIn("1. INVENTAIRE DES CIBLES FOURNIES", tree)
        self.assertIn("2. DOMAINES ET SOUS-DOMAINES HÉBERGEANT DU PHP", tree)
        self.assertIn("3. ÉLÉMENTS VULNÉRABLES", tree)
        self.assertIn("4. ÉLÉMENTS NON CONCLUSIFS", tree)

    def test_exact_query_destination_does_not_match_another_query_or_another_ip(self):
        source = self.service("http", port=80, scheme="http")
        destination = self.service("https")
        redirect = self.redirect(source, destination)
        self.phase(source, observations=[redirect])
        self.phase(destination, version="8.3.36")
        self.phase(destination, "redirect", "8.3.36", path="/portail/index.php?a=2")
        rows = self.merged()
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "INDETERMINE")
        self.assertFalse(report._true(rows[0]["observations"][0]["redirect_evaluated"]))
        self.phase(destination, "redirect", "8.3.36", path="/portail/index.php?a=1")
        rows = self.merged()
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "NON")
        self.assertTrue(report._true(rows[0]["observations"][0]["redirect_evaluated"]))
        self.services["https"]["ip"] = "192.0.2.11"
        rows = self.merged()
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "INDETERMINE")
        self.assertTrue(any(gap["reason_code"] == "INVALID_SCAN_XML" for gap in rows[-1]["collection_gaps"]))

    def test_other_hostname_runtime_is_only_attributed_to_destination(self):
        source = self.service("alias", host="alias.example.com")
        destination = self.service("application", host="application.example.com")
        self.phase(source, observations=[self.redirect(source, destination, "/application.php")])
        self.phase(destination, "redirect", "8.3.35", path="/application.php", state="POTENTIALLY_VULNERABLE")
        compact = {row["cible"]: row for row in report.compact_rows(self.merged())}
        self.assertEqual((compact[source["hostname"]]["php"], compact[source["hostname"]]["vulnerable"]),
                         ("INCONNUE", "INDETERMINE"))
        self.assertEqual((compact[destination["hostname"]]["php"], compact[destination["hostname"]]["vulnerable"]),
                         ("8.3.35", "OUI"))
        self.assertIn("destination VISITÉE", compact[source["hostname"]]["explication"])

    def test_missing_necessary_destination_blocks_negative_but_preserves_positive(self):
        for state, version, expected in (("PATCHED_VERSION_ADVERTISED", "8.3.36", "INDETERMINE"),
                                         ("POTENTIALLY_VULNERABLE", "8.3.35", "OUI")):
            with self.subTest(state=state):
                self.services = {}
                source, destination = self.service("source"), self.service("destination", port=8443)
                self.phase(source, version=version, state=state,
                           observations=[self.redirect(source, destination, "/portail")])
                destination["phase_jobs"].append({"job_id": "missing", "phase": "redirect",
                                                  "status": "BUDGET_EXHAUSTED"})
                rows = self.merged()
                self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], expected)
                self.assertTrue(rows[0]["collection_gaps"])
                self.assertEqual(report.collection_metrics(rows, self.collection())["services_budget_exhausted"], 1)

    def test_diagnostic_source_conflict_survives_and_metrics_do_not_double_count_gains(self):
        service = self.service()
        self.phase(service, version="8.3.36")
        self.phase(service, "redirect", "8.3.35", source="phpinfo-structured",
                   state="POTENTIALLY_VULNERABLE", path="/diagnostic")
        rows = self.merged()
        self.assertEqual(rows[0]["versions"], "8.3.36 | 8.3.35")
        self.assertEqual(rows[0]["collection_original_reason_code"], "CONFLICTING_VERSIONS")
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "OUI")
        metrics = report.collection_metrics(rows, self.collection())
        self.assertEqual((metrics["services_version_base"], metrics["services_version_redirect"],
                          metrics["services_conflicting_versions"], metrics["services_version_diagnostic_only"]),
                         (1, 0, 1, 0))
        self.assertIn("phpinfo structuré", report.compact_rows(rows)[0]["explication"])

    def test_diagnostic_only_is_measured_without_turning_optional_candidates_into_gaps(self):
        service = self.service()
        service["candidate_paths"] = ["/unselected", "/another-unselected"]
        self.phase(service, version="8.3.36", source="phpinfo-structured")
        rows = self.merged()
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "NON")
        self.assertEqual(report.collection_metrics(rows, self.collection())["services_version_diagnostic_only"], 1)
        self.assertEqual(rows[0]["collection_gaps"], [])

    def test_reused_exact_observation_does_not_create_a_gap_or_duplicate_its_cost(self):
        service = self.service()
        self.phase(service, version="8.3.36", requests=2)
        service["phase_jobs"].append({"job_id": "reused", "phase": "redirect", "status": "REUSED",
                                      "reused_observations": [url_identity(service, "/")]})
        rows = self.merged()
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "NON")
        self.assertEqual(report.collection_metrics(rows, self.collection())["total_get_requests"], 2)

    def test_unfinished_phase_remains_conservative_and_does_not_invent_requests(self):
        service = self.service()
        self.phase(service, version="8.3.36", requests=3)
        service["phase_jobs"].append({"job_id": "interrupted", "phase": "redirect", "status": "RUNNING"})
        service["halted_reason"] = "HTTP_BUDGET_UNCERTAIN"
        rows = self.merged()
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "INDETERMINE")
        self.assertTrue(any("conservativement" in note for note in rows[0]["notes"]))
        self.assertEqual(report.collection_metrics(rows, self.collection())["total_get_requests"], 3)
        ledger = {service["service_key"]: {"charged_requests": 5, "charged_elapsed_ms": 20000,
                    "reservations": {"finished": {"status": "SETTLED", "requests": 3, "budget_ms": 8000},
                                     "uncertain": {"status": "RESERVED", "requests": 2, "budget_ms": 12000}}}}
        metrics = report.collection_metrics(rows, self.collection(), ledger)
        self.assertEqual((metrics["total_get_requests"], metrics["charged_get_quota"],
                          metrics["uncertain_get_quota"], metrics["uncertain_elapsed_ms"]), (3, 5, 2, 12000))

    def test_a_planned_service_is_not_counted_as_an_assessment(self):
        self.service()
        rows = self.merged()
        self.assertEqual((rows[0]["row_type"], rows[0]["state"], rows[0]["reason_code"]),
                         ("COVERAGE", "NOT_ASSESSED", "SCAN_NOT_ATTEMPTED"))
        compact = report.compact_rows(rows)[0]
        self.assertEqual(compact["vulnerable"], "INDETERMINE")
        self.assertNotIn("Ports évalués", compact["explication"])
        self.assertEqual(report.collection_metrics(rows, self.collection())["services_assessed"], 0)

    def test_reassuring_header_on_a_deferred_redirect_does_not_cover_its_destination(self):
        service = self.service()
        observation = {"path": "/", "path_identity": url_identity(service, "/"), "http_status": "302",
                       "state": "PATCHED_VERSION_ADVERTISED", "versions": ["8.3.36"],
                       "redirect_to": "https://outside.example.test/portal", "redirect_followed": "false",
                       "redirect_reason": "Exact destination deferred to the managed redirect phase.",
                       "redirect_identity": "b" * 64}
        self.phase(service, version="8.3.36", observations=[observation])
        service["redirect_results"] = [{"source_path_identity": observation["path_identity"],
            "redirect_identity": observation["redirect_identity"], "destination_ips": [],
            "status": "UNASSESSED", "reason_code": "OUTSIDE_AUTHORIZED_DOMAINS"}]
        rows = self.merged()
        compact = report.compact_rows(rows)[0]
        self.assertEqual(compact["vulnerable"], "INDETERMINE")
        self.assertEqual(rows[0]["reason_code"], "OUTSIDE_AUTHORIZED_DOMAINS")
        self.assertIn("outside.example.test", compact["explication"])

    def test_private_plan_write_error_remains_an_explained_gap(self):
        service = self.service()
        job = self.phase(service, version="8.3.36")
        root = ET.parse(self.base / job["xml"])
        structured(root.getroot().find("./host/ports/port/script"), "true", "private_plan_error")
        root.write(self.base / job["xml"], encoding="utf-8")
        rows = self.merged()
        self.assertEqual(rows[0]["reason_code"], "INPUT_UNAVAILABLE")
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "INDETERMINE")

    def test_imported_legacy_multiport_xml_does_not_duplicate_assessments(self):
        service = self.service()
        job = self.phase(service, version="8.3.36")
        root = ET.parse(self.base / job["xml"])
        ports = root.getroot().find("./host/ports")
        other = deepcopy(ports[0])
        other.set("portid", "8443")
        ports.append(other)
        root.write(self.base / job["xml"], encoding="utf-8")
        job["imported"] = True
        original = report.parse_report(self.base / job["xml"])
        rows = report.merge_collection_rows(original, self.collection(), self.base)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["port"] for row in rows}, {"443", "8443"})
        self.assertTrue(all(row["row_type"] == "ASSESSMENT" for row in rows))

    def test_redirecting_fixed_header_does_not_hide_a_missing_next_hop(self):
        source = self.service("source")
        middle = self.service("middle", host="middle.example.com", port=8443)
        final = self.service("final", host="final.example.com", port=9443)
        first = self.redirect(source, middle, "/middle")
        second = self.redirect(middle, final, "/final", source_path="/middle")
        self.phase(source, version="8.3.36", observations=[first])
        self.phase(middle, "redirect", "8.3.36", path="/middle", observations=[second])
        rows = self.merged()
        compact = {row["cible"]: row for row in report.compact_rows(rows)}
        self.assertEqual(compact[source["hostname"]]["vulnerable"], "INDETERMINE")
        self.assertEqual(compact[middle["hostname"]]["vulnerable"], "INDETERMINE")
        self.phase(final, "redirect", "8.3.36", path="/final")
        rows = self.merged()
        self.assertTrue(all(row["vulnerable"] == "NON" for row in report.compact_rows(rows)))
        self.assertTrue(all(not row["collection_gaps"] for row in rows))

    def test_v060_companion_keeps_its_historical_navigation_verdict(self):
        source = self.service("http", port=80, scheme="http")
        destination = self.service("https")
        self.phase(source, observations=[self.redirect(source, destination, "/")])
        self.phase(destination, version="8.3.36")
        rows = self.merged()
        for row in rows:
            for observation in row.get("observations", []):
                if observation.get("redirect_to"):
                    observation.pop("redirect_conclusive", None)
                    observation.pop("redirect_coverage_reason", None)
                    observation.pop("redirect_destination_http_statuses", None)
                    observation["redirect_scope"] = "HORS_PERIMETRE_DU_CONTROLE"
        historical = [{"cible": "app.example.com", "php": "8.3.36", "vulnerable": "NON",
                       "explication": "Ports évalués : 80,443. Versions annoncées corrigées sur les services évalués ; runtime à confirmer côté serveur. Source publiée : en-têtes HTTP."}]
        details = {"schema_version": "1", "tool_version": "0.6.0", "rows": rows}
        (self.base / "raw").mkdir(exist_ok=True)
        (self.base / "raw/report-details.json").write_text(json.dumps(details), encoding="utf-8")
        (self.base / "report.json").write_text(json.dumps(historical), encoding="utf-8")
        loaded = report.load_campaign_report(self.base / "report.json")
        self.assertEqual(loaded["tool_version"], "0.6.0")
        self.assertEqual(report.compact_rows(rows)[0]["vulnerable"], "INDETERMINE")
        original = deepcopy(loaded)
        fresh = self.base / "reexport"
        report.write_campaign_report(loaded, fresh)
        reloaded = report.load_campaign_report(fresh / "report.json")
        self.assertEqual(reloaded["tool_version"], "0.6.1")
        self.assertEqual(reloaded["rows"], original["rows"])
        self.assertEqual(loaded, original)
        self.assertEqual(json.loads((self.base / "report.json").read_text())[0]["vulnerable"], "NON")


if __name__ == "__main__":
    unittest.main()
