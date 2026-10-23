"""Offline launcher traversal: exact destinations, pinned scope and shared quotas."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from campaign_state import EventLedger
import http_campaign
import scan
from test_campaign_report import xml_file


def element(parent, tag, text=None, **attributes):
    node = ET.SubElement(parent, tag, attributes)
    node.text = str(text) if text is not None else None
    return node


def discovery_xml(path, hostname, ip, ports):
    """Only Nmap port/service discovery; HTTP observations belong to later jobs."""
    root = ET.Element("nmaprun")
    host = element(root, "host")
    element(host, "status", state="up")
    element(host, "address", addr=ip, addrtype="ipv6" if ":" in ip else "ipv4")
    names = element(host, "hostnames")
    element(names, "hostname", name=hostname, type="user")
    services = element(host, "ports")
    for port, scheme in ports:
        service = element(services, "port", portid=str(port), protocol="tcp")
        element(service, "state", state="open")
        attributes = {"name": "http"}
        if scheme == "https":
            attributes["tunnel"] = "ssl"
        element(service, "service", **attributes)
    stats = element(root, "runstats")
    element(stats, "finished", exit="success", time="1792756800")
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


class FixtureControl:
    """Synthetic completed NSE phases; no process, DNS or socket is opened."""

    def __init__(self, response=None, crash=None):
        self.response = response or (lambda _identity, _phase, _paths: {})
        self.crash = crash
        self.calls = []
        self.discovery_calls = []
        self.stopped = False

    @staticmethod
    def options(command):
        argument_file = Path(command[command.index("--script-args-file") + 1])
        result = {}
        for line in argument_file.read_text().splitlines():
            key, _, raw = line.partition("=")
            raw = raw.rstrip(",")
            if raw.startswith("{"):
                result[key.removeprefix("http-php2shell.")] = json.loads("[" + raw[1:-1] + "]")
            else:
                result[key.removeprefix("http-php2shell.")] = json.loads(raw)
        return result

    def run(self, command, endpoint, output, _timeout):
        if not endpoint.get("collection_phase"):
            self.discovery_calls.append(copy.deepcopy(endpoint))
            discovery_xml(output / endpoint["xml"], "redirected.example.com",
                          endpoint["ip"], [(443, "https")])
            return {**endpoint, "status": "COMPLETED", "returncode": 0}
        identity = endpoint["identity"]
        phase = endpoint["collection_phase"]
        paths = json.loads((output / "state/private" / (endpoint["job_id"] + ".json")).read_text())
        options = self.options(command)
        call = {"identity": copy.deepcopy(identity), "phase": phase, "paths": paths,
                "options": options, "command": list(command)}
        self.calls.append(call)
        if self.crash and self.crash(call):
            raise KeyboardInterrupt
        fixture = self.response(identity, phase, paths)
        version = fixture.get("version")
        redirects = fixture.get("redirects", {})
        requests = fixture.get("requests", min(len(paths) * options["samples"], options["max_requests"]))
        elapsed = fixture.get("elapsed", requests * 100)
        state = "PATCHED_VERSION_ADVERTISED" if version else "UNKNOWN"
        reason = fixture.get("reason", "REDIRECT_NOT_ASSESSED" if redirects else
                             "VERSION_AT_OR_ABOVE_FIX" if version else "PHP_NOT_IDENTIFIED")
        root = ET.Element("nmaprun")
        host = element(root, "host")
        element(host, "status", state="up")
        element(host, "address", addr=identity["ip"], addrtype="ipv6" if ":" in identity["ip"] else "ipv4")
        names = element(host, "hostnames")
        element(names, "hostname", name=identity["hostname"], type="user")
        ports = element(host, "ports")
        port = element(ports, "port", portid=str(identity["port"]), protocol="tcp")
        element(port, "state", state="open")
        attributes = {"name": "http"}
        if identity["scheme"] == "https":
            attributes["tunnel"] = "ssl"
        element(port, "service", **attributes)
        script = element(port, "script", id="http-php2shell")
        fields = {"state": state, "reason": "Synthetic published version fixture", "reason_code": reason,
                  "vhost": identity["hostname"], "scheme": identity["scheme"], "path": http_campaign.public_path(paths[0]),
                  "http_status": "200", "exploitability": "NOT_TESTED", "php_detected": "YES" if version else "UNKNOWN",
                  "requests_made": requests, "elapsed_ms": elapsed, "collection_phase": phase,
                  "traversal_complete": "false" if redirects or reason in http_campaign.HALTS else "true",
                  "traversal_reason_code": reason, "script_version": "0.4.0"}
        for key, value in fields.items():
            element(script, "elem", value, key=key)
        versions = element(script, "table", key="versions")
        evidence = element(script, "table", key="evidence")
        if version:
            element(versions, "elem", version)
            entry = element(evidence, "table")
            for key, value in {"source": "x-powered-by", "version": version, "state": state}.items():
                element(entry, "elem", value, key=key)
        candidates = element(script, "table", key="candidate_paths")
        for candidate in fixture.get("candidates", []):
            element(candidates, "elem", candidate)
        observations = element(script, "table", key="observations")
        redirect_lines = []
        for target in paths[:requests]:
            observation = element(observations, "table")
            origin_id = http_campaign.url_identity(identity["scheme"], identity["hostname"], identity["port"], target)
            for key, value in {"path": http_campaign.public_path(target), "path_identity": origin_id,
                               "http_status": 302 if target in redirects else fixture.get("http_status", 200),
                               "reason_code": "REDIRECT_NOT_ASSESSED" if target in redirects else reason}.items():
                element(observation, "elem", value, key=key)
            if target in redirects:
                destination = http_campaign.parse_destination(redirects[target])
                destination_id = destination["path_identity"]
                element(observation, "elem", destination_id, key="redirect_identity")
                element(observation, "elem", "OUT_OF_SCOPE", key="redirect_scope")
                raw = redirects[target]
                element(observation, "elem", raw.split("?", 1)[0] + ("?[redacted]" if "?" in raw else ""), key="redirect_to")
                redirect_lines.append("\t".join((origin_id, destination_id, raw,
                                                  str(endpoint.get("chain_hops", 0) + 1))))
        Path(options["private_plan"]).write_text("\n".join(redirect_lines), encoding="utf-8")
        stats = element(root, "runstats")
        element(stats, "finished", exit="success", time="1792756800")
        ET.ElementTree(root).write(output / endpoint["xml"], encoding="utf-8", xml_declaration=True)
        return {**endpoint, "status": "COMPLETED", "returncode": 0,
                "started_at": "2026-10-23T12:00:00Z", "finished_at": "2026-10-23T12:00:01Z"}

    def stop(self):
        self.stopped = True


class HTTPCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="php2shell-http-campaign-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.args = scan.parser().parse_args([])
        self.args.nmap = "fixture-nmap"
        self.args.workers = self.args.workers_per_ip = 1
        self.resolve_calls = []
        self.manifest = {"targets": [], "ports": "80,443,8443", "address_families": ["ipv4"],
                         "scope": {"mode": "domains", "domains": ["example.com"],
                                   "excluded_hosts": [], "excluded_subdomains": []},
                         "http": {"paths": ["/", "/index.php"], "timeout_ms": 5000,
                                  "budget_ms": 20000, "max_requests": 5, "redirects": 2, "samples": 1}}
        self.ledger = EventLedger(self.output)

    def add_target(self, name="app.example.com", ip="93.184.216.10", ports=((80, "http"), (443, "https")), paths=None):
        index = len(self.manifest["targets"]) + 1
        xml = f"raw/{index:06d}.xml"
        discovery_xml(self.output / xml, name, ip, ports)
        target = {"hostname": name, "dns_status": "RESOLVED", "addresses": [ip],
                  "requested_paths": paths or ["/", "/index.php"], "endpoints": [
                      {"task_id": f"discovery-{index}", "ip": ip, "family": "ipv4",
                       "ports": self.manifest["ports"], "status": "COMPLETED", "returncode": 0, "xml": xml}]}
        self.manifest["targets"].append(target)
        return target

    def resolve(self, name, *_args):
        self.resolve_calls.append(name)
        return {"dns_status": "RESOLVED", "addresses": ["93.184.216.50"], "dns_error": ""}

    def collect(self, control):
        with patch.object(http_campaign.shutil, "which", return_value="/fixture/nmap"):
            return http_campaign.run_collection(self.manifest, self.output, self.args, control, self.ledger,
                resolve=self.resolve, validate_hostname=scan.hostname, exclusion=scan.exclusion_reason,
                save=scan.atomic_json, endpoint_identity=scan.endpoint_task_id)

    def services(self):
        return list(self.manifest["http_collection"]["services"].values())

    def legacy_resume(self, *, status, attempts, complete_xml=False):
        self.add_target(ports=((443, "https"),))
        self.manifest.update(schema_version="1", tool_version="0.5.5", campaign_id="legacy-fixture",
                             profile="quick", status="PARTIAL")
        target = self.manifest["targets"][0]
        endpoint = target["endpoints"][0]
        endpoint.update(status=status, attempts=attempts,
                        returncode=0 if status == "COMPLETED" else None if status == "PLANNED" else 1,
                        stdout="raw/000001.stdout.log", stderr="raw/000001.stderr.log",
                        command=["/fixture/nmap", "--script", "http-php2shell.nse", endpoint["ip"]])
        endpoint["task_id"] = scan.endpoint_task_id(target["hostname"], endpoint,
                                                    target["requested_paths"], self.manifest["http"])
        if complete_xml:
            xml_file(self.output / endpoint["xml"], name=target["hostname"], ip=endpoint["ip"],
                     state="PATCHED_VERSION_ADVERTISED", version="8.3.36")
            document = ET.parse(self.output / endpoint["xml"])
            script = document.find(".//script[@id='http-php2shell']")
            script.find("elem[@key='requests_made']").text = "3"
            element(script, "elem", "3500", key="elapsed_ms")
            document.write(self.output / endpoint["xml"], encoding="utf-8", xml_declaration=True)
        elif status != "PLANNED":
            (self.output / endpoint["xml"]).write_text("<nmaprun>", encoding="utf-8")
        scan.atomic_json(self.output / "manifest.json", self.manifest)
        control = FixtureControl(lambda *_args: {"version": "8.3.36"})
        arguments = scan.parser().parse_args(["--resume", str(self.output), "--workers", "1"])
        with patch.object(scan.shutil, "which", return_value="/fixture/nmap"), \
             patch.object(scan.Processes, "run", side_effect=control.run), \
             patch.object(scan, "resolve_target") as resolver, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = scan.resume_campaign(arguments)
        resolver.assert_not_called()
        self.manifest = json.loads((self.output / "manifest.json").read_text())
        return code, control

    def test_failed_pre_06_campaign_keeps_unknown_previous_http_cost_charged_on_migration(self):
        code, control = self.legacy_resume(status="FAILED", attempts=[{"number": 1, "status": "FAILED"}])
        self.assertEqual(code, 2)
        self.assertEqual(len(control.discovery_calls), 1)
        self.assertEqual(control.calls, [])
        endpoint = self.manifest["targets"][0]["endpoints"][0]
        self.assertTrue(endpoint["legacy_http_budget_uncertain"])
        service = self.services()[0]
        self.assertEqual(service["phase_jobs"][0]["status"], "INTERRUPTED")
        self.assertEqual(service["phase_jobs"][0]["error"], "HTTP_BUDGET_UNCERTAIN")
        quota = self.manifest["http_services"][service["service_key"]]
        self.assertEqual((quota["charged_requests"], quota["charged_elapsed_ms"]), (5, 20000))
        self.assertEqual({reservation["status"] for reservation in quota["reservations"].values()}, {"RESERVED"})

    def test_unattempted_pre_06_planned_endpoint_can_collect_its_first_allowance(self):
        code, control = self.legacy_resume(status="PLANNED", attempts=[])
        self.assertEqual(code, 0)
        self.assertFalse(self.manifest["targets"][0]["endpoints"][0].get("legacy_http_budget_uncertain"))
        self.assertEqual(len(control.discovery_calls), 1)
        self.assertEqual([(call["phase"], call["options"]["max_requests"]) for call in control.calls], [("base", 5)])

    def test_valid_completed_pre_06_xml_is_reused_with_its_observed_counters(self):
        code, control = self.legacy_resume(status="COMPLETED", attempts=[{"number": 1, "status": "COMPLETED"}], complete_xml=True)
        self.assertEqual(code, 0)
        self.assertEqual(control.discovery_calls, [])
        self.assertEqual(control.calls, [])
        self.assertFalse(self.manifest["targets"][0]["endpoints"][0].get("legacy_http_budget_uncertain"))
        quota = self.manifest["http_services"][self.services()[0]["service_key"]]
        self.assertEqual((quota["charged_requests"], quota["charged_elapsed_ms"]), (3, 3500))

    def test_imported_legacy_zero_counters_remain_zero(self):
        self.add_target(ports=((443, "https"),))
        path = self.output / self.manifest["targets"][0]["endpoints"][0]["xml"]
        xml_file(path, name="app.example.com", ip="93.184.216.10",
                 state="PATCHED_VERSION_ADVERTISED", version="8.3.36")
        root = ET.parse(path)
        script = root.find(".//script[@id='http-php2shell']")
        script.find("elem[@key='requests_made']").text = "0"
        element(script, "elem", "0", key="elapsed_ms")
        root.write(path, encoding="utf-8", xml_declaration=True)
        control = FixtureControl()
        self.collect(control)
        self.assertEqual(control.calls, [])
        quota = self.manifest["http_services"][self.services()[0]["service_key"]]
        self.assertEqual((quota["charged_requests"], quota["charged_elapsed_ms"]), (0, 0))

    def test_imported_legacy_access_denied_and_rate_limit_keep_the_service_halted(self):
        for index, reason in enumerate(("HTTP_ACCESS_DENIED", "RATE_LIMITED")):
            self.add_target(name=f"legacy-{index}.example.com", ip=f"93.184.216.{20 + index}", ports=((443, "https"),))
            target = self.manifest["targets"][-1]
            path = self.output / target["endpoints"][0]["xml"]
            xml_file(path, name=target["hostname"], ip=target["addresses"][0], state="UNKNOWN", version="")
            root = ET.parse(path)
            script = root.find(".//script[@id='http-php2shell']")
            script.find("elem[@key='reason_code']").text = reason
            element(script, "elem", reason, key="traversal_reason_code")
            element(script, "elem", "100", key="elapsed_ms")
            root.write(path, encoding="utf-8", xml_declaration=True)
        control = FixtureControl()
        self.collect(control)
        self.assertEqual(control.calls, [])
        for service in self.services():
            quota = self.manifest["http_services"][service["service_key"]]
            self.assertIn(service["halted_reason"], ("HTTP_ACCESS_DENIED", "RATE_LIMITED"))
            self.assertEqual(quota["halted_reason"], service["halted_reason"])

    def test_imported_reassuring_banner_does_not_hide_an_observed_access_stop(self):
        for index, status in enumerate((401, 403, 429)):
            self.add_target(name=f"fixed-{index}.example.com", ip=f"93.184.216.{30 + index}", ports=((443, "https"),))
            target = self.manifest["targets"][-1]
            path = self.output / target["endpoints"][0]["xml"]
            xml_file(path, name=target["hostname"], ip=target["addresses"][0],
                     state="PATCHED_VERSION_ADVERTISED", version="8.3.36")
            root = ET.parse(path)
            script = root.find(".//script[@id='http-php2shell']")
            script.find("elem[@key='reason_code']").text = "VERSION_AT_OR_ABOVE_FIX"
            script.find("elem[@key='http_status']").text = str(status)
            observation = script.find("table[@key='observations']/table")
            observation.find("elem[@key='http_status']").text = str(status)
            element(script, "elem", "100", key="elapsed_ms")
            root.write(path, encoding="utf-8", xml_declaration=True)
        control = FixtureControl()
        self.collect(control)
        self.assertEqual(control.calls, [])
        expected = {"AUTHENTICATION_REQUIRED", "HTTP_ACCESS_DENIED", "RATE_LIMITED"}
        self.assertEqual({service["halted_reason"] for service in self.services()}, expected)
        self.assertEqual({quota["halted_reason"] for quota in self.manifest["http_services"].values()}, expected)

    def test_nmap_phase_probes_keep_the_configured_maximum_rate(self):
        self.args.max_rate = 7
        self.add_target(ports=((443, "https"),))
        control = FixtureControl(lambda *_args: {"version": "8.3.36"})
        self.collect(control)
        command = control.calls[0]["command"]
        self.assertEqual(command[command.index("--max-rate") + 1], "7")

    def test_http_to_https_visits_the_exact_application_destination_and_pinned_vhost(self):
        self.add_target()

        def response(identity, phase, paths):
            if identity["scheme"] == "http":
                return {"redirects": {"/": "https://app.example.com/portail/index.php?a=42"}}
            return {"version": "8.3.36"} if paths == ["/portail/index.php?a=42"] else {}

        control = FixtureControl(response)
        self.assertFalse(self.collect(control))
        exact = [call for call in control.calls if call["phase"] == "redirect"]
        self.assertEqual(len(exact), 1)
        self.assertEqual(exact[0]["paths"], ["/portail/index.php?a=42"])
        self.assertEqual(exact[0]["identity"], {"hostname": "app.example.com", "ip": "93.184.216.10", "port": 443, "scheme": "https"})
        self.assertEqual(exact[0]["options"]["vhost"], "app.example.com")
        self.assertEqual(exact[0]["options"]["scheme"], "https")
        self.assertEqual(exact[0]["command"][-1], "93.184.216.10")
        self.assertEqual(self.resolve_calls, [])
        https = next(service for service in self.services() if service["scheme"] == "https")
        self.assertEqual(https["required_destinations"][0]["status"], "COMPLETED")
        self.assertNotIn("a=42", json.dumps(self.manifest))
        self.assertNotIn("a=42", self.ledger.path.read_text())

    def test_authorized_other_hostname_owns_its_runtime_and_uses_its_own_host(self):
        self.add_target("source.example.com", ports=((80, "http"),))
        self.add_target("target.example.com", "93.184.216.11", ports=((443, "https"),))
        response = lambda identity, phase, paths: ({"redirects": {"/": "https://target.example.com/app.php"}}
                    if identity["hostname"] == "source.example.com" else
                    {"version": "8.3.36"} if phase == "redirect" else {})
        control = FixtureControl(response)
        self.collect(control)
        exact = next(call for call in control.calls if call["phase"] == "redirect")
        self.assertEqual((exact["options"]["vhost"], exact["command"][-1]), ("target.example.com", "93.184.216.11"))
        source = next(service for service in self.services() if service["hostname"] == "source.example.com")
        target = next(service for service in self.services() if service["hostname"] == "target.example.com")
        self.assertFalse(any(job["phase"] == "redirect" for job in source["phase_jobs"]))
        self.assertTrue(any(job["phase"] == "redirect" for job in target["phase_jobs"]))

    def test_exact_unicode_destination_is_not_serialized_as_json_unicode_escapes(self):
        self.add_target()
        target = "/café.php?clé=été"
        control = FixtureControl(lambda identity, phase, paths:
            {"redirects": {"/": "https://app.example.com" + target}}
            if identity["scheme"] == "http" else {})
        self.collect(control)
        exact = next(call for call in control.calls if call["phase"] == "redirect")
        arguments = Path(exact["command"][exact["command"].index("--script-args-file") + 1]).read_text()
        self.assertIn(target, arguments)
        self.assertNotIn("\\u00", arguments)
        self.assertEqual(exact["options"]["path"], target)

    def test_new_authorized_hostname_is_validated_resolved_and_discovered_before_its_get(self):
        self.add_target("source.example.com", ports=((80, "http"),))

        def response(identity, phase, _paths):
            if identity["hostname"] == "source.example.com":
                return {"redirects": {"/": "https://redirected.example.com/application.php"}}
            return {"version": "8.3.36"} if phase == "redirect" else {}

        control = FixtureControl(response)
        self.collect(control)
        self.assertEqual(self.resolve_calls, ["redirected.example.com"])
        self.assertEqual(len(control.discovery_calls), 1)
        self.assertEqual(control.discovery_calls[0]["ip"], "93.184.216.50")
        redirected = next(call for call in control.calls if call["phase"] == "redirect")
        self.assertEqual(redirected["paths"], ["/application.php"])
        self.assertEqual(redirected["options"]["vhost"], "redirected.example.com")
        self.assertEqual(redirected["command"][-1], "93.184.216.50")
        self.assertEqual({target["hostname"] for target in self.manifest["targets"]},
                         {"source.example.com", "redirected.example.com"})

    def test_forbidden_resolved_address_is_never_probed_even_by_nmap_discovery(self):
        self.add_target(ports=((80, "http"),))

        def forbidden(name, *_args):
            self.resolve_calls.append(name)
            # Validate addresses defensively even when a resolver's serialized
            # result unexpectedly contains a forbidden address.
            return {"dns_status": "RESOLVED", "addresses": ["127.0.0.1"],
                    "excluded_addresses": ["127.0.0.1"]}

        self.resolve = forbidden
        control = FixtureControl(lambda *_args: {"redirects": {"/": "https://private.example.com/app.php"}})
        self.collect(control)
        self.assertEqual(control.discovery_calls, [])
        self.assertEqual(len(control.calls), 1)
        result = self.services()[0]["redirect_results"][0]
        self.assertEqual(result["status"], "UNASSESSED")
        self.assertEqual(result["reason_code"], "NO_PUBLIC_ADDRESS")

    def test_new_hostname_base_observation_satisfies_pending_redirect_without_an_extra_get(self):
        self.add_target("source.example.com", ports=((80, "http"),))
        self.args.samples = 2
        control = FixtureControl(lambda identity, phase, paths:
            {"redirects": {"/": "https://redirected.example.com/index.php"}}
            if identity["hostname"] == "source.example.com" else {})
        self.collect(control)
        self.assertEqual([call["phase"] for call in control.calls], ["base", "base"])
        self.assertTrue(all(call["options"]["samples"] == 2 for call in control.calls))
        destination = next(service for service in self.services() if service["hostname"] == "redirected.example.com")
        self.assertTrue(any(job["status"] == "REUSED" for job in destination["phase_jobs"]))
        self.assertEqual(destination["required_destinations"][0]["status"], "COMPLETED")

    def test_external_excluded_and_unauthorized_port_destinations_are_never_contacted(self):
        for destination, cause in (("https://external.invalid/app.php", "OUTSIDE_AUTHORIZED_DOMAINS"),
                                   ("https://excluded.example.com/app.php", "EXCLUDED_BY_OPERATOR"),
                                   ("https://app.example.com:4443/app.php", "UNAUTHORIZED_PORT")):
            with self.subTest(destination=destination):
                self.manifest["http_collection"] = {"services": {}}
                self.manifest["http_services"] = {}
                self.manifest["targets"] = []
                self.manifest["scope"]["excluded_hosts"] = ["excluded.example.com"]
                self.add_target(ports=((80, "http"),))
                control = FixtureControl(lambda *_args: {"redirects": {"/": destination}})
                self.collect(control)
                self.assertEqual(len(control.calls), 1)
                self.assertEqual(self.resolve_calls, [])
                self.assertEqual(control.discovery_calls, [])
                self.assertEqual(self.services()[0]["redirect_results"][0]["reason_code"], cause)

    def test_redirect_target_limit_is_checked_before_dns_or_discovery(self):
        self.add_target(ports=((80, "http"),))
        control = FixtureControl(lambda *_args:
            {"redirects": {"/": "https://new.example.com/index.php"}})
        with patch.object(http_campaign, "MAX_CAMPAIGN_TARGETS", 1):
            self.collect(control)
        self.assertEqual(self.resolve_calls, [])
        self.assertEqual(control.discovery_calls, [])
        self.assertEqual(self.services()[0]["redirect_results"][0]["reason_code"], "REDIRECT_PLAN_LIMIT")

    def test_redirect_edge_limit_prevents_access_before_overflow(self):
        self.add_target(ports=((80, "http"),))
        control = FixtureControl(lambda identity, phase, paths:
            {"redirects": {"/": "https://first.example.com/index.php",
                           "/index.php": "https://second.example.com/index.php"}}
            if identity["hostname"] == "app.example.com" else {})
        with patch.object(http_campaign, "MAX_REDIRECT_DESTINATIONS", 1):
            self.collect(control)
        self.assertEqual(self.resolve_calls, ["first.example.com"])
        source = next(service for service in self.services() if service["hostname"] == "app.example.com")
        self.assertEqual(source["redirect_results"][-1]["reason_code"], "REDIRECT_PLAN_LIMIT")

    def test_identical_redirect_destinations_are_requested_only_once(self):
        self.add_target(ports=((80, "http"), (443, "https")))

        def response(identity, phase, paths):
            if identity["scheme"] == "http":
                return {"redirects": {"/": "https://app.example.com/app.php?a=1",
                                      "/index.php": "https://app.example.com/app.php?a=1"}}
            return {}

        control = FixtureControl(response)
        self.collect(control)
        self.assertEqual([call["paths"] for call in control.calls if call["phase"] == "redirect"], [["/app.php?a=1"]])

    def test_two_source_services_share_one_destination_request_and_retain_both_requirements(self):
        self.add_target("one.example.com", ports=((80, "http"),))
        self.add_target("two.example.com", "93.184.216.11", ports=((80, "http"),))
        self.add_target("target.example.com", "93.184.216.12", ports=((443, "https"),))
        response = lambda identity, _phase, _paths: ({"redirects": {"/": "https://target.example.com/app.php"}}
                   if identity["hostname"] != "target.example.com" else {})
        control = FixtureControl(response)
        self.collect(control)
        exact = [call for call in control.calls if call["phase"] == "redirect"]
        self.assertEqual(len(exact), 1)
        target = next(service for service in self.services() if service["hostname"] == "target.example.com")
        self.assertEqual(len(target["required_destinations"]), 2)
        self.assertTrue(all(item["status"] == "COMPLETED" for item in target["required_destinations"]))

    def test_different_queries_share_one_service_quota_without_starving_the_second_job(self):
        self.args.workers = self.args.workers_per_ip = 2
        self.add_target()

        def response(identity, phase, paths):
            if identity["scheme"] == "http":
                return {"redirects": {"/": "https://app.example.com/app.php?a=1",
                                      "/index.php": "https://app.example.com/app.php?a=2"}}
            return {}

        control = FixtureControl(response)
        self.collect(control)
        exact = [call["paths"] for call in control.calls if call["phase"] == "redirect"]
        self.assertEqual(sorted(exact), [["/app.php?a=1"], ["/app.php?a=2"]])
        https = next(service for service in self.services() if service["scheme"] == "https")
        self.assertTrue(all(item["status"] == "COMPLETED" for item in https["required_destinations"]))
        self.assertEqual(self.manifest["http_services"][https["service_key"]]["charged_requests"], 4)

    def test_reassuring_observation_of_another_query_never_covers_the_exact_redirect(self):
        self.add_target(paths=["/app.php?a=1"])

        def response(identity, phase, _paths):
            if identity["scheme"] == "http":
                return {"redirects": {"/app.php?a=1": "https://app.example.com/app.php?a=2"}}
            return {"version": "8.3.36"} if phase == "base" else {}

        control = FixtureControl(response)
        self.collect(control)
        exact = [call for call in control.calls if call["phase"] == "redirect"]
        self.assertEqual(len(exact), 1)
        self.assertEqual(exact[0]["paths"], ["/app.php?a=2"])

    def test_an_observation_of_the_same_exact_destination_can_cover_the_redirect_without_a_new_get(self):
        self.add_target(paths=["/app.php?a=1"])
        response = lambda identity, _phase, _paths: ({"redirects": {"/app.php?a=1": "https://app.example.com/app.php?a=1"}}
                   if identity["scheme"] == "http" else {"version": "8.3.36"})
        control = FixtureControl(response)
        self.collect(control)
        self.assertFalse(any(call["phase"] == "redirect" for call in control.calls))
        https = next(service for service in self.services() if service["scheme"] == "https")
        self.assertEqual(https["required_destinations"][0]["status"], "COMPLETED")

    def test_redirect_loop_stops_without_resetting_the_chain(self):
        self.add_target()

        def response(identity, phase, paths):
            if identity["scheme"] == "http":
                return {"redirects": {"/": "https://app.example.com/loop"}}
            if phase == "redirect":
                return {"redirects": {"/loop": "http://app.example.com/"}}
            return {}

        control = FixtureControl(response)
        self.collect(control)
        self.assertEqual(len(control.calls), 3)
        outcomes = [item for service in self.services() for item in service["redirect_results"]]
        self.assertIn("REDIRECT_LOOP", [item.get("reason_code") for item in outcomes])

    def test_cross_origin_chain_limit_does_not_reset_when_switching_services(self):
        self.args.redirects = 1
        self.add_target()

        def response(identity, phase, _paths):
            if identity["scheme"] == "http":
                return {"redirects": {"/": "https://app.example.com/first"}}
            return {"redirects": {"/first": "http://app.example.com/second"}} if phase == "redirect" else {}

        control = FixtureControl(response)
        self.collect(control)
        self.assertEqual([call["paths"] for call in control.calls if call["phase"] == "redirect"], [["/first"]])
        outcomes = [item for service in self.services() for item in service["redirect_results"]]
        self.assertIn("CHAIN_LIMIT", [item.get("reason_code") for item in outcomes])

    def test_required_exact_destinations_consume_the_allowance_before_optional_links(self):
        self.add_target()

        def response(identity, phase, paths):
            if identity["scheme"] == "http":
                return {"redirects": {"/": "https://app.example.com/required.php"}}
            if phase == "base":
                return {"candidates": ["/alpha", "/beta"]}
            return {}

        control = FixtureControl(response)
        self.collect(control)
        https = [call for call in control.calls if call["identity"]["scheme"] == "https"]
        self.assertEqual([call["phase"] for call in https], ["base", "redirect", "links"])
        self.assertEqual(https[1]["paths"], ["/required.php"])
        self.assertEqual(https[2]["options"]["max_requests"], 2)

    def test_denied_response_with_fixed_banner_still_halts_all_later_phases(self):
        self.add_target("source.example.com", ports=((80, "http"),), paths=["/"])
        self.add_target("target.example.com", "93.184.216.11", ports=((443, "https"),), paths=["/"])
        control = FixtureControl(lambda identity, phase, paths:
            {"redirects": {"/": "https://target.example.com/other.php"}}
            if identity["hostname"] == "source.example.com" else
            {"version": "8.3.36", "http_status": 429})
        self.collect(control)
        self.assertEqual([call["phase"] for call in control.calls], ["base", "base"])
        target = next(service for service in self.services() if service["hostname"] == "target.example.com")
        self.assertEqual(target["halted_reason"], "RATE_LIMITED")
        self.assertEqual(target["required_destinations"][0]["reason_code"], "RATE_LIMITED")

    def test_optional_navigation_is_at_most_two_nonrecursive_visits(self):
        self.add_target(ports=((443, "https"),))

        def response(_identity, phase, _paths):
            return {"candidates": ["/alpha", "/beta", "/gamma"]} if phase == "base" else {"candidates": ["/recursive"]}

        control = FixtureControl(response)
        self.collect(control)
        self.assertEqual([(call["phase"], call["paths"]) for call in control.calls],
                         [("base", ["/", "/index.php"]), ("links", ["/alpha", "/beta"])])
        key = self.services()[0]["service_key"]
        self.assertEqual(self.manifest["http_services"][key]["charged_requests"], 4)

    def test_explicit_samples_are_preserved_on_base_paths(self):
        self.args.samples = 2
        self.add_target(ports=((443, "https"),), paths=["/explicit.php"])
        control = FixtureControl(lambda *_args: {"version": "8.3.36"})
        self.collect(control)
        self.assertEqual(control.calls[0]["options"]["samples"], 2)
        self.assertEqual(control.calls[0]["paths"], ["/explicit.php"])
        self.assertEqual(self.manifest["http_services"][self.services()[0]["service_key"]]["charged_requests"], 2)

    def test_exact_redirect_keeps_explicit_samples_and_the_destination_remaining_allowance(self):
        self.args.samples = 2
        self.add_target(paths=["/"])

        def response(identity, phase, _paths):
            if identity["scheme"] == "http":
                return {"redirects": {"/": "https://app.example.com/exact.php"}}
            return {"version": "8.3.36"} if phase == "redirect" else {}

        control = FixtureControl(response)
        self.collect(control)
        redirect = next(call for call in control.calls if call["phase"] == "redirect")
        self.assertEqual(redirect["paths"], ["/exact.php"])
        self.assertEqual(redirect["options"]["samples"], 2)
        self.assertEqual(redirect["options"]["max_requests"], 3)
        self.assertEqual(redirect["options"]["budget"], 19800)
        key = next(service["service_key"] for service in self.services() if service["scheme"] == "https")
        self.assertEqual(self.manifest["http_services"][key]["charged_requests"], 4)

    def test_a_version_on_one_port_keeps_other_selected_ports_and_skips_optional_links(self):
        self.add_target(ports=((80, "http"), (443, "https"), (8443, "https")))
        control = FixtureControl(lambda *_args: {"version": "8.3.36", "candidates": ["/alpha", "/beta"]})
        self.collect(control)
        self.assertEqual({call["identity"]["port"] for call in control.calls}, {80, 443, 8443})
        self.assertTrue(all(call["phase"] == "base" for call in control.calls))
        self.assertTrue(all(call["paths"] == ["/", "/index.php"] for call in control.calls))

    def test_authentication_halt_prevents_optional_visits(self):
        self.add_target(ports=((443, "https"),))
        control = FixtureControl(lambda *_args: {"reason": "HTTP_ACCESS_DENIED", "requests": 1,
                                                "candidates": ["/alpha", "/beta"]})
        self.collect(control)
        self.assertEqual(len(control.calls), 1)
        self.assertEqual(self.services()[0]["halted_reason"], "HTTP_ACCESS_DENIED")

    def test_legacy_completed_collection_is_charged_once_and_never_restarted_with_fresh_quota(self):
        self.add_target(ports=((443, "https"),))
        source = self.output / self.manifest["targets"][0]["endpoints"][0]["xml"]
        xml_file(source, name="app.example.com", ip="93.184.216.10", port=443,
                 state="PATCHED_VERSION_ADVERTISED", version="8.3.36")
        root = ET.parse(source)
        script = root.find(".//script[@id='http-php2shell']")
        script.find("elem[@key='requests_made']").text = "3"
        element(script, "elem", "3500", key="elapsed_ms")
        root.write(source, encoding="utf-8", xml_declaration=True)
        initial = copy.deepcopy(self.manifest)
        control = FixtureControl()
        self.collect(control)
        self.assertEqual(control.calls, [])
        key = self.services()[0]["service_key"]
        self.assertEqual((self.manifest["http_services"][key]["charged_requests"],
                          self.manifest["http_services"][key]["charged_elapsed_ms"]), (3, 3500))
        self.manifest = self.ledger.replay(initial)
        self.collect(control)
        self.assertEqual(control.calls, [])
        self.assertEqual(self.manifest["http_services"][key]["charged_requests"], 3)
        self.assertEqual(len(self.services()[0]["phase_jobs"]), 1)

    def test_lost_private_query_input_is_reported_without_reconstructing_or_guessing_it(self):
        self.add_target()
        initial = copy.deepcopy(self.manifest)
        original_append = self.ledger.append

        def interrupt_after_planning(kind, key, value):
            original_append(kind, key, value)
            if (kind == "http_collection"
                    and any(job.get("phase") == "redirect" and job.get("status") == "PLANNED"
                            for job in value["phase_jobs"])):
                raise KeyboardInterrupt

        self.ledger.append = interrupt_after_planning
        response = lambda identity, _phase, _paths: ({"redirects": {"/": "https://app.example.com/app.php?secret=42"}}
                   if identity["scheme"] == "http" else {})
        with self.assertRaises(KeyboardInterrupt):
            self.collect(FixtureControl(response))
        self.ledger = EventLedger(self.output)
        self.manifest = self.ledger.replay(initial)
        redirect = next(job for service in self.services() for job in service["phase_jobs"] if job["phase"] == "redirect")
        (self.output / "state/private" / (redirect["job_id"] + ".json")).unlink()
        resumed = FixtureControl(response)
        self.collect(resumed)
        self.assertFalse(any(call["phase"] == "redirect" for call in resumed.calls))
        self.assertEqual(redirect["status"], "INPUT_UNAVAILABLE")
        self.assertEqual(redirect["error"], "PRIVATE_INPUT_UNAVAILABLE")

    def test_unknown_interrupted_phase_cannot_spend_a_new_allowance_on_resume(self):
        self.add_target(ports=((443, "https"),))
        initial = copy.deepcopy(self.manifest)
        crashed = FixtureControl(crash=lambda _call: True)
        self.assertTrue(self.collect(crashed))
        self.assertTrue(crashed.stopped)
        self.manifest = self.ledger.replay(initial)
        resumed = FixtureControl()
        self.assertFalse(self.collect(resumed))
        self.assertEqual(resumed.calls, [])
        key = self.services()[0]["service_key"]
        self.assertEqual(self.manifest["http_services"][key]["charged_requests"], 5)
        self.assertEqual(self.manifest["http_services"][key]["charged_elapsed_ms"], 20000)

    def test_three_completed_gets_then_resume_match_continuous_counts_and_remaining_time(self):
        self.add_target(ports=((443, "https"),))
        initial = copy.deepcopy(self.manifest)
        original_append = self.ledger.append
        interrupted = False

        def interrupt_after_completed(kind, key, value):
            nonlocal interrupted
            original_append(kind, key, value)
            if (not interrupted and kind == "http_collection"
                    and any(job.get("status") == "COMPLETED" for job in value["phase_jobs"])):
                interrupted = True
                raise KeyboardInterrupt

        self.ledger.append = interrupt_after_completed
        response = lambda _identity, phase, _paths: ({"requests": 3, "elapsed": 3500,
                    "candidates": ["/alpha", "/beta"]} if phase == "base" else {})
        first = FixtureControl(response)
        self.assertTrue(self.collect(first))
        self.ledger = EventLedger(self.output)
        self.manifest = self.ledger.replay(initial)
        resumed = FixtureControl(response)
        self.assertFalse(self.collect(resumed))
        self.assertEqual([(call["phase"], call["paths"]) for call in resumed.calls], [("links", ["/alpha", "/beta"])])
        self.assertEqual(resumed.calls[0]["options"]["max_requests"], 2)
        self.assertEqual(resumed.calls[0]["options"]["budget"], 16500)
        key = self.services()[0]["service_key"]
        self.assertEqual(self.manifest["http_services"][key]["charged_requests"], 5)
        resumed_totals = (self.manifest["http_services"][key]["charged_requests"],
                          self.manifest["http_services"][key]["charged_elapsed_ms"])
        resumed_jobs = [(job["phase"], job["paths"], job["status"]) for job in self.services()[0]["phase_jobs"]]
        self.output = self.output / "continuous"
        self.output.mkdir()
        self.manifest = copy.deepcopy(initial)
        discovery_xml(self.output / "raw/000001.xml", "app.example.com", "93.184.216.10", [(443, "https")])
        self.ledger = EventLedger(self.output)
        continuous = FixtureControl(response)
        self.assertFalse(self.collect(continuous))
        continuous_record = self.manifest["http_services"][key]
        self.assertEqual((continuous_record["charged_requests"], continuous_record["charged_elapsed_ms"]), resumed_totals)
        self.assertEqual([(job["phase"], job["paths"], job["status"]) for job in self.services()[0]["phase_jobs"]], resumed_jobs)


class ExactURLTests(unittest.TestCase):
    def test_queries_and_meaningful_encodings_keep_distinct_internal_identities(self):
        identify = lambda target: http_campaign.url_identity(
            "https", "app.example.com", 443, target)
        values = ("/index.php?a=1", "/index.php?a=2", "/index.php?a=1&b=2",
                  "/index.php?b=2&a=1", "/%2Findex.php?a=1", "//index.php?a=1")
        self.assertEqual(len({identify(value) for value in values}), len(values))
        self.assertEqual(identify(values[0]), identify(values[0]))

    def test_exact_destination_preserves_query_and_discards_fragment(self):
        destination = http_campaign.parse_destination(
            "https://app.example.com:8443/portail/index.php?a=1&b=%2F#section")
        self.assertEqual(destination["scheme"], "https")
        self.assertEqual(destination["hostname"], "app.example.com")
        self.assertEqual(destination["port"], 8443)
        self.assertEqual(destination["target"], "/portail/index.php?a=1&b=%2F")

    def test_non_web_credentials_and_malformed_destinations_are_rejected(self):
        for url in ("file:///etc/passwd", "ftp://app.example.com/path",
                    "https://user:password@app.example.com/", "//app.example.com/",
                    "https://app.example.com:0/", "https://app.example.com:65536/",
                    "https://app.example.com/path\r\nInjected: header"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                http_campaign.parse_destination(url)


if __name__ == "__main__":
    unittest.main()
