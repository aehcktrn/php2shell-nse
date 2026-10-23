#!/usr/bin/env python3
"""Compare real local continuous and gracefully interrupted HTTP collection.

Only the synthetic name resume.example.test is accepted and DNS is pinned to
loopback. Nmap discovery probes are excluded from the GET counters by User-Agent.
Elapsed milliseconds naturally vary between runs; each run must reconcile its
own completed phase timings and preserve the remaining traversal allowance.
Unknown abrupt-process costs are covered conservatively by the offline budget
and campaign tests, since a missing observation cannot be reconstructed.
"""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from integration import FixtureHandler, LocalServer


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from campaign_state import EventLedger
from report import parse_report
import scan


NAME = "resume.example.test"
BASE_PATHS = ("/", "/index.php", "/third")
EXACT_PATHS = ("/a.php?a=1", "/a.php?a=2")


class ResumeHandler(FixtureHandler):
    """Stable discovery signature and a distinct, versioned exact destination."""

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass  # Normal during Nmap transport/service detection.

    def do_GET(self):
        collector = self.headers.get("User-Agent", "").startswith("php2shell-scanner/")
        supplied_host = self.headers.get("Host", "")
        name = supplied_host.split(":", 1)[0]
        entry = {"host": supplied_host, "path": self.path,
                 "sni": getattr(self.connection, "_test_sni", None), "collector": collector,
                 "scheme": "https" if self.server.is_tls else "http"}
        with self.server.record_lock:
            self.server.requests.append(entry)
        status, headers, body = 200, {}, b"Synthetic stable local service."
        if collector and name == NAME:
            if not self.server.is_tls and self.path in BASE_PATHS[:2]:
                status = 302
                query = 1 if self.path == "/" else 2
                headers["Location"] = f"https://{NAME}:{self.server.tls_port}/a.php?a={query}"
            elif self.server.is_tls and self.path in EXACT_PATHS:
                headers["X-Powered-By"] = "PHP/8.3.36"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class InterruptAfterThreeGETs(EventLedger):
    """Raise at a durable completion boundary, after the quota was settled."""

    interrupted_key = None

    def append(self, kind, key, value):
        super().append(kind, key, value)
        if (type(self).interrupted_key is None and kind == "http_collection"
                and any(job.get("phase") == "base" and job.get("status") == "COMPLETED"
                        and job.get("requests_made") == 3 for job in value.get("phase_jobs", []))):
            type(self).interrupted_key = key
            raise KeyboardInterrupt


class CollectionResumeIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nmap = os.environ.get("NMAP") or shutil.which("nmap")
        openssl = shutil.which("openssl")
        if not cls.nmap or not Path(cls.nmap).is_file() or not openssl:
            raise RuntimeError("Nmap and OpenSSL are required for this local integration test.")
        cls.temporary = tempfile.TemporaryDirectory(prefix="php2shell-real-resume-")
        cls.base = Path(cls.temporary.name)
        cert, key = cls.base / "fixture.crt", cls.base / "fixture.key"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", f"/CN={NAME}", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True, timeout=20)
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cert, key)

        def capture_sni(connection, name, _context):
            connection._test_sni = name

        cls.context.set_servername_callback(capture_sni)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @staticmethod
    def resolve_fixture(name, *_args, **_kwargs):
        if name != NAME:
            raise AssertionError("Refused a non-fixture DNS name: " + name)
        return {"dns_status": "RESOLVED", "addresses": ["127.0.0.1"], "excluded_addresses": [],
                "dns_error": "", "dns_families": {
                    "ipv4": {"status": "RESOLVED", "addresses": ["127.0.0.1"]}}}

    def serve(self, stack):
        # Nmap enumerates ports numerically. HTTP first makes the exact durable
        # interruption point independent of the operating system's port choice.
        servers = sorted((LocalServer(), LocalServer()), key=lambda server: server.server_port)
        http, https = servers
        http.is_tls, https.is_tls = False, True
        http.tls_port = https.server_port
        https.socket = self.context.wrap_socket(https.socket, server_side=True)
        for server in servers:
            server.RequestHandlerClass = ResumeHandler
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def cleanup(server=server, thread=thread):
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            stack.callback(cleanup)
        return http, https

    @staticmethod
    def collected(*servers):
        return [dict(entry) for server in servers for entry in server.requests if entry["collector"]]

    def arguments(self, targets, paths, ports, output):
        return scan.parser().parse_args([str(targets), "--paths-file", str(paths), "--ports", ports,
            "--families", "ipv4", "--allow-non-global", "--workers", "1", "--workers-per-ip", "1",
            "--http-timeout", "2000", "--http-budget", "20000", "--target-timeout", "90",
            "--nmap", self.nmap, "--output", str(output)])

    def run_fresh(self, targets, paths, ports, output, *, interrupt=False):
        text = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(scan, "resolve_target", side_effect=self.resolve_fixture))
            if interrupt:
                stack.enter_context(patch.object(scan, "EventLedger", InterruptAfterThreeGETs))
            stack.enter_context(redirect_stdout(text))
            stack.enter_context(redirect_stderr(text))
            result = scan.run_campaign(self.arguments(targets, paths, ports, output))
        self.assertEqual(result, 130 if interrupt else 0, text.getvalue())
        return json.loads((output / "manifest.json").read_text())

    def assert_complete_collection(self, manifest, output, observed):
        services = manifest["http_collection"]["services"]
        self.assertEqual(len(services), 2)
        self.assertEqual(Counter((entry["scheme"], entry["path"]) for entry in observed), Counter({
            ("http", "/"): 1, ("http", "/index.php"): 1, ("http", "/third"): 1,
            ("https", "/"): 1, ("https", "/index.php"): 1, ("https", "/third"): 1,
            ("https", "/a.php?a=1"): 1, ("https", "/a.php?a=2"): 1}))
        for entry in observed:
            self.assertEqual(entry["host"].split(":", 1)[0], NAME)
            if entry["scheme"] == "https":
                self.assertEqual(entry["sni"], NAME)
        observations = set()
        counts = {}
        versions = {}
        for key, service in services.items():
            budget = manifest["http_services"][key]
            jobs = service["phase_jobs"]
            self.assertTrue(all(job["status"] == "COMPLETED" for job in jobs))
            self.assertEqual(budget["charged_requests"], sum(job["requests_made"] for job in jobs))
            self.assertEqual(budget["charged_elapsed_ms"], sum(job["elapsed_ms"] for job in jobs))
            self.assertLessEqual(budget["charged_requests"], 5)
            self.assertLessEqual(budget["charged_elapsed_ms"], 20000)
            self.assertTrue(all(reservation["status"] == "SETTLED" for reservation in budget["reservations"].values()))
            counts[key] = budget["charged_requests"]
            versions[key] = set()
            for job in jobs:
                rows = [row for row in parse_report(output / job["xml"]) if row["row_type"] == "ASSESSMENT"]
                self.assertEqual(len(rows), 1)
                versions[key].update(filter(None, rows[0]["versions"].split(" | ")))
                observations.update((key, item["path_identity"]) for item in rows[0]["observations"])
            if service["scheme"] == "https":
                self.assertEqual(versions[key], {"8.3.36"})
                self.assertEqual(budget["charged_requests"], 5)
                self.assertEqual(len(service["required_destinations"]), 2)
                self.assertTrue(all(item["status"] == "COMPLETED" for item in service["required_destinations"]))
            else:
                self.assertEqual(budget["charged_requests"], 3)
        return counts, versions, observations

    def test_continuous_and_graceful_resume_issue_the_same_eight_gets(self):
        targets, paths = self.base / "targets.txt", self.base / "paths.txt"
        targets.write_text(NAME + "\n", encoding="utf-8")
        paths.write_text("/third\n", encoding="utf-8")
        with ExitStack() as stack:
            http, https = self.serve(stack)
            ports = f"{http.server_port},{https.server_port}"
            continuous_output = self.base / "continuous"
            continuous = self.run_fresh(targets, paths, ports, continuous_output)
            continuous_observed = self.collected(http, https)
            baseline = self.assert_complete_collection(continuous, continuous_output, continuous_observed)
            for server in (http, https):
                with server.record_lock:
                    server.requests.clear()

            InterruptAfterThreeGETs.interrupted_key = None
            resumed_output = self.base / "resumed"
            paused = self.run_fresh(targets, paths, ports, resumed_output, interrupt=True)
            paused_observed = self.collected(http, https)
            self.assertEqual([entry["path"] for entry in paused_observed], list(BASE_PATHS))
            self.assertTrue(all(entry["scheme"] == "http" for entry in paused_observed))
            interrupted_key = InterruptAfterThreeGETs.interrupted_key
            budget = paused["http_services"][interrupted_key]
            self.assertEqual(budget["charged_requests"], 3)
            remaining_time = 20000 - budget["charged_elapsed_ms"]
            self.assertGreater(remaining_time, 0)
            self.assertTrue(all(item["status"] == "SETTLED" for item in budget["reservations"].values()))

            text = io.StringIO()
            arguments = scan.parser().parse_args(["--resume", str(resumed_output), "--allow-non-global",
                "--workers", "1", "--workers-per-ip", "1", "--target-timeout", "90", "--nmap", self.nmap])
            with patch.object(scan, "resolve_target", side_effect=self.resolve_fixture) as resolver, \
                 redirect_stdout(text), redirect_stderr(text):
                result = scan.resume_campaign(arguments)
            self.assertEqual(result, 0, text.getvalue())
            resolver.assert_not_called()
            resumed = json.loads((resumed_output / "manifest.json").read_text())
            final_observed = self.collected(http, https)
            self.assertEqual(self.assert_complete_collection(resumed, resumed_output, final_observed), baseline)
            self.assertEqual(resumed["http_services"][interrupted_key]["charged_elapsed_ms"], budget["charged_elapsed_ms"])
            self.assertEqual(resumed["http_services"][interrupted_key]["charged_requests"], 3)
            # All observations before the interruption were completed. No GET
            # from that settled service is replayed after the process boundary.
            new_requests = final_observed[len(paused_observed):]
            self.assertTrue(all(entry["scheme"] == "https" for entry in new_requests))
            for service in resumed["http_collection"]["services"].values():
                if service["scheme"] != "https":
                    continue
                base_job = next(job for job in service["phase_jobs"] if job["phase"] == "base")
                base_time = base_job["elapsed_ms"]
                for job in service["phase_jobs"]:
                    if job["phase"] != "redirect":
                        continue
                    options = (resumed_output / "state/private" / (job["job_id"] + ".args")).read_text()
                    maximum = int(re.search(r"http-php2shell.max_requests=(\d+)", options).group(1))
                    milliseconds = int(re.search(r"http-php2shell.budget=(\d+)", options).group(1))
                    self.assertLessEqual(maximum, 2)
                    self.assertLessEqual(milliseconds, 20000 - base_time)


if __name__ == "__main__":
    unittest.main(verbosity=2)
