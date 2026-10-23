#!/usr/bin/env python3
"""Run the campaign CLI end to end against synthetic loopback services only.

Run explicitly with: python3 tests/test_scan_integration.py
NMAP and NMAP_DATADIR select the real Nmap executable and its data directory.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import csv
from datetime import datetime, timezone
import errno
import io
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from integration import FixtureHandler, LocalServer, SECRET_BODY, phpinfo_html


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import scan

FINGERPRINT_SECRET = "SYNTHETIC_NMAP_ENVIRONMENT_DO_NOT_PERSIST"


class PerPortVersionHandler(FixtureHandler):
    """Keep real HTTP behavior while varying the banner between listeners."""

    def send_header(self, keyword, value):
        if keyword.lower() == "x-powered-by":
            value = f"PHP/{self.server.php_version}"
        super().send_header(keyword, value)


class ExactRedirectHandler(FixtureHandler):
    """Configurable ordinary responses for exact redirect destinations."""

    def do_GET(self):
        route = getattr(self.server, "routes", {}).get(self.path)
        if route is None:
            return super().do_GET()
        with self.server.record_lock:
            self.server.requests.append({"method": "GET", "path": self.path,
                "host": self.headers.get("Host"), "sni": getattr(self.connection, "_test_sni", None)})
        status, headers, body = route
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class HostRequiredHandler(socketserver.BaseRequestHandler):
    """Version probes get no HTTP signature; the intended vhost gets PHP."""

    def handle(self):
        self.request.settimeout(0.25)
        request = bytearray()
        try:
            while len(request) < 8192 and b"\r\n\r\n" not in request:
                chunk = self.request.recv(8192 - len(request))
                if not chunk:
                    break
                request.extend(chunk)
        except (socket.timeout, OSError):
            pass
        lines = bytes(request).split(b"\r\n")
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        expected_host = f"localhost:{self.server.server_address[1]}".encode("ascii")
        is_expected = (lines[0].startswith(b"GET ") and
                       headers.get(b"host") == expected_host)
        with self.server.record_lock:
            self.server.requests.append({"expected_host": is_expected,
                                         "request_line": lines[0].decode("ascii", errors="replace")})
        if is_expected:
            response = (b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.3.35\r\n"
                        b"Content-Length: 7\r\nConnection: close\r\n\r\nFixture")
        else:
            # Close immediately after this unrecognized response so -sV does
            # not spend one timeout per probe on this synthetic listener.
            response = b"SYNTHETIC_HOST_REQUIRED\r\n"
        try:
            self.request.sendall(response)
        except OSError:
            pass


class HostRequiredServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port):
        super().__init__(("127.0.0.1", port), HostRequiredHandler)
        self.requests = []
        self.record_lock = threading.Lock()


class FingerprintSecretHandler(socketserver.BaseRequestHandler):
    """Unknown HTTP response that Nmap embeds in its service fingerprint."""

    def handle(self):
        self.request.settimeout(0.1)
        try:
            request = self.request.recv(8192)
        except OSError:
            request = b""
        # Respond even to the NULL discovery probe, without a recognizable
        # Server banner. This reliably exercises Nmap's raw servicefp path.
        with self.server.record_lock:
            self.server.requests.append(request)
        body = phpinfo_html().replace(SECRET_BODY.encode(), FINGERPRINT_SECRET.encode())
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                    + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        try:
            self.request.sendall(response)
        except OSError:
            pass


class FingerprintSecretServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port):
        super().__init__(("127.0.0.1", port), FingerprintSecretHandler)
        self.requests = []
        self.record_lock = threading.Lock()


class ScanCLIIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nmap = os.environ.get("NMAP") or shutil.which("nmap")
        if not cls.nmap or not Path(cls.nmap).is_file():
            raise RuntimeError("Install Nmap or set NMAP=/path/to/nmap")
        if not (ROOT / "scan.py").is_file():
            raise RuntimeError("Missing campaign CLI: scan.py")
        cls.temp = tempfile.TemporaryDirectory(prefix="php2shell-campaign-integration-")
        cls.base = Path(cls.temp.name)
        cls.counter = 0
        cls.tls_context = None
        openssl = shutil.which("openssl")
        if openssl:
            cert, key = cls.base / "fixture.crt", cls.base / "fixture.key"
            subprocess.run(
                [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                check=True, capture_output=True, timeout=20,
            )
            cls.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cls.tls_context.load_cert_chain(cert, key)

            def capture_sni(tls_socket, server_name, _context):
                tls_socket._test_sni = server_name

            cls.tls_context.set_servername_callback(capture_sni)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextmanager
    def serve(self, *, tls=False, version=None, handler=None):
        server = LocalServer()
        if handler is not None:
            server.RequestHandlerClass = handler
        if version is not None:
            server.php_version = version
            server.RequestHandlerClass = PerPortVersionHandler
        if tls:
            server.socket = self.tls_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def run_campaign(self, port, *extra_args):
        type(self).counter += 1
        run = self.base / f"input-{self.counter}"
        run.mkdir()
        targets = run / "targets.txt"
        targets.write_text("# Local synthetic fixture only\nlocalhost\n", encoding="utf-8")
        paths = run / "paths.txt"
        paths.write_text("/old\n", encoding="utf-8")
        output = self.base / f"campaign-{self.counter}"
        command = [
            sys.executable, str(ROOT / "scan.py"), str(targets),
            "--ports", str(port),
            "--families", "ipv4", "--workers", "1", "--target-timeout", "60",
            "--allow-non-global",
            "--paths-file", str(paths), "--output", str(output),
            "--nmap", self.nmap, *extra_args,
        ]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(completed.returncode, 0, completed.stdout + "\n" + completed.stderr)
        self.assertTrue((output / "manifest.json").is_file(), completed.stdout)
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["profile"], "quick")
        return output, manifest, completed

    def assert_compact_report(self, output, hostname, version, verdict):
        text = (output / "report.json").read_text(encoding="utf-8")
        compact = json.loads(text)
        self.assertIsInstance(compact, list)
        self.assertEqual(len(compact), 1)
        self.assertEqual(len(text.splitlines()), 3)
        row = compact[0]
        fields = ("cible", "php", "vulnerable", "explication")
        self.assertEqual(set(row), set(fields))
        self.assertTrue(all(isinstance(value, str) for value in row.values()))
        self.assertEqual((row["cible"], row["php"], row["vulnerable"]), (hostname, version, verdict))
        self.assertTrue(row["explication"])
        self.assertTrue(all("\n" not in value and "\r" not in value for value in row.values()))
        with (output / "report.csv").open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(tuple(reader.fieldnames), fields)
            self.assertEqual(list(reader), compact)
        return row

    def phase_documents(self, output, manifest, hostname=None):
        documents = []
        for service in manifest["http_collection"]["services"].values():
            if hostname is not None and service["hostname"] != hostname:
                continue
            for job in service["phase_jobs"]:
                self.assertEqual(job["status"], "COMPLETED", job)
                self.assertTrue(job["xml"].startswith("raw/http/"), job)
                xml = ET.parse(output / job["xml"]).getroot()
                script = xml.find(".//script[@id='http-php2shell']")
                self.assertIsNotNone(script, job)
                self.assertEqual(script.find("elem[@key='vhost']").text, service["hostname"])
                self.assertEqual(script.find("elem[@key='ip']").text, service["ip"])
                self.assertEqual(script.find("elem[@key='port']").text, str(service["port"]))
                self.assertEqual(script.find("elem[@key='scheme']").text, service["scheme"])
                self.assertEqual(script.find("elem[@key='collection_phase']").text, job["phase"])
                documents.append((service, job, script))
        return documents

    def assert_report_matches_manifest(self, output, manifest, port, *, verdict="OUI"):
        self.assertEqual(manifest["status"], "COMPLETED")
        self.assertEqual(len(manifest["targets"]), 1)
        target = manifest["targets"][0]
        self.assertEqual(target["hostname"], "localhost")
        self.assertEqual(target["dns_status"], "RESOLVED")
        self.assertEqual(target["addresses"], ["127.0.0.1"])
        self.assertEqual(len(target["endpoints"]), 1)
        endpoint = target["endpoints"][0]
        self.assertEqual(endpoint["ip"], "127.0.0.1")
        self.assertEqual(endpoint["status"], "COMPLETED")
        self.assertTrue((output / endpoint["xml"]).is_file())
        discovery = ET.parse(output / endpoint["xml"]).getroot()
        self.assertIsNone(discovery.find(".//script[@id='http-php2shell']"))
        phases = self.phase_documents(output, manifest, "localhost")
        self.assertEqual(len(phases), 1)
        self.assertEqual(phases[0][1]["phase"], "base")
        self.assertEqual(phases[0][0]["port"], port)
        report = json.loads((output / "raw" / "report-details.json").read_text())
        rows = [row for row in report["rows"] if row["row_type"] == "ASSESSMENT"]
        self.assertEqual(len(rows), 1, report)
        row = rows[0]
        self.assertEqual(row["hostname"], "localhost")
        self.assertEqual(row["ip"], "127.0.0.1")
        self.assertEqual(str(row["port"]), str(port))
        self.assertEqual(row["state"], "POTENTIALLY_VULNERABLE")
        self.assertIn("8.3.35", row["versions"])
        self.assertTrue(row["reason_code"])
        self.assert_compact_report(output, "localhost", "8.3.35", verdict)
        self.assertTrue((output / "changes.csv").is_file())
        return report, row

    def test_http_campaign_then_disappearance_never_means_patched(self):
        with self.serve() as server:
            port = server.server_port
            output, manifest, _ = self.run_campaign(port)
            self.assert_report_matches_manifest(output, manifest, port)
            with server.record_lock:
                requests = [item for item in server.requests if item["path"] == "/old"]
            self.assertTrue(requests)
            self.assertTrue(all(item["host"] == f"localhost:{port}" for item in requests))
        # The listener is now closed. The same name/IP/port is scanned again.
        second, second_manifest, _ = self.run_campaign(port, "--previous", str(output / "report.json"))
        self.assertEqual(second_manifest["status"], "COMPLETED")
        report = json.loads((second / "raw" / "report-details.json").read_text())
        self.assertTrue(report["rows"], "A closed service must remain represented in coverage")
        self.assertTrue(all(row["state"] != "PATCHED_VERSION_ADVERTISED" for row in report["rows"]))
        self.assertFalse(any(row.get("inventory_patch_status") == "PATCH_CONFIRMED" for row in report["rows"]))
        self.assertTrue(report["changes"], "The previous service must appear in the comparison")
        self.assertIn("NO_LONGER_OBSERVED", json.dumps(report["changes"]))
        self.assert_compact_report(second, "localhost", "INCONNUE", "INDETERMINE")

    def test_tls_confirmed_backport_is_non_despite_old_banner_and_preserves_sni(self):
        if self.tls_context is None:
            self.skipTest("openssl is required for the local TLS fixture")
        with self.serve(tls=True) as server:
            port = server.server_port
            inventory = self.base / "runtime-proof.json"
            inventory.write_text(json.dumps({
                "schema_version": "1",
                "records": [{
                    "hostname": "localhost", "port": port, "scheme": "https", "ip": "127.0.0.1",
                    "authenticated": True, "source": "synthetic authenticated inventory",
                    "evidence_reference": "fixture://package-and-active-worker-proof",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "covers_all_backends": True,
                    "instances": [{
                        "id": "synthetic-web-worker", "runtime": "php-fpm", "version": "8.3.35",
                        "package": "synthetic-php-with-vendor-backports", "active_runtime_verified": True,
                        "cves": {"CVE-2026-109618": "fixed", "CVE-2026-109619": "fixed"},
                    }],
                }],
            }), encoding="utf-8")
            output, manifest, _ = self.run_campaign(port, "--inventory", str(inventory))
            _, row = self.assert_report_matches_manifest(output, manifest, port, verdict="NON")
            self.assertEqual(row["inventory_patch_status"], "PATCH_CONFIRMED")
            # The inventory backport proof does not overwrite the observed old banner.
            self.assertEqual(row["state"], "POTENTIALLY_VULNERABLE")
            compact = json.loads((output / "report.json").read_text())
            self.assertIn("attest", compact[0]["explication"].lower())
            with server.record_lock:
                requests = [item for item in server.requests if item["path"] == "/old"]
            self.assertTrue(requests)
            for item in requests:
                self.assertEqual(item["host"], f"localhost:{port}")
                self.assertEqual(item["sni"], "localhost")

    def test_http_to_https_redirect_assesses_exact_query_and_preserves_private_inputs(self):
        if self.tls_context is None:
            self.skipTest("openssl is required for the local TLS fixture")
        secret = "SYNTHETIC_REDIRECT_QUERY_DO_NOT_PUBLISH"
        exact = f"/application.php?a=1&token={secret}"
        with self.serve(handler=ExactRedirectHandler) as http_server, \
                self.serve(tls=True, handler=ExactRedirectHandler) as https_server:
            http_server.routes = {
                "/entry": (302, {"Location": f"https://localhost:{https_server.server_port}{exact}"}, b"Redirect"),
                "/old": (200, {"X-Powered-By": "PHP/8.3.36"}, b"Fixed base service"),
            }
            https_server.routes = {
                "/entry": (200, {}, b"Static landing page"),
                "/old": (200, {}, b"Static base page"),
                exact: (200, {"X-Powered-By": "PHP/8.3.35"}, b"Published application version"),
            }
            ports = f"{http_server.server_port},{https_server.server_port}"
            output, manifest, _ = self.run_campaign(ports, "--path", "/entry")
            self.assertEqual(manifest["status"], "COMPLETED")
            phases = self.phase_documents(output, manifest)
            self.assertEqual(sum(job["phase"] == "base" for _, job, _ in phases), 2)
            redirected = [(service, job, script) for service, job, script in phases if job["phase"] == "redirect"]
            self.assertEqual(len(redirected), 1)
            service, job, script = redirected[0]
            self.assertEqual((service["hostname"], service["ip"], service["port"], service["scheme"]),
                             ("localhost", "127.0.0.1", https_server.server_port, "https"))
            self.assertEqual(job["paths"], ["/application.php?[redacted]"])
            self.assertEqual(script.find("elem[@key='state']").text, "POTENTIALLY_VULNERABLE")
            with https_server.record_lock:
                application_requests = [entry for entry in https_server.requests if entry["path"].startswith("/application.php")]
            self.assertEqual([entry["path"] for entry in application_requests], [exact])
            self.assertTrue(all(entry["host"] == f"localhost:{https_server.server_port}"
                                and entry["sni"] == "localhost" for entry in application_requests))
            compact = json.loads((output / "report.json").read_text())
            self.assertEqual(len(compact), 1)
            self.assertEqual(set(compact[0]), {"cible", "php", "vulnerable", "explication"})
            self.assertEqual(compact[0]["cible"], "localhost")
            self.assertEqual(compact[0]["vulnerable"], "OUI")
            self.assertEqual(set(compact[0]["php"].split(" | ")), {"8.3.35", "8.3.36"})
            public_files = [path for path in output.rglob("*")
                            if path.is_file() and "private" not in path.relative_to(output).parts]
            for path in public_files:
                self.assertNotIn(secret.encode(), path.read_bytes(), str(path.relative_to(output)))
            private_files = list((output / "state" / "private").iterdir())
            self.assertTrue(any(secret.encode() in path.read_bytes() for path in private_files))
            self.assertTrue(all(path.stat().st_mode & 0o077 == 0 for path in private_files))

    def test_dry_run_resolves_and_writes_plan_without_contacting_http(self):
        with self.serve() as server:
            output, manifest, _ = self.run_campaign(server.server_port, "--dry-run")
            self.assertEqual(manifest["status"], "PLANNED")
            self.assertEqual(manifest["targets"][0]["hostname"], "localhost")
            self.assertEqual(manifest["targets"][0]["addresses"], ["127.0.0.1"])
            self.assertFalse((output / "report.json").exists())
            with server.record_lock:
                self.assertEqual(server.requests, [])

    def test_discovery_fingerprints_never_persist_diagnostic_body_or_secrets(self):
        try:
            server = FingerprintSecretServer(9000)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                self.skipTest(f"Loopback port 9000 already in use: {exc}")
            raise
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            output, manifest, completed = self.run_campaign(9000)
            self.assert_report_matches_manifest(output, manifest, 9000)
            endpoint = manifest["targets"][0]["endpoints"][0]
            discovery = ET.parse(output / endpoint["xml"]).getroot()
            service = discovery.find("host/ports/port/service")
            self.assertIsNotNone(service)
            self.assertEqual(service.get("method"), "table", "Fixture must exercise unidentified HTTP")
            self.assertIsNone(service.get("servicefp"))
            phases = self.phase_documents(output, manifest)
            evidence = phases[0][2].findall("table[@key='evidence']/table")
            self.assertTrue(any(item.find("elem[@key='source']").text == "phpinfo-structured"
                                for item in evidence))
            for path in output.rglob("*"):
                if path.is_file():
                    content = path.read_bytes()
                    self.assertNotIn(FINGERPRINT_SECRET.encode(), content, str(path.relative_to(output)))
                    self.assertNotIn(SECRET_BODY.encode(), content, str(path.relative_to(output)))
                    self.assertNotIn(b"ENV_SECRET", content, str(path.relative_to(output)))
            self.assertNotIn(FINGERPRINT_SECRET, completed.stdout + completed.stderr)
            with server.record_lock:
                requests = list(server.requests)
            self.assertTrue(any(b"GET /old " in request and b"Host: localhost:9000" in request
                                for request in requests), "PHP evidence must come from a Host-aware NSE GET")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_all_http_and_https_ports_are_assessed_after_first_affected_service(self):
        if self.tls_context is None:
            self.skipTest("openssl is required for the local TLS fixture")
        with ExitStack() as stack:
            servers = [stack.enter_context(self.serve(tls=tls, version="8.3.36"))
                       for tls in (False, True, False)]
            expected = {}
            # An affected service comes first in Nmap's port order, but the
            # remaining HTTP and HTTPS services must still be evaluated.
            for server, version in zip(sorted(servers, key=lambda item: item.server_port),
                                       ("8.3.35", "8.3.36", "8.4.27")):
                server.php_version = version
                expected[server.server_port] = version
            ports = ",".join(str(port) for port in expected)
            output, manifest, _ = self.run_campaign(ports)
            self.assertEqual(manifest["status"], "COMPLETED")
            self.assertEqual(len(manifest["targets"]), 1)
            endpoints = manifest["targets"][0]["endpoints"]
            self.assertEqual(len(endpoints), 1)
            xml = ET.parse(output / endpoints[0]["xml"]).getroot()
            discovered_ports = set()
            for port in xml.findall("host/ports/port"):
                script = port.find("script[@id='http-php2shell']")
                self.assertIsNone(script, ET.tostring(port, encoding="unicode"))
                self.assertEqual(port.find("state").get("state"), "open")
                discovered_ports.add(int(port.get("portid")))
            self.assertEqual(discovered_ports, set(expected))
            phases = self.phase_documents(output, manifest)
            self.assertEqual(len(phases), len(expected))
            self.assertTrue(all(job["phase"] == "base" for _, job, _ in phases))
            assessed_ports = {service["port"]: script.find("elem[@key='state']").text
                              for service, _, script in phases}
            self.assertEqual(set(assessed_ports), set(expected))
            self.assertEqual(assessed_ports[min(expected)], "POTENTIALLY_VULNERABLE")
            self.assertEqual(set(assessed_ports.values()),
                             {"POTENTIALLY_VULNERABLE", "PATCHED_VERSION_ADVERTISED"})
            details = json.loads((output / "raw" / "report-details.json").read_text())
            rows = [row for row in details["rows"] if row["row_type"] == "ASSESSMENT"]
            self.assertEqual(len(rows), 3)
            self.assertEqual({int(row["port"]): row["versions"] for row in rows}, expected)
            self.assertTrue(all(row["hostname"] == "localhost" and row["ip"] == "127.0.0.1"
                                for row in rows))
            compact = self.assert_compact_report(output, "localhost",
                                                 " | ".join(expected.values()), "OUI")
            self.assertIn("Ports évalués :", compact["explication"])
            for port in expected:
                self.assertIn(str(port), compact["explication"])
            for server in servers:
                with server.record_lock:
                    requests = [item for item in server.requests if item["path"] == "/old"]
                self.assertTrue(requests, server.server_port)
                self.assertTrue(all(item["host"] == f"localhost:{server.server_port}"
                                    for item in requests))
                if server is servers[1]:
                    self.assertTrue(all(item["sni"] == "localhost" for item in requests))

    def test_quick_web_port_is_assessed_when_version_probes_cannot_identify_http(self):
        # A real nonprivileged quick-profile port that shortport.http does not
        # select by number. A local port collision may skip only this fixture.
        try:
            server = HostRequiredServer(9000)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                self.skipTest(f"Loopback port 9000 already in use: {exc}")
            raise
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            output, manifest, _ = self.run_campaign(9000)
            endpoint = manifest["targets"][0]["endpoints"][0]
            xml = ET.parse(output / endpoint["xml"]).getroot()
            port = xml.find("host/ports/port[@portid='9000']")
            self.assertIsNotNone(port)
            self.assertEqual(port.find("state").get("state"), "open")
            # The fixture must actually exercise service-detection failure,
            # rather than accidentally rely on -sV recognizing HTTP.
            self.assertEqual(port.find("service").get("method"), "table")
            self.assertIsNone(port.find("script[@id='http-php2shell']"))
            phases = self.phase_documents(output, manifest)
            self.assertEqual(len(phases), 1)
            self.assertEqual(phases[0][0]["port"], 9000)
            self.assertEqual(phases[0][2].find("elem[@key='state']").text, "POTENTIALLY_VULNERABLE")
            self.assert_report_matches_manifest(output, manifest, 9000)
            with server.record_lock:
                requests = list(server.requests)
            self.assertTrue(any(not item["expected_host"] for item in requests))
            self.assertTrue(any(item["expected_host"] and item["request_line"].startswith("GET /old ")
                                for item in requests))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_single_file_discover_scans_root_and_child_with_real_nmap_and_host(self):
        # Discovery and DNS are deterministic; only the loopback Nmap/NSE
        # transport is real. No public CT service or DNS server is contacted.
        type(self).counter += 1
        inputs = self.base / f"discovery-input-{self.counter}"
        inputs.mkdir()
        domains = inputs / "domains.txt"
        domains.write_text("example.test\n", encoding="utf-8")
        output = self.base / f"discovery-campaign-{self.counter}"
        now = datetime.now(timezone.utc).isoformat()
        source_result = {
            "root": "example.test", "source": "crt.sh", "status": "COMPLETED",
            "reason_code": "OK", "processing_complete": True, "exhaustive": False,
            "started_at": now, "finished_at": now,
            "candidates": ["example.test", "app.example.test"], "candidate_count": 2,
            "excluded_candidates": [], "warnings": ["PASSIVE_SOURCE_NOT_EXHAUSTIVE"],
        }
        fixture_dns = {name: "127.0.0.1" for name in source_result["candidates"]}

        def resolve_fixture(name, families, timeout, allow_non_global=False):
            self.assertTrue(allow_non_global)
            address = fixture_dns[name]
            return {"dns_status": "RESOLVED", "addresses": [address],
                    "dns_families": {"ipv4": {"status": "RESOLVED", "addresses": [address]}},
                    "dns_partial": False, "dns_error": "", "resolved_at": now}

        messages = io.StringIO()
        with self.serve() as server:
            port = server.server_port
            arguments = [
                str(domains), "--discover", "--ports", str(port), "--families", "ipv4",
                "--workers", "1", "--target-timeout", "60", "--path", "/old",
                "--allow-non-global", "--output", str(output), "--nmap", self.nmap,
            ]
            with patch.object(scan, "discover_root", return_value=source_result) as discover, \
                    patch.object(scan, "resolve_target", side_effect=resolve_fixture) as resolve, \
                    redirect_stdout(messages), redirect_stderr(messages):
                status = scan.main(arguments)
            self.assertEqual(status, 0, messages.getvalue())
            discover.assert_called_once()
            self.assertEqual(discover.call_args.args, ("example.test",))
            self.assertEqual(resolve.call_count, 2)
            self.assertEqual({call.args[0] for call in resolve.call_args_list},
                             {"example.test", "app.example.test"})
            self.assertTrue(all(call.args[1:] == (["ipv4"], 15, True)
                                for call in resolve.call_args_list))
            with server.record_lock:
                requests = [item for item in server.requests if item["path"] == "/old"]
            self.assertTrue(requests, (output / "raw" / "000001.xml").read_text())
            self.assertEqual({item["host"] for item in requests},
                             {f"example.test:{port}", f"app.example.test:{port}"})

        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "COMPLETED")
        self.assertEqual(manifest["profile"], "quick")
        self.assertEqual(manifest["scope"]["domains"], ["example.test"])
        self.assertEqual(manifest["scope"]["excluded_hosts"], [])
        expected = {"example.test", "app.example.test"}
        by_name = {item["hostname"]: item for item in manifest["targets"]}
        self.assertEqual(set(by_name), expected)
        self.assertEqual(by_name["app.example.test"]["sources"], ["crt.sh:example.test"])
        self.assertIn("input:domains.txt:1", by_name["example.test"]["sources"])
        self.assertEqual(manifest["excluded_candidates"], [])
        self.assertEqual([item["file"] for item in manifest["inputs"]], ["domains.txt"])
        self.assertEqual({path.name for path in inputs.iterdir()}, {"domains.txt"})
        self.assertEqual(domains.read_text(), "example.test\n")
        for name in ("targets.txt", "discovered.txt"):
            self.assertEqual(set((output / name).read_text().splitlines()), expected)
        discovery = json.loads((output / "discovery.json").read_text())
        self.assertEqual(discovery, manifest["discovery"])
        self.assertEqual(discovery["queries"][0]["source"], "crt.sh")
        self.assertEqual(discovery["queries"][0]["root"], "example.test")
        self.assertFalse(discovery["exhaustive"])
        candidates = {item["hostname"]: item for item in discovery["candidates"]}
        self.assertTrue(candidates["example.test"]["retained"])
        self.assertTrue(candidates["app.example.test"]["retained"])
        self.assertEqual(candidates["app.example.test"]["sources"], ["crt.sh:example.test"])
        self.assertEqual(candidates["app.example.test"]["addresses"], ["127.0.0.1"])

        for target in by_name.values():
            self.assertEqual(target["addresses"], ["127.0.0.1"])
            self.assertEqual(len(target["endpoints"]), 1)
            endpoint = target["endpoints"][0]
            self.assertEqual(endpoint["status"], "COMPLETED")
            self.assertEqual(endpoint["command"][-1], "127.0.0.1")
            self.assertIn("-n", endpoint["command"])
            xml = ET.parse(output / endpoint["xml"]).getroot()
            self.assertEqual(xml.find("host/address").get("addr"), "127.0.0.1")
            script = xml.find(".//script[@id='http-php2shell']")
            self.assertIsNone(script)
            phases = self.phase_documents(output, manifest, target["hostname"])
            self.assertEqual(len(phases), 1)
            self.assertEqual(phases[0][1]["phase"], "base")
            self.assertEqual(phases[0][2].find("elem[@key='state']").text, "POTENTIALLY_VULNERABLE")
        report = json.loads((output / "raw" / "report-details.json").read_text())
        self.assertEqual(report["discovery"], discovery)
        self.assertTrue(report["summary"]["discovery_processing_complete"])
        self.assertFalse(report["summary"]["discovery_exhaustive"])
        rows = [row for row in report["rows"] if row["row_type"] == "ASSESSMENT"]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual((row["ip"], str(row["port"])), ("127.0.0.1", str(port)))
            self.assertEqual(row["target_sources"], by_name[row["hostname"]]["sources"])
            self.assertEqual(row["state"], "POTENTIALLY_VULNERABLE")
            self.assertIn("8.3.35", row["versions"])
        text = (output / "report.json").read_text()
        compact = json.loads(text)
        self.assertEqual(len(text.splitlines()), 4)
        self.assertEqual({row["cible"]: (row["php"], row["vulnerable"]) for row in compact},
                         {name: ("8.3.35", "OUI") for name in expected})
        with (output / "report.csv").open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(tuple(reader.fieldnames), ("cible", "php", "vulnerable", "explication"))
            self.assertEqual(list(reader), compact)


if __name__ == "__main__":
    unittest.main(verbosity=2)
