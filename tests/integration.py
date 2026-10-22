#!/usr/bin/env python3
"""Exercise the real NSE engine against synthetic loopback HTTP/HTTPS fixtures.

Run: python3 tests/integration.py
Optional environment: NMAP=/path/to/nmap NMAP_DATADIR=/path/to/nmap-data
No vulnerable PHP installation or public scanning target is used.
"""
from __future__ import annotations

import http.server
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "http-php2shell.nse"
VHOST = "application.example.test"
FALLBACK_VHOST = "fallback.example.test"
SECRET_COOKIE = "SYNTHETIC_COOKIE_MUST_NOT_APPEAR"
SECRET_BODY = "SYNTHETIC_BODY_MUST_NOT_APPEAR"


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Keep the real BaseHTTP/Python signature so -sV can identify this fixture.

    def log_message(self, *_args):
        pass

    def do_GET(self):
        entry = {"method": "GET", "path": self.path, "host": self.headers.get("Host"),
                 "sni": getattr(self.connection, "_test_sni", None)}
        with self.server.record_lock:
            self.server.requests.append(entry)
        status, headers, body = 200, {}, b"Synthetic fixture."
        supplied_host = self.headers.get("Host", "").split(":", 1)[0]
        if self.path == "/":
            body = b"Static landing page."
        elif self.path == "/index.php" and supplied_host == FALLBACK_VHOST:
            headers["X-Powered-By"] = "PHP/8.3.35"
        elif self.path == "/old":
            headers["X-Powered-By"] = "PHP/8.3.35"
        elif self.path == "/fixed":
            headers["X-Powered-By"] = "PHP/8.3.36"
        elif self.path == "/silent":
            body = b"Documentation example: PHP/8.3.36"
        elif self.path == "/redirect":
            status = 302
            headers["Location"] = f"http://127.0.0.1:{self.server.server_port}/fixed"
        elif self.path == "/redirect-relative":
            status = 302
            headers["Location"] = "/old"
        elif self.path == "/redirect-foreign":
            status = 302
            headers["Location"] = "http://outside.example.invalid/fixed"
        elif self.path == "/redirect-port":
            status = 302
            headers["Location"] = f"http://127.0.0.1:{self.server.foreign_port}/old"
        elif self.path.startswith("/redirect-chain/"):
            status = 302
            step = int(self.path.rsplit("/", 1)[-1])
            headers["Location"] = f"/redirect-chain/{step + 1}"
        elif self.path == "/conflict":
            headers["X-Powered-By"] = "PHP/8.4.26"
            headers["Server"] = "Apache PHP/8.4.27"
        elif self.path == "/cookies":
            headers["X-Powered-By"] = "PHP/8.3.35"
            headers["Set-Cookie"] = f"session={SECRET_COOKIE}; HttpOnly"
            body = SECRET_BODY.encode()
        elif self.path == "/vhost":
            if supplied_host == VHOST:
                headers["X-Powered-By"] = "PHP/8.5.12"
            else:
                status = 404
        elif self.path == "/large":
            headers["X-Powered-By"] = "PHP/8.2.35"
            body = b"X" * 100_000
        elif self.path == "/blocked":
            status = 403
        elif self.path == "/authenticate":
            status = 401
            headers["WWW-Authenticate"] = 'Basic realm="synthetic"'
        elif self.path == "/rate-limited":
            status = 429
            headers["Retry-After"] = "60"
        elif self.path == "/hidden-version":
            headers["X-Powered-By"] = "PHP"
        elif self.path == "/varying":
            with self.server.record_lock:
                self.server.variant_count += 1
                count = self.server.variant_count
            headers["X-Powered-By"] = "PHP/8.3.35" if count % 2 else "PHP/8.3.36"
        elif self.path == "/slow":
            time.sleep(0.75)
        elif self.path == "/partial":
            headers["X-Powered-By"] = "PHP/8.3"
        else:
            status = 404
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class LocalServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.requests = []
        self.sni_names = []
        self.record_lock = threading.Lock()
        self.variant_count = 0
        self.foreign_port = 1

    def shutdown_request(self, request):
        if isinstance(request, ssl.SSLSocket):
            # Send close_notify. An abrupt TLS close makes some OpenSSL/Nsock
            # versions reject a fully sent response as a truncated TLS stream.
            try:
                request.settimeout(1)
                plain_socket = request.unwrap()
                plain_socket.close()
                return
            except (OSError, ssl.SSLError):
                pass
        super().shutdown_request(request)

    def handle_error(self, _request, _client_address):
        # Connection resets are expected during TCP/TLS transport detection.
        pass


class NSEIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nmap = os.environ.get("NMAP") or shutil.which("nmap")
        if not cls.nmap or not Path(cls.nmap).is_file():
            raise RuntimeError("Nmap is required; install it or set NMAP=/path/to/nmap")
        if not SCRIPT.is_file():
            raise RuntimeError(f"Missing script: {SCRIPT}")
        cls.temp = tempfile.TemporaryDirectory(prefix="php2shell-nse-tests-")
        cls.httpd = LocalServer()
        cls.http_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.http_thread.start()
        cls.httpsd = None
        cls.https_thread = None
        openssl = shutil.which("openssl")
        if openssl:
            temp_path = Path(cls.temp.name)
            cert, key = temp_path / "fixture.crt", temp_path / "fixture.key"
            subprocess.run(
                [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", f"/CN={VHOST}", "-keyout", str(key), "-out", str(cert)],
                check=True, capture_output=True, timeout=20,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            cls.httpsd = LocalServer()
            def capture_sni(tls_socket, server_name, _context):
                # Bind SNI to this connection, so a later HTTP assertion cannot
                # accidentally use a name observed only during a version probe.
                tls_socket._test_sni = server_name
                with cls.httpsd.record_lock:
                    cls.httpsd.sni_names.append(server_name)
            context.set_servername_callback(capture_sni)
            cls.httpsd.socket = context.wrap_socket(cls.httpsd.socket, server_side=True)
            cls.https_thread = threading.Thread(target=cls.httpsd.serve_forever, daemon=True)
            cls.https_thread.start()

    @classmethod
    def tearDownClass(cls):
        for server, thread in [(cls.httpd, cls.http_thread), (cls.httpsd, cls.https_thread)]:
            if server is not None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
        cls.temp.cleanup()

    def scan(self, path, *, server=None, vhost=None, discover=False, targets_file=None,
             extra_args=""):
        server = server or self.httpd
        args = f"http-php2shell.path={path},http-php2shell.timeout=2000"
        if vhost:
            args += f",http-php2shell.vhost={vhost}"
        if extra_args:
            args += "," + extra_args
        script_selector = str(SCRIPT) if discover else "+" + str(SCRIPT)
        command = [self.nmap, "-sT", "-Pn", "-n", "-p", str(server.server_port),
                   "--script", script_selector, "--script-args", args,
                   "--script-timeout", "15s", "-oX", "-"]
        if targets_file is not None:
            command.extend(["--resolve-all", "-iL", str(targets_file)])
        else:
            command.append("127.0.0.1")
        if discover:
            command[1:1] = ["-sV"]
        if os.environ.get("NMAP_DATADIR"):
            command[1:1] = ["--datadir", os.environ["NMAP_DATADIR"]]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60 if discover else 25)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        try:
            root = ET.fromstring(completed.stdout)
        except ET.ParseError as exc:
            self.fail(f"Invalid Nmap XML: {exc}\n{completed.stdout}\n{completed.stderr}")
        script = root.find(".//script[@id='http-php2shell']")
        self.assertIsNotNone(script, completed.stdout + completed.stderr)
        state = script.find("elem[@key='state']")
        self.assertIsNotNone(state, ET.tostring(script, encoding="unicode"))
        exploitability = script.find("elem[@key='exploitability']")
        self.assertIsNotNone(exploitability)
        self.assertEqual(exploitability.text, "NOT_TESTED")
        verdict = script.find("elem[@key='verdict']")
        remediation = script.find("elem[@key='remediation']")
        verification = script.find("elem[@key='verification']")
        self.assertIsNotNone(verdict)
        self.assertIsNotNone(remediation)
        self.assertIsNotNone(verification)
        human = script.get("output", "")
        self.assertTrue(human.startswith("\n" + verdict.text), human)
        self.assertIn("PHP : ", human)
        self.assertIn("Correctif : " + remediation.text, human)
        self.assertIn("Verification : " + verification.text, human)
        self.assertNotIn("detection_method:", human)
        self.assertIsNotNone(script.find("elem[@key='reason_code']"))
        self.assertIsNotNone(script.find("elem[@key='requests_made']"))
        return state.text, script, completed.stdout

    @staticmethod
    def field(element, key):
        value = element.find(f"elem[@key='{key}']")
        return value.text if value is not None else None

    @staticmethod
    def observations(script):
        return script.findall("table[@key='observations']/table")

    def test_vulnerable_version_header(self):
        state, script, _ = self.scan("/old")
        self.assertEqual(state, "POTENTIALLY_VULNERABLE")
        versions = [elem.text for elem in script.findall("table[@key='versions']/elem")]
        self.assertIn("8.3.35", versions)

    def test_fixed_version_header(self):
        self.assertEqual(self.scan("/fixed")[0], "PATCHED_VERSION_ADVERTISED")

    def test_missing_header_is_unknown_even_when_body_mentions_php(self):
        self.assertEqual(self.scan("/silent")[0], "UNKNOWN")

    def test_same_origin_absolute_redirect_is_followed(self):
        with self.httpd.record_lock:
            before = len(self.httpd.requests)
        state, script, _ = self.scan("/redirect")
        self.assertEqual(state, "PATCHED_VERSION_ADVERTISED")
        with self.httpd.record_lock:
            paths = [entry["path"] for entry in self.httpd.requests[before:]]
        self.assertIn("/redirect", paths)
        self.assertIn("/fixed", paths)
        observed_paths = [self.field(item, "path") for item in self.observations(script)]
        self.assertEqual(observed_paths, ["/redirect", "/fixed"])

    def test_relative_redirect_preserves_vhost(self):
        with self.httpd.record_lock:
            before = len(self.httpd.requests)
        state, script, _ = self.scan("/redirect-relative", vhost=VHOST)
        self.assertEqual(state, "POTENTIALLY_VULNERABLE")
        with self.httpd.record_lock:
            requests = [entry for entry in self.httpd.requests[before:]
                        if entry["path"] in ("/redirect-relative", "/old")]
        self.assertEqual([entry["path"] for entry in requests], ["/redirect-relative", "/old"])
        for entry in requests:
            self.assertEqual(entry["host"], f"{VHOST}:{self.httpd.server_port}")
        self.assertEqual(self.field(script, "vhost"), VHOST)

    def test_foreign_hostname_redirect_is_not_followed(self):
        state, script, _ = self.scan("/redirect-foreign")
        self.assertEqual(state, "UNKNOWN")
        self.assertEqual(self.field(script, "reason_code"), "REDIRECT_NOT_ASSESSED")
        observations = self.observations(script)
        self.assertTrue(observations)
        self.assertEqual(self.field(observations[0], "redirect_scope"),
                         "HORS_PERIMETRE_DU_CONTROLE")
        self.assertEqual(self.field(observations[0], "redirect_to"),
                         "http://outside.example.invalid/fixed")
        self.assertTrue(all(self.field(item, "vhost") == "127.0.0.1" for item in observations))
        self.assertNotIn("/fixed", [self.field(item, "path") for item in observations])

    def test_redirect_to_different_port_does_not_contact_destination(self):
        outside = LocalServer()
        thread = threading.Thread(target=outside.serve_forever, daemon=True)
        thread.start()
        self.httpd.foreign_port = outside.server_port
        try:
            state, script, _ = self.scan("/redirect-port")
            self.assertEqual(state, "UNKNOWN")
            self.assertEqual(self.field(script, "reason_code"), "REDIRECT_NOT_ASSESSED")
            with outside.record_lock:
                self.assertEqual(outside.requests, [], "A cross-origin port was contacted")
        finally:
            outside.shutdown()
            outside.server_close()
            thread.join(timeout=5)

    def test_fallback_reaches_php_after_static_root(self):
        state, script, _ = self.scan("/", vhost=FALLBACK_VHOST)
        self.assertEqual(state, "POTENTIALLY_VULNERABLE")
        observations = self.observations(script)
        self.assertEqual([self.field(item, "path") for item in observations], ["/", "/index.php"])
        self.assertEqual(self.field(script, "requests_made"), "2")
        for item in observations:
            self.assertEqual(self.field(item, "ip"), "127.0.0.1")
            self.assertEqual(self.field(item, "port"), str(self.httpd.server_port))
            self.assertEqual(self.field(item, "vhost"), FALLBACK_VHOST)
            self.assertEqual(self.field(item, "http_host"), f"{FALLBACK_VHOST}:{self.httpd.server_port}")

    def test_request_budget_stops_redirect_chain(self):
        with self.httpd.record_lock:
            before = len(self.httpd.requests)
        state, script, _ = self.scan(
            "/redirect-chain/0",
            extra_args="http-php2shell.max_requests=2,http-php2shell.redirects=5",
        )
        self.assertEqual(state, "UNKNOWN")
        self.assertEqual(self.field(script, "reason_code"), "REQUEST_BUDGET_EXHAUSTED")
        self.assertEqual(self.field(script, "requests_made"), "2")
        with self.httpd.record_lock:
            requests = self.httpd.requests[before:]
        self.assertEqual([item["path"] for item in requests], ["/redirect-chain/0", "/redirect-chain/1"])

    def test_small_time_budget_does_not_start_fallback(self):
        with self.httpd.record_lock:
            before = len(self.httpd.requests)
        state, script, _ = self.scan("/slow", extra_args="http-php2shell.budget=100")
        self.assertEqual(state, "UNKNOWN")
        self.assertEqual(self.field(script, "requests_made"), "1")
        with self.httpd.record_lock:
            requests = self.httpd.requests[before:]
        self.assertEqual([item["path"] for item in requests], ["/slow"])

    def test_optional_samples_keep_heterogeneous_versions(self):
        with self.httpd.record_lock:
            self.httpd.variant_count = 0
        state, script, _ = self.scan("/varying", extra_args="http-php2shell.samples=2")
        self.assertEqual(state, "UNKNOWN")
        self.assertEqual(self.field(script, "reason_code"), "CONFLICTING_VERSIONS")
        versions = [elem.text for elem in script.findall("table[@key='versions']/elem")]
        self.assertEqual(set(versions), {"8.3.35", "8.3.36"})
        self.assertEqual(self.field(script, "priority"), "VERIFY_PRIORITY")
        self.assertEqual(self.field(script, "requests_made"), "2")

    def test_explicit_paths_retain_conflicting_versions(self):
        state, script, _ = self.scan("/old", extra_args='http-php2shell.paths={"/fixed"}')
        self.assertEqual(state, "UNKNOWN")
        self.assertEqual(self.field(script, "reason_code"), "CONFLICTING_VERSIONS")
        self.assertEqual(self.field(script, "priority"), "VERIFY_PRIORITY")
        observations = self.observations(script)
        self.assertEqual([self.field(item, "path") for item in observations], ["/old", "/fixed"])
        self.assertEqual(
            {self.field(item, "state") for item in observations},
            {"POTENTIALLY_VULNERABLE", "PATCHED_VERSION_ADVERTISED"},
        )

    def test_conflicting_version_headers(self):
        state, script, _ = self.scan("/conflict")
        self.assertEqual(state, "UNKNOWN")
        versions = [elem.text for elem in script.findall("table[@key='versions']/elem")]
        self.assertIn("8.4.26", versions)
        self.assertIn("8.4.27", versions)

    def test_no_cookie_or_body_secrets_in_output(self):
        state, _, output = self.scan("/cookies")
        self.assertEqual(state, "POTENTIALLY_VULNERABLE")
        self.assertNotIn(SECRET_COOKIE, output)
        self.assertNotIn(SECRET_BODY, output)

    def test_http_virtual_host(self):
        self.assertEqual(self.scan("/vhost", vhost=VHOST)[0], "PATCHED_VERSION_ADVERTISED")

    def test_https_virtual_host_and_sni(self):
        if self.httpsd is None:
            self.skipTest("openssl is required to create the local TLS fixture")
        with self.httpsd.record_lock:
            before = len(self.httpsd.requests)
        state, script, _ = self.scan("/vhost", server=self.httpsd, vhost=VHOST)
        self.assertEqual(state, "PATCHED_VERSION_ADVERTISED")
        with self.httpsd.record_lock:
            requests = [entry for entry in self.httpsd.requests[before:]
                        if entry["path"] == "/vhost"]
        self.assertTrue(requests, "The NSE GET was not received by the TLS fixture")
        for entry in requests:
            self.assertEqual(entry["host"], f"{VHOST}:{self.httpsd.server_port}")
            self.assertEqual(entry["sni"], VHOST, "SNI on the NSE GET connection")
        for observation in self.observations(script):
            self.assertEqual(self.field(observation, "tls_sni"), VHOST)
            self.assertEqual(self.field(observation, "http_host"), f"{VHOST}:{self.httpsd.server_port}")

    def test_service_detection_selects_http_on_an_arbitrary_port(self):
        state, _, output = self.scan("/old", discover=True)
        self.assertEqual(state, "POTENTIALLY_VULNERABLE")
        service = ET.fromstring(output).find(".//port/service")
        self.assertIsNotNone(service)
        self.assertEqual(service.get("name"), "http")
        self.assertEqual(service.get("method"), "probed")

    def test_service_detection_selects_https_on_an_arbitrary_port(self):
        if self.httpsd is None:
            self.skipTest("openssl is required to create the local TLS fixture")
        state, _, output = self.scan("/fixed", server=self.httpsd, discover=True)
        self.assertEqual(state, "PATCHED_VERSION_ADVERTISED")
        service = ET.fromstring(output).find(".//port/service")
        self.assertIsNotNone(service)
        self.assertEqual(service.get("name"), "http")
        self.assertEqual(service.get("tunnel"), "ssl")
        self.assertEqual(service.get("method"), "probed")

    def test_domain_file_preserves_host_and_sni_without_vhost_override(self):
        if self.httpsd is None:
            self.skipTest("openssl is required to create the local TLS fixture")
        targets_file = Path(self.temp.name) / "domains.txt"
        # localhost resolves locally; no public DNS name or /etc/hosts edit.
        targets_file.write_text("localhost\n", encoding="utf-8")
        with self.httpsd.record_lock:
            before = len(self.httpsd.requests)
        state, _, _ = self.scan("/fixed", server=self.httpsd, discover=True,
                                targets_file=targets_file)
        self.assertEqual(state, "PATCHED_VERSION_ADVERTISED")
        with self.httpsd.record_lock:
            requests = [entry for entry in self.httpsd.requests[before:]
                        if entry["path"] == "/fixed"]
        self.assertTrue(requests, "The NSE GET was not received by the TLS fixture")
        for entry in requests:
            self.assertEqual(entry["host"], f"localhost:{self.httpsd.server_port}")
            self.assertEqual(entry["sni"], "localhost", "SNI on the NSE GET connection")

    def test_large_response_keeps_header_evidence(self):
        self.assertEqual(self.scan("/large")[0], "PATCHED_VERSION_ADVERTISED")

    def test_access_denied_is_not_a_nonvulnerable_result(self):
        with self.httpd.record_lock:
            before = len(self.httpd.requests)
        state, script, _ = self.scan("/blocked", vhost=FALLBACK_VHOST)
        self.assertEqual(state, "UNKNOWN")
        self.assertEqual(self.field(script, "reason_code"), "HTTP_ACCESS_DENIED")
        with self.httpd.record_lock:
            paths = [item["path"] for item in self.httpd.requests[before:]]
        self.assertEqual(paths, ["/blocked"], "A denied request must not cause path traversal")

    def test_authentication_and_rate_limit_stop_traversal(self):
        for path, expected_reason in [
            ("/authenticate", "AUTHENTICATION_REQUIRED"),
            ("/rate-limited", "RATE_LIMITED"),
        ]:
            with self.subTest(path=path):
                with self.httpd.record_lock:
                    before = len(self.httpd.requests)
                state, script, _ = self.scan(path, vhost=FALLBACK_VHOST)
                self.assertEqual(state, "UNKNOWN")
                self.assertEqual(self.field(script, "reason_code"), expected_reason)
                with self.httpd.record_lock:
                    paths = [item["path"] for item in self.httpd.requests[before:]]
                self.assertEqual(paths, [path])

    def test_php_without_version_has_specific_reason(self):
        state, script, _ = self.scan("/hidden-version")
        self.assertEqual(state, "UNKNOWN")
        self.assertEqual(self.field(script, "reason_code"), "PHP_VERSION_HIDDEN")
        self.assertEqual(self.field(script, "php_detected"), "YES")

    def test_partial_version_is_unknown(self):
        self.assertEqual(self.scan("/partial")[0], "UNKNOWN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
