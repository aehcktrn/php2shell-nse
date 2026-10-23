#!/usr/bin/env python3
"""Reproduce collection gains with synthetic loopback HTTP/HTTPS services.

Run explicitly: python3 tests/benchmark_collection.py [--output NEW_DIRECTORY]
Only DNS names under example.test are admitted and all are pinned to 127.0.0.1.
The measurements describe this fixture, never an Internet detection rate.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import scan


CASES = ("base", "redirect", "links", "diagnostic", "documentation", "conflict")
NAMES = tuple(case + ".example.test" for case in CASES)
SECRET = "SYNTHETIC_PHPINFO_ENVIRONMENT_MUST_NOT_BE_PERSISTED"


def diagnostic(version):
    return (f'<html><head><title>PHP {version} - phpinfo()</title></head><body>'
            f'<h1 class="p">PHP Version {version}</h1><table>'
            '<tr><td class="e">System </td><td class="v">Local benchmark</td></tr>'
            '<tr><td class="e">Server API </td><td class="v">FPM/FastCGI</td></tr></table>'
            f'<table><tr><td class="e">ENV_SECRET</td><td class="v">{SECRET}</td></tr></table>'
            '</body></html>').encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BaseHTTP/0.6"

    def log_message(self, *_args):
        pass

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            # Nmap's service probes routinely close synthetic connections.
            pass

    def do_GET(self):
        host = self.headers.get("Host", "").split(":", 1)[0]
        case = host.split(".", 1)[0] if host in NAMES else "probe"
        entry = {"host": self.headers.get("Host", ""), "path": self.path,
                 "sni": getattr(self.connection, "_test_sni", None),
                 "collector": "php2shell-scanner" in self.headers.get("User-Agent", "")}
        with self.server.record_lock:
            self.server.requests.append(entry)
        status, headers, body = 200, {}, b"Synthetic local benchmark."
        if case == "base" and self.path in ("/", "/index.php"):
            headers["X-Powered-By"] = "PHP/8.3.36"
        elif case == "redirect":
            if not self.server.is_tls and self.path in ("/", "/index.php"):
                status = 302
                headers["Location"] = f"https://{host}:{self.server.tls_port}/portal/index.php?entry=1"
            elif self.server.is_tls and self.path == "/portal/index.php?entry=1":
                headers["X-Powered-By"] = "PHP/8.3.35"
        elif case == "links":
            if self.path in ("/", "/index.php"):
                body = (b'<a href="/logout.php">action</a><a href="/delete.php">action</a>'
                        b'<a href="https://outside.example.test/foreign.php">external</a>'
                        b'<a href="/portal.php?export=1">query</a><a href="/portal.php">Portal</a>')
            elif self.path == "/portal.php":
                headers["X-Powered-By"] = "PHP/8.3.36"
        elif case == "diagnostic" and self.path in ("/", "/index.php"):
            body = diagnostic("8.3.36")
        elif case == "documentation":
            body = b'<html><title>PHP documentation</title><p>Requires PHP 8.3.35; OpenSSL 8.3.35.</p></html>'
        elif case == "conflict" and self.path in ("/", "/index.php"):
            headers["X-Powered-By"] = "PHP/8.3.36"
            body = diagnostic("8.3.35")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def serve(stack, context=None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.requests = []
    server.record_lock = threading.Lock()
    server.is_tls = context is not None
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def cleanup():
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    stack.callback(cleanup)
    return server


def resolve_fixture(name, families, timeout, allow_non_global=False):
    if name not in NAMES:
        raise AssertionError("Benchmark refused a non-fixture DNS name: " + name)
    return {"dns_status": "RESOLVED", "addresses": ["127.0.0.1"], "excluded_addresses": [],
            "dns_families": {"ipv4": {"status": "RESOLVED", "addresses": ["127.0.0.1"]}}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--nmap", default=os.environ.get("NMAP", "nmap"))
    args = parser.parse_args(argv)
    if not shutil.which(args.nmap) or not shutil.which("openssl"):
        parser.error("Nmap and OpenSSL are required for the local benchmark.")
    base = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="php2shell-local-benchmark-"))
    if base.exists() and any(base.iterdir()):
        parser.error("--output must be new or empty.")
    base.mkdir(parents=True, exist_ok=True)
    inputs = base / "input"
    inputs.mkdir()
    targets = inputs / "targets.txt"
    targets.write_text("\n".join(NAMES) + "\n", encoding="utf-8")
    cert, key = inputs / "fixture.crt", inputs / "fixture.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=example.test", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True, timeout=20)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    def capture_sni(connection, name, _context):
        connection._test_sni = name
    context.set_servername_callback(capture_sni)
    with ExitStack() as stack:
        http = serve(stack)
        https = serve(stack, context)
        http.tls_port = https.server_port
        ports = f"{http.server_port},{https.server_port}"
        campaign = base / "campaign"
        arguments = scan.parser().parse_args([str(targets), "--ports", ports, "--families", "ipv4",
            "--allow-non-global", "--workers", "4", "--workers-per-ip", "2", "--target-timeout", "90",
            "--nmap", args.nmap, "--output", str(campaign)])
        with patch.object(scan, "resolve_target", side_effect=resolve_fixture):
            code = scan.run_campaign(arguments)
        if code != 0:
            raise RuntimeError(f"Local campaign returned {code}; artifacts: {campaign}")
        details = json.loads((campaign / "raw/report-details.json").read_text())
        compact = json.loads((campaign / "report.json").read_text())
        metrics = details["summary"]["collection_metrics"]
        rows = [row for row in details["rows"] if row.get("collection_service_key")]
        baseline_headers = sum(any(item.get("version") and item.get("source") in ("server", "x-powered-by")
                                   and item.get("collection_phase") == "base" for item in row.get("evidence", []))
                               for row in rows)
        expected = {"base.example.test": ("8.3.36", "NON"),
                    "redirect.example.test": ("8.3.35", "OUI"),
                    "links.example.test": ("8.3.36", "NON"),
                    "diagnostic.example.test": ("8.3.36", "NON"),
                    "documentation.example.test": ("INCONNUE", "INDETERMINE"),
                    "conflict.example.test": ("8.3.36 | 8.3.35", "OUI")}
        actual = {row["cible"]: (row["php"], row["vulnerable"]) for row in compact}
        if actual != expected:
            raise AssertionError({"expected": expected, "actual": actual, "campaign": str(campaign)})
        collector_requests = [request for server in (http, https) for request in server.requests if request["collector"]]
        if any(request["host"].split(":", 1)[0] not in NAMES for request in collector_requests):
            raise AssertionError("Collector used an unexpected Host.")
        if any(request["sni"] not in NAMES for request in https.requests if request["collector"]):
            raise AssertionError("Collector did not preserve SNI.")
        forbidden = ("/logout.php", "/delete.php", "/portal.php?export=1", "/foreign.php")
        if any(request["path"] in forbidden for request in collector_requests):
            raise AssertionError("Collector visited an inadmissible navigation link.")
    for path in campaign.rglob("*"):
        if path.is_file() and SECRET.encode() in path.read_bytes():
            raise AssertionError("Diagnostic environment leaked into artifacts: " + str(path))
    result = {"fixture": "Six synthetic DNS names, two loopback HTTP/HTTPS services per name",
              "header_only_base_services_with_version": baseline_headers,
              "enhanced_base_services_with_version": metrics["services_version_base"],
              "final_services_with_version": metrics["services_with_version"],
              "metrics": metrics, "campaign": str(campaign),
              "limitation": "Local reproducible fixture; not an Internet detection rate."}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
