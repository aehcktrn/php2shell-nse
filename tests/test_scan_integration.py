#!/usr/bin/env python3
"""Run the campaign CLI end to end against synthetic loopback services only.

Run explicitly with: python3 tests/test_scan_integration.py
NMAP and NMAP_DATADIR select the real Nmap executable and its data directory.
"""
from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from integration import LocalServer


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import scan


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
    def serve(self, *, tls=False):
        server = LocalServer()
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
            "--profile", "rapide", "--ports", str(port),
            "--families", "ipv4", "--workers", "1", "--target-timeout", "60",
            "--paths-file", str(paths), "--output", str(output),
            "--nmap", self.nmap, *extra_args,
        ]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(completed.returncode, 0, completed.stdout + "\n" + completed.stderr)
        self.assertTrue((output / "manifest.json").is_file(), completed.stdout)
        return output, json.loads((output / "manifest.json").read_text()), completed

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

    def test_dry_run_resolves_and_writes_plan_without_contacting_http(self):
        with self.serve() as server:
            output, manifest, _ = self.run_campaign(server.server_port, "--dry-run")
            self.assertEqual(manifest["status"], "PLANNED")
            self.assertEqual(manifest["targets"][0]["hostname"], "localhost")
            self.assertEqual(manifest["targets"][0]["addresses"], ["127.0.0.1"])
            self.assertFalse((output / "report.json").exists())
            with server.record_lock:
                self.assertEqual(server.requests, [])

    def test_discovery_scans_only_retained_subdomain_with_real_nmap_and_host(self):
        # Discovery and DNS are deterministic; only the loopback Nmap/NSE
        # transport is real. No public CT service or DNS server is contacted.
        type(self).counter += 1
        inputs = self.base / f"discovery-input-{self.counter}"
        inputs.mkdir()
        roots, excluded = inputs / "roots.txt", inputs / "exclude.txt"
        roots.write_text("example.test\n", encoding="utf-8")
        excluded.write_text("example.test\n", encoding="utf-8")
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

        def resolve_fixture(name, families, timeout):
            address = fixture_dns[name]
            return {"dns_status": "RESOLVED", "addresses": [address],
                    "dns_families": {"ipv4": {"status": "RESOLVED", "addresses": [address]}},
                    "dns_partial": False, "dns_error": "", "resolved_at": now}

        messages = io.StringIO()
        with self.serve() as server:
            port = server.server_port
            arguments = [
                "--discover-subdomains", str(roots), "--exclude", str(excluded),
                "--profile", "rapide", "--ports", str(port), "--families", "ipv4",
                "--workers", "1", "--target-timeout", "60", "--path", "/old",
                "--output", str(output), "--nmap", self.nmap,
            ]
            with patch.object(scan, "discover_root", return_value=source_result) as discover, \
                    patch.object(scan, "resolve_target", side_effect=resolve_fixture) as resolve, \
                    redirect_stdout(messages), redirect_stderr(messages):
                status = scan.main(arguments)
            self.assertEqual(status, 0, messages.getvalue())
            discover.assert_called_once()
            self.assertEqual(discover.call_args.args, ("example.test",))
            resolve.assert_called_once_with("app.example.test", ["ipv4"], 15)
            with server.record_lock:
                requests = [item for item in server.requests if item["path"] == "/old"]
            self.assertTrue(requests, (output / "raw" / "000001.xml").read_text())
            self.assertTrue(all(item["host"] == f"app.example.test:{port}" for item in requests))

        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "COMPLETED")
        self.assertEqual(manifest["scope"]["domains"], ["example.test"])
        self.assertEqual(manifest["scope"]["excluded_hosts"], ["example.test"])
        self.assertEqual([item["hostname"] for item in manifest["targets"]], ["app.example.test"])
        target = manifest["targets"][0]
        self.assertEqual(target["sources"], ["crt.sh:example.test"])
        self.assertEqual(target["addresses"], ["127.0.0.1"])
        self.assertTrue(any(item["hostname"] == "example.test" and item["reason"] == "EXCLUDED_BY_OPERATOR"
                            for item in manifest["excluded_candidates"]))
        for name in ("targets.txt", "discovered.txt"):
            self.assertEqual((output / name).read_text(), "app.example.test\n")
        discovery = json.loads((output / "discovery.json").read_text())
        self.assertEqual(discovery, manifest["discovery"])
        self.assertEqual(discovery["queries"][0]["source"], "crt.sh")
        self.assertEqual(discovery["queries"][0]["root"], "example.test")
        self.assertFalse(discovery["exhaustive"])
        candidates = {item["hostname"]: item for item in discovery["candidates"]}
        self.assertFalse(candidates["example.test"]["retained"])
        self.assertTrue(candidates["app.example.test"]["retained"])
        self.assertEqual(candidates["app.example.test"]["sources"], ["crt.sh:example.test"])
        self.assertEqual(candidates["app.example.test"]["addresses"], ["127.0.0.1"])

        self.assertEqual(len(target["endpoints"]), 1)
        endpoint = target["endpoints"][0]
        self.assertEqual(endpoint["status"], "COMPLETED")
        self.assertEqual(endpoint["command"][-1], "127.0.0.1")
        self.assertIn("-n", endpoint["command"])
        xml = ET.parse(output / endpoint["xml"]).getroot()
        self.assertEqual(xml.find("host/address").get("addr"), "127.0.0.1")
        script = xml.find(".//script[@id='http-php2shell']")
        self.assertIsNotNone(script)
        self.assertEqual(script.find("elem[@key='state']").text, "POTENTIALLY_VULNERABLE")
        report = json.loads((output / "raw" / "report-details.json").read_text())
        self.assertEqual(report["discovery"], discovery)
        self.assertTrue(report["summary"]["discovery_processing_complete"])
        self.assertFalse(report["summary"]["discovery_exhaustive"])
        rows = [row for row in report["rows"] if row["row_type"] == "ASSESSMENT"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["hostname"], row["ip"], str(row["port"])),
                         ("app.example.test", "127.0.0.1", str(port)))
        self.assertEqual(row["target_sources"], ["crt.sh:example.test"])
        self.assertEqual(row["state"], "POTENTIALLY_VULNERABLE")
        self.assertIn("8.3.35", row["versions"])
        self.assert_compact_report(output, "app.example.test", "8.3.35", "OUI")


if __name__ == "__main__":
    unittest.main(verbosity=2)
