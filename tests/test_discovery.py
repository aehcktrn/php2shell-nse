"""Offline contracts for passive discovery, source failures and hard deadlines."""
from __future__ import annotations

from email.message import Message
from http.client import IncompleteRead
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import discovery


class Response:
    def __init__(self, data, content_type="application/json", **headers):
        self.status = 200
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        for name, value in headers.items():
            self.headers[name.replace("_", "-")] = str(value)
        self.stream = io.BytesIO(data)
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.stream.close()

    def read(self, size):
        self.read_sizes.append(size)
        return self.stream.read(size)


class DiscoveryTests(unittest.TestCase):
    def parse(self, payload, max_names=10000):
        result = discovery._new_result("example.com", 30, max_names, 8388608)
        return discovery._parse_payload(payload, result, max_names)

    def fetch(self, response, **options):
        opener = Mock()
        if isinstance(response, Exception):
            opener.open.side_effect = response
        else:
            opener.open.return_value = response
        with patch.object(discovery, "build_opener", return_value=opener) as build:
            result = discovery._fetch_root("example.com", options.get("timeout", 30),
                                           options.get("max_names", 10000), options.get("max_bytes", 8388608))
        return result, opener, build

    def test_multiline_sans_are_normalized_deduplicated_and_bounded_to_root(self):
        result = self.parse([
            {"name_value": "API.Example.COM.\nwww.example.com\ncafé.example.com", "result_count": 1},
            {"name_value": "api.example.com\nexample.com\nwww.example.com", "result_count": 1},
        ])
        self.assertEqual(result["candidates"], ["api.example.com", "example.com", "www.example.com", "xn--caf-dma.example.com"])
        self.assertEqual(result["duplicate_count"], 2)
        self.assertEqual(result["candidate_count"], 4)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertTrue(result["processing_complete"])
        self.assertFalse(result["exhaustive"])

    def test_scope_uses_dns_label_boundaries(self):
        result = self.parse([{"name_value": "evilexample.com\nexample.com.evil.test\nother.example.net\napp.example.com"}])
        self.assertEqual(result["candidates"], ["app.example.com"])
        self.assertEqual(result["rejection_counts"], {"OUTSIDE_QUERY_ROOT": 3})

    def test_wildcard_certificate_is_not_transformed_into_a_host(self):
        result = self.parse([{"name_value": "*.example.com\n*.internal.example.com\n*.foreign.example.net"}])
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["wildcard_count"], 2)
        self.assertEqual(result["rejection_counts"]["CERTIFICATE_WILDCARD"], 2)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["reason_code"], "EMPTY_RESULT")

    def test_invalid_names_never_become_targets_or_terminal_controls(self):
        values = ["127.0.0.1", "::1", "https://app.example.com", "app.example.com:443",
                  "-flag.example.com", "bad..example.com", "a\x1b[31m.example.com", "a*.example.com",
                  "a/b.example.com", "a b.example.com", "a\\b.example.com",
                  "\tleading.example.com", "trailing.example.com\t", "\x0bleading.example.com"]
        result = self.parse([{"name_value": "\n".join(values)}])
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["rejected_count"], len(values))
        for item in result["excluded_candidates"]:
            self.assertTrue(all(c.isprintable() for c in item["hostname"]))

    def test_crlf_san_separators_and_ordinary_spaces_remain_supported(self):
        result = self.parse([{"name_value": " api.example.com \r\nwww.example.com\r\n"}])
        self.assertEqual(result["candidates"], ["api.example.com", "www.example.com"])
        self.assertEqual(result["rejected_count"], 0)

    def test_rejection_samples_are_bounded_with_exact_rejection_count(self):
        result = self.parse([{"name_value": "\n".join(f"host-{i}.outside.example" for i in range(120))}])
        self.assertEqual(result["rejected_count"], 120)
        self.assertEqual(len(result["excluded_candidates"]), 100)
        self.assertTrue(result["excluded_samples_truncated"])
        self.assertTrue(all(item["source"] == "crt.sh:example.com" for item in result["excluded_candidates"]))

    def test_local_name_limit_is_partial_and_retains_collected_names(self):
        result = self.parse([{"name_value": "a.example.com\nb.example.com\nc.example.com\na.example.com"}], max_names=2)
        self.assertEqual(result["candidates"], ["a.example.com", "b.example.com"])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["reason_code"], "NAME_LIMIT_REACHED")
        self.assertFalse(result["processing_complete"])

    def test_exact_name_limit_without_extra_name_is_not_local_truncation(self):
        result = self.parse([{"name_value": "a.example.com\nb.example.com"}], max_names=2)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(result["exhaustive"])

    def test_provider_grouped_result_count_detects_cap(self):
        result = self.parse([{"name_value": "a.example.com", "result_count": 9999},
                             {"name_value": "b.example.com", "result_count": 1}])
        self.assertEqual(result["provider_result_count"], 10000)
        self.assertEqual(result["reason_code"], "PROVIDER_LIMIT_REACHED")
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(len(result["candidates"]), 2)

    def test_missing_provider_counts_are_explicitly_unknown(self):
        result = self.parse([{"name_value": "a.example.com"}])
        self.assertFalse(result["provider_count_complete"])
        self.assertIn("PROVIDER_TRUNCATION_UNKNOWN", result["warnings"])
        self.assertFalse(result["exhaustive"])

    def test_record_limit_is_not_silently_complete(self):
        with patch.object(discovery, "MAX_RECORDS", 1):
            result = self.parse([{"name_value": "a.example.com"}, {"name_value": "b.example.com"}])
        self.assertEqual(result["records_received"], 2)
        self.assertEqual(result["records_processed"], 1)
        self.assertEqual(result["reason_code"], "RECORD_LIMIT_REACHED")
        self.assertEqual(result["candidates"], ["a.example.com"])

    def test_missing_or_malformed_records_are_partial_not_empty_success(self):
        for malformed in (None, [], "bad", {}, {"name_value": None}, {"name_value": ["a.example.com"]}, {"name_value": ""}):
            with self.subTest(malformed=malformed):
                result = self.parse([{"name_value": "a.example.com"}, malformed])
                self.assertEqual(result["status"], "PARTIAL")
                self.assertEqual(result["reason_code"], "INVALID_SOURCE_RECORDS")
                self.assertEqual(result["candidates"], ["a.example.com"])

    def test_top_level_error_object_is_failure(self):
        for payload in ({"error": "timeout"}, None, "", 0):
            with self.subTest(payload=payload):
                result = self.parse(payload)
                self.assertEqual(result["status"], "FAILED")
                self.assertEqual(result["reason_code"], "INVALID_RESPONSE")

    def test_empty_array_means_no_candidates_returned_not_exhaustive(self):
        result = self.parse([])
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["reason_code"], "EMPTY_RESULT")
        self.assertFalse(result["exhaustive"])
        self.assertEqual(result["candidates"], [])

    def test_https_request_uses_fixed_origin_verified_defaults_and_no_redirects(self):
        response = Response(b'[{"name_value":"app.example.com"}]')
        result, opener, build = self.fetch(response)
        request = opener.open.call_args.args[0]
        parsed = urlsplit(request.full_url)
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ("https", "crt.sh", "/"))
        self.assertEqual(parse_qs(parsed.query), {"q": ["%.example.com"], "output": ["json"], "match": ["ILIKE"]})
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(request.get_header("Accept-encoding"), "identity")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 30)
        self.assertIsInstance(build.call_args.args[0], discovery._NoRedirect)
        self.assertEqual(result["candidates"], ["app.example.com"])

    def test_redirect_handler_does_not_follow_foreign_location(self):
        handler = discovery._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "http://foreign.example/"))
        result, opener, _ = self.fetch(HTTPError("https://crt.sh/", 302, "Found", Message(), io.BytesIO()))
        self.assertEqual(result["reason_code"], "REDIRECT_REFUSED")
        self.assertEqual(opener.open.call_count, 1)

    def test_rate_limit_is_recorded_without_retry(self):
        headers = Message()
        headers["Retry-After"] = "120"
        error = HTTPError("https://crt.sh/", 429, "Rate limited", headers, io.BytesIO())
        result, opener, _ = self.fetch(error)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["reason_code"], "RATE_LIMITED")
        self.assertEqual(result["retry_after_seconds"], 120)
        self.assertEqual(opener.open.call_count, 1)

    def test_http_service_errors_are_not_empty_discovery(self):
        result, _, _ = self.fetch(HTTPError("https://crt.sh/", 503, "Unavailable", Message(), io.BytesIO(b"secret response")))
        self.assertEqual(result["reason_code"], "HTTP_ERROR")
        self.assertEqual(result["http_status"], 503)
        self.assertNotIn("secret response", json.dumps(result))

    def test_http_200_html_error_is_not_parsed_as_zero_names(self):
        result, _, _ = self.fetch(Response(b"<html>source timeout</html>", "text/html"))
        self.assertEqual(result["reason_code"], "INVALID_CONTENT_TYPE")
        self.assertEqual(result["status"], "FAILED")

    def test_invalid_json_and_non_utf8_are_source_failures(self):
        for data in (b"not json", b"[", b"\xff\xfe", b'{"error":"timeout"}'):
            with self.subTest(data=data):
                result, _, _ = self.fetch(Response(data))
                self.assertEqual(result["reason_code"], "INVALID_RESPONSE")

    def test_response_size_is_bounded_without_trusting_content_length(self):
        response = Response(b" " * 300)
        result, _, _ = self.fetch(response, max_bytes=128)
        self.assertEqual(result["reason_code"], "RESPONSE_TOO_LARGE")
        self.assertEqual(result["response_bytes"], 129)
        self.assertEqual(response.read_sizes, [129])

    def test_declared_oversize_is_rejected_before_body_read(self):
        response = Response(b"[]", Content_Length="10000000")
        result, _, _ = self.fetch(response, max_bytes=1024)
        self.assertEqual(result["reason_code"], "RESPONSE_TOO_LARGE")
        self.assertEqual(response.read_sizes, [])

    def test_incomplete_body_is_explicit_failure(self):
        result, _, _ = self.fetch(Response(b"[]", Content_Length="200"))
        self.assertEqual(result["reason_code"], "INCOMPLETE_RESPONSE")
        result, _, _ = self.fetch(IncompleteRead(b"[", 12))
        self.assertEqual(result["reason_code"], "INCOMPLETE_RESPONSE")

    def test_unsolicited_compression_is_not_decompressed(self):
        response = Response(b"not a compressed payload", Content_Encoding="gzip")
        result, _, _ = self.fetch(response)
        self.assertEqual(result["reason_code"], "UNSUPPORTED_CONTENT_ENCODING")
        self.assertEqual(response.read_sizes, [])

    def test_network_timeout_and_errors_remain_explicit(self):
        for error, reason in ((socket.timeout(), "TIMEOUT"), (URLError(socket.timeout()), "TIMEOUT"),
                              (URLError("proxy secret"), "NETWORK_ERROR")):
            with self.subTest(error=type(error).__name__):
                result, _, _ = self.fetch(error)
                self.assertEqual(result["reason_code"], reason)
                self.assertNotIn("proxy secret", json.dumps(result))

    def test_invalid_root_and_limits_fail_before_worker_launch(self):
        for root in ("com", "*.example.com", "https://example.com", "127.0.0.1", "bad..example.com",
                     "\texample.com", "example.com\t"):
            with self.subTest(root=root), patch.object(discovery.subprocess, "Popen") as launch:
                with self.assertRaises(ValueError):
                    discovery.discover_root(root)
                launch.assert_not_called()
        for options in ({"timeout": 0}, {"timeout": True}, {"timeout": float("nan")},
                        {"timeout": float("inf")}, {"max_names": 100001}, {"max_bytes": 1023}):
            with self.subTest(options=options), patch.object(discovery.subprocess, "Popen") as launch:
                with self.assertRaises(ValueError):
                    discovery.discover_root("example.com", **options)
                launch.assert_not_called()

    def test_worker_result_is_validated_and_never_becomes_exhaustive(self):
        value = self.parse([{"name_value": "app.example.com"}])
        value["exhaustive"] = True
        child = Mock(returncode=0)
        child.communicate.return_value = (json.dumps(value).encode(), None)
        with patch.object(discovery.subprocess, "Popen", return_value=child) as launch:
            result = discovery.discover_root("Example.COM.")
        self.assertFalse(result["exhaustive"])
        self.assertTrue(result["processing_complete"])
        self.assertEqual(result["candidates"], ["app.example.com"])
        self.assertIsInstance(launch.call_args.args[0], list)
        self.assertEqual(child.communicate.call_args.kwargs, {"timeout": 30})

    def test_foreign_or_invalid_worker_output_is_rejected(self):
        for output in (b"bad json", b"[]", b"{}", json.dumps({**self.parse([]), "candidates": ["evil.example.net"]}).encode()):
            with self.subTest(output=output[:20]):
                child = Mock(returncode=0)
                child.communicate.return_value = (output, None)
                with patch.object(discovery.subprocess, "Popen", return_value=child):
                    result = discovery.discover_root("example.com")
                self.assertEqual(result["reason_code"], "SOURCE_WORKER_ERROR")
                self.assertEqual(result["candidates"], [])

    def test_fractional_remaining_budget_is_forwarded_to_worker_and_deadline(self):
        child = Mock(returncode=0)
        child.communicate.return_value = (json.dumps(self.parse([])).encode(), None)
        with patch.object(discovery.subprocess, "Popen", return_value=child) as launch:
            result = discovery.discover_root("example.com", timeout=0.125)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(child.communicate.call_args.kwargs["timeout"], 0.125)
        command = launch.call_args.args[0]
        self.assertEqual(command[command.index("--timeout") + 1], "0.125")

    def test_keyboard_interrupt_kills_worker_and_propagates(self):
        child = Mock()
        child.communicate.side_effect = [KeyboardInterrupt(), (b"", None)]
        with patch.object(discovery.subprocess, "Popen", return_value=child), self.assertRaises(KeyboardInterrupt):
            discovery.discover_root("example.com")
        child.kill.assert_called_once_with()
        self.assertEqual(child.communicate.call_count, 2)

    def test_real_process_deadline_kills_hung_worker_without_network(self):
        with tempfile.TemporaryDirectory(prefix="php2shell-discovery-deadline-") as directory:
            worker = Path(directory) / "worker.py"
            worker.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
            launched = []
            real_popen = subprocess.Popen

            def launch(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                launched.append(process)
                return process

            started = time.monotonic()
            with patch.object(discovery, "__file__", str(worker)), patch.object(discovery.subprocess, "Popen", side_effect=launch):
                result = discovery.discover_root("example.com", timeout=1)
            self.assertEqual(result["reason_code"], "TIMEOUT")
            self.assertLess(time.monotonic() - started, 5)
            self.assertIsNotNone(launched[0].poll())


if __name__ == "__main__":
    unittest.main()
