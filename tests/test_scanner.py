"""
test_scanner.py — 主要機能の単体テスト / Unit tests for core features

実行方法 / Run:
    python -m unittest discover tests -v

ネットワークアクセスは一切行いません（モックデータで確認します）。
No network access — checks are tested with mock data only.
"""

import os
import sys
import unittest
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety import validate_target, RateLimiter, SafetyError
from checks import (
    check_https,
    check_security_headers,
    check_version_disclosure,
    check_info_leakage,
    check_cookie_flags,
    check_form_validation,
)
from report import render_markdown, to_json_dict

CONFIG = {
    "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
    "allowed_ports": [80, 443, 3000],
    "max_requests_per_scan": 3,
    "request_interval_seconds": 0,
}


class TestValidateTarget(unittest.TestCase):
    """URL安全チェックのテスト / URL safety validation tests."""

    def test_localhost_allowed(self):
        parsed = validate_target("http://localhost:3000", CONFIG)
        self.assertEqual(parsed.hostname, "localhost")

    def test_127_allowed(self):
        validate_target("http://127.0.0.1:3000/path", CONFIG)

    def test_external_domain_rejected(self):
        with self.assertRaises(SafetyError):
            validate_target("https://example.com", CONFIG)

    def test_external_ip_rejected(self):
        with self.assertRaises(SafetyError):
            validate_target("http://8.8.8.8", CONFIG)

    def test_bad_scheme_rejected(self):
        with self.assertRaises(SafetyError):
            validate_target("ftp://localhost:3000", CONFIG)

    def test_bad_port_rejected(self):
        with self.assertRaises(SafetyError):
            validate_target("http://localhost:9999", CONFIG)

    def test_credentials_in_url_rejected(self):
        with self.assertRaises(SafetyError):
            validate_target("http://user:pass@localhost:3000", CONFIG)


class TestRateLimiter(unittest.TestCase):
    def test_limit_enforced(self):
        limiter = RateLimiter(max_requests=2, interval_seconds=0)
        limiter.acquire()
        limiter.acquire()
        with self.assertRaises(SafetyError):
            limiter.acquire()


class TestChecks(unittest.TestCase):
    """各チェック機能のテスト / Tests for each passive check."""

    def test_http_detected(self):
        f = check_https(urlparse("http://localhost:3000"), "http://localhost:3000")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "Medium")

    def test_https_ok(self):
        self.assertIsNone(check_https(urlparse("https://localhost"), "https://localhost"))

    def test_missing_headers_detected(self):
        findings = check_security_headers({}, "http")
        ids = [f.id for f in findings]
        self.assertIn("missing-header-content-security-policy", ids)
        # HSTS は http では要求されない / HSTS only expected over https
        self.assertNotIn("missing-header-strict-transport-security", ids)

    def test_good_headers_pass(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=63072000",
            "Referrer-Policy": "no-referrer",
        }
        self.assertEqual(check_security_headers(headers, "https"), [])

    def test_version_disclosure(self):
        findings = check_version_disclosure({"Server": "Apache/2.4.1", "X-Powered-By": "Express"})
        self.assertEqual(len(findings), 2)

    def test_debug_leak_on_error_page(self):
        body = "Traceback (most recent call last):\n  File ..." 
        findings = check_info_leakage(body, 500)
        self.assertEqual(len(findings), 1)

    def test_no_leak_on_normal_page(self):
        body = "Traceback (most recent call last):"
        self.assertEqual(check_info_leakage(body, 200), [])

    def test_cookie_flags(self):
        findings = check_cookie_flags(["session=abc123"], "https")
        self.assertEqual(len(findings), 1)
        self.assertIn("HttpOnly", findings[0].evidence)

    def test_cookie_flags_ok(self):
        cookies = ["session=abc; HttpOnly; Secure; SameSite=Lax"]
        self.assertEqual(check_cookie_flags(cookies, "https"), [])

    def test_form_validation_hint(self):
        body = '<form><input name="email" type="text"></form>'
        findings = check_form_validation(body)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "Info")


class TestReport(unittest.TestCase):
    def test_markdown_contains_required_sections(self):
        findings = check_version_disclosure({"Server": "Apache/2.4.1"})
        md = render_markdown("http://localhost:3000", findings)
        for keyword in ["実行日時", "対象 / Target", "重要度", "修正方法", "参考"]:
            self.assertIn(keyword, md)

    def test_json_dict_serializable(self):
        import json
        findings = check_version_disclosure({"Server": "nginx/1.25"})
        json.dumps(to_json_dict("http://localhost:3000", findings))  # 例外が出なければOK


if __name__ == "__main__":
    unittest.main()
