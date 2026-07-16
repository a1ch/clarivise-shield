"""Unit tests for the QR/quishing URL-normalization logic in main.py.
Mirrors main.py::_qr_text_to_url (kept dependency-free so it runs anywhere).
Run: python -m unittest connector/test_qr.py  (or: python connector/test_qr.py)
"""
import re
import unittest
from urllib.parse import urlparse


def _qr_text_to_url(text):
    if not text:
        return None
    url = text.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        if re.match(r"^www\.", url, re.IGNORECASE) or re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", url, re.IGNORECASE):
            url = "https://" + url
        else:
            return None
    try:
        if not urlparse(url).netloc:
            return None
    except Exception:
        return None
    return url


class QrUrlNormalization(unittest.TestCase):
    def test_keeps_full_https(self):
        self.assertEqual(_qr_text_to_url("https://login.micros0ft-verify.com/auth"),
                         "https://login.micros0ft-verify.com/auth")

    def test_keeps_full_http(self):
        self.assertEqual(_qr_text_to_url("http://example.com/x"), "http://example.com/x")

    def test_prepends_https_to_www(self):
        self.assertEqual(_qr_text_to_url("www.paypal-secure.com/login"),
                         "https://www.paypal-secure.com/login")

    def test_prepends_https_to_bare_domain(self):
        self.assertEqual(_qr_text_to_url("bit.ly/abc123"), "https://bit.ly/abc123")

    def test_trims_whitespace(self):
        self.assertEqual(_qr_text_to_url("   https://example.com  "), "https://example.com")

    def test_ignores_non_url_payloads(self):
        for junk in ("WIFI:S:Net;T:WPA;P:pw;;", "just some text", "BEGIN:VCARD", "upi://pay?pa=x@bank"):
            self.assertIsNone(_qr_text_to_url(junk), junk)

    def test_ignores_empty_and_none(self):
        self.assertIsNone(_qr_text_to_url(""))
        self.assertIsNone(_qr_text_to_url(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)