"""Offline URL admission checks, not connection or DNS-rebinding tests."""

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "_hermes_url_snapshot", Path(__file__).parent / "_verify.py"
)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class URLAdmissionChallenges(unittest.TestCase):
    def test_public_literal_is_admitted(self):
        self.assertIsNone(v._validate_fetch_url("https://93.184.216.34/docs"))

    def test_userinfo_is_rejected_before_resolution(self):
        with mock.patch.object(v.socket, "getaddrinfo", side_effect=AssertionError("DNS called")):
            with self.assertRaises(v._UnsafeURL):
                v._validate_fetch_url("https://inert:inert@93.184.216.34/")

    def test_whitespace_and_control_are_rejected(self):
        for url in ("https://93.184.216.34/a b", "https://93.184.216.34/\npath"):
            with self.assertRaises(v._UnsafeURL):
                v._validate_fetch_url(url)

    def test_zero_and_invalid_ports_are_rejected(self):
        for port in ("0", "65536", "invalid"):
            with self.assertRaises(v._UnsafeURL):
                v._validate_fetch_url("https://93.184.216.34:" + port + "/")

    def test_shared_address_space_is_not_public(self):
        with self.assertRaises(v._UnsafeURL):
            v._validate_fetch_url("http://100.64.0.1/")

    def test_mapped_private_ipv4_is_rejected(self):
        with self.assertRaises(v._UnsafeURL):
            v._validate_fetch_url("http://[::ffff:127.0.0.1]/")

    def test_malformed_ipv6_has_fixed_rejection_type(self):
        with self.assertRaises(v._UnsafeURL):
            v._validate_fetch_url("https://[broken/")

    def test_oversized_body_is_not_silently_truncated(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"x" * (v.MAX_FETCH_BYTES + 1)
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(v, "_validate_fetch_url"), mock.patch.object(
            v.urllib.request, "build_opener", return_value=opener
        ):
            with self.assertRaisesRegex(ValueError, "HERMES_VERIFY_SOURCE_BODY_LIMIT"):
                v._fetch_text("https://93.184.216.34/")
        response.read.assert_called_once_with(v.MAX_FETCH_BYTES + 1)

    def test_oversized_host_status_is_unknown(self):
        result = v.grade_tool_result("read_file", "observed", status="x" * 33)
        self.assertEqual(result["level"], "UNKNOWN")
        self.assertEqual(result["receipt"]["basis"], "INVALID_HOST_STATUS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
