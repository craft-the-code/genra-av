"""Tests for abusech_feeds.py: what each feed answer turns into (no network)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import abusech_feeds as f  # noqa: E402

A = "a" * 64
B = "b" * 64
C = "c" * 64


class URLhaus(unittest.TestCase):
    def test_only_payloads_with_a_family(self):
        body = {"query_status": "ok", "payloads": [
            {"sha256_hash": A, "signature": "AgentTesla"},
            {"sha256_hash": B, "signature": None},
            {"sha256_hash": C, "signature": "  "},
        ]}
        self.assertEqual(f.urlhaus_hashes(body), {A})

    def test_upper_case_and_bad_values(self):
        body = {"query_status": "ok", "payloads": [
            {"sha256_hash": A.upper(), "signature": "Mirai"},
            {"sha256_hash": "not-a-hash", "signature": "Mirai"},
            {"sha256_hash": 5, "signature": "Mirai"},
            "junk",
        ]}
        self.assertEqual(f.urlhaus_hashes(body), {A})

    def test_no_results_is_empty_other_status_fails(self):
        self.assertEqual(f.urlhaus_hashes({"query_status": "no_results"}), set())
        with self.assertRaises(ValueError):
            f.urlhaus_hashes({"query_status": "http_get_expected"})
        with self.assertRaises(ValueError):
            f.urlhaus_hashes({"query_status": "ok"})


class ThreatFox(unittest.TestCase):
    def test_sha256_iocs_with_enough_confidence(self):
        body = {"query_status": "ok", "data": [
            {"ioc": A, "ioc_type": "sha256_hash", "confidence_level": 100},
            {"ioc": B, "ioc_type": "sha256_hash", "confidence_level": 50},
            {"ioc": C, "ioc_type": "md5_hash", "confidence_level": 100},
            {"ioc": "1.2.3.4:80", "ioc_type": "ip:port", "confidence_level": 100},
            {"ioc": C, "ioc_type": "sha256_hash", "confidence_level": "high"},
        ]}
        self.assertEqual(f.threatfox_hashes(body), {A})

    def test_threshold_is_inclusive(self):
        body = {"query_status": "ok", "data": [{"ioc": B, "ioc_type": "sha256_hash", "confidence_level": f.MIN_CONFIDENCE}]}
        self.assertEqual(f.threatfox_hashes(body), {B})

    def test_status(self):
        self.assertEqual(f.threatfox_hashes({"query_status": "no_result"}), set())
        with self.assertRaises(ValueError):
            f.threatfox_hashes({"query_status": "unknown_auth_key"})


if __name__ == "__main__":
    unittest.main()
