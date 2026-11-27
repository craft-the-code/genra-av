#!/usr/bin/env python3
"""Tests for hash_grade.py's decisions (no network). Run: python3 -m unittest scripts/test_hash_grade.py"""
import datetime
import importlib.util
import os
import unittest

spec = importlib.util.spec_from_file_location("hash_grade", os.path.join(os.path.dirname(__file__), "hash_grade.py"))
hg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hg)

NOW = datetime.datetime(2026, 11, 27, 12, 0, tzinfo=datetime.timezone.utc)
FAMS = ({"remcosrat", "agenttesla"}, {"connectwise"})
TWO_ENGINES = {
    "ReversingLabs": {"threat_name": "Win32.Trojan.Remcos", "status": "MALICIOUS"},
    "Triage": {"malware_family": "remcos", "score": "10"},
    "Spamhaus_HBL": [{"detection": "not detected"}],
}


def info(**kw):
    base = {"signature": "RemcosRAT", "first_seen": "2026-11-24 08:00:00", "vendor_intel": TWO_ENGINES}
    base.update(kw)
    return base


class Grade(unittest.TestCase):
    def test_listed_family_two_engines_old_enough_is_trusted(self):
        ok, why = hg.qualifies(info(), FAMS, NOW)
        self.assertTrue(ok, why)

    def test_family_not_listed_or_never_trusted(self):
        self.assertFalse(hg.qualifies(info(signature="SomethingNew"), FAMS, NOW)[0])
        self.assertFalse(hg.qualifies(info(signature="ConnectWise"), (FAMS[0] | {"connectwise"}, FAMS[1]), NOW)[0])
        self.assertFalse(hg.qualifies(info(signature=None), FAMS, NOW)[0])

    def test_too_new(self):
        ok, why = hg.qualifies(info(first_seen="2026-11-26 13:00:00"), FAMS, NOW)
        self.assertFalse(ok)
        self.assertIn("48 hours", why)

    def test_one_engine_is_not_enough(self):
        one = {"ReversingLabs": {"status": "MALICIOUS"}, "Triage": {"score": "3"}}
        self.assertFalse(hg.qualifies(info(vendor_intel=one), FAMS, NOW)[0])

    def test_negative_wording_is_not_a_detection(self):
        vi = {"A": {"verdict": "not malicious"}, "B": {"detection": "No malware found"}, "C": {"verdict": "benign"}}
        self.assertEqual(hg.malicious_engines(vi), [])

    def test_withdrawn_entry(self):
        self.assertFalse(hg.qualifies(None, FAMS, NOW)[0])

    def test_csv_export_rows(self):
        text = '# MalwareBazaar recent\n# "first_seen_utc","sha256_hash","signature"\n"2026-11-27 01:00:00", "' + "a" * 64 + '", "RemcosRAT"\n'
        rows = list(hg.recent_rows(text))
        self.assertEqual(rows[0]["sha256_hash"].strip('" '), "a" * 64)


if __name__ == "__main__":
    unittest.main()
