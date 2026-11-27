"""Tests for scripts/yara_select.py and the YARA part of scripts/check-pack.py. Standard library only.

Run: python3 -m unittest discover -s scripts -p 'test_*.py'
"""
import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ys = load("yara_select", "yara_select.py")
cp = load("check_pack", "check-pack.py")

FORGE = '''import "pe"
import "magic"

/*
 * YARA Rule Set
 * Repository Name: ditekSHen, a header that must not land under another source's rule
 */
rule KEPT_A : FILE {
\tmeta:
\t\tlicense_url = "https://github.com/ditekshen/detection/blob/abc/LICENSE.txt"
\tcondition:
\t\tpe.is_pe
}

rule DROPPED_GPL {
\tmeta:
\t\tlicense_url = "https://github.com/kevoreilly/CAPEv2/blob/abc/LICENSE"
\tcondition:
\t\ttrue
}
/* Repository Name: signature-base */

private rule KEPT_B {
\tmeta:
\t\tlicense_url = "https://github.com/Neo23x0/signature-base/blob/abc/LICENSE"
\tcondition:
\t\tKEPT_A
}

rule DISABLED_ONE {
\tmeta:
\t\tlicense_url = "https://github.com/Neo23x0/signature-base/blob/abc/LICENSE"
\tcondition:
\t\ttrue
}

rule SIGNATURE_BASE_HKTL_Mimikatz {
\tmeta:
\t\tlicense_url = "https://github.com/Neo23x0/signature-base/blob/abc/LICENSE"
\tcondition:
\t\ttrue
}

global rule GLOBAL_GATE {
	meta:
		license_url = "https://github.com/Neo23x0/signature-base/blob/abc/LICENSE"
	condition:
		filesize < 10MB
}

rule NO_OWN_LICENCE {
	condition:
		true
}
/* license_url = "https://github.com/Neo23x0/signature-base/blob/abc/LICENSE" */

rule AMBIGUOUS {
\tmeta:
\t\tlicense_url = "https://github.com/Neo23x0/signature-base/blob/abc/LICENSE"
\tcondition:
rule\x0bsneaky
}
'''

RL = '''import "pe"
rule Win32_Ransomware_Demo : tc_detection malicious
{
    condition:
        pe.is_pe
}
rule KEPT_A { condition: false }
'''


def quiet(f, *a):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        f(*a)
    return buf.getvalue()


class YaraSelect(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        p = lambda n: os.path.join(self.d, n)
        open(p("forge.yar"), "w").write(FORGE)
        os.makedirs(p("rl/windows"))
        open(p("rl/windows/demo.yara"), "w").write(RL)
        json.dump({"rules": ["DISABLED_ONE"]}, open(p("disabled.json"), "w"))
        json.dump({"rules": ["Win32_Ransomware_Demo", "NOT_SHIPPED"]}, open(p("malware.json"), "w"))
        quiet(ys.select, [os.path.join(ROOT, "rules/yara-sources.json"), p("disabled.json"), p("blocks.yar"), "--forge", p("forge.yar"), "--forge-tag", "20261122", "--rl", p("rl"), "--rl-commit", "c" * 40])
        self.p = p

    def assemble(self, refused: str, out: str) -> dict:
        open(self.p("refused.txt"), "w").write(refused)
        os.makedirs(out, exist_ok=True)
        return json.loads(quiet(ys.assemble, [self.p("blocks.yar"), self.p("refused.txt"), self.p("malware.json"), os.path.join(ROOT, "rules/licenses"), out]))

    def test_only_licensed_unambiguous_rules_and_supported_modules(self):
        text = open(self.p("blocks.yar")).read()
        names = [m.group(1) for m in map(ys.RULE_LINE.match, text.splitlines()) if m]
        self.assertEqual(names, ["KEPT_A", "KEPT_B", "Win32_Ransomware_Demo"], "GPL, disabled, hacking tool, global, unlicensed, ambiguous and RL's duplicate out")
        self.assertIn('import "pe"', text)
        self.assertNotIn('import "magic"', text, "a module the engine lacks would refuse every rule")
        self.assertNotIn("Repository Name", text, "comments between rules are dropped")

    def test_golden_count_matches_the_rust_reader(self):
        golden = open(os.path.join(HERE, "testdata/yara-count.yar"), encoding="utf-8").read()
        self.assertEqual(ys.count(golden), 6)
        self.assertEqual(sum(1 for l in golden.splitlines() if cp.RULE_LINE.match(l)), 6, "check-pack counts the same")

    def test_assemble_is_deterministic_and_carries_licences_and_the_malware_list(self):
        out, out2 = os.path.join(self.d, "out"), os.path.join(self.d, "out2")
        y = self.assemble("", out)
        self.assertEqual(y["rules"], 3)
        self.assertEqual(y["malware"], ["Win32_Ransomware_Demo"], "only shipped rules, from the reviewed list")
        self.assertEqual((y["forge_tag"], y["rl_commit"]), ("20261122", "c" * 40))
        self.assertRegex(y["file"], r"^yara-[0-9a-f]{12}\.yar$")
        body = open(os.path.join(out, y["file"]), encoding="utf-8").read()
        self.assertIn("Detection Rule License", body)
        self.assertIn("ESET spol. s r.o.", body)
        self.assertEqual(y, self.assemble("", out2))
        self.assertEqual(open(os.path.join(out2, y["file"]), "rb").read(), open(os.path.join(out, y["file"]), "rb").read())

    def test_refusing_a_rule_another_one_uses_fails(self):
        with self.assertRaises(SystemExit):
            self.assemble("KEPT_A\n", os.path.join(self.d, "o3"))
        y = self.assemble("KEPT_B\n", os.path.join(self.d, "o4"))
        self.assertEqual(y["rules"], 2)

    def test_check_pack_yara(self):
        out, exp = os.path.join(self.d, "out"), os.path.join(self.d, "exp")
        y = self.assemble("", out)
        self.assemble("", exp)
        json.dump(y, open(os.path.join(exp, "yara.json"), "w"))
        pack = {"yara": dict(y)}
        cp.check_yara(pack, out, exp)
        for bad in [{"yara": dict(y, rules=float(y["rules"]))}, {"yara": dict(y, malware=["Other"])}, {}]:
            with self.assertRaises(SystemExit):
                cp.check_yara(bad, out, exp)
        with self.assertRaises(SystemExit):
            cp.check_yara(pack, out, None)
        # Carried over unchanged from the previous signed pack: no rebuild needed.
        cp.check_yara(pack, out, None, {"yara": dict(y)}, out)
        with self.assertRaises(SystemExit):
            cp.check_yara({}, out, None, {"yara": dict(y)}, out)
        with self.assertRaises(SystemExit):
            cp.check_yara(pack, out, exp, {"yara": dict(y, forge_tag="20991231", file="x")}, out)
        with open(os.path.join(out, y["file"]), "ab") as f:
            f.write(b"\nrule Sneaked_In { condition: true }\n")
        with self.assertRaises(SystemExit):
            cp.check_yara(pack, out, exp)


if __name__ == "__main__":
    unittest.main()


class YaraCarry(unittest.TestCase):
    def test_carries_the_previous_rules_or_none(self):
        carry = load("yara_carry", "yara-carry.py")
        d = tempfile.mkdtemp()
        out, prev = os.path.join(d, "out"), os.path.join(d, "prev")
        os.makedirs(out), os.makedirs(prev)
        new = {"file": "yara-111111111111.yar", "rules": 1}
        old = {"file": "yara-222222222222.yar", "rules": 2, "sha256": "2" * 64}
        with open(os.path.join(out, new["file"]), "w") as f:
            f.write("new")
        with open(os.path.join(prev, old["file"]), "w") as f:
            f.write("old")
        with open(os.path.join(out, "pack.json"), "w") as f:
            json.dump({"version": 2, "yara": new}, f)
        with open(os.path.join(prev, "pack.json"), "w") as f:
            json.dump({"version": 1, "yara": old}, f)
        import sys
        argv = sys.argv
        try:
            sys.argv = ["x", os.path.join(out, "pack.json"), prev]
            quiet(carry.main)
            p = json.load(open(os.path.join(out, "pack.json")))
            self.assertEqual(p["yara"], old)
            self.assertFalse(os.path.exists(os.path.join(out, new["file"])))
            self.assertEqual(open(os.path.join(out, old["file"])).read(), "old")
            os.remove(os.path.join(prev, "pack.json"))
            quiet(carry.main)
            self.assertNotIn("yara", json.load(open(os.path.join(out, "pack.json"))))
        finally:
            sys.argv = argv
