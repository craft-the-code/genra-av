"""Tests for scripts/yara_select.py and the YARA part of scripts/check-pack.py. Standard library only.

Run: python3 -m unittest discover -s scripts -p 'test_yara*.py'
"""
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ys = load("yara_select", "yara_select.py")
cp = load("check_pack", "check-pack.py")

FORGE = '''import "pe"
import "magic"

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
'''

RL = '''import "pe"
rule Win32_Ransomware_Demo : tc_detection malicious
{
    condition:
        pe.is_pe
}
rule KEPT_A { condition: false }
'''


class YaraSelect(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        p = lambda n: os.path.join(self.d, n)
        open(p("forge.yar"), "w").write(FORGE)
        os.makedirs(p("rl/windows"))
        open(p("rl/windows/demo.yara"), "w").write(RL)
        root = os.path.dirname(HERE)
        json.dump({"rules": ["DISABLED_ONE"]}, open(p("disabled.json"), "w"))
        ys.select([os.path.join(root, "rules/yara-sources.json"), p("disabled.json"), p("blocks.yar"), "--forge", p("forge.yar"), "--forge-tag", "20261122", "--rl", p("rl"), "--rl-commit", "c" * 40])
        self.p = p

    def test_only_licensed_rules_and_supported_modules(self):
        text = open(self.p("blocks.yar")).read()
        names = [m.group(1) for m in map(ys.RULE_LINE.match, text.splitlines()) if m]
        self.assertEqual(names, ["KEPT_A", "KEPT_B", "Win32_Ransomware_Demo"], "GPL and disabled out; RL's duplicate KEPT_A out")
        self.assertIn('import "pe"', text)
        self.assertNotIn('import "magic"', text, "a module the engine lacks would refuse every rule")

    def test_assemble_drops_refused_and_counts_like_the_client(self):
        open(self.p("refused.txt"), "w").write("KEPT_B\n")
        out = os.path.join(self.d, "out")
        os.makedirs(out)
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ys.assemble([self.p("blocks.yar"), self.p("refused.txt"), out])
        y = json.loads(buf.getvalue())
        self.assertEqual(y["rules"], 2)
        self.assertRegex(y["file"], r"^yara-[0-9a-f]{12}\.yar$")
        body = open(os.path.join(out, y["file"]), encoding="utf-8").read()
        self.assertNotIn("rule KEPT_B", body)
        self.assertIn("Detection Rule License", body)
        # Deterministic: the signing job's rebuild gives the same bytes.
        out2 = os.path.join(self.d, "out2")
        os.makedirs(out2)
        with contextlib.redirect_stdout(io.StringIO()):
            ys.assemble([self.p("blocks.yar"), self.p("refused.txt"), out2])
        self.assertEqual(open(os.path.join(out2, y["file"]), "rb").read(), open(os.path.join(out, y["file"]), "rb").read())

        pack = {"yara": dict(y)}
        cp.check_yara(pack, out, out2)  # identical: passes
        with self.assertRaises(SystemExit):
            cp.check_yara(pack, out, None)
        with open(os.path.join(out, y["file"]), "ab") as f:
            f.write(b"\nrule Sneaked_In { condition: true }\n")
        with self.assertRaises(SystemExit):
            cp.check_yara(pack, out, out2)


if __name__ == "__main__":
    unittest.main()
