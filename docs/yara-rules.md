# YARA rules in the rule pack

Genra ships YARA rules for malware families (ADR 0004, layer 2). They come from public rule sets
whose licences allow redistribution, are rebuilt with every rule pack, and run in Genra's engine
([boreal](https://github.com/vthib/boreal), MIT/Apache-2.0).

## Where the rules come from

| Source | Licence | How it reaches the pack |
|---|---|---|
| [ReversingLabs YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | MIT | Whole repository, at the commit named in the file header |
| [Florian Roth's signature-base](https://github.com/Neo23x0/signature-base) | [Detection Rule License 1.1](https://github.com/Neo23x0/signature-base/blob/master/LICENSE) | Through the [YARA Forge](https://github.com/YARAHQ/yara-forge) "core" release |
| [SEKOIA Community](https://github.com/SEKOIA-IO/Community) | Detection Rule License 1.1 | YARA Forge core |
| [ditekSHen detection](https://github.com/ditekshen/detection) | BSD-2-Clause | YARA Forge core |
| [Mandiant red team countermeasures](https://github.com/mandiant/red_team_tool_countermeasures) | BSD-2-Clause | YARA Forge core |
| [Volexity threat-intel](https://github.com/volexity/threat-intel) | BSD-2-Clause | YARA Forge core |
| [ESET malware-ioc](https://github.com/eset/malware-ioc) | BSD-2-Clause | YARA Forge core |
| [WithSecure iocs](https://github.com/WithSecureLabs/iocs) | BSD-2-Clause | YARA Forge core |
| [Google GCTI](https://github.com/chronicle/GCTI) | Apache-2.0 | YARA Forge core |
| [Trellix ARC](https://github.com/advanced-threat-research/Yara-Rules) | Apache-2.0 | YARA Forge core |
| [elceef yara-rulz](https://github.com/elceef/yara-rulz) | MIT | YARA Forge core |

Copyright stays with each rule's authors. Every rule is shipped as written, with its `author`,
`reference`, `source_url` and `license_url` meta, and the rule file starts with each source's own
licence text and copyright notice (copied into `rules/licenses/`), which is what the Detection Rule
License, the BSD, MIT and Apache licences ask for. Comments between rules (YARA Forge's per-repository
headers) are dropped, so no text ends up under another source's rule. The machine-readable allow list
is `rules/yara-sources.json`.

Two notes: a few signature-base rules by 0x0d4y carry `license = "CC BY 4.0"` in their own meta,
which also allows redistribution with attribution (kept in the meta). YARA Forge's own code is
GPL-3.0; Genra uses only its release file of other people's rules, under each rule's own licence,
and none of Forge's code.

Left out on purpose: GPL rule sets (CAPE, craiu), sets without a licence file (Malpedia
signator-rules and others in YARA Forge with `license_url = "N/A"`), and Elastic's rules (Elastic
License 2.0). A set joins only after its licence has been read.

## What is left out for now

Rules for hacking and admin tools, "suspicious" or "generic" indicators, exploits and logs
(names with `HKTL`, `HackTool`, `Tool`, `INDICATOR`, `SUSP`, `EXPL`, `LOG`, `PUA`, `Generic`):
they would flag programs admins use (remote desktop tools, PsExec) or call something malware that
is not. They come back once the clean corpus covers such tools and the message can say "hacking
tool" instead. About 3 100 rules ship today.

## How a rule reaches users

1. Every rule-pack run (`.github/workflows/rule-pack.yml`) takes the newest YARA Forge core release and
   ReversingLabs' latest commit, keeps the rules on the allow list, minus `rules/yara-disabled.json`
   (`scripts/yara_select.py`).
2. Genra's engine compiles each rule; the ones it refuses are dropped (`genra-av yara check`).
3. The signing job downloads the same release and commit itself (the commit must be on
   ReversingLabs' own default branch: GitHub also serves a fork's commits under the parent's name),
   rebuilds the file with the standard library, and signs only if it is byte for byte what the
   build job produced. The Forge release and the commit may only move forward. When the rules
   cannot be built in a run, the previous signed rules are carried over unchanged.
4. The app downloads the file (only when its digest changes), checks it against the signed pack and
   compiles it once. If the file cannot be used (an older engine that refuses a rule), only the
   YARA layer is off: the hash lists and the other checks keep working.

## Severity

Every YARA match is **suspicious**: Genra asks once, with "Cách ly" as the main button. A rule is
rated malware (quarantined without asking) only when it is named in `rules/yara-malware.json`,
reviewed in this repository after the detection report shows it matched no clean file; the list is
empty today. Rule text never decides it (a `severity`-like meta in an upstream rule is ignored), and
even a malware-rated rule never moves a validly signed program on its own (the signed-file rail).
One file, with every entry of an archive inside it, gets at most 1.5 s of YARA time in all.

A rule that matches a clean file goes into `rules/yara-disabled.json`; the weekly detection report
lists those rules by name. A single rule can also be switched off at once through the pack's
`disabled` list (`yara.<rule name>`).
