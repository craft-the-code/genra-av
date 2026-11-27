// Golden file: Rust (crates/core/src/yara.rs) and Python (scripts/yara_select.py, check-pack.py) must count the same rules here: 6.
rule A { condition: false }
private rule B : tag {
  condition: true
}
global	private rule C{ condition: true }
/*
rule Café notes in a comment still count the same in both: Caf
*/
  rule indented_not_counted
rule
rule 
rules are not rule declarations
ruleodd_separator_not_counted
private  rule   D_1 // spaces
ruleX not_counted
global rule E
