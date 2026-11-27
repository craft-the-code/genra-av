//! Repair tests on synthetic workbooks in temporary folders. Nothing here looks at the real
//! home folder, Excel or ~/Library.

use super::*;
use crate::journal::EntryState;
use std::io::{Cursor, Write};

pub(crate) fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("genra-machine-r-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::canonicalize(&d).unwrap()
}

// ---- fixtures (built independently of the core's private test helpers) ----

fn container(raw: &[u8]) -> Vec<u8> {
    assert!(raw.len() <= 4096);
    let mut v = vec![0x01, 0xFF, 0x3F];
    v.extend_from_slice(raw);
    v
}

fn dir_record(id: u16, data: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(data);
    v
}

fn write_vba<F: std::io::Read + Write + std::io::Seek>(comp: &mut cfb::CompoundFile<F>, root: &str, modules: &[(&str, &str)]) {
    let base = PathBuf::from(root);
    if root != "/" {
        comp.create_storage_all(&base).unwrap();
    }
    comp.create_storage(base.join("VBA")).unwrap();
    let mut dir = Vec::new();
    for (name, _) in modules {
        dir.extend(dir_record(0x0019, name.as_bytes()));
        dir.extend(dir_record(0x001A, name.as_bytes()));
        dir.extend(dir_record(0x0031, &0u32.to_le_bytes()));
        dir.extend(dir_record(0x002B, &[]));
    }
    dir.extend(dir_record(0x0010, &[]));
    comp.create_stream(base.join("VBA/dir")).unwrap().write_all(&container(&dir)).unwrap();
    for (name, src) in modules {
        comp.create_stream(base.join("VBA").join(name)).unwrap().write_all(&container(src.as_bytes())).unwrap();
    }
    comp.create_stream(base.join("PROJECT")).unwrap().write_all(b"ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n").unwrap();
}

/// The worm's shape: copies itself to XLSTART and hooks every sheet.
pub(crate) const WORM: &str = "Attribute VB_Name = \"Kangatang\"\r\nSub Auto_Open()\r\nApplication.OnSheetActivate = \"x\"\r\nActiveWorkbook.SaveCopyAs Application.StartupPath & \"\\mypersonnel.xls\"\r\nEnd Sub\r\n";
/// Someone's own harmless macro.
const OWN: &str = "Attribute VB_Name = \"Tinh\"\r\nSub Tong()\r\nRange(\"A1\").Value = 1\r\nEnd Sub\r\n";

fn rec(t: u16, d: &[u8]) -> Vec<u8> {
    let mut v = t.to_le_bytes().to_vec();
    v.extend_from_slice(&(d.len() as u16).to_le_bytes());
    v.extend_from_slice(d);
    v
}

fn bof(dt: u16) -> Vec<u8> {
    let mut d = vec![0x00, 0x06];
    d.extend_from_slice(&dt.to_le_bytes());
    d.extend_from_slice(&[0x54, 0x38, 0xCD, 0x07, 0xC9, 0x00, 0x02, 0x00, 0x06, 0x08, 0x00, 0x00]);
    d
}

/// A small BIFF8 Workbook stream: globals with one data sheet, then the sheet.
fn workbook_stream() -> Vec<u8> {
    let mut s = rec(0x0809, &bof(0x0005));
    let bs = s.len();
    let mut b = 0u32.to_le_bytes().to_vec();
    b.extend_from_slice(&[0, 0, 4, 0]);
    b.extend_from_slice(b"Data");
    s.extend(rec(0x0085, &b));
    s.extend(rec(0x000A, &[]));
    let lb = s.len() as u32;
    s[bs + 4..bs + 8].copy_from_slice(&lb.to_le_bytes());
    s.extend(rec(0x0809, &bof(0x0010)));
    s.extend(rec(0x000A, &[]));
    s
}

/// An .xls with a VBA project holding `modules`.
pub(crate) fn xls(modules: &[(&str, &str)]) -> Vec<u8> {
    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    comp.create_stream("/Workbook").unwrap().write_all(&workbook_stream()).unwrap();
    if !modules.is_empty() {
        write_vba(&mut comp, "/_VBA_PROJECT_CUR", modules);
    }
    comp.flush().unwrap();
    comp.into_inner().into_inner()
}

fn vba_project_bin(modules: &[(&str, &str)]) -> Vec<u8> {
    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    write_vba(&mut comp, "/", modules);
    comp.flush().unwrap();
    comp.into_inner().into_inner()
}

/// An .xlsm with one sheet and a VBA project holding the worm.
pub(crate) fn xlsm() -> Vec<u8> {
    let parts: Vec<(&str, Vec<u8>)> = vec![
        ("[Content_Types].xml", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#.to_vec()),
        ("_rels/.rels", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#.to_vec()),
        ("xl/workbook.xml", br#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>"#.to_vec()),
        ("xl/_rels/workbook.xml.rels", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>"#.to_vec()),
        ("xl/worksheets/sheet1.xml", br#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>81 dong</t></is></c></row></sheetData></worksheet>"#.to_vec()),
        ("xl/vbaProject.bin", vba_project_bin(&[("Kangatang", WORM)])),
    ];
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in parts {
        w.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(&data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

pub(crate) fn pack() -> Pack {
    Pack::parse(
        br#"{"format":1,"version":1,"published":"x","rules":[
        {"id":"GENRA.Office.Kangatang.Module","family":"Kangatang","severity":"malware","message_vi":"m","machine_persistence":"xlstart","when":{"vba_module_name_any":["Kangatang"]}}]}"#,
    )
    .unwrap()
}

fn no_excel() -> ExcelStatus {
    ExcelStatus::default()
}

fn plan_of(steps: Vec<Action>) -> Plan {
    Plan {
        group_id: Journal::new_group_id().unwrap(),
        steps: steps.into_iter().map(|action| Step { action, title_vi: "b".into(), title_en: "s".into(), needs: None }).collect(),
        summary_vi: String::new(),
        summary_en: String::new(),
    }
}

fn no_macros(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    let f = extract::facts(&bytes);
    assert!(f.vba.is_empty() && !f.vba_unreadable, "{} still has macros", path.display());
    assert!(genra_av_core::scan(&bytes, Some(&pack())).verdict.is_none_or(|v| v < Severity::Suspicious));
}

#[test]
fn xlsm_is_replaced_by_a_verified_xlsx_and_undone_in_one_press() {
    let root = tmp("xlsm");
    let file = root.join("Bao cao.xlsm");
    let original = xlsm();
    std::fs::write(&file, &original).unwrap();
    let mut j = Journal::open(root.join("data")).unwrap();
    let plan = plan_of(vec![Action::ReplaceWithClean { path: file.clone() }]);
    let mut seen = Vec::new();
    let r = run_in(&plan, &mut j, no_excel, |p| seen.push(p.state));
    assert_eq!(r.outcome, Outcome::Done, "{r:#?}");
    assert!(r.verified);
    assert_eq!(seen, [StepState::Started, StepState::Done]);
    let clean = root.join("Bao cao.xlsx");
    assert_eq!(r.cleaned[0].clean_path, clean);
    assert!(!file.exists(), "the macro file is gone from its folder");
    no_macros(&clean);
    let q = j.quarantine().list().unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].sha256, sha256_hex(&original), "original kept in quarantine");
    assert_eq!(q[0].original_path, file);

    j.undo_group(&plan.group_id).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), original, "original bytes back");
    assert!(!clean.exists(), "clean copy taken back (into quarantine, not deleted)");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn xls_is_replaced_in_place_by_a_verified_clean_copy() {
    let root = tmp("xls");
    let file = root.join("BIỂU TỔNG HỢP.xls");
    let original = xls(&[("Kangatang", WORM), ("ThisWorkbook", "Attribute VB_Name = \"ThisWorkbook\"\r\n")]);
    assert_eq!(extract::facts(&original).vba.len(), 2, "fixture carries macros");
    std::fs::write(&file, &original).unwrap();
    let mut j = Journal::open(root.join("data")).unwrap();
    let plan = plan_of(vec![Action::ReplaceWithClean { path: file.clone() }]);
    let r = run_in(&plan, &mut j, no_excel, |_| {});
    assert_eq!(r.outcome, Outcome::Done, "{r:#?}");
    assert_eq!(r.cleaned[0].clean_path, file, "same name, same place");
    no_macros(&file);
    assert_ne!(std::fs::read(&file).unwrap(), original);
    assert_eq!(j.quarantine().list().unwrap()[0].sha256, sha256_hex(&original));
    // The journal holds the quarantine first, then the new file, each done.
    let g = j.group(&plan.group_id).unwrap();
    assert!(matches!(g[0].change, crate::journal::Change::Quarantine { .. }) && matches!(g[1].change, crate::journal::Change::CreateFile { .. }));
    assert!(g.iter().all(|e| e.state == EntryState::Done));
    j.undo_group(&plan.group_id).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), original);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_failing_step_rolls_the_whole_group_back() {
    let root = tmp("rollback");
    let a = root.join("a.xls");
    let a_bytes = xls(&[("Kangatang", WORM)]);
    std::fs::write(&a, &a_bytes).unwrap();
    let b = root.join("b.xls");
    std::fs::write(&b, b"not an office file at all").unwrap();
    let mut j = Journal::open(root.join("data")).unwrap();
    let plan = plan_of(vec![Action::ReplaceWithClean { path: a.clone() }, Action::ReplaceWithClean { path: b.clone() }]);
    let r = run_in(&plan, &mut j, no_excel, |_| {});
    let Outcome::RolledBack { failed_step, .. } = &r.outcome else { panic!("{r:#?}") };
    assert_eq!(*failed_step, 1);
    assert!(!r.verified && r.cleaned.is_empty());
    assert_eq!(std::fs::read(&a).unwrap(), a_bytes, "first file back as it was");
    assert_eq!(std::fs::read(&b).unwrap(), b"not an office file at all");
    assert!(r.title_vi.contains("máy vẫn như cũ"));
    let mut names: Vec<String> = std::fs::read_dir(&root).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["a.xls", "b.xls", "data"], "no temp files left");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_existing_xlsx_is_never_overwritten() {
    let root = tmp("exists");
    let file = root.join("a.xlsm");
    std::fs::write(&file, xlsm()).unwrap();
    std::fs::write(root.join("a.xlsx"), b"the user's own a.xlsx").unwrap();
    let mut j = Journal::open(root.join("data")).unwrap();
    let r = run_in(&plan_of(vec![Action::ReplaceWithClean { path: file.clone() }]), &mut j, no_excel, |_| {});
    assert!(matches!(r.outcome, Outcome::RolledBack { .. }));
    assert_eq!(std::fs::read(root.join("a.xlsx")).unwrap(), b"the user's own a.xlsx");
    assert!(file.exists());
    assert!(j.quarantine().list().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn nothing_changes_while_excel_has_the_file_open() {
    let root = tmp("open");
    let file = root.join("a.xls");
    let bytes = xls(&[("Kangatang", WORM)]);
    std::fs::write(&file, &bytes).unwrap();
    let mut j = Journal::open(root.join("data")).unwrap();
    let excel = || ExcelStatus { running: true, open_documents: vec!["a.xls".into()] };
    let r = run_in(&plan_of(vec![Action::ReplaceWithClean { path: file.clone() }]), &mut j, excel, |_| panic!("no step may start"));
    assert_eq!(r.outcome, Outcome::NeedsAction { need: Need::CloseApp { app: "Excel".into(), open_documents: vec!["a.xls".into()] } });
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert!(j.entries().unwrap().is_empty(), "not even a journal line");
    assert!(r.detail_vi.contains("Genra chưa thay đổi gì"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn quarantine_and_xlstart_actions_check_their_preconditions() {
    let root = tmp("xlact");
    let elsewhere = root.join("Documents");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let not_startup = elsewhere.join("mypersonnel.xls");
    std::fs::write(&not_startup, xls(&[("Kangatang", WORM)])).unwrap();
    let mut j = Journal::open(root.join("data")).unwrap();
    let r = run_in(&plan_of(vec![Action::RemoveXlstartItem { path: not_startup.clone() }]), &mut j, no_excel, |_| {});
    assert!(matches!(r.outcome, Outcome::RolledBack { .. }), "only files in an Excel startup folder");
    assert!(not_startup.exists());

    let r = run_in(&plan_of(vec![Action::QuarantineFile { path: not_startup.clone(), expected_sha256: "00".into() }]), &mut j, no_excel, |_| {});
    assert!(matches!(r.outcome, Outcome::RolledBack { .. }), "a changed hash is refused");
    let sha = sha256_hex(&std::fs::read(&not_startup).unwrap());
    let r = run_in(&plan_of(vec![Action::QuarantineFile { path: not_startup.clone(), expected_sha256: sha }]), &mut j, no_excel, |_| {});
    assert_eq!(r.outcome, Outcome::Done);
    assert!(!not_startup.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// A machine with the worm: the file the user opened, the copy in XLSTART, another infected
/// workbook in Documents, and things that must be left alone.
struct Machine {
    root: PathBuf,
    threat: PathBuf,
    xlstart: PathBuf,
    worm_in_xlstart: PathBuf,
    personal: PathBuf,
    other_infected: PathBuf,
    own_macros: PathBuf,
    plain: PathBuf,
}

fn machine(name: &str) -> Machine {
    let root = tmp(name);
    let xlstart = root.join("AppData/Roaming/Microsoft/Excel/XLSTART");
    let docs = root.join("Documents");
    let zalo = root.join("Downloads/Zalo");
    for d in [&xlstart, &docs, &zalo] {
        std::fs::create_dir_all(d).unwrap();
    }
    let m = Machine {
        threat: zalo.join("BIỂU TỔNG HỢP.xls"),
        worm_in_xlstart: xlstart.join("mypersonnel.xls"),
        personal: xlstart.join("PERSONAL.XLSB"),
        other_infected: docs.join("So lieu thang 11.xls"),
        own_macros: docs.join("Tinh luong.xls"),
        plain: docs.join("Danh sach.xls"),
        xlstart,
        root,
    };
    std::fs::write(&m.threat, xls(&[("Kangatang", WORM)])).unwrap();
    std::fs::write(&m.worm_in_xlstart, xls(&[("Kangatang", WORM)])).unwrap();
    std::fs::write(&m.personal, xls(&[("Tinh", OWN)])).unwrap();
    std::fs::write(&m.other_infected, xls(&[("Kangatang", WORM), ("Module1", OWN)])).unwrap();
    std::fs::write(&m.own_macros, xls(&[("Tinh", OWN)])).unwrap();
    std::fs::write(&m.plain, xls(&[])).unwrap();
    m
}

fn scope<'a>(m: &Machine, p: &'a Pack, excel: ExcelStatus) -> Scope<'a> {
    Scope { pack: Some(p), reputation: None, xlstart_dirs: vec![m.xlstart.clone()], scan_roots: vec![m.root.join("Documents"), m.root.join("Downloads")], excel, removable: vec![], persistence: Some(vec![]), processes: Some(vec![]), locks: Some(vec![]) }
}

#[test]
fn the_plan_cleans_the_machine_not_just_the_file() {
    let m = machine("plan");
    let p = pack();
    let report = genra_av_core::scan(&std::fs::read(&m.threat).unwrap(), Some(&p));
    let plan = plan_for_threat_in(&m.threat, &report, &scope(&m, &p, ExcelStatus::default()));
    let actions: Vec<&Action> = plan.steps.iter().map(|s| &s.action).collect();
    assert_eq!(
        actions,
        [
            &Action::ReplaceWithClean { path: m.threat.clone() },
            &Action::RemoveXlstartItem { path: m.worm_in_xlstart.clone() },
            &Action::ReplaceWithClean { path: m.other_infected.clone() },
        ],
        "PERSONAL.XLSB, a workbook with the user's own macros and a plain one are left alone"
    );
    assert!(plan.steps.iter().all(|s| s.needs.is_none()));
    assert_eq!(plan.summary_vi, "Gỡ sâu khỏi Excel · làm sạch 2 tệp · không đụng gì khác");
    assert!(plan.steps[1].title_vi.starts_with("Gỡ sâu khỏi Excel"));

    // Run it, check every file, then undo it all in one press.
    let before: Vec<(PathBuf, Vec<u8>)> = [&m.threat, &m.worm_in_xlstart, &m.other_infected, &m.personal, &m.own_macros, &m.plain].iter().map(|p| ((*p).clone(), std::fs::read(p).unwrap())).collect();
    let mut j = Journal::open(m.root.join("data")).unwrap();
    let r = run_in(&plan, &mut j, no_excel, |_| {});
    assert_eq!(r.outcome, Outcome::Done, "{r:#?}");
    assert_eq!(r.title_vi, "Đã dọn xong, máy hoạt động bình thường");
    no_macros(&m.threat);
    no_macros(&m.other_infected);
    assert!(!m.worm_in_xlstart.exists());
    for (p, b) in &before[3..] {
        assert_eq!(&std::fs::read(p).unwrap(), b, "{} untouched", p.display());
    }
    assert_eq!(j.quarantine().list().unwrap().len(), 3);
    j.undo_group(&plan.group_id).unwrap();
    for (p, b) in &before {
        assert_eq!(&std::fs::read(p).unwrap(), b, "{} back as it was", p.display());
    }
    let _ = std::fs::remove_dir_all(&m.root);
}

#[test]
fn the_plan_asks_for_excel_to_close_when_it_must() {
    let m = machine("needs");
    let p = pack();
    let report = genra_av_core::scan(&std::fs::read(&m.threat).unwrap(), Some(&p));
    let excel = ExcelStatus { running: true, open_documents: vec!["BIỂU TỔNG HỢP.xls".into(), "Book1".into()] };
    let plan = plan_for_threat_in(&m.threat, &report, &scope(&m, &p, excel.clone()));
    assert!(plan.steps[0].needs.is_some(), "Excel has the file open");
    assert!(plan.steps[1].needs.is_some(), "Excel runs while XLSTART is changed");
    assert!(plan.steps[2].needs.is_none(), "another file Excel does not have open");
    assert_eq!(plan.need(), Some(Need::CloseApp { app: "Excel".into(), open_documents: vec!["BIỂU TỔNG HỢP.xls".into(), "Book1".into()] }));
    let _ = std::fs::remove_dir_all(&m.root);
}

#[test]
fn a_threat_that_does_not_persist_cleans_only_the_file() {
    let m = machine("single");
    let p = Pack::parse(br#"{"format":1,"version":1,"published":"x","rules":[{"id":"d","family":"downloader","severity":"malware","message_vi":"m","when":{"vba_source_any":["OnSheetActivate"]}}]}"#).unwrap();
    let report = genra_av_core::scan(&std::fs::read(&m.threat).unwrap(), Some(&p));
    let plan = plan_for_threat_in(&m.threat, &report, &scope(&m, &p, ExcelStatus::default()));
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.summary_vi, "Làm sạch 1 tệp · không đụng gì khác");
    let _ = std::fs::remove_dir_all(&m.root);
}

#[test]
fn clean_destinations() {
    assert_eq!(clean_destination(Path::new("/a/B.xlsm"), Some("xlsx")), PathBuf::from("/a/B.xlsx"));
    assert_eq!(clean_destination(Path::new("/a/B.XLSX"), Some("xlsx")), PathBuf::from("/a/B.XLSX"));
    assert_eq!(clean_destination(Path::new("/a/B.xls"), None), PathBuf::from("/a/B.xls"));
    assert_eq!(clean_destination(Path::new("/a/so.lieu.docm"), Some("docx")), PathBuf::from("/a/so.lieu.docx"));
    assert!(is_office_version("16.0") && is_office_version("15.0") && !is_office_version("Common") && !is_office_version("16"));
}

#[test]
fn plans_and_reports_serialise_for_the_app() {
    let plan = plan_of(vec![Action::SetOfficeMacroPolicy { app: OfficeApp::Excel, level: MacroLevel::DisableWithNotification }, Action::DisableStartupItem { id: "file:/x".into() }]);
    let v = serde_json::to_value(&plan).unwrap();
    assert_eq!(v["steps"][0]["action"], serde_json::json!({"type":"set_office_macro_policy","app":"Excel","level":"DisableWithNotification"}));
    let back: Plan = serde_json::from_value(v).unwrap();
    assert_eq!(back.steps[1].action, Action::DisableStartupItem { id: "file:/x".into() });
}

#[test]
fn a_threat_found_in_xlstart_is_moved_out_not_cleaned_in_place() {
    let m = machine("inxl");
    let p = pack();
    let report = genra_av_core::scan(&std::fs::read(&m.worm_in_xlstart).unwrap(), Some(&p));
    let plan = plan_for_threat_in(&m.worm_in_xlstart, &report, &scope(&m, &p, ExcelStatus::default()));
    let actions: Vec<&Action> = plan.steps.iter().map(|s| &s.action).collect();
    assert_eq!(
        actions,
        [
            &Action::RemoveXlstartItem { path: m.worm_in_xlstart.clone() },
            &Action::ReplaceWithClean { path: m.other_infected.clone() },
            &Action::ReplaceWithClean { path: m.threat.clone() },
        ],
        "the worm's copy once, then the infected documents (sorted by path)"
    );
    let mut j = Journal::open(m.root.join("data")).unwrap();
    let r = run_in(&plan, &mut j, no_excel, |_| {});
    assert_eq!(r.outcome, Outcome::Done, "{r:#?}");
    assert!(!m.worm_in_xlstart.exists());
    let _ = std::fs::remove_dir_all(&m.root);
}

/// A shortcut that runs cmd with a long hidden command, as USB worms make.
fn worm_lnk() -> Vec<u8> {
    let mut b = vec![0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    b.extend((0x08u32 | 0x20 | 0x80).to_le_bytes());
    b.resize(76, 0);
    for s in ["..\\..\\..\\Windows\\System32\\cmd.exe", &format!("/c start wscript /e:vbs \"_\\x.dat\" & start explorer \"Tai lieu\" {}", "&".repeat(400))] {
        let u: Vec<u16> = s.encode_utf16().collect();
        b.extend((u.len() as u16).to_le_bytes());
        for c in u {
            b.extend(c.to_le_bytes());
        }
    }
    b
}

#[test]
fn a_threat_that_is_not_an_office_file_is_quarantined_with_the_usb_worm_s_other_shortcuts() {
    let root = tmp("usb-plan");
    let usb = root.join("USB");
    std::fs::create_dir_all(&usb).unwrap();
    let a = usb.join("Tai lieu.lnk");
    let b = usb.join("Hinh anh.lnk");
    std::fs::write(&a, worm_lnk()).unwrap();
    std::fs::write(&b, worm_lnk()).unwrap();
    let p = pack();
    let report = genra_av_core::scan_named("Tai lieu.lnk", &std::fs::read(&a).unwrap(), Some(&p), None);
    assert!(report.verdict.is_some_and(|v| v >= genra_av_core::rules::Severity::Suspicious));
    let mut s = Scope { pack: Some(&p), reputation: None, xlstart_dirs: vec![], scan_roots: vec![], excel: ExcelStatus::default(), removable: vec![usb.clone()], persistence: Some(vec![]), processes: Some(vec![]), locks: Some(vec![]) };
    let plan = plan_for_threat_in(&a, &report, &s);
    let quarantined: Vec<&PathBuf> = plan.steps.iter().filter_map(|st| if let Action::QuarantineFile { path, .. } = &st.action { Some(path) } else { None }).collect();
    assert_eq!(quarantined, [&a, &b], "the shortcut itself, then the worm's other shortcut; nothing replaced");
    assert!(!plan.steps.iter().any(|st| matches!(st.action, Action::ReplaceWithClean { .. })));
    // Not on a removable drive: only the file itself.
    s.removable.clear();
    let plan = plan_for_threat_in(&a, &report, &s);
    assert_eq!(plan.steps.len(), 1);
    assert!(plan.summary_vi.contains("cách ly"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn what_the_threat_left_on_the_machine_is_planned_around_its_quarantine() {
    let root = tmp("traces-plan");
    let threat = root.join("AppData").join("svc").join("update.js");
    std::fs::create_dir_all(threat.parent().unwrap()).unwrap();
    std::fs::write(&threat, b"x").unwrap();
    let p = pack();
    let mut report = genra_av_core::scan_named("update.js", b"x", Some(&p), None);
    report.verdict = Some(genra_av_core::rules::Severity::Malware);
    let t = threat.display().to_string();
    let persist = |id: &str, scope, kind, command: String, file: Option<PathBuf>| startup::Persist { id: id.into(), name: id.into(), scope, kind, target: None, command, file };
    let processes = vec![
        traces::Running { pid: 4242, started: "t0".into(), exe: Some("C:\\Windows\\System32\\wscript.exe".into()), command: format!("wscript.exe \"{t}\"") },
        traces::Running { pid: 4243, started: "t1".into(), exe: Some("C:\\Windows\\notepad.exe".into()), command: "notepad.exe".into() },
    ];
    let s = Scope {
        pack: Some(&p),
        reputation: None,
        xlstart_dirs: vec![],
        scan_roots: vec![],
        excel: ExcelStatus::default(),
        removable: vec![],
        persistence: Some(vec![
            persist("run:HKCU|svc", startup::ItemScope::User, startup::PersistKind::Entry, format!("wscript.exe \"{t}\""), None),
            persist("run:HKLM|svc", startup::ItemScope::System, startup::PersistKind::Entry, format!("wscript.exe {t}"), None),
            persist("task:\\svc", startup::ItemScope::System, startup::PersistKind::Task { name: "\\svc".into() }, format!("wscript.exe {t} //B"), None),
            persist("file:x", startup::ItemScope::User, startup::PersistKind::Entry, t.clone(), Some(threat.clone())),
            persist("run:HKCU|zalo", startup::ItemScope::User, startup::PersistKind::Entry, "C:\\Zalo\\Zalo.exe".into(), None),
        ]),
        processes: Some(processes),
        locks: Some(vec![(traces::LOCKS[0].0.into(), traces::LOCKS[0].1.into()), ("HKCU\\Software\\X".into(), "DisableTaskMgr".into())]),
    };
    let plan = plan_for_threat_in(&threat, &report, &s);
    let kinds: Vec<String> = plan.steps.iter().map(|st| serde_json::to_value(&st.action).unwrap()["type"].as_str().unwrap().to_string()).collect();
    assert_eq!(kinds, ["stop_process", "quarantine_file", "disable_threat_startup", "disable_scheduled_task", "lift_lock"], "stop first so the file can move; {kinds:?}");
    assert_eq!(plan.steps[0].action, Action::StopProcess { pid: 4242, started: "t0".into(), path: threat.clone(), program: "wscript.exe".into(), image: false });
    assert_eq!(plan.steps[2].action, Action::DisableThreatStartup { id: "run:HKCU|svc".into() });
    assert!(plan.summary_vi.contains("dừng 1 chương trình") && plan.summary_vi.contains("tắt 2 mục tự chạy") && plan.summary_vi.contains("1 mục tự chạy cần quyền quản trị"), "{}", plan.summary_vi);

    // A suspicious (not malware) threat: its own traces, but no machine-wide locks.
    report.verdict = Some(genra_av_core::rules::Severity::Suspicious);
    report.findings.retain(|f| f.severity < genra_av_core::rules::Severity::Malware);
    let plan = plan_for_threat_in(&threat, &report, &s);
    assert!(!plan.steps.iter().any(|st| matches!(st.action, Action::LiftLock { .. })));

    // An Office document is cleaned in place: Excel holding it is never stopped.
    let doc = root.join("bao-cao.xlsm");
    let plan = plan_for_threat_in(&doc, &report, &s);
    assert!(plan.steps.iter().all(|st| matches!(st.action, Action::ReplaceWithClean { .. })), "{:?}", plan.steps);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_running_threat_windows_will_not_stop_is_left_for_after_a_restart_not_rolled_back() {
    let root = tmp("still-running");
    let threat = root.join("svc.exe");
    std::fs::write(&threat, b"MZ worm").unwrap();
    let sha = sha256_hex(b"MZ worm");
    let plan = Plan {
        group_id: Journal::new_group_id().unwrap(),
        steps: vec![
            // Off Windows, stopping always fails: it stands for a process Windows will not stop.
            Step { action: Action::StopProcess { pid: 999_999, started: "t".into(), path: threat.clone(), program: "svc.exe".into(), image: true }, title_vi: "a".into(), title_en: "a".into(), needs: None },
            Step { action: Action::QuarantineFile { path: threat.clone(), expected_sha256: sha }, title_vi: "b".into(), title_en: "b".into(), needs: None },
            Step { action: Action::DisableThreatStartup { id: "run:HKCU\\x|gone".into() }, title_vi: "c".into(), title_en: "c".into(), needs: None },
        ],
        summary_vi: String::new(),
        summary_en: String::new(),
    };
    let mut j = Journal::open(root.join("data")).unwrap();
    let r = run_in(&plan, &mut j, ExcelStatus::default, |_| {});
    assert_eq!(r.outcome, Outcome::Done, "{:?}", r.steps);
    let states: Vec<StepState> = r.steps.iter().map(|s| s.state).collect();
    assert_eq!(states, [StepState::NotAllowed, StepState::NotAllowed, StepState::Skipped]);
    assert!(threat.exists(), "left in place until the restart, nothing rolled back");
    let _ = std::fs::remove_dir_all(&root);
}
