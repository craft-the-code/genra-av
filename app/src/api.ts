import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Severity = "info" | "suspicious" | "malware";
export interface Finding {
  rule: string;
  family: string;
  severity: Severity;
  message_vi: string;
  /** English from the rule pack; null for packs written before it existed. */
  message_en: string | null;
  auto_quarantine: boolean;
}
export interface Report {
  sha256: string;
  kind: "ole" | "zip" | "other";
  vba_modules: { name: string; bytes: number }[];
  findings: Finding[];
  verdict: Severity | null;
  allowed: boolean;
}
export interface ScanResult { name: string; path: string; size: number; hash_only: boolean; report: Report }
export interface RulesInfo {
  version: number;
  published: string;
  rules: number;
  hashes: number;
  source: "bundled" | "installed";
  expires: number | null;
  last_ok: number | null;
  last_try: number | null;
  last_error: string | null;
}

/** A repair or quarantine that did not happen. `refused`: the cleaner will not touch this file. */
export interface Failure { kind: "refused" | "failed"; code: string; detail: string }

export type StepState = "started" | "done" | "skipped" | "not_allowed" | "failed";
export interface StepProgress { index: number; total: number; title_vi: string; title_en: string; state: StepState }
export interface RepairProgress { phase: "planning" | "step"; step: StepProgress | null }
export interface StepResult {
  index: number;
  title_vi: string;
  title_en: string;
  state: StepState;
  detail_vi: string;
  detail_en: string;
  error: string | null;
}
export type Outcome =
  | { type: "done" }
  | { type: "needs_action"; need: { type: "close_app"; app: string; open_documents: string[] } }
  | { type: "rolled_back"; failed_step: number; error: string }
  | { type: "rollback_failed"; failed_step: number; error: string; rollback_error: string };
export interface RunReport {
  group_id: string;
  outcome: Outcome;
  steps: StepResult[];
  verified: boolean;
  title_vi: string;
  title_en: string;
  detail_vi: string;
  detail_en: string;
}
export interface CleanedView { name: string; original_path: string; clean_name: string; clean_path: string; renamed: boolean; removed: string[] }
export type RepairDone = {
  state: "done";
  group_id: string;
  name: string;
  family: string;
  xlstart: string[];
  cleaned: CleanedView[];
  skipped: number;
  machine: { stopped: number; startup: number; unlocked: number; shown: number; left: number };
  verified: boolean;
  report: RunReport;
};
export type RepairNeedsExcel = { state: "needs_excel"; group_id: string; name: string; open_documents: string[]; report: RunReport };
export type RepairNotDone = { state: "not_done"; name: string; rolled_back: boolean; report: RunReport };
export type RepairView = RepairDone | RepairNeedsExcel | RepairNotDone;
export interface ExcelStatus { running: boolean; open_documents: string[] }
export interface Quarantined { id: string; name: string }

export type Undo = { type: "quarantine"; id: string } | { type: "group"; id: string };
export type EntryKind = "check" | "quick_scan" | "quarantine" | "repair" | "fix" | "startup_off";
export interface Entry {
  id: string;
  at: number;
  kind: EntryKind;
  name: string;
  path?: string;
  verdict?: Severity;
  family?: string;
  files?: number;
  hits?: number;
  undo?: Undo;
  undone: boolean;
  can_undo: boolean;
  /** Quick scan: the files it found. */
  items?: HitItem[];
  /** Quick scan: stopped part way. */
  stopped?: boolean;
  /** Folder scan: how many folders (`path` is the first). */
  folders?: number;
}
export interface HitItem { path: string; name: string; verdict?: Severity; family?: string; hash_only: boolean }
export interface QuarantineItem { id: string; original_path: string; sha256: string; size: number; reason: string; quarantined_at: number }
export interface HistoryView { entries: Entry[]; other_quarantine: QuarantineItem[] }

export interface Progress { phase: "walking" | "waiting"; folder: string; files: number }
export interface QuickResult { at: number; scope: "quick" | "full" | "folder"; stopped: boolean; files_seen: number; files_read: number; files_cached: number; roots: string[]; hits: ScanResult[] }

export type HealthStatus = "ok" | "warn" | "bad" | "unknown";
export interface HealthItem {
  id: string;
  status: HealthStatus;
  title_vi: string;
  title_en: string;
  detail_vi: string;
  detail_en: string;
  /** The one fix this item offers ("Sửa giúp tôi"), when it has one. */
  fix: string | null;
}
export interface StartupItem {
  id: string;
  name: string;
  location: string;
  /** Masked: tokens and passwords are shown as "…". */
  command: string;
  scope: "user" | "system";
  signed: boolean | null;
  publisher: string | null;
  verdict: "ok" | "unknown" | "warn" | "bad";
  reason_vi: string;
  reason_en: string;
  can_disable: boolean;
}
export interface GuardPlace { kind: "downloads" | "zalo" | "usb"; paths: string[] }
export interface MachineOverview { health: HealthItem[]; startup: StartupItem[]; guard: GuardPlace[] }
export interface Settings { send_hashes: boolean }

export const rulesInfo = () => invoke<RulesInfo>("rules_info");
export const launchPath = () => invoke<string | null>("launch_path");
export const pickFile = () => invoke<string | null>("pick_file");
export const scanFile = (path: string) => invoke<ScanResult>("scan_file", { path });
export const repairFile = (path: string) => invoke<RepairView>("repair_file", { path });
export const continueRepair = (groupId: string) => invoke<RepairView>("continue_repair", { groupId });
export const excelStatus = () => invoke<ExcelStatus>("excel_status");
export const closeExcel = () => invoke<void>("close_excel");
export const quarantineFile = (path: string) => invoke<Quarantined>("quarantine_file", { path });
export const undo = (u: Undo) => invoke<string[]>("undo", { undo: u });
export const history = () => invoke<HistoryView>("history");
export const quickScan = (scope: "quick" | "full" = "quick") => invoke<void>("quick_scan", { scope });
/** The folder picker, several at once; empty when it was closed. */
export const pickFolders = () => invoke<string[]>("pick_folders");
export const scanFolders = (folders: string[]) => invoke<void>("scan_folders", { folders });
export const stopScan = () => invoke<void>("stop_scan");
export const recheckHit = (entryId: string, path: string) => invoke<void>("recheck_hit", { entryId, path });
export const reveal = (path: string) => invoke<void>("reveal", { path });
export const openLink = (which: "privacy" | "terms" | "source") => invoke<void>("open_link", { which });
export const machineOverview = (refresh = false) => invoke<MachineOverview>("machine_overview", { refresh });
export const fixHealth = (fix: string) => invoke<RunReport>("fix_health", { fix });
export const disableStartup = (id: string) => invoke<RunReport>("disable_startup", { id });
export const installId = () => invoke<string>("get_install_id");
export type UpdateInfo = { version: string; notes: string | null };
export const checkUpdate = () => invoke<UpdateInfo | null>("check_update");
export const installUpdate = () => invoke<void>("install_update");
export const getSettings = () => invoke<Settings>("get_settings");
export const setSendHashes = (on: boolean) => invoke<Settings>("set_send_hashes", { on });
export const reportFalsePositive = (sha256: string, ruleId: string | null, note: string | null) =>
  invoke<void>("report_false_positive", { sha256, ruleId, note });

export const onProgress = (f: (p: Progress) => void): Promise<UnlistenFn> => listen<Progress>("quick-progress", (e) => f(e.payload));
export const onQuickDone = (f: (r: QuickResult) => void): Promise<UnlistenFn> => listen<QuickResult>("quick-done", (e) => f(e.payload));
export const onRepairProgress = (f: (p: RepairProgress) => void): Promise<UnlistenFn> =>
  listen<RepairProgress>("repair-progress", (e) => f(e.payload));
export const onRulesChanged = (f: () => void): Promise<UnlistenFn> => listen("rules-changed", () => f());
export const onDropped = (f: (paths: string[]) => void): Promise<UnlistenFn> => listen<string[]>("dropped", (e) => f(e.payload));
