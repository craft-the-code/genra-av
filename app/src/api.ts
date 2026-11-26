import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Severity = "info" | "suspicious" | "malware";
export interface Finding { rule: string; family: string; severity: Severity; message_vi: string; auto_quarantine: boolean }
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
export interface RepairDone {
  id: string;
  name: string;
  clean_path: string;
  clean_name: string;
  renamed: boolean;
  removed: string[];
  kept: string[];
  quarantine_id: string;
  family: string;
  machine: unknown | null;
}
export interface Quarantined { id: string; name: string }

export type Undo = { type: "quarantine"; id: string } | { type: "repair"; id: string };
export type EntryKind = "check" | "quick_scan" | "quarantine" | "repair";
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
}
export interface QuarantineItem { id: string; original_path: string; sha256: string; size: number; reason: string; quarantined_at: number }
export interface HistoryView { entries: Entry[]; other_quarantine: QuarantineItem[] }

export interface Progress { phase: "walking" | "waiting"; folder: string; files: number }
export interface QuickResult { at: number; files_seen: number; files_read: number; files_cached: number; roots: string[]; hits: ScanResult[] }

export type Tone = "ok" | "warn" | "bad";
export interface HealthItem { id: string; tone: Tone; title_vi: string; detail_vi: string; fix_id: string | null }
export interface StartupItem { name: string; location: string; publisher: string | null; tone: Tone; detail_vi: string }
export interface MachineOverview {
  health: HealthItem[] | null;
  startup: StartupItem[] | null;
  excel: { running: boolean; open_books: string[] } | null;
}
export interface Settings { send_hashes: boolean }

export const rulesInfo = () => invoke<RulesInfo>("rules_info");
export const launchPath = () => invoke<string | null>("launch_path");
export const pickFile = () => invoke<string | null>("pick_file");
export const scanFile = (path: string) => invoke<ScanResult>("scan_file", { path });
export const repairFile = (path: string) => invoke<RepairDone>("repair_file", { path });
export const quarantineFile = (path: string) => invoke<Quarantined>("quarantine_file", { path });
export const undo = (u: Undo) => invoke<string>("undo", { undo: u });
export const history = () => invoke<HistoryView>("history");
export const quickScan = () => invoke<void>("quick_scan");
export const reveal = (path: string) => invoke<void>("reveal", { path });
export const openLink = (which: "privacy" | "terms" | "source") => invoke<void>("open_link", { which });
export const machineOverview = () => invoke<MachineOverview>("machine_overview");
export const getSettings = () => invoke<Settings>("get_settings");
export const setSendHashes = (on: boolean) => invoke<Settings>("set_send_hashes", { on });
export const reportFalsePositive = (sha256: string, ruleId: string | null, note: string | null) =>
  invoke<void>("report_false_positive", { sha256, ruleId, note });

export const onProgress = (f: (p: Progress) => void): Promise<UnlistenFn> => listen<Progress>("quick-progress", (e) => f(e.payload));
export const onQuickDone = (f: (r: QuickResult) => void): Promise<UnlistenFn> => listen<QuickResult>("quick-done", (e) => f(e.payload));
export const onRulesChanged = (f: () => void): Promise<UnlistenFn> => listen("rules-changed", () => f());
export const onDropped = (f: (paths: string[]) => void): Promise<UnlistenFn> => listen<string[]>("dropped", (e) => f(e.payload));
