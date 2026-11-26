import { invoke } from "@tauri-apps/api/core";

export type Severity = "info" | "suspicious" | "malware";
export interface Finding { rule: string; family: string; severity: Severity; message_vi: string }
export interface Report {
  sha256: string;
  kind: "ole" | "zip" | "other";
  vba_modules: { name: string; bytes: number }[];
  findings: Finding[];
  verdict: Severity | null;
  allowed: boolean;
}
export interface ScanResult { name: string; path: string; size: number; report: Report }
export interface RulesInfo { version: number; published: string; rules: number }

export const rulesInfo = () => invoke<RulesInfo>("rules_info");
export const launchPath = () => invoke<string | null>("launch_path");
export const scanFile = (path: string) => invoke<ScanResult>("scan_file", { path });
export const reveal = (path: string) => invoke<void>("reveal", { path });
export const reportFalsePositive = (sha256: string, ruleId: string | null, note: string | null) =>
  invoke<void>("report_false_positive", { sha256, ruleId, note });
