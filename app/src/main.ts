// Genra AV window. Plain TypeScript: four screens do not need a framework, and the window stays
// small and quick to open on old office PCs (ADR 0003, principle 9). Every file action runs in
// Rust; the window only asks and shows (docs/ux/README.md, mock-ups v2).
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getVersion } from "@tauri-apps/api/app";
import * as api from "./api";
import type { Failure, QuickResult, RepairDone, RepairNeedsExcel, RepairNotDone, RepairView, ScanResult, Severity, Undo } from "./api";
import { icon, line, mark, trigramPattern, type Tone } from "./icons";
import { t, setLang, getLang, type Lang } from "./i18n";

type Page = "overview" | "scan" | "machine" | "settings";
type Theme = "system" | "light" | "dark";
type ScanState =
  | { status: "idle" }
  | { status: "busy"; name: string; slow: boolean; token: number }
  | { status: "done"; result: ScanResult }
  | { status: "error"; code: string; detail: string };
type Act =
  | { s: "idle" }
  | { s: "working"; what: "clean" | "quarantine" }
  | { s: "refused"; f: Failure }
  | { s: "failed"; f: Failure }
  /** Mock 4: nothing changed yet, Excel must close; Genra polls and carries on by itself. */
  | { s: "excel"; v: RepairNeedsExcel; path: string; asked: "none" | "genra" | "self"; continuing: boolean; error: string }
  | { s: "not_done"; v: RepairNotDone }
  | { s: "repaired"; done: RepairDone; undoing: boolean; error: string }
  | { s: "quarantined"; q: api.Quarantined };
type ReportState = { open: boolean; note: string; status: "idle" | "sending" | "done" | "error"; error: string };
type Notice = { tone: Tone; text: string } | null;

const PAGES: { id: Page; icon: string }[] = [
  { id: "overview", icon: "house" },
  { id: "scan", icon: "file-check" },
  { id: "machine", icon: "monitor" },
  { id: "settings", icon: "sliders-horizontal" },
];
/** A read that has not come back after this long is almost always the OS permission prompt. */
const PERMISSION_WAIT_MS = 3000;
const HISTORY_ROWS = 5;

const state = {
  page: "overview" as Page,
  theme: "light" as Theme,
  appVersion: "",
  update: null as api.UpdateInfo | null,
  updating: "idle" as "idle" | "busy" | "error",
  rules: null as api.RulesInfo | null,
  settings: { send_hashes: false } as api.Settings,
  scan: { status: "idle" } as ScanState,
  act: { s: "idle" } as Act,
  details: false,
  report: { open: false, note: "", status: "idle", error: "" } as ReportState,
  quick: {
    running: false,
    /** What the running scan walks: the usual places, every drive, or a folder. */
    scope: "quick" as "quick" | "full" | "folder",
    stopping: false,
    folder: "",
    files: 0,
    waiting: false,
    result: null as QuickResult | null,
    handled: new Set<string>(),
    error: "",
  },
  history: null as api.HistoryView | null,
  historyAll: false,
  hitsAll: false,
  machine: null as api.MachineOverview | null,
  machineLoading: false,
  machineError: "",
  /** The health fix or startup item being changed right now. */
  machineBusy: "",
  machineNotice: null as { tone: Tone; text: string; undo?: Undo } | null,
  startupAll: false,
  repairProgress: null as api.RepairProgress | null,
  installId: "",
  copied: false,
  notice: null as Notice,
  dragOver: false,
};
let scanToken = 0;

// ---------- helpers

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

function store(key: string, value?: string): string | null {
  try {
    if (value !== undefined) localStorage.setItem(key, value);
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

const nf = (n: number) => n.toLocaleString(getLang() === "vi" ? "vi-VN" : "en-US");

function fmtSize(n: number): string {
  const f = (x: number) => x.toLocaleString(getLang(), { maximumFractionDigits: x < 10 ? 1 : 0 });
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${f(n / 1024)} KB`;
  return `${f(n / 1024 / 1024)} MB`;
}

function fmtWhen(secs: number): string {
  const d = new Date(secs * 1000);
  const time = d.toLocaleTimeString(getLang(), { hour: "2-digit", minute: "2-digit" });
  const today = new Date().toDateString() === d.toDateString();
  return today ? time : `${time} ${d.toLocaleDateString(getLang(), { day: "2-digit", month: "2-digit" })}`;
}

const fmtDate = (secs: number) => new Date(secs * 1000).toLocaleDateString(getLang(), { day: "2-digit", month: "2-digit", year: "numeric" });

function relTime(secs: number): string {
  const diff = Math.max(0, Date.now() / 1000 - secs);
  if (diff < 60) return t("time.just_now");
  if (diff < 3600) return t("time.minutes", { n: Math.floor(diff / 60) });
  if (diff < 6 * 3600) return t("time.hours", { n: Math.floor(diff / 3600) });
  return t("time.at", { time: fmtWhen(secs) });
}

/** Shortens a folder for display: the home folder becomes ~, long paths keep their last parts. */
function shortFolder(p: string): string {
  const parts = p.split(/[\\/]/).filter(Boolean);
  const users = parts.findIndex((x) => x === "Users" || x === "home");
  const rest = users >= 0 && parts.length > users + 2 ? ["~", ...parts.slice(users + 2)] : parts;
  return rest.length > 4 ? `…/${rest.slice(-3).join("/")}` : rest.join("/") || p;
}

const baseName = (p: string) => p.split(/[\\/]/).pop() ?? p;

/** The English text when the window is in English and it exists, else the Vietnamese one. */
const tr = (vi: string, en?: string | null) => (getLang() === "en" && en ? en : vi);

const tone = (r: ScanResult): Tone => {
  const v = r.report.verdict;
  if (v === "malware" && !r.hash_only) return "bad";
  if (v === "malware" || v === "suspicious") return "warn";
  return "ok";
};
const isThreat = (r: ScanResult) => r.report.verdict === "malware" || r.report.verdict === "suspicious";
const verdictTone = (v?: Severity | null): Tone => (v === "malware" ? "bad" : v === "suspicious" ? "warn" : "ok");

function statusWord(r: ScanResult): string {
  if (r.hash_only) return t("status.hash");
  const tn = tone(r);
  return tn === "bad" ? t("status.malware") : tn === "warn" ? t("status.suspicious") : t("status.safe");
}

function familyName(family: string): string {
  const key = `family.${family}`;
  const s = t(key);
  return s === key ? family : s;
}

/** The finding that decides the verdict (highest severity, first in pack order). */
function topFinding(r: ScanResult) {
  const rank: Record<Severity, number> = { info: 0, suspicious: 1, malware: 2 };
  return [...r.report.findings].sort((a, b) => rank[b.severity] - rank[a.severity])[0] ?? null;
}

function failureCode(e: unknown): Failure {
  if (e && typeof e === "object" && "code" in e) return e as Failure;
  return { kind: "failed", code: "other", detail: String(e) };
}

// ---------- theme

function applyTheme() {
  const root = document.documentElement;
  if (state.theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", state.theme);
}

// ---------- sidebar

function rulesLine(): string {
  const r = state.rules;
  if (!r) return "";
  if (r.source === "installed" && r.last_ok) return t("footer.rules.updated", { when: relTime(r.last_ok) });
  if (r.source === "bundled" && r.last_error) return t("footer.rules.bundled_failed");
  return t("footer.rules.bundled");
}

function sidebar(): string {
  const items = PAGES.map(
    ({ id, icon: ic }) =>
      `<li><button class="nav-item" data-action="nav" data-page="${id}" data-fid="nav-${id}"${
        state.page === id ? ' aria-current="page"' : ""
      }>${line(ic)}<span>${esc(t(`nav.${id}`))}</span></button></li>`,
  ).join("");
  return `<aside class="side">
    <div class="brand">${mark}<span class="brand-name">GENRA <span>AV</span></span></div>
    <nav aria-label="${esc(t("nav.label"))}"><ul class="nav">${items}</ul></nav>
    <div class="side-foot">
      <div class="line">${line("shield", 16)}<span>${esc(t("footer.guard"))}</span></div>
      ${state.update ? `<button class="link footer-update" data-action="goto-update" data-fid="goto-update">${esc(t("update.footer", { version: state.update.version }))}</button>` : ""}
      <div class="line rules">${esc(rulesLine())}</div>
    </div>
  </aside>`;
}

// ---------- Tổng quan

function remainingHits(): ScanResult[] {
  return state.quick.result?.hits.filter((h) => !state.quick.handled.has(h.path)) ?? [];
}

function lastQuickEntry(): api.Entry | undefined {
  return state.history?.entries.find((e) => e.kind === "quick_scan");
}

type Pending = { entry: api.Entry; item: api.HitItem };

/** Files earlier scans found that nothing has dealt with, newest scan first. A folder scan or a
 * stopped scan saw only part of the computer, so the scans before it still count; a quick or
 * whole-computer scan that ran to the end replaces everything older. */
function pendingItems(): Pending[] {
  const out: Pending[] = [];
  const seen = new Set<string>();
  for (const e of state.history?.entries ?? []) {
    if (e.kind !== "quick_scan") continue;
    for (const item of openItems(e)) {
      if (!seen.has(item.path)) {
        seen.add(item.path);
        out.push({ entry: e, item });
      }
    }
    if (entryScope(e) !== "folder" && !e.stopped) break;
  }
  return out;
}

type ScanScope = "quick" | "full" | "folder";

/** The scope a history entry was scanned with (older entries are quick scans). */
function entryScope(e: api.Entry): ScanScope {
  return e.path ? "folder" : e.name === "full" ? "full" : "quick";
}

function safeText(scope: ScanScope, folder: string, at: number, files: number): string {
  const args = { when: t("time.at", { time: fmtWhen(at) }), files: nf(files), folder: shortFolder(folder) };
  return t(scope === "full" ? "band.safe.full" : scope === "folder" ? "band.safe.folder" : "band.safe.text", args);
}

function band(): string {
  const q = state.quick;
  let tn: Tone | "busy" | "mark" = "mark";
  let title = "";
  let text: string[] = [];
  let action = "";
  const primary = (a: string, label: string) =>
    `<button class="btn on-dark primary" data-action="${a}" data-fid="band-${a}">${esc(label)}</button>`;
  const secondary = (a: string, label: string) =>
    `<button class="btn on-dark" data-action="${a}" data-fid="band-${a}">${line("refresh-cw", 16)}${esc(label)}</button>`;
  const hits = remainingHits();
  let ok = false;

  if (q.running) {
    tn = q.waiting ? "mark" : "busy";
    if (q.waiting) {
      title = t("band.waiting.title");
      text = [t("band.waiting.text", { folder: shortFolder(q.folder) })];
    } else {
      title = t(q.scope === "full" ? "band.running.full" : q.scope === "folder" ? "band.running.folder" : "band.running.title");
      text = [q.folder ? t("band.running.text", { folder: shortFolder(q.folder), files: nf(q.files) }) : t("band.running.start")];
    }
    action = q.stopping
      ? `<button class="btn on-dark" disabled>${esc(t("band.stopping"))}</button>`
      : `<button class="btn on-dark" data-action="stop-scan" data-fid="band-stop">${esc(t("band.stop"))}</button>`;
  } else if (hits.length) {
    const first = hits[0];
    const bad = hits.some((h) => !h.hash_only);
    tn = bad ? "bad" : "warn";
    title = t("band.hits.title", { n: hits.length });
    const what = first.hash_only ? t("status.hash").toLowerCase() : familyName(topFinding(first)?.family ?? "");
    text = [
      hits.length > 1 ? t("band.hits.more", { name: first.name, what, more: hits.length - 1 }) : t("band.hits.one", { name: first.name, what }),
      t(first.hash_only ? "band.hits.suspicious" : "band.hits.promise"),
    ];
    action = first.hash_only ? primary("band-look", t("band.look")) : primary("band-clean", t("band.clean"));
  } else {
    const last = lastQuickEntry();
    const pending = pendingItems().length;
    if (pending) {
      tn = "warn";
      title = t("band.previous.title", { n: pending });
      text = [t("band.previous.listed")];
      action = primary("quick", t("band.scan"));
    } else if (last?.stopped) {
      // A stopped scan saw only part of the computer: never call that "safe".
      title = t("band.stopped.title");
      text = [t("band.stopped.text", { files: nf(last.files ?? 0) })];
      action = primary("quick", t("band.scan"));
    } else if (last && (last.hits ?? 0) > 0 && !(last.items ?? []).length) {
      // Written before scans kept their file list.
      tn = "warn";
      title = t("band.previous.title", { n: last.hits ?? 0 });
      text = [t("band.previous.text")];
      action = primary("quick", t("band.scan"));
    } else if (last) {
      ok = true;
      tn = "ok";
      title = t("band.safe.title");
      text = [safeText(entryScope(last), last.path ?? "", last.at, last.files ?? 0)];
      action = secondary("quick", t("band.scan"));
    } else {
      title = t("band.never.title");
      text = [t("band.never.text")];
      action = primary("quick", t("band.scan"));
    }
  }
  if (q.error) text.push(t("band.error", { detail: q.error }));
  // The usual scan stays the one button; the wider ones sit beside it as quiet links.
  const more = q.running
    ? ""
    : `<div class="band-more">
        <button class="link on-dark" data-action="scan-full" data-fid="band-full">${esc(t("band.full"))}</button>
        <button class="link on-dark" data-action="scan-folder" data-fid="band-folder">${esc(t("band.folder"))}</button>
      </div>`;
  const glyph =
    tn === "busy"
      ? '<div class="band-spinner" aria-hidden="true"></div>'
      : tn === "mark"
        ? `<div class="band-mark">${q.waiting ? line("lock", 30) : mark}</div>`
        : icon(tn);
  return `<section class="band${ok ? " ok" : ""}" aria-labelledby="band-title" aria-live="polite">
    ${trigramPattern}
    <div class="band-icon">${glyph}</div>
    <div class="band-body">
      <h2 id="band-title">${esc(title)}</h2>
      ${text.map((x) => `<p>${esc(x)}</p>`).join("")}
      ${action ? `<div class="actions">${action}</div>` : ""}
      ${more}
    </div>
  </section>`;
}

const HIT_ROWS = 5;

/** Files a quick scan found that an earlier repair or quarantine has not dealt with yet. */
function openItems(e: api.Entry): api.HitItem[] {
  const dealt = new Set(
    (state.history?.entries ?? [])
      .filter((x) => x.at >= e.at && (x.kind === "repair" || x.kind === "quarantine") && !x.undone && x.path)
      .map((x) => x.path as string),
  );
  return (e.items ?? []).filter((i) => !dealt.has(i.path) && !state.quick.handled.has(i.path));
}

/** "Tệp tìm thấy": every file the quick scan found, each one press from its own result. */
function hitsCard(): string {
  if (state.quick.running) return "";
  type HitRow = { tone: Tone; name: string; sub: string; action: string };
  const folder = (p: string) => shortFolder(p.slice(0, Math.max(0, p.length - baseName(p).length)));
  let rows: HitRow[] = [];
  const current = remainingHits();
  if (current.length) {
    rows = current.map((r, i) => ({
      tone: tone(r),
      name: r.name,
      sub: [r.hash_only ? t("status.hash") : familyName(topFinding(r)?.family ?? ""), folder(r.path)].filter(Boolean).join(" · "),
      action: `<button class="link" data-action="hit-open" data-path="${esc(r.path)}" data-fid="hit-${i}">${esc(t("hits.open"))}<span class="sr-only"> ${esc(r.name)}</span></button>`,
    }));
  }
  // Files earlier scans found (a folder scan does not clear what the quick scan saw elsewhere).
  const listed = new Set(current.map((r) => r.path));
  const older = pendingItems().filter((p) => !listed.has(p.item.path));
  rows = rows.concat(
    older.map(({ entry, item: it }, i) => ({
      tone: it.hash_only ? "warn" : verdictTone(it.verdict),
      name: it.name,
      sub: [it.hash_only ? t("status.hash") : it.family ? familyName(it.family) : "", folder(it.path)].filter(Boolean).join(" · "),
      action: `<button class="link" data-action="hit-recheck" data-entry="${esc(entry.id)}" data-path="${esc(it.path)}" data-fid="hit-old-${i}">${esc(t("hits.recheck"))}<span class="sr-only"> ${esc(it.name)}</span></button>`,
    })),
  );
  if (!rows.length) return "";
  const shown = state.hitsAll ? rows : rows.slice(0, HIT_ROWS);
  const list = shown
    .map((r) => `<li class="row">${icon(r.tone)}<div class="row-text"><div class="row-name">${esc(r.name)}</div><div class="row-sub">${esc(r.sub)}</div></div>${r.action}</li>`)
    .join("");
  const more =
    rows.length > HIT_ROWS
      ? `<button class="link quiet" data-action="hits-all" data-fid="hits-all">${esc(state.hitsAll ? t("history.less") : t("history.more", { n: rows.length }))}</button>`
      : "";
  return `<section class="card hits" aria-labelledby="hits-title">
    <h2 class="overline" id="hits-title">${esc(t("hits.title", { n: rows.length }))}</h2>
    <ul class="rows">${list}</ul>${more}
  </section>`;
}

type Row = { at: number; tone: Tone; name: string; sub: string; undo?: Undo; undoLabel?: string; undone?: boolean };

function historyRows(): Row[] {
  const h = state.history;
  if (!h) return [];
  const rows: Row[] = h.entries.map((e) => {
    const when = fmtWhen(e.at);
    const fam = e.family ? familyName(e.family) : "";
    switch (e.kind) {
      case "repair":
        return {
          at: e.at,
          tone: e.undone ? "soon" : "ok",
          name: e.name,
          sub: [t("history.repaired"), fam, when].filter(Boolean).join(" · "),
          undo: e.can_undo ? e.undo : undefined,
          undoLabel: t("history.undo"),
          undone: e.undone,
        };
      case "fix":
        return {
          at: e.at,
          tone: e.undone ? "soon" : "ok",
          name: fixName(e.family ?? ""),
          sub: [t("history.fixed"), when].join(" · "),
          undo: e.can_undo ? e.undo : undefined,
          undoLabel: t("history.undo"),
          undone: e.undone,
        };
      case "startup_off":
        return {
          at: e.at,
          tone: e.undone ? "soon" : "ok",
          name: e.name,
          sub: [t("history.startup_off"), when].join(" · "),
          undo: e.can_undo ? e.undo : undefined,
          undoLabel: t("history.undo"),
          undone: e.undone,
        };
      case "quarantine":
        return {
          at: e.at,
          tone: e.undone ? "soon" : "bad",
          name: e.name,
          sub: [t("history.quarantined"), fam, when].filter(Boolean).join(" · "),
          undo: e.can_undo ? e.undo : undefined,
          undoLabel: t("history.restore"),
          undone: e.undone,
        };
      case "quick_scan": {
        const hits = e.hits ?? 0;
        return {
          at: e.at,
          tone: hits ? verdictTone(e.verdict) : e.stopped ? "warn" : "ok",
          name:
            entryScope(e) === "full"
              ? t("history.full")
              : entryScope(e) === "folder"
                ? t("history.folder", { folder: shortFolder(e.path ?? "") })
                : t("history.quick"),
          sub: `${t(hits ? "history.quick.hits" : e.stopped ? "history.quick.stopped" : "history.quick.safe", { files: nf(e.files ?? 0), hits })} · ${when}`,
        };
      }
      default:
        return {
          at: e.at,
          tone: verdictTone(e.verdict),
          name: e.name,
          sub: [e.verdict ? (e.verdict === "malware" ? t("status.malware") : t("status.suspicious")) : t("status.safe"), fam, when]
            .filter(Boolean)
            .join(" · "),
        };
    }
  });
  for (const i of h.other_quarantine)
    rows.push({
      at: i.quarantined_at,
      tone: "bad",
      name: baseName(i.original_path),
      sub: [t("history.quarantined"), i.reason ? familyName(i.reason) : "", fmtWhen(i.quarantined_at)].filter(Boolean).join(" · "),
      undo: { type: "quarantine", id: i.id },
      undoLabel: t("history.restore"),
    });
  return rows.sort((a, b) => b.at - a.at);
}

function fixName(id: string): string {
  const key = `fix.${id}`;
  const s = t(key);
  return s === key ? id : s;
}

function historyCard(): string {
  const rows = historyRows();
  const shown = state.historyAll ? rows : rows.slice(0, HISTORY_ROWS);
  const list = shown
    .map((r, i) => {
      const act = r.undo
        ? `<button class="link with-icon" data-action="undo" data-type="${r.undo.type}" data-id="${esc(r.undo.id)}" data-fid="undo-${i}">${line("undo-2", 16)}${esc(r.undoLabel ?? "")}<span class="sr-only"> ${esc(r.name)}</span></button>`
        : r.undone
          ? `<span class="muted caption">${esc(t("history.undone"))}</span>`
          : "";
      return `<li class="row">${icon(r.tone)}<div class="row-text"><div class="row-name">${esc(r.name)}</div><div class="row-sub">${esc(r.sub)}</div></div>${act}</li>`;
    })
    .join("");
  const more =
    rows.length > HISTORY_ROWS
      ? `<button class="link quiet" data-action="history-all" data-fid="history-all">${esc(state.historyAll ? t("history.less") : t("history.more", { n: rows.length }))}</button>`
      : "";
  return `<section class="card history" aria-labelledby="history-title">
    <h2 class="overline" id="history-title">${esc(t("history.title"))}</h2>
    ${list ? `<ul class="rows">${list}</ul>${more}` : `<p class="empty">${esc(t("history.empty"))}</p>`}
  </section>`;
}

function noticeBlock(): string {
  const n = state.notice;
  return n ? `<div class="notice ${n.tone}" role="status">${icon(n.tone)}<span>${esc(n.text)}</span></div>` : "";
}

function overview(): string {
  return `<h1 tabindex="-1">${esc(t("overview.title"))}</h1>
    ${noticeBlock()}
    ${band()}
    ${hitsCard()}
    ${historyCard()}
    <p class="hint">${esc(t("hint.drop"))}</p>`;
}

// ---------- Kiểm tra tệp

function dropZone(): string {
  return `<section class="drop${state.dragOver ? " over" : ""}" aria-labelledby="drop-title">
    <h2 id="drop-title">${esc(state.dragOver ? t("scan.drop.release") : t("scan.drop.title"))}</h2>
    <p>${esc(t("scan.drop.hint"))}</p>
    <button class="link" data-action="pick" data-fid="pick">${esc(t("scan.drop.pick"))}</button>
  </section>`;
}

function safeResult(r: ScanResult): string {
  const rep = r.report;
  const checked: string[] = [];
  if (rep.allowed) checked.push(t("result.safe.allowed"));
  if (rep.kind === "other") checked.push(t("result.safe.not_office"));
  else checked.push(rep.vba_modules.length ? t("result.safe.macro_quiet") : t("result.safe.no_macro"));
  checked.push(t("result.safe.no_match", { version: state.rules?.version ?? "" }));
  return `<section class="card hero result" aria-labelledby="res-title">
    ${icon("ok")}
    <div class="result-body">
      <div class="result-head">
        <span class="status-word ok">${esc(t("status.safe"))}</span>
        <h2 id="res-title">${esc(t("result.safe.title"))}</h2>
        <p>${esc(r.name)} · ${fmtSize(r.size)}</p>
      </div>
      <div><h3 class="overline">${esc(t("result.safe.checked"))}</h3>
        <ul class="bullets ok">${checked.map((c) => `<li>${esc(c)}</li>`).join("")}</ul></div>
      <div class="actions">
        <button class="btn" data-action="reveal" data-path="${esc(r.path)}" data-fid="reveal">${esc(t("result.reveal"))}</button>
        <button class="link" data-action="pick" data-fid="again">${esc(t("result.again"))}</button>
      </div>
    </div>
  </section>`;
}

function detailsPanel(r: ScanResult): string {
  const rep = r.report;
  const findings = rep.findings
    .map(
      (f) => `<dt>${esc(t("details.rule"))}</dt><dd class="mono">${esc(f.rule)}</dd>
        <dt>${esc(t("details.family"))}</dt><dd>${esc(f.family)} · ${esc(t(`severity.${f.severity}`))}</dd>`,
    )
    .join("");
  const modules = rep.vba_modules.length
    ? rep.vba_modules.map((m) => `${esc(m.name)} (${fmtSize(m.bytes)})`).join(", ")
    : esc(t("details.modules.none"));
  const act = state.act;
  const extra =
    act.s === "refused" || act.s === "failed"
      ? `<dt>Genra</dt><dd class="mono">${esc(act.f.detail)}</dd>`
      : act.s === "not_done"
        ? act.v.report.steps
            .filter((x) => x.error)
            .map((x) => `<dt>Genra</dt><dd class="mono">${esc(tr(x.title_vi, x.title_en))}: ${esc(x.error ?? "")}</dd>`)
            .join("")
        : "";
  return `<section class="card inset" id="details" aria-labelledby="details-title">
    <h3 class="overline" id="details-title">${esc(t("details.title"))}</h3>
    <dl class="details">
      ${findings}
      <dt>${esc(t("details.modules"))}</dt><dd>${modules}</dd>
      <dt>${esc(t("details.kind"))}</dt><dd>${esc(t(`kind.${rep.kind}`))}</dd>
      <dt>${esc(t("details.sha256"))}</dt><dd class="mono">${esc(rep.sha256)}</dd>
      ${extra}
    </dl>
  </section>`;
}

function reportPanel(): string {
  const rp = state.report;
  if (rp.status === "done") return `<div class="notice ok" role="status">${icon("ok")}<span>${esc(t("report.done"))}</span></div>`;
  if (!rp.open) return "";
  const sending = rp.status === "sending";
  return `<section class="card inset report" aria-labelledby="report-title">
    <h3 class="overline" id="report-title">${esc(t("report.title"))}</h3>
    <p class="muted caption" style="margin:0 0 10px">${esc(t("report.privacy"))}</p>
    <label for="report-note">${esc(t("report.note"))}</label>
    <textarea id="report-note" data-fid="report-note" maxlength="2000" placeholder="${esc(t("report.note.placeholder"))}">${esc(rp.note)}</textarea>
    ${rp.status === "error" ? `<div class="notice warn" role="alert">${icon("warn")}<span>${esc(t("report.error", { detail: rp.error }))}</span></div>` : ""}
    <div class="actions" style="margin-top:10px">
      <button class="btn" data-action="report-send" data-fid="report-send"${sending ? " disabled" : ""}>${esc(sending ? t("report.sending") : t("report.send"))}</button>
      <button class="link" data-action="report-cancel" data-fid="report-cancel">${esc(t("report.cancel"))}</button>
    </div>
  </section>`;
}

function threatTitle(r: ScanResult): string {
  if (r.hash_only) return t("result.hash.title");
  if (r.report.verdict !== "malware") return t("result.suspicious.title");
  const fam = topFinding(r)?.family ?? "";
  const key = `result.title.${fam}`;
  const s = t(key);
  return s === key ? t("result.malware.title") : s;
}

function threatBullets(r: ScanResult): string[] {
  const fam = topFinding(r)?.family ?? "";
  const plain = [1, 2, 3].map((i) => `result.does.${fam}.${i}`).filter((k) => t(k) !== k);
  if (!r.hash_only && r.report.verdict === "malware" && plain.length) return plain.map((k) => t(k));
  if (r.hash_only) return [t("result.hash.text")];
  return [...new Set(r.report.findings.filter((f) => f.severity !== "info").map((f) => tr(f.message_vi, f.message_en)))];
}

function threatResult(r: ScanResult): string {
  const tn = tone(r);
  const a = state.act;
  const working = a.s === "working";
  const quarantineOnly = r.hash_only || a.s === "refused";
  const step = (txt: string, soon = false) =>
    `<li>${line("chevron-right", 14)}<span>${esc(txt)}${soon ? ` <span class="soon-tag">${esc(t("soon"))}</span>` : ""}</span></li>`;
  const plan = quarantineOnly
    ? step(t("result.plan.quarantine"))
    : step(t("result.plan.replace")) + step(t("result.plan.machine")) + step(t("result.plan.verify"));
  let status = "";
  if (working && a.what === "clean") status = progressBlock();
  if (a.s === "refused")
    status = `<div class="card inset warn-inset" role="alert"><h3>${esc(t("refused.title"))}</h3><p>${esc(t(`refused.${a.f.code}`))}</p><p class="muted">${esc(t("refused.kept"))}</p></div>`;
  else if (a.s === "not_done")
    status = `<div class="card inset warn-inset" role="alert"><h3>${esc(tr(a.v.report.title_vi, a.v.report.title_en))}</h3><p>${esc(
      tr(a.v.report.detail_vi, a.v.report.detail_en),
    )}</p></div>`;
  else if (a.s === "failed")
    status = `<div class="notice warn" role="alert">${icon("warn")}<span><strong>${esc(t("failed.title"))}.</strong> ${esc(
      a.f.code === "not_allowed" ? t("scan.error.not_allowed") : t("failed.text", { detail: a.f.detail }),
    )}</span></div>`;
  const primary = quarantineOnly
    ? `<button class="btn primary" data-action="quarantine" data-fid="quarantine"${working ? " disabled" : ""}>${esc(
        working ? t("result.quarantining") : t("result.quarantine"),
      )}</button>`
    : `<button class="btn primary" data-action="clean" data-fid="clean"${working ? " disabled" : ""}>${esc(
        working ? t("result.cleaning") : t("result.clean"),
      )}</button>`;
  return `<section class="card hero result ${tn === "bad" ? "danger" : "warning"}" aria-labelledby="res-title">
    ${icon(tn)}
    <div class="result-body">
      <div class="result-head">
        <span class="status-word ${tn}">${esc(statusWord(r))}</span>
        <h2 id="res-title">${esc(threatTitle(r))}</h2>
        <p>${esc(r.name)} · ${fmtSize(r.size)}</p>
      </div>
      <div><h3 class="overline">${esc(t(r.report.verdict === "malware" && !r.hash_only ? "result.what" : "result.why"))}</h3>
        <ul class="bullets ${tn}">${threatBullets(r).map((m) => `<li>${esc(m)}</li>`).join("")}</ul></div>
      ${tn === "warn" && !r.hash_only ? `<p class="flat">${esc(t("result.suspicious.advice"))}</p>` : ""}
      ${status || `<div class="card inset plan"><h3 class="overline">${esc(t("result.plan"))}</h3><ul class="steps">${plan}</ul></div>`}
      <div class="actions">
        ${primary}
        <button class="link" data-action="details" data-fid="details" aria-expanded="${state.details}" aria-controls="details">${esc(
          t(state.details ? "result.details.hide" : "result.details"),
        )}</button>
        ${
          state.report.status === "done"
            ? ""
            : `<button class="link quiet push" data-action="report-open" data-fid="report-open" aria-expanded="${state.report.open}">${esc(t("result.report"))}</button>`
        }
      </div>
      ${state.details ? detailsPanel(r) : ""}
      ${reportPanel()}
    </div>
  </section>`;
}

function progressBlock(): string {
  const p = state.repairProgress;
  const text =
    p?.phase === "step" && p.step
      ? t("repair.step", { n: p.step.index + 1, total: p.step.total, title: tr(p.step.title_vi, p.step.title_en) })
      : t("repair.planning");
  return `<div class="card inset plan" role="status"><div class="notice"><div class="spinner" aria-hidden="true"></div><span>${esc(text)}</span></div></div>`;
}

function removedWords(removed: string[]): string {
  return removed.some((x) => x.toLowerCase().includes("vba") || x.toLowerCase().includes("macro") || x.toLowerCase().includes("module"))
    ? t("done.macros")
    : removed.length
      ? removed.join(", ")
      : t("done.macros");
}

function doneResult(a: Extract<Act, { s: "repaired" }>): string {
  const d = a.done;
  const item = (tn: Tone, title: string, detail: string) =>
    `<li>${icon(tn)}<div><div class="step-title">${esc(title)}</div><div class="row-sub">${esc(detail)}</div></div></li>`;
  const items: string[] = [];
  if (d.xlstart.length) items.push(item("ok", t("done.xlstart"), t("done.xlstart.detail", { names: d.xlstart.join(", ") })));
  if (d.cleaned.length === 1) {
    const c = d.cleaned[0];
    items.push(
      item(
        "ok",
        t("done.clean", { name: c.name }),
        c.renamed ? t("done.clean.renamed", { removed: removedWords(c.removed), clean: c.clean_name }) : t("done.clean.inplace", { removed: removedWords(c.removed) }),
      ),
    );
  } else if (d.cleaned.length > 1) {
    items.push(item("ok", t("done.clean.many", { n: d.cleaned.length }), t("done.clean.many.detail", { name: d.cleaned[0].name, more: d.cleaned.length - 1 })));
  }
  items.push(item("ok", t("done.quarantine"), t("done.quarantine.detail")));
  if (d.verified) items.push(item("ok", t("done.verify"), t("done.verify.detail")));
  const machine = d.xlstart.length > 0;
  const first = d.cleaned[0];
  return `<section class="card hero result" aria-labelledby="res-title">
    ${icon("ok")}
    <div class="result-body">
      <div class="result-head">
        <h2 id="res-title">${esc(t(machine ? "done.title.machine" : "done.title"))}</h2>
        <p>${esc(t(machine ? "done.text.machine" : "done.text"))}</p>
      </div>
      <ul class="done-steps" data-fid="done-steps">${items.join("")}</ul>
      <div class="card inset tell">${line("message-square")}<span>${esc(t("done.tell"))}</span></div>
      ${a.error ? `<div class="notice warn" role="alert">${icon("warn")}<span>${esc(a.error)}</span></div>` : ""}
      <div class="actions">
        ${first ? `<button class="btn primary" data-action="reveal" data-path="${esc(first.clean_path)}" data-fid="reveal-clean">${esc(t("result.reveal"))}</button>` : ""}
        <button class="link with-icon" data-action="undo-repair" data-fid="undo-repair"${a.undoing ? " disabled" : ""}>${line("undo-2", 18)}${esc(t("done.undo"))}</button>
      </div>
    </div>
  </section>`;
}

/** Mock 4: Excel holds what the repair must change. Nothing has changed yet. */
function excelResult(a: Extract<Act, { s: "excel" }>): string {
  const docs = a.v.open_documents;
  const lines = [
    docs.length ? t("excel.open", { n: docs.length, names: docs.join(", ") }) : t("excel.running"),
    t("excel.ask"),
    t("excel.never"),
  ];
  const waiting = a.continuing ? t("excel.continuing") : a.asked === "genra" ? t("excel.asked") : a.asked === "self" ? t("excel.self") : "";
  return `<section class="card hero result" aria-labelledby="res-title">
    <span class="excel-mark">${line("file-spreadsheet", 40)}</span>
    <div class="result-body">
      <div class="result-head"><h2 id="res-title">${esc(t("excel.title"))}</h2>${lines.map((x) => `<p>${esc(x)}</p>`).join("")}</div>
      <div class="card inset tell ok-tell">${icon("ok")}<span>${esc(t("excel.promise"))}</span></div>
      ${a.continuing ? progressBlock() : waiting ? `<div class="notice" role="status"><div class="spinner" aria-hidden="true"></div><span>${esc(waiting)}</span></div>` : ""}
      ${a.error ? `<div class="notice warn" role="alert">${icon("warn")}<span>${esc(a.error)}</span></div>` : ""}
      <div class="actions">
        <button class="btn primary" data-action="close-excel" data-fid="close-excel"${a.asked === "genra" || a.continuing ? " disabled" : ""}>${esc(t("excel.close"))}</button>
        <button class="btn" data-action="excel-self" data-fid="excel-self"${a.asked !== "none" || a.continuing ? " disabled" : ""}>${esc(t("excel.later"))}</button>
      </div>
    </div>
  </section>`;
}

function quarantinedResult(q: api.Quarantined): string {
  return `<section class="card hero result" aria-labelledby="res-title">
    ${icon("ok")}
    <div class="result-body">
      <div class="result-head"><h2 id="res-title">${esc(t("quarantined.title"))}</h2><p>${esc(t("quarantined.text", { name: q.name }))}</p></div>
      <div class="actions">
        <button class="btn primary" data-action="pick" data-fid="again">${esc(t("result.again"))}</button>
        <button class="link with-icon" data-action="undo" data-type="quarantine" data-id="${esc(q.id)}" data-fid="undo-q">${line("undo-2", 18)}${esc(t("history.restore"))}</button>
      </div>
    </div>
  </section>`;
}

function scanPage(): string {
  const s = state.scan;
  const a = state.act;
  let body = "";
  let showDrop = true;
  if (a.s === "repaired") {
    body = doneResult(a);
    showDrop = false;
  } else if (a.s === "excel") {
    body = excelResult(a);
    showDrop = false;
  } else if (a.s === "quarantined") {
    body = quarantinedResult(a.q);
    showDrop = false;
  } else if (s.status === "busy") {
    body = s.slow
      ? `<section class="card hero result info">${line("lock", 40)}<div class="result-body"><div class="result-head"><h2>${esc(t("scan.waiting"))}</h2><p>${esc(
          t("scan.waiting.hint"),
        )}</p></div><div class="notice"><div class="spinner" aria-hidden="true"></div><span>${esc(t("scan.busy", { name: s.name }))}</span></div></div></section>`
      : `<section class="card hero"><div class="notice"><div class="spinner" aria-hidden="true"></div><span>${esc(t("scan.busy", { name: s.name }))}</span></div></section>`;
  } else if (s.status === "error") {
    const known = ["too_large", "not_a_file", "not_allowed"];
    const msg = known.includes(s.code) ? t(`scan.error.${s.code}`) : t("scan.error.other", { detail: s.detail });
    body = `<section class="card hero result warning" aria-labelledby="res-title">${icon("warn")}
      <div class="result-body"><div class="result-head"><h2 id="res-title">${esc(t("scan.error.title"))}</h2><p>${esc(msg)}</p></div></div></section>`;
  } else if (s.status === "done") {
    if (isThreat(s.result)) {
      body = threatResult(s.result);
      showDrop = false;
    } else body = safeResult(s.result);
  }
  return `<h1 tabindex="-1">${esc(t("scan.title"))}</h1>
    ${noticeBlock()}
    <div class="stack">${showDrop ? dropZone() : ""}<div role="status" aria-live="polite">${body}</div></div>`;
}

// ---------- Máy của bạn (mock 6)

const healthTone = (st: api.HealthStatus): Tone => (st === "unknown" ? "soon" : st);
const verdictToneOf = (v: api.StartupItem["verdict"]): Tone => (v === "unknown" ? "soon" : v);
/** Health items that need the user and have a one-press fix: shown first, as in mock 6. */
const attention = (m: api.MachineOverview) => m.health.filter((h) => h.fix && (h.status === "warn" || h.status === "bad"));

function skeletonRows(n: number): string {
  return Array.from({ length: n }, () => `<li class="row skel-row" aria-hidden="true"><span class="skel dot"></span><div class="row-text"><span class="skel bar"></span><span class="skel bar short"></span></div><span></span></li>`).join("");
}

function startupRow(s: api.StartupItem, i: number): string {
  const who = [s.publisher, s.signed === true ? t("machine.signed") : s.signed === false ? t("machine.unsigned") : ""].filter(Boolean).join(" · ");
  const busy = state.machineBusy === s.id;
  const off = s.can_disable
    ? `<button class="link" data-action="startup-off" data-id="${esc(s.id)}" data-fid="startup-off-${i}"${busy || state.machineBusy ? " disabled" : ""}>${esc(busy ? t("machine.off.busy") : t("machine.off"))}<span class="sr-only"> ${esc(s.name)}</span></button>`
    : "";
  return `<li class="row startup">${icon(verdictToneOf(s.verdict))}<div class="row-text">
      <div class="row-name">${esc(s.name)} <span class="muted loc" title="${esc(s.location)}">(${esc(shortFolder(s.location))})</span></div>
      <div class="row-sub">${esc([who, tr(s.reason_vi, s.reason_en)].filter(Boolean).join(" · "))}</div>
      <div class="row-sub mono cmd" title="${esc(s.command)}">${esc(s.command)}</div>
    </div>${off}</li>`;
}

function machinePage(): string {
  const m = state.machine;
  const r = state.rules;
  const row = (tn: Tone, name: string, detail: string, right = "") =>
    `<li class="row">${icon(tn)}<div class="row-text"><div class="row-name">${esc(name)}</div><div class="row-sub">${esc(detail)}</div></div>${right}</li>`;
  const rulesDetail = r
    ? r.source === "installed"
      ? t("machine.rules.installed", { version: r.version, hashes: nf(r.hashes), when: r.last_ok ? relTime(r.last_ok) : "—" })
      : t("machine.rules.bundled", { version: r.version })
    : "";
  const loading = !m && (state.machineLoading || !state.machineError);
  const todo = m ? attention(m).length + m.startup.filter((s) => s.can_disable).length : 0;
  const sub = loading ? t("machine.loading") : m ? (todo ? t("machine.sub.todo", { n: todo }) : t("machine.sub.ok")) : t("machine.error", { detail: state.machineError });

  const cards = m
    ? attention(m)
        .map((h) => {
          const busy = state.machineBusy === h.fix;
          return `<section class="card warning attention" aria-labelledby="fix-${esc(h.id)}">${icon(healthTone(h.status))}
          <div class="row-text"><h2 class="attention-title" id="fix-${esc(h.id)}">${esc(tr(h.title_vi, h.title_en))}</h2><p>${esc(tr(h.detail_vi, h.detail_en))}</p></div>
          <button class="btn primary" data-action="fix" data-fix="${esc(h.fix ?? "")}" data-fid="fix-${esc(h.id)}"${state.machineBusy ? " disabled" : ""}>${esc(busy ? t("machine.fix.busy") : t("machine.fix"))}</button></section>`;
        })
        .join("")
    : "";
  const health = m
    ? m.health
        .filter((h) => !attention(m).includes(h))
        .map((h) => row(healthTone(h.status), tr(h.title_vi, h.title_en), tr(h.detail_vi, h.detail_en)))
        .join("")
    : loading
      ? skeletonRows(3)
      : "";

  let startup = "";
  if (m) {
    const items = m.startup;
    const needs = items.filter((s) => s.verdict !== "ok");
    const fine = items.filter((s) => s.verdict === "ok");
    const shown = state.startupAll ? items : needs;
    const list = shown.map((s, i) => startupRow(s, i)).join("");
    const more = fine.length
      ? `<button class="link quiet" data-action="startup-all" data-fid="startup-all">${esc(state.startupAll ? t("machine.startup.less") : t("machine.startup.more", { n: fine.length }))}</button>`
      : "";
    startup = items.length
      ? `${list ? `<ul class="rows">${list}</ul>` : `<p class="empty">${esc(t("machine.startup.fine", { n: fine.length }))}</p>`}${more}`
      : `<p class="empty">${esc(t("machine.startup.empty"))}</p>`;
  } else if (loading) startup = `<ul class="rows">${skeletonRows(3)}</ul>`;

  const guardIcon: Record<api.GuardPlace["kind"], string> = { downloads: "folder", zalo: "message-square", usb: "hard-drive" };
  const places: api.GuardPlace[] = m?.guard ?? [
    { kind: "downloads", paths: [] },
    { kind: "zalo", paths: [] },
    { kind: "usb", paths: [] },
  ];
  const guard = places
    .map((g) => {
      const where = g.kind === "usb"
        ? g.paths.length
          ? t("machine.guard.usb.now", { names: g.paths.map(baseName).join(", ") })
          : t("machine.guard.usb.none")
        : g.paths.length
          ? shortFolder(g.paths[0])
          : m
            ? t("machine.guard.missing")
            : "";
      return `<li class="row">${line(guardIcon[g.kind], 18)}<div class="row-text"><div class="row-name">${esc(t(`machine.guard.${g.kind}`))}</div><div class="row-sub">${esc(
        [t("machine.guard.detail"), where].filter(Boolean).join(" · "),
      )}</div></div><span class="status-word soon">${esc(t("machine.guard.soon"))}</span></li>`;
    })
    .join("");

  const n = state.machineNotice;
  const notice = n
    ? `<div class="notice ${n.tone}" role="status">${icon(n.tone)}<span>${esc(n.text)}</span>${
        n.undo ? `<button class="link with-icon" data-action="undo" data-type="${n.undo.type}" data-id="${esc(n.undo.id)}" data-fid="machine-undo">${line("undo-2", 16)}${esc(t("history.undo"))}</button>` : ""
      }</div>`
    : "";
  return `<h1 tabindex="-1">${esc(t("machine.title"))}</h1>
    <p class="page-sub" aria-live="polite">${esc(sub)}</p>
    ${notice}
    <div class="stack">
      ${cards}
      <section class="card" aria-labelledby="m-health" aria-busy="${loading}"><h2 class="overline" id="m-health">${esc(t("machine.health"))}</h2>
        <ul class="rows">${row(r?.source === "installed" ? "ok" : "warn", t("machine.rules"), rulesDetail)}${health}</ul></section>
      <section class="card" aria-labelledby="m-startup" aria-busy="${loading}"><h2 class="overline" id="m-startup">${esc(t("machine.startup"))}</h2>${startup}</section>
      <section class="card" aria-labelledby="m-guard"><h2 class="overline" id="m-guard">${esc(t("machine.guard"))}</h2>
        <ul class="rows">${guard}</ul></section>
    </div>`;
}

// ---------- Cài đặt

function settingsPage(): string {
  const radio = (name: string, value: string, label: string, checked: boolean) =>
    `<label class="choice"><input type="radio" name="${name}" value="${value}" data-fid="${name}-${value}"${checked ? " checked" : ""}><span>${esc(label)}</span></label>`;
  const r = state.rules;
  const checked = r?.last_try
    ? `${relTime(r.last_try)}${r.last_error ? ` · ${t("settings.rules.checked.failed")}` : ""}`
    : t("settings.rules.checked.never");
  const link = (which: string, label: string) =>
    `<button class="link with-icon" data-action="link" data-which="${which}" data-fid="link-${which}">${esc(label)}${line("external-link", 14)}</button>`;
  return `<h1 tabindex="-1">${esc(t("settings.title"))}</h1>
    <div class="stack">
      <section class="card"><fieldset><legend>${esc(t("settings.theme"))}</legend><div class="choices">
        ${(["system", "light", "dark"] as Theme[]).map((v) => radio("theme", v, t(`settings.theme.${v}`), state.theme === v)).join("")}
      </div></fieldset></section>
      <section class="card"><fieldset><legend>${esc(t("settings.lang"))}</legend><div class="choices">
        ${radio("lang", "vi", "Tiếng Việt", getLang() === "vi")}${radio("lang", "en", "English", getLang() === "en")}
      </div></fieldset></section>
      <section class="card"><h3>${esc(t("settings.privacy"))}</h3><p class="flat">${esc(t("settings.privacy.text"))}</p>
        <label class="toggle"><input type="checkbox" name="send_hashes" data-fid="send-hashes"${state.settings.send_hashes ? " checked" : ""}>
          <span class="switch" aria-hidden="true"></span>
          <span><span class="toggle-title">${esc(t("settings.send_hashes"))}</span><span class="row-sub">${esc(t("settings.send_hashes.text"))}</span></span></label>
        <div class="install-id">
          <div class="row-text"><span class="toggle-title" id="install-id-label">${esc(t("settings.install_id"))}</span>
            <code class="mono" aria-labelledby="install-id-label" data-fid="install-id">${esc(state.installId || "—")}</code>
            <span class="row-sub">${esc(t("settings.install_id.text"))}</span></div>
          <button class="btn with-icon" data-action="copy-id" data-fid="copy-id"${state.installId ? "" : " disabled"}>${line("copy", 16)}${esc(
            state.copied ? t("settings.install_id.copied") : t("settings.install_id.copy"),
          )}</button>
        </div>
      </section>
      <section class="card"><h3>${esc(t("settings.rules"))}</h3>
        ${
          r
            ? `<dl class="details">
          <dt>${esc(t("settings.rules.version"))}</dt><dd>${r.version} · ${r.rules}</dd>
          <dt>${esc(t("settings.rules.source"))}</dt><dd>${esc(t(`settings.rules.source.${r.source}`))}</dd>
          <dt>${esc(t("settings.rules.published"))}</dt><dd>${esc(isNaN(Date.parse(r.published)) ? r.published : fmtWhen(Date.parse(r.published) / 1000))}</dd>
          ${r.expires ? `<dt>${esc(t("settings.rules.expires"))}</dt><dd>${esc(fmtDate(r.expires))}</dd>` : ""}
          <dt>${esc(t("settings.rules.hashes"))}</dt><dd>${nf(r.hashes)}</dd>
          <dt>${esc(t("settings.rules.checked"))}</dt><dd>${esc(checked)}</dd>
        </dl>`
            : ""
        }
      </section>
      <section class="card"><h3>${esc(t("settings.about"))}</h3><p class="muted flat">${esc(t("settings.about.text", { app: state.appVersion }))}</p>
        ${
          state.update
            ? `<div class="update-row"><span class="row-text"><span class="toggle-title">${esc(t("update.available", { version: state.update.version }))}</span>
            <span class="row-sub">${esc(state.updating === "error" ? t("update.failed") : t("update.text"))}</span></span>
            <button class="btn primary" data-action="install-update" data-fid="install-update"${state.updating === "busy" ? " disabled" : ""}>${esc(
              state.updating === "busy" ? t("update.installing") : t("update.install"),
            )}</button></div>`
            : ""
        }
        <div class="actions links">${link("privacy", t("settings.privacy_link"))}${link("terms", t("settings.terms_link"))}${link("source", t("settings.source_link"))}</div>
      </section>
    </div>`;
}

function page(): string {
  switch (state.page) {
    case "overview":
      return overview();
    case "scan":
      return scanPage();
    case "machine":
      return machinePage();
    case "settings":
      return settingsPage();
  }
}

// ---------- render (keeps keyboard focus across re-renders by data-fid)

const root = document.getElementById("app")!;

function render(focusHeading = false) {
  const active = document.activeElement as HTMLElement | null;
  const fid = active?.dataset?.fid;
  // A mouse click should not leave a keyboard focus ring behind after the re-render.
  const ring = !!active?.matches(":focus-visible");
  const scrollTop = root.querySelector(".main")?.scrollTop ?? 0;
  root.innerHTML = `<div class="shell">${sidebar()}<main class="main"><div class="page">${page()}</div></main></div>`;
  const main = root.querySelector<HTMLElement>(".main")!;
  if (focusHeading) {
    main.scrollTop = 0;
    root.querySelector<HTMLElement>("h1")?.focus();
  } else {
    main.scrollTop = scrollTop;
    if (fid) root.querySelector<HTMLElement>(`[data-fid="${fid}"]`)?.focus({ preventScroll: true, focusVisible: ring } as FocusOptions);
  }
}

function go(p: Page) {
  state.page = p;
  state.notice = null;
  if (p === "scan" && (state.act.s === "repaired" || state.act.s === "quarantined")) {
    state.act = { s: "idle" };
    state.scan = { status: "idle" };
  }
  if (p === "overview") void refreshHistory();
  if (p === "machine") {
    state.machineNotice = null;
    if (!state.machine && !state.machineLoading) void loadMachine(false);
  }
  render(true);
}

// ---------- actions

async function refreshHistory() {
  try {
    state.history = await api.history();
    render();
  } catch {
    /* the list stays as it was */
  }
}

async function refreshRules() {
  try {
    state.rules = await api.rulesInfo();
    render();
  } catch {
    /* keep the last known */
  }
}

function resetResult() {
  state.act = { s: "idle" };
  state.details = false;
  state.report = { open: false, note: "", status: "idle", error: "" };
  state.notice = null;
}

async function scanPath(path: string) {
  const token = ++scanToken;
  state.page = "scan";
  resetResult();
  state.scan = { status: "busy", name: baseName(path), slow: false, token };
  render(true);
  // Reading a file in Downloads/Desktop/Documents can wait on the macOS permission prompt.
  setTimeout(() => {
    if (state.scan.status === "busy" && state.scan.token === token) {
      state.scan.slow = true;
      render();
    }
  }, PERMISSION_WAIT_MS);
  try {
    const result = await api.scanFile(path);
    if (token !== scanToken) return;
    state.scan = { status: "done", result };
  } catch (e) {
    if (token !== scanToken) return;
    const detail = String(e);
    const code = ["too_large", "not_a_file", "not_allowed"].includes(detail) ? detail : "other";
    state.scan = { status: "error", code, detail };
  }
  render(true);
  void refreshHistory();
}

function showResult(result: ScanResult) {
  resetResult();
  state.scan = { status: "done", result };
  state.page = "scan";
}

async function pick() {
  try {
    const picked = await api.pickFile();
    if (picked) await scanPath(picked);
  } catch (e) {
    state.scan = { status: "error", code: "other", detail: String(e) };
    render();
  }
}

/** Paths a finished repair dealt with, so the band stops listing them. */
function markHandled(v: RepairDone, path: string) {
  state.quick.handled.add(path);
  for (const c of v.cleaned) state.quick.handled.add(c.original_path);
}

function applyRepairView(v: RepairView, path: string) {
  state.repairProgress = null;
  if (v.state === "done") {
    state.act = { s: "repaired", done: v, undoing: false, error: "" };
    markHandled(v, path);
    state.machine = null;
  } else if (v.state === "needs_excel") {
    const prev = state.act.s === "excel" && state.act.v.group_id === v.group_id ? state.act : null;
    state.act = { s: "excel", v, path, asked: prev?.asked ?? "none", continuing: false, error: "" };
    watchExcel();
  } else state.act = { s: "not_done", v };
}

async function clean() {
  const s = state.scan;
  if (s.status !== "done") return;
  const path = s.result.path;
  state.act = { s: "working", what: "clean" };
  state.repairProgress = null;
  render();
  try {
    applyRepairView(await api.repairFile(path), path);
  } catch (e) {
    const f = failureCode(e);
    state.act = f.kind === "refused" ? { s: "refused", f } : { s: "failed", f };
  }
  render(true);
  void refreshHistory();
}

// While a repair waits for Excel: look every second, carry on by itself once Excel is gone (J2).
let excelTimer: number | undefined;
function watchExcel() {
  window.clearInterval(excelTimer);
  excelTimer = window.setInterval(() => void tickExcel(), 1000);
}

async function tickExcel() {
  const a = state.act;
  if (a.s !== "excel") {
    window.clearInterval(excelTimer);
    return;
  }
  if (a.continuing) return;
  let st: api.ExcelStatus;
  try {
    st = await api.excelStatus();
  } catch {
    return;
  }
  if (state.act !== a || st.running) return;
  window.clearInterval(excelTimer);
  a.continuing = true;
  render();
  try {
    applyRepairView(await api.continueRepair(a.v.group_id), a.path);
  } catch (e) {
    state.act = { s: "failed", f: failureCode(e) };
  }
  render(true);
  void refreshHistory();
}

async function closeExcel() {
  const a = state.act;
  if (a.s !== "excel") return;
  a.asked = "genra";
  a.error = "";
  render();
  try {
    await api.closeExcel();
  } catch (e) {
    a.error = t("excel.failed", { detail: String(e) });
    a.asked = "self";
    render();
  }
}

async function loadMachine(refresh: boolean) {
  state.machineLoading = true;
  state.machineError = "";
  if (state.page === "machine") render();
  try {
    state.machine = await api.machineOverview(refresh);
  } catch (e) {
    state.machineError = String(e);
  }
  state.machineLoading = false;
  if (state.page === "machine") render();
}

/** "Sửa giúp tôi" and "Tắt" share this: run, say what happened with its undo, read the machine again. */
async function machineChange(busy: string, run: () => Promise<api.RunReport>, done: string) {
  state.machineBusy = busy;
  state.machineNotice = null;
  render();
  try {
    const r = await run();
    const ok = r.outcome.type === "done";
    const changed = r.steps.some((x) => x.state === "done");
    state.machineNotice = ok
      ? { tone: "ok", text: changed ? done : tr(r.steps[0]?.detail_vi ?? r.detail_vi, r.steps[0]?.detail_en ?? r.detail_en), undo: changed ? { type: "group", id: r.group_id } : undefined }
      : { tone: "warn", text: tr(r.detail_vi, r.detail_en) };
  } catch (e) {
    state.machineNotice = { tone: "warn", text: t("machine.change.failed", { detail: String(e) }) };
  }
  state.machineBusy = "";
  state.machine = null;
  void refreshHistory();
  await loadMachine(true);
}

async function copyInstallId() {
  const id = state.installId;
  if (!id) return;
  try {
    await navigator.clipboard.writeText(id);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = id;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  state.copied = true;
  render();
  setTimeout(() => {
    state.copied = false;
    render();
  }, 2000);
}

async function quarantine() {
  const s = state.scan;
  if (s.status !== "done") return;
  state.act = { s: "working", what: "quarantine" };
  render();
  try {
    const q = await api.quarantineFile(s.result.path);
    state.act = { s: "quarantined", q };
    state.quick.handled.add(s.result.path);
  } catch (e) {
    state.act = { s: "failed", f: failureCode(e) };
  }
  render(true);
  void refreshHistory();
}

async function doUndo(u: Undo) {
  try {
    await api.undo(u);
    state.notice = { tone: "ok", text: t("done.undone") };
    if (state.page === "scan") {
      state.act = { s: "idle" };
      state.scan = { status: "idle" };
    }
    if (state.page === "machine") {
      state.machineNotice = { tone: "ok", text: t("done.undone.machine") };
      state.machine = null;
      void loadMachine(true);
    }
  } catch (e) {
    const f = failureCode(e);
    const text = f.code === "clean_changed" ? t("undo.clean_changed") : t("undo.failed", { detail: f.detail });
    if (state.act.s === "repaired") state.act.error = text;
    else state.notice = { tone: "warn", text };
  }
  if (state.act.s === "repaired") state.act.undoing = false;
  render();
  void refreshHistory();
}

async function startQuick(scope: ScanScope = "quick") {
  if (state.quick.running) return;
  const begin = () => {
    Object.assign(state.quick, { running: true, scope, stopping: false, folder: "", files: 0, waiting: false, error: "" });
    render();
  };
  try {
    if (scope === "folder") {
      // Running from the start, so a tiny folder's "done" cannot arrive before the band switches.
      begin();
      if (!(await api.scanFolder())) {
        state.quick.running = false;
        render();
      }
    } else {
      begin();
      await api.quickScan(scope);
    }
  } catch (e) {
    if (String(e) !== "busy") {
      state.quick.running = false;
      state.quick.error = String(e);
      render();
    }
  }
}

async function sendReport() {
  const s = state.scan;
  if (s.status !== "done") return;
  state.report.status = "sending";
  render();
  try {
    const top = topFinding(s.result);
    await api.reportFalsePositive(s.result.report.sha256, top?.rule ?? null, state.report.note.trim() || null);
    state.report = { open: false, note: "", status: "done", error: "" };
  } catch (e) {
    state.report.status = "error";
    state.report.error = String(e);
  }
  render();
}

root.addEventListener("click", (ev) => {
  const el = (ev.target as HTMLElement).closest<HTMLElement>("[data-action]");
  if (!el || (el as HTMLButtonElement).disabled) return;
  switch (el.dataset.action) {
    case "nav":
      go(el.dataset.page as Page);
      break;
    case "pick":
      void pick();
      break;
    case "reveal":
      if (el.dataset.path) void api.reveal(el.dataset.path);
      break;
    case "details":
      state.details = !state.details;
      render();
      break;
    case "clean":
      void clean();
      break;
    case "quarantine":
      void quarantine();
      break;
    case "undo-repair":
      if (state.act.s === "repaired") {
        state.act.undoing = true;
        render();
        void doUndo({ type: "group", id: state.act.done.group_id });
      }
      break;
    case "undo":
      void doUndo({ type: el.dataset.type as "quarantine" | "group", id: el.dataset.id ?? "" } as Undo);
      break;
    case "quick":
      void startQuick();
      break;
    case "scan-full":
      void startQuick("full");
      break;
    case "scan-folder":
      void startQuick("folder");
      break;
    case "stop-scan":
      state.quick.stopping = true;
      render();
      void api.stopScan();
      break;
    case "close-excel":
      void closeExcel();
      break;
    case "excel-self":
      if (state.act.s === "excel") {
        state.act.asked = "self";
        render();
      }
      break;
    case "fix": {
      const fix = el.dataset.fix ?? "";
      void machineChange(fix, () => api.fixHealth(fix), t("machine.fix.done"));
      break;
    }
    case "startup-off": {
      const id = el.dataset.id ?? "";
      const item = state.machine?.startup.find((x) => x.id === id);
      void machineChange(id, () => api.disableStartup(id), t("machine.off.done", { name: item?.name ?? "" }));
      break;
    }
    case "startup-all":
      state.startupAll = !state.startupAll;
      render();
      break;
    case "copy-id":
      void copyInstallId();
      break;
    case "goto-update":
      state.page = "settings";
      render(true);
      break;
    case "install-update":
      state.updating = "busy";
      render();
      api.installUpdate().catch(() => {
        state.updating = "error";
        render();
      });
      break;
    case "band-clean": {
      const first = remainingHits()[0];
      if (first) {
        showResult(first);
        render(true);
        void clean();
      }
      break;
    }
    case "band-look": {
      const first = remainingHits()[0];
      if (first) {
        showResult(first);
        render(true);
      }
      break;
    }
    case "hit-open": {
      const hit = remainingHits().find((h) => h.path === el.dataset.path);
      if (hit) {
        showResult(hit);
        render(true);
      }
      break;
    }
    case "hit-recheck": {
      const path = el.dataset.path ?? "";
      api
        .recheckHit(el.dataset.entry ?? "", path)
        .then(() => scanPath(path))
        .catch((e) => {
          state.scan = { status: "error", code: "other", detail: String(e) };
          state.page = "scan";
          render(true);
        });
      break;
    }
    case "hits-all":
      state.hitsAll = !state.hitsAll;
      render();
      break;
    case "history-all":
      state.historyAll = !state.historyAll;
      render();
      break;
    case "link":
      void api.openLink(el.dataset.which as "privacy" | "terms" | "source");
      break;
    case "report-open":
      state.report.open = !state.report.open;
      render();
      if (state.report.open) root.querySelector<HTMLElement>("#report-note")?.focus();
      break;
    case "report-cancel":
      state.report = { open: false, note: "", status: "idle", error: "" };
      render();
      root.querySelector<HTMLElement>('[data-fid="report-open"]')?.focus();
      break;
    case "report-send":
      void sendReport();
      break;
  }
});

root.addEventListener("input", (ev) => {
  const el = ev.target as HTMLTextAreaElement;
  if (el.id === "report-note") state.report.note = el.value;
});

root.addEventListener("change", (ev) => {
  const el = ev.target as HTMLInputElement;
  if (el.name === "theme") {
    state.theme = el.value as Theme;
    store("genra.theme", state.theme);
    applyTheme();
  } else if (el.name === "lang") {
    setLang(el.value as Lang);
    store("genra.lang", el.value);
    render();
  } else if (el.name === "send_hashes") {
    void api.setSendHashes(el.checked).then(
      (s) => {
        state.settings = s;
        render();
      },
      () => render(),
    );
  }
});

// ---------- start

async function start() {
  const savedTheme = store("genra.theme");
  if (savedTheme === "light" || savedTheme === "dark" || savedTheme === "system") state.theme = savedTheme;
  applyTheme();
  setLang(store("genra.lang") === "en" ? "en" : "vi");
  render();

  await api.onProgress((p) => {
    Object.assign(state.quick, { running: true, folder: p.folder, files: p.files, waiting: p.phase === "waiting" });
    if (state.page === "overview") render();
  });
  await api.onQuickDone((r) => {
    Object.assign(state.quick, { running: false, stopping: false, waiting: false, result: r, handled: new Set<string>() });
    // The band reads the new history entry (folder and stopped scans keep older findings).
    void refreshHistory();
  });
  await api.onRulesChanged(() => void refreshRules());
  await api.onRepairProgress((p) => {
    state.repairProgress = p;
    if (state.page === "scan" && (state.act.s === "working" || state.act.s === "excel")) render();
  });
  await api.onDropped((paths) => {
    state.dragOver = false;
    if (paths.length) void scanPath(paths[0]);
    else render();
  });

  const [rules, version, settings, hist, installId] = await Promise.all([
    api.rulesInfo(),
    getVersion(),
    api.getSettings(),
    api.history(),
    api.installId().catch(() => ""),
  ]);
  Object.assign(state, { rules, appVersion: version, settings, history: hist, installId });
  render();
  // Updates come from signed GitHub releases; a failed check (offline, no release yet) stays silent.
  api
    .checkUpdate()
    .then((u) => {
      state.update = u;
      if (u) render();
    })
    .catch(() => {});

  const launched = await api.launchPath();
  if (launched) void scanPath(launched);
  // J7: the first quick scan runs by itself; after that it is one press on Tổng quan.
  else if (!hist.entries.some((e) => e.kind === "quick_scan")) void startQuick();

  // Hover feedback only; the drop itself arrives as "dropped" after Rust has allowed the paths.
  await getCurrentWebview().onDragDropEvent((e) => {
    const p = e.payload;
    if (p.type === "enter" || p.type === "over") {
      if (!state.dragOver || state.page !== "scan") {
        state.dragOver = true;
        if (state.page !== "scan" || state.scan.status === "done" || state.act.s !== "idle") {
          state.page = "scan";
          resetResult();
          state.scan = { status: "idle" };
        }
        render();
      }
    } else if (p.type === "leave") {
      state.dragOver = false;
      render();
    }
  });
  // Relative times in the sidebar ("10 phút trước") stay current.
  setInterval(() => render(), 60_000);
}

void start();
