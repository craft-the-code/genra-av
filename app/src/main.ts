// Genra AV window. Plain TypeScript: four screens do not need a framework, and the window stays
// small and quick to open on old office PCs (ADR 0003, principle 9). Every file action runs in
// Rust; the window only asks and shows (docs/ux/README.md, mock-ups v2).
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getVersion } from "@tauri-apps/api/app";
import * as api from "./api";
import type { Failure, QuickResult, RepairDone, ScanResult, Severity, Undo } from "./api";
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
  rules: null as api.RulesInfo | null,
  settings: { send_hashes: false } as api.Settings,
  scan: { status: "idle" } as ScanState,
  act: { s: "idle" } as Act,
  details: false,
  report: { open: false, note: "", status: "idle", error: "" } as ReportState,
  quick: {
    running: false,
    folder: "",
    files: 0,
    waiting: false,
    result: null as QuickResult | null,
    handled: new Set<string>(),
    error: "",
  },
  history: null as api.HistoryView | null,
  historyAll: false,
  machine: null as api.MachineOverview | null,
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
      title = t("band.running.title");
      text = [q.folder ? t("band.running.text", { folder: shortFolder(q.folder), files: nf(q.files) }) : t("band.running.start")];
    }
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
  } else if (q.result) {
    ok = true;
    tn = "ok";
    title = t("band.safe.title");
    text = [t("band.safe.text", { when: t("time.at", { time: fmtWhen(q.result.at) }), files: nf(q.result.files_seen) })];
    action = secondary("quick", t("band.scan"));
  } else {
    const last = lastQuickEntry();
    if (last && (last.hits ?? 0) > 0) {
      tn = "warn";
      title = t("band.previous.title", { n: last.hits ?? 0 });
      text = [t("band.previous.text")];
      action = primary("quick", t("band.scan"));
    } else if (last) {
      ok = true;
      tn = "ok";
      title = t("band.safe.title");
      text = [t("band.safe.text", { when: t("time.at", { time: fmtWhen(last.at) }), files: nf(last.files ?? 0) })];
      action = secondary("quick", t("band.scan"));
    } else {
      title = t("band.never.title");
      text = [t("band.never.text")];
      action = primary("quick", t("band.scan"));
    }
  }
  if (q.error) text.push(t("band.error", { detail: q.error }));
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
    </div>
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
          tone: hits ? verdictTone(e.verdict) : "ok",
          name: t("history.quick"),
          sub: `${t(hits ? "history.quick.hits" : "history.quick.safe", { files: nf(e.files ?? 0), hits })} · ${when}`,
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
  const extra = state.act.s === "refused" || state.act.s === "failed" ? `<dt>Genra</dt><dd class="mono">${esc(state.act.f.detail)}</dd>` : "";
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
  return [...new Set(r.report.findings.filter((f) => f.severity !== "info").map((f) => f.message_vi))];
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
    : step(t("result.plan.replace")) + step(t("result.plan.machine"), state.machine?.health == null) + step(t("result.plan.verify"));
  let status = "";
  if (a.s === "refused")
    status = `<div class="card inset warn-inset" role="alert"><h3>${esc(t("refused.title"))}</h3><p>${esc(t(`refused.${a.f.code}`))}</p><p class="muted">${esc(t("refused.kept"))}</p></div>`;
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

function removedWords(d: RepairDone): string {
  return d.removed.some((x) => x.toLowerCase().includes("vba") || x.toLowerCase().includes("macro") || x.toLowerCase().includes("module"))
    ? t("done.macros")
    : d.removed.length
      ? d.removed.join(", ")
      : t("done.macros");
}

function doneResult(a: Extract<Act, { s: "repaired" }>): string {
  const d = a.done;
  const item = (tn: Tone, title: string, detail: string) =>
    `<li>${icon(tn)}<div><div class="step-title">${esc(title)}</div><div class="row-sub">${esc(detail)}</div></div></li>`;
  const cleanDetail = d.renamed
    ? t("done.clean.renamed", { removed: removedWords(d), clean: d.clean_name })
    : t("done.clean.inplace", { removed: removedWords(d) });
  return `<section class="card hero result" aria-labelledby="res-title">
    ${icon("ok")}
    <div class="result-body">
      <div class="result-head">
        <h2 id="res-title">${esc(t("done.title"))}</h2>
        <p>${esc(t("done.text"))}</p>
      </div>
      <ul class="done-steps">
        ${item("ok", t("done.clean", { name: d.name }), cleanDetail)}
        ${item("ok", t("done.quarantine"), t("done.quarantine.detail"))}
        ${item("ok", t("done.verify"), t("done.verify.detail"))}
        ${d.machine ? "" : item("soon", t("done.machine"), t("done.machine.soon"))}
      </ul>
      <div class="card inset tell">${line("message-square")}<span>${esc(t("done.tell"))}</span></div>
      ${a.error ? `<div class="notice warn" role="alert">${icon("warn")}<span>${esc(a.error)}</span></div>` : ""}
      <div class="actions">
        <button class="btn primary" data-action="reveal" data-path="${esc(d.clean_path)}" data-fid="reveal-clean">${esc(t("result.reveal"))}</button>
        <button class="link with-icon" data-action="undo-repair" data-fid="undo-repair"${a.undoing ? " disabled" : ""}>${line("undo-2", 18)}${esc(t("done.undo"))}</button>
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

// ---------- Máy của bạn

function machinePage(): string {
  const m = state.machine;
  const r = state.rules;
  const row = (tn: Tone, name: string, detail: string, right = "") =>
    `<li class="row">${icon(tn)}<div class="row-text"><div class="row-name">${esc(name)}</div><div class="row-sub">${esc(detail)}</div></div>${right}</li>`;
  const soon = `<span class="status-word soon">${esc(t("status.soon"))}</span>`;
  const rulesDetail = r
    ? r.source === "installed"
      ? t("machine.rules.installed", { version: r.version, hashes: nf(r.hashes), when: r.last_ok ? relTime(r.last_ok) : "—" })
      : t("machine.rules.bundled", { version: r.version })
    : "";
  const health = m?.health
    ? m.health.map((h) => row(h.tone, h.title_vi, h.detail_vi)).join("")
    : row("soon", t("machine.defender"), t("machine.defender.detail"), soon) + row("soon", t("machine.macro"), t("machine.macro.detail"), soon);
  const startup = m?.startup
    ? m.startup.length
      ? `<ul class="rows">${m.startup.map((s) => row(s.tone, s.name, [s.publisher, s.detail_vi].filter(Boolean).join(" · "))).join("")}</ul>`
      : `<p class="empty">${esc(t("machine.startup.empty"))}</p>`
    : `<div class="soon-block">${soon}<p>${esc(t("machine.startup.soon"))}</p></div>`;
  const guard = (ic: string, name: string) =>
    `<li class="row">${line(ic, 18)}<div class="row-text"><div class="row-name">${esc(name)}</div><div class="row-sub">${esc(t("machine.guard.detail"))}</div></div>${soon}</li>`;
  return `<h1 tabindex="-1">${esc(t("machine.title"))}</h1>
    <p class="page-sub">${esc(t("machine.sub"))}</p>
    <div class="stack">
      <section class="card" aria-labelledby="m-health"><h2 class="overline" id="m-health">${esc(t("machine.health"))}</h2>
        <ul class="rows">${row(r?.source === "installed" ? "ok" : "warn", t("machine.rules"), rulesDetail)}${health}</ul></section>
      <section class="card" aria-labelledby="m-startup"><h2 class="overline" id="m-startup">${esc(t("machine.startup"))}</h2>${startup}</section>
      <section class="card" aria-labelledby="m-guard"><h2 class="overline" id="m-guard">${esc(t("machine.guard"))}</h2>
        <ul class="rows">${guard("folder", t("machine.guard.downloads"))}${guard("message-square", t("machine.guard.zalo"))}${guard("hard-drive", t("machine.guard.usb"))}</ul></section>
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

async function clean() {
  const s = state.scan;
  if (s.status !== "done") return;
  state.act = { s: "working", what: "clean" };
  render();
  try {
    const done = await api.repairFile(s.result.path);
    state.act = { s: "repaired", done, undoing: false, error: "" };
    state.quick.handled.add(s.result.path);
  } catch (e) {
    const f = failureCode(e);
    state.act = f.kind === "refused" ? { s: "refused", f } : { s: "failed", f };
  }
  render(true);
  void refreshHistory();
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

async function startQuick() {
  if (state.quick.running) return;
  Object.assign(state.quick, { running: true, folder: "", files: 0, waiting: false, error: "" });
  render();
  try {
    await api.quickScan();
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
        void doUndo({ type: "repair", id: state.act.done.id });
      }
      break;
    case "undo":
      void doUndo({ type: el.dataset.type as "quarantine" | "repair", id: el.dataset.id ?? "" } as Undo);
      break;
    case "quick":
      void startQuick();
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
    Object.assign(state.quick, { running: false, waiting: false, result: r, handled: new Set<string>() });
    render();
    void refreshHistory();
  });
  await api.onRulesChanged(() => void refreshRules());
  await api.onDropped((paths) => {
    state.dragOver = false;
    if (paths.length) void scanPath(paths[0]);
    else render();
  });

  const [rules, version, settings, hist, machine] = await Promise.all([
    api.rulesInfo(),
    getVersion(),
    api.getSettings(),
    api.history(),
    api.machineOverview(),
  ]);
  Object.assign(state, { rules, appVersion: version, settings, history: hist, machine });
  render();

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
