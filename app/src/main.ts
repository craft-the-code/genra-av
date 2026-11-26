// Genra AV window. Plain TypeScript: six screens and one real flow (check a file) do not need a
// framework, and the window stays small and quick to open on old office PCs (ADR 0003, principle 9).
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getVersion } from "@tauri-apps/api/app";
import * as api from "./api";
import type { ScanResult, Severity } from "./api";
import { icon, mark, type Tone } from "./icons";
import { t, setLang, getLang, type Lang } from "./i18n";

type Page = "overview" | "scan" | "clean" | "health" | "quarantine" | "settings";
type Theme = "system" | "light" | "dark";
type ScanState =
  | { status: "idle" }
  | { status: "busy"; name: string }
  | { status: "done"; result: ScanResult }
  | { status: "error"; code: string; detail: string };
type ReportState = { open: boolean; note: string; status: "idle" | "sending" | "done" | "error"; error: string };

const PAGES: Page[] = ["overview", "scan", "clean", "health", "quarantine", "settings"];

const state = {
  page: "overview" as Page,
  theme: "system" as Theme,
  appVersion: "",
  rules: null as api.RulesInfo | null,
  scan: { status: "idle" } as ScanState,
  details: false,
  report: { open: false, note: "", status: "idle", error: "" } as ReportState,
  recent: [] as { result: ScanResult; at: Date }[],
  dragOver: false,
};

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

function fmtSize(n: number): string {
  const nf = (x: number) => x.toLocaleString(getLang(), { maximumFractionDigits: x < 10 ? 1 : 0 });
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${nf(n / 1024)} KB`;
  return `${nf(n / 1024 / 1024)} MB`;
}

const fmtTime = (d: Date) => d.toLocaleTimeString(getLang(), { hour: "2-digit", minute: "2-digit" });

const tone = (v: Severity | null): Tone => (v === "malware" ? "bad" : v === "suspicious" ? "warn" : "ok");
const statusWord = (tn: Tone) =>
  ({ ok: t("status.safe"), warn: t("status.suspicious"), bad: t("status.malware"), soon: t("status.soon") })[tn];
const badge = (tn: Tone, label = statusWord(tn)) => `<span class="status-word ${tn}">${esc(label)}</span>`;

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

const soonAttrs = () => `aria-disabled="true" title="${esc(t("soon"))}" data-action="soon"`;

// ---------- theme

function applyTheme() {
  const root = document.documentElement;
  if (state.theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", state.theme);
}

// ---------- views

function sidebar(): string {
  const items = PAGES.map(
    (p) =>
      `<li><button class="nav-item" data-action="nav" data-page="${p}" data-fid="nav-${p}"${
        state.page === p ? ' aria-current="page"' : ""
      }>${esc(t(`nav.${p}`))}</button></li>`,
  ).join("");
  const rulesLine = state.rules ? t("footer.rules", { version: state.rules.version }) : "";
  return `<aside class="side">
    <div class="brand">${mark}<span class="brand-name">GENRA <span>AV</span></span></div>
    <nav aria-label="${esc(t("nav.label"))}"><ul class="nav">${items}</ul></nav>
    <div class="side-foot">
      <div class="line"><span aria-hidden="true">○</span><span>${esc(t("footer.guard"))}</span></div>
      <div class="line"><span aria-hidden="true">✓</span><span>${esc(rulesLine)}</span></div>
    </div>
  </aside>`;
}

function overview(): string {
  const rows = state.recent
    .map(({ result, at }, i) => {
      const tn = tone(result.report.verdict);
      const f = topFinding(result);
      const what = tn === "ok" ? statusWord("ok") : `${statusWord(tn)} · ${familyName(f?.family ?? "")}`;
      return `<li class="row">${icon(tn)}
        <div><div class="row-name">${esc(result.name)}</div><div class="row-sub">${esc(what)} · ${fmtTime(at)}</div></div>
        <button class="link" data-action="recent" data-index="${i}" data-fid="recent-${i}">${esc(t("overview.recent.view"))}<span class="sr-only"> ${esc(result.name)}</span></button></li>`;
    })
    .join("");
  const stat = (k: string) =>
    `<div class="card"><div class="muted">${esc(t(k))}</div><div class="stat-value" aria-hidden="true">—</div><div class="stat-note">${esc(t("soon.v01"))}</div></div>`;
  return `<h1 tabindex="-1">${esc(t("overview.title"))}</h1>
    <section class="card hero result">
      <div class="icon" style="width:56px;height:66px">${mark}</div>
      <div class="result-body">
        <div class="result-head"><h2>${esc(t("overview.hero.title"))}</h2><p>${esc(t("overview.hero.text"))}</p></div>
        <div class="actions"><button class="btn primary" data-action="nav" data-page="scan" data-fid="hero-scan">${esc(t("overview.hero.cta"))}</button></div>
      </div>
    </section>
    <div class="stats">${stat("overview.stat.checked")}${stat("overview.stat.blocked")}${stat("overview.stat.cleaned")}</div>
    <section class="card" style="margin-top:16px">
      <h2 class="overline">${esc(t("overview.recent"))}</h2>
      ${rows ? `<ul class="rows">${rows}</ul>` : `<p class="empty">${esc(t("overview.recent.empty"))}</p>`}
    </section>`;
}

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
        ${badge("ok")}
        <h2 id="res-title">${esc(t("result.safe.title"))}</h2>
        <p>${esc(r.name)} · ${fmtSize(r.size)}</p>
      </div>
      <div><h3 class="overline">${esc(t("result.safe.checked"))}</h3>
        <ul class="bullets ok">${checked.map((c) => `<li>${esc(c)}</li>`).join("")}</ul></div>
      <div class="actions">
        <button class="btn" data-action="reveal" data-fid="reveal">${esc(t("result.reveal"))}</button>
        <button class="btn" data-action="pick" data-fid="again">${esc(t("result.again"))}</button>
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
  return `<section class="card inset" id="details" aria-labelledby="details-title">
    <h3 class="overline" id="details-title">${esc(t("details.title"))}</h3>
    <dl class="details">
      ${findings}
      <dt>${esc(t("details.modules"))}</dt><dd>${modules}</dd>
      <dt>${esc(t("details.kind"))}</dt><dd>${esc(t(`kind.${rep.kind}`))}</dd>
      <dt>${esc(t("details.sha256"))}</dt><dd class="mono">${esc(rep.sha256)}</dd>
    </dl>
  </section>`;
}

function reportPanel(): string {
  const rp = state.report;
  if (rp.status === "done")
    return `<div class="notice ok" role="status">${icon("ok")}<span>${esc(t("report.done"))}</span></div>`;
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

function threatResult(r: ScanResult): string {
  const tn = tone(r.report.verdict);
  const bad = tn === "bad";
  const top = topFinding(r);
  const msgs = [...new Set(r.report.findings.filter((f) => f.severity !== "info").map((f) => f.message_vi))];
  return `<section class="card hero result ${bad ? "danger" : "warning"}" aria-labelledby="res-title">
    ${icon(tn)}
    <div class="result-body">
      <div class="result-head">
        ${badge(tn)}
        <h2 id="res-title">${esc(t(bad ? "result.malware.title" : "result.suspicious.title"))}</h2>
        <p>${esc(r.name)} · ${esc(familyName(top?.family ?? ""))}</p>
      </div>
      <div><h3 class="overline">${esc(t(bad ? "result.what" : "result.why"))}</h3>
        <ul class="bullets ${tn}">${msgs.map((m) => `<li>${esc(m)}</li>`).join("")}</ul></div>
      ${bad ? "" : `<p style="margin:0">${esc(t("result.suspicious.advice"))}</p>`}
      <div class="card inset">
        <h3 class="overline">${esc(t("result.plan"))} <span class="soon-tag">${esc(t("soon"))}</span></h3>
        <p style="margin:0">${esc(t("result.plan.soon"))}</p>
        <p class="muted" style="margin:6px 0 0">${esc(t("result.plan.meanwhile"))}</p>
      </div>
      <div class="actions">
        <button class="btn primary" ${soonAttrs()} data-fid="clean">${esc(t("result.clean"))}</button>
        <button class="btn" data-action="details" data-fid="details" aria-expanded="${state.details}" aria-controls="details">${esc(
          t(state.details ? "result.details.hide" : "result.details"),
        )}</button>
        <div class="side-links">
          <button class="link" ${soonAttrs()} data-fid="clean-file">${esc(t("result.clean_file_only"))}</button>
          ${
            state.report.status === "done"
              ? ""
              : `<button class="link quiet" data-action="report-open" data-fid="report-open" aria-expanded="${state.report.open}">${esc(t("result.report"))}</button>`
          }
        </div>
      </div>
      ${state.details ? detailsPanel(r) : ""}
      ${reportPanel()}
    </div>
  </section>`;
}

function scanPage(): string {
  const s = state.scan;
  let body = "";
  if (s.status === "busy")
    body = `<section class="card hero"><div class="notice">${'<div class="spinner" aria-hidden="true"></div>'}<span>${esc(t("scan.busy", { name: s.name }))}</span></div></section>`;
  else if (s.status === "error") {
    const msg =
      s.code === "too_large" || s.code === "not_a_file" ? t(`scan.error.${s.code}`) : t("scan.error.other", { detail: s.detail });
    body = `<section class="card hero result warning" aria-labelledby="res-title">${icon("warn")}
      <div class="result-body"><div class="result-head"><h2 id="res-title">${esc(t("scan.error.title"))}</h2><p>${esc(msg)}</p></div></div></section>`;
  } else if (s.status === "done") {
    const v = s.result.report.verdict;
    body = v === "malware" || v === "suspicious" ? threatResult(s.result) : safeResult(s.result);
  }
  // A threat result fills the screen; the drop zone comes back with "Kiểm tra tệp khác" / a new drop.
  const showDrop = !(s.status === "done" && tone(s.result.report.verdict) !== "ok");
  return `<h1 tabindex="-1">${esc(t("scan.title"))}</h1>
    <div class="stack">${showDrop ? dropZone() : ""}<div role="status" aria-live="polite">${body}</div></div>`;
}

function emptyPage(titleKey: string, headKey: string, textKey: string, extra = ""): string {
  return `<h1 tabindex="-1">${esc(t(titleKey))}</h1>
    <section class="card hero result">
      ${icon("soon")}
      <div class="result-body">
        <div class="result-head">${badge("soon", t("soon.v01"))}<h2>${esc(t(headKey))}</h2><p>${esc(t(textKey))}</p></div>
        ${extra}
      </div>
    </section>`;
}

function healthPage(): string {
  const r = state.rules;
  const item = (tn: Tone, name: string, detail: string, word: string) =>
    `<div class="card">${icon(tn)}<div><div class="health-name">${esc(name)}</div><div class="muted">${esc(detail)}</div></div>${badge(tn, word)}</div>`;
  return `<h1 tabindex="-1">${esc(t("health.title"))}</h1>
    <p class="page-sub">${esc(t("health.summary"))}</p>
    <div class="health">
      ${item(
        "ok",
        t("health.rules"),
        r ? t("health.rules.detail", { version: r.version, count: r.rules, published: r.published }) : "",
        t("status.ok"),
      )}
      ${item("soon", t("health.defender"), t("health.defender.detail"), t("status.soon"))}
      ${item("soon", t("health.macro"), t("health.macro.detail"), t("status.soon"))}
      ${item("soon", t("health.guard"), t("health.guard.detail"), t("status.soon"))}
    </div>`;
}

function settingsPage(): string {
  const radio = (name: string, value: string, label: string, checked: boolean) =>
    `<label class="choice"><input type="radio" name="${name}" value="${value}" data-fid="${name}-${value}"${checked ? " checked" : ""}><span>${esc(label)}</span></label>`;
  return `<h1 tabindex="-1">${esc(t("settings.title"))}</h1>
    <div class="stack">
      <section class="card"><fieldset><legend>${esc(t("settings.theme"))}</legend><div class="choices">
        ${(["system", "light", "dark"] as Theme[]).map((v) => radio("theme", v, t(`settings.theme.${v}`), state.theme === v)).join("")}
      </div></fieldset></section>
      <section class="card"><fieldset><legend>${esc(t("settings.lang"))}</legend><div class="choices">
        ${radio("lang", "vi", "Tiếng Việt", getLang() === "vi")}${radio("lang", "en", "English", getLang() === "en")}
      </div></fieldset></section>
      <section class="card"><h3>${esc(t("settings.privacy"))}</h3><p style="margin:6px 0 0">${esc(t("settings.privacy.text"))}</p></section>
      <section class="card"><h3>${esc(t("settings.about"))}</h3><p class="muted" style="margin:6px 0 0">${esc(
        t("settings.about.text", { app: state.appVersion, rules: state.rules?.version ?? "" }),
      )}</p></section>
    </div>`;
}

function page(): string {
  switch (state.page) {
    case "overview":
      return overview();
    case "scan":
      return scanPage();
    case "clean":
      return emptyPage("clean.title", "clean.empty.title", "clean.empty.text",
        `<p style="margin:0">${esc(t("clean.empty.now"))}</p><div class="actions"><button class="btn primary" data-action="nav" data-page="scan" data-fid="clean-scan">${esc(t("overview.hero.cta"))}</button></div>`);
    case "health":
      return healthPage();
    case "quarantine":
      return emptyPage("quarantine.title", "quarantine.empty.title", "quarantine.empty.text");
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
    if (fid)
      root.querySelector<HTMLElement>(`[data-fid="${fid}"]`)?.focus({ preventScroll: true, focusVisible: ring } as FocusOptions);
  }
}

function go(p: Page) {
  state.page = p;
  render();
}

// ---------- actions

async function scanPath(path: string) {
  const name = path.split(/[\\/]/).pop() ?? path;
  state.page = "scan";
  state.scan = { status: "busy", name };
  state.details = false;
  state.report = { open: false, note: "", status: "idle", error: "" };
  render();
  try {
    const result = await api.scanFile(path);
    state.scan = { status: "done", result };
    state.recent.unshift({ result, at: new Date() });
    state.recent = state.recent.slice(0, 8);
  } catch (e) {
    const detail = String(e);
    const code = detail === "too_large" || detail === "not_a_file" ? detail : "other";
    state.scan = { status: "error", code, detail };
  }
  render(true);
}

async function pick() {
  const picked = await open({ multiple: false, directory: false });
  if (typeof picked === "string") await scanPath(picked);
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
  if (!el) return;
  const s = state.scan;
  switch (el.dataset.action) {
    case "nav":
      go(el.dataset.page as Page);
      break;
    case "pick":
      void pick();
      break;
    case "reveal":
      if (s.status === "done") void api.reveal(s.result.path);
      break;
    case "details":
      state.details = !state.details;
      render();
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
    case "recent": {
      const item = state.recent[Number(el.dataset.index)];
      if (item) {
        state.scan = { status: "done", result: item.result };
        state.details = false;
        state.report = { open: false, note: "", status: "idle", error: "" };
        state.page = "scan";
        render(true);
      }
      break;
    }
    case "soon":
      break; // "Sắp có": the control is shown so the layout is final, but does nothing yet.
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
  }
});

// ---------- start

async function start() {
  const savedTheme = store("genra.theme");
  if (savedTheme === "light" || savedTheme === "dark" || savedTheme === "system") state.theme = savedTheme;
  applyTheme();
  setLang(store("genra.lang") === "en" ? "en" : "vi");
  render();

  const [rules, version] = await Promise.all([api.rulesInfo(), getVersion()]);
  state.rules = rules;
  state.appVersion = version;
  render();

  const launched = await api.launchPath();
  if (launched) void scanPath(launched);

  await getCurrentWebview().onDragDropEvent((e) => {
    const p = e.payload;
    if (p.type === "enter" || p.type === "over") {
      if (!state.dragOver || state.page !== "scan") {
        state.dragOver = true;
        if (state.page !== "scan" || state.scan.status === "done") {
          state.page = "scan";
          if (state.scan.status === "done" && tone(state.scan.result.report.verdict) !== "ok") state.scan = { status: "idle" };
        }
        render();
      }
    } else if (p.type === "leave") {
      state.dragOver = false;
      render();
    } else if (p.type === "drop") {
      state.dragOver = false;
      if (p.paths.length) void scanPath(p.paths[0]);
      else render();
    }
  });
}

void start();
