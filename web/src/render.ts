/**
 * Pure rendering: LamassuState -> HTML.
 *
 * No DOM access, no fetching, no timers — the same state always produces the
 * same string, which is what lets every visual claim be tested against it.
 * `main.ts` is the only module that touches the document.
 *
 * The visual language is the audit sensor's feed: one line per event, a stable
 * per-pid colour so a burst of activity reads as one actor, a fixed-width
 * class column, and escaping before rendering. What is added is the half
 * the audit sensor does not have: findings, taint, canary, drops and provenance.
 */

import {
  digestChip,
  esc,
  eventDetail,
  fmtCount,
  fmtTs,
  kindLabel,
  markChip,
  safe,
  severityClass,
  INVARIANT_EXPLAINER,
  SCORED_EXPLAINER,
} from "./format.js";
import type {
  FindingRow,
  ProcTreeNode,
  LamassuState,
} from "./reducer.js";
import type { Origin } from "./stream.js";
import { canaryHits, procTree, sessionsInOrder, taintedSessions } from "./reducer.js";

function pidColor(pid: number): string {
  // Same hue for one pid on every row, so an actor keeps its colour.
  const hues = [265, 145, 45, 210, 330, 95];
  return `hsl(${hues[Math.abs(Math.imul(pid, 2654435761)) % hues.length]} 70% 62%)`;
}

/* ---------------------------------------------------------------- banners */

export function renderBanners(state: LamassuState): string {
  const parts: string[] = [];
  if (state.inferredProvenance) {
    parts.push(`
      <div class="banner banner-provenance" data-testid="banner-inferred" role="status">
        <strong>INFERRED PROVENANCE</strong>
        <span>This feed is on the proxy path. Trust was inferred from message roles, not declared by the harness
        (<code>{"t":"warning","code":"inferred-provenance"}</code>). A declared finding and an inferred finding are
        not the same claim; they are counted and labelled separately below.</span>
      </div>`);
  }
  if (state.drop.lossy) {
    parts.push(`
      <div class="banner banner-loss" data-testid="banner-loss" role="alert">
        <strong>LOSSY FEED — EVENTS WERE LOST</strong>
        <span>drop_total=${fmtCount(state.drop.dropTotal)} · upd_fail_total=${fmtCount(state.drop.updFailTotal)}.
        The kernel ring filled or map updates failed, so this is an incomplete record.
        <em>Nothing fired</em> here does NOT mean <em>nothing ran</em>.</span>
      </div>`);
  }
  if (state.protocol.errors > 0) {
    parts.push(`
      <div class="banner banner-protocol" data-testid="banner-protocol" role="alert">
        <strong>UNREADABLE LINES: ${fmtCount(state.protocol.errors)}</strong>
        <span>Lines this frontend could not parse or does not recognise. They are reported, never skipped silently.</span>
        <ul>${state.protocol.errorsDetail
          .slice(-5)
          .map((d) => `<li>${safe(d)}</li>`)
          .join("")}</ul>
      </div>`);
  }
  return `<div class="banners">${parts.join("")}</div>`;
}

/* ------------------------------------------------------------------ stats */

export function renderStats(state: LamassuState): string {
  const invariant = state.findings.filter((f) => f.invariant).length;
  const scored = state.findings.length - invariant;
  const blocked = [...state.sessions.values()].filter((s) => s.decision === "block").length;
  const tainted = [...state.sessions.values()].filter((s) => s.tainted).length;
  const cells: Array<[string, string, string]> = [
    ["sessions", fmtCount(state.sessions.size), "sessions observed"],
    ["tainted", fmtCount(tainted), "sessions that ingested a data span"],
    ["events", fmtCount(state.events.length), "syscall events in view"],
    ["invariant", fmtCount(invariant), "structural findings (forced the decision)"],
    ["scored", fmtCount(scored), "heuristic findings (compared to a threshold)"],
    ["blocked", fmtCount(blocked), "sessions with a BLOCK decision"],
    ["drop_total", fmtCount(state.drop.dropTotal), "events dropped by the kernel ring"],
    ["upd_fail_total", fmtCount(state.drop.updFailTotal), "failed map updates"],
  ];
  return `<div class="stats">${cells
    .map(
      ([k, v, title]) =>
        `<div class="stat" data-testid="stat-${k}" title="${esc(title)}"><span class="stat-k">${esc(k)}</span><span class="stat-v">${v}</span></div>`,
    )
    .join("")}</div>`;
}

/* ------------------------------------------------------------ proc tree */

function procRow(node: ProcTreeNode): string {
  const taintMark = node.tainted
    ? `<span class="taint-flag" data-tainted="true" title="emitted while the session was tainted">TAINTED</span>`
    : "";
  const state = node.alive ? "alive" : "exited";
  return `<li class="proc-node ${node.tainted ? "is-tainted" : ""}" data-testid="proc-node" data-pid="${node.pid}" data-tainted="${node.tainted}" data-depth="${node.depth}" style="--indent:${node.depth * 18}px">
    <span class="proc-pid" style="color:${pidColor(node.pid)}">${node.pid}</span>
    <span class="proc-comm">${safe(node.comm) || "<unknown>"}</span>
    <span class="proc-meta">ppid=${node.ppid} · ${node.events} ev · <span class="proc-state proc-${state}">${state}</span></span>
    ${taintMark}
  </li>`;
}

export function renderProcessTree(state: LamassuState): string {
  const tree = procTree(state);
  if (tree.length === 0) {
    return `<section class="panel" data-panel="tree"><h2>Process tree</h2><p class="empty">no processes yet</p></section>`;
  }
  return `<section class="panel" data-panel="tree">
    <h2>Process tree <span class="hint">by pid/ppid · tainted nodes marked</span></h2>
    <ul class="tree" data-testid="proc-tree">${tree.map(procRow).join("")}</ul>
  </section>`;
}

/* --------------------------------------------------------------- events */

function eventRowHtml(row: LamassuState["events"][number]): string {
  return `<tr data-testid="event-row" data-kind="${esc(row.kind)}" data-pid="${row.pid}" data-session="${esc(row.session)}" data-tainted="${row.tainted}">
    <td class="c-seq">${row.seq}</td>
    <td class="c-ts">${fmtTs(row.ts)}</td>
    <td><span class="kind kind-${esc(row.kind)}">${esc(kindLabel(row.kind))}</span></td>
    <td class="c-pid" style="color:${pidColor(row.pid)}">${row.pid}</td>
    <td class="c-sess">${safe(row.session)}</td>
    <td class="c-detail">${eventDetail(row)}${row.tainted ? ` <span class="taint-dot" title="tainted session at emit time">▲</span>` : ""}</td>
  </tr>`;
}

export function renderEvents(state: LamassuState): string {
  if (state.events.length === 0) {
    return `<section class="panel" data-panel="events"><h2>Event stream</h2><p class="empty">no events yet</p></section>`;
  }
  return `<section class="panel" data-panel="events">
    <h2>Event stream <span class="hint">exec / exit / open / net · newest last</span></h2>
    <div class="scroll">
      <table class="events">
        <thead><tr><th>seq</th><th>time</th><th>kind</th><th>pid</th><th>session</th><th>detail</th></tr></thead>
        <tbody>${state.events.map(eventRowHtml).join("")}</tbody>
      </table>
    </div>
  </section>`;
}

/* ------------------------------------------------------------- findings */

function findingRowHtml(f: FindingRow): string {
  const forced = f.blockedBy ? `<span class="forced" title="this finding is why the session was blocked">forced BLOCK</span>` : "";
  return `<tr data-testid="finding-row" data-rule="${esc(f.rule)}" data-layer="${esc(f.layer)}"
      data-invariant="${f.invariant}" data-provenance="${esc(f.provenance)}" data-severity="${esc(f.severity)}"
      class="${f.invariant ? "row-invariant" : "row-scored"}">
    <td class="c-mark">${markChip(f.invariant)}</td>
    <td class="c-layer">${safe(f.layer)}</td>
    <td class="c-rule">${safe(f.rule)}</td>
    <td><span class="sev ${severityClass(f.severity)}">${esc(f.severity)}</span></td>
    <td class="c-prov"><span class="prov prov-${esc(f.provenance)}">${esc(f.provenance)}</span></td>
    <td class="c-digest">${digestChip(f.evidence_digest)}</td>
    <td class="c-span">${f.span_index >= 0 ? `span ${f.span_index}` : "—"}</td>
    <td class="c-sess">${safe(f.session)}</td>
    <td>${forced}</td>
  </tr>`;
}

export function renderFindings(state: LamassuState): string {
  if (state.findings.length === 0) {
    return `<section class="panel" data-panel="findings"><h2>Findings</h2><p class="empty">nothing fired</p></section>`;
  }
  const invariant = state.findings.filter((f) => f.invariant);
  const scored = state.findings.filter((f) => !f.invariant);
  return `<section class="panel" data-panel="findings">
    <h2>Findings <span class="hint">one row per rule firing</span></h2>
    <p class="legend">
      <span class="legend-item">${markChip(true)} — ${esc(INVARIANT_EXPLAINER)}</span>
      <span class="legend-item">${markChip(false)} — ${esc(SCORED_EXPLAINER)}</span>
    </p>
    <div class="counts">
      <span data-testid="count-invariant">${invariant.length} invariant</span>
      <span data-testid="count-scored">${scored.length} scored</span>
    </div>
    <div class="scroll">
      <table class="findings">
        <thead><tr><th>claim</th><th>layer</th><th>rule</th><th>severity</th><th>provenance</th><th>evidence</th><th>scope</th><th>session</th><th></th></tr></thead>
        <tbody>${state.findings.map(findingRowHtml).join("")}</tbody>
      </table>
    </div>
  </section>`;
}

/* --------------------------------------------------------------- canary */

export function renderCanary(state: LamassuState): string {
  const hits = canaryHits(state);
  if (hits.length === 0) {
    return `<section class="panel" data-panel="canary"><h2>Canary hits</h2><p class="empty">no egress/canary-leak findings</p></section>`;
  }
  return `<section class="panel panel-canary" data-panel="canary">
    <h2>Canary hits <span class="hint">egress/canary-leak · digest only</span></h2>
    <ul class="canary-list">
      ${hits
        .map(
          (f) => `<li data-testid="canary-row" data-session="${esc(f.session)}" data-digest="${esc(f.evidence_digest)}">
        <span class="canary-flag">CANARY LEAK</span>
        <span class="canary-layer">${safe(f.layer)}/${safe(f.rule)}</span>
        ${markChip(f.invariant)}
        <span class="sev ${severityClass(f.severity)}">${esc(f.severity)}</span>
        <span class="prov prov-${esc(f.provenance)}">${esc(f.provenance)}</span>
        <span class="canary-digest" title="the matched secret is never in the stream; only this hash is">digest ${safe(f.evidence_digest)}</span>
        <span class="canary-sess">session ${safe(f.session)}</span>
      </li>`,
        )
        .join("")}
    </ul>
    <p class="hint">The stream carries a truncated evidence hash, never the matched text (§2), so this view can show
    that a canary left, and which digest matched, but never the secret itself — and it does not invent one.</p>
  </section>`;
}

/* ------------------------------------------------------- tainted sessions */

function taintOrigins(origins: Origin[]): string {
  if (origins.length === 0) return `<span class="hint">origin not declared</span>`;
  return origins
    .map(
      (o) =>
        `<span class="origin" title="the span declaration that tainted this session">${safe(o.channel)}:${safe(o.ref)}</span>`,
    )
    .join(" ");
}

export function renderTaint(state: LamassuState): string {
  const rows = taintedSessions(state);
  if (rows.length === 0) {
    return `<section class="panel" data-panel="taint"><h2>Tainted sessions</h2><p class="empty">no session ingested a data span</p></section>`;
  }
  return `<section class="panel" data-panel="taint">
    <h2>Tainted sessions <span class="hint">taint is derived from a data span, never set</span></h2>
    <ul class="taint-list">
      ${rows
        .map(
          (s) => `<li data-testid="tainted-session" data-session="${esc(s.sid)}">
        <span class="taint-flag">TAINTED</span>
        <span class="sess-id">${safe(s.sid)}</span>
        <span class="sess-harness">${safe(s.harness) || "unknown harness"}</span>
        <span class="sess-root">root_pid ${s.rootPid}</span>
        <span class="sess-origins">tainted by ${taintOrigins(s.origins)}</span>
        <span class="sess-count">${s.taintedEvents} tainted events</span>
        <span class="sess-decision">${s.decision ? `decision ${esc(s.decision)}` : "no decision"}</span>
      </li>`,
        )
        .join("")}
    </ul>
  </section>`;
}

/* ----------------------------------------------------------- provenance */

export function renderProvenance(state: LamassuState): string {
  const declared = state.findings.filter((f) => f.provenance === "declared");
  const inferred = state.findings.filter((f) => f.provenance === "inferred");
  const rows = [...declared.map((f) => [f, "declared"] as const), ...inferred.map((f) => [f, "inferred"] as const)];
  if (rows.length === 0) {
    return `<section class="panel" data-panel="provenance"><h2>Provenance</h2><p class="empty">no findings</p></section>`;
  }
  return `<section class="panel" data-panel="provenance">
    <h2>Provenance <span class="hint">declared (socket path) vs inferred (proxy path)</span></h2>
    <div class="prov-split">
      <div class="prov-col prov-col-declared" data-testid="prov-declared"><span class="prov-k">declared</span><span class="prov-v">${declared.length}</span></div>
      <div class="prov-col prov-col-inferred" data-testid="prov-inferred"><span class="prov-k">inferred</span><span class="prov-v">${inferred.length}</span></div>
    </div>
    <div class="scroll">
      <table class="prov-table">
        <thead><tr><th>provenance</th><th>layer/rule</th><th>session</th></tr></thead>
        <tbody>${rows
          .map(
            ([f, p]) =>
              `<tr data-testid="prov-row" data-provenance="${p}"><td><span class="prov prov-${p}">${p}</span></td><td>${safe(f.layer)}/${safe(f.rule)}</td><td>${safe(f.session)}</td></tr>`,
          )
          .join("")}</tbody>
      </table>
    </div>
  </section>`;
}

/* --------------------------------------------------------------- layout */

export function renderSessions(state: LamassuState): string {
  const rows = sessionsInOrder(state);
  if (rows.length === 0) {
    return `<section class="panel" data-panel="sessions"><h2>Sessions</h2><p class="empty">no sessions yet</p></section>`;
  }
  return `<section class="panel" data-panel="sessions">
    <h2>Sessions</h2>
    <ul class="session-list">
      ${rows
        .map(
          (s) => `<li data-testid="session-row" data-session="${esc(s.sid)}" data-tainted="${s.tainted}" class="${s.tainted ? "is-tainted" : ""}">
        <span class="sess-id">${safe(s.sid)}</span>
        <span class="sess-harness">${safe(s.harness) || "unknown harness"}</span>
        <span class="sess-root">root_pid ${s.rootPid}</span>
        <span class="sess-spans">${s.spans.length} spans</span>
        <span class="sess-findings">${s.findings.length} findings</span>
        ${s.tainted ? `<span class="taint-flag">TAINTED</span>` : ""}
        <span class="proc-state proc-${s.open ? "alive" : "exited"}">${s.open ? "open" : "closed"}</span>
        <span class="sess-decision">${s.decision ? `decision ${esc(s.decision)}` : "no decision"}</span>
      </li>`,
        )
        .join("")}
    </ul>
  </section>`;
}

export function renderRoot(state: LamassuState): string {
  return `${renderBanners(state)}
    ${renderStats(state)}
    <main class="grid">
      ${renderProcessTree(state)}
      ${renderTaint(state)}
      ${renderEvents(state)}
      ${renderFindings(state)}
      ${renderCanary(state)}
      ${renderProvenance(state)}
      ${renderSessions(state)}
    </main>`;
}
