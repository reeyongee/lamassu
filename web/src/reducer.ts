/**
 * The reducer: stream lines -> state.
 *
 * Pure. No DOM, no timers, no transport. Every visualisation in the UI is a
 * projection of the `LamassuState` this module returns, and every assertion
 * about what the UI shows is an assertion about this state (see reducer.test.ts)
 * or about the rendered DOM given this state (see render.test.ts).
 */

import type {
  Decision,
  EventKind,
  EventLine,
  FindingLine,
  Origin,
  Provenance,
  Severity,
  StreamLine,
  Trust,
  WarningLine,
} from "./stream.js";
import { WARNING_EVENTS_DROPPED, WARNING_INFERRED_PROVENANCE } from "./stream.js";

export interface EventRow {
  seq: number;
  session: string;
  kind: EventKind;
  ts: number;
  pid: number;
  ppid: number;
  comm: string;
  cmdline: string;
  filename: string;
  port: number;
  addr: string;
  flags: number;
  /** Emitted while the session was tainted (computed core-side at emit time). */
  tainted: boolean;
}

export interface FindingRow {
  seq: number;
  session: string;
  layer: string;
  rule: string;
  severity: Severity;
  invariant: boolean;
  provenance: Provenance;
  evidence_digest: string;
  span_index: number;
  tainted: boolean;
  /** It forced the session's decision: only invariant findings can. */
  blockedBy: boolean;
}

export interface SpanRow {
  seq: number;
  session: string;
  trust: Trust;
  origin: Origin | null;
  role: string;
  text_len: number;
}

export interface ProcNode {
  pid: number;
  ppid: number;
  comm: string;
  session: string;
  /** Any event from this pid carried tainted=true. */
  tainted: boolean;
  firstTs: number;
  lastTs: number;
  events: number;
  /** No exit event seen for this pid. */
  alive: boolean;
}

export interface ProcTreeNode extends ProcNode {
  /** 0 for a session root; children are one deeper. */
  depth: number;
}

export interface SessionState {
  sid: string;
  harness: string;
  rootPid: number;
  open: boolean;
  /** True iff a span with trust=data was declared (taint is derived, §3). */
  tainted: boolean;
  /** Origins of the data spans that tainted it, in declaration order. */
  taintOrigins: Origin[];
  spans: SpanRow[];
  findings: FindingRow[];
  decision: Decision | null;
  events: number;
  dropTotal: number;
  updFailTotal: number;
  counts: { events: number; findings: number } | null;
}

export interface DropState {
  dropTotal: number;
  updFailTotal: number;
  /** Drops the core reported with no owning session (`events-dropped`). An
   *  un-owned event cannot be attributed to a session, so folding it into the
   *  per-session max would discard it and hide the loss. */
  globalDrops: number;
  /** drop_total or upd_fail_total is non-zero: the feed is lossy. */
  lossy: boolean;
}

export interface ProtocolState {
  /** Lines we could not parse or do not recognise. Rendered, never hidden. */
  errors: number;
  errorsDetail: string[];
  /** Lines whose seq was not greater than the last seen (monotonic, §9). */
  duplicates: number;
  lastSeq: number;
}

export interface LamassuState {
  sessions: Map<string, SessionState>;
  procs: Map<number, ProcNode>;
  events: EventRow[];
  findings: FindingRow[];
  warnings: WarningLine[];
  /** True once an `inferred-provenance` warning line arrived. */
  inferredProvenance: boolean;
  drop: DropState;
  protocol: ProtocolState;
}

/** Rows kept in the append-only views; bounded so a live feed cannot grow forever. */
const MAX_EVENT_ROWS = 4000;
const MAX_FINDING_ROWS = 1000;

export function createState(): LamassuState {
  return {
    sessions: new Map(),
    procs: new Map(),
    events: [],
    findings: [],
    warnings: [],
    inferredProvenance: false,
    drop: { dropTotal: 0, updFailTotal: 0, globalDrops: 0, lossy: false },
    protocol: { errors: 0, errorsDetail: [], duplicates: 0, lastSeq: 0 },
  };
}

function newSession(sid: string, harness: string, rootPid: number): SessionState {
  return {
    sid,
    harness,
    rootPid,
    open: true,
    tainted: false,
    taintOrigins: [],
    spans: [],
    findings: [],
    decision: null,
    events: 0,
    dropTotal: 0,
    updFailTotal: 0,
    counts: null,
  };
}

function sessionOf(state: LamassuState, sid: string): SessionState {
  let s = state.sessions.get(sid);
  if (!s) {
    s = newSession(sid, "", -1);
    state.sessions.set(sid, s);
  }
  return s;
}

function pushEvent(state: LamassuState, row: EventRow): void {
  state.events.push(row);
  if (state.events.length > MAX_EVENT_ROWS) state.events.splice(0, state.events.length - MAX_EVENT_ROWS);
}

function pushFinding(state: LamassuState, row: FindingRow): void {
  state.findings.push(row);
  if (state.findings.length > MAX_FINDING_ROWS) state.findings.splice(0, state.findings.length - MAX_FINDING_ROWS);
}

/** Insert-or-update a process node. A pid's identity is sticky: the first
 *  `comm`/`ppid` seen is kept unless a later exec changes them, and `tainted`
 *  is sticky-true, matching "every event emitted while tainted carries it". */
function touchProc(state: LamassuState, e: EventLine): void {
  const existing = state.procs.get(e.pid);
  const node: ProcNode = existing ?? {
    pid: e.pid,
    ppid: e.ppid,
    comm: e.comm,
    session: e.session,
    tainted: false,
    firstTs: e.ts,
    lastTs: e.ts,
    events: 0,
    alive: true,
  };
  node.ppid = e.ppid;
  if (e.comm) node.comm = e.comm;
  node.session = e.session;
  node.tainted = node.tainted || e.tainted;
  node.lastTs = Math.max(node.lastTs, e.ts);
  node.firstTs = Math.min(node.firstTs, e.ts);
  node.events += 1;
  if (e.kind === "exit") node.alive = false;
  else node.alive = true;
  state.procs.set(e.pid, node);
}

function applyEvent(state: LamassuState, line: EventLine): void {
  const session = sessionOf(state, line.session);
  session.events += 1;
  pushEvent(state, {
    seq: line.seq,
    session: line.session,
    kind: line.kind,
    ts: line.ts,
    pid: line.pid,
    ppid: line.ppid,
    comm: line.comm,
    cmdline: line.cmdline,
    filename: line.filename,
    port: line.port,
    addr: line.addr,
    flags: line.flags,
    tainted: line.tainted === true,
  });
  touchProc(state, line);
}

function applyFinding(state: LamassuState, line: FindingLine): void {
  const session = sessionOf(state, line.session);
  const row: FindingRow = {
    seq: line.seq,
    session: line.session,
    layer: line.layer,
    rule: line.rule,
    severity: line.severity,
    invariant: line.invariant === true,
    provenance: line.provenance,
    evidence_digest: line.evidence_digest,
    span_index: line.span_index,
    tainted: line.tainted === true,
    blockedBy: false,
  };
  session.findings.push(row);
  pushFinding(state, row);
}

function applySpan(state: LamassuState, line: Extract<StreamLine, { t: "span" }>): void {
  const session = sessionOf(state, line.session);
  const origin = line.origin ?? null;
  session.spans.push({
    seq: line.seq,
    session: line.session,
    trust: line.trust,
    origin,
    role: line.role ?? "",
    text_len: line.text_len ?? 0,
  });
  // Taint is derived, never set (§3): a data span is what taints a session.
  if (line.trust === "data") {
    session.tainted = true;
    if (origin) session.taintOrigins.push(origin);
  }
}

function applyDecision(state: LamassuState, line: Extract<StreamLine, { t: "decision" }>): void {
  const session = sessionOf(state, line.session);
  session.decision = line.decision;
  // An invariant finding is the only thing that can force BLOCK (§4). Mark the
  // findings that did, so the UI can say *why* rather than just *that*.
  if (line.decision === "block") {
    for (const f of session.findings) {
      if (f.invariant) {
        f.blockedBy = true;
        const global = state.findings.find((g) => g.seq === f.seq);
        if (global) global.blockedBy = true;
      }
    }
  }
}

function applyClose(state: LamassuState, line: Extract<StreamLine, { t: "session_close" }>): void {
  const session = sessionOf(state, line.session);
  session.open = false;
  const c = line.counts;
  if (c) {
    session.dropTotal = c.drop_total ?? 0;
    session.updFailTotal = c.upd_fail_total ?? 0;
    session.counts = { events: c.events ?? 0, findings: c.findings ?? 0 };
  }
  mergeDrops(state);
}

/** Session counters are cumulative per session; the UI shows the worst seen. */
function mergeDrops(state: LamassuState): void {
  let dropTotal = 0;
  let updFailTotal = 0;
  for (const s of state.sessions.values()) {
    dropTotal = Math.max(dropTotal, s.dropTotal);
    updFailTotal = Math.max(updFailTotal, s.updFailTotal);
  }
  // A global (un-owned) drop is not attributable to any session, so it is
  // merged separately rather than lost in the per-session maximum.
  dropTotal = Math.max(dropTotal, state.drop.globalDrops);
  state.drop.dropTotal = dropTotal;
  state.drop.updFailTotal = updFailTotal;
  state.drop.lossy = dropTotal > 0 || updFailTotal > 0;
}

export function ingest(state: LamassuState, line: StreamLine): LamassuState {
  const seq = typeof line.seq === "number" ? line.seq : 0;
  // §9: seq is monotonic. A line that is not newer is a duplicate/rewind; we
  // count it so a resyncing feed is visible instead of silently replayed.
  if (seq > 0 && seq <= state.protocol.lastSeq) {
    state.protocol.duplicates += 1;
    return state;
  }
  if (seq > 0) state.protocol.lastSeq = seq;

  switch (line.t) {
    case "session_open": {
      const s = sessionOf(state, line.session);
      s.harness = line.harness ?? s.harness;
      s.rootPid = line.root_pid ?? s.rootPid;
      s.open = true;
      // A session root is a process even before it execs anything, so the
      // tree shows it: the harness is what spawns everything else.
      if (!state.procs.has(s.rootPid)) {
        state.procs.set(s.rootPid, {
          pid: s.rootPid,
          ppid: 0,
          comm: s.harness || line.session,
          session: line.session,
          tainted: false,
          firstTs: 0,
          lastTs: 0,
          events: 0,
          alive: true,
        });
      }
      break;
    }
    case "session_close":
      applyClose(state, line);
      break;
    case "span":
      applySpan(state, line);
      break;
    case "event":
      applyEvent(state, line);
      break;
    case "finding":
      applyFinding(state, line);
      break;
    case "decision":
      applyDecision(state, line);
      break;
    case "warning": {
      state.warnings.push(line);
      if (line.code === WARNING_INFERRED_PROVENANCE) state.inferredProvenance = true;
      if (line.code === WARNING_EVENTS_DROPPED) {
        // The core dropped events and said so. Without this the UI would show an
        // intact record for an incomplete run, which is the exact failure the
        // drop counters exist to prevent.
        state.drop.globalDrops += line.drop_total ?? 0;
        mergeDrops(state);
      }
      break;
    }
    default: {
      state.protocol.errors += 1;
      const t = (line as { t?: unknown }).t;
      state.protocol.errorsDetail.push(`unknown line type: ${String(t)}`);
      break;
    }
  }
  return state;
}

export function ingestAll(state: LamassuState, lines: StreamLine[]): LamassuState {
  for (const line of lines) ingest(state, line);
  return state;
}

/** Parse one JSONL line. Returns an error string rather than throwing so the
 *  caller can attribute a bad line instead of dropping the whole transcript. */
export function parseLine(raw: string): StreamLine | { error: string } {
  const text = raw.trim();
  if (!text) return { error: "empty line" };
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (err) {
    return { error: `malformed JSON: ${(err as Error).message}` };
  }
  if (typeof obj !== "object" || obj === null || typeof (obj as { t?: unknown }).t !== "string") {
    return { error: "line is not an object with a string `t`" };
  }
  return obj as StreamLine;
}

/** Parse a whole transcript (a `.jsonl` file body) into state. */
export function ingestText(state: LamassuState, body: string): LamassuState {
  for (const raw of body.split(/\r?\n/)) {
    if (!raw.trim()) continue;
    const parsed = parseLine(raw);
    if ("error" in parsed) {
      state.protocol.errors += 1;
      state.protocol.errorsDetail.push(parsed.error);
      continue;
    }
    ingest(state, parsed);
  }
  return state;
}

/**
 * Flatten the process map into a depth-first tree, in event order.
 * Roots are nodes whose parent is not itself tracked; a node whose parent
 * appears only later is still parented correctly because the ordering pass
 * runs after the whole stream has been folded in.
 */
export function procTree(state: LamassuState): ProcTreeNode[] {
  const children = new Map<number, number[]>();
  const rows = [...state.procs.values()].sort((a, b) => a.pid - b.pid);
  for (const n of rows) {
    const kids = children.get(n.ppid) ?? [];
    kids.push(n.pid);
    children.set(n.ppid, kids);
  }
  const roots = rows.filter((n) => !state.procs.has(n.ppid) || n.ppid === n.pid).map((n) => n.pid);
  const out: ProcTreeNode[] = [];
  const seen = new Set<number>();
  const walk = (pid: number, depth: number): void => {
    if (seen.has(pid)) return; // pid-reuse cycle guard
    seen.add(pid);
    const node = state.procs.get(pid);
    if (!node) return;
    out.push({ ...node, depth });
    for (const kid of children.get(pid) ?? []) walk(kid, depth + 1);
  };
  for (const r of roots) walk(r, 0);
  for (const n of rows) if (!seen.has(n.pid)) walk(n.pid, 0); // orphans
  return out;
}

/** The canary row is the loudest thing in the app; it is not just a finding. */
export function canaryHits(state: LamassuState): FindingRow[] {
  return state.findings.filter((f) => f.layer === "egress" && f.rule === "canary-leak");
}

export interface TaintedSession {
  sid: string;
  harness: string;
  rootPid: number;
  origins: Origin[];
  /** Events emitted while tainted, per the per-event flag. */
  taintedEvents: number;
  decision: Decision | null;
}

/** Sessions that ingested a `data` span, and the origins that tainted them. */
export function taintedSessions(state: LamassuState): TaintedSession[] {
  const out: TaintedSession[] = [];
  for (const s of state.sessions.values()) {
    if (!s.tainted) continue;
    out.push({
      sid: s.sid,
      harness: s.harness,
      rootPid: s.rootPid,
      origins: s.taintOrigins,
      taintedEvents: state.events.filter((e) => e.session === s.sid && e.tainted).length,
      decision: s.decision,
    });
  }
  return out;
}

export interface ProvenanceSplit {
  declared: FindingRow[];
  inferred: FindingRow[];
}

/** Declared vs inferred, per finding — never merged into one number. */
export function provenanceSplit(state: LamassuState): ProvenanceSplit {
  return {
    declared: state.findings.filter((f) => f.provenance === "declared"),
    inferred: state.findings.filter((f) => f.provenance === "inferred"),
  };
}

export function sessionsInOrder(state: LamassuState): SessionState[] {
  return [...state.sessions.values()].sort((a, b) => {
    const ao = a.rootPid;
    const bo = b.rootPid;
    if (ao !== bo) return ao - bo;
    return a.sid.localeCompare(b.sid);
  });
}
