/**
 * The wire types of the lamassu §9 stream.
 *
 * The stream is the ONLY interface this frontend consumes. Every field here
 * is named exactly as CONTRACTS.md §9 names it; an unknown `t` is a
 * protocol error the reducer reports, never silently ignored (a feed that
 * quietly dropped lines we cannot parse would be exactly the failure mode
 * §8 forbids).
 */

export type Trust = "system" | "user" | "data";
export type EventKind = "exec" | "exit" | "open" | "net";
export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Decision = "allow" | "block";
export type Provenance = "declared" | "inferred";

export interface SessionOpenLine {
  seq: number;
  t: "session_open";
  session: string;
  harness?: string;
  root_pid: number;
}

export interface SessionCloseLine {
  seq: number;
  t: "session_close";
  session: string;
  counts?: {
    events?: number;
    findings?: number;
    drop_total?: number;
    upd_fail_total?: number;
  };
}

export interface Origin {
  channel: string;
  ref: string;
}

export interface SpanLine {
  seq: number;
  t: "span";
  session: string;
  trust: Trust;
  origin?: Origin;
  role?: string;
  text_len?: number;
}

export interface EventLine {
  seq: number;
  t: "event";
  session: string;
  kind: EventKind;
  ts: number;
  pid: number;
  ppid: number;
  comm: string;
  cmdline: string;
  filename: string;
  flags: number;
  dirfd: number;
  port: number;
  addr: string;
  tainted: boolean;
}

export interface FindingLine {
  seq: number;
  t: "finding";
  session: string;
  layer: string;
  rule: string;
  severity: Severity;
  /** Structural guarantee (true) vs heuristic score (false). Never alike. */
  invariant: boolean;
  provenance: Provenance;
  /** Truncated hash; the stream carries no raw matched text. */
  evidence_digest: string;
  span_index: number;
  tainted?: boolean;
}

export interface DecisionLine {
  seq: number;
  t: "decision";
  session: string;
  decision: Decision;
  findings?: FindingLine[];
}

export interface WarningLine {
  seq: number;
  t: "warning";
  code: string;
  message?: string;
  /** Present on `events-dropped`: how many events the core could not attribute
   *  to any session. Carried in the stream so the loss is visible to the UI and
   *  not only in the core's exit summary. */
  drop_total?: number;
}

export type StreamLine =
  | SessionOpenLine
  | SessionCloseLine
  | SpanLine
  | EventLine
  | FindingLine
  | DecisionLine
  | WarningLine;

/** Non-zero drop counters must be loud: they mean events were lost. */
export const WARNING_INFERRED_PROVENANCE = "inferred-provenance";

/** A warning line the core emits when events were dropped: the feed is lossy.
 *  It must be distinguishable from "nothing fired" — that is the project's
 *  central honesty rule, and a stderr-only count would hide it from this UI. */
export const WARNING_EVENTS_DROPPED = "events-dropped";
