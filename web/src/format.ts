/**
 * Formatting and escaping, shared by every view.
 *
 * The stream is untrusted: a cmdline or filename can contain anything the
 * audited process put there. Everything that reaches innerHTML goes through
 * `esc`, and control characters are neutralised first, exactly as
 * the audit sensor does before rendering a record (feed.js `scrub`, upstream
 * README "What you're looking at"). A crafted path must not be able to forge
 * a row or inject markup.
 */

import type { EventKind, Severity } from "./stream.js";

export function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Control characters become visible escapes instead of invisible payloads. */
export function scrub(s: string): string {
  return s.replace(/[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/g, (c) => {
    const code = c.charCodeAt(0).toString(16).padStart(2, "0");
    return `\\x${code}`;
  });
}

/** Untrusted text -> safe HTML: scrub first, then escape. */
export function safe(s: string | null | undefined): string {
  return esc(scrub(s ?? ""));
}

export function fmtTs(ts: number): string {
  if (!ts || ts <= 0) return "—";
  const d = new Date(ts);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

const KIND_LABEL: Record<EventKind, string> = {
  exec: "exec",
  exit: "exit",
  open: "open",
  net: "net",
};

export function kindLabel(kind: EventKind): string {
  return KIND_LABEL[kind] ?? String(kind);
}

const SEVERITY_CLASS: Record<Severity, string> = {
  INFO: "sev-info",
  LOW: "sev-low",
  MEDIUM: "sev-medium",
  HIGH: "sev-high",
  CRITICAL: "sev-critical",
};

export function severityClass(sev: Severity): string {
  return SEVERITY_CLASS[sev] ?? "sev-info";
}

export const INVARIANT_MARK_TEXT = "INVARIANT";
export const SCORED_MARK_TEXT = "scored";

export const INVARIANT_EXPLAINER =
  "structural guarantee: the finding forced the decision, no threshold compared";
export const SCORED_EXPLAINER =
  "heuristic score: compared against the policy threshold, may not have forced the decision";

/** The marker chip. Invariant and scored MUST never look alike. */
export function markChip(invariant: boolean): string {
  return invariant
    ? `<span class="mark mark-invariant" data-mark="invariant" title="${esc(INVARIANT_EXPLAINER)}">! ${INVARIANT_MARK_TEXT}</span>`
    : `<span class="mark mark-scored" data-mark="scored" title="${esc(SCORED_EXPLAINER)}">~ ${SCORED_MARK_TEXT}</span>`;
}

/**
 * A truncated digest is all the stream carries — never the raw matched text
 * (§2, PIP tests/test_audit.py). We render the digest only, and say so.
 */
export function digestChip(digest: string): string {
  if (!digest) return `<span class="digest digest-absent" title="no digest on this line">no digest</span>`;
  return `<span class="digest" title="truncated evidence hash — raw matched text never leaves the core">${esc(digest)}</span>`;
}

export function fmtCount(n: number): string {
  return n.toLocaleString("en-US");
}

/** One event detail string, mirroring the audit sensor's per-class detail column. */
export function eventDetail(row: {
  kind: EventKind;
  comm: string;
  cmdline: string;
  filename: string;
  port: number;
  addr: string;
  flags: number;
}): string {
  switch (row.kind) {
    case "exec":
      return `${safe(row.cmdline.trim() || row.filename)}`;
    case "exit":
      return `${safe(row.comm)} exited`;
    case "open": {
      const acc = row.flags & 0o3;
      const mode = acc === 1 ? "w" : acc === 2 ? "rw" : "r";
      const plus = row.flags & 0o100 ? "+" : "";
      return `<span class="mode">(${mode}${plus})</span> ${safe(row.filename)}`;
    }
    case "net": {
      const peer = row.addr ? `${row.addr}:${row.port}` : `:${row.port}`;
      return `${safe(row.comm)} → <span class="peer">${safe(peer)}</span>`;
    }
  }
}
