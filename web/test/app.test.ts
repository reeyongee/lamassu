/**
 * End-to-end through the app shell: a real jsdom document, the real template,
 * the real reducer and renderer. No mocks of the pipeline itself — only the
 * WebSocket constructor is substituted, and only so the test does not need a
 * server. This is the test that proves the user-visible requirement: the page
 * shows a tainted process, an invariant finding that is not a scored one, a
 * canary row, and a drop warning, from the shipped fixture.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createApp, panelsHtml, type AppHandle } from "../src/main.js";
import { sampleBody } from "./fixture.js";

let root: HTMLElement;
let app: AppHandle;

beforeEach(() => {
  document.body.innerHTML = "";
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(root);
});

describe("replaying the fixture through the app", () => {
  beforeEach(() => {
    app.replay(sampleBody(), "stream.sample.jsonl");
  });

  it("renders a node for a tainted process", () => {
    const tainted = root.querySelectorAll('[data-testid="proc-node"][data-tainted="true"]');
    expect(tainted.length).toBeGreaterThan(0);
    expect(root.querySelector('[data-testid="proc-node"][data-pid="4312"]')?.textContent).toContain("TAINTED");
  });

  it("renders an invariant finding with the invariant marker", () => {
    const row = root.querySelector('[data-testid="finding-row"][data-invariant="true"]');
    expect(row).not.toBeNull();
    expect(row?.querySelector('[data-mark="invariant"]')).not.toBeNull();
    expect(row?.textContent).toContain("INVARIANT");
  });

  it("renders a canary-hit row", () => {
    const rows = root.querySelectorAll('[data-testid="canary-row"]');
    expect(rows.length).toBe(1);
    expect(rows[0]?.textContent).toContain("5e1d0a9b8c7f6e5d");
  });

  it("renders a non-zero drop-counter warning", () => {
    const loss = root.querySelector('[data-testid="banner-loss"]');
    expect(loss).not.toBeNull();
    expect(loss?.textContent).toContain("drop_total=3");
  });

  it("renders the inferred-provenance banner", () => {
    expect(root.querySelector('[data-testid="banner-inferred"]')).not.toBeNull();
  });

  it("does NOT put the invariant marker on a scored finding", () => {
    const row = root.querySelector('[data-testid="finding-row"][data-rule="data-imperative"]');
    expect(row).not.toBeNull();
    expect(row?.getAttribute("data-invariant")).toBe("false");
    expect(row?.querySelector('[data-mark="invariant"]')).toBeNull();
    expect(row?.querySelector('[data-mark="scored"]')).not.toBeNull();
    expect(row?.textContent).not.toContain("INVARIANT");
  });

  it("reports the file as the source, not the socket", () => {
    const status = root.querySelector('[data-testid="source-status"]');
    expect(status?.getAttribute("data-kind")).toBe("file");
    expect(status?.textContent).toContain("stream.sample.jsonl");
    expect(status?.textContent).toContain("replayed");
  });

  it("shows every one of the seven surfaces", () => {
    for (const name of ["tree", "events", "findings", "taint", "canary", "provenance", "sessions"]) {
      expect(root.querySelector(`[data-panel="${name}"]`), name).not.toBeNull();
    }
  });
});

describe("streaming through the app", () => {
  it("updates the document as lines arrive over a socket", () => {
    const fake: { onopen: unknown; onmessage: unknown; onerror: unknown; onclose: unknown; close(): void } = {
      onopen: null,
      onmessage: null,
      onerror: null,
      onclose: null,
      close() {},
    };
    app.connect("ws://localhost:5173/stream", () => fake as unknown as WebSocket);
    (fake.onopen as (ev: Event) => void)(new Event("open"));
    expect(root.querySelector('[data-testid="source-status"]')?.getAttribute("data-state")).toBe("live");

    (fake.onmessage as (ev: MessageEvent) => void)({
      data: sampleBody(),
    } as MessageEvent);

    expect(root.querySelectorAll('[data-testid="proc-node"]').length).toBeGreaterThan(0);
    expect(root.querySelector('[data-testid="canary-row"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="banner-loss"]')).not.toBeNull();
  });

  it("says so when the socket cannot connect, rather than showing an empty feed as success", () => {
    const fake: { onopen: unknown; onmessage: unknown; onerror: unknown; onclose: unknown; close(): void } = {
      onopen: null,
      onmessage: null,
      onerror: null,
      onclose: null,
      close() {},
    };
    app.connect("ws://nope:9/stream", () => fake as unknown as WebSocket);
    (fake.onerror as (ev: Event) => void)(new Event("error"));
    expect(root.querySelector('[data-testid="source-status"]')?.getAttribute("data-state")).toBe("error");
    const banner = root.querySelector('[data-testid="banner-protocol"]');
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain("websocket error");
  });
});

describe("panelsHtml and the static shell", () => {
  it("renders the panels and the status bar, and starts empty", () => {
    const html = panelsHtml(app.state);
    expect(html).toContain("Process tree");
    expect(html).toContain("nothing fired");
    expect(html).toContain("no events yet");
    expect(html).toContain("lamassu");
  });

  it("does not include the toolbar, so repainting cannot reset it", () => {
    // index.html owns the toolbar. If paint() rewrote it, the WebSocket URL
    // would be cleared while the user is typing it.
    const html = panelsHtml(app.state);
    expect(html).not.toContain(`id="ws-url"`);
    expect(html).not.toContain(`id="load-fixture"`);
  });

  it("leaves a toolbar that lives outside the repainted region untouched", () => {
    document.body.innerHTML = `<div class="toolbar"><input id="ws-url" value="ws://linux-box:5173/stream"></div>`;
    const live = document.createElement("div");
    document.body.append(live);
    const a = createApp(live);
    a.replay(sampleBody(), "sample.jsonl");
    const typed = document.querySelector<HTMLInputElement>("#ws-url");
    expect(typed?.value).toBe("ws://linux-box:5173/stream");
    expect(live.querySelector('[data-testid="canary-row"]')).not.toBeNull();
  });
});
