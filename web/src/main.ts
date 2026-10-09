/**
 * The application shell: the only module that touches the DOM.
 *
 * It owns one `LamassuState`, feeds it from a file or a socket, and repaints
 * `renderRoot(state)` into the root element. All the meaning lives in
 * `reducer.ts` and `render.ts`; this file is glue, kept small on purpose so
 * the interesting behaviour stays testable without a document.
 */

import type { LamassuState } from "./reducer.js";
import { createState, ingest, ingestText, sessionsInOrder } from "./reducer.js";
import { renderRoot } from "./render.js";
import { esc } from "./format.js";
import { defaultSocketUrl, type SourceStatus, type StreamSource, WebSocketSource } from "./source.js";
import type { StreamLine } from "./stream.js";
// Bundled as a string: the sample is part of the package, so the button cannot
// 404 on a deploy and leave a quiet, empty-looking feed behind a working UI.
import SAMPLE_TRANSCRIPT from "../fixtures/stream.sample.jsonl?raw";

export interface AppHandle {
  state: LamassuState;
  /** Replay a whole `.jsonl` body. The primary path on macOS. */
  replay(body: string, name?: string): void;
  /** Fold one already-parsed line in (used by the socket path and tests). */
  push(line: StreamLine): void;
  /** Connect a WebSocket; failures are surfaced, not hidden. `make` is the
   *  injection seam used by the tests to exercise the socket path offline. */
  connect(url?: string, make?: (url: string) => WebSocket): void;
  paint(): void;
}

function statusBar(status: SourceStatus | null, state: LamassuState): string {
  if (!status) return "";
  const cls =
    status.state === "error" ? "src-error" : status.state === "live" ? "src-live" : status.state === "closed" ? "src-closed" : "src-idle";
  return `<div class="statusbar">
    <span class="src ${cls}" data-testid="source-status" data-state="${esc(status.state)}" data-kind="${esc(status.kind)}">
      ${esc(status.kind)}: ${esc(status.label)} — ${esc(status.detail)}
    </span>
    <span class="seq" data-testid="seq">last seq ${state.protocol.lastSeq}</span>
    <span class="sessions">${sessionsInOrder(state).length} session(s)</span>
  </div>`;
}

/**
 * What `paint()` writes: the status bar, the heading, and the seven panels.
 * The toolbar is deliberately NOT part of this — it lives in `index.html` and
 * is never repainted, because repainting the live region would reset the
 * WebSocket URL input while it is being typed and drop a chosen file.
 */
export function panelsHtml(state: LamassuState, status: SourceStatus | null = null): string {
  return `${statusBar(status, state)}
    <header class="head">
      <h1>lamassu <span class="sub">realtime</span></h1>
      <p class="tagline">What the session ran, what it opened, what it dialed — and what the firewall did about it.</p>
    </header>
    ${renderRoot(state)}`;
}

export function createApp(root: HTMLElement): AppHandle {
  let state = createState();
  let current: StreamSource | null = null;
  let latest: SourceStatus | null = null;

  const paint = (): void => {
    root.innerHTML = panelsHtml(state, latest);
  };

  const err = (message: string): void => {
    state.protocol.errors += 1;
    state.protocol.errorsDetail.push(message);
    paint();
  };

  return {
    get state() {
      return state;
    },
    paint,
    replay(body: string, name = "transcript.jsonl"): void {
      stop();
      state = createState();
      latest = { kind: "file", label: name, state: "loading", detail: "reading", received: 0 };
      paint();
      let received = 0;
      for (const raw of body.split(/\r?\n/)) {
        if (!raw.trim()) continue;
        received += 1;
      }
      ingestText(state, body);
      latest = { kind: "file", label: name, state: "closed", detail: `replayed ${received} lines`, received };
      paint();
    },
    push(line: StreamLine): void {
      ingest(state, line);
      paint();
    },
    connect(url = defaultSocketUrl(), make?: (url: string) => WebSocket): void {
      stop();
      state = createState();
      current = new WebSocketSource(
        url,
        (line) => {
          ingest(state, line);
          paint();
        },
        (s) => {
          latest = s;
          paint();
        },
        err,
        make,
      );
      latest = current.status;
      current.start();
      paint();
    },
  };

  function stop(): void {
    current?.stop();
    current = null;
  }
}

/** Boot from the page: file first, then optionally the socket. */
export function boot(root: HTMLElement): AppHandle {
  const app = createApp(root);
  app.paint();

  const fileInput = document.querySelector<HTMLInputElement>("#file");
  const loadFixture = document.querySelector<HTMLButtonElement>("#load-fixture");
  const openSocket = document.querySelector<HTMLButtonElement>("#connect");
  const urlInput = document.querySelector<HTMLInputElement>("#ws-url");
  const status = document.querySelector<HTMLElement>("#source-note");

  fileInput?.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    void file.text().then((body) => app.replay(body, file.name));
  });

  loadFixture?.addEventListener("click", () => {
    // The shipped transcript is bundled, not fetched, so the button cannot
    // silently 404 and leave the page looking like a working but empty feed.
    app.replay(SAMPLE_TRANSCRIPT, "fixtures/stream.sample.jsonl");
    if (status) status.textContent = "replayed the bundled sample transcript";
  });

  openSocket?.addEventListener("click", () => {
    app.connect(urlInput?.value || defaultSocketUrl());
  });

  // `?ws=ws://linux-box:5173/stream` connects on load, so the socket path is
  // as easy to reach as the file path. `?fixture=1` replays the shipped sample
  // the same way. Neither hides which source is in use: the status bar says so.
  const params = new URLSearchParams(window.location.search);
  const wsParam = params.get("ws");
  if (wsParam) {
    if (urlInput) urlInput.value = wsParam;
    app.connect(wsParam);
  } else if (params.has("fixture")) {
    app.replay(SAMPLE_TRANSCRIPT, "fixtures/stream.sample.jsonl");
  }

  return app;
}

const rootEl = document.querySelector<HTMLElement>("#app");
if (rootEl) {
  const w = window as unknown as { lamassu?: AppHandle };
  w.lamassu = boot(rootEl);
}
