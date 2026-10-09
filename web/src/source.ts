/**
 * The transport: a WebSocket when one is available, and a `.jsonl` file
 * always.
 *
 * The file path is the primary one, not a fallback. On macOS the BPF sensor
 * cannot run at all (no eBPF), so a transcript captured elsewhere is the
 * normal way to drive this UI during development. Nothing here is mocked:
 * the file is the same §9 stream the live socket carries.
 */

import type { StreamLine } from "./stream.js";
import { parseLine } from "./reducer.js";

export type SourceKind = "file" | "websocket";

export interface SourceStatus {
  kind: SourceKind;
  label: string;
  state: "idle" | "loading" | "live" | "closed" | "error";
  detail: string;
  received: number;
}

export interface StreamSource {
  readonly kind: SourceKind;
  readonly status: SourceStatus;
  start(): void;
  stop(): void;
}

type LineSink = (line: StreamLine) => void;
type StatusSink = (status: SourceStatus) => void;
type ErrorSink = (message: string) => void;

/** Fold a whole transcript body through `sink`. Synchronous and pure of I/O. */
export function feedText(
  body: string,
  sink: LineSink,
  onError: ErrorSink,
): number {
  let count = 0;
  for (const raw of body.split(/\r?\n/)) {
    if (!raw.trim()) continue;
    const parsed = parseLine(raw);
    if ("error" in parsed) {
      onError(parsed.error);
      continue;
    }
    sink(parsed);
    count += 1;
  }
  return count;
}

export class FileSource implements StreamSource {
  readonly kind = "file" as const;
  status: SourceStatus;

  constructor(
    private readonly name: string,
    private readonly body: string,
    private readonly sink: LineSink,
    private readonly onStatus: StatusSink,
    private readonly onError: ErrorSink,
  ) {
    this.status = { kind: "file", label: name, state: "idle", detail: "loaded", received: 0 };
  }

  start(): void {
    this.status = { ...this.status, state: "loading" };
    this.onStatus(this.status);
    const received = feedText(this.body, this.sink, this.onError);
    this.status = {
      kind: "file",
      label: this.name,
      state: "closed",
      detail: `replayed ${received} lines`,
      received,
    };
    this.onStatus(this.status);
  }

  stop(): void {
    /* nothing to tear down */
  }
}

/** Read a `.jsonl` from a `File` (or any Blob) and replay it. */
export async function fileSourceFromBlob(
  file: { name: string; text(): Promise<string> },
  sink: LineSink,
  onStatus: StatusSink,
  onError: ErrorSink,
): Promise<FileSource> {
  const body = await file.text();
  return new FileSource(file.name, body, sink, onStatus, onError);
}

export class WebSocketSource implements StreamSource {
  readonly kind = "websocket" as const;
  status: SourceStatus;
  private ws: WebSocket | null = null;

  constructor(
    private readonly url: string,
    private readonly sink: LineSink,
    private readonly onStatus: StatusSink,
    private readonly onError: ErrorSink,
    /** Injection seam so the socket path is testable without a live server. */
    private readonly make: (url: string) => WebSocket = (u) => new WebSocket(u),
  ) {
    this.status = { kind: "websocket", label: url, state: "idle", detail: "connecting", received: 0 };
  }

  start(): void {
    const ws = this.make(this.url);
    this.ws = ws;
    this.status = { ...this.status, state: "loading" };
    this.onStatus(this.status);

    ws.onopen = () => {
      this.status = { ...this.status, state: "live", detail: "connected" };
      this.onStatus(this.status);
    };
    ws.onmessage = (ev: MessageEvent) => {
      const data = typeof ev.data === "string" ? ev.data : String(ev.data);
      // A socket frame may carry one line or a batch; both are fine.
      const received = feedText(data, this.sink, this.onError);
      this.status = { ...this.status, received: this.status.received + received };
      this.onStatus(this.status);
    };
    ws.onerror = () => {
      // Do not claim the socket is working when it is not: the UI says the
      // file path is still available. §9 warnings are data; this is transport.
      this.status = { ...this.status, state: "error", detail: `could not connect to ${this.url}` };
      this.onStatus(this.status);
      this.onError(`websocket error: ${this.url}`);
    };
    ws.onclose = (ev: CloseEvent) => {
      this.status = {
        ...this.status,
        state: "closed",
        detail: `closed (${ev.code}${ev.reason ? `: ${ev.reason}` : ""})`,
      };
      this.onStatus(this.status);
    };
  }

  stop(): void {
    this.ws?.close();
    this.ws = null;
  }
}

export function defaultSocketUrl(loc: { protocol: string; host: string } = window.location): string {
  const proto = loc.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${loc.host}/stream`;
}
