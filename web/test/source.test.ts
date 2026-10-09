/**
 * Transport tests. Two paths, both first class: the `.jsonl` file (the normal
 * dev loop on macOS, where the BPF sensor cannot run) and the WebSocket (a
 * Linux host). The socket is exercised through an injected factory — no live
 * server — because the point under test is what we do with what arrives, and
 * what we say when nothing does.
 */

import { describe, expect, it, vi } from "vitest";
import {
  defaultSocketUrl,
  feedText,
  FileSource,
  WebSocketSource,
  type SourceStatus,
} from "../src/source.js";
import type { StreamLine } from "../src/stream.js";
import { sampleBody } from "./fixture.js";

class FakeSocket {
  onopen: ((ev: Event) => unknown) | null = null;
  onmessage: ((ev: MessageEvent) => unknown) | null = null;
  onerror: ((ev: Event) => unknown) | null = null;
  onclose: ((ev: CloseEvent) => unknown) | null = null;
  closed = false;

  close(): void {
    this.closed = true;
  }

  emitOpen(): void {
    this.onopen?.(new Event("open"));
  }

  emitData(body: string): void {
    this.onmessage?.({ data: body } as MessageEvent);
  }

  emitError(): void {
    this.onerror?.(new Event("error"));
  }

  emitClose(code = 1000, reason = ""): void {
    this.onclose?.({ code, reason } as CloseEvent);
  }
}

describe("feedText", () => {
  it("splits a body into lines and reports the count", () => {
    const lines: StreamLine[] = [];
    const count = feedText(sampleBody(), (l) => lines.push(l), () => {});
    expect(count).toBe(30);
    expect(lines.length).toBe(30);
    expect(lines[0]?.t).toBe("session_open");
  });

  it("routes a bad line to onError and keeps the good ones", () => {
    const lines: StreamLine[] = [];
    const errors: string[] = [];
    const count = feedText(
      ['{"seq":1,"t":"session_open","session":"s","root_pid":1}', "{oops", ""].join("\n"),
      (l) => lines.push(l),
      (e) => errors.push(e),
    );
    expect(count).toBe(1);
    expect(lines).toHaveLength(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("malformed JSON");
  });
});

describe("FileSource: the primary path", () => {
  it("replays a transcript and reports how many lines it read", () => {
    const seen: StreamLine[] = [];
    const statuses: SourceStatus[] = [];
    const src = new FileSource("stream.sample.jsonl", sampleBody(), (l) => seen.push(l), (s) => statuses.push(s), () => {});
    src.start();
    expect(seen).toHaveLength(30);
    expect(src.status.state).toBe("closed");
    expect(src.status.received).toBe(30);
    expect(src.status.detail).toContain("replayed 30 lines");
    expect(statuses.at(-1)?.state).toBe("closed");
  });

  it("is not a mock: it is the same stream the socket carries", () => {
    const seen: StreamLine[] = [];
    new FileSource("x", sampleBody(), (l) => seen.push(l), () => {}, () => {}).start();
    const kinds = new Set(seen.map((l) => l.t));
    expect([...kinds].sort()).toEqual(
      ["decision", "event", "finding", "session_close", "session_open", "span", "warning"].sort(),
    );
  });
});

describe("WebSocketSource", () => {
  it("folds frames into lines and reports live then closed", () => {
    const fake = new FakeSocket();
    const seen: StreamLine[] = [];
    const statuses: SourceStatus[] = [];
    const src = new WebSocketSource(
      "ws://localhost:5173/stream",
      (l) => seen.push(l),
      (s) => statuses.push(s),
      () => {},
      () => fake as unknown as WebSocket,
    );
    src.start();
    expect(src.status.state).toBe("loading");
    fake.emitOpen();
    expect(src.status.state).toBe("live");
    fake.emitData(`{"seq":1,"t":"session_open","session":"s","root_pid":1}\n{"seq":2,"t":"decision","session":"s","decision":"allow"}`);
    expect(seen).toHaveLength(2);
    expect(src.status.received).toBe(2);
    fake.emitClose(1006, "host down");
    expect(src.status.state).toBe("closed");
    expect(src.status.detail).toContain("1006");
    expect(statuses.some((s) => s.state === "live")).toBe(true);
  });

  it("reports a failed connection instead of pretending to be live", () => {
    const fake = new FakeSocket();
    const errors: string[] = [];
    const src = new WebSocketSource(
      "ws://nope:9/stream",
      () => {},
      () => {},
      (e) => errors.push(e),
      () => fake as unknown as WebSocket,
    );
    src.start();
    fake.emitError();
    expect(src.status.state).toBe("error");
    expect(src.status.detail).toContain("could not connect");
    expect(errors).toHaveLength(1);
  });

  it("closes the underlying socket on stop", () => {
    const fake = new FakeSocket();
    const src = new WebSocketSource(
      "ws://localhost/stream",
      () => {},
      () => {},
      () => {},
      () => fake as unknown as WebSocket,
    );
    src.start();
    src.stop();
    expect(fake.closed).toBe(true);
  });
});

describe("defaultSocketUrl", () => {
  it("picks ws on http and wss on https", () => {
    expect(defaultSocketUrl({ protocol: "http:", host: "localhost:5173" })).toBe("ws://localhost:5173/stream");
    expect(defaultSocketUrl({ protocol: "https:", host: "box:8443" })).toBe("wss://box:8443/stream");
  });

  it("defaults to the current location", () => {
    const url = defaultSocketUrl();
    expect(url).toMatch(/^wss?:\/\/.+\/stream$/);
    vi.unstubAllGlobals();
  });
});
