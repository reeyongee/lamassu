/**
 * Cross-slice integration: the transcript that `replay/replay.c` actually
 * produced, rendered by the real app shell.
 *
 * This is the only test that proves the two halves agree. The unit tests use a
 * hand-written fixture; if replay and the frontend drifted apart in a field name
 * or a line type, every unit test would still pass and the system would be broken.
 * So the fixture here is generated, not authored:
 *
 *   cd .. && ./replay/run.sh replay/fixtures/events.jsonl replay/fixtures/spans.jsonl > web/fixtures/replay-transcript.jsonl
 *
 * A field rename in the core or in the renderer fails this test.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createApp, type AppHandle } from "../src/main.js";

const here = dirname(fileURLToPath(import.meta.url));
const transcript = readFileSync(join(here, "..", "fixtures", "replay-transcript.jsonl"), "utf8");

let root: HTMLElement;
let app: AppHandle;

beforeEach(() => {
  document.body.innerHTML = "";
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(root);
});

describe("the real replay transcript", () => {
  it("folds with zero unreadable lines", () => {
    app.replay(transcript, "replay-transcript.jsonl");
    // app.replay returns void; an unreadable line is surfaced as a banner, and
    // its absence is the assertion that every line was understood.
    expect(root.querySelector('[data-testid="banner-protocol"]')).toBeNull();
  });

  it("renders the process tree with the tainted nodes replay marked", () => {
    app.replay(transcript, "replay-transcript.jsonl");
    const nodes = root.querySelectorAll('[data-testid="proc-node"]');
    expect(nodes.length).toBeGreaterThan(0);
    // replay marked tainted=true on events of a tainted session; the tree must
    // carry the same marking through, not invent or drop it
    expect(root.querySelectorAll('[data-testid="proc-node"][data-tainted="true"]').length)
      .toBeGreaterThan(0);
  });

  it("renders both kinds of finding, and never conflates them", () => {
    app.replay(transcript, "replay-transcript.jsonl");
    expect(root.querySelectorAll('[data-testid="finding-row"][data-invariant="true"]').length)
      .toBeGreaterThan(0);
    // A scored finding must never carry the blocking label.
    for (const row of root.querySelectorAll('[data-testid="finding-row"][data-invariant="false"]')) {
      expect(row.querySelector('[data-mark="invariant"]')).toBeNull();
    }
  });

  it("surfaces the canary hit replay detected", () => {
    app.replay(transcript, "replay-transcript.jsonl");
    expect(root.querySelectorAll('[data-testid="canary-row"]').length).toBeGreaterThan(0);
  });

  it("shows the drop counter replay reported", () => {
    app.replay(transcript, "replay-transcript.jsonl");
    const loss = root.querySelector('[data-testid="banner-loss"]');
    expect(loss).not.toBeNull();
    // replay's count table reported drop_total=1; the UI must not round it to nothing
    expect(loss?.textContent).toContain("drop_total=1");
  });

  it("renders every event kind the sensor emits", () => {
    app.replay(transcript, "replay-transcript.jsonl");
    const kinds = new Set(
      [...root.querySelectorAll('[data-testid="event-row"]')].map(
        (r) => (r as HTMLElement).dataset.kind ?? "",
      ),
    );
    for (const k of ["exec", "exit", "open", "net"]) expect(kinds.has(k)).toBe(true);
  });
});
