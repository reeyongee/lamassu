/**
 * Shared test helpers. The fixture is the package's own copy of a §9 stream,
 * so these tests are self-contained: they do not depend on `replay/` existing
 * or on any Linux host.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createState, ingestText, type LamassuState } from "../src/reducer.js";

/** Resolve the fixture without assuming the transform kept a file: URL. */
function locateFixture(): string {
  const candidates: string[] = [];
  if (import.meta.url.startsWith("file:")) {
    candidates.push(resolve(dirname(fileURLToPath(import.meta.url)), "../fixtures/stream.sample.jsonl"));
  }
  let dir = process.cwd();
  for (let i = 0; i < 4; i += 1) {
    candidates.push(resolve(dir, "fixtures/stream.sample.jsonl"));
    dir = dirname(dir);
  }
  for (const c of candidates) if (existsSync(c)) return c;
  throw new Error(`stream.sample.jsonl not found; tried ${candidates.join(", ")}`);
}

export const SAMPLE_PATH = locateFixture();

export function sampleBody(): string {
  return readFileSync(SAMPLE_PATH, "utf8");
}

export function sampleState(): LamassuState {
  return ingestText(createState(), sampleBody());
}
