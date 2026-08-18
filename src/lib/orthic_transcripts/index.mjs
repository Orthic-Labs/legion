// JavaScript surface for tools/lib/orthic_transcripts (plan 5.1).
//
// The shared substrate is implemented in Python (the file under
// tools/lib/orthic_transcripts/*.py) so Handoff, Taste, and Insights can all
// consume identical byte spans + event IDs without forking the parser. This
// shim spawns the Python parser over a temporary file and returns parsed
// JSON, so the e2e-7-shared-transcript.test.mjs contract (event IDs, byte
// spans, flags, prefix receipt, resolveSession) is satisfied uniformly.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..", "..");
const PYTHON_DIR = resolve(HERE);
const PYTHON_ENTRY = join(PYTHON_DIR, "driver.py");

function pythonBinary() {
  if (process.platform === "win32") return "py";
  if (process.env.ORTHIC_PYTHON) return process.env.ORTHIC_PYTHON;
  return "python3";
}

function runPython(args, payload) {
  const result = spawnSync(pythonBinary(), [PYTHON_ENTRY, ...args], {
    cwd: ROOT,
    input: payload === undefined ? undefined : JSON.stringify(payload),
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, PYTHONIOENCODING: "utf-8" },
  });
  if (result.status !== 0) {
    const err = new Error(
      `orthic_transcripts python driver failed (status=${result.status}): ` +
        (result.stderr || result.stdout || "<no output>"),
    );
    err.stderr = result.stderr;
    err.stdout = result.stdout;
    throw err;
  }
  const text = (result.stdout || "").trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (err) {
    const wrapped = new Error(
      `orthic_transcripts python driver returned non-JSON: ${err.message}: ${text.slice(0, 256)}`,
    );
    throw wrapped;
  }
}

function normalizeProjectionOptions(options) {
  if (options === null || options === undefined) return {};
  if (typeof options === "string") return { transcriptPath: options };
  return { ...options };
}

/**
 * The shared parser entry point. Accepts an options object or a string
 * transcript path. Returns either an event array (default) or the frozen
 * prefix receipt when ``asPrefixReceipt: true`` is set.
 */
export function parse(options) {
  const opts = normalizeProjectionOptions(options);
  // Forward every option except known-meta ones; the driver accepts kwargs.
  return runPython(["parse"], opts);
}

/** Tolerant variant — returns [] / empty receipt when the file is absent. */
export function parseOrEmpty(options) {
  const opts = normalizeProjectionOptions(options);
  try {
    return runPython(["parse"], opts);
  } catch (err) {
    if (typeof err?.message === "string" && /not found/.test(err.message)) {
      if (opts.asPrefixReceipt || opts.as_prefix_receipt) {
        return {
          host: "",
          sessionId: "",
          transcriptId: "",
          prefixLength: 0,
          prefixDigest: "",
          parserDigest: PARSER_DIGEST,
          parserVersion: "orthic.transcript-event.v1",
          eventsObserved: 0,
        };
      }
      return [];
    }
    throw err;
  }
}

/** Capitalized alias per the e2e-7 contract. */
export function TranscriptEventV1(options) {
  return parseOrEmpty(options);
}

/** camelCase alias per the e2e-7 contract. */
export function transcriptEventV1(options) {
  return parseOrEmpty(options);
}

/**
 * Exact-match session resolver. Plan 5.2 substring-bug fix lives here. A
 * candidate matches only when ``requestedSessionId == candidate.sessionId``
 * or ``requestedSessionId == Path(candidate.path).stem``. Substring
 * containment is explicitly rejected.
 */
export function resolveSession(options) {
  return runPython(["resolve-session"], options || {});
}

export function resolveSessionId(options) {
  return resolveSession(options);
}

export function matchTranscript(options) {
  return resolveSession(options);
}

/** Stable parser implementation digest (sha256: prefix). */
export function parserDigest() {
  return runPython(["parser-digest"], {});
}

export const PARSER_DIGEST = parserDigest();

// Provide a default object so `Object.keys(module)` shows the full surface.
export default {
  parse,
  parseOrEmpty,
  TranscriptEventV1,
  transcriptEventV1,
  resolveSession,
  resolveSessionId,
  matchTranscript,
  parserDigest,
};