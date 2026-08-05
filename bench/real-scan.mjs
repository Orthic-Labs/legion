// AU20 production-scanner bridge.
//
// The bench's own detectors (./detectors/*.mjs) are approximations written
// against the same fixtures they score, so their recall proves the harness is
// wired and nothing about /audit. This module runs the REAL thing: it invokes
// tools/skills/audit/collect-facts.mjs — the same entry point `/audit` uses —
// against a fixture and reports what the production scanner actually found.
//
// Three rules this module exists to enforce:
//
//   1. A scanner whose tool is absent reports `unavailable`. It is never a pass
//      and never a fail; it is excluded from the score and named in the output.
//      A missing binary silently reading as "no findings" is the exact failure
//      the bench was built to detect.
//   2. Fixtures are materialised into a temp directory, never scanned in place.
//      Scanning in place would let a fixture's defect leak into this repo's own
//      audit runs.
//   3. Nothing credential-shaped is ever committed. Secret fixtures that a real
//      scanner must catch are SYNTHESISED at run time (see synthesizeFixture),
//      because any literal committed here would be flagged forever afterwards
//      by every audit of this workspace.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";

const execFileAsync = promisify(execFile);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const COLLECT_FACTS = path.resolve(HERE, "..", "collect-facts.mjs");

/**
 * Defect class -> the production check in collect-facts.mjs that owns it.
 * `null` means /audit has no deterministic scanner for that class, which is a
 * reportable coverage fact rather than a bench defect: doc drift is Cortex's
 * stale-reference machinery, not an audit scanner.
 */
export const PRODUCTION_CHECK_BY_CLASS = {
  secret: "secrets",
  dependency_cve: "deps_cve",
  dead_code: "dead_code",
  duplication: "duplication",
  type_error: "types",
  drift: null,
};

/**
 * Secret fixtures that the production scanner must catch, generated at run time.
 *
 * The committed fixture uses an obviously-unreal literal (AKIA_EXAMPLE_NOT_REAL_*)
 * so that browsing this repo never shows anything credential-shaped. gitleaks is
 * deliberately tuned to ignore exactly that shape, so the committed fixture cannot
 * measure production recall. These strings are structurally valid provider token
 * formats and are NOT real credentials — Stripe's published documentation example
 * and a randomly generated GitHub PAT-shaped string that was never issued.
 */
const SYNTHETIC_SOURCES = {
  "secret-detectable": [
    "// Synthesised at run time by real-scan.mjs — never committed.",
    "// Not live credentials: Stripe's documented example value and an",
    "// unissued PAT-shaped random string.",
    'const stripeKey = "sk_live_XXXX_REDACTED_XXXX";',
    'const githubToken = "ghp_XXXX_REDACTED_XXXX";',
    "module.exports = { stripeKey, githubToken };",
    "",
  ].join("\n"),
};

/** Materialise a fixture (or a synthetic source) into a fresh temp directory. */
function materialize(entry) {
  const dir = mkdtempSync(path.join(tmpdir(), "au20-"));
  if (entry.synthetic) {
    const body = SYNTHETIC_SOURCES[entry.synthetic];
    if (!body) throw new Error(`no synthetic source registered: ${entry.synthetic}`);
    writeFileSync(path.join(dir, "app.js"), body, "utf8");
    return dir;
  }
  // entry.file is "fixtures/<name>/<file>" — copy the whole fixture directory so
  // multi-file fixtures (package.json + lockfile, README + client) stay intact.
  const fixtureDir = path.join(HERE, path.dirname(entry.file));
  cpSync(fixtureDir, dir, { recursive: true });
  return dir;
}

/**
 * Run one production check against one fixture.
 *
 * Returns { state, findings, reason }:
 *   state "scored"      — the scanner ran; `findings` is its real count
 *   state "unavailable" — the tool is absent or the check skipped itself
 *   state "error"       — the scanner errored; never scored as either outcome
 */
export async function runProductionCheck(entry) {
  const check = PRODUCTION_CHECK_BY_CLASS[entry.class];
  if (!check) {
    return { state: "unavailable", findings: null, reason: `no production scanner owns class "${entry.class}"` };
  }
  let dir;
  try {
    dir = materialize(entry);
    const outDir = path.join(dir, "__facts");
    await execFileAsync(
      process.execPath,
      [COLLECT_FACTS, dir, "--only", check, "--out", outDir],
      { timeout: 300000, maxBuffer: 32 * 1024 * 1024 },
    );
    const facts = JSON.parse(readFileSync(path.join(outDir, "facts.json"), "utf8"));
    const row = facts.checks.find((c) => c.check === check);
    if (!row) return { state: "error", findings: null, reason: `check "${check}" absent from facts.json` };
    if (row.status !== "ran") {
      return {
        state: "unavailable",
        findings: null,
        reason: row.skip_reason || (row.tool_absent ? `${row.tool} not installed` : `status=${row.status}`),
      };
    }
    if (row.findings_count === null || row.findings_count === undefined) {
      return { state: "error", findings: null, reason: `${check} ran but reported no findings_count` };
    }
    return { state: "scored", findings: row.findings_count, reason: null };
  } catch (err) {
    return { state: "error", findings: null, reason: String(err?.message ?? err).slice(0, 300) };
  } finally {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
}
