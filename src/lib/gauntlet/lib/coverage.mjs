// Phase 6.7 — changed-lines-only coverage.
//
// We drive node's built-in coverage via NODE_V8_COVERAGE and parse the
// resulting JSON. That avoids a hard dependency on c8/istanbul and keeps
// the gauntlet self-contained. Coverage is reported as the fraction of
// added lines in the diff that were executed at least once by the test
// command. Whole-repo coverage is intentionally discarded — it moves too
// slowly to gate anything and punishes untouched legacy code.

import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, rmSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";

export function runCoverage({ cwd, files, testCommand }) {
  const tmp = mkdtempSync(resolve(tmpdir(), "gauntlet-cov-"));
  const env = { ...process.env, NODE_V8_COVERAGE: tmp };
  try {
    const result = spawnSync("sh", ["-c", testCommand], { cwd, env, encoding: "utf8", timeout: 60_000 });
    if (result.status !== 0) {
      return {
        ok: false,
        passed: 0,
        failed: 0,
        total: 0,
        error: `test_command_failed:exit_${result.status}`,
        stderr_tail: (result.stderr ?? "").slice(-200),
      };
    }
    const summary = summariseCoverage({ cwd, files, coverageDir: tmp });
    return {
      ok: summary.covered === summary.total && summary.total > 0,
      passed: summary.covered,
      failed: summary.total - summary.covered,
      total: summary.total,
      percent: summary.total === 0 ? 0 : Number(((summary.covered / summary.total) * 100).toFixed(2)),
      results: summary.perLine,
    };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function summariseCoverage({ cwd, files, coverageDir }) {
  const perLine = [];
  const fileSet = new Map(files.map((f) => [resolve(cwd, f.path), new Set(f.lines)]));
  if (!existsSync(coverageDir)) return { covered: 0, total: 0, perLine };
  const entries = readCoverageEntries(coverageDir);
  for (const entry of entries) {
    const filePath = resolve(entry.url);
    const wanted = fileSet.get(filePath);
    if (!wanted) continue;
    for (const fn of entry.functions ?? []) {
      for (const range of fn.ranges ?? []) {
        const start = range.startOffset;
        const end = range.endOffset;
        const sourceText = readSource(filePath);
        if (!sourceText) continue;
        const startLine = offsetToLine(sourceText, start);
        const endLine = offsetToLine(sourceText, end);
        for (let line = startLine; line <= endLine; line += 1) {
          if (!wanted.has(line)) continue;
          perLine.push({ file: filePath, line, count: range.count });
        }
      }
    }
  }
  const total = perLine.length;
  const covered = perLine.filter((r) => r.count > 0).length;
  return { covered, total, perLine };
}

function readCoverageEntries(dir) {
  const entries = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    try {
      const raw = readFileSync(resolve(dir, name), "utf8");
      const data = JSON.parse(raw);
      const result = data.result?.[0];
      if (result) entries.push(result);
    } catch { /* skip malformed */ }
  }
  return entries;
}

function readSource(path) {
  try { return readFileSync(path, "utf8"); } catch { return null; }
}

function offsetToLine(text, offset) {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}
