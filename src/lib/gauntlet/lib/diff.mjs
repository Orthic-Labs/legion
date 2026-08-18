// Phase 6.7 — diff extractor.
// Bounded to the frozen diff: returns per-file added-line numbers so the
// mutation engine and the coverage filter do not touch the rest of the
// repo. Cost stays proportional to the diff, never repo-wide.
//
// Source precedence:
//   1. --diff <file>           : explicit frozen diff (preferred for /commit)
//   2. --base <ref>            : git diff <base>...HEAD (CI mode)
//   3. (default)               : git diff against HEAD (working tree only)

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export function loadDiff({ cwd, base, head, diffFile } = {}) {
  let raw;
  if (diffFile) {
    raw = readFileSync(resolve(cwd ?? process.cwd(), diffFile), "utf8");
  } else if (base) {
    const range = head ? `${base}...${head}` : base;
    const result = spawnSync("git", ["diff", "--unified=0", range], { cwd, encoding: "utf8" });
    if (result.status !== 0) throw new Error(`git diff ${range} failed: ${result.stderr}`);
    raw = result.stdout;
  } else {
    const result = spawnSync("git", ["diff", "--unified=0", "HEAD"], { cwd, encoding: "utf8" });
    if (result.status !== 0) throw new Error(`git diff HEAD failed: ${result.stderr}`);
    raw = result.stdout;
  }
  return parseUnified(raw);
}

// Parse `git diff --unified=0` hunk headers and the `+` lines inside.
export function parseUnified(raw) {
  const files = [];
  let current = null;
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    if (line.startsWith("diff --git ")) {
      if (current) files.push(current);
      current = { path: null, added: [], removed: [] };
      continue;
    }
    if (line.startsWith("+++ ") && current) {
      // +++ b/path  (or +++ /dev/null for deletions)
      const m = /^\+\+\+ (?:\/dev\/null|b\/)(.*)$/.exec(line);
      if (m) current.path = m[1] || null;
      continue;
    }
    if (line.startsWith("@@") && current?.path) {
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
      if (m) {
        const start = Number(m[1]);
        const count = Number(m[2] ?? 1);
        for (let i = 0; i < count; i += 1) current.added.push(start + i);
      }
      continue;
    }
  }
  if (current) files.push(current);
  // Drop pure-deletion files (no surviving line to mutate or cover).
  return files
    .filter((f) => f.path && f.added.length > 0)
    .map((f) => ({ path: f.path, lines: f.added }));
}

export function summarise(files) {
  return {
    files: files.length,
    lines: files.reduce((n, f) => n + f.lines.length, 0),
  };
}
