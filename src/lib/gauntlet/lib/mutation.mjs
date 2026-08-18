// Phase 6.7 — mutation testing on changed lines.
//
// For each added line in the diff, derive a candidate mutant by applying a
// small syntactic transformation. Rerun the user-supplied test command
// against the mutated source. A mutant that survives (test still passes)
// proves the test cannot fail on that change — the preventive twin of
// Insights' tests-that-cannot-fail detector.
//
// Scope is one line per mutant. We rewrite the source file in place under
// a backup path, run the test, then restore. A failing restore is itself
// a hard error (we never leave a mutated source behind).

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, copyFileSync, renameSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const MUTATORS = [
  {
    id: "neq-flip",
    apply: (line) => line.replace(/(\b\w[\w.]*)\s*===\s*([^\n]+)/g, "$1!==$2"),
  },
  {
    id: "or-swap",
    apply: (line) => line.replace(/&&/, "||"),
  },
  {
    id: "neg-flip",
    apply: (line) => line.replace(/(\breturn\s+)(.+)/, "$1!($2)"),
  },
  {
    id: "literal-zero",
    apply: (line) => line.replace(/(\breturn\s+)([0-9]+)/, "$10"),
  },
  {
    id: "string-empty",
    apply: (line) => line.replace(/(\breturn\s+)(['"`])([^\n'"]*)\2/, "$1$2$2"),
  },
];

function findMutator(line) {
  for (const m of MUTATORS) if (m.apply(line) !== line) return m;
  return null;
}

export function runMutation({ cwd, files, testCommand }) {
  const abs = (p) => resolve(cwd ?? process.cwd(), p);
  const results = [];
  for (const file of files) {
    const path = abs(file.path);
    if (!existsSync(path)) {
      results.push({ file: file.path, status: "skipped", reason: "missing_locator" });
      continue;
    }
    const original = readFileSync(path, "utf8");
    const sourceLines = original.split(/\r?\n/);
    for (const lineNo of file.lines) {
      const idx = lineNo - 1;
      if (idx < 0 || idx >= sourceLines.length) {
        results.push({ file: file.path, line: lineNo, status: "skipped", reason: "out_of_range" });
        continue;
      }
      const line = sourceLines[idx];
      const mutator = findMutator(line);
      if (!mutator) {
        results.push({ file: file.path, line: lineNo, status: "no-mutator", reason: "syntactic_shape_unhandled" });
        continue;
      }
      const mutated = sourceLines.slice();
      mutated[idx] = mutator.apply(line);
      const backup = path + ".gauntlet-backup";
      copyFileSync(path, backup);
      try {
        writeFileSync(path, mutated.join("\n"));
        const result = spawnSync("sh", ["-c", testCommand], { cwd, encoding: "utf8", timeout: 60_000 });
        const survived = result.status === 0;
        results.push({
          file: file.path,
          line: lineNo,
          mutator: mutator.id,
          status: survived ? "survived" : "killed",
          ...(survived ? { exit_code: 0 } : { exit_code: result.status }),
          ...(survived ? {} : { stderr_tail: (result.stderr ?? "").slice(-200) }),
        });
      } finally {
        // Restore — never leave a mutated source behind.
        renameSync(backup, path);
      }
    }
  }
  const survived = results.filter((r) => r.status === "survived").length;
  const killed = results.filter((r) => r.status === "killed").length;
  const skipped = results.filter((r) => r.status === "skipped" || r.status === "no-mutator").length;
  return {
    passed: killed,
    failed: survived,
    skipped,
    total: results.length,
    // Mutants that survive are the gauntlet's signal of weak tests.
    // If none survived, the diff's tests demonstrably fail under each fault.
    ok: survived === 0,
    results,
  };
}
