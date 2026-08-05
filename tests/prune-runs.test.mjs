import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { pruneOldRuns, RUN_DIR_RE } from "../collect-facts.mjs";

function seed(root, names) {
  fs.mkdirSync(root, { recursive: true });
  for (const name of names) fs.mkdirSync(path.join(root, name), { recursive: true });
}

test("pruneOldRuns keeps only the newest run dir, deletes older ones", () => {
  const auditRoot = fs.mkdtempSync(path.join(os.tmpdir(), "audit-prune-"));
  try {
    const current = "2026-07-14T06-57-14-645Z";
    seed(auditRoot, [
      "2026-07-09T15-40-39-512Z",
      "2026-07-13T10-18-11-252Z",
      current,
    ]);
    pruneOldRuns(auditRoot, current, 1);
    const left = fs.readdirSync(auditRoot).sort();
    assert.deepEqual(left, [current], "only the current run survives");
  } finally {
    fs.rmSync(auditRoot, { recursive: true, force: true });
  }
});

test("pruneOldRuns never touches the persistent stores or non-timestamp dirs", () => {
  const auditRoot = fs.mkdtempSync(path.join(os.tmpdir(), "audit-prune-"));
  try {
    const current = "2026-07-14T06-57-14-645Z";
    seed(auditRoot, [
      "2026-07-09T15-40-39-512Z", // old run — should go
      current,                    // current run — stays
      "audit",                    // typed finding store — must stay
      "architect",                // typed decision store — must stay
      "skill-backup-2026-07-10",  // backup — must stay
      "runtime",                  // runtime capture dir — must stay
    ]);
    fs.writeFileSync(path.join(auditRoot, "audit", "findings.jsonl"), "{}\n");
    pruneOldRuns(auditRoot, current, 1);
    const left = new Set(fs.readdirSync(auditRoot));
    assert.ok(left.has(current), "current run kept");
    assert.ok(left.has("audit") && fs.existsSync(path.join(auditRoot, "audit", "findings.jsonl")), "finding store intact");
    assert.ok(left.has("architect"), "decision store intact");
    assert.ok(left.has("skill-backup-2026-07-10"), "backup intact");
    assert.ok(left.has("runtime"), "runtime dir intact");
    assert.ok(!left.has("2026-07-09T15-40-39-512Z"), "old run deleted");
  } finally {
    fs.rmSync(auditRoot, { recursive: true, force: true });
  }
});

test("pruneOldRuns keeps N when asked, and the current run is always safe", () => {
  const auditRoot = fs.mkdtempSync(path.join(os.tmpdir(), "audit-prune-"));
  try {
    const current = "2026-07-14T06-57-14-645Z";
    seed(auditRoot, [
      "2026-07-09T15-40-39-512Z",
      "2026-07-13T10-18-11-252Z",
      current,
    ]);
    pruneOldRuns(auditRoot, current, 2);
    const left = fs.readdirSync(auditRoot).sort();
    assert.deepEqual(left, ["2026-07-13T10-18-11-252Z", current], "newest 2 kept");
  } finally {
    fs.rmSync(auditRoot, { recursive: true, force: true });
  }
});

test("RUN_DIR_RE matches only the exact ISO run-dir shape", () => {
  assert.ok(RUN_DIR_RE.test("2026-07-14T06-57-14-645Z"));
  assert.ok(!RUN_DIR_RE.test("audit"));
  assert.ok(!RUN_DIR_RE.test("skill-backup-2026-07-10"));
  assert.ok(!RUN_DIR_RE.test("2026-07-14"));
});
