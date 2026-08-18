// Phase 6.7 — gauntlet self-tests.
//
// These tests are the gauntlet's own proof: when fed a code+test fixture
// where the test is too weak to detect a token-flip mutant, the gauntlet
// must report that mutant as 'survived'. Never weaken a test to make the
// gauntlet pass — fix the gauntlet or the fixture.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, readFileSync, writeFileSync, copyFileSync, mkdirSync, cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

// Fixtures ship as plain tracked files, not embedded git repositories: a
// gitlink is not carried by a clone, so the fixtures would arrive empty for
// everyone but the author and these tests would fail. Each fixture is
// materialised into a throwaway repo here — `base/` is committed, `changed/`
// is layered on top uncommitted to form the diff the gauntlet scans.
const materialised = [];
function materialise(name) {
  const src = resolve(__dirname, "fixtures", name);
  const dir = mkdtempSync(resolve(tmpdir(), `gauntlet-${name}-`));
  materialised.push(dir);
  const git = (...args) => run("git", args, { cwd: dir });
  cpSync(resolve(src, "base"), dir, { recursive: true });
  git("init", "-q", "--initial-branch=main");
  git("config", "user.email", "t@t");
  git("config", "user.name", "t");
  git("add", "-A");
  git("commit", "-qm", "init");
  const changed = resolve(src, "changed");
  if (existsSync(changed)) cpSync(changed, dir, { recursive: true });
  return dir;
}
process.on("exit", () => {
  for (const dir of materialised) rmSync(dir, { recursive: true, force: true });
});

function run(cmd, args, opts) {
  return spawnSync(cmd, args, { encoding: "utf8", ...opts });
}

describe("phase 6.7 evidence gauntlet", () => {
  it("emits a Arcane-shaped check object with host executor and receipt", () => {
    const fixture = materialise("sample-diff");
    const result = run("node", [resolve(ROOT, "gauntlet.mjs"), "--no-coverage", "--no-order", "--test", "node --test test/sum.test.mjs"], { cwd: fixture });
    assert.equal(result.status, 1, `gauntlet must exit 1 when a mutant survives; stdout=${result.stdout}; stderr=${result.stderr}`);
    const out = JSON.parse(result.stdout);
    assert.equal(out.executor, "host");
    assert.equal(out.authority, "host");
    assert.equal(out.kind, "gauntlet");
    assert.equal(out.status, "failed");
    assert.equal(out.exit_code, 1);
    assert.ok(out.receipt, "receipt field required");
    const receipt = JSON.parse(out.receipt);
    assert.equal(receipt.schema, "orthic.tool-receipt.v1");
    assert.equal(receipt.exit_status, 1);
    assert.ok(receipt.summary && receipt.summary.mutation, "receipt must include mutation summary");
  });

  it("catches a surviving mutant in the weak fixture", () => {
    const fixture = materialise("sample-diff");
    const result = run("node", [resolve(ROOT, "gauntlet.mjs"), "--no-coverage", "--no-order", "--test", "node --test test/sum.test.mjs"], { cwd: fixture });
    const out = JSON.parse(result.stdout);
    const layers = JSON.parse(out.output);
    const survived = layers.layers.mutation.results.filter((r) => r.status === "survived");
    assert.ok(survived.length > 0, `fixture must contain at least one killable-but-survived mutant; got: ${JSON.stringify(layers.layers.mutation.results)}`);
    // The weak test should let the `===` mutation on the changed line survive.
    const neqSurvivor = survived.find((r) => r.mutator === "neq-flip");
    assert.ok(neqSurvivor, `expected a ` === `→`!==` survivor; got: ${JSON.stringify(survived)}`);
  });

  it("reports clean change-line mutation when test is strong enough", () => {
    const fixture = materialise("sample-diff");
    // Strengthen the test by exercising both the `=== 0` branch (so a
    // `===`→`!==` mutation on that line breaks the test) AND the
    // negative-result path of `mean` (so a `neg-flip` on `sum/len`
    // breaks the test). Fix the test to actually cover the change —
    // never weaken the gauntlet to make it pass.
    // Bypass node --test's recursive-detection by using a plain script
    // that imports the test file and runs assertions under `node:assert`.
    const testPath = resolve(fixture, "test/sum.test.mjs");
    const original = readFileSync(testPath, "utf8");
    const strong = `import { sum, mean } from "../src/sum.js";
import assert from "node:assert/strict";
if (sum([1, 2, 3]) !== 6) throw new Error("sum([1,2,3]) failed");
if (sum([10, 20]) !== 30) throw new Error("sum([10,20]) failed");
if (sum([0, 5, 7]) !== 12) throw new Error("sum([0,5,7]) failed");
if (mean([]) !== 0) throw new Error("mean([]) failed");
if (mean([2, 4, 6]) !== 4) throw new Error("mean([2,4,6]) failed");
console.log("strong-test-ok");
`;
    writeFileSync(testPath, strong);
    try {
      const result = run("node", [resolve(ROOT, "gauntlet.mjs"), "--no-coverage", "--no-order", "--test", "node test/sum.test.mjs"], { cwd: fixture });
      const out = JSON.parse(result.stdout);
      const layers = JSON.parse(out.output);
      const survivors = layers.layers.mutation.results.filter((r) => r.status === "survived");
      assert.equal(survivors.length, 0, `strong test should kill every mutator; survivors: ${JSON.stringify(survivors)}; stderr=${result.stderr}`);
      assert.equal(out.status, "passed");
    } finally {
      // Restore original weak test so the next test in the suite is deterministic.
      writeFileSync(testPath, original);
    }
  });

  it("returns 'no_diff' failure when the diff is empty", () => {
    // Use a from-scratch git repo so the diff is genuinely empty.
    const emptyRepo = materialise("empty-repo");
    mkdirSync(emptyRepo, { recursive: true });
    const git = (args) => spawnSync("git", ["-c", "user.email=a@b", "-c", "user.name=a", ...args], { cwd: emptyRepo, encoding: "utf8" });
    mkdirSync(resolve(emptyRepo, "src"), { recursive: true });
    writeFileSync(resolve(emptyRepo, "src/sum.js"), "export function sum(values) { return values.reduce((a,b)=>a+b,0); }\n");
    git(["init", "-q"]);
    git(["add", "-A"]);
    git(["commit", "-q", "-m", "init"]);
    const result = run("node", [resolve(ROOT, "gauntlet.mjs"), "--no-mutation", "--no-coverage", "--no-order"], { cwd: emptyRepo });
    assert.equal(result.status, 1, "gauntlet must exit 1 when diff is empty");
    const out = JSON.parse(result.stdout);
    assert.equal(out.status, "failed");
    assert.ok(out.receipt, "receipt always emitted");
    const receipt = JSON.parse(out.receipt);
    assert.equal(receipt.exit_status, 1);
  });
});
