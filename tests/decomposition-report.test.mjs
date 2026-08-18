import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RENDERER = path.resolve(HERE, "../tools/audit/render-report.mjs");

const ADR_REF = "docs/plans/2026-07-13-billing-decomposition.md";

function makeFacts(dir) {
  return {
    kind: "audit-facts",
    generated_at: "2026-07-13T00:00:00.000Z",
    workspace: dir,
    out_dir: dir,
    incomplete: false,
    decomposition: {
      threshold: 400,
      thresholdKind: "review-trigger",
      oversized: [
        { file: "src/Cohesive.ts", loc: 420, bytes: 12000, class: "runtime" },
        { file: "src/Mixed.ts", loc: 760, bytes: 26000, class: "runtime" },
      ],
      mechanical_splits: [],
    },
    checks: [
      { check: "build", status: "ran", findings_count: 0, exit_code: 0 },
      { check: "types", status: "ran", findings_count: 0, exit_code: 0 },
      { check: "lint", status: "ran", findings_count: 0, exit_code: 0 },
    ],
  };
}

function makeReport() {
  return {
    schema_version: 2,
    lenses_ran: ["architecture"],
    triage_top: ["decomp-mixed"],
    decomposition_assessments: [
      {
        file: "src/Cohesive.ts",
        trigger: { loc: 420, bytes: 12000 },
        verdict: "not-needed",
        rationale: "One cohesive parser pipeline; splitting would increase coupling.",
        evidence: ["src/Cohesive.ts:18-96", "src/Cohesive.ts:210-355"],
      },
      {
        file: "src/Mixed.ts",
        trigger: { loc: 760, bytes: 26000 },
        verdict: "confirmed",
        findingId: "decomp-mixed",
        rationale: "Billing orchestration and retry policy have separate state and callers.",
        evidence: ["src/Mixed.ts:20-310", "src/Mixed.ts:400-720"],
      },
    ],
    findings: [{
      id: "decomp-mixed",
      subtype: "decomposition",
      category: "architecture",
      severity: "medium",
      tier: "MANUAL",
      file: "src/Mixed.ts",
      title: "Separate billing orchestration from retry policy",
      detail: "Two independently changing responsibilities share one module.",
      evidence: "src/Mixed.ts:20-310; src/Mixed.ts:400-720",
      decomposition_plan: {
        verdict: "confirmed",
        current_responsibilities: [
          { name: "Billing orchestration", symbols: ["submitInvoice"], evidence: ["src/Mixed.ts:20-310"] },
          { name: "Retry policy", symbols: ["nextRetry"], evidence: ["src/Mixed.ts:400-720"] },
        ],
        keep_in_place: { component: "BillingCoordinator", responsibility: "Public orchestration facade", symbols: ["submitInvoice"] },
        target_components: [{
          component: "RetryPolicy",
          destination: "src/billing/RetryPolicy.ts",
          responsibility: "Backoff and retry eligibility",
          moves: ["nextRetry"],
          public_contract: "nextRetry(attempt, error): RetryDecision",
          dependencies: ["Clock"],
        }],
        steps: [
          { order: 1, change: "Characterize retry decisions", verification: "Focused retry-policy tests pass" },
          { order: 2, change: "Extract RetryPolicy and delegate from BillingCoordinator", verification: "Billing contract tests remain green" },
        ],
        behavior_contracts: ["Invoice submission result and retry timing remain unchanged"],
        risks: ["Clock ownership could change retry timing"],
        architect_decision_ref: ADR_REF,
      },
    }],
  };
}

function renderAgent(dir, factsPath, reportPath, extraArgs = []) {
  const result = spawnSync(process.execPath, [RENDERER, "--facts", factsPath, "--report", reportPath, "--agent", ...extraArgs], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

test("LOC only triggers review while confirmed decomposition renders an executable target design", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-decomposition-report-"));
  try {
    const factsPath = path.join(dir, "facts.json");
    const reportPath = path.join(dir, "report.json");
    const outputPath = path.join(dir, "audit.md");
    fs.mkdirSync(path.join(dir, "docs", "plans"), { recursive: true });
    fs.writeFileSync(path.join(dir, ADR_REF), "# ADR — billing decomposition\n");
    fs.writeFileSync(factsPath, JSON.stringify(makeFacts(dir)));
    fs.writeFileSync(reportPath, JSON.stringify(makeReport()));

    const rendered = spawnSync(process.execPath, [RENDERER, "--facts", factsPath, "--report", reportPath, "--out", outputPath], { encoding: "utf8" });
    assert.equal(rendered.status, 0, rendered.stderr || rendered.stdout);
    const markdown = fs.readFileSync(outputPath, "utf8");
    assert.match(markdown, /Decomposition assessments/);
    assert.match(markdown, /· 1 findings ·/);
    assert.match(markdown, /Cohesive\.ts.*not-needed/);
    assert.doesNotMatch(markdown, /decomp-src-Cohesive-ts/);
    assert.doesNotMatch(markdown, /invalid assessment/);
    assert.match(markdown, /Current responsibilities/);
    assert.match(markdown, /Billing orchestration/);
    assert.match(markdown, /RetryPolicy/);
    assert.match(markdown, /src\/billing\/RetryPolicy\.ts/);
    assert.match(markdown, /Characterize retry decisions/);
    assert.match(markdown, /Invoice submission result and retry timing remain unchanged/);

    const summary = renderAgent(dir, factsPath, reportPath);
    assert.equal(summary.incomplete, false);
    assert.equal(summary.decomposition_coverage.complete, true);
    assert.deepEqual(summary.decomposition_coverage.undetermined, []);
    assert.equal(summary.findings[0].decomposition_plan.target_components[0].component, "RetryPolicy");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("coverage gates: missing plan, missing ADR, whole-file span, unassessed, and undetermined", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-decomposition-gates-"));
  try {
    const factsPath = path.join(dir, "facts.json");
    const reportPath = path.join(dir, "report.json");
    fs.mkdirSync(path.join(dir, "docs", "plans"), { recursive: true });
    fs.writeFileSync(path.join(dir, ADR_REF), "# ADR — billing decomposition\n");
    fs.writeFileSync(factsPath, JSON.stringify(makeFacts(dir)));

    // Confirmed verdict with the plan stripped → invalid_confirmed, report INCOMPLETE.
    const noPlan = makeReport();
    delete noPlan.findings[0].decomposition_plan;
    fs.writeFileSync(reportPath, JSON.stringify(noPlan));
    let summary = renderAgent(dir, factsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.deepEqual(summary.decomposition_coverage.invalid_confirmed, ["src/Mixed.ts"]);

    // Plan whose architect_decision_ref does not exist on disk → invalid_confirmed.
    const ghostRef = makeReport();
    ghostRef.findings[0].decomposition_plan.architect_decision_ref = "docs/plans/does-not-exist.md";
    fs.writeFileSync(reportPath, JSON.stringify(ghostRef));
    summary = renderAgent(dir, factsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.deepEqual(summary.decomposition_coverage.invalid_confirmed, ["src/Mixed.ts"]);

    // architect_decision_ref must be a real FILE under an allowed decision-record root whose
    // realpath stays inside the workspace. Each of these existing-but-invalid refs is rejected:
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-outside-"));
    try {
      const outsideFile = path.join(outsideDir, "unrelated.md");
      fs.writeFileSync(outsideFile, "# not this repo's decision record\n");
      const badRefs = [
        outsideFile,                                                        // absolute path outside repo
        path.relative(dir, outsideFile).split(path.sep).join("/"),          // ../ escape
        ".",                                                                 // repo root itself
        "docs/plans",                                                        // a directory, not a file
        "README.md",                                                         // outside allowed decision roots
        "docs/plans/../../README.md",                                        // lexical escape from an allowed root
      ];
      fs.writeFileSync(path.join(dir, "README.md"), "# readme\n");
      // A link may stay inside the workspace while physically escaping the allowed decision root.
      try {
        fs.symlinkSync(path.join(dir, "README.md"), path.join(dir, "docs", "plans", "internal-escape.md"));
        badRefs.push("docs/plans/internal-escape.md");
      } catch {}
      // symlink under an allowed root pointing OUTSIDE the repo (junction-escape class); skipped
      // only where the environment cannot create symlinks (e.g. unprivileged Windows).
      try {
        fs.symlinkSync(outsideFile, path.join(dir, "docs", "plans", "escape.md"));
        badRefs.push("docs/plans/escape.md");
      } catch {}
      for (const badRef of badRefs) {
        const invalidRef = makeReport();
        invalidRef.findings[0].decomposition_plan.architect_decision_ref = badRef;
        fs.writeFileSync(reportPath, JSON.stringify(invalidRef));
        summary = renderAgent(dir, factsPath, reportPath);
        assert.equal(summary.incomplete, true, `ref should be rejected: ${badRef}`);
        assert.deepEqual(summary.decomposition_coverage.invalid_confirmed, ["src/Mixed.ts"], `ref should be rejected: ${badRef}`);
      }
    } finally {
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }

    // Plan without risks → invalid_confirmed (doc contract requires risks[]).
    const noRisks = makeReport();
    noRisks.findings[0].decomposition_plan.risks = [];
    fs.writeFileSync(reportPath, JSON.stringify(noRisks));
    summary = renderAgent(dir, factsPath, reportPath);
    assert.equal(summary.incomplete, true);

    // not-needed backed only by a whole-file span → fails the evidence bar.
    const wholeFile = makeReport();
    wholeFile.decomposition_assessments[0].evidence = ["src/Cohesive.ts:1-420"];
    fs.writeFileSync(reportPath, JSON.stringify(wholeFile));
    summary = renderAgent(dir, factsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.equal(summary.decomposition_coverage.invalid_assessments[0].candidate, "src/Cohesive.ts");
    assert.match(summary.decomposition_coverage.invalid_assessments[0].problems.join(" "), /whole-file span/);

    // Evidence not in path:line form → fails the format bar.
    const prose = makeReport();
    prose.decomposition_assessments[0].evidence = ["the file looks cohesive"];
    fs.writeFileSync(reportPath, JSON.stringify(prose));
    summary = renderAgent(dir, factsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.match(summary.decomposition_coverage.invalid_assessments[0].problems.join(" "), /path:line/);

    // Unassessed runtime candidate → missing, report INCOMPLETE.
    const unassessed = makeReport();
    unassessed.decomposition_assessments = unassessed.decomposition_assessments.filter((item) => item.file !== "src/Cohesive.ts");
    fs.writeFileSync(reportPath, JSON.stringify(unassessed));
    summary = renderAgent(dir, factsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.deepEqual(summary.decomposition_coverage.missing, ["src/Cohesive.ts"]);

    // not-needed at >=3x the review trigger (400 → 1200) needs a second assessor.
    const hugeFacts = makeFacts(dir);
    hugeFacts.decomposition.oversized.push({ file: "src/Huge.ts", loc: 1300, bytes: 48000, class: "runtime" });
    const hugeFactsPath = path.join(dir, "facts-huge.json");
    fs.writeFileSync(hugeFactsPath, JSON.stringify(hugeFacts));
    const loneAssessor = makeReport();
    loneAssessor.decomposition_assessments.push({
      file: "src/Huge.ts",
      trigger: { loc: 1300, bytes: 48000 },
      verdict: "not-needed",
      rationale: "Single generated state machine; splitting would break codegen round-trips.",
      evidence: ["src/Huge.ts:40-220", "src/Huge.ts:600-950"],
    });
    fs.writeFileSync(reportPath, JSON.stringify(loneAssessor));
    summary = renderAgent(dir, hugeFactsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.equal(summary.decomposition_coverage.invalid_assessments[0].candidate, "src/Huge.ts");
    assert.match(summary.decomposition_coverage.invalid_assessments[0].problems.join(" "), /second_assessor/);

    // A disagreeing second assessor also invalidates the not-needed stamp (worse verdict wins)...
    const splitVerdict = structuredClone(loneAssessor);
    splitVerdict.decomposition_assessments[2].second_assessor = {
      verdict: "undetermined",
      rationale: "Caller graph unclear; needs impact analysis.",
      evidence: ["src/Huge.ts:600-950"],
    };
    fs.writeFileSync(reportPath, JSON.stringify(splitVerdict));
    summary = renderAgent(dir, hugeFactsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.match(summary.decomposition_coverage.invalid_assessments[0].problems.join(" "), /worse verdict wins/);

    // Second-assessor evidence is held to the SAME bar as the primary: not anchored in the
    // candidate file → rejected; whole-file span → rejected.
    const unanchoredSecond = structuredClone(loneAssessor);
    unanchoredSecond.decomposition_assessments[2].second_assessor = {
      verdict: "not-needed",
      rationale: "Looks fine.",
      evidence: ["README.md:1"],
    };
    fs.writeFileSync(reportPath, JSON.stringify(unanchoredSecond));
    summary = renderAgent(dir, hugeFactsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.match(summary.decomposition_coverage.invalid_assessments[0].problems.join(" "), /second_assessor: no evidence anchored/);

    const wholeFileSecond = structuredClone(loneAssessor);
    wholeFileSecond.decomposition_assessments[2].second_assessor = {
      verdict: "not-needed",
      rationale: "Read the whole file.",
      evidence: ["src/Huge.ts:1-1300"],
    };
    fs.writeFileSync(reportPath, JSON.stringify(wholeFileSecond));
    summary = renderAgent(dir, hugeFactsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.match(summary.decomposition_coverage.invalid_assessments[0].problems.join(" "), /second_assessor: whole-file span/);

    // ...while an agreeing, evidence-backed second assessor completes the review.
    const dualAssessor = structuredClone(loneAssessor);
    dualAssessor.decomposition_assessments[2].second_assessor = {
      verdict: "not-needed",
      rationale: "Independently confirmed: one responsibility, generated code, no divergent callers.",
      evidence: ["src/Huge.ts:40-220", "src/Huge.ts:1005-1180"],
    };
    fs.writeFileSync(reportPath, JSON.stringify(dualAssessor));
    summary = renderAgent(dir, hugeFactsPath, reportPath);
    assert.equal(summary.incomplete, false);
    assert.equal(summary.decomposition_coverage.complete, true);

    // Heavy incoming relationships trigger the second-assessor rule even below 3x size: a 500-LOC
    // candidate with 1000 incoming relationships cannot be dismissed by a lone assessor.
    const hubFacts = makeFacts(dir);
    hubFacts.decomposition.oversized.push({
      file: "src/Hub.ts", loc: 500, bytes: 18000, class: "runtime",
      graphMetrics: "available", symbolCount: 12, incomingRelationships: 1000, outgoingRelationships: 4,
    });
    const hubFactsPath = path.join(dir, "facts-hub.json");
    fs.writeFileSync(hubFactsPath, JSON.stringify(hubFacts));
    const hubLone = makeReport();
    hubLone.decomposition_assessments.push({
      file: "src/Hub.ts",
      trigger: { loc: 500, bytes: 18000 },
      verdict: "not-needed",
      rationale: "Thin event hub; one responsibility.",
      evidence: ["src/Hub.ts:30-180"],
    });
    fs.writeFileSync(reportPath, JSON.stringify(hubLone));
    summary = renderAgent(dir, hubFactsPath, reportPath);
    assert.equal(summary.incomplete, true);
    assert.equal(summary.decomposition_coverage.invalid_assessments[0].candidate, "src/Hub.ts");
    assert.match(summary.decomposition_coverage.invalid_assessments[0].problems.join(" "), /incoming relationships.*second_assessor/);

    const hubDual = structuredClone(hubLone);
    hubDual.decomposition_assessments[2].second_assessor = {
      verdict: "not-needed",
      rationale: "Independently confirmed: pure fan-out dispatcher, no divergent responsibilities.",
      evidence: ["src/Hub.ts:200-410"],
    };
    fs.writeFileSync(reportPath, JSON.stringify(hubDual));
    summary = renderAgent(dir, hubFactsPath, reportPath);
    assert.equal(summary.incomplete, false);

    // undetermined is an honest, complete read-only verdict — listed, not INCOMPLETE.
    const undetermined = makeReport();
    undetermined.decomposition_assessments[0].verdict = "undetermined";
    undetermined.decomposition_assessments[0].rationale = "Callers unknown; needs graph impact + characterization tests.";
    fs.writeFileSync(reportPath, JSON.stringify(undetermined));
    summary = renderAgent(dir, factsPath, reportPath);
    assert.equal(summary.incomplete, false);
    assert.deepEqual(summary.decomposition_coverage.undetermined, ["src/Cohesive.ts"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("filter-dir scopes decomposition coverage to the filtered candidates", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-decomposition-scope-"));
  try {
    const factsPath = path.join(dir, "facts.json");
    const reportPath = path.join(dir, "report.json");
    fs.writeFileSync(factsPath, JSON.stringify(makeFacts(dir)));
    const scoped = makeReport();
    scoped.decomposition_assessments = scoped.decomposition_assessments.filter((item) => item.file === "src/Cohesive.ts");
    scoped.findings = [];
    scoped.triage_top = [];
    fs.writeFileSync(reportPath, JSON.stringify(scoped));
    const summary = renderAgent(dir, factsPath, reportPath, ["--filter-dir", "src/Cohesive.ts"]);
    assert.equal(summary.incomplete, false);
    assert.equal(summary.decomposition_coverage.runtime_candidates, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
