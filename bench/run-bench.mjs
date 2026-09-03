#!/usr/bin/env node
// AU20 planted-finding bench runner.
//
// Runs entirely offline and deterministically: no network calls, no paid
// API, no LLM calls. Loads manifest.json, applies the matching bench-local
// detector (tools/skills/audit/bench/detectors/*.mjs) to each fixture, and
// scores recall/precision per defect class plus overall.
//
// Usage:
//   node tools/skills/audit/bench/run-bench.mjs [--threshold 0.8] [--json]
//   node tools/skills/audit/bench/run-bench.mjs --real          (production scanners)
//
// Two modes, and the difference is the whole point:
//
//   default  bench-local detectors (./detectors/*.mjs). These are approximations
//            written against the same fixtures they score, so a high score proves
//            the HARNESS is wired — never that /audit catches these classes.
//            Its value is regression detection on the fixture corpus.
//   --real   the production path: tools/skills/audit/collect-facts.mjs, the same
//            entry point /audit uses. This measures actual audit recall. A class
//            whose tool is absent reports `unavailable` — excluded from the score
//            and named in the output, never silently counted as a pass.
//
// Exit code: 0 if overall_recall >= threshold AND false_positives == 0.
//            1 otherwise (a low score is a valid, honest result — this
//            script never adjusts the gate to force a pass). In --real mode it
//            also exits 1 when NO class could be scored, because a bench that
//            measured nothing must not report success.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { scanSecrets } from "./detectors/secrets.mjs";
import { scanDeps } from "./detectors/deps-cve.mjs";
import { scanDeadCode } from "./detectors/dead-code.mjs";
import { scanDuplication } from "./detectors/duplication.mjs";
import { scanTypes } from "./detectors/types.mjs";
import { scanDrift } from "./detectors/drift.mjs";
import { runProductionCheck, PRODUCTION_CHECK_BY_CLASS } from "./real-scan.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_THRESHOLD = 0.7;

/**
 * Entries that exist only in --real mode.
 *
 * The committed secret fixture uses an obviously-unreal literal so that nothing
 * credential-shaped is ever stored in this repo. gitleaks is deliberately tuned
 * to ignore that shape, so the committed fixture cannot measure production
 * recall — it measures the bench regex only. These synthetic entries are written
 * to a temp dir at run time and deleted after, giving the secret class genuine
 * production coverage without committing a token-shaped literal.
 */
const SYNTHETIC_ENTRIES = [
  {
    id: "AU20-S01",
    class: "secret",
    planted: true,
    synthetic: "secret-detectable",
    detector: "secrets",
    signal: "Provider-prefixed token formats (sk_live_*, ghp_*) that gitleaks' shipped rules match.",
    note: "Synthesised at run time, never committed. Not live credentials.",
  },
];

function parseArgs(argv) {
  const out = { threshold: DEFAULT_THRESHOLD, json: false, real: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--threshold") out.threshold = Number(argv[++i]);
    else if (argv[i] === "--json") out.json = true;
    else if (argv[i] === "--real") out.real = true;
  }
  return out;
}

function readFixture(rel) {
  return readFileSync(path.join(HERE, rel), "utf8");
}

/** Runs the detector for one manifest entry, returns true if it fired (i.e. would flag). */
function detectorFired(entry) {
  switch (entry.detector) {
    case "secrets": {
      const src = readFixture(entry.file);
      return scanSecrets(src).some((f) => f.line === entry.line);
    }
    case "deps_cve": {
      const pkg = JSON.parse(readFixture(entry.file));
      return scanDeps(pkg).length > 0;
    }
    case "dead_code": {
      const src = readFixture(entry.file);
      return scanDeadCode(src).length > 0;
    }
    case "duplication": {
      const src = readFixture(entry.file);
      return scanDuplication(src).length > 0;
    }
    case "types": {
      const src = readFixture(entry.file);
      return scanTypes(src).some((f) => f.line === entry.line);
    }
    case "drift": {
      const doc = readFixture(entry.doc_file);
      const code = readFixture(entry.file);
      return scanDrift(doc, code) !== null;
    }
    default:
      throw new Error(`Unknown detector: ${entry.detector} (entry ${entry.id})`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = JSON.parse(readFileSync(path.join(HERE, "manifest.json"), "utf8"));
  const entries = args.real ? [...manifest.entries, ...SYNTHETIC_ENTRIES] : manifest.entries;

  const byClass = {};
  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;
  const missed = [];
  const fpEntries = [];
  const unavailable = [];

  for (const entry of entries) {
    const cls = entry.class;
    byClass[cls] ||= { planted: 0, caught: 0, negatives: 0, falsePositives: 0, unavailable: 0 };

    let fired;
    if (args.real) {
      const result = await runProductionCheck(entry);
      if (result.state !== "scored") {
        // Not a pass and not a fail. Excluded from every denominator and named
        // in the output — a missing scanner reading as "clean" is the defect
        // this bench exists to prevent.
        byClass[cls].unavailable++;
        unavailable.push({ id: entry.id, class: cls, check: PRODUCTION_CHECK_BY_CLASS[cls], reason: result.reason });
        continue;
      }
      fired = result.findings > 0;
    } else {
      fired = detectorFired(entry);
    }

    if (entry.planted) {
      byClass[cls].planted++;
      if (fired) {
        truePositives++;
        byClass[cls].caught++;
      } else {
        falseNegatives++;
        missed.push(entry.id);
      }
    } else {
      byClass[cls].negatives++;
      if (fired) {
        falsePositives++;
        byClass[cls].falsePositives++;
        fpEntries.push(entry.id);
      } else {
        trueNegatives++;
      }
    }
  }

  const totalPlanted = truePositives + falseNegatives;
  const overallRecall = totalPlanted > 0 ? truePositives / totalPlanted : 1;
  const overallPrecision =
    truePositives + falsePositives > 0 ? truePositives / (truePositives + falsePositives) : 1;

  const recallByClass = {};
  const precisionByClass = {};
  for (const [cls, stats] of Object.entries(byClass)) {
    recallByClass[cls] = stats.planted > 0 ? Number((stats.caught / stats.planted).toFixed(3)) : null;
    const classTP = stats.caught;
    const classFP = stats.falsePositives;
    precisionByClass[cls] = classTP + classFP > 0 ? Number((classTP / (classTP + classFP)).toFixed(3)) : 1;
  }

  const result = {
    mode: args.real ? "production-scanners" : "bench-local-detectors",
    fixture_count: entries.length,
    defect_classes: Object.keys(byClass),
    scored_classes: Object.entries(byClass).filter(([, s]) => s.planted + s.negatives > 0).map(([c]) => c),
    unavailable_classes: Object.entries(byClass).filter(([, s]) => s.planted + s.negatives === 0).map(([c]) => c),
    unavailable_entries: unavailable,
    negative_controls: entries.filter((e) => !e.planted).length,
    planted_defects: totalPlanted,
    recall_by_class: recallByClass,
    precision_by_class: precisionByClass,
    overall_recall: Number(overallRecall.toFixed(3)),
    overall_precision: Number(overallPrecision.toFixed(3)),
    true_positives: truePositives,
    false_negatives: falseNegatives,
    false_positives: falsePositives,
    true_negatives: trueNegatives,
    missed_defects: missed,
    false_positive_entries: fpEntries,
    gate_threshold: args.threshold,
  };

  // A run that scored nothing has proven nothing. In --real mode that is the
  // likely state on a machine missing knip/jscpd/tsc, and it must not read green.
  const noCoverage = totalPlanted === 0;
  const passed = !noCoverage && result.overall_recall >= args.threshold && result.false_positives === 0;
  result.gate_passed = passed;
  if (noCoverage) result.gate_failure_reason = "no planted defect could be scored — every relevant scanner was unavailable";

  // Qualification receipt: signed corpus digest + metrics + execution environment
  const corpusDigest = createHash('sha256').update(JSON.stringify(entries.map((e) => e.id).sort())).digest('hex');
  result.qualificationReceipt = {
    schemaVersion: 1,
    kind: 'audit-qualification-receipt',
    corpusDigest: `sha256:${corpusDigest}`,
    mode: result.mode,
    fixtureCount: result.fixture_count,
    metrics: {
      overallRecall: result.overall_recall,
      overallPrecision: result.overall_precision,
      falsePositives: result.false_positives,
      recallByClass: result.recall_by_class,
      precisionByClass: result.precision_by_class,
    },
    threshold: args.threshold,
    gatePassed: passed,
    executionEnvironment: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      timestamp: new Date().toISOString(),
    },
    unavailableClasses: result.unavailable_classes,
    scoredClasses: result.scored_classes,
  };
  result.qualificationReceipt.receiptDigest = `sha256:${createHash('sha256').update(JSON.stringify(result.qualificationReceipt)).digest('hex')}`;

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log("AU20 planted-finding bench");
    console.log("===========================");
    console.log(`Mode:                ${result.mode}`);
    if (args.real) {
      console.log("                     (measures real /audit recall via collect-facts.mjs)");
    } else {
      console.log("                     (bench-local approximations — proves the harness, NOT /audit)");
    }
    console.log(`Fixtures:            ${result.fixture_count} (${result.planted_defects} planted scored, ${result.negative_controls} negative controls)`);
    if (unavailable.length) {
      console.log("");
      console.log(`Unavailable (${unavailable.length}) — excluded from the score, never counted as passes:`);
      for (const u of unavailable) console.log(`  ${u.id.padEnd(10)} ${String(u.class).padEnd(15)} ${u.reason}`);
    }
    console.log("");
    console.log("Per-class recall / precision:");
    for (const cls of Object.keys(byClass)) {
      const r = recallByClass[cls];
      const p = precisionByClass[cls];
      console.log(`  ${cls.padEnd(16)} recall=${r === null ? "n/a" : r}  precision=${p}`);
    }
    console.log("");
    console.log(`Overall recall:      ${result.overall_recall}  (threshold ${args.threshold})`);
    console.log(`Overall precision:   ${result.overall_precision}`);
    console.log(`False positives:     ${result.false_positives}${fpEntries.length ? " (" + fpEntries.join(", ") + ")" : ""}`);
    console.log(`Missed defects:      ${missed.length ? missed.join(", ") : "none"}`);
    console.log("");
    console.log(passed ? "GATE: PASS" : `GATE: FAIL${result.gate_failure_reason ? " — " + result.gate_failure_reason : ""}`);
    console.log(`\nQualification receipt: ${result.qualificationReceipt.receiptDigest}`);
  }

  process.exit(passed ? 0 : 1);
}

await main();
