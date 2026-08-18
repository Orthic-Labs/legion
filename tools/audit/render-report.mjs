#!/usr/bin/env node
// render-report.mjs — turn facts.json (+ optional report.json findings) into ONE Markdown
// audit report: scanner-coverage proof table, NOT-SCANNED banners, top-N triage, findings
// grouped by remediation type with tiered fixes, and a re-run appendix.
//
// Usage: node render-report.mjs --facts <facts.json> [--report <report.json>] [--out <md>]
//
// report.json (produced by the reasoning lenses) shape (schema v2; v1 remains supported):
//   { schema_version:2, constraints_surface:[{scope,constraint,evidence,status}],
//     decomposition_assessments:[{file,trigger,verdict,rationale,evidence,findingId}],
//     findings:[{id,category,subtype,severity,evidence_strength,judgment,status,tier,file,line,
//                evidence,caused_by,title,detail,fix,sources,decomposition_plan}],
//     triage_top:[id,...], summary:{...} }
// decomposition_assessments contract: `file` is the candidate path (for a mechanical split, the
// split's dir); `evidence` entries are `path:line`/`path:start-end` loci; not-needed/confirmed on a
// file-size candidate needs at least one sub-span of the candidate (whole-file spans are rejected);
// not-needed at >=3x the review trigger OR >= the configured incoming-relationships threshold
// (`.agent/config.json → hygiene.secondAssessorIncomingRelationships`, default 25) needs
// `second_assessor:{verdict,rationale,evidence}` with an agreeing verdict (worse verdict wins) and
// evidence meeting the SAME candidate-anchor/sub-span bar as the primary; a confirmed verdict needs
// a `subtype:"decomposition"` finding whose plan passes validDecompositionPlan, including an
// `architect_decision_ref` that is a real FILE under `.audit/` or `docs/plans/` whose realpath
// stays inside the workspace (absolute, `../`, ".", directory, and symlink/junction-escape refs
// all rejected).
// ponytail: deterministic string assembly — no template engine, the report IS the output.

import { readFileSync, realpathSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname, basename, isAbsolute, resolve, sep } from 'node:path';

const args = process.argv.slice(2);
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const has = (n) => args.includes(n);
const cleanPath = (p) => p ? String(p).replace(/\\/g, '/').replace(/^\.\/+/, '').replace(/\/+$/, '') : null;
const filterDir = cleanPath(flag('--filter-dir'));
const inDir = (file, dir) => {
  const f = cleanPath(file);
  const d = cleanPath(dir);
  return !d || f === d || f.startsWith(d + '/');
};
const factsPath = flag('--facts'); if (!factsPath) { console.error('--facts required'); process.exit(2); }
const facts = JSON.parse(readFileSync(factsPath, 'utf8'));
const report = flag('--report') ? JSON.parse(readFileSync(flag('--report'), 'utf8')) : { findings: [], constraints_surface: [], triage_top: [], summary: {} };
// Did the reasoning lenses actually run? report.json MUST list which lenses produced output
// in `lenses_ran`. If absent/empty, this was a scanner-only pass — NEVER report it as clean.
const lensesRan = !!flag('--report') && Array.isArray(report.lenses_ran) && report.lenses_ran.length > 0;
const outPath = flag('--out') || join(dirname(factsPath), 'audit-report.md');

const SECURITY_CHECKS = new Set(['secrets', 'sast', 'ci_lint', 'docker', 'deps_cve', 'cargo_audit']);
// Allowed decision-record roots for architect_decision_ref (see architectDecisionRefExists).
const DECISION_REF_ROOTS = ['.audit/', 'docs/plans/'];
const REMEDIATION = { security: 'Secure', 'schema-drift': 'Schema-fix', 'doc-drift': 'Docs', architecture: 'Refactor', naming: 'Standardize', 'dead-file': 'Delete', 'ai-slop': 'Delete', minimize: 'Simplify', correctness: 'Fix', performance: 'Optimize', a11y: 'Accessibility', 'data-safety': 'Data-safety', 'ui-ux': 'UI/UX', resilience: 'Harden', 'platform-parity': 'Parity', 'release-readiness': 'Release' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const CAP = 5;                       // per-group body cap; overflow -> appendix
const icon = (s) => ({ ran: '✅', skipped: '⚠️', error: '⛔' }[s] || '•');
const repo = basename(facts.workspace || 'repo');
const date = (facts.generated_at || '').slice(0, 10);
const commit = (facts.checks.find(c => c.check === 'repo')?.meta?.commit || '').slice(0, 10);

const L = [];
const w = (s = '') => L.push(s);
const cell = (value) => String(value ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const constraintsSurface = (Array.isArray(report.constraints_surface) ? report.constraints_surface : []).map((constraint) => {
  const evidence = String(constraint?.evidence ?? '').trim();
  return {
    ...constraint,
    constraint: String(constraint?.constraint ?? '').trim() || 'unknown',
    evidence: evidence || 'unknown',
    status: evidence ? (constraint?.status || 'unknown') : 'unknown',
  };
});

// File size is a deterministic REVIEW TRIGGER, not an architecture verdict. The architecture lens
// must assess every runtime candidate and confirmed findings must carry a complete Architect plan.
// Never synthesize "split this file" merely because it crossed a LOC threshold.
const decompositionAssessments = Array.isArray(report.decomposition_assessments) ? report.decomposition_assessments : [];
const decompositionCandidates = [
  ...(facts.decomposition?.oversized || []).map((item) => ({ ...item, candidate: item.file, kind: 'file-size' })),
  // Mechanical splits are keyed by their containing dir; an assessment targets them via `file` = that dir.
  ...(facts.decomposition?.mechanical_splits || []).map((item) => ({ ...item, candidate: item.dir, kind: 'mechanical-split' })),
].filter((item) => inDir(item.candidate, filterDir));
const runtimeCandidates = decompositionCandidates.filter((item) => (item.class || 'runtime') === 'runtime');
const assessmentByFile = new Map(decompositionAssessments.map((item) => [cleanPath(item.file), item]));
const candidatePaths = new Set(decompositionCandidates.map((item) => cleanPath(item.candidate)));
const missingAssessments = runtimeCandidates.filter((item) => !assessmentByFile.has(cleanPath(item.candidate)));
const validVerdicts = new Set(['not-needed', 'confirmed', 'undetermined']);
// Assessment evidence must be `path:line` / `path:start-end` loci. For a not-needed/confirmed
// verdict on a file-size candidate, at least one entry must be a symbol-level SUB-span of the
// candidate — a whole-file span merely restates the trigger and is the cheap-stamp gaming vector.
const SPAN_RE = /^(.+?):(\d+)(?:-(\d+))?$/;
const parseSpan = (value) => {
  const match = SPAN_RE.exec(String(value ?? '').trim());
  return match ? { path: cleanPath(match[1]), start: Number(match[2]), end: match[3] ? Number(match[3]) : null } : null;
};
// A not-needed dismissal is high-stakes at >=3x the review trigger OR at/above the configurable
// incoming-relationships threshold (a heavily-depended-on module dismissed cheaply is the same
// risk class as a huge one). The renderer then requires a second independent assessor record on
// the assessment itself, held to the SAME evidence bar as the primary (candidate-anchored
// sub-spans, not just syntax). Self-reportable like the rest of report.json, but the forced shape
// stops a lazy loop from silently skipping the step, and a recorded disagreeing second verdict
// makes the not-needed stamp invalid (worse verdict wins).
const HIGH_STAKES_MULTIPLIER = 3;
const reviewTrigger = Number(facts.decomposition?.threshold);
const secondAssessorIncoming = (() => {
  try {
    const config = JSON.parse(readFileSync(join(facts.workspace, '.agent', 'config.json'), 'utf8'));
    const configured = Number(config?.hygiene?.secondAssessorIncomingRelationships);
    if (Number.isInteger(configured) && configured >= 1) return configured;
  } catch {}
  return 25; // workspace default — a module with 25+ incoming relationships is load-bearing
})();
// ONE evidence validator for primary and second assessor — asymmetry between the two was a bypass
// (second-assessor evidence passing on syntax alone, e.g. `README.md:1` or a whole-file span).
const evidenceProblems = (candidate, verdict, evidence, label) => {
  const problems = [];
  const entries = Array.isArray(evidence) ? evidence : [];
  if (!entries.length) { problems.push(`${label}missing evidence`); return problems; }
  const spans = entries.map(parseSpan);
  if (spans.some((span) => !span)) { problems.push(`${label}evidence entries must be \`path:line\` or \`path:start-end\` loci`); return problems; }
  if (candidate.kind === 'file-size' && (verdict === 'not-needed' || verdict === 'confirmed')) {
    const own = spans.filter((span) => span.path === cleanPath(candidate.candidate));
    if (!own.length) problems.push(`${label}no evidence anchored in the candidate file`);
    else if (Number.isFinite(candidate.loc) && own.every((span) => span.start <= 1 && (span.end ?? span.start) >= candidate.loc)) {
      problems.push(`${label}whole-file span is not symbol-level evidence — cite the specific responsibilities/symbols`);
    }
  }
  return problems;
};
const assessmentProblemsFor = (candidate, assessment) => {
  const problems = [];
  if (!validVerdicts.has(assessment.verdict)) problems.push(`invalid verdict ${JSON.stringify(assessment.verdict ?? null)}`);
  if (!String(assessment.rationale || '').trim()) problems.push('missing rationale');
  problems.push(...evidenceProblems(candidate, assessment.verdict, assessment.evidence, ''));
  if (assessment.verdict === 'not-needed') {
    const size = candidate.kind === 'mechanical-split' ? candidate.logical_loc : candidate.loc;
    const bySize = Number.isFinite(reviewTrigger) && Number.isFinite(size) && size >= reviewTrigger * HIGH_STAKES_MULTIPLIER;
    const incoming = Number(candidate.incomingRelationships);
    const byIncoming = candidate.graphMetrics === 'available' && Number.isFinite(incoming) && incoming >= secondAssessorIncoming;
    if (bySize || byIncoming) {
      const trigger = bySize
        ? `${size} LOC (>=${HIGH_STAKES_MULTIPLIER}x trigger ${reviewTrigger})`
        : `${incoming} incoming relationships (>=${secondAssessorIncoming})`;
      const second = assessment.second_assessor;
      if (!second || typeof second !== 'object') {
        problems.push(`not-needed at ${trigger} requires second_assessor {verdict,rationale,evidence}`);
      } else {
        if (second.verdict !== 'not-needed') problems.push(`second assessor verdict ${JSON.stringify(second.verdict ?? null)} — worse verdict wins, not-needed cannot stand`);
        if (!String(second.rationale || '').trim()) problems.push('second_assessor missing rationale');
        problems.push(...evidenceProblems(candidate, 'not-needed', second.evidence, 'second_assessor: '));
      }
    }
  }
  return problems;
};
const invalidAssessments = runtimeCandidates.flatMap((candidate) => {
  const assessment = assessmentByFile.get(cleanPath(candidate.candidate));
  if (!assessment) return [];
  const problems = assessmentProblemsFor(candidate, assessment);
  return problems.length ? [{ candidate: candidate.candidate, problems }] : [];
});
const assessmentProblemsByFile = new Map(invalidAssessments.map((item) => [cleanPath(item.candidate), item.problems]));
const invalidConfirmed = decompositionAssessments.filter((assessment) => {
  if (assessment.verdict !== 'confirmed') return false;
  const finding = (report.findings || []).find((item) => item.id === assessment.findingId);
  return !finding || finding.subtype !== 'decomposition' || !validDecompositionPlan(finding.decomposition_plan);
});
const undeterminedAssessments = runtimeCandidates.filter((item) => assessmentByFile.get(cleanPath(item.candidate))?.verdict === 'undetermined');
const orphanAssessments = decompositionAssessments.filter((item) => !candidatePaths.has(cleanPath(item.file)));
const decompositionCoverage = {
  candidates: decompositionCandidates.length,
  runtime_candidates: runtimeCandidates.length,
  assessed: runtimeCandidates.length - missingAssessments.length,
  missing: missingAssessments.map((item) => item.candidate),
  invalid_assessments: invalidAssessments,
  invalid_confirmed: invalidConfirmed.map((item) => item.file),
  // undetermined is honest in read-only audit but is OPEN work in audit-fix — never "clean".
  undetermined: undeterminedAssessments.map((item) => item.candidate),
  // informational: assessments for paths that are not size candidates (a below-trigger review is legal).
  orphan_assessments: orphanAssessments.map((item) => item.file),
  complete: missingAssessments.length === 0 && invalidAssessments.length === 0 && invalidConfirmed.length === 0,
};
report.findings = dedupe(report.findings || []).filter(f => inDir(f.file || '', filterDir));   // collapse scanner+lens overlaps before scoring/triage
if (filterDir) report.triage_top = (report.triage_top || []).filter(id => report.findings.some(f => f.id === id));

// AU14 fingerprint helpers — module-scope consts must exist before computeTrajectory() is called below.
const AGING_BUCKETS = [
  { bucket: '0-7d', maxDays: 7 },
  { bucket: '8-30d', maxDays: 30 },
  { bucket: '31-90d', maxDays: 90 },
  { bucket: '90+d', maxDays: Infinity },
];
const AGE_THRESHOLD_DAYS = 30;   // matched findings older than this count as "aged" rather than "unchanged"
const fingerprint = (f) => `${cleanPath(f.file) || 'unknown'}:${f.line ?? ''}::${f.category || 'unknown'}::${String(f.title || '').trim().toLowerCase()}`;
const looseFingerprint = (f) => `${f.category || 'unknown'}::${String(f.title || '').trim().toLowerCase()}::${basename(cleanPath(f.file) || 'unknown')}`;
const bucketFor = (days) => (AGING_BUCKETS.find((b) => days <= b.maxDays) || AGING_BUCKETS[AGING_BUCKETS.length - 1]).bucket;

const gate = qualityGate(facts);
const coverage = coverageGate(report.coverage);        // AU13 — per-change coverage rows (see references/coverage-and-trajectory.md)
const trajectory = computeTrajectory(report, facts);    // AU14 — audit_diff trajectory vs prior run

if (has('--agent')) {
  const summary = {
    kind: 'audit-agent-summary',
    schema_version: Number(report.schema_version) || 1,
    workspace: facts.workspace,
    generated_at: facts.generated_at,
    scope: facts.scope || null,
    filter_dir: filterDir || null,
    incomplete: !!facts.incomplete || !lensesRan || !decompositionCoverage.complete,
    lenses_ran: lensesRan ? (report.lenses_ran || []) : false,
    quality_gate: gate.state,   // CLEAN | NOT CLEAN | UNPROVEN — 0 warnings/errors across lint·types·build
    quality_gate_failed: gate.failed.map(c => ({ check: c.check, tool: c.tool || null, findings: c.findings_count ?? null, exit: c.exit_code ?? null })),
    coverage_gate: coverage ? { state: coverage.state, ratio: coverage.ratio, severity: coverage.severity, no_test_files: coverage.noTestFiles } : null,
    audit_diff: trajectory,
    constraints_surface: constraintsSurface.map(c => ({
      scope: c.scope || null,
      constraint: c.constraint || 'unknown',
      evidence: c.evidence || 'unknown',
      status: c.status || 'unknown',
    })),
    decomposition_coverage: decompositionCoverage,
    decomposition_assessments: decompositionAssessments,
    findings: report.findings.map(f => ({
      id: f.id,
      severity: f.severity,
      tier: f.tier || 'MANUAL',
      category: f.category,
      file: f.file,
      line: f.line ?? null,
      title: f.title,
      action: f.action || '',
      evidence: f.evidence || '',
      evidence_strength: f.evidence_strength || null,
      judgment: f.judgment || null,
      status: f.status || null,
      caused_by: Array.isArray(f.caused_by) ? f.caused_by : [],
      sources: f.sources || [],
      decomposition_plan: f.decomposition_plan || null,
    })),
  };
  console.log(JSON.stringify(summary, null, 2));
  process.exit(0);
}

// ---- header ----
w(`# Audit — ${repo} · ${date}${commit ? ' · ' + commit : ''}`);
if (facts.incomplete) w(`\n> ⛔ **INCOMPLETE** — a required scanner did not run. Findings below are partial; see §1.`);
if (!lensesRan) w(`\n> ⛔ **REASONING LENSES NOT RUN** — scanner-only pass. Decomposition (beyond the deterministic LOC floor), architecture quality, AI-slop, correctness, and minimize were NOT assessed. Health score withheld; do NOT report this audit as clean.`);
if (lensesRan && !decompositionCoverage.complete) w(`\n> ⛔ **DECOMPOSITION REVIEW INCOMPLETE** — ${missingAssessments.length} runtime size candidate(s) were not assessed, ${invalidAssessments.length} assessment(s) fail the evidence bar (verdict/rationale/symbol-level loci), and ${invalidConfirmed.length} confirmed assessment(s) lack a complete, on-disk Architect target design. LOC is not a verdict; complete the evidence-backed architecture review.`);
const score = healthScore(report, facts, lensesRan && decompositionCoverage.complete);
w(`\n**Repo health: ${score == null ? '_withheld — lenses not run_' : score + '/100 (' + (score >= 85 ? 'good' : score >= 60 ? 'fair' : 'poor') + ')'}** · ${report.findings.length} findings · ${facts.checks.filter(c => c.status === 'ran').length}/${facts.checks.length} checks ran${lensesRan ? '' : ' · ⚠️ lenses not run'}`);
// Quality gate — the literal "clean = 0 warnings/errors" bar. Deliberately SEPARATE from the health
// score: the score reflects lens findings and can read "good" while clippy/eslint/biome/tsc still carry
// warnings. This line is scanner-driven and valid even on a lenses-not-run pass.
const gateIcon = { 'CLEAN': '✅', 'NOT CLEAN': '⛔', 'UNPROVEN': '⚠️' }[gate.state] || '•';
w(`\n**Quality gate: ${gateIcon} ${gate.state}** — clean requires 0 warnings/errors across \`lint\` · \`types\` · \`build\`.`);
if (gate.failed.length) w(`> ⛔ ${gate.failed.map(c => `\`${c.check}\`${c.tool ? ` (${c.tool})` : ''} = ${(c.findings_count ?? 0) > 0 ? c.findings_count + ' finding(s)' : 'exit ' + c.exit_code}`).join(' · ')} — must reach **0** to be called clean.`);
if (gate.state === 'UNPROVEN') w(`> ⚠️ Cannot certify clean — ${gate.unproven.map(c => `\`${c.check}\` ${c.status}${c.tool ? ` (${c.tool})` : ''}`).join(', ')} did not run. Install the tool / wire the linter, then re-audit.`);
w('');
// Trajectory (AU14) — direction, not just a snapshot. First-ever run has no prior history to diff.
if (trajectory.vs_prior_run) {
  const v = trajectory.vs_prior_run;
  w(`**Trajectory vs prior run** (${v.prior_run_at ? v.prior_run_at.slice(0, 10) : 'unknown'}): resolved ${v.resolved} · new ${v.new} · aged ${v.aged} · unchanged ${v.unchanged} · newly-P0 ${v.newly_p0}`);
} else {
  w(`**Trajectory:** first recorded run at this history path — no prior snapshot to diff against yet. Re-run to see \`audit_diff\`.`);
}
w(`_Aging: ${trajectory.aging_buckets.map(b => `${b.bucket}=${b.count}`).join(' · ')}_`);
w('');
if (facts.scope) {
  const s = facts.scope;
  w(`Scope: ${s.mode || 'whole-repo'} · type=${s.type || 'all'}${s.dir ? ' · dir=' + s.dir : ''}${s.base ? ' · base=' + s.base : ''}${s.base_commit ? ' · base_commit=' + s.base_commit : ''} · changed_files=${(s.changed_files || []).length}`);
  w('');
}
if (filterDir) {
  w(`Filter: findings under \`${filterDir}\``);
  w('');
}

if (constraintsSurface.length) {
  w('## 0 · Constraints surface');
  w('_Evidence-backed constraints that bound recommendations; `unknown` is explicit, never guessed._\n');
  w('| scope | constraint | evidence | status |');
  w('|---|---|---|---|');
  for (const c of constraintsSurface) {
    w(`| ${cell(c.scope || 'general')} | ${cell(c.constraint || 'unknown')} | ${cell(c.evidence || 'unknown')} | ${cell(c.status || 'unknown')} |`);
  }
  w('');
}

// ---- §1 proof ----
w('## 1 · Proof — scanner coverage');
w('_Re-run any command to verify — the audit does not ask you to trust it._\n');
w('| check | tool | command | status | exit | findings | candidates | log |');
w('|---|---|---|---|---|---|---|---|');
for (const c of facts.checks) {
  const cmd = c.command ? '`' + c.command + '`' : '—';
  const reason = c.status !== 'ran' && c.skip_reason ? ` _(${c.skip_reason})_` : '';
  w(`| ${c.check} | ${c.tool || '—'} | ${cmd} | ${icon(c.status)} ${c.status}${reason} | ${c.exit_code ?? '—'} | ${c.findings_count ?? '—'} | ${c.candidate_count ?? '—'} | ${c.log || '—'} |`);
}
w('');
// NOT-SCANNED banners for security checks that did not run
// not-applicable skips ("no Dockerfile", "no Cargo.toml"…) are not coverage gaps — no banner for those.
for (const c of facts.checks.filter(c => SECURITY_CHECKS.has(c.check) && c.status !== 'ran' && !/^no /i.test(c.skip_reason || ''))) {
  w(`> ⚠️ **NOT SCANNED: ${c.check} (${c.tool || 'n/a'}).** ${c.skip_reason || 'did not run'}. Any ${c.check} statement below is an unverified LLM hint, **not** a scan result — treat as untriaged.`);
}
w('');

// ---- §2 decomposition review ----
w('## 2 · Decomposition assessments');
w('_LOC/bytes only trigger review. A confirmed verdict requires responsibility, dependency, state, caller, and test evidence plus an Architect target design._\n');
if (!decompositionCandidates.length) w('_No size-triggered components._');
for (const candidate of decompositionCandidates) {
  const assessment = assessmentByFile.get(cleanPath(candidate.candidate));
  const size = candidate.kind === 'mechanical-split'
    ? `${candidate.logical_loc} reconstructed LOC across ${candidate.parts} parts`
    : `${candidate.loc} LOC${candidate.bytes ? ` / ${candidate.bytes} bytes` : ''}`;
  if (!assessment) {
    w(`- \`${candidate.candidate}\` — **unassessed** (${size}; review trigger only)`);
    continue;
  }
  w(`- \`${candidate.candidate}\` — **${assessment.verdict}** (${size}) — ${assessment.rationale || 'no rationale supplied'}${assessment.findingId ? ` · finding \`${assessment.findingId}\`` : ''}`);
  if (Array.isArray(assessment.evidence) && assessment.evidence.length) w(`  - evidence: ${assessment.evidence.map((item) => `\`${item}\``).join(', ')}`);
  const problems = assessmentProblemsByFile.get(cleanPath(candidate.candidate));
  if (problems) w(`  - ⛔ invalid assessment: ${problems.join('; ')}`);
}
if (undeterminedAssessments.length) w(`\n> ⚠️ ${undeterminedAssessments.length} runtime candidate(s) are **undetermined**. Honest in a read-only audit (the assessment must name the missing evidence); in audit-fix these are OPEN work — gather the evidence or report them OPEN, never fold them into "clean".`);
w('');

// ---- §2A test coverage on the change (AU13) ----
w('## 2A · Test coverage on the change');
w('_Read of the diff against the test set — no test execution. Below 0.8 coverage ratio is high, below 0.5 (or any touched symbol with zero covering test) is critical. `UNPROVEN` when the repo has no test infrastructure to read against — never reported as clean._\n');
if (!coverage) {
  w('_Not reported this run — coverage-on-the-change is diff-scoped lens output (see `/commit`, `references/coverage-and-trajectory.md`). A whole-repo `/audit` pass may have nothing to diff against._');
} else {
  const covIcon = coverage.state === 'CLEAN' ? '✅' : coverage.state === 'UNPROVEN' ? '⚠️' : '⛔';
  w(`**Coverage gate: ${covIcon} ${coverage.state}** — ratio ${coverage.ratio == null ? 'unproven (no test infrastructure)' : (coverage.ratio * 100).toFixed(0) + '%'}${coverage.severity ? ` · severity: **${coverage.severity}**` : ''}`);
  if (coverage.noTestFiles.length) w(`> ⛔ ${coverage.noTestFiles.length} touched file(s) have **no covering test at all**: ${coverage.noTestFiles.map((f) => `\`${f}\``).join(', ')}`);
  w('');
  w('| file | touched | covered | uncovered | tests | verdict |');
  w('|---|---|---|---|---|---|');
  for (const row of coverage.perFile) {
    w(`| \`${cell(row.file)}\` | ${cell((row.touched || []).join(', ') || '—')} | ${cell((row.covered || []).join(', ') || '—')} | ${cell((row.uncovered || []).join(', ') || '—')} | ${cell((row.tests || []).join(', ') || '—')} | ${cell(row.verdict || 'unknown')} |`);
  }
}
w('');

// ---- §3 triage ----
const byId = Object.fromEntries(report.findings.map(f => [f.id, f]));
let top = (report.triage_top || []).map(id => byId[id]).filter(Boolean);
if (!top.length) top = [...report.findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)).slice(0, 10);
w('## 3 · Top 10 that matter');
if (!top.length) w('_No findings._');
top.slice(0, 10).forEach((f, i) => w(`${i + 1}. \`[${f.severity}][${f.tier || 'MANUAL'}]\` **${f.title}** — \`${f.file}${f.line ? ':' + f.line : ''}\` (${f.id})`));
w('');

// ---- §4 findings by remediation ----
w('## 4 · Findings by remediation type');
const groups = {};
for (const f of report.findings) (groups[REMEDIATION[f.category] || 'Other'] ??= []).push(f);
const overflow = [];
for (const [group, items] of Object.entries(groups)) {
  items.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const body = items.slice(0, CAP), rest = items.slice(CAP);
  overflow.push(...rest);
  w(`\n### ${group} (${items.length}${rest.length ? `, ${body.length} shown` : ''})`);
  for (const f of body) renderFinding(f);
}
if (!report.findings.length) w('\n_No findings emitted by the reasoning lenses._');
w('');

// ---- §5 skipped ----
w('## 5 · Skipped / not-scanned');
const skipped = facts.checks.filter(c => c.status !== 'ran');
if (!skipped.length) w('_Every check ran._');
for (const c of skipped) w(`- **${c.check}** (${c.tool || 'n/a'}): ${c.status} — ${c.skip_reason || ''}`);
w('');

// ---- §6 appendix ----
w('## 6 · Appendix');
if (overflow.length) { w(`\n### Overflow findings (${overflow.length})`); for (const f of overflow) renderFinding(f); }
w('\n### Re-run commands');
for (const c of facts.checks.filter(c => c.command)) w(`- \`${c.command}\`  → ${c.log || '(no log)'}`);
w('\n### Raw logs');
w(`Evidence dir: \`${facts.out_dir}\``);

writeFileSync(outPath, L.join('\n'), 'utf8');
console.log(`render-report → ${outPath}  (${report.findings.length} findings, ${facts.checks.filter(c=>c.status==='ran').length}/${facts.checks.length} checks ran)`);

// Quality gate: a repo is CLEAN only when every build/lint/type check RAN and returned zero
// findings (0 warnings, 0 errors). A gate check that is `error` or skipped because its TOOL is
// absent ⇒ UNPROVEN (cannot certify — never silently clean). A structural "no <thing>" skip (no
// linter configured, no build script, no typed stack) is not a gate member — it can't fail a bar
// it isn't subject to. The `/^no /i` discriminator mirrors the NOT-SCANNED banner logic above.
function qualityGate(facts) {
  const GATE_CHECKS = new Set(['lint', 'types', 'build']);
  const relevant = (facts.checks || []).filter(c => GATE_CHECKS.has(c.check));
  const failed = relevant.filter(c => c.status === 'ran' && ((c.findings_count || 0) > 0 || (c.exit_code != null && c.exit_code !== 0)));
  const unproven = relevant.filter(c => c.status === 'error' || (c.status === 'skipped' && !/^no /i.test(c.skip_reason || '')));
  const ran = relevant.filter(c => c.status === 'ran');
  if (failed.length) return { state: 'NOT CLEAN', failed, unproven, ran };
  if (unproven.length || !ran.length) return { state: 'UNPROVEN', failed, unproven, ran };
  return { state: 'CLEAN', failed, unproven, ran };
}

// AU13 — per-change coverage rows. `report.coverage` is lens-computed input (a READ of the diff
// against the test set, no test execution) in the shape locked with /commit's schema:
//   { ratio, perFile:[{file,touched,covered,uncovered,tests,verdict}] }
// Absent entirely on a whole-repo /audit pass — this is diff-scoped and there is nothing to render.
// A touched file with an empty `tests` array is critical on any non-trivial change regardless of the
// aggregate ratio; a missing/unreadable ratio means the repo has no test infrastructure to read
// against, which is UNPROVEN, never CLEAN.
function coverageGate(coverage) {
  if (!coverage || !Array.isArray(coverage.perFile) || !coverage.perFile.length) return null;
  const perFile = coverage.perFile;
  const totalTouched = perFile.reduce((n, f) => n + (Array.isArray(f.touched) ? f.touched.length : 0), 0);
  const totalCovered = perFile.reduce((n, f) => n + (Array.isArray(f.covered) ? f.covered.length : 0), 0);
  const ratio = Number.isFinite(coverage.ratio) ? coverage.ratio : (totalTouched ? totalCovered / totalTouched : null);
  const noTestFiles = perFile.filter((f) => (!Array.isArray(f.tests) || !f.tests.length) && Array.isArray(f.touched) && f.touched.length);
  let state, severity;
  if (ratio == null) { state = 'UNPROVEN'; severity = null; }
  else if (noTestFiles.length || ratio < 0.5) { state = 'NOT CLEAN'; severity = 'critical'; }
  else if (ratio < 0.8) { state = 'NOT CLEAN'; severity = 'high'; }
  else { state = 'CLEAN'; severity = null; }
  return { state, ratio, severity, noTestFiles: noTestFiles.map((f) => f.file), perFile };
}

// AU14 — audit_diff trajectory. The RUNNER (this renderer), not the lenses, owns history: it persists
// a compact fingerprint digest at `<workspace>/.audit/audit-trajectory.json` (override via
// `--trajectory-history <path>`) and diffs the CURRENT finding set against that digest on every
// invocation. Fingerprint = file:line + category + title (case-folded); when no exact match survives
// we retry once on category+title+basename(file) so a same-run rename isn't double-counted as both
// resolved and new — the loose match is accepted only when it is a unique 1:1 pairing on both sides.
function computeTrajectory(report, facts) {
  const historyPath = flag('--trajectory-history') || join(facts.workspace || dirname(factsPath), '.audit', 'audit-trajectory.json');
  const nowIso = facts.generated_at || new Date().toISOString();
  const now = Date.parse(nowIso) || Date.now();

  let history = null;
  try { history = JSON.parse(readFileSync(historyPath, 'utf8')); } catch {}
  const priorEntries = history && history.fingerprints && typeof history.fingerprints === 'object' ? history.fingerprints : {};
  const priorRunAt = history && history.run_at ? history.run_at : null;
  const hadPriorRun = !!priorRunAt || Object.keys(priorEntries).length > 0;

  const current = Array.isArray(report.findings) ? report.findings : [];
  const currentFps = current.map((f) => ({ f, fp: fingerprint(f), loose: looseFingerprint(f) }));

  const matchedPrior = new Set();
  const matchedCurrent = new Set();
  const matches = [];   // { fp, prior:{severity,first_seen}, current:{f,fp,loose} }

  // pass 1 — exact fingerprint match
  for (const item of currentFps) {
    if (priorEntries[item.fp] && !matchedPrior.has(item.fp)) {
      matches.push({ fp: item.fp, prior: priorEntries[item.fp], current: item });
      matchedPrior.add(item.fp);
      matchedCurrent.add(item.fp);
    }
  }
  // pass 2 — loose (rename-tolerant) match, unambiguous 1:1 leftovers only
  const priorByLoose = new Map();
  for (const [fp, entry] of Object.entries(priorEntries)) {
    if (matchedPrior.has(fp) || !entry.loose) continue;
    if (!priorByLoose.has(entry.loose)) priorByLoose.set(entry.loose, []);
    priorByLoose.get(entry.loose).push(fp);
  }
  for (const item of currentFps) {
    if (matchedCurrent.has(item.fp)) continue;
    const candidates = priorByLoose.get(item.loose);
    if (candidates && candidates.length === 1 && !matchedPrior.has(candidates[0])) {
      const fp = candidates[0];
      matches.push({ fp: item.fp, prior: priorEntries[fp], current: item });
      matchedPrior.add(fp);
      matchedCurrent.add(item.fp);
    }
  }

  const matchByCurrentFp = new Map(matches.map((m) => [m.fp, m]));
  let aged = 0, unchanged = 0, newlyP0 = 0;
  for (const m of matches) {
    const firstSeen = Date.parse(m.prior.first_seen) || now;
    const ageDays = (now - firstSeen) / 86400000;
    if (ageDays > AGE_THRESHOLD_DAYS) aged++; else unchanged++;
    const wasCritical = m.prior.severity === 'critical';
    const isCritical = m.current.f.severity === 'critical';
    if (isCritical && !wasCritical) newlyP0++;
  }
  const newFindings = currentFps.filter((item) => !matchedCurrent.has(item.fp));
  for (const item of newFindings) if (item.f.severity === 'critical') newlyP0++;
  const resolvedCount = Object.keys(priorEntries).length - matchedPrior.size;

  // aging buckets over the FULL current finding set: matched findings keep their prior first_seen,
  // new findings start the clock at this run.
  const bucketCounts = new Map(AGING_BUCKETS.map((b) => [b.bucket, 0]));
  for (const item of currentFps) {
    const m = matchByCurrentFp.get(item.fp);
    const firstSeen = m ? (Date.parse(m.prior.first_seen) || now) : now;
    const ageDays = (now - firstSeen) / 86400000;
    const bucket = bucketFor(ageDays);
    bucketCounts.set(bucket, (bucketCounts.get(bucket) || 0) + 1);
  }
  const agingBuckets = AGING_BUCKETS.map((b) => ({ bucket: b.bucket, count: bucketCounts.get(b.bucket) || 0 }));

  const auditDiff = {
    vs_prior_run: hadPriorRun
      ? { prior_run_at: priorRunAt, resolved: resolvedCount, new: newFindings.length, aged, unchanged, newly_p0: newlyP0 }
      : null,
    aging_buckets: agingBuckets,
  };

  // Persist the fresh digest for the NEXT run. first_seen carries forward on a match; new findings
  // reset the clock. Never block the render on a write failure — trajectory is best-effort history.
  const nextFingerprints = {};
  for (const item of currentFps) {
    const m = matchByCurrentFp.get(item.fp);
    nextFingerprints[item.fp] = {
      severity: item.f.severity || 'low',
      first_seen: m ? (m.prior.first_seen || nowIso) : nowIso,
      last_seen: nowIso,
      loose: item.loose,
    };
  }
  try {
    mkdirSync(dirname(historyPath), { recursive: true });
    writeFileSync(historyPath, JSON.stringify({ run_at: nowIso, fingerprints: nextFingerprints }, null, 2), 'utf8');
  } catch (err) {
    console.error(`audit-trajectory: could not persist history at ${historyPath}: ${err.message}`);
  }

  return auditDiff;
}

function healthScore(report, facts, lensesRan) {
  if (!lensesRan) return null;   // scanner-only pass — a clean score would be a lie
  const w = { critical: 25, high: 12, medium: 5, low: 1 };
  let s = 100;
  for (const f of report.findings) s -= (w[f.severity] || 1);
  if (facts.incomplete) s -= 10;
  return Math.max(0, Math.min(100, s));
}

function dedupe(findings) {
  const evidenceOrder = { verified: 0, 'strong-inference': 1, possible: 2 };
  const seen = new Map();
  for (const f of findings) {
    // line-specific findings merge by location (scanner + lens on the same line); file-level
    // findings (line null, e.g. multiple CVEs on package.json) merge by title so distinct ones survive.
    const key = f.line != null ? `${f.file}::${f.line}::${f.category}` : `${f.file}::${f.category}::${f.title}`;
    const prev = seen.get(key);
    if (prev) {
      prev.sources = [...new Set([...(prev.sources || []), ...(f.sources || [])])];
      prev.caused_by = [...new Set([...(prev.caused_by || []), ...(f.caused_by || [])])];
      if ((evidenceOrder[f.evidence_strength] ?? 9) < (evidenceOrder[prev.evidence_strength] ?? 9)) {
        prev.evidence_strength = f.evidence_strength;
      }
      if (f.status === 'disputed') prev.status = 'disputed';
      if (f.judgment === 'interpretive') prev.judgment = 'interpretive';
      if ((SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[prev.severity] ?? 9)) { prev.severity = f.severity; prev.title = f.title; prev.detail = f.detail; }
    } else seen.set(key, { ...f, sources: f.sources || [] });
  }
  return [...seen.values()];
}

function renderFinding(f) {
  const meta = [
    f.evidence_strength && `evidence-strength: **${f.evidence_strength}**`,
    f.judgment && `judgment: **${f.judgment}**`,
    f.status && `status: **${f.status}**`,
  ].filter(Boolean);
  w(`\n**[${f.id}] ${f.title}**  \`${f.severity}\` · tier: **${f.tier || 'MANUAL'}** · \`${f.file}${f.line ? ':' + f.line : ''}\`${f.evidence ? ' · evidence: `' + f.evidence + '`' : ''}${meta.length ? ' · ' + meta.join(' · ') : ''}`);
  if (Array.isArray(f.caused_by) && f.caused_by.length) {
    w(`caused by: ${f.caused_by.map(id => `\`${id}\``).join(', ')}`);
  }
  if (f.detail) w(`> ${f.detail}`);
  if (f.action) w(`**Fix:** ${f.action}`);
  if (f.fix) {
    const isDiff = /^[-+]/m.test(f.fix);
    w('```' + (isDiff ? 'diff' : '')); w(f.fix); w('```');
  }
  if (f.subtype === 'decomposition' && f.decomposition_plan) renderDecompositionPlan(f.decomposition_plan);
}

function validDecompositionPlan(plan) {
  return !!plan
    && plan.verdict === 'confirmed'
    && Array.isArray(plan.current_responsibilities) && plan.current_responsibilities.length > 1
    && plan.current_responsibilities.every((item) => item.name && Array.isArray(item.symbols) && item.symbols.length > 0 && Array.isArray(item.evidence) && item.evidence.length > 0)
    && plan.keep_in_place?.component && plan.keep_in_place?.responsibility
    && Array.isArray(plan.target_components) && plan.target_components.length > 0
    && plan.target_components.every((item) => item.component && item.destination && item.responsibility && Array.isArray(item.moves) && item.moves.length > 0 && item.public_contract && Array.isArray(item.dependencies))
    && Array.isArray(plan.steps) && plan.steps.length > 0
    && plan.steps.every((item) => item.change && item.verification)
    && Array.isArray(plan.behavior_contracts) && plan.behavior_contracts.length > 0
    && Array.isArray(plan.risks) && plan.risks.length > 0
    && architectDecisionRefExists(plan.architect_decision_ref);
}

// The ADR/plan reference must be a real regular FILE inside one of the documented decision-record
// roots — read-only /audit writes under `.audit/` (e.g. `.audit/<ts>/architect/` or the typed
// `.audit/architect/decisions.jsonl`), audit-fix/direct Architect writes `docs/plans/`. Validation
// is physical, not lexical: repo-relative only, must start with an allowed root, and both lexical
// resolution AND realpath (symlink/junction-following) must stay inside the workspace, ending at
// stat().isFile(). This rejects absolute refs, `../` escapes, `"."`/directories, and
// junction/symlink hops that point outside the repository. Roots: DECISION_REF_ROOTS (top of file).
function architectDecisionRefExists(ref) {
  if (typeof ref !== 'string' || !ref.trim()) return false;
  if (isAbsolute(ref)) return false;
  const norm = cleanPath(ref);
  if (!norm || !DECISION_REF_ROOTS.some((allowed) => norm.startsWith(allowed))) return false;
  const root = resolve(facts.workspace || dirname(factsPath));
  const target = resolve(root, norm);
  const allowedRoot = DECISION_REF_ROOTS
    .map((allowed) => resolve(root, allowed))
    .find((candidate) => target.startsWith(candidate + sep));
  if (!allowedRoot) return false;
  try {
    const realRoot = realpathSync(root);
    const realAllowedRoot = realpathSync(allowedRoot);
    const real = realpathSync(target);
    if (!realAllowedRoot.startsWith(realRoot + sep)) return false;
    if (!real.startsWith(realAllowedRoot + sep)) return false;
    return statSync(real).isFile();
  } catch {
    return false; // missing file, dangling link, or unreadable path — never valid
  }
}

function renderDecompositionPlan(plan) {
  w('\n#### Decomposition design');
  w(`**Verdict:** ${plan.verdict}`);
  w('\n**Current responsibilities**');
  for (const item of (plan.current_responsibilities || [])) {
    w(`- **${item.name}** — symbols: ${(item.symbols || []).map((symbol) => `\`${symbol}\``).join(', ') || 'unknown'}; evidence: ${(item.evidence || []).map((evidence) => `\`${evidence}\``).join(', ') || 'unknown'}`);
  }
  const keep = plan.keep_in_place || {};
  w(`\n**Keep in place:** **${keep.component || 'unknown'}** — ${keep.responsibility || 'unknown'}${Array.isArray(keep.symbols) && keep.symbols.length ? `; symbols: ${keep.symbols.map((symbol) => `\`${symbol}\``).join(', ')}` : ''}`);
  w('\n**Target components**');
  w('| component | destination | responsibility | moves | public contract | dependencies |');
  w('|---|---|---|---|---|---|');
  for (const item of (plan.target_components || [])) {
    w(`| ${cell(item.component)} | \`${cell(item.destination)}\` | ${cell(item.responsibility)} | ${cell((item.moves || []).join(', '))} | \`${cell(item.public_contract)}\` | ${cell((item.dependencies || []).join(', ') || 'none')} |`);
  }
  w('\n**Implementation sequence**');
  for (const item of (plan.steps || [])) w(`${item.order || 1}. ${item.change} — verify: ${item.verification}`);
  w('\n**Behavior-preservation contracts**');
  for (const item of (plan.behavior_contracts || [])) w(`- ${item}`);
  if (Array.isArray(plan.risks) && plan.risks.length) {
    w('\n**Risks**');
    for (const item of plan.risks) w(`- ${item}`);
  }
  w(`\n**Architect decision:** \`${plan.architect_decision_ref || 'missing'}\``);
}
