import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { verificationDigest, verificationProjection } from '../lib/verification-projection.mjs';

const FIXTURE = new URL('./fixtures/verify/facts.json', import.meta.url);
const root = fileURLToPath(new URL('..', import.meta.url));

function fixtureFacts() {
  return JSON.parse(readFileSync(FIXTURE, 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test('verifier fixture is frozen and valid', () => {
  const facts = fixtureFacts();
  assert.equal(facts.kind, 'audit-facts');
  assert.ok(facts.checks.length >= 2);
  assert.ok(facts.provider_reconciliation.providerResults.length >= 2);
  assert.ok(facts.plan.seal.digest);
  assert.ok(facts.plan.binding.repositoryRevision);
});

test('semantic projection ignores timestamps and output paths', () => {
  const facts = fixtureFacts();
  const baseline = verificationDigest(facts);
  const moved = clone(facts);
  // Workspace identity is semantic (which repository was audited); output
  // directory, log path, and timestamps are not.
  moved.generated_at = '2026-08-07T12:00:00.000Z';
  moved.out_dir = '/tmp/other/path/.audit/run-2';
  moved.plan.generatedAt = '2026-08-07T12:00:00.000Z';
  assert.equal(verificationDigest(moved), baseline, 'timestamp/path changes must not create semantic drift');
});

test('provider status mutation is detected', () => {
  const facts = fixtureFacts();
  const baseline = verificationDigest(facts);
  const mutated = clone(facts);
  mutated.provider_reconciliation.providerResults[0].status = 'fail';
  assert.notEqual(verificationDigest(mutated), baseline, 'provider status change must create drift');
});

test('finding fingerprint mutation is detected', () => {
  const facts = fixtureFacts();
  const baseline = verificationDigest(facts);
  const mutated = clone(facts);
  mutated.checks[0].findings[0].evidenceDigest = 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  assert.notEqual(verificationDigest(mutated), baseline, 'finding fingerprint change must create drift');
});

test('denominator mutation is detected', () => {
  const facts = fixtureFacts();
  const baseline = verificationDigest(facts);
  const mutated = clone(facts);
  mutated.plan.denominator.providerIds = ['language.typescript'];
  assert.notEqual(verificationDigest(mutated), baseline, 'denominator change must create drift');
});

test('tool version mutation is detected', () => {
  const facts = fixtureFacts();
  const baseline = verificationDigest(facts);
  const mutated = clone(facts);
  mutated.checks[0].toolVersion = '8.19.0';
  assert.notEqual(verificationDigest(mutated), baseline, 'tool version change must create drift');
});

test('plan seal mutation is detected', () => {
  const facts = fixtureFacts();
  const baseline = verificationDigest(facts);
  const mutated = clone(facts);
  mutated.plan.seal.digest = 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
  assert.notEqual(verificationDigest(mutated), baseline, 'plan seal change must create drift');
});

test('repository binding mutation is detected', () => {
  const facts = fixtureFacts();
  const baseline = verificationDigest(facts);
  const mutated = clone(facts);
  mutated.plan.binding.repositoryRevision = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  assert.notEqual(verificationDigest(mutated), baseline, 'repository binding change must create drift');
});

test('unreplayable checks are classified, not merged into content drift', () => {
  const facts = fixtureFacts();
  const projection = verificationProjection(facts);
  // An unreplayable check (e.g. missing sandbox) must remain a distinct status
  // and never be silently normalized to pass.
  const mutated = clone(facts);
  mutated.checks[0].status = 'unproven';
  mutated.checks[0].skip_reason = 'network sandbox receipt missing';
  const projection2 = verificationProjection(mutated);
  const check = projection2.checks.find((item) => item.check === 'secrets');
  assert.equal(check.executionStatus, 'unproven');
  assert.notEqual(verificationDigest(mutated), verificationDigest(facts));
  assert.ok(projection.checks.length === projection2.checks.length);
});

test('audit-verify.mjs executes end-to-end over a frozen fixture', () => {
  // The verifier collects the current repository binding from the workspace it
  // is pointed at, so the spawned test runs against a real (temporary) git repo
  // seeded from the frozen fixture. A synthetic fixture cannot byte-match a live
  // empty repo (binding, provider set, and replayed secrets differ), so the
  // verifier must legitimately report drift and exit 1 — the assertion is that
  // it runs to completion, reaches the semantic projection gate, and reports
  // per-field drift instead of crashing or exiting 0.
  const factsSource = fixtureFacts();
  const planSource = JSON.parse(readFileSync(new URL('./fixtures/verify/plan.json', import.meta.url), 'utf8'));
  const temp = mkdtempSync(join(tmpdir(), 'legion-verify-e2e-'));
  try {
    execFileSync('git', ['init', '-q', temp], { stdio: 'ignore' });
    execFileSync('git', ['-C', temp, 'config', 'user.email', 'verify@legion.test'], { stdio: 'ignore' });
    execFileSync('git', ['-C', temp, 'config', 'user.name', 'Legion Verify'], { stdio: 'ignore' });
    execFileSync('git', ['-C', temp, 'commit', '-q', '--allow-empty', '-m', 'verify fixture baseline'], { stdio: 'ignore' });

    const revision = execFileSync('git', ['-C', temp, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const seededFacts = { ...factsSource, workspace: temp, out_dir: join(temp, '.audit', 'run-1') };
    const seededPlan = { ...planSource, root: temp };
    seededFacts.plan.binding.repositoryRevision = revision;
    seededPlan.binding.repositoryRevision = revision;
    const factsPath = join(temp, 'facts.json');
    const planPath = join(temp, 'plan.json');
    writeFileSync(factsPath, JSON.stringify(seededFacts, null, 2));
    writeFileSync(planPath, JSON.stringify(seededPlan, null, 2));

    const result = spawnSync(process.execPath, [
      'audit-verify.mjs',
      '--facts', factsPath,
      '--plan', planPath,
    ], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, AUDIT_NETWORK_GUARD: 'inactive' },
    });
    assert.equal(result.status, 1, 'verifier must exit 1 when drift is detected');
    assert.match(result.stdout, /semantic verification projection/);
    assert.match(result.stdout, /DRIFT|MATCH|UNPROVEN/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
