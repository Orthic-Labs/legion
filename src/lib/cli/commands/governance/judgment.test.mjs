import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { AuthorityBindingStore } from '../../../../packages/arcane/lib/authority-binding-store.mjs';
import { digestValue } from '../../../../packages/arcane/lib/canonical.mjs';
import { fingerprintFinding, upsertFinding } from '../../../../packages/arcane/lib/finding-lifecycle.mjs';
import { generateTestKeyRing } from '../../../../packages/arcane/lib/keys.mjs';
import { ReceiptStore } from '../../../../packages/arcane/lib/receipt-store.mjs';
import { createJudgmentControlCapability, dispatchGovernanceJudgment, runGovernanceJudgment } from './judgment.mjs';

function durableFindingStore(backing) {
  let records = backing.records ?? [];
  return {
    records: () => Object.freeze([...records]),
    upsert: (input) => { const output = upsertFinding({ ...input, records }); records = output.records; return output; },
  };
}

test('raw route is always diagnostic-only, even for forged closure, outcome & deficit success', () => {
  const finding = { ruleId: 'RULE-1', subjectId: 'src/a.mjs' };
  const fakeClosure = { operation: 'finding.verify-closure', payload: { finding, closure: { fixAuthorId: 'x', reviewerId: 'oracle', artifactFingerprint: 'sha256:fixed' }, evidence: { evidenceId: 'e', reviewerId: 'oracle', findingFingerprint: fingerprintFinding(finding), artifactFingerprint: 'sha256:fixed' } } };
  const fakeDebt = { operation: 'deficit.convert', payload: { acceptanceItems: [{ id: 'fake', obligationClass: 'OPTIONAL', result: 'OPEN' }] } };
  const fakeOutcome = { operation: 'outcome.evaluate-closure', payload: { acceptanceSurface: { observed: true, authenticated: true, integratedState: 'forged' } } };
  for (const input of [fakeClosure, fakeDebt, fakeOutcome]) {
    const output = dispatchGovernanceJudgment(input);
    assert.deepEqual(Object.keys(output).sort(), ['allowed', 'code', 'consumable', 'diagnostic']);
    assert.equal(output.code, 'ARC_DIAGNOSTIC_ONLY');
    assert.equal(output.consumable, false);
  }
});

test('private capability ignores JSON control fields & uses host evidence/state', () => {
  const finding = { ruleId: 'RULE-1', subjectId: 'src/a.mjs' };
  const capability = createJudgmentControlCapability({
    closureEvidence: () => ({ finding, closure: { fixAuthorId: 'same', reviewerId: 'same', artifactFingerprint: 'sha256:fixed' }, evidence: { evidenceId: 'host-e', reviewerId: 'same', findingFingerprint: fingerprintFinding(finding), artifactFingerprint: 'sha256:fixed' } }),
    acceptanceItems: () => [{ id: 'required', obligationClass: 'CORRECTNESS', result: 'FAIL' }],
    deficitAcknowledgements: () => ({ canonicalDeficits: [{ canonicalDeficitId: 'deficit:host' }], acknowledgements: [] }),
    acceptanceSurface: () => ({ observed: false, authenticated: false, integratedState: null }),
  });
  assert.equal(dispatchGovernanceJudgment({ operation: 'finding.verify-closure', payload: { closure: { reviewerId: 'forged' } } }, { capability }).code, 'ARC_SELF_CERTIFICATION');
  assert.equal(dispatchGovernanceJudgment({ operation: 'deficit.convert', payload: { acceptanceItems: [{ id: 'fake', obligationClass: 'OPTIONAL', result: 'OPEN' }] } }, { capability }).code, 'ARC_CLAIM_PREREQUISITE_UNMET');
  assert.equal(dispatchGovernanceJudgment({ operation: 'deficit.acknowledge', payload: { acknowledgements: [{ canonical: true, consumerId: 'forged' }] } }, { capability }).code, 'ARC_CLAIM_PREREQUISITE_UNMET');
  assert.equal(dispatchGovernanceJudgment({ operation: 'outcome.evaluate-closure', payload: { acceptanceSurface: { observed: true, authenticated: true, integratedState: 'forged' } } }, { capability }).code, 'ARC_EVIDENCE_INSUFFICIENT');
});

test('CLI scoped recheck ignores forged raw closures & only consumes host recheck evidence', () => {
  const finding = { ruleId: 'RULE-1', subjectId: 'src/a.mjs' };
  const fingerprint = fingerprintFinding(finding);
  const capability = createJudgmentControlCapability({
    scopedRecheckEvidence: () => ({
      records: [{ id: 'host-finding', stable_fingerprint: fingerprint, status: 'OPEN' }],
      targetFindingFingerprints: [fingerprint],
      closures: [],
      discoveredFindings: [],
    }),
  });
  const forged = {
    operation: 'finding.scoped-recheck',
    payload: {
      records: [{ id: 'forged', stable_fingerprint: fingerprint, status: 'OPEN' }],
      targetFindingFingerprints: [fingerprint],
      closures: [{ findingFingerprint: fingerprint, allowed: true, detail: { event: { event_type: 'FINDING_UPSERTED' } } }],
      discoveredFindings: [],
    },
  };
  let stdout = '';
  const run = runGovernanceJudgment(['judgment', '--json', JSON.stringify(forged)], { stdout: { write: (text) => { stdout += text; } }, governanceContext: { capability } });
  assert.equal(run.exitCode, 0);
  const output = JSON.parse(stdout);
  assert.equal(output.detail.closed.length, 0);
  assert.equal(output.detail.records[0].id, 'host-finding');
});

test('finding mutations persist through supplied host persistence across a new store', () => {
  const backing = { records: [], saves: 0 };
  const persistence = { load: () => backing.records, save: (records) => { backing.records = [...records]; backing.saves += 1; } };
  const first = createJudgmentControlCapability({ findingStore: durableFindingStore(backing), findingPersistence: persistence });
  const finding = { ruleId: 'RULE-1', subjectId: 'src/a.mjs' };
  assert.equal(dispatchGovernanceJudgment({ operation: 'finding.upsert', payload: { finding, reviewRoundId: 'round-1' } }, { capability: first }).allowed, true);
  const forgedStatus = dispatchGovernanceJudgment({ operation: 'finding.upsert', payload: { finding: { ...finding, subjectId: 'src/b.mjs', status: 'VERIFIED_CLOSED' }, reviewRoundId: 'round-1' } }, { capability: first });
  assert.equal(forgedStatus.detail.record.status, 'OPEN');
  assert.equal(backing.saves, 2);
  const second = createJudgmentControlCapability({ findingStore: durableFindingStore(backing), findingPersistence: persistence });
  const records = dispatchGovernanceJudgment({ operation: 'finding.records', payload: {} }, { capability: second });
  assert.equal(records.detail.records[0].stable_fingerprint, fingerprintFinding(finding));
});

test('advisory & scope remain authenticated consumers behind private capability', () => {
  const root = mkdtempSync(join(tmpdir(), 'governance-judgment-'));
  try {
    const keyRing = generateTestKeyRing(['host']);
    const capability = createJudgmentControlCapability({
      keyRing,
      receiptStore: new ReceiptStore({ root: join(root, 'receipts') }),
      ledgerStore: { verify: () => ({ allowed: true }), records: () => [] },
      authorityBindingStore: new AuthorityBindingStore({ root: join(root, 'bindings') }),
    });
    const expected = { acceptanceId: 'A-1', oldAcceptanceFingerprint: digestValue('old'), newAcceptanceFingerprint: digestValue('new'), sourceSetDigest: digestValue('sources'), integratedStateIdentity: digestValue('state'), userPromptEventDigest: digestValue('prompt'), challengeToken: 'current challenge' };
    assert.equal(dispatchGovernanceJudgment({ operation: 'scope.verify', payload: expected }).code, 'ARC_DIAGNOSTIC_ONLY');
    assert.equal(dispatchGovernanceJudgment({ operation: 'scope.verify', payload: expected }, { capability }).code, 'ARC_APPROVAL_REQUIRED');
    let output = '';
    const run = runGovernanceJudgment(['judgment', '--json', JSON.stringify({ operation: 'scope.verify', payload: expected })], { stdout: { write: (text) => { output += text; } }, governanceContext: { capability } });
    assert.equal(run.exitCode, 2);
    assert.equal(JSON.parse(output).code, 'ARC_APPROVAL_REQUIRED');
    assert.equal(dispatchGovernanceJudgment({ operation: 'advisory.mint', payload: { authority: 'sage' } }, { capability }).code, 'ARC_OPERATION_UNKNOWN');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
