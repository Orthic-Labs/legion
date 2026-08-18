import assert from 'node:assert/strict';
import test from 'node:test';
import { changePassport, passportDigest, signPassport, verifyPassport } from '../src/lib/provenance/passport.mjs';

test('passport digest is content-bound', () => {
  const a = changePassport({ baseCommit: 'a', patchDigest: 'sha256:p', findingIds: ['f1'], producer: {}, commands: [], verificationArtifacts: [], createdAt: 't', signingKey: 'k' });
  const b = changePassport({ baseCommit: 'a', patchDigest: 'sha256:p', findingIds: ['f1'], producer: {}, commands: [], verificationArtifacts: [], createdAt: 't', signingKey: 'k' });
  assert.equal(a.passportDigest, b.passportDigest);
  const c = changePassport({ baseCommit: 'a', patchDigest: 'sha256:other', findingIds: ['f1'], producer: {}, commands: [], verificationArtifacts: [], createdAt: 't', signingKey: 'k' });
  assert.notEqual(a.passportDigest, c.passportDigest);
});

test('provenance absence is distinct from a defect', () => {
  // An unsigned passport is valid provenance evidence of "no signature",
  // distinct from a passport that fails verification.
  const unsigned = changePassport({ baseCommit: 'a', patchDigest: 'sha256:p', findingIds: [], producer: {}, commands: [], verificationArtifacts: [], createdAt: 't', signingKey: null });
  assert.equal(unsigned.signature.value, null);
  assert.equal(unsigned.passportDigest.startsWith('sha256:'), true);
});

test('finding ids are sorted for determinism', () => {
  const a = changePassport({ baseCommit: 'a', patchDigest: 'sha256:p', findingIds: ['f2', 'f1'], producer: {}, commands: [], verificationArtifacts: [], createdAt: 't', signingKey: 'k' });
  const b = changePassport({ baseCommit: 'a', patchDigest: 'sha256:p', findingIds: ['f1', 'f2'], producer: {}, commands: [], verificationArtifacts: [], createdAt: 't', signingKey: 'k' });
  assert.deepEqual(a.findingIds, ['f1', 'f2']);
  assert.equal(a.passportDigest, b.passportDigest);
});

test('provenance is evidence, not correctness truth', () => {
  const passport = signPassport({ baseCommit: 'a', patchDigest: 'sha256:p', findingIds: [], producer: { kind: 'agent' }, commands: [], verificationArtifacts: [], createdAt: 't' }, 'k');
  // A valid signature proves provenance, never that the change is correct.
  assert.equal(verifyPassport(passport, 'k'), true);
  assert.ok(!('correct' in passport));
});
