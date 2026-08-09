// Signed change passport per SNIP-PASSPORT-01. Provenance is evidence, not
// correctness truth. The passport signs content digests, never prose.

import { createHash, createHmac } from 'node:crypto';

export function passportDigest(body) {
  const { signature, ...unsigned } = body;
  return `sha256:${createHash('sha256').update(JSON.stringify(unsigned)).digest('hex')}`;
}

export function signPassport(body, signingKey) {
  if (!signingKey) {
    return {
      ...body,
      signature: { algorithm: null, keyId: null, value: null },
    };
  }
  const unsigned = { ...body };
  delete unsigned.signature;
  const value = createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest('hex');
  const keyId = `sha256:${createHash('sha256').update(`passport-key\0${signingKey}`).digest('hex').slice(0, 16)}`;
  return {
    ...unsigned,
    signature: { algorithm: 'HMAC-SHA256', keyId, value },
  };
}

export function verifyPassport(passport, signingKey) {
  if (!signingKey || passport?.signature?.algorithm !== 'HMAC-SHA256') return false;
  const unsigned = { ...passport };
  delete unsigned.signature;
  const expected = createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest('hex');
  return passport.signature.value === expected;
}

export function changePassport({ baseCommit, patchDigest, findingIds, producer, commands, verificationArtifacts, createdAt, signingKey }) {
  const body = {
    schemaVersion: 1,
    kind: 'legion-change-passport',
    baseCommit,
    patchDigest,
    findingIds: [...(findingIds ?? [])].sort(),
    producer: producer ?? {},
    commands: [...(commands ?? [])].sort(),
    verificationArtifacts: [...(verificationArtifacts ?? [])].sort(),
    createdAt,
    signature: null,
  };
  body.passportDigest = passportDigest(body);
  return signPassport(body, signingKey);
}
