import { digestBytes } from '../artifacts/digests.mjs';
export function verifySkillBytes(bytes, expectedDigest) { const digest = digestBytes(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)); return { ok: digest === expectedDigest, digest, expectedDigest }; }
