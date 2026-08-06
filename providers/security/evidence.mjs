// Security evidence helpers per Security Appendix §9. Bounded excerpts with
// digests; no unrestricted source text in the top-level model.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { stableId } from './contracts.mjs';

const MAX_EVIDENCE_BYTES = 64 * 1024;

function excerptDigest(text) {
  return `sha256:${createHash('sha256').update(text).digest('hex')}`;
}

export function lineNumber(text, index) {
  return text.slice(0, Math.max(0, index)).split('\n').length;
}

export function boundedExcerpt(text, index, radius = 240) {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + radius);
  return text.slice(start, end);
}

export function sourceEvidence({ file, text, index = 0, endIndex = index, description }) {
  const excerpt = boundedExcerpt(text, index);
  const record = {
    kind: 'source-location',
    file,
    line: lineNumber(text, index),
    endLine: lineNumber(text, Math.max(index, endIndex)),
    excerptDigest: excerptDigest(excerpt),
    description,
    strength: 'verified',
  };
  return { ...record, id: stableId('security-evidence', record) };
}

export function readFrozenText(root, relativePath) {
  const buffer = readFileSync(join(root, relativePath));
  if (buffer.length > MAX_EVIDENCE_BYTES * 32) return null;
  if (buffer.includes(0)) return null;
  return buffer.toString('utf8');
}
