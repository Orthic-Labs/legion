// Hostile evidence envelope (B7-029) for every reviewer family.
//
// Repository text — source, docs, comments, skills, configuration, retrieved
// content, runtime output — is DATA, never instruction. This module is the one
// place that turns such text into a reviewer-safe record: escaped, normalized,
// byte-capped, digest-preserving, and structurally separated from the trusted
// instruction fields of a judgment packet (SNIP-13).
//
// The defence is structural, not lexical: `buildReviewPacket` composes the
// packet's authority fields (provider, role, context, schema, tools, policy,
// verdict vocabulary) exclusively from its own trusted arguments and never
// reads them out of evidence. Override attempts found in evidence are recorded
// as visible artefacts so a reviewer can see the repository tried, but they can
// never take effect.

import { createHash } from 'node:crypto';

export const UNTRUSTED_EVIDENCE_SCHEMA_VERSION = 1;

export const UNTRUSTED_EVIDENCE_KINDS = Object.freeze([
  'source',
  'docs',
  'comment',
  'skill',
  'configuration',
  'retrieved-content',
  'runtime-text',
]);

export const REVIEW_FAMILIES = Object.freeze([
  'security',
  'copy',
  'narrative',
  'ux',
  'visual',
]);

export const DEFAULT_EVIDENCE_MAX_BYTES = 8192;

// Characters that can rewrite what a human or a model believes it is reading.
const BIDI = new RegExp('[' + String.fromCodePoint(0x200e, 0x200f, 0x061c, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069) + ']', 'g');
const ZERO_WIDTH = /[​-‍⁠﻿]/g;
// C0/C1 controls, minus the newline and tab that carry display meaning.
const CONTROL = /[\0---]/g;

function escapeCodePoint(character) {
  return `\\u${character.codePointAt(0).toString(16).padStart(4, '0')}`;
}

function digestOf(namespace, value) {
  return `sha256:${createHash('sha256').update(`${namespace}\0${JSON.stringify(value)}`).digest('hex')}`;
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

// Override attempts the repository may embed. Matching is for VISIBILITY only —
// nothing downstream consumes the match to make a decision, so a miss degrades
// to "not reported", never to "override applied".
const OVERRIDE_PATTERNS = Object.freeze([
  { target: 'provider', pattern: /\b(?:provider|producer)\s*(?:[:=]|\bto\b)\s*[\w.@/-]+/gi },
  { target: 'role', pattern: /\b(?:role|persona|you\s+are)\s*(?:[:=]|\bnow\b)?\s*(?:system|admin|root|developer|assistant|adjudicator)\b/gi },
  { target: 'context', pattern: /\b(?:context(?:Id)?|conversation|session)\s*[:=]?\s*(?:reuse|previous|prior|shared|carry[\s-]?over)[\w-]*/gi },
  { target: 'schema', pattern: /\b(?:new\s+)?schema\s*[:=]\s*[\w./-]+/gi },
  { target: 'tools', pattern: /\btools?\s*[:=]\s*[\w.,\s/-]+/gi },
  { target: 'policy', pattern: /\b(?:policy|policyEffect|severity|blocking)\s*[:=]\s*[\w-]+/gi },
  { target: 'verdict', pattern: /\bverdict\s*[:=]\s*[A-Z_]{3,}/g },
  { target: 'instruction', pattern: /\b(?:ignore|disregard|override|forget)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^\n]{0,20}\b(?:instruction|prompt|rule|direction)s?\b/gi },
  { target: 'instruction', pattern: /^\s*(?:\/\/|#|\/\*|<!--)?\s*(?:SYSTEM|ASSISTANT|DEVELOPER)\s*:/gim },
]);

/**
 * Wrap one piece of repository-controlled text as untrusted evidence.
 * Raw bytes beyond the cap are never carried in the record — the full content
 * remains reachable only through the bound artifact reference.
 */
export function wrapUntrustedEvidence({
  evidenceKind,
  sourcePath,
  sourceDigest,
  artifactRef,
  text,
  maxBytes = DEFAULT_EVIDENCE_MAX_BYTES,
  label = null,
  locator = null,
}) {
  if (!UNTRUSTED_EVIDENCE_KINDS.includes(evidenceKind)) {
    throw new TypeError(`unknown untrusted evidence kind: ${String(evidenceKind)}`);
  }
  requireString(sourcePath, 'sourcePath');
  requireString(sourceDigest, 'sourceDigest');
  if (!artifactRef || typeof artifactRef !== 'object') {
    throw new TypeError('artifactRef is required: raw source is reachable only through a bound artifact');
  }
  requireString(artifactRef.path, 'artifactRef.path');
  requireString(artifactRef.digest, 'artifactRef.digest');
  if (typeof text !== 'string') throw new TypeError('text must be a string');
  if (!Number.isInteger(maxBytes) || maxBytes <= 0) throw new TypeError('maxBytes must be a positive integer');

  const originalBytes = Buffer.byteLength(text, 'utf8');
  const truncated = originalBytes > maxBytes;
  // Slice on a code-point boundary so truncation cannot manufacture a
  // half-character that renders as something else.
  let body = text;
  if (truncated) {
    const buffer = Buffer.from(text, 'utf8').subarray(0, maxBytes);
    body = new TextDecoder('utf8', { fatal: false }).decode(buffer).replace(/�$/, '');
  }
  const includedBytes = truncated ? maxBytes : originalBytes;

  // NFC always runs, so it is always declared; the escape passes are declared
  // only when they actually changed something.
  const normalizations = ['unicode-nfc'];
  let display = body.normalize('NFC');
  if (BIDI.test(display)) normalizations.push('bidi-escaped');
  display = display.replace(BIDI, escapeCodePoint);
  if (ZERO_WIDTH.test(display)) normalizations.push('zero-width-escaped');
  display = display.replace(ZERO_WIDTH, escapeCodePoint);
  if (CONTROL.test(display)) normalizations.push('control-escaped');
  display = display.replace(CONTROL, escapeCodePoint);

  const omissions = truncated
    ? [{ reason: 'byte-cap', omittedBytes: originalBytes - includedBytes, fromOffset: includedBytes, artifactRef }]
    : [];

  const record = {
    schemaVersion: UNTRUSTED_EVIDENCE_SCHEMA_VERSION,
    kind: 'legion-untrusted-evidence',
    trusted: false,
    evidenceKind,
    label,
    sourcePath,
    sourceDigest,
    artifactRef: { path: artifactRef.path, digest: artifactRef.digest },
    locator,
    encoding: 'escaped-utf8',
    text: display,
    originalBytes,
    includedBytes,
    truncated,
    normalizations: [...new Set(normalizations)].sort(),
    omissions,
  };
  record.digest = digestOf('untrusted-evidence', record);
  return record;
}

export function detectOverrideAttempts(records) {
  const attempts = [];
  for (const record of records ?? []) {
    for (const { target, pattern } of OVERRIDE_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(record.text)) !== null) {
        attempts.push({
          target,
          sourcePath: record.sourcePath,
          evidenceDigest: record.digest,
          excerptDigest: digestOf('override-attempt', match[0]),
          // Recorded for visibility. Packet authority is composed from trusted
          // arguments only, so this can never be honoured.
          applied: false,
        });
        if (match.index === pattern.lastIndex) pattern.lastIndex += 1;
      }
    }
  }
  return attempts.sort((a, b) => (a.target + a.excerptDigest).localeCompare(b.target + b.excerptDigest));
}

/**
 * Guard against the one mistake the envelope cannot survive: pasting untrusted
 * text into a trusted field.
 */
export function assertNoUntrustedInterpolation(instructions, records) {
  const haystack = JSON.stringify(instructions ?? []);
  for (const record of records ?? []) {
    for (const line of record.text.split('\n')) {
      const candidate = line.trim();
      if (candidate.length < 8) continue;
      if (haystack.includes(candidate)) {
        throw new Error(`untrusted evidence must not be interpolated into instructions (${record.sourcePath})`);
      }
    }
  }
  return true;
}

/**
 * Build a reviewer packet whose authority fields come only from trusted
 * arguments. Applies to security, copy, narrative, UX, and visual review alike.
 */
export function buildReviewPacket({
  family,
  subjectId,
  candidateId = null,
  instructions,
  reviewer,
  schema,
  verdictVocabulary,
  policy = {},
  budget = null,
  tools = [],
  evidence = [],
  binding,
}) {
  if (!REVIEW_FAMILIES.includes(family)) {
    throw new TypeError(`unknown reviewer family: ${String(family)}`);
  }
  requireString(subjectId, 'subjectId');
  requireString(schema, 'schema');
  if (!Array.isArray(instructions)) throw new TypeError('instructions must be an array of trusted strings');
  if (!Array.isArray(verdictVocabulary) || verdictVocabulary.length === 0) {
    throw new TypeError('verdictVocabulary must be a non-empty array');
  }
  if (!reviewer || typeof reviewer !== 'object') throw new TypeError('reviewer is required');
  requireString(reviewer.role, 'reviewer.role');
  requireString(reviewer.contextId, 'reviewer.contextId');
  if (reviewer.fresh !== true) throw new Error('reviewer context must be fresh');
  if (!binding || typeof binding !== 'object') throw new TypeError('binding is required');

  const records = [...evidence];
  for (const record of records) {
    if (record?.kind !== 'legion-untrusted-evidence' || record.trusted !== false) {
      throw new TypeError('packet evidence must be wrapped untrusted-evidence records');
    }
  }
  assertNoUntrustedInterpolation(instructions, records);

  const packet = {
    schemaVersion: 1,
    kind: 'legion-review-packet',
    family,
    subjectId,
    candidateId,
    // Trusted half.
    instructions: Object.freeze([...instructions]),
    reviewer: Object.freeze({ ...reviewer }),
    schema,
    verdictVocabulary: Object.freeze([...verdictVocabulary]),
    policy: Object.freeze({ ...policy }),
    budget: budget === null ? null : Object.freeze({ ...budget }),
    tools: Object.freeze([...tools]),
    // Untrusted half.
    evidence: Object.freeze(records),
    omittedEvidence: Object.freeze(records.flatMap((record) => record.omissions)),
    truncated: records.some((record) => record.truncated),
    injectionAttempts: Object.freeze(detectOverrideAttempts(records)),
    binding: Object.freeze({ ...binding }),
  };
  packet.digest = digestOf('review-packet', packet);
  return Object.freeze(packet);
}

export function buildUntrustedEvidenceSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/core/untrusted-evidence-v1.json',
    title: 'UntrustedEvidenceV1',
    type: 'object',
    required: [
      'schemaVersion', 'kind', 'trusted', 'evidenceKind', 'sourcePath', 'sourceDigest',
      'artifactRef', 'encoding', 'text', 'originalBytes', 'includedBytes', 'truncated',
      'normalizations', 'omissions', 'digest',
    ],
    properties: {
      schemaVersion: { const: UNTRUSTED_EVIDENCE_SCHEMA_VERSION },
      kind: { const: 'legion-untrusted-evidence' },
      trusted: { const: false },
      evidenceKind: { enum: [...UNTRUSTED_EVIDENCE_KINDS] },
      label: { type: ['string', 'null'] },
      sourcePath: { type: 'string', minLength: 1 },
      sourceDigest: { type: 'string', pattern: '^sha256:' },
      artifactRef: {
        type: 'object',
        required: ['path', 'digest'],
        properties: {
          path: { type: 'string', minLength: 1 },
          digest: { type: 'string', pattern: '^sha256:' },
        },
        additionalProperties: false,
      },
      locator: { type: ['object', 'string', 'null'] },
      encoding: { const: 'escaped-utf8' },
      text: { type: 'string' },
      originalBytes: { type: 'integer', minimum: 0 },
      includedBytes: { type: 'integer', minimum: 0 },
      truncated: { type: 'boolean' },
      normalizations: { type: 'array', items: { type: 'string' } },
      omissions: {
        type: 'array',
        items: {
          type: 'object',
          required: ['reason', 'omittedBytes', 'fromOffset'],
          properties: {
            reason: { enum: ['byte-cap', 'policy-redaction', 'binary-content'] },
            omittedBytes: { type: 'integer', minimum: 0 },
            fromOffset: { type: 'integer', minimum: 0 },
            artifactRef: { type: 'object' },
          },
          additionalProperties: false,
        },
      },
      digest: { type: 'string', pattern: '^sha256:' },
    },
    additionalProperties: false,
  };
}
