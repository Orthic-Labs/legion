// Shared helpers for harness binding writers: marker-delimited idempotent
// blocks for Markdown targets, and write-if-different for JSON/frontmatter
// targets. Both bind.mjs's writers and drift.mjs's comparisons must use the
// exact same marker builder to avoid false-positive drift.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const MARKER_START = '<!-- legion:bind:start v1 -->';
const MARKER_END = '<!-- legion:bind:end -->';
const MARKER_RE = /<!-- legion:bind:start v1 -->[\s\S]*?<!-- legion:bind:end -->/;

export function markerBlock(content) {
  return `${MARKER_START}\n${content.trim()}\n${MARKER_END}`;
}

export function upsertMarkerBlock(existing, content) {
  const block = markerBlock(content);
  if (MARKER_RE.test(existing)) return existing.replace(MARKER_RE, block);
  if (!existing || existing.length === 0) return `${block}\n`;
  const sep = existing.endsWith('\n') ? '\n' : '\n\n';
  return `${existing}${sep}${block}\n`;
}

export function hasCurrentMarkerBlock(existing, content) {
  return existing.includes(markerBlock(content));
}

export function extractMarkerBlock(existing) {
  return existing.match(MARKER_RE)?.[0] ?? null;
}

export function readTextIfExists(path) {
  return existsSync(path) ? readFileSync(path, 'utf8') : '';
}

// Write `content` at `path` only if it differs from what's already on disk
// (write-if-different — never append, never rewrite identical bytes).
export function writeIfDifferent(path, content) {
  const current = existsSync(path) ? readFileSync(path, 'utf8') : null;
  if (current === content) return false;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
  return true;
}

// Apply the marker-block upsert to a Markdown target and write only if the
// resulting file content actually changes.
export function writeMarkerTarget(path, content) {
  const existing = readTextIfExists(path);
  const next = upsertMarkerBlock(existing, content);
  return writeIfDifferent(path, next);
}
