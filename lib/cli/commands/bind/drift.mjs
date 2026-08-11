// Shared drift computation, imported by both bind.mjs (--check) and
// doctor.mjs (the `binding` report section). Compares a prior
// .legion/binding.json receipt's tracked files against what each harness
// writer's targets() currently expects, without duplicating that logic.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import * as claudeCode from './claude-code.mjs';
import * as codex from './codex.mjs';
import * as gemini from './gemini.mjs';
import * as agentsMd from './agents-md.mjs';
import { extractMarkerBlock, markerBlock } from './common.mjs';

const HARNESS_MODULES = {
  [claudeCode.NAME]: claudeCode,
  [codex.NAME]: codex,
  [gemini.NAME]: gemini,
  [agentsMd.NAME]: agentsMd,
};

export function bindingReceiptPath(root) {
  return join(root, '.legion', 'binding.json');
}

export function readBindingReceipt(root) {
  const path = bindingReceiptPath(root);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

function artifact(text) {
  return { bytes: Buffer.byteLength(text, 'utf8'), digest: `sha256:${createHash('sha256').update(text).digest('hex')}` };
}

function targetText(target) {
  if (target.kind === 'marker') return markerBlock(target.blockContent);
  if (target.kind === 'toml-managed') return target.result.content;
  return target.content;
}

function actualText(text, target) {
  return target.kind === 'marker' ? extractMarkerBlock(text) : text;
}

function receiptPath(root, path) {
  return relative(root, path).replaceAll('\\', '/');
}

export function artifactForTarget(root, target) {
  const text = targetText(target);
  return { path: receiptPath(root, target.path), kind: target.kind, ...artifact(text) };
}

function driftForFile(root, record, target) {
  const path = typeof record === 'string' ? record : record.path;
  const diskPath = resolve(root, path);
  if (!existsSync(diskPath)) return { path, kind: 'missing' };
  if (!target) return null; // no longer a tracked target for this harness; nothing to compare
  const actual = actualText(readFileSync(diskPath, 'utf8'), target);
  if (actual === null) return { path, kind: 'missing-managed-block' };
  const expected = artifactForTarget(root, target);
  const observed = artifact(actual);
  if (observed.digest !== expected.digest || observed.bytes !== expected.bytes) return { path, kind: target.kind === 'marker' ? 'stale-marker' : 'modified', expected, observed };
  if (typeof record === 'object' && (record.digest !== observed.digest || record.bytes !== observed.bytes)) return { path, kind: 'receipt-digest-mismatch', expected: record, observed };
  return null;
}

// Drift for one harness entry from the receipt, computed against the
// writer's *current* targets() (so doctrine edits since the receipt was
// written surface as stale-marker, not silently pass).
export function driftForHarness(root, harnessEntry) {
  const mod = HARNESS_MODULES[harnessEntry.name];
  const currentTargets = mod ? mod.targets(root) : [];
  const targetByPath = new Map(currentTargets.map((t) => [receiptPath(root, t.path), t]));
  return (harnessEntry.files ?? [])
    .map((record) => driftForFile(root, record, targetByPath.get(typeof record === 'string' ? receiptPath(root, record) : record.path)))
    .filter(Boolean);
}

// Full binding-section shape shared by `legion doctor` and `legion bind --check`.
export function computeBindingSection(root) {
  const receipt = readBindingReceipt(root);
  if (!receipt) return { receiptPresent: false, harnesses: [] };
  const harnesses = (receipt.harnesses ?? []).map((entry) => ({
    name: entry.name,
    fidelityTier: entry.fidelityTier,
    filesTracked: (entry.files ?? []).length,
    drift: driftForHarness(root, entry),
  }));
  return { receiptPresent: true, harnesses };
}

export { HARNESS_MODULES };
