// Shared drift computation, imported by both bind.mjs (--check) and
// doctor.mjs (the `binding` report section). Compares a prior
// .legion/binding.json receipt's tracked files against what each harness
// writer's targets() currently expects, without duplicating that logic.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as claudeCode from './claude-code.mjs';
import * as codex from './codex.mjs';
import * as agentsMd from './agents-md.mjs';
import { markerBlock } from './common.mjs';

const HARNESS_MODULES = {
  [claudeCode.NAME]: claudeCode,
  [codex.NAME]: codex,
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

function driftForFile(path, target) {
  if (!existsSync(path)) return { path, kind: 'missing' };
  if (!target) return null; // no longer a tracked target for this harness; nothing to compare
  const actual = readFileSync(path, 'utf8');
  if (target.kind === 'marker') {
    return actual.includes(markerBlock(target.blockContent)) ? null : { path, kind: 'stale-marker' };
  }
  return actual === target.content ? null : { path, kind: 'modified' };
}

// Drift for one harness entry from the receipt, computed against the
// writer's *current* targets() (so doctrine edits since the receipt was
// written surface as stale-marker, not silently pass).
export function driftForHarness(root, harnessEntry) {
  const mod = HARNESS_MODULES[harnessEntry.name];
  const currentTargets = mod ? mod.targets(root) : [];
  const targetByPath = new Map(currentTargets.map((t) => [t.path, t]));
  return (harnessEntry.files ?? [])
    .map((path) => driftForFile(path, targetByPath.get(path)))
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
