// The harness adapter registry: the single list of supported harnesses and the
// data-driven interface over them. Each adapter is a descriptor (adapters/*.mjs);
// the engine implements detect/capabilities/install/verify/uninstall once.
//
// Adding a harness is one import + one array entry here plus its descriptor
// file, with NO engine change and no forked skills — provided its surfaces can
// be expressed with the mechanisms the engine already implements. A harness with
// a genuinely new transport or config format needs one shared mechanism added to
// the engine, used by every harness thereafter; it never needs a second copy of
// Legion's semantics. An unknown harness can skip this file entirely by
// declaring its descriptor as data (see adapters/generic.mjs).
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import claudeCode from './adapters/claude-code.mjs';
import codex from './adapters/codex.mjs';
import cline from './adapters/cline.mjs';
import commandCode from './adapters/command-code.mjs';
import pi from './adapters/pi.mjs';
import generic from './adapters/generic.mjs';
import * as engine from './engine.mjs';

const LEGION_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

// Order matters only for detection preference: the packaged-plugin harness first,
// the generic fallback last.
export const ADAPTERS = Object.freeze([claudeCode, codex, cline, commandCode, pi, generic]);
export const ADAPTER_IDS = Object.freeze(ADAPTERS.map((a) => a.id));

export function adapterById(id) {
  const a = ADAPTERS.find((x) => x.id === id);
  if (!a) throw new Error(`unknown harness: ${id} (known: ${ADAPTER_IDS.join(', ')})`);
  return a;
}

// A descriptor may resolve itself from runtime data (the generic adapter reads a
// custom harness's declaration). Everything else is a static descriptor.
function resolved(adapter, root, env) {
  return typeof adapter.resolve === 'function' ? adapter.resolve(root, env) : adapter;
}

const opts = (root) => ({ root, legionRoot: LEGION_ROOT });

export function detectHarnesses(root, env = process.env) {
  // The generic adapter is a fallback, never an auto-detection: it would match
  // any repo with an AGENTS.md. It is selected explicitly by id.
  return ADAPTERS.filter((a) => a.id !== 'generic' && engine.detect(a, root, env)).map((a) => a.id);
}

export function capabilities(id, { root = process.cwd(), env = process.env } = {}) {
  return engine.capabilities(resolved(adapterById(id), root, env), opts(root));
}

export function install(id, { root = process.cwd(), env = process.env, surfaces } = {}) {
  return engine.install(resolved(adapterById(id), root, env), { ...opts(root), surfaces });
}

export function verify(id, { root = process.cwd(), env = process.env } = {}) {
  return engine.verify(resolved(adapterById(id), root, env), opts(root));
}

export function uninstall(id, { root = process.cwd(), env = process.env } = {}) {
  return engine.uninstall(resolved(adapterById(id), root, env), opts(root));
}

// The full declared fidelity matrix across every supported harness — the
// cross-harness table doctor and the conformance tests read.
export function fidelityMatrix({ root = process.cwd(), env = process.env } = {}) {
  return ADAPTERS.map((a) => capabilities(a.id, { root, env }));
}

export { LEGION_ROOT };
