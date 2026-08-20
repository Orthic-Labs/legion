import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { validateSkillBundle } from './contracts.mjs';

const COMMAND = /^\/([a-z][a-z0-9-]*)(?:\s|$)/;
const DEFAULT_ROOT = resolve(import.meta.dirname, '../../..');

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * Deterministic explicit-invocation resolver (M-018).
 *
 * Natural-language semantic classification is NOT performed here: it is the
 * always-on Legion orchestration model's job, over the compact canonical
 * catalog in context. This module only resolves explicit slash commands and
 * aliases deterministically, and validates that the selected canonical id is
 * packaged and available.
 */
export function resolveSkillInvocation(input, { root = DEFAULT_ROOT } = {}) {
  const text = String(input ?? '').trim();
  const match = COMMAND.exec(text);
  if (!match) return { status: 'not-found', reason: 'not-explicit-command' };

  const requested = `/${match[1]}`;
  const suppliedArguments = text.slice(match[0].length).trim();
  const aliases = readJson(resolve(root, 'src/config/capability-aliases.json')).aliases ?? {};
  let target = requested;
  let aliasArguments = '';
  const seen = new Set();
  while (aliases[target] && aliases[target].startsWith('/')) {
    if (seen.has(target)) return { status: 'invalid', requested, reason: 'alias-cycle' };
    seen.add(target);
    const declaration = aliases[target].trim();
    const nextTarget = declaration.split(/\s+/, 1)[0];
    const declaredArguments = declaration.slice(nextTarget.length).trim();
    aliasArguments = [declaredArguments, aliasArguments].filter(Boolean).join(' ');
    target = nextTarget;
  }

  const canonical = target.slice(1);
  const index = readJson(resolve(root, 'src/registry/skills/index.json'));
  const record = index.bundles.find(({ id }) => id === canonical);
  if (!record) return { status: 'not-found', requested, canonical };
  const manifest = validateSkillBundle(readJson(resolve(root, record.manifest)));
  const argumentText = [aliasArguments, suppliedArguments].filter(Boolean).join(' ');
  const resolvedInvocation = argumentText ? `${target} ${argumentText}` : target;
  return { status: 'resolved', requested, canonical, argumentText, resolvedInvocation, manifestPath: record.manifest, manifest };
}

/**
 * Deterministic selection validator (M-018). Accepts an already-produced
 * selection — never raw natural language. The semantic classifier is the
 * Legion orchestration model; this runtime validates the selected ids.
 *
 * semantic source: every selected item must be kind=capability and public.
 * explicit source: explicit capabilities and entrypoints resolve per alias/config.
 */
export function validateCapabilitySelection(selection, options = {}) {
  const root = options.root ?? DEFAULT_ROOT;
  const ids = Array.isArray(selection?.ids) ? selection.ids : [];
  const source = selection?.source === 'explicit' ? 'explicit' : 'semantic';
  const index = readJson(resolve(root, 'src/registry/skills/index.json'));
  const bundles = new Map(index.bundles.map((bundle) => [bundle.id, bundle]));

  const resolved = [];
  const invalid = [];
  for (const id of ids) {
    const record = bundles.get(id);
    if (!record) { invalid.push({ id, reason: 'not-found' }); continue; }
    if (source === 'semantic') {
      const catalogRecord = index.bundles.find((b) => b.id === id);
      if (catalogRecord.kind !== 'capability') { invalid.push({ id, reason: 'not-capability' }); continue; }
      if (catalogRecord.discoverability !== 'public') { invalid.push({ id, reason: 'not-public' }); continue; }
    }
    const manifest = validateSkillBundle(readJson(resolve(root, record.manifest)));
    resolved.push({ id, manifestPath: record.manifest, manifest });
  }
  return { status: invalid.length ? 'invalid' : 'resolved', source, resolved, invalid };
}
