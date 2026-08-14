import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { validateSkillBundle } from './contracts.mjs';

const COMMAND = /^\/([a-z][a-z0-9-]*)(?:\s|$)/;

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function resolveSkillInvocation(input, { root = resolve(import.meta.dirname, '../..') } = {}) {
  const match = COMMAND.exec(String(input ?? '').trim());
  if (!match) return { status: 'not-found', reason: 'not-explicit-command' };

  const requested = `/${match[1]}`;
  const aliases = readJson(resolve(root, '_audit/capability-aliases.json')).aliases ?? {};
  let target = requested;
  const seen = new Set();
  while (aliases[target] && aliases[target].startsWith('/')) {
    if (seen.has(target)) return { status: 'invalid', requested, reason: 'alias-cycle' };
    seen.add(target);
    target = aliases[target].split(/\s+/, 1)[0];
  }

  const canonical = target.slice(1);
  const index = readJson(resolve(root, 'registry/skills/index.json'));
  const record = index.bundles.find(({ id }) => id === canonical);
  if (!record) return { status: 'not-found', requested, canonical };
  const manifest = validateSkillBundle(readJson(resolve(root, record.manifest)));
  return { status: 'resolved', requested, canonical, manifestPath: record.manifest, manifest };
}
