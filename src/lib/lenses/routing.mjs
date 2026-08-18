import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadRoutingGraph, validateRoutingGraph } from '../routing/index.mjs';

const EXPECTED = new Set(['commercial', 'research', 'editorial', 'design']);

export function validateCommercialLenses(root) {
  const findings = [];
  const index = JSON.parse(readFileSync(resolve(root, 'src/registry/lenses/commercial-routing.json'), 'utf8'));
  const records = index.lenses.map((id) => JSON.parse(readFileSync(resolve(root, 'src', 'lenses', `${id}.json`), 'utf8')));
  if (new Set(index.lenses).size !== EXPECTED.size || index.lenses.some((id) => !EXPECTED.has(id))) findings.push({ code: 'lens-roster', detail: 'registry must contain only four typed commercial lenses' });
  for (const record of records) {
    if (record.availability !== 'available' || record.targetType !== 'content' || record.targetRef !== 'src/registry/routing/domains.json') findings.push({ code: 'lens-availability', lensId: record.id, detail: 'lens must bind packaged domain routing' });
    if (record.privateOverlay?.state !== 'optional' || !Array.isArray(record.privateOverlay?.fields) || record.privateOverlay.fields.length) findings.push({ code: 'private-overlay', lensId: record.id, detail: 'private overlay must remain optional, empty & unbound' });
    if (hasSlashSkill(record)) findings.push({ code: 'slash-skill', lensId: record.id, detail: 'lens leaks a slash skill' });
  }
  const routing = validateRoutingGraph(loadRoutingGraph(root));
  if (!routing.ok) findings.push(...routing.findings.map((item) => ({ ...item, code: `routing-${item.code}` })));
  return { ok: findings.length === 0, findings, lensIds: records.map(({ id }) => id).sort() };
}

export function hasSlashSkill(value) {
  if (typeof value === 'string') return /(^|\s)\/[a-z][a-z0-9-]*/i.test(value);
  if (Array.isArray(value)) return value.some(hasSlashSkill);
  return value && typeof value === 'object' && Object.values(value).some(hasSlashSkill);
}
