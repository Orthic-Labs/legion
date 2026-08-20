import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadRoutingGroups, validateRoutingGroups } from '../routing/index.mjs';

export function validateCommercialLenses(root) {
  const findings = [];
  const index = JSON.parse(readFileSync(resolve(root, 'src/registry/lenses/commercial-routing.json'), 'utf8'));
  const records = index.lenses.map((id) => JSON.parse(readFileSync(resolve(root, 'src', 'lenses', `${id}.json`), 'utf8')));
  const graph = loadRoutingGroups(root);
  const routing = validateRoutingGroups(graph);
  const groups = new Set(graph.domains?.map(({ id }) => id) ?? []);
  if (new Set(index.lenses).size !== index.lenses.length) findings.push({ code: 'lens-roster', detail: 'lens registry ids must be unique' });
  for (const [position, record] of records.entries()) {
    if (record.id !== index.lenses[position] || record.availability !== 'available') findings.push({ code: 'lens-availability', lensId: record.id, detail: 'lens id must match its registry entry & remain available' });
    if (record.group != null && !groups.has(record.group)) findings.push({ code: 'lens-group', lensId: record.id, detail: 'optional grouping metadata must resolve to a current routing group' });
    if (Object.hasOwn(record, 'targetType') || Object.hasOwn(record, 'targetRef')) findings.push({ code: 'lens-routing-authority', lensId: record.id, detail: 'lens metadata cannot declare a routing target' });
    if (record.privateOverlay?.state !== 'optional' || !Array.isArray(record.privateOverlay?.fields) || record.privateOverlay.fields.length) findings.push({ code: 'private-overlay', lensId: record.id, detail: 'private overlay must remain optional, empty & unbound' });
    if (hasSlashSkill(record)) findings.push({ code: 'slash-skill', lensId: record.id, detail: 'lens leaks a slash skill' });
  }
  if (!routing.ok) findings.push(...routing.findings.map((item) => ({ ...item, code: `routing-${item.code}` })));
  return { ok: findings.length === 0, findings, lensIds: records.map(({ id }) => id).sort() };
}

export function hasSlashSkill(value) {
  if (typeof value === 'string') return /(^|\s)\/[a-z][a-z0-9-]*/i.test(value);
  if (Array.isArray(value)) return value.some(hasSlashSkill);
  return value && typeof value === 'object' && Object.values(value).some(hasSlashSkill);
}
