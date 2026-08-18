import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { hasSlashSkill, validateCommercialLenses } from '../lenses/routing.mjs';

const EXPECTED = new Set(['brand-assets', 'frontend-design', 'product-validation', 'research-workflow']);

export function validateInternalRecipes(root) {
  const findings = [];
  const lensIds = new Set(validateCommercialLenses(root).lensIds);
  const index = JSON.parse(readFileSync(resolve(root, 'src/registry/recipes/index.json'), 'utf8'));
  const records = index.recipes.map((id) => JSON.parse(readFileSync(resolve(root, 'src', 'recipes', `${id}.json`), 'utf8')));
  const byId = new Map(records.map((record) => [record.id, record]));
  if (new Set(index.recipes).size !== EXPECTED.size || index.recipes.some((id) => !EXPECTED.has(id))) findings.push({ code: 'recipe-roster', detail: 'registry must contain only four internal recipes' });
  for (const record of records) {
    if (record.internal !== true || record.availability !== 'unavailable') findings.push({ code: 'recipe-availability', recipeId: record.id, detail: 'Wave 1 recipes remain internal & unavailable' });
    if (!Array.isArray(record.privateFields) || record.privateFields.some((field) => !/^[a-z][a-z0-9-]*$/.test(field))) findings.push({ code: 'private-fields', recipeId: record.id, detail: 'private fields must use safe explicit names' });
    for (const lens of record.lenses ?? []) if (!lensIds.has(lens)) findings.push({ code: 'recipe-reference', recipeId: record.id, detail: `unknown lens: ${lens}` });
    for (const dependency of record.dependsOn ?? []) if (!byId.has(dependency)) findings.push({ code: 'recipe-reference', recipeId: record.id, detail: `unknown recipe: ${dependency}` });
    if (hasSlashSkill(record)) findings.push({ code: 'slash-skill', recipeId: record.id, detail: 'recipe leaks a slash skill' });
  }
  for (const id of byId) visit(id, byId, new Set(), new Set(), findings);
  return { ok: findings.length === 0, findings, recipeIds: [...byId.keys()].sort() };
}

function visit(id, byId, active, done, findings) {
  if (done.has(id)) return;
  if (active.has(id)) { findings.push({ code: 'recipe-dag', recipeId: id, detail: 'recipe dependency cycle' }); return; }
  active.add(id); for (const dependency of byId.get(id)?.dependsOn ?? []) visit(dependency, byId, active, done, findings); active.delete(id); done.add(id);
}
