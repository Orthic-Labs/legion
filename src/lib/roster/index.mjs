import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const ROSTER_DIR = resolve(ROOT, 'roster');
const ROLE_IDS = Object.freeze(['sage', 'alchemist', 'oracle']);
const MODEL_TIERS = new Set(['frontier-judgment', 'balanced-executor', 'mechanical-cheap']);
const ROUTE_METHODS = Object.freeze({
  sage: 'doctrine/sage.md',
  alchemist: 'doctrine/alchemist.md',
  oracle: 'doctrine/oracle.md',
});
const PROJECTION_SECTIONS = Object.freeze(['Purpose', 'Triggers', 'Routes', 'Capabilities', 'Inputs', 'Outputs', 'Boundaries', 'Handoffs', 'Evidence rules', 'Model policy']);

function parseFrontmatter(text, path) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text);
  if (!match) throw new TypeError(`${path}: missing frontmatter`);
  const values = {};
  for (const line of match[1].split(/\r?\n/)) {
    const index = line.indexOf(':');
    if (index > 0) values[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }
  return { values, body: text.slice(match[0].length).trim() };
}

function section(body, name) {
  const match = new RegExp(`^##\\s+${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\r?\\n`, 'mi').exec(body);
  if (!match) return null;
  const start = match.index + match[0].length;
  const rest = body.slice(start);
  const next = rest.search(/^##\s+/m);
  return `## ${name}\n\n${(next < 0 ? rest : rest.slice(0, next)).trim()}`;
}

export function rosterPath(id) {
  if (!ROLE_IDS.includes(id)) throw new TypeError(`unknown roster role: ${id}`);
  return resolve(ROSTER_DIR, `${id}.md`);
}

export function loadRosterRole(id) {
  const path = rosterPath(id);
  const { values, body } = parseFrontmatter(readFileSync(path, 'utf8'), path);
  if (values.name !== id) throw new TypeError(`${path}: expected name ${id}`);
  if (!values.description?.includes('Dispatch')) throw new TypeError(`${path}: description must contain Dispatch`);
  if (!MODEL_TIERS.has(values.modelTier)) throw new TypeError(`${path}: unsupported modelTier ${values.modelTier ?? '<missing>'}`);
  return Object.freeze({ id, path, name: values.name, description: values.description, modelTier: values.modelTier, delegationTiers: values.delegationTiers ?? '', body });
}

export function rosterRoles() {
  return ROLE_IDS.map(loadRosterRole);
}

export function roleProjection(id) {
  const role = loadRosterRole(id);
  const sections = PROJECTION_SECTIONS.map((name) => section(role.body, name)).filter(Boolean);
  return [
    '---',
    `name: ${role.name}`,
    `description: ${role.description}`,
    '---',
    '',
    `# ${role.name[0].toUpperCase()}${role.name.slice(1)} — Legion role`,
    '',
    `Model tier: \`${role.modelTier}\`. Host resolves a compatible provider/model; roster source is vendor-neutral.`,
    '',
    `Route method: \`${ROUTE_METHODS[id]}\`.`,
    '',
    ...sections,
    '',
  ].join('\n');
}

export function lowFidelityProjection() {
  return [
    '# Legion authority context',
    '',
    ...rosterRoles().map((role) => `- **${role.name}** — ${role.description} Model tier: \`${role.modelTier}\`.`),
    '- **Covenant seat** — doctrine-only advisory review seat; not an authority.',
    '',
    'Use Legion routing. Do not edit generated harness files; rerun `legion bind --write`.',
  ].join('\n');
}

export const ROSTER_ROLE_IDS = ROLE_IDS;
