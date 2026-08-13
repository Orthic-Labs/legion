import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { roleProjection, rosterRoles } from '../../../roster/index.mjs';
import { doctrineText } from './doctrine.mjs';
import { writeIfDifferent, writeMarkerTarget } from './common.mjs';
import { mcpInstallConfig } from '../../../../integrations/mcp/install.mjs';
import { migrateMcpServers } from '../../../naming/migrations.mjs';

export const NAME = 'gemini';
export const FIDELITY_TIER = 'full';

function tomlString(value) { return JSON.stringify(value); }

export function detect(root) { return existsSync(join(root, '.gemini')) || existsSync(join(root, 'GEMINI.md')); }

function context(root) {
  const commands = rosterRoles().map((role) => `/legion:${role.id}`).join(', ');
  return {
    path: join(root, 'GEMINI.md'), kind: 'marker', reason: 'install Legion role context for Gemini CLI',
    blockContent: `# Legion\n\nUse native Legion role commands: ${commands}.\n\n${rosterRoles().map((role) => `- **${role.name}**: ${role.description} Tier: \`${role.modelTier}\`.`).join('\n')}\n- **Covenant seat**: advisory doctrine role, not an authority.`,
  };
}

function commandTarget(root, name, description, prompt) {
  return { path: join(root, '.gemini', 'commands', 'legion', `${name}.toml`), kind: 'whole', reason: `install Gemini /legion:${name} role command`, content: `description = ${tomlString(description)}\nprompt = ${tomlString(prompt)}\n` };
}

function commands(root) {
  const roster = rosterRoles().map((role) => commandTarget(root, role.id, role.description, `${roleProjection(role.id)}\n\nApply this role to the user request:\n{{args}}`));
  return [...roster, commandTarget(root, 'covenant-seat', 'Advisory Covenant review seat.', `${doctrineText('covenant-seat.md')}\n\nReview this immutable packet only:\n{{args}}`)];
}

function settings(root) {
  const path = join(root, '.gemini', 'settings.json');
  let existing = {};
  if (existsSync(path)) { try { existing = migrateMcpServers(JSON.parse(readFileSync(path, 'utf8'))); } catch { existing = {}; } }
  const mcpServers = { ...(existing.mcpServers ?? {}), legion: mcpInstallConfig().mcpServers.legion };
  return { path, kind: 'whole', reason: 'register Legion MCP server in Gemini project settings', content: `${JSON.stringify({ ...existing, mcpServers }, null, 2)}\n` };
}

export function targets(root) { return [context(root), ...commands(root), settings(root)]; }
export function plan(root) { return targets(root).map(({ path, reason }) => ({ path, reason })); }
export function write(root) {
  const wrote = [];
  for (const target of targets(root)) {
    if (target.kind === 'marker') writeMarkerTarget(target.path, target.blockContent);
    else writeIfDifferent(target.path, target.content);
    wrote.push(target.path);
  }
  return { wrote, wouldWrite: [] };
}
