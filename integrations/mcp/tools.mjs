// MCP tool registry per SNIP-MCP-01. Read-only tools only; mutation tools
// remain absent until separately authorized after v1. Repository instructions
// can never alter the tool schema.

import { NEMESIS_VERSION } from '../../lib/version.mjs';
import { readFileSync, statSync } from 'node:fs';
import { resolve, relative, sep } from 'node:path';

export function listTools() {
  return [
    { name: 'nemesis_doctor', description: 'Run nemesis doctor on a repository.', inputSchema: { type: 'object', properties: { root: { type: 'string' } } } },
    { name: 'nemesis_plan', description: 'Build and seal an audit plan.', inputSchema: { type: 'object', properties: { root: { type: 'string' }, profile: { type: 'string', enum: ['fast', 'standard', 'full', 'release'] } } } },
    { name: 'nemesis_audit', description: 'Run a complete audit.', inputSchema: { type: 'object', properties: { root: { type: 'string' }, profile: { type: 'string' } } } },
    { name: 'nemesis_verify', description: 'Verify a prior run out of band.', inputSchema: { type: 'object', properties: { facts: { type: 'string' } } } },
    { name: 'nemesis_get_run', description: 'Read a run artifact.', inputSchema: { type: 'object', properties: { run: { type: 'string' }, artifact: { type: 'string' } } } },
    { name: 'nemesis_get_finding', description: 'Read a finding from a run.', inputSchema: { type: 'object', properties: { run: { type: 'string' }, findingId: { type: 'string' } } } },
    { name: 'nemesis_explain', description: 'Explain a finding or gap.', inputSchema: { type: 'object', properties: { id: { type: 'string' }, run: { type: 'string' } } } },
    { name: 'nemesis_list_providers', description: 'List providers.', inputSchema: { type: 'object', properties: {} } },
    { name: 'nemesis_list_languages', description: 'List languages.', inputSchema: { type: 'object', properties: {} } },
  ];
}

export async function callTool(params) {
  const { name, arguments: args } = params ?? {};
  const tool = listTools().find((item) => item.name === name);
  if (!tool) {
    return { content: [{ type: 'text', text: `unknown tool: ${name}` }], isError: true };
  }
  try {
    const result = await invoke(name, args ?? {});
    // Single-line JSON keeps MCP stdio frames newline-delimited.
    return { content: [{ type: 'text', text: JSON.stringify(result) }], isError: false };
  } catch (error) {
    return { content: [{ type: 'text', text: error.message }], isError: true };
  }
}

async function invoke(name, args) {
  switch (name) {
    case 'nemesis_list_providers': {
      const { loadProviderRegistry } = await import('../../registry/provider-registry.mjs');
      const registry = loadProviderRegistry();
      return { providers: registry.providers.map((p) => p.id).sort(), version: NEMESIS_VERSION };
    }
    case 'nemesis_list_languages': {
      const { loadProviderRegistry } = await import('../../registry/provider-registry.mjs');
      const registry = loadProviderRegistry();
      return { languages: (registry.coverageFamilies ?? []).map((f) => f.id).sort(), version: NEMESIS_VERSION };
    }
    case 'nemesis_explain': {
      const { runExplain } = await import('../../lib/cli/commands/explain.mjs');
      const stdout = { write() {} };
      const result = await runExplain([args.id, ...(args.run ? ['--run', args.run] : []), '--json'], { stdout, stderr: { write() {} }, env: process.env, cwd: process.cwd() });
      return { exitCode: result.exitCode };
    }
    case 'nemesis_get_run': {
      const artifact = safeArtifactName(args.artifact ?? 'report.json');
      const text = readFileSync(runArtifactPath(args.run, artifact), 'utf8');
      return { artifact, content: JSON.parse(text) };
    }
    case 'nemesis_get_finding': {
      const report = JSON.parse(readFileSync(runArtifactPath(args.run, 'report.json'), 'utf8'));
      const finding = (report.findings ?? []).find((f) => f.id === args.findingId || f.ruleId === args.findingId);
      return { finding: finding ?? null };
    }
    default:
      throw new Error(`tool ${name} requires a host-granted root and is not invoked in stdio tests`);
  }
}

function safeArtifactName(name) {
  if (typeof name !== 'string' || !name || name.includes('\0') || name.includes('/') || name.includes('\\')) {
    throw new Error('artifact must be a single file name');
  }
  return name;
}

function runArtifactPath(run, artifact) {
  if (typeof run !== 'string' || !run) throw new Error('run must be an explicit artifact directory');
  const root = resolve(process.cwd());
  const absolute = resolve(root, run, artifact);
  const rel = relative(root, absolute);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) throw new Error('run artifact path escapes host root');
  if (!statSync(resolve(root, run)).isDirectory()) throw new Error('run must identify a directory');
  return absolute;
}
