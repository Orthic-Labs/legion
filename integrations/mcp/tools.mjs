// MCP tool registry per SNIP-MCP-01. Read-only tools only; mutation tools
// remain absent until separately authorized after v1. Repository instructions
// can never alter the tool schema.

import { NEMESIS_VERSION } from '../../lib/version.mjs';
import { readFileSync, statSync } from 'node:fs';
import { resolve, relative, sep } from 'node:path';

function hostFilesystem() {
  return {
    readFile: async (path, encoding) => readFileSync(path, encoding),
    stat: async (path) => statSync(path),
  };
}

export function listTools() {
  const rootInput = (properties = {}) => ({ type: 'object', required: ['root'], additionalProperties: false, properties: { root: { type: 'string', minLength: 1 }, ...properties } });
  const closedInput = (properties = {}, required = []) => ({ type: 'object', required, additionalProperties: false, properties });
  return [
    { name: 'nemesis_doctor', description: 'Run nemesis doctor on a repository.', inputSchema: rootInput() },
    { name: 'nemesis_plan', description: 'Build and seal an audit plan.', inputSchema: rootInput({ profile: { type: 'string', enum: ['fast', 'standard', 'full', 'release'] } }) },
    { name: 'nemesis_audit', description: 'Run a complete audit.', inputSchema: rootInput({ profile: { type: 'string', enum: ['fast', 'standard', 'full', 'release'] } }) },
    { name: 'nemesis_verify', description: 'Verify a prior run out of band.', inputSchema: rootInput({ priorRun: {} }) },
    { name: 'nemesis_get_run', description: 'Read a run artifact.', inputSchema: closedInput({ run: { type: 'string', minLength: 1 }, artifact: { type: 'string' } }, ['run']) },
    { name: 'nemesis_get_finding', description: 'Read a finding from a run.', inputSchema: closedInput({ run: { type: 'string', minLength: 1 }, findingId: { type: 'string', minLength: 1 } }, ['run', 'findingId']) },
    { name: 'nemesis_explain', description: 'Explain a finding or gap.', inputSchema: closedInput({ id: { type: 'string', minLength: 1 }, run: { type: 'string' } }, ['id']) },
    { name: 'nemesis_list_providers', description: 'List providers.', inputSchema: closedInput() },
    { name: 'nemesis_list_languages', description: 'List languages.', inputSchema: closedInput() },
  ];
}

export async function callTool(params, context = {}) {
  const { name, arguments: args } = params ?? {};
  const tool = listTools().find((item) => item.name === name);
  if (!tool) {
    return { content: [{ type: 'text', text: `unknown tool: ${name}` }], isError: true };
  }
  try {
    validateArguments(tool.inputSchema, args ?? {});
    const result = await invoke(name, args ?? {}, context);
    const text = JSON.stringify(result);
    if (Buffer.byteLength(text) > (context.maxOutputBytes ?? 1_000_000)) throw new Error('tool output exceeds configured limit');
    // Single-line JSON keeps MCP stdio frames newline-delimited.
    return { content: [{ type: 'text', text }], structuredContent: result, isError: false };
  } catch (error) {
    return { content: [{ type: 'text', text: error.message }], isError: true };
  }
}

async function invoke(name, args, context) {
  const hostRoot = resolve(context.root ?? process.cwd());
  const core = context.core ?? await defaultCore(context.host);
  switch (name) {
    case 'nemesis_doctor':
    case 'nemesis_plan':
    case 'nemesis_audit':
    case 'nemesis_verify': {
      const root = safeRoot(hostRoot, args.root ?? '.');
      const operation = name.slice('nemesis_'.length);
      return core[operation]({ ...args, root });
    }
    case 'nemesis_list_providers': {
      return { providers: core.providers(), version: NEMESIS_VERSION };
    }
    case 'nemesis_list_languages': {
      return { languages: core.languages(), version: NEMESIS_VERSION };
    }
    case 'nemesis_list_families': return { families: core.families(), version: NEMESIS_VERSION };
    case 'nemesis_list_skills': return { skills: core.skills(), version: NEMESIS_VERSION };
    case 'nemesis_explain': return core.explain({ ...args, root: hostRoot });
    case 'nemesis_get_run': return core.getRun({ ...args, root: hostRoot });
    case 'nemesis_get_finding': return core.getFinding({ ...args, root: hostRoot });
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

function runArtifactPath(run, artifact, root = resolve(process.cwd())) {
  if (typeof run !== 'string' || !run) throw new Error('run must be an explicit artifact directory');
  const absolute = resolve(root, run, artifact);
  const rel = relative(root, absolute);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) throw new Error('run artifact path escapes host root');
  if (!statSync(resolve(root, run)).isDirectory()) throw new Error('run must identify a directory');
  return absolute;
}

function safeRoot(hostRoot, requested) {
  if (typeof requested !== 'string' || !requested || requested.includes('\0')) throw new Error('root must be a path');
  const absolute = resolve(hostRoot, requested);
  const rel = relative(hostRoot, absolute);
  if (rel === '..' || rel.startsWith(`..${sep}`)) throw new Error('repository root escapes host root');
  return absolute;
}

async function defaultCore(hostOverride) {
  const [{ audit, verifyRun, inspectProduct }, { createHost }, { loadProviderRegistry }] = await Promise.all([
    import('../../lib/core/index.mjs'), import('../../lib/host/index.mjs'), import('../../registry/provider-registry.mjs'),
  ]);
  const host = hostOverride ?? createHost({ fs: hostFilesystem() });
  const registry = () => loadProviderRegistry();
  const getRun = ({ root, run, artifact = 'report.json' }) => {
    const safeArtifact = safeArtifactName(artifact);
    return { run, artifact: safeArtifact, content: JSON.parse(readFileSync(runArtifactPath(run, safeArtifact, root), 'utf8')) };
  };
  return {
    doctor: async ({ root }) => inspectProduct({ projection: { files: [], root }, binding: { root }, contract: {} }, host),
    plan: async (options) => audit({ ...options, planOnly: true, providers: registry().providers }, host),
    audit: async (options) => audit({ ...options, providers: registry().providers }, host),
    verify: async (options) => {
      const priorRun = options.priorRun ?? options.run;
      return verifyRun({
        priorRun: priorRun ? safeRoot(options.root, priorRun) : null,
        currentRepository: options.currentRepository ?? { binding: { root: options.root } },
      }, host);
    },
    providers: () => registry().providers.map(({ id }) => id).sort(),
    languages: () => (registry().languages ?? []).map((entry) => entry.id ?? entry).sort(),
    families: () => (registry().coverageFamilies ?? registry().families ?? []).map((entry) => entry.id ?? entry).sort(),
    skills: () => ['designer', 'writing'],
    getRun,
    getFinding: ({ root, run, findingId }) => {
      const report = getRun({ root, run }).content;
      return { run, findingId, finding: (report.findings ?? []).find((item) => item.id === findingId || item.ruleId === findingId) ?? null };
    },
    explain: ({ root, run, id }) => {
      const report = run ? getRun({ root, run }).content : {};
      const finding = (report.findings ?? []).find((item) => item.id === id || item.ruleId === id) ?? null;
      const gap = (report.coverage_gaps ?? []).find((item) => item.id === id || item.kind === id) ?? null;
      return { schemaVersion: 1, kind: 'nemesis-explain', run: run ?? null, id, found: Boolean(finding || gap), finding, gap };
    },
  };
}

function validateArguments(schema, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('tool arguments must be an object');
  const allowed = new Set(Object.keys(schema.properties ?? {}));
  const extra = Object.keys(args).filter((key) => !allowed.has(key));
  if (extra.length) throw new Error(`unexpected tool argument: ${extra[0]}`);
  for (const key of schema.required ?? []) if (!(key in args)) throw new Error(`missing required tool argument: ${key}`);
  for (const [key, rule] of Object.entries(schema.properties ?? {})) {
    if (!(key in args) || !rule.type) continue;
    if (rule.type === 'string' && (typeof args[key] !== 'string' || (rule.minLength && args[key].length < rule.minLength))) throw new Error(`${key} must be a non-empty string`);
    if (rule.enum && !rule.enum.includes(args[key])) throw new Error(`${key} has an unsupported value`);
  }
}
