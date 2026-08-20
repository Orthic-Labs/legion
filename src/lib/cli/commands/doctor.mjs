import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { EXIT } from '../../errors.mjs';
import { loadProviderRegistry } from '../../../registry/provider-registry.mjs';
import { CortexAdapter } from '../../adapters/cortex/index.mjs';
import { computeBindingSection } from './bind/drift.mjs';
import { runSemanticHealth } from '../../../packages/arcane/lib/semantic-health.mjs';
import { checkCanonicalNames } from '../../naming/check.mjs';
import { inspectMcpNaming } from '../../naming/migrations.mjs';

function namingBindings(root) {
  const claudePath = resolve(root, '.mcp.json');
  let claudeCode = { status: 'absent', legacy: [] };
  if (existsSync(claudePath)) {
    try { claudeCode = inspectMcpNaming(JSON.parse(readFileSync(claudePath, 'utf8'))); }
    catch { claudeCode = { status: 'invalid', legacy: [] }; }
  }
  const geminiPath = resolve(root, '.gemini', 'settings.json');
  let gemini = { status: 'absent', legacy: [] };
  if (existsSync(geminiPath)) {
    try { gemini = inspectMcpNaming(JSON.parse(readFileSync(geminiPath, 'utf8'))); }
    catch { gemini = { status: 'invalid', legacy: [] }; }
  }
  const codexPath = resolve(root, '.codex', 'config.toml');
  const codexText = existsSync(codexPath) ? readFileSync(codexPath, 'utf8') : '';
  const codexLegacy = [...codexText.matchAll(/^\[mcp_servers\.(seer|forge|sorcerer|sentinel)\]\s*$/gmi)].map((match) => match[1].toLowerCase());
  return { claudeCode, gemini, codex: { status: codexLegacy.length ? 'legacy-present' : codexText ? 'canonical' : 'absent', legacy: codexLegacy } };
}

import { computeHostSection } from './doctor-host.mjs';

function namingBindingsHealthy(state) {
  return Object.values(state).every(({ status }) => !['legacy-present', 'invalid'].includes(status));
}

// legion doctor --json per SNIP-DOCTOR-01: repository, cortex state/mode,
// coverage, provider selection, host capabilities, clean-claim eligibility,
// gaps, and exact remediation commands.
export async function runDoctor(argv, { stdout, stderr, env, cwd, host }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, options: { json: { type: 'boolean' } }, strict: true });
  const root = resolve(parsed.positionals[0] ?? cwd);
  const registry = loadProviderRegistry();
  const adapter = new CortexAdapter({
    mode: env.LEGION_CORTEX_MODE ?? 'external',
    externalCommand: env.LEGION_CORTEX_BIN ?? null,
    precomputedPath: env.LEGION_CORTEX_PRECOMPUTED ?? null,
  });
  const compatible = await adapter.ensureCompatible();
  const projection = compatible.ok
    ? await adapter.generateOrLoadProjection({ repositoryRoot: root })
    : { state: 'unproven', reason: compatible.error };
  const freshness = projection?.state === 'ready'
    ? await adapter.verifyFreshness({ repositoryRoot: root, projection })
    : { fresh: false, reason: projection?.reason ?? 'cortex unavailable' };

  const rawCortexState = projection?.state === 'ready' ? (freshness.fresh ? 'ready' : 'stale') : (projection?.state ?? 'missing');
  // The doctor contract's cortex.state enum is ready|stale|missing|incompatible|corrupt;
  // map any non-ready projection state (unproven/error/blocked) to missing.
  const cortexState = ['ready', 'stale', 'missing', 'incompatible', 'corrupt'].includes(rawCortexState)
    ? rawCortexState
    : 'missing';
  const toolchains = host?.toolchain?.discover?.({ root, env }) ?? { state: 'unproven', tools: [] };
  const arcaneSemanticHealth = runSemanticHealth({ cwd: root, env });
  const naming = checkCanonicalNames({ root: resolve(import.meta.dirname, '..', '..', '..', '..') });
  const namingBindingState = namingBindings(root);

  const report = {
    schemaVersion: 1,
    kind: 'legion-doctor',
    repository: { root },
    cortex: {
      state: cortexState,
      mode: adapter.mode,
      generationId: projection?.generationId ?? null,
      manifestDigest: projection?.manifestDigest ?? null,
    },
    coverage: {
      languages: (registry.coverageFamilies ?? []).map((family) => family.id).sort(),
      frameworks: [],
      systems: [],
      unsupported: projection?.unsupportedExtensions ?? [],
    },
    providers: {
      selected: [],
      blocked: [],
      missingTools: [],
    },
    hostCapabilities: {
      networkSandbox: env.AUDIT_NETWORK_GUARD === 'active',
      signing: Boolean(env.AUDIT_PLAN_SIGNING_KEY),
      browser: false,
      toolchains,
    },
    arcane: { semanticHealth: arcaneSemanticHealth },
    // Installation identity, discovery, projection drift, declared
    // fidelity, and effect-gate registration, so a harness that cannot see
    // Legion is diagnosable without reading source.
    host: computeHostSection(root),
    naming: { ...naming, bindings: namingBindingState },
    binding: computeBindingSection(root),
    cleanClaimPossible: false,
    gaps: [
      ...(projection?.state !== 'ready' ? [{ kind: 'cortex-unavailable', detail: projection?.reason ?? null }] : []),
      ...(!freshness.fresh ? [{ kind: 'cortex-stale', detail: freshness.reason ?? null }] : []),
      ...(compatible.ok ? [] : [{ kind: 'cortex-incompatible', detail: compatible.error }]),
      ...(!arcaneSemanticHealth.healthy ? [{ kind: 'arcane-semantic-health-unhealthy', detail: arcaneSemanticHealth.probes.filter((probe) => !probe.ok).map((probe) => ({ id: probe.id, error: probe.error })) }] : []),
      ...(naming.status === 'pass' ? [] : [{ kind: 'naming-contract-failed', detail: naming.unclassified }]),
      ...(namingBindingsHealthy(namingBindingState) ? [] : [{ kind: 'naming-migration-pending', detail: namingBindingState }]),
    ],
    commands: [
      ...(projection?.state !== 'ready' ? ['Install or configure Cortex, then rerun legion doctor.'] : []),
      ...(!env.AUDIT_NETWORK_GUARD ? ['Set AUDIT_NETWORK_GUARD=active for project-executing providers.'] : []),
      ...(!env.AUDIT_PLAN_SIGNING_KEY ? ['Set AUDIT_PLAN_SIGNING_KEY to sign the frozen plan.'] : []),
      ...(!arcaneSemanticHealth.healthy ? ['Run legion doctor after repairing the failing Arcane semantic probe.'] : []),
      ...(naming.status === 'pass' ? [] : ['Run pnpm naming:check after repairing unclassified legacy names.']),
      ...(namingBindingsHealthy(namingBindingState) ? [] : ['Run legion bind --write after reviewing reported legacy or conflicting MCP bindings.']),
    ],
  };
  stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  return { exitCode: EXIT.PASS };
}
