import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { EXIT } from '../../errors.mjs';
import { loadProviderRegistry } from '../../../registry/provider-registry.mjs';
import { MembraneAdapter } from '../../adapters/membrane/index.mjs';
import { computeBindingSection } from './bind/drift.mjs';
import { runSemanticHealth } from '../../verification/arcane/semantic-health.mjs';
import { checkCanonicalNames } from '../../naming/check.mjs';
import { inspectMcpNaming } from '../../naming/migrations.mjs';

export const DOCTOR_BLUEPRINT_TIMEOUT_MS = 15_000;

function lifecycle(stderr, phase, detail = null) {
  stderr.write(`${JSON.stringify({ kind: 'legion-doctor-lifecycle', phase, detail, at: new Date().toISOString() })}\n`);
}

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

// legion doctor --json per SNIP-DOCTOR-01: repository, Membrane context state,
// coverage, provider selection, host capabilities, clean-claim eligibility,
// gaps, and exact remediation commands.
export async function runDoctor(argv, { stdout, stderr, env, cwd, host }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, options: { json: { type: 'boolean' } }, strict: true });
  const root = resolve(parsed.positionals[0] ?? cwd);
  const registry = loadProviderRegistry();
  lifecycle(stderr, 'started', { root });
  const adapter = new MembraneAdapter({
    packetPath: env.LEGION_MEMBRANE_PACKET ?? null,
    timeoutMs: DOCTOR_BLUEPRINT_TIMEOUT_MS,
  });
  lifecycle(stderr, 'blueprint-probe-started', { timeoutMs: DOCTOR_BLUEPRINT_TIMEOUT_MS });
  const compatible = await adapter.ensureCompatible();
  const projection = compatible.ok
    ? await adapter.generateOrLoadProjection({ request: { root } })
    : { status: 'unavailable', reason: compatible.error };
  lifecycle(stderr, 'blueprint-probe-finished', { status: projection?.status ?? 'unavailable' });
  const freshness = projection?.status !== 'unavailable'
    ? await adapter.verifyFreshness({ packet: projection })
    : { fresh: false, reason: projection?.reason ?? 'Membrane unavailable' };

  const rawBlueprintState = projection?.status !== 'unavailable' ? (freshness.fresh ? 'ready' : 'stale') : 'missing';
  const blueprintState = ['ready', 'stale', 'missing', 'incompatible', 'corrupt'].includes(rawBlueprintState)
    ? rawBlueprintState
    : 'missing';
  const toolchains = host?.toolchain?.discover?.({ root, env }) ?? { state: 'unproven', tools: [] };
  lifecycle(stderr, 'semantic-probes-started');
  const arcaneSemanticHealth = runSemanticHealth({
    cwd: root,
    env,
    onProbe: (detail) => lifecycle(stderr, 'semantic-probe', detail),
  });
  lifecycle(stderr, 'semantic-probes-finished', { healthy: arcaneSemanticHealth.healthy });
  const naming = checkCanonicalNames({ root: resolve(import.meta.dirname, '..', '..', '..', '..') });
  const namingBindingState = namingBindings(root);
  lifecycle(stderr, 'host-probes-started');
  const hostSection = computeHostSection(root);
  lifecycle(stderr, 'host-probes-finished', { state: hostSection.hostRequirements.state });

  const report = {
    schemaVersion: 1,
    kind: 'legion-doctor',
    repository: { root },
    blueprint: {
      state: blueprintState,
      mode: adapter.mode,
      packetDigest: projection?.packetDigest ?? null,
    },
    coverage: {
      languages: (registry.coverageFamilies ?? []).map((family) => family.id).sort(),
      frameworks: [],
      systems: [],
      unsupported: [],
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
    host: hostSection,
    naming: { ...naming, bindings: namingBindingState },
    binding: computeBindingSection(root),
    cleanClaimPossible: false,
    gaps: [
      ...(projection?.status === 'unavailable' ? [{ kind: 'membrane-unavailable', detail: projection?.reason ?? null }] : []),
      ...(!freshness.fresh ? [{ kind: 'blueprint-stale', detail: freshness.reason ?? null }] : []),
      ...(compatible.ok ? [] : [{ kind: 'membrane-incompatible', detail: compatible.error }]),
      ...(!arcaneSemanticHealth.healthy ? [{ kind: 'arcane-semantic-health-unhealthy', detail: arcaneSemanticHealth.probes.filter((probe) => !probe.ok).map((probe) => ({ id: probe.id, error: probe.error })) }] : []),
      ...(hostSection.guard.codexHookTrust.state === 'ARC_HOOK_TRUST_REQUIRED' ? [{ kind: 'guard-hook-trust-required', code: 'ARC_HOOK_TRUST_REQUIRED', detail: hostSection.guard.codexHookTrust.missing }] : []),
      ...(naming.status === 'pass' ? [] : [{ kind: 'naming-contract-failed', detail: naming.unclassified }]),
      ...(namingBindingsHealthy(namingBindingState) ? [] : [{ kind: 'naming-migration-pending', detail: namingBindingState }]),
    ],
    commands: [
      ...(projection?.status === 'unavailable' ? ['Start Membrane context transport, then rerun legion doctor.'] : []),
      ...(!env.AUDIT_NETWORK_GUARD ? ['Set AUDIT_NETWORK_GUARD=active for project-executing providers.'] : []),
      ...(!env.AUDIT_PLAN_SIGNING_KEY ? ['Set AUDIT_PLAN_SIGNING_KEY to sign the frozen plan.'] : []),
      ...(!arcaneSemanticHealth.healthy ? ['Run legion doctor after repairing the failing Arcane semantic probe.'] : []),
      ...(hostSection.guard.codexHookTrust.state === 'ARC_HOOK_TRUST_REQUIRED' ? ['Open Codex /hooks & trust current Guard hook definitions, then rerun legion doctor.'] : []),
      ...(naming.status === 'pass' ? [] : ['Run pnpm naming:check after repairing unclassified legacy names.']),
      ...(namingBindingsHealthy(namingBindingState) ? [] : ['Run legion bind --write after reviewing reported legacy or conflicting MCP bindings.']),
    ],
  };
  stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  lifecycle(stderr, 'finished', { gaps: report.gaps.length });
  return { exitCode: EXIT.PASS };
}
