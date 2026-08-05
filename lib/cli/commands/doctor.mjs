import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { EXIT } from '../../errors.mjs';
import { loadProviderRegistry } from '../../../registry/provider-registry.mjs';
import { CortexAdapter } from '../../adapters/cortex/index.mjs';

// nemesis doctor --json per SNIP-DOCTOR-01: repository, cortex state/mode,
// coverage, provider selection, host capabilities, clean-claim eligibility,
// gaps, and exact remediation commands.
export async function runDoctor(argv, { stdout, stderr, env, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, options: { json: { type: 'boolean' } }, strict: false });
  const root = resolve(parsed.positionals[0] ?? cwd);
  const registry = loadProviderRegistry();
  const adapter = new CortexAdapter({
    mode: env.NEMESIS_CORTEX_MODE ?? 'external',
    externalCommand: env.NEMESIS_CORTEX_BIN ?? null,
    precomputedPath: env.NEMESIS_CORTEX_PRECOMPUTED ?? null,
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

  const report = {
    schemaVersion: 1,
    kind: 'nemesis-doctor',
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
    },
    cleanClaimPossible: false,
    gaps: [
      ...(projection?.state !== 'ready' ? [{ kind: 'cortex-unavailable', detail: projection?.reason ?? null }] : []),
      ...(!freshness.fresh ? [{ kind: 'cortex-stale', detail: freshness.reason ?? null }] : []),
      ...(compatible.ok ? [] : [{ kind: 'cortex-incompatible', detail: compatible.error }]),
    ],
    commands: [
      ...(projection?.state !== 'ready' ? ['Install or configure Cortex, then rerun nemesis doctor.'] : []),
      ...(!env.AUDIT_NETWORK_GUARD ? ['Set AUDIT_NETWORK_GUARD=active for project-executing providers.'] : []),
      ...(!env.AUDIT_PLAN_SIGNING_KEY ? ['Set AUDIT_PLAN_SIGNING_KEY to sign the frozen plan.'] : []),
    ],
  };
  stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  return { exitCode: EXIT.PASS };
}
