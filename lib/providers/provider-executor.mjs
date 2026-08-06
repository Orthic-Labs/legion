// Sealed generic provider executor. Supports runner kinds: legacy-check,
// runtime-script, security-pack, external-process, imported-artifact, and
// reasoning-contract (planned/bundled but never invoked here). Internal module
// paths resolve relative to the installed Nemesis package and must match the
// sealed provider record.

import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { runExternal } from './external-process.mjs';
import { requireProjectExecutionSandbox } from '../host/sandbox-policy.mjs';

export async function executePlannedProvider({
  provider,
  root,
  plan,
  projection,
  artifacts,
  options = {},
  host,
}) {
  requireProjectExecutionSandbox(provider, host);

  switch (provider.runner?.kind) {
    case 'legacy-check':
      return runLegacyCheck(provider, root, host);
    case 'external-process':
      return runExternal({
        provider: provider.id,
        executable: provider.runner.executable,
        args: provider.runner.args ?? [],
        cwd: root,
        timeoutMs: plan.config?.limits?.providerTimeoutMs ?? 120000,
        maxOutputBytes: plan.config?.limits?.maxOutputBytes ?? 8388608,
        environmentKeys: provider.runner.environmentKeys ?? ['PATH', 'HOME'],
      }, host);
    case 'runtime-script':
    case 'security-pack':
      return runRuntimeScript(provider, root, plan, projection, artifacts, host);
    case 'imported-artifact':
      return runImportedArtifact(provider, artifacts, host);
    case 'reasoning-contract':
      // Planned and bundled only; deterministic code never invokes reasoning.
      return {
        provider: provider.id,
        status: 'skipped',
        complete: true,
        activation: { kind: 'reasoning-contract', matched: false, reason: 'deterministic executor does not invoke reasoning contracts' },
      };
    default:
      return {
        provider: provider.id,
        status: 'error',
        complete: false,
        coverageGaps: [{ kind: 'unsupported-runner', runner: provider.runner?.kind ?? null }],
      };
  }
}

async function runLegacyCheck(provider, root, host) {
  return runExternal({
    provider: provider.id,
    executable: provider.runner.check,
    args: [],
    cwd: root,
    environmentKeys: ['PATH', 'HOME'],
  }, host);
}

async function runRuntimeScript(provider, root, plan, projection, artifacts, host) {
  const modulePath = resolveRepositoryModule(provider.runner.script);
  const module = await import(pathToFileURL(modulePath).href);
  if (typeof module.default === 'object' && module.default?.id && module.default.id !== provider.id) {
    throw new Error(`security pack ID mismatch: plan=${provider.id}, module=${module.default.id}`);
  }
  const runner = module.default?.analyze ?? module.run ?? module.default?.run;
  if (typeof runner !== 'function') {
    throw new Error(`runtime-script ${provider.runner.script} exports no runnable function`);
  }
  const result = await runner({
    root,
    plan,
    projection,
    artifacts,
    provider: provider.id,
    host,
  });
  return {
    provider: provider.id,
    ...result,
  };
}

async function runImportedArtifact(provider, artifacts, host) {
  const artifact = artifacts?.get(provider.runner.artifact);
  if (!artifact) {
    return {
      provider: provider.id,
      status: 'missing',
      complete: false,
      coverageGaps: [{ kind: 'imported-artifact-missing', artifact: provider.runner.artifact }],
    };
  }
  return {
    provider: provider.id,
    status: 'pass',
    complete: true,
    artifact: provider.runner.artifact,
  };
}

export function resolveRepositoryModule(script) {
  // Resolve scripts relative to the Nemesis installation root, never from a
  // mutable external registry path.
  if (script.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(script)) {
    throw new Error(`runtime-script path must be repository-relative: ${script}`);
  }
  return resolve(import.meta.dirname, '..', '..', script);
}
