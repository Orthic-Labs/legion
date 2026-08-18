// Sealed generic provider executor. Supports runner kinds: legacy-check,
// runtime-script, security-pack, external-process, imported-artifact, and
// reasoning-contract (planned/bundled but never invoked here). Internal module
// paths resolve relative to the installed Legion package and must match the
// sealed provider record.

import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { runExternal } from './executor/external-process.mjs';
import { requireProjectExecutionSandbox } from '../host/sandbox-policy.mjs';
import { normalizeProviderResult } from './sdk/result.mjs';
import { validateProviderOutputAuthority } from './sdk/contracts.mjs';
import { validateSchema } from '../qualification/schema-validator.mjs';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

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
      return runLegacyCheck(provider, root, plan, projection, artifacts, host);
    case 'external-process':
      return runExternal({
        provider: provider.id,
        executable: provider.runner.executable,
        executableDigest: provider.runner.executableDigest,
        args: provider.runner.args ?? [],
        cwd: root,
        timeoutMs: plan.config?.limits?.providerTimeoutMs ?? 120000,
        maxOutputBytes: plan.config?.limits?.maxOutputBytes ?? 8388608,
        environmentKeys: provider.runner.environmentKeys ?? ['PATH', 'HOME'],
        projectExecution: provider.hostCapabilities?.includes('project-execution') === true,
      }, host);
    case 'runtime-script':
    case 'security-pack':
      return runRuntimeScript(provider, root, plan, projection, artifacts, host);
    case 'imported-artifact':
      return runImportedArtifact(provider, artifacts, host);
    case 'reasoning-contract':
      return runReasoning(provider,plan,projection,artifacts,host);
    default:
      return {
        provider: provider.id,
        status: 'error',
        complete: false,
        coverageGaps: [{ kind: 'unsupported-runner', runner: provider.runner?.kind ?? null }],
      };
  }
}

async function runLegacyCheck(provider, root, plan, projection, artifacts, host) {
  if(typeof host.processRunner?.run!=='function')return{provider:provider.id,status:'unproven',complete:false,coverageGaps:[{kind:'named-check-host-unavailable',check:provider.runner.check}]};
  const result=await host.processRunner.run({kind:'legion-named-check',provider:provider.id,check:provider.runner.check,cwd:root,binding:plan.binding??null,denominator:plan.denominator??null,projection,artifacts});
  if(!result||typeof result.complete!=='boolean')return{provider:provider.id,status:'unproven',complete:false,coverageGaps:[{kind:'named-check-receipt-invalid',check:provider.runner.check}]};
  return{provider:provider.id,status:result.status??'unproven',complete:result.complete===true,findings:result.findings??[],candidates:result.candidates??[],coverageGaps:result.coverageGaps??[]};
}

async function runReasoning(provider,plan,projection,artifacts,host){const review=host.reviewer?.review??host.reviewer?.run;if(typeof review!=='function')return{provider:provider.id,status:'unproven',complete:false,coverageGaps:[{kind:'reasoning-reviewer-unavailable'}]};const packet={schemaVersion:1,kind:'legion-reasoning-packet',provider:provider.id,contract:provider.runner.contract,binding:plan.binding??null,projection,artifactIds:[...artifacts.keys()]};const result=await review.call(host.reviewer,packet);if(!result||typeof result.complete!=='boolean')return{provider:provider.id,status:'unproven',complete:false,coverageGaps:[{kind:'reasoning-receipt-invalid'}]};return{provider:provider.id,status:result.status??'unproven',complete:result.complete===true,findings:result.findings??[],candidates:result.candidates??[],coverageGaps:result.coverageGaps??[]};}

async function runRuntimeScript(provider, root, plan, projection, artifacts, host) {
  const modulePath = resolveRepositoryModule(provider.runner.module??provider.runner.script);
  const moduleBytes=await readFile(modulePath);
  const moduleDigest=`sha256:${createHash('sha256').update(moduleBytes).digest('hex')}`;
  if(moduleDigest!==provider.runner.moduleDigest)throw new Error(`provider ${provider.id} module digest mismatch`);
  const module = await import(pathToFileURL(modulePath).href);
  if (typeof module.default === 'object' && module.default?.id && module.default.id !== provider.id) {
    throw new Error(`security pack ID mismatch: plan=${provider.id}, module=${module.default.id}`);
  }
  const runner = module.analyze ?? module.default?.analyze;
  if (typeof runner !== 'function') {
    throw new Error(`runtime-script ${provider.runner.module} exports no runnable function`);
  }
  const result = await runner({
    root,
    plan,
    projection,
    artifacts,
    provider: provider.id,
    host,
  });
  const normalized=normalizeProviderResult(provider,result);
  validateProviderOutputAuthority(provider,normalized);
  const schema=JSON.parse(await readFile(resolve(import.meta.dirname,'..','..','src/schemas/provider-result-v1.schema.json'),'utf8'));
  const issues=validateSchema(schema,normalized);
  if(issues.length)throw new TypeError(`provider ${provider.id} result schema invalid: ${issues.join(',')}`);
  return normalized;
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
  // Resolve scripts relative to the Legion installation root, never from a
  // mutable external registry path.
  if(!script)throw new Error('runtime-script requires sealed module path');
  if (script.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(script)) {
    throw new Error(`runtime-script path must be repository-relative: ${script}`);
  }
  return resolve(import.meta.dirname, '..', '..', script);
}
