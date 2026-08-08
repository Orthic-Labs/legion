import { parseArgs } from 'node:util';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { EXIT, NemesisError } from '../../errors.mjs';
import { DEFAULT_CONFIG, mergeConfig, profileConfig } from '../../config/index.mjs';

export async function runPlan(argv, { stdout, stderr, cwd, host, core=null }) {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { json: { type: 'boolean' }, out: { type: 'string' }, profile: { type: 'string' } },
    strict: true,
  });
  const root = resolve(parsed.positionals[0] ?? cwd);
  if (!existsSync(root)) throw new NemesisError(`root does not exist: ${root}`, { code: 'USAGE', exitCode: EXIT.USAGE });
  const profile = parsed.values.profile ?? DEFAULT_CONFIG.profile;
  const config = mergeConfig({
    defaults: profileConfig(profile),
    cli: parsed.values.profile ? { profile } : {},
  });
  const api=core??await import('../../index.mjs');const registry=api.loadProviderRegistry();const projection=await host.cortex?.project?.({root})??{state:'unproven',files:[],reason:'cortex-projection-unavailable'};const repositoryBinding=await api.bindRepository(root,{revision:null});
  const plan = await api.buildPlan({ root, registry, projection, repositoryBinding },host);
  if (parsed.values.json) {
    stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  } else {
    stdout.write(`plan sealed: ${plan.seal.digest}\nprofile: ${config.profile}\nproviders: ${plan.denominator.providerIds.join(', ')}\n`);
  }
  return { exitCode: EXIT.PASS };
}
