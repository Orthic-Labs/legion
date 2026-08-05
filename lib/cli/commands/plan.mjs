import { parseArgs } from 'node:util';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { EXIT, NemesisError } from '../../errors.mjs';
import { buildAuditPlan } from '../../../audit-plan.mjs';
import { loadProviderRegistry } from '../../../registry/provider-registry.mjs';
import { readCortexProjection } from '../../../adapters/cortex-projection.mjs';

export function runPlan(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { json: { type: 'boolean' }, out: { type: 'string' }, profile: { type: 'string' } },
    strict: false,
  });
  const root = resolve(parsed.positionals[0] ?? cwd);
  if (!existsSync(root)) throw new NemesisError(`root does not exist: ${root}`, { code: 'USAGE', exitCode: EXIT.USAGE });
  const registry = loadProviderRegistry();
  const projection = readCortexProjection(root, { outDir: '.agent' });
  const repositoryBinding = { repositoryRevision: null, dirty: false, dirtyPatchDigest: null };
  const plan = buildAuditPlan({ root, registry, projection, repositoryBinding });
  if (parsed.values.json) {
    stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  } else {
    stdout.write(`plan sealed: ${plan.seal.digest}\nproviders: ${plan.denominator.providerIds.join(', ')}\n`);
  }
  return { exitCode: EXIT.PASS };
}
