import { parseArgs } from 'node:util';
import { EXIT } from '../../errors.mjs';
import { loadProviderRegistry } from '../../../registry/provider-registry.mjs';

export function runProviders(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { json: { type: 'boolean' }, selected: { type: 'boolean' }, all: { type: 'boolean' } },
    strict: false,
  });
  const registry = loadProviderRegistry();
  const providers = registry.providers.map((provider) => ({
    id: provider.id,
    role: provider.role,
    phase: provider.phase,
    runner: provider.runner?.kind ?? null,
    benchmark: provider.benchmark ?? null,
    producesSecurityCandidates: Boolean(provider.producesSecurityCandidates),
  })).sort((a, b) => a.id.localeCompare(b.id));
  if (parsed.values.json) {
    stdout.write(`${JSON.stringify({ schemaVersion: 1, kind: 'nemesis-providers', providers }, null, 2)}\n`);
  } else {
    for (const provider of providers) {
      stdout.write(`${provider.id}\t${provider.role}\t${provider.phase}\t${provider.runner ?? ''}\n`);
    }
  }
  return { exitCode: EXIT.PASS };
}
