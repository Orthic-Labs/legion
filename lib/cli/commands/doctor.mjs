import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { EXIT } from '../../errors.mjs';
import { loadProviderRegistry } from '../../../registry/provider-registry.mjs';

// PR05: structural doctor over the provider registry. PR09 deepens it with
// Cortex freshness, tool presence, sandbox/signing availability, and exact
// remediation commands.
export function runDoctor(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, options: { json: { type: 'boolean' } }, strict: false });
  const root = resolve(parsed.positionals[0] ?? cwd);
  const registry = loadProviderRegistry();
  const report = {
    schemaVersion: 1,
    kind: 'nemesis-doctor',
    repository: { root },
    cortex: { state: 'unchecked', mode: null },
    coverage: {
      languages: (registry.coverageFamilies ?? []).map((family) => family.id).sort(),
      unsupported: [],
    },
    providers: {
      selected: [],
      blocked: [],
      missingTools: [],
    },
    hostCapabilities: {
      networkSandbox: false,
      signing: false,
      browser: false,
    },
    cleanClaimPossible: false,
    gaps: [
      { kind: 'doctor-depth', detail: 'PR09 deepens this report with Cortex freshness, tool presence, and capability receipts' },
    ],
    commands: [],
  };
  stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  return { exitCode: EXIT.PASS };
}
