import { parseArgs } from 'node:util';
import { EXIT } from '../../errors.mjs';
import { loadProviderRegistry } from '../../../registry/provider-registry.mjs';

// Renders the provider registry's coverage families as the language surface.
// PR17 replaces this with the generated coverage registry v2; until then the
// coverage families are the source of truth.

export function runLanguages(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, options: { json: { type: 'boolean' } }, strict: true });
  const registry = loadProviderRegistry();
  const languages = (registry.coverageFamilies ?? [])
    .map((family) => ({
      id: family.id,
      kind: family.kind ?? 'family',
      qualification: family.qualification ?? 'unproven',
      providers: [...(family.providers ?? [])].sort(),
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
  if (parsed.values.json) {
    stdout.write(`${JSON.stringify({ schemaVersion: 1, kind: 'legion-languages', languages }, null, 2)}\n`);
  } else {
    for (const language of languages) {
      stdout.write(`${language.id}\t${language.qualification}\n`);
    }
  }
  return { exitCode: EXIT.PASS };
}
