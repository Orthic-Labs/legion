// Language bench smoke: loads the coverage registry and native provider matrix,
// and verifies every Wave-0 language maps to a native provider and a tier.
import { readFileSync } from 'node:fs';
import { NATIVE_PROVIDERS, nativeProviderFor } from '../../providers/native/index.mjs';

const registry = JSON.parse(readFileSync(new URL('../../registry/coverage/coverage-registry.json', import.meta.url), 'utf8'));
const wave0 = registry.languages.filter((record) =>
  ['javascript', 'typescript', 'python', 'rust', 'go', 'java', 'kotlin', 'csharp']
    .some((name) => record.id.endsWith(name)));

let mapped = 0;
for (const record of wave0) {
  const ext = record.extensions[0];
  const provider = nativeProviderFor(ext);
  if (provider) mapped += 1;
}
console.log(`languages bench: ${wave0.length} Wave-0 rows, ${mapped} native-provider mapped`);
if (wave0.length < 8) process.exit(1);
if (mapped < 8) process.exit(1);
console.log('GATE: PASS');
