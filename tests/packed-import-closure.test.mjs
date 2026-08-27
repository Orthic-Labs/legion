import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkPackedImportClosure, findMissingPackedRelativeImports, relativeEsmSpecifiers } from '../scripts/check-packed-import-closure.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('relative ESM parser covers import, export, & dynamic import forms', () => {
  const source = [
    "import './side-effect.mjs';",
    "import { value } from '../shared/value.mjs';",
    "export { value } from './re-export.mjs';",
    "await import('./dynamic.mjs');",
  ].join('\n');
  assert.deepEqual(relativeEsmSpecifiers(source), ['./side-effect.mjs', '../shared/value.mjs', './re-export.mjs', './dynamic.mjs']);
});

test('relative ESM closure identifies an unshipped target', () => {
  const missing = findMissingPackedRelativeImports({
    packedFiles: ['src/adapters/blueprint-packet.mjs'],
    sources: { 'src/adapters/blueprint-packet.mjs': "import { consume } from '../packages/context/lib/context.mjs';" },
  });
  assert.deepEqual(missing, [{
    from: 'src/adapters/blueprint-packet.mjs',
    specifier: '../packages/context/lib/context.mjs',
    target: 'src/packages/context/lib/context.mjs',
  }]);
});

test('actual npm pack dry-run retains every static relative ESM target', () => {
  const result = checkPackedImportClosure(root);
  assert.equal(result.status, 'pass', result.message);
});
