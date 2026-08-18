import assert from 'node:assert/strict';
import test from 'node:test';
import { runGenericSourceAccounting } from '../src/providers/generic-source-suite.mjs';

test('known parsed languages are fully accounted for', () => {
  const result = runGenericSourceAccounting({
    files: ['src/app.ts', 'src/lib.rs', 'src/service.py'],
    parsedExtensions: ['ts', 'rs', 'py'],
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.complete, true);
  assert.deepEqual(result.coverageGaps, []);
});

test('unknown parsed language remains UNPROVEN with a file denominator', () => {
  const result = runGenericSourceAccounting({
    files: ['src/app.ts', 'src/module.xyz', 'src/other.xyz'],
    parsedExtensions: ['ts', 'xyz'],
  });
  assert.equal(result.status, 'unproven');
  assert.equal(result.complete, false);
  assert.equal(result.coverageGaps.length, 1);
  assert.equal(result.coverageGaps[0].extension, 'xyz');
  assert.equal(result.coverageGaps[0].pathCount, 2);
});
