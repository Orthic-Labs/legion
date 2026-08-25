import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze } from '../src/providers/ast-grep/index.mjs';

test('ast-grep cannot pass when frozen paths were not examined', () => {
  const result = analyze({
    projection: { files: ['a.ts', 'b.ts'] },
    artifacts: { astGrepTool: { version: '1' }, examinedPaths: [] },
  });
  assert.equal(result.status, 'unproven');
  assert.equal(result.complete, false);
  assert.equal(result.denominator.examined, 0);
  assert.deepEqual(result.denominator.unexamined, ['a.ts', 'b.ts']);
  assert.ok(result.coverageGaps.some(({ kind }) => kind === 'structural-denominator-incomplete'));
});

test('ast-grep passes only after every frozen path is examined', () => {
  const result = analyze({
    projection: { files: ['a.ts', 'b.ts'] },
    artifacts: { astGrepTool: { version: '1' }, examinedPaths: ['b.ts', 'a.ts'] },
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.complete, true);
  assert.deepEqual(result.denominator.unexamined, []);
});
