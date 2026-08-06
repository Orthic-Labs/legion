import assert from 'node:assert/strict';
import test from 'node:test';
import cPack, { unsafeMemoryPatterns } from '../../../providers/native/c-family/index.mjs';
import { cmakeCommand, cmakePresetReceipt } from '../../../providers/build/cmake/index.mjs';

const projection = (files = []) => ({ files, parsedExtensions: files.map((f) => f.split('.').pop()), auditFacts: {} });

test('c-family pack detects C/C++ projects', () => {
  assert.equal(cPack.detect({ projection: projection(['main.c', 'CMakeLists.txt']) }), true);
  assert.equal(cPack.detect({ projection: projection(['a.py']) }), false);
});

test('c-family pack uses compile_commands when present', () => {
  const commands = cPack.commands({ root: '/repo', files: ['a.c'], manifests: ['compile_commands.json'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'c-family.syntax'));
});

test('c-family pack falls back to cmake build', () => {
  const commands = cPack.commands({ root: '/repo', files: ['a.c'], manifests: ['CMakeLists.txt'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'c-family.cmake'));
});

test('c-family pack emits optional linters only outside fast profile', () => {
  const full = cPack.commands({ root: '/repo', files: ['a.c'], manifests: ['compile_commands.json'], profile: 'standard' });
  assert.ok(full.some((c) => c.id === 'c-family.tidy'));
  assert.ok(full.some((c) => c.id === 'c-family.cppcheck'));
  const fast = cPack.commands({ root: '/repo', files: ['a.c'], manifests: ['compile_commands.json'], profile: 'fast' });
  assert.ok(!fast.some((c) => c.id === 'c-family.tidy'));
});

test('unsafe libc functions are flagged', () => {
  const observations = unsafeMemoryPatterns(['a.c'], () => 'strcpy(dst, src);\ngets(buf);');
  assert.ok(observations.some((o) => o.ruleId === 'c-family.unsafe-libc'));
});

test('safe bounded functions are not flagged', () => {
  const observations = unsafeMemoryPatterns(['a.c'], () => 'strncpy(dst, src, n);\nfgets(buf, sizeof buf, f);');
  assert.ok(!observations.some((o) => o.ruleId === 'c-family.unsafe-libc'));
});

test('cmake preset receipt records configuration', () => {
  const receipt = cmakePresetReceipt({ root: '/repo', presetPresent: true, presetName: 'dev', buildDir: 'build/dev' });
  assert.equal(receipt.presetName, 'dev');
  assert.equal(cmakePresetReceipt({ root: '/repo' }).presetPresent, false);
});

test('cmake command prefers presets', () => {
  const contract = cmakeCommand({ root: '/repo', preset: 'dev' });
  assert.deepEqual(contract.args, ['--preset', 'dev']);
});

test('cmake command falls back to -S/-B', () => {
  const contract = cmakeCommand({ root: '/repo', buildDir: 'build' });
  assert.deepEqual(contract.args, ['-S', '/repo', '-B', 'build']);
});
