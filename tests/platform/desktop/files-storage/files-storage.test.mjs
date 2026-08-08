import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateDesktopStorage, executeDesktopStorage, FILE_CASES } from '../../../../providers/runtime/desktop/files/index.mjs';

test('B4-019 requires hostile/recovery file evidence & source-preserving migrations', () => {
  const result = evaluateDesktopStorage({
    cases: FILE_CASES.map((id) => ({ id, kind: 'required', terminal: true, status: 'pass' })),
    migrations: [{ id: 'v1-v2', terminal: true, status: 'fail', sourcePreserved: true }],
    locations: { data: 'AppData/Roaming/app', cache: 'AppData/Local/app/cache', logs: 'AppData/Local/app/logs', temp: 'Temp/app' },
    evidence: { source: 'native-host', terminal: true },
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.denominator.accounted, FILE_CASES.length + 1);
});

test('B4-019 rejects empty denominators & executes required cases through host', async () => {
  assert.notEqual(evaluateDesktopStorage({}).status, 'pass');
  const host = { run: async ({ id, kind }) => ({ id, kind, terminal: true, status: 'pass', ...(kind === 'migration' ? { sourcePreserved: true } : {}) }), locations: async () => ({ data: 'd', cache: 'c', logs: 'l', temp: 't' }), receipt: async () => ({ source: 'native-host', terminal: true }) };
  const result = await executeDesktopStorage({ host, migrationIds: ['v1-v2'] });
  assert.equal(result.status, 'pass');
});

test('B4-019 blocks migration failure that cannot prove source preservation', () => {
  const result = evaluateDesktopStorage({ migrations: [{ id: 'legacy', terminal: true, status: 'fail', sourcePreserved: false }] });
  assert.equal(result.status, 'fail');
  assert.ok(result.coverageGaps.includes('migration-source-not-preserved:legacy'));
});
