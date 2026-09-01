import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildSurfaceRecord,
  checkPathBinaries,
} from '../scripts/verify-plugin-parity.mjs';

test('repository parity is structural while installed activation remains fail-closed', () => {
  const missing = checkPathBinaries(undefined, { env: { PATH: '', PATHEXT: '.EXE' } });
  assert.ok(missing.problems.some((problem) => problem.includes("plugin binary 'legion'")));
  assert.ok(missing.problems.some((problem) => problem.includes("plugin binary 'legion-hook'")));

  const structural = buildSurfaceRecord(undefined, { checkInstalledBinaries: false });
  assert.deepEqual(structural.problems, []);
});
