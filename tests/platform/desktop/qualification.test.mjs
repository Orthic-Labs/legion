import assert from 'node:assert/strict';
import test from 'node:test';
import { integrateDesktopEvidence } from '../../../providers/runtime/desktop/index.mjs';
import { createDesktopQualificationFixtures } from '../../../qualification/platforms/desktop/fixtures.mjs';
import { qualifyDesktopPlatform } from '../../../qualification/platforms/desktop/qualification.mjs';

test('B4-025 reconciles control/scenario denominators without source-only release closure', () => {
  const result = integrateDesktopEvidence({
    targetId: 'app', controls: ['desktop-runtime', 'desktop-release'], scenarios: ['launch'],
    receipts: [{ controlId: 'desktop-runtime', scenarioId: 'launch', targetId: 'app', status: 'pass', terminal: true, claimLevel: 'runtime' }, { controlId: 'desktop-release', targetId: 'app', status: 'pass', terminal: true, claimLevel: 'source', sourceRegexOnly: true }],
    platformMatrices: [{ os: 'windows', status: 'pass' }, { os: 'macos', status: 'unsupported', reason: 'host-unavailable' }],
  });
  assert.equal(result.status, 'fail');
  assert.deepEqual(result.denominator.controls, { total: 2, accounted: 1, missing: ['desktop-release'] });
  assert.deepEqual(result.denominator.scenarios, { total: 1, accounted: 1, missing: [] });
  assert.ok(result.coverageGaps.includes('native-release-evidence-missing:desktop-release'));
  assert.equal(result.platformMatrices[1].status, 'unsupported');
});

test('B4-025 emits provisional fixture qualification with explicit host gaps', () => {
  const fixtures = createDesktopQualificationFixtures({ targetId: 'app' });
  const result = qualifyDesktopPlatform({ targetId: 'app', fixtures });
  assert.equal(fixtures.length, 10);
  assert.equal(result.provisional, true);
  assert.equal(result.status, 'partial');
  assert.ok(result.coverageGaps.some((gap) => gap.includes('clean-machine')));
});

test('B4-025 does not account nonterminal receipts or pass empty qualification', () => {
  const result = integrateDesktopEvidence({ targetId: 'app', controls: ['c'], scenarios: ['s'], receipts: [{ targetId: 'app', controlId: 'c', scenarioId: 's', status: 'pass', terminal: false }] });
  assert.equal(result.denominator.controls.accounted, 0);
  assert.equal(result.stopShip, true);
  assert.notEqual(qualifyDesktopPlatform({ targetId: 'app', fixtures: [] }).status, 'pass');
});

test('B4-025 joins every required desktop evidence family', () => {
  const kinds = [
    'legion-desktop-runtime', 'legion-desktop-ipc', 'legion-desktop-files-storage',
    'legion-desktop-os-matrix', 'legion-desktop-performance',
    'legion-desktop-installer-lifecycle', 'legion-desktop-updater', 'legion-desktop-windows',
  ];
  const receipts = kinds.map((kind, index) => ({ kind, targetId: 'app', controlId: `c${index}`, scenarioId: `s${index}`, claimLevel: 'runtime', status: 'pass', terminal: true }));
  const result = integrateDesktopEvidence({
    targetId: 'app', controls: receipts.map((item) => item.controlId), scenarios: receipts.map((item) => item.scenarioId), receipts,
    platformMatrices: [{ os: 'windows', status: 'pass' }, { os: 'macos', status: 'unsupported', reason: 'host-unavailable' }],
  });
  assert.equal(result.denominator.evidenceFamilies.accounted, result.denominator.evidenceFamilies.total);
  assert.ok(!result.coverageGaps.some((gap) => gap.startsWith('evidence-family-missing:')));
  assert.equal(result.platformMatrices[1].status, 'unsupported');
});
