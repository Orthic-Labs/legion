import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateInstallerLifecycle, INSTALLER_CASES } from '../../../../providers/runtime/desktop/installer/index.mjs';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const pkg = { digest: DIGEST, signed: true, production: true, signatureReceipt: { status: 'pass', artifactDigest: DIGEST } };
const capability = { status: 'available' };

const scenario = (id, overrides = {}) => ({ id, status: 'pass', terminal: true, ...overrides });
const NEGATIVE = new Set(['interrupted-install', 'offline-uninstall', 'locked-files']);

test('B4-022 records clean-machine capability gap without simulating installer success', () => {
  const result = evaluateInstallerLifecycle({
    package: pkg, capability: { status: 'unavailable', reason: 'clean-vm-unavailable' }, scenarios: [],
  });
  assert.equal(result.status, 'partial');
  assert.ok(result.coverageGaps.includes('installer-capability-clean-vm-unavailable'));
  assert.equal(result.releaseClaim, false);
});

test('B4-022 fails unsafe rollback & rejects non-isolated destructive targets', () => {
  const unsafe = evaluateInstallerLifecycle({
    package: pkg, capability,
    scenarios: [
      scenario('install'), scenario('repair'), scenario('upgrade'), scenario('downgrade'),
      scenario('rollback', { newerDataPreserved: false }),
      scenario('uninstall'), scenario('reinstall'),
      scenario('interrupted-install', { status: 'fail' }),
      scenario('offline-uninstall', { status: 'fail' }),
      scenario('locked-files', { status: 'fail' }),
      scenario('modes', { modes: ['per-user', 'machine-wide'] }),
      scenario('snapshots', { snapshotCount: 3 }),
      scenario('logs', { logFile: '/tmp/install.log' }),
      scenario('changes', { changes: [{ from: '1.0', to: '2.0' }] }),
      scenario('cleanup', { artifactsRemaining: false }),
    ],
  });
  assert.equal(unsafe.status, 'fail');
  assert.throws(() => evaluateInstallerLifecycle({ destructiveTarget: 'D:/Claude' }), /isolated temp target/);
});

test('B4-022 cannot pass zero lifecycle scenarios or caller-only signing booleans', () => {
  const result = evaluateInstallerLifecycle({
    package: { digest: DIGEST, signed: true, production: true },
    capability, scenarios: [],
  });
  assert.notEqual(result.status, 'pass');
  assert.ok(result.coverageGaps.includes('signature-receipt-unproven'));
});

test('B4-022 rejects incomplete package with missing signature receipt', () => {
  const result = evaluateInstallerLifecycle({
    package: { digest: DIGEST, production: true },
    capability, scenarios: [],
  });
  assert.ok(result.coverageGaps.includes('signature-receipt-unproven'));
});

test('B4-022 requires negative cases to actually fail', () => {
  const result = evaluateInstallerLifecycle({
    package: pkg, capability,
    scenarios: [
      scenario('install'), scenario('repair'), scenario('upgrade'), scenario('downgrade'),
      scenario('rollback', { newerDataPreserved: true }),
      scenario('uninstall'), scenario('reinstall'),
      scenario('interrupted-install', { status: 'pass' }),
      scenario('offline-uninstall', { status: 'pass' }),
      scenario('locked-files', { status: 'pass' }),
      scenario('modes', { modes: ['per-user'] }),
      scenario('snapshots', { snapshotCount: 1 }),
      scenario('logs', { logFile: '/tmp/install.log' }),
      scenario('changes', { changes: [{ from: '1.0', to: '2.0' }] }),
      scenario('cleanup', { artifactsRemaining: false }),
    ],
  });
  assert.ok(result.coverageGaps.includes('negative-case-not-failed:interrupted-install'));
  assert.ok(result.coverageGaps.includes('negative-case-not-failed:offline-uninstall'));
  assert.ok(result.coverageGaps.includes('negative-case-not-failed:locked-files'));
});

test('B4-022 denominator reports accounted lifecycle cases and negative failures', () => {
  const result = evaluateInstallerLifecycle({
    package: pkg, capability,
    scenarios: [
      scenario('install'), scenario('repair'), scenario('upgrade'), scenario('downgrade'),
      scenario('rollback', { newerDataPreserved: true }),
      scenario('uninstall'), scenario('reinstall'),
      scenario('interrupted-install', { status: 'fail' }),
      scenario('offline-uninstall', { status: 'fail' }),
      scenario('locked-files', { status: 'fail' }),
      scenario('modes', { modes: ['per-user', 'machine-wide'] }),
      scenario('snapshots', { snapshotCount: 3 }),
      scenario('logs', { logFile: '/tmp/install.log' }),
      scenario('changes', { changes: [{ from: '1.0', to: '2.0' }] }),
      scenario('cleanup', { artifactsRemaining: false }),
    ],
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.denominator.total, INSTALLER_CASES.length);
  assert.equal(result.denominator.negativeCases, 3);
  assert.equal(result.releaseClaim, true);
});

test('B4-022 requires all 15 installer lifecycle cases including modes/snapshots/logs/changes/cleanup', () => {
  assert.ok(INSTALLER_CASES.includes('modes'));
  assert.ok(INSTALLER_CASES.includes('snapshots'));
  assert.ok(INSTALLER_CASES.includes('logs'));
  assert.ok(INSTALLER_CASES.includes('changes'));
  assert.ok(INSTALLER_CASES.includes('cleanup'));
  assert.equal(INSTALLER_CASES.length, 15);
  const result = evaluateInstallerLifecycle({
    package: pkg, capability,
    scenarios: INSTALLER_CASES.filter((id) => id !== 'cleanup').map((id) =>
      NEGATIVE.has(id) ? scenario(id, { status: 'fail' }) : scenario(id)
    ),
  });
  assert.ok(result.coverageGaps.includes('lifecycle-case-missing:cleanup'));
});
