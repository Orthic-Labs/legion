import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateWindowsPlatform, WINDOWS_CASES } from '../../../../providers/runtime/desktop/windows/index.mjs';
import { evaluateMacosPlatform } from '../../../../providers/runtime/desktop/macos/index.mjs';
import { evaluateLinuxPlatform } from '../../../../providers/runtime/desktop/linux/index.mjs';

const artifact = { digest: `sha256:${'a'.repeat(64)}`, final: true };

test('B4-024 preserves exact OS matrices & final-artifact facts', () => {
  const windows = evaluateWindowsPlatform({ matrix: { os: 'windows', version: '11', architecture: 'x64' }, artifact, checks: WINDOWS_CASES.map((id) => ({ id, status: 'pass', terminal: true, artifactDigest: artifact.digest, controlIds: ['desktop-signing'] })) });
  assert.equal(windows.status, 'pass');
  assert.equal(windows.matrix.os, 'windows');
  assert.deepEqual(windows.receipts.find(({ id }) => id === 'authenticode').controlIds, ['desktop-signing']);
});

test('B4-024 cannot transfer one OS pass to unavailable OS hosts', () => {
  const mac = evaluateMacosPlatform({ capability: { status: 'unavailable', reason: 'mac-host-unavailable' } });
  const linux = evaluateLinuxPlatform({ capability: { status: 'unavailable', reason: 'linux-host-unavailable' } });
  assert.equal(mac.status, 'unproven');
  assert.equal(linux.status, 'unproven');
  assert.notEqual(mac.matrix.os, linux.matrix.os);
});

test('B4-024 cannot pass empty named behavior denominators', () => {
  assert.notEqual(evaluateWindowsPlatform({ matrix: { os: 'windows', version: '11', architecture: 'x64' }, artifact, checks: [] }).status, 'pass');
});
import { compileDesktopOsMatrix } from '../../../../providers/runtime/desktop/os-integration/index.mjs';

test('B4-024 names complete Windows behavior denominators', () => {
  const allChecks = WINDOWS_CASES.map((id) => ({ id, status: 'pass', terminal: true, artifactDigest: artifact.digest }));
  const result = evaluateWindowsPlatform({ matrix: { os: 'windows', version: '11', architecture: 'x64' }, artifact, checks: allChecks });
  assert.equal(result.status, 'pass');
  assert.equal(result.receipts.length, WINDOWS_CASES.length);
  assert.deepEqual(result.receipts.map((r) => r.id).sort(), [...WINDOWS_CASES].sort());
  assert.equal(result.matrix.os, 'windows');
  assert.equal(result.matrix.version, '11');
  assert.equal(result.matrix.architecture, 'x64');
});

test('B4-024 names complete macOS behavior denominators', () => {
  const macosIds = ['hardened-runtime', 'notarization', 'gatekeeper', 'entitlements', 'app-sandbox', 'keychain', 'tcc', 'app-translocation', 'architectures', 'login-items-helpers', 'menus-windows', 'residual-data'];
  const allChecks = macosIds.map((id) => ({ id, status: 'pass', terminal: true, artifactDigest: artifact.digest }));
  const result = evaluateMacosPlatform({ matrix: { os: 'macos', version: '15', architecture: 'arm64' }, artifact, checks: allChecks, capability: { status: 'available' } });
  assert.equal(result.status, 'pass');
  assert.equal(result.receipts.length, 12);
  assert.equal(result.matrix.os, 'macos');
  assert.equal(result.matrix.version, '15');
  assert.equal(result.matrix.architecture, 'arm64');
});

test('B4-024 names complete Linux behavior denominators', () => {
  const linuxIds = ['xdg', 'x11-wayland', 'libraries', 'appimage', 'flatpak', 'snap', 'deb-rpm', 'desktop-entry', 'mime-protocol', 'polkit', 'sandbox', 'distribution-desktop'];
  const allChecks = linuxIds.map((id) => ({ id, status: 'pass', terminal: true }));
  const result = evaluateLinuxPlatform({ matrix: { os: 'linux', version: '24.04', architecture: 'x64' }, checks: allChecks, capability: { status: 'available' } });
  assert.equal(result.status, 'pass');
  assert.equal(result.receipts.length, 12);
  assert.equal(result.matrix.os, 'linux');
  assert.equal(result.matrix.version, '24.04');
  assert.equal(result.matrix.architecture, 'x64');
});

test('B4-024 macOS notarization and gatekeeper require final artifact', () => {
  const macosIds = ['hardened-runtime', 'notarization', 'gatekeeper', 'entitlements', 'app-sandbox', 'keychain', 'tcc', 'app-translocation', 'architectures', 'login-items-helpers', 'menus-windows', 'residual-data'];
  const checks = macosIds.map((id) => ({ id, status: 'pass', terminal: true, artifactDigest: ['notarization', 'gatekeeper'].includes(id) ? `sha256:${'b'.repeat(64)}` : artifact.digest }));
  const result = evaluateMacosPlatform({ matrix: { os: 'macos', version: '15', architecture: 'arm64' }, artifact, checks, capability: { status: 'available' } });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.some((g) => g.includes('macos-final-artifact-unproven:notarization')));
  assert.ok(result.coverageGaps.some((g) => g.includes('macos-final-artifact-unproven:gatekeeper')));
});

test('B4-024 Windows authenticode requires final artifact', () => {
  const checks = WINDOWS_CASES.map((id) => ({ id, status: 'pass', terminal: true, artifactDigest: ['authenticode', 'installer'].includes(id) ? `sha256:${'b'.repeat(64)}` : artifact.digest }));
  const result = evaluateWindowsPlatform({ matrix: { os: 'windows', version: '11', architecture: 'x64' }, artifact, checks });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.some((g) => g.includes('windows-final-artifact-unproven:authenticode')));
  assert.ok(result.coverageGaps.some((g) => g.includes('windows-final-artifact-unproven:installer')));
});

test('B4-024 one OS pass cannot support another OS evidence', () => {
  const windows = evaluateWindowsPlatform({ matrix: { os: 'windows', version: '11', architecture: 'x64' }, artifact, checks: WINDOWS_CASES.map((id) => ({ id, status: 'pass', terminal: true, artifactDigest: artifact.digest })) });
  assert.equal(windows.status, 'pass');
  assert.equal(windows.matrix.os, 'windows');
  assert.notEqual(windows.matrix.os, 'macos');
  assert.notEqual(windows.matrix.os, 'linux');
  const macResult = evaluateMacosPlatform({ matrix: { os: 'macos', version: '15', architecture: 'arm64' }, checks: [], capability: { status: 'unavailable', reason: 'no-mac-host' } });
  assert.equal(macResult.status, 'unproven');
  assert.equal(macResult.matrix.os, 'macos');
  assert.ok(macResult.coverageGaps.some((g) => g.includes('macos-capability-unavailable')));
});

test('B4-024 macOS capability unavailable produces typed gaps', () => {
  const result = evaluateMacosPlatform({ matrix: { os: 'macos', version: '15', architecture: 'arm64' }, capability: { status: 'unavailable', reason: 'vm-host-missing' } });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.some((g) => g.includes('macos-capability-unavailable')));
});

test('B4-024 Linux capability unavailable produces typed gaps', () => {
  const result = evaluateLinuxPlatform({ matrix: { os: 'linux', version: '24.04', architecture: 'x64' }, capability: { status: 'unavailable', reason: 'vm-host-missing' } });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.some((g) => g.includes('linux-capability-unavailable')));
});

test('B4-024 nonterminal checks produce gaps', () => {
  const checks = WINDOWS_CASES.map((id) => ({ id, status: 'pass', terminal: false, artifactDigest: artifact.digest }));
  const result = evaluateWindowsPlatform({ matrix: { os: 'windows', version: '11', architecture: 'x64' }, artifact, checks });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.some((g) => g.startsWith('windows-check-nonterminal:')));
});

test('B4-024 incomplete matrix produces gap without masking platform', () => {
  const result = evaluateWindowsPlatform({ matrix: {}, checks: WINDOWS_CASES.map((id) => ({ id, status: 'pass', terminal: true, artifactDigest: artifact.digest })), artifact });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.includes('windows-matrix-incomplete'));
  assert.equal(result.matrix.os, 'windows');
  assert.equal(result.matrix.version, null);
  assert.equal(result.matrix.architecture, null);
});

test('B4-024 OS-integration matrix allows unsupported with reason', () => {
  const result = compileDesktopOsMatrix({
    cases: [
      { id: 'single-instance', os: 'windows', version: '11', architecture: 'x64', state: {}, controlIds: ['desktop-native'], status: 'pass', terminal: true },
      { id: 'multi-window', os: 'macos', version: '15', architecture: 'arm64', state: {}, controlIds: ['desktop-native'], status: 'unsupported', reason: 'vm-unavailable', terminal: true },
    ],
  });
  const singleInstance = result.receipts.find((r) => r.id === 'single-instance');
  assert.equal(singleInstance.status, 'pass');
  const multiWindow = result.receipts.find((r) => r.id === 'multi-window');
  assert.equal(multiWindow.status, 'unsupported');
  assert.equal(multiWindow.reason, 'vm-unavailable');
});
