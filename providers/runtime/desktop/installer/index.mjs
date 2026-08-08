const DIGEST = /^sha256:[a-f0-9]{64}$/;
export const INSTALLER_CASES = Object.freeze(['install', 'repair', 'upgrade', 'downgrade', 'rollback', 'uninstall', 'reinstall', 'interrupted-install', 'offline-uninstall', 'locked-files', 'modes', 'snapshots', 'logs', 'changes', 'cleanup']);
const NEGATIVE_CASES = new Set(['interrupted-install', 'offline-uninstall', 'locked-files']);
const SIGNATURE_RECEIPT_REQUIRED = true;

export function evaluateInstallerLifecycle({ package: pkg = {}, capability = {}, scenarios = [], destructiveTarget = null } = {}) {
  if (destructiveTarget !== null && destructiveTarget !== undefined) {
    const normalized = String(destructiveTarget).replaceAll('\\', '/').toLowerCase();
    if (!/(^|\/)temp(\/|$)/.test(normalized)) throw new Error('destructive installer scenarios require an isolated temp target');
  }
  const gaps = [];
  if (!DIGEST.test(pkg.digest ?? '') || pkg.production !== true) gaps.push('production-package-unproven');
  if (SIGNATURE_RECEIPT_REQUIRED && (pkg.signatureReceipt?.status !== 'pass' || pkg.signatureReceipt?.artifactDigest !== pkg.digest)) gaps.push('signature-receipt-unproven');
  if (capability.status !== 'available') gaps.push(`installer-capability-${capability.reason ?? capability.status ?? 'missing'}`);
  for (const scenario of scenarios) {
    if (scenario.terminal !== true) gaps.push(`scenario-nonterminal:${scenario.id ?? 'unknown'}`);
    if (scenario.id === 'rollback' && scenario.newerDataPreserved !== true) gaps.push('rollback-newer-data-unsafe');
    if (NEGATIVE_CASES.has(scenario.id) && scenario.status !== 'fail') gaps.push(`negative-case-not-failed:${scenario.id}`);
    if (scenario.id === 'modes' && !scenario.modes?.length) gaps.push('modes-not-documented');
    if (scenario.id === 'snapshots' && !scenario.snapshotCount) gaps.push('snapshots-not-documented');
    if (scenario.id === 'logs' && !scenario.logFile) gaps.push('logs-not-documented');
    if (scenario.id === 'changes' && !scenario.changes?.length) gaps.push('changes-not-documented');
    if (scenario.id === 'cleanup' && scenario.artifactsRemaining) gaps.push('cleanup-not-complete');
  }
  for (const id of INSTALLER_CASES) if (!scenarios.some((item) => item.id === id && item.terminal === true)) gaps.push(`lifecycle-case-missing:${id}`);
  const unsafe = gaps.includes('rollback-newer-data-unsafe');
  return { schemaVersion: 1, kind: 'nemesis-desktop-installer-lifecycle', status: unsafe ? 'fail' : gaps.length ? 'partial' : 'pass', terminal: true,
    package: pkg, capability, scenarios, releaseClaim: !gaps.length,
    denominator: { total: INSTALLER_CASES.length, required: INSTALLER_CASES.length, accounted: scenarios.filter((s) => s.terminal === true).length, negativeCases: scenarios.filter((s) => NEGATIVE_CASES.has(s.id) && s.status === 'fail').length },
    coverageGaps: gaps.sort() };
}

export async function executeInstallerLifecycle({ host, package: pkg, capability, destructiveTarget } = {}) {
  if (!host?.run) return evaluateInstallerLifecycle({ package: pkg, capability, destructiveTarget });
  const scenarios = [];
  for (const id of INSTALLER_CASES) scenarios.push(await host.run({ id, package: pkg, destructiveTarget, isolated: true }));
  return evaluateInstallerLifecycle({ package: pkg, capability, scenarios, destructiveTarget });
}
