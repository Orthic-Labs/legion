const TIERS = new Set(['simulator', 'emulator', 'physical', 'device-farm', 'imported']);

export function planMobileHosts({ target = {}, devices = [], requirements = [], checkedAt = null } = {}) {
  const normalizedDevices = devices.filter((item) => item && TIERS.has(item.tier)).map((item) => ({
    id: item.id, tier: item.tier, platform: item.platform ?? null, osVersion: item.osVersion ?? null,
    model: item.model ?? null, architecture: item.architecture ?? null, formFactor: item.formFactor ?? null,
    display: item.display ?? null, cutout: item.cutout ?? null, foldState: item.foldState ?? null,
    locale: item.locale ?? null, accessibility: item.accessibility ?? {},
    hardware: item.hardware ?? {}, power: item.power ?? null, thermal: item.thermal ?? null,
    buildTrack: item.buildTrack ?? null, status: item.status ?? 'unavailable',
    exclusiveKey: item.exclusiveKey ?? null, receipt: item.receipt ?? null,
  }));
  const planned = requirements.map((requirement) => {
    const evidenceTier = TIERS.has(requirement.tier) ? requirement.tier : 'physical';
    const device = normalizedDevices.find((item) => item.tier === evidenceTier && item.status === 'available');
    return { id: requirement.id, evidenceTier, controlIds: requirement.controlIds ?? [], deviceId: device?.id ?? null,
      status: device ? 'available' : 'unavailable', gap: device ? null : `${evidenceTier}-device-unavailable`,
      binding: { targetId: target.id ?? null, artifactDigest: target.artifactDigest ?? null, bundleId: target.bundleId ?? null,
        packageId: target.packageId ?? null, backendEnvironment: target.backendEnvironment ?? null, testAccountId: target.testAccountId ?? null,
        deviceId: device?.id ?? null, deviceStateDigest: device?.deviceStateDigest ?? null },
      cleanup: device ? ['uninstall', 'reset-device-state', 'release-exclusive-key'] : [] };
  });
  const gaps = planned.filter((item) => item.status !== 'available');
  return { schemaVersion: 1, kind: 'legion-mobile-host-plan', status: gaps.length ? 'partial' : 'pass', claimLevel: 'runtime', checkedAt,
    target, devices: normalizedDevices, requirements: planned,
    exclusiveDeviceKeys: [...new Set(normalizedDevices.filter((item) => item.status === 'available').map((item) => item.exclusiveKey).filter(Boolean))].sort(),
    denominator: { total: planned.length, accounted: planned.length, available: planned.length - gaps.length, gaps: gaps.length },
    coverageGaps: gaps.map((item) => `${item.id}:${item.gap}`).sort() };
}
