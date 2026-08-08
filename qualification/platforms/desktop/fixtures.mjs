export function createDesktopQualificationFixtures({ targetId } = {}) {
  const supported = ['electron', 'tauri', 'apple', 'dotnet', 'qt-native', 'flutter'];
  return [
    ...supported.map((id) => ({ id, targetId, family: 'desktop', status: 'unproven', terminal: true, claimLevel: 'runtime', coverageGaps: [`${id}-artifact-unprovided`] })),
    { id: 'clean-machine', targetId, family: 'desktop', status: 'unproven', terminal: true, claimLevel: 'release', coverageGaps: ['clean-machine-host-unavailable'] },
    { id: 'fault', targetId, family: 'desktop', status: 'unproven', terminal: true, claimLevel: 'runtime', coverageGaps: ['fault-target-unprovided'] },
    { id: 'upgrade', targetId, family: 'desktop', status: 'unproven', terminal: true, claimLevel: 'release', coverageGaps: ['upgrade-package-unprovided'] },
    { id: 'negative-control', targetId, family: 'desktop', status: 'unproven', terminal: true, claimLevel: 'runtime', coverageGaps: ['negative-control-artifact-unprovided'] },
  ];
}
