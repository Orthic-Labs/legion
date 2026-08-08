export function createMobileQualificationFixtures() {
  return [
    { id: 'native-ios', platform: 'ios', controls: [{ id: 'lifecycle', requiredTier: 'simulator' }, { id: 'battery', requiredTier: 'physical' }], receipts: [{ controlId: 'lifecycle', tier: 'simulator', status: 'pass', terminal: true }] },
    { id: 'native-android', platform: 'android', controls: [{ id: 'lifecycle', requiredTier: 'emulator' }, { id: 'battery', requiredTier: 'physical' }], receipts: [] },
    { id: 'flutter', platform: 'cross-platform', controls: [], receipts: [] },
    { id: 'react-native', platform: 'cross-platform', controls: [], receipts: [] },
    { id: 'extension', platform: 'ios', controls: [], receipts: [] },
    { id: 'emulator-only', platform: 'android', controls: [{ id: 'battery', requiredTier: 'physical' }], receipts: [{ controlId: 'battery', tier: 'emulator', status: 'pass', terminal: true }] },
    { id: 'missing-store', platform: 'ios', controls: [{ id: 'store', requiredTier: 'external' }], receipts: [] },
    { id: 'lifecycle-fault', platform: 'android', controls: [{ id: 'process-death', requiredTier: 'physical' }], receipts: [] },
    { id: 'clean-control', platform: 'ios', controls: [], receipts: [] },
  ];
}
