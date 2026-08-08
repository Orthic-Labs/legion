export function createServiceQualificationFixtures() {
  return [
    { id: 'clean', expected: 'pass' }, { id: 'defect', expected: 'fail' }, { id: 'partial', expected: 'partial' },
    { id: 'stale-environment', expected: 'unproven' }, { id: 'unsupported-runtime', expected: 'blocked' },
  ];
}
