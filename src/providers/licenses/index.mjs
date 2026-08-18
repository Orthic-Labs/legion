// License policy provider. Normalizes detected/declared/unknown SPDX license
// evidence with transitive paths; every dependency has one of the three states.

export function normalizeLicense({ name, version, detected, declared, path }) {
  return {
    schemaVersion: 1,
    kind: 'legion-license-record',
    package: { name, version },
    detected: detected ?? null,
    declared: declared ?? null,
    status: detected ?? declared ? 'known' : 'unknown',
    path: path ?? null,
  };
}

export function policyResult({ records, policy }) {
  const unknown = records.filter((record) => record.status === 'unknown');
  const blocked = records.filter((record) =>
    (policy?.allow ?? []).length && !policy.allow.includes(record.detected ?? record.declared));
  return {
    schemaVersion: 1,
    kind: 'legion-license-policy-result',
    total: records.length,
    known: records.length - unknown.length,
    unknown,
    blocked,
    complete: unknown.length === 0 && blocked.length === 0,
  };
}
