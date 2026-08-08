export const PROVIDER_STATUS = Object.freeze(['pass', 'fail', 'partial', 'unproven', 'skipped', 'error', 'pending', 'missing', 'candidates', 'blocked']);
export const PROVIDER_ROLE = Object.freeze(['deterministic', 'candidate-generator', 'adjudicator', 'variant-analysis', 'renderer']);
export const EVIDENCE_CLASS = Object.freeze(['deterministic', 'measured', 'interpretive', 'external', 'human']);
export const JUDGMENT_VERDICT = Object.freeze(['confirmed', 'rejected', 'unproven', 'needs-human']);
export function assertEnum(label, values, value) { if (!values.includes(value)) throw new TypeError(`unknown ${label}: ${value}`); return value; }
export function assertSchemaVersion(label, version, supported = [1]) { if (!supported.includes(version)) throw new TypeError(`${label} unsupported schema version: ${version}`); return version; }
