export function classifyVersion(value) { return value == null ? { kind: 'unknown', value: null } : /^[~^<>=*]/.test(value) ? { kind: 'declared-range', value } : { kind: 'resolved', value }; }
