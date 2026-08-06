// Privacy controls per PR41. Default telemetry is OFF; opt-in aggregate
// diagnostics with a data dictionary; export/delete commands; every integration
// documents exactly what leaves the machine.

export const TELEMETRY_DEFAULT = 'off';

export function privacyReceipt({ telemetry, integrations, egress }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-privacy-receipt',
    telemetry: telemetry ?? TELEMETRY_DEFAULT,
    integrations: [...(integrations ?? [])].sort(),
    egress: (egress ?? []).map((entry) => ({
      integration: entry.integration,
      leavesMachine: entry.leavesMachine ?? [],
      dataDictionary: entry.dataDictionary ?? 'See the integration documentation.',
    })),
    exportCommand: 'nemesis privacy export',
    deleteCommand: 'nemesis privacy delete',
  };
}

export function privacyDataDictionary() {
  return {
    telemetry: { default: TELEMETRY_DEFAULT, content: ['provider ids', 'duration', 'outcome'] },
    githubAction: { leavesMachine: ['SARIF report', 'audit summary'], content: ['finding ids', 'severities', 'rule ids'] },
    mcp: { leavesMachine: ['none by default'], content: [] },
  };
}
