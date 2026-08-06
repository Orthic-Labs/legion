// OSV-Scanner v2 provider per SNIP-OSV-01. Distinguishes direct/transitive/
// reachable-unknown and preserves package/lockfile evidence. The vulnerability
// database is never updated during an offline audit.

export function osvCommand({ resolvedOsvScanner, outputPath, repositoryRoot, policy, offlineDb }) {
  return {
    executable: resolvedOsvScanner,
    args: ['scan', '--format', 'json', '--output', outputPath, repositoryRoot],
    cwd: repositoryRoot,
    timeoutMs: policy?.providerTimeoutMs ?? 120000,
    maxOutputBytes: policy?.maxOutputBytes ?? 8388608,
    environmentKeys: ['PATH', 'HOME', 'USERPROFILE', 'TEMP', 'TMP', 'OSV_SCANNER_OFFLINE_DB'],
    env: offlineDb ? { OSV_SCANNER_OFFLINE_DB: offlineDb } : {},
  };
}

export function normalizeVulnerability(vuln, { provider = 'osv.scanner', providerVersion = '2.0.0' }) {
  const source = vuln.related ?? vuln.aliases ?? [];
  return {
    schemaVersion: 1,
    kind: 'nemesis-osv-vulnerability',
    provider,
    providerVersion,
    id: vuln.id ?? vuln.ghsa_id ?? null,
    package: {
      name: vuln.package?.name ?? null,
      ecosystem: vuln.package?.ecosystem ?? null,
      version: vuln.package?.version ?? vuln.package?.purl ?? null,
      purl: vuln.package?.purl ?? null,
    },
    summary: vuln.summary ?? null,
    severity: vuln.severity ?? (vuln.database_specific?.severity ?? null),
    references: source.slice(0, 10),
    reachability: 'unknown', // never inferred from missing graph evidence
    evidenceRefs: [],
  };
}

export function normalizeScanResult(raw, { provider = 'osv.scanner', providerVersion = '2.0.0', offlineDb = null, dbDigest = null } = {}) {
  const results = raw?.results ?? [];
  const vulnerabilities = [];
  const examined = [];
  for (const result of results) {
    for (const source of result?.packages ?? []) {
      const packageId = source.package?.purl ?? source.package?.name ?? null;
      examined.push(packageId);
      for (const vuln of source.vulnerabilities ?? []) {
        vulnerabilities.push(normalizeVulnerability(vuln, { provider, providerVersion }));
      }
    }
  }
  return {
    schemaVersion: 1,
    kind: 'nemesis-osv-result',
    provider,
    providerVersion,
    offline: Boolean(offlineDb),
    databaseDigest: dbDigest ?? null,
    packageCount: examined.length,
    vulnerabilities,
    examined,
    complete: raw?.scan_complete ?? true,
    coverageGaps: raw?.scan_incomplete_reasons?.map((reason) => ({ kind: 'osv-incomplete', reason })) ?? [],
  };
}
