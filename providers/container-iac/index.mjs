// Container/IaC provider (Trivy/Grype/tfsec-style facts). Optional adapters
// record exact tool/rules database identity and offline state; they never
// auto-install and never update advisory databases during an offline audit.

export function trivyCommand({ resolvedTrivy, repositoryRoot, policy, outputPath, scoped = 'fs' }) {
  return {
    executable: resolvedTrivy,
    args: [scoped, '--format', 'json', '--output', outputPath, repositoryRoot],
    cwd: repositoryRoot,
    timeoutMs: policy?.providerTimeoutMs ?? 120000,
    maxOutputBytes: policy?.maxOutputBytes ?? 8388608,
    environmentKeys: ['PATH', 'HOME', 'USERPROFILE', 'TEMP', 'TMP', 'TRIVY_OFFLINE_DB'],
  };
}

export function normalizeIaCFinding(finding, { provider = 'container-iac.trivy', providerVersion = '0.50.0' } = {}) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-iac-finding',
    provider,
    providerVersion,
    ruleId: finding.rule_id ?? finding.ID ?? finding.id ?? null,
    severity: finding.severity ?? finding.Severity ?? null,
    target: finding.target ?? finding.Target ?? null,
    resource: finding.resource ?? finding.Misconfiguration?.resource ?? null,
    message: finding.message ?? finding.Description ?? null,
    toolDb: finding.db ?? null,
    evidenceRefs: [],
  };
}

export function offlineState({ offline, databaseDigest, databaseVersion }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-iac-offline-state',
    offline,
    databaseDigest: databaseDigest ?? null,
    databaseVersion: databaseVersion ?? null,
  };
}
