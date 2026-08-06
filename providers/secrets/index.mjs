// Secrets provider (gitleaks current-tree and history modes) with tracked/
// untracked denominator receipts and mandatory secret redaction. No secret
// value is ever persisted in normalized output.

const REDACTED = '[REDACTED]';

export function redact(value) {
  if (value == null) return value;
  return String(value).replace(/[A-Za-z0-9_-]{16,}/g, REDACTED);
}

export function gitleaksCommand({ resolvedGitleaks, repositoryRoot, mode = 'current', policy, reportPath }) {
  const args = mode === 'history'
    ? ['git', 'log', '-p', '--full-history', '--all']
    : ['detect', '--source', repositoryRoot, '--report-format', 'json', '--report-path', reportPath, '--no-banner'];
  return {
    executable: resolvedGitleaks,
    args,
    cwd: repositoryRoot,
    timeoutMs: policy?.providerTimeoutMs ?? 120000,
    maxOutputBytes: policy?.maxOutputBytes ?? 8388608,
    environmentKeys: ['PATH', 'HOME', 'USERPROFILE', 'TEMP', 'TMP'],
  };
}

export function normalizeFinding(finding, { provider = 'secrets.gitleaks', providerVersion = '8.18.0', mode = 'current' } = {}) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-secret-finding',
    provider,
    providerVersion,
    ruleId: finding.RuleID ?? finding.ruleId ?? 'secret.unknown',
    file: finding.File ?? finding.file ?? null,
    line: Number(finding.StartLine ?? finding.line ?? 1),
    endLine: Number(finding.EndLine ?? finding.endLine ?? null),
    secretType: finding.RuleID ?? finding.ruleId ?? null,
    secretDigest: finding.SecretDigest ?? finding.secretDigest ?? null,
    // The raw secret value is redacted; only a digest may be retained.
    match: finding.Match ? redact(finding.Match) : null,
    commit: finding.Commit ?? finding.commit ?? null,
    mode,
    evidenceRefs: [],
  };
}

export function denominatorReceipt({ mode, trackedFiles, untrackedFiles, historyRefs }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-secret-denominator',
    mode,
    trackedFiles: trackedFiles ?? 0,
    untrackedFiles: untrackedFiles ?? 0,
    historyRefs: historyRefs ?? 0,
  };
}
