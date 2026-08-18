// Secrets provider (gitleaks current-tree and history modes) with tracked/
// untracked denominator receipts and mandatory secret redaction. No secret
// value is ever persisted in normalized output.

const REDACTED = '[REDACTED]';

export function redact(value) {
  if (value == null) return value;
  return REDACTED;
}

export function gitleaksCommand({ resolvedGitleaks, repositoryRoot, mode = 'current', policy, reportPath }) {
  const args = mode === 'history'
    ? ['git', repositoryRoot, '--log-opts=--full-history --all', '--report-format', 'json', '--report-path', reportPath, '--no-banner']
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
    kind: 'legion-secret-finding',
    provider,
    providerVersion,
    ruleId: finding.RuleID ?? finding.ruleId ?? 'secret.unknown',
    file: finding.File ?? finding.file ?? null,
    line: Number(finding.StartLine ?? finding.line ?? 1),
    endLine: Number(finding.EndLine ?? finding.endLine ?? null),
    secretType: finding.RuleID ?? finding.ruleId ?? null,
    secretDigest: /^sha256:[a-f0-9]{64}$/.test(finding.SecretDigest??finding.secretDigest??'')?(finding.SecretDigest??finding.secretDigest):null,
    // The raw secret value is redacted; only a digest may be retained.
    match: finding.Match ? redact(finding.Match) : null,
    commit: finding.Commit ?? finding.commit ?? null,
    mode,
    validity: finding.Validity ?? finding.validity ?? 'unproven',
    classification: finding.Classification ?? finding.classification ?? 'unproven',
    evidenceRefs: [],
  };
}

export function denominatorReceipt({ mode, trackedFiles, untrackedFiles, ignoredFiles, generatedFiles, releaseArtifacts, historyRefs }) {
  return {
    schemaVersion: 1,
    kind: 'legion-secret-denominator',
    mode,
    trackedFiles: trackedFiles ?? 0,
    untrackedFiles: untrackedFiles ?? 0,
    ignoredFiles: ignoredFiles ?? 0,
    generatedFiles: generatedFiles ?? 0,
    releaseArtifacts: releaseArtifacts ?? 0,
    historyRefs: historyRefs ?? 0,
  };
}
export function analyze({artifacts}={}){const evidence=artifacts?.secretEvidence??null;if(!evidence)return{status:'unproven',complete:false,denominator:{kind:'secret-scope',expected:0,examined:0},findings:[],coverageGaps:[{kind:'secret-evidence-missing'}]};const receipt=denominatorReceipt(evidence.denominator??{});const findings=(evidence.findings??[]).map((finding)=>normalizeFinding(finding,{mode:receipt.mode}));const expected=receipt.trackedFiles+receipt.untrackedFiles+receipt.ignoredFiles+receipt.generatedFiles+receipt.releaseArtifacts+receipt.historyRefs;const examined=evidence.examined??0;const gaps=[];if(!evidence.tool?.version||!/^sha256:[a-f0-9]{64}$/.test(evidence.rulesetDigest??''))gaps.push({kind:'secret-tool-or-ruleset-unbound'});if(expected===0)gaps.push({kind:'secret-denominator-zero'});if(examined!==expected)gaps.push({kind:'secret-denominator-mismatch',expected,examined});return{status:gaps.length?'unproven':findings.length?'fail':'pass',complete:gaps.length===0,denominator:{kind:'secret-scope',expected,examined},findings,coverageGaps:gaps};}
