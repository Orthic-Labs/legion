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
    kind: 'legion-iac-finding',
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
    kind: 'legion-iac-offline-state',
    offline,
    databaseDigest: databaseDigest ?? null,
    databaseVersion: databaseVersion ?? null,
  };
}
export function infrastructureDenominator({source=[],rendered=[]}){return{schemaVersion:1,source:[...source],rendered:[...rendered],gaps:rendered.length?[]:['rendered-resources-absent'],complete:source.length>0&&rendered.length>0};}
const validDigest=(value)=>/^sha256:[a-f0-9]{64}$/.test(value??'');
const sameBinding=(actual,expected)=>actual&&expected&&actual.repositoryRevision===expected.repositoryRevision&&actual.digest===expected.digest;
export function analyze({plan,projection,artifacts}={}){const source=(projection?.files??[]).map((file)=>file.path??file).filter((path)=>/(Dockerfile|\.ya?ml$|\.tf$|compose)/i.test(path));const rendered=artifacts?.renderedInfrastructure??[];const denominator=infrastructureDenominator({source,rendered});const evidence=artifacts?.iacEvidence;const gaps=denominator.gaps.map((kind)=>({kind}));if(!evidence||!sameBinding(evidence.binding,plan?.binding)||evidence.executionReceipt?.complete!==true||!validDigest(evidence.executionReceipt?.tool?.executableDigest)||!validDigest(evidence.databaseDigest)||evidence.examined!==source.length+rendered.length)gaps.push({kind:'iac-evidence-invalid'});return{status:gaps.length?'unproven':(evidence.findings??[]).length?'fail':'pass',complete:gaps.length===0,denominator:{kind:'infrastructure-resources',expected:source.length+rendered.length,examined:evidence?.examined??0},findings:evidence?.findings??[],coverageGaps:gaps};}
