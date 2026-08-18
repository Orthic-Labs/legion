// OpenGrep SAST/taint provider. Pinned executable and ruleset identity,
// JSON/SARIF artifact preservation, source/sink trace normalization with
// capability level (pattern, intrafile, interfile/interprocedural where
// reported), and candidate-only output. Security observations become
// candidates; they never become final findings here.

import { createHash } from 'node:crypto';

export function candidateId({ provider, ruleId, file, line, traceDigest }) {
  const body = JSON.stringify({ provider, ruleId, file, line, traceDigest: traceDigest ?? null });
  return `sha256:${createHash('sha256').update(`opengrep-candidate\0${body}`).digest('hex')}`;
}

export function rulesetIdentity({ path, digest, license, source, version }) {
  return {
    schemaVersion: 1,
    kind: 'legion-opengrep-ruleset',
    path,
    digest: digest ?? null,
    license: license ?? null,
    source: source ?? null,
    version: version ?? null,
  };
}

export function normalizeFinding(finding, { provider = 'opengrep.sast', providerVersion = '1.0.0', ruleset = null } = {}) {
  const path = finding.path ?? finding.file ?? null;
  const line = Number(finding.start?.line ?? finding.line ?? 1);
  const trace = finding.dataflow_trace ?? finding.taint_sink ?? null;
  const capability = trace
    ? (trace.interfile_vars?.length || trace.interproc ? 'interfile' : 'intrafile')
    : 'pattern';
  return {
    schemaVersion: 1,
    kind: 'legion-opengrep-finding',
    provider,
    providerVersion,
    ruleset,
    ruleId: finding.check_id ?? finding.ruleId ?? 'opengrep.rule',
    severity: finding.extra?.severity ?? finding.severity ?? 'warning',
    message: finding.extra?.message ?? finding.message ?? finding.check_id,
    file: path,
    range: {
      start: { line, column: Number(finding.start?.col ?? finding.column ?? 0) },
      end: { line: Number(finding.end?.line ?? line), column: Number(finding.end?.col ?? finding.column ?? 0) },
    },
    capability,
    source: trace?.source
      ? { file: trace.source[0]?.[0] ?? null, line: Number(trace.source[0]?.[1] ?? null) }
      : null,
    sink: trace?.sink
      ? { file: trace.sink[0]?.[0] ?? null, line: Number(trace.sink[0]?.[1] ?? null) }
      : null,
    intermediateVars: trace?.intermediate_vars?.map(([file, line]) => ({ file, line: Number(line) })) ?? [],
    evidenceRefs: [],
  };
}

export function toCandidate(finding, { provider = 'opengrep.sast', providerVersion = '1.0.0', denominatorDigest }) {
  const traceDigest = finding.source || finding.sink
    ? `sha256:${createHash('sha256').update(JSON.stringify([finding.source, finding.sink, finding.intermediateVars])).digest('hex')}`
    : null;
  return {
    schemaVersion: 2,
    kind: 'security-candidate',
    id: candidateId({ provider, ruleId: finding.ruleId, file: finding.file, line: finding.range.start.line, traceDigest }),
    provider,
    providerVersion,
    ruleId: finding.ruleId,
    candidateClass: 'sast',
    claim: finding.message,
    severityHint: finding.severity === 'ERROR' || finding.severity === 'error' ? 'high' : 'medium',
    sources: finding.source ? [finding.source.file] : [],
    sinks: finding.sink ? [finding.sink.file] : [],
    attackerCapabilities: [],
    preconditions: [],
    effects: [],
    assets: [],
    trustBoundaryCrossings: [],
    requiredControls: [],
    observedControls: [],
    chainRoles: [],
    evidenceRefs: finding.evidenceRefs ?? [],
    detectorMetadata: {
      capability: finding.capability,
      source: finding.source,
      sink: finding.sink,
      intermediateVars: finding.intermediateVars,
    },
    uncertainty: ['A pattern match is never a vulnerability by itself; adjudication is required.'],
    binding: null,
    denominatorDigest,
    verdict: 'UNADJUDICATED',
    adjudicationRequired: true,
  };
}

export function commandContract({ resolvedOpenGrep, jsonPath, sarifPath, frozenRulesPath, frozenPaths, repositoryRoot, policy }) {
  return {
    executable: resolvedOpenGrep,
    args: [
      'scan',
      '--json-output', jsonPath,
      '--sarif-output', sarifPath,
      '--metrics', 'off',
      '--disable-version-check',
      '-f', frozenRulesPath,
      ...frozenPaths,
    ],
    cwd: repositoryRoot,
    timeoutMs: policy?.providerTimeoutMs ?? 120000,
    maxOutputBytes: policy?.maxOutputBytes ?? 8388608,
    environmentKeys: ['PATH', 'HOME', 'USERPROFILE', 'TEMP', 'TMP'],
  };
}

const validDigest=(value)=>/^sha256:[a-f0-9]{64}$/.test(value??'');
const equalBinding=(actual,expected)=>actual&&expected&&JSON.stringify(actual)===JSON.stringify(expected);
export function providerResult({binding,expectedBinding=binding,denominator,ruleset,tool,executionReceipt,candidates=[]}){if(!equalBinding(binding,expectedBinding)||!validDigest(binding?.digest)||!validDigest(denominator?.digest)||!Number.isInteger(denominator?.expected)||denominator.expected<1||denominator.examined!==denominator.expected||!validDigest(ruleset?.digest)||!tool?.name||!tool?.version||!validDigest(tool?.executableDigest)||executionReceipt?.complete!==true||executionReceipt.tool?.executableDigest!==tool.executableDigest||!validDigest(executionReceipt.stdoutArtifact?.digest))throw new Error('OpenGrep result requires matching binding denominator rules execution receipt and sealed tool digest');return{schemaVersion:1,provider:'security.opengrep',status:'candidates',complete:true,binding,denominator,ruleset,tool,executionReceipt,candidates,findings:[],coverageGaps:[]};}
export function analyze({plan,artifacts}={}){const evidence=artifacts?.opengrep??null;if(!evidence)return{status:'unproven',complete:false,denominator:{kind:'sealed-source-paths',expected:plan?.denominator?.pathCount??0,examined:0},findings:[],candidates:[],coverageGaps:[{kind:'opengrep-evidence-missing'}]};try{return{...providerResult(evidence),status:'candidates',complete:true};}catch(error){return{status:'unproven',complete:false,denominator:{kind:'sealed-source-paths',expected:0,examined:0},findings:[],candidates:[],coverageGaps:[{kind:'opengrep-evidence-invalid',reason:error.message}]};}}
