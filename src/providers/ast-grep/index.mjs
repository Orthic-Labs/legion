// ast-grep structural provider. Pinned executable discovery, capability/version
// receipt, machine-JSON scan normalization with stable fingerprints, and
// rewrite preview as a patch artifact. Never applies rewrites (PR35–PR37 own
// application), never forks the DSL, never loads untrusted grammars.

import { createHash } from 'node:crypto';

export function stableFingerprint({ ruleId, file, range, structuralDigest }) {
  const body = JSON.stringify({ ruleId, file, range, structuralDigest: structuralDigest ?? null });
  return `sha256:${createHash('sha256').update(`ast-grep-match\0${body}`).digest('hex')}`;
}

export function normalizeMatch(line, { ruleId, provider = 'ast-grep.structural', severity = 'warning' }) {
  const file = line.file ?? line.path ?? null;
  const range = line.range ?? {
    start: { line: Number(line.line ?? line.start?.line ?? 1), column: Number(line.column ?? line.start?.column ?? 0) },
    end: { line: Number(line.end?.line ?? line.line ?? 1), column: Number(line.end?.column ?? line.column ?? 0) },
  };
  return {
    ruleId: line.ruleId ?? ruleId,
    severity: line.severity ?? severity,
    message: line.message ?? line.note ?? ruleId,
    file,
    range,
    metavariables: line.metavariables ?? line.meta ?? {},
    fingerprint: stableFingerprint({
      ruleId: line.ruleId ?? ruleId,
      file,
      range,
      structuralDigest: line.structuralDigest ?? line.digest ?? null,
    }),
    rawArtifactRef: line.rawArtifactRef ?? null,
  };
}

export function normalizeStream(lines, context) {
  return (lines ?? [])
    .map((line) => normalizeMatch(line, context))
    .filter((match) => match.file);
}

export function commandContract({ resolvedAstGrep, packPath, frozenPaths, repositoryRoot, policy }) {
  return {
    executable: resolvedAstGrep,
    args: ['scan', '--config', packPath, '--json=stream', ...frozenPaths],
    cwd: repositoryRoot,
    timeoutMs: policy?.providerTimeoutMs ?? 120000,
    maxOutputBytes: policy?.maxOutputBytes ?? 8388608,
    environmentKeys: ['PATH', 'HOME', 'USERPROFILE', 'TEMP', 'TMP'],
  };
}

export function rewritePreview({ ruleId, file, edits }) {
  // Preview-only patch artifact; application requires PR35–PR37 controls.
  return {
    schemaVersion: 1,
    kind: 'legion-ast-grep-rewrite-preview',
    ruleId,
    file,
    edits: (edits ?? []).map((edit) => ({
      startLine: edit.startLine,
      endLine: edit.endLine,
      replacement: edit.replacement,
      digest: `sha256:${createHash('sha256').update(edit.replacement ?? '').digest('hex')}`,
    })),
    applied: false,
    note: 'preview only; application is governed by isolated-worktree remediation',
  };
}

export function capabilityReceipt({ executable, version, languages }) {
  return {
    schemaVersion: 1,
    kind: 'legion-ast-grep-capability',
    executable,
    version: version ?? null,
    languages: [...new Set(languages ?? [])].sort(),
  };
}
export function analyze({projection,artifacts}={}){const paths=(projection?.files??[]).map((file)=>file.path??file);const matches=artifacts?.structuralMatches??[];const unsupported=artifacts?.unsupportedGrammars??[];const gaps=[];if(!paths.length)gaps.push({kind:'structural-denominator-zero'});if(!artifacts?.astGrepTool)gaps.push({kind:'structural-tool-unqualified'});for(const grammar of unsupported)gaps.push({kind:'unsupported-grammar',grammar});return{status:gaps.length?'unproven':'pass',complete:gaps.length===0,denominator:{kind:'sealed-source-paths',expected:paths.length,examined:artifacts?.examinedPaths?.length??0},findings:[],candidates:matches,coverageGaps:gaps};}
