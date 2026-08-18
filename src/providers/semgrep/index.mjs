// Semgrep provider (CE/local vs platform capability). Distinguishes
// CE/local/platform capability and records ruleset identity, account/network
// requirements, and licensing. Never requires a cloud account and never
// uploads by default.

export function semgrepCapability({ mode = 'ce', accountRequired = false, networkRequired = false, ruleset = null, version = null }) {
  return {
    schemaVersion: 1,
    kind: 'legion-semgrep-capability',
    mode, // ce | local | platform
    accountRequired,
    networkRequired,
    ruleset: ruleset ?? null,
    version: version ?? null,
  };
}

export function semgrepCommand({ resolvedSemgrep, rulesPath, repositoryRoot, policy, outputPath }) {
  return {
    executable: resolvedSemgrep,
    args: ['scan', '--config', rulesPath, '--json', '--output', outputPath, repositoryRoot],
    cwd: repositoryRoot,
    timeoutMs: policy?.providerTimeoutMs ?? 120000,
    maxOutputBytes: policy?.maxOutputBytes ?? 8388608,
    environmentKeys: ['PATH', 'HOME', 'USERPROFILE', 'TEMP', 'TMP'],
  };
}
