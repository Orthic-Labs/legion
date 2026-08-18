export const WINDOWS_CASES = Object.freeze(['dpi-awareness', 'unicode-long-path', 'appdata-registry-acl', 'authenticode', 'smartscreen-defender', 'dll-search', 'uac', 'services-tasks', 'quoted-registration', 'installer', 'remote-desktop', 'edr-assumptions']);
export function evaluateWindowsPlatform(input = {}) {
  const { matrix = {}, artifact = {}, checks = [], capability = { status: 'available' } } = input;
  const boundMatrix = { os: 'windows', version: matrix.version ?? null, architecture: matrix.architecture ?? null };
  const gaps = [];
  if (!boundMatrix.version || !boundMatrix.architecture) gaps.push('windows-matrix-incomplete');
  if (capability.status !== 'available') gaps.push(`windows-capability-${capability.reason ?? capability.status}`);
  for (const check of checks) {
    if (check.terminal !== true) gaps.push(`windows-check-nonterminal:${check.id}`);
    if (['authenticode', 'installer'].includes(check.id) && (artifact.final !== true || check.artifactDigest !== artifact.digest)) gaps.push(`windows-final-artifact-unproven:${check.id}`);
  }
  for (const id of WINDOWS_CASES) if (!checks.some((item) => item.id === id && item.terminal === true)) gaps.push(`windows-case-missing:${id}`);
  return { schemaVersion: 1, kind: 'legion-desktop-windows', status: gaps.length ? 'unproven' : 'pass', terminal: true, matrix: boundMatrix, artifact, receipts: checks, coverageGaps: gaps.sort() };
}

export async function executeWindowsPlatform({ host, ...input } = {}) { if (!host?.check) return evaluateWindowsPlatform(input); const checks = []; for (const id of WINDOWS_CASES) checks.push(await host.check({ os: 'windows', id, artifact: input.artifact })); return evaluateWindowsPlatform({ ...input, checks }); }
