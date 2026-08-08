export const MACOS_CASES = Object.freeze(['hardened-runtime', 'notarization', 'gatekeeper', 'entitlements', 'app-sandbox', 'keychain', 'tcc', 'app-translocation', 'architectures', 'login-items-helpers', 'menus-windows', 'residual-data']);
export function evaluateMacosPlatform({ matrix = {}, artifact = {}, checks = [], capability = {} } = {}) {
  const boundMatrix = { os: 'macos', version: matrix.version ?? null, architecture: matrix.architecture ?? null };
  const gaps = [];
  if (!boundMatrix.version || !boundMatrix.architecture) gaps.push('macos-matrix-incomplete');
  if (capability.status !== 'available') gaps.push(`macos-capability-unavailable:${capability.reason ?? capability.status ?? 'missing'}`);
  for (const check of checks) { if (check.terminal !== true) gaps.push(`macos-check-nonterminal:${check.id}`); if (['notarization', 'gatekeeper'].includes(check.id) && (artifact.final !== true || check.artifactDigest !== artifact.digest)) gaps.push(`macos-final-artifact-unproven:${check.id}`); }
  if (capability.status === 'available') for (const id of MACOS_CASES) if (!checks.some((item) => item.id === id && item.terminal === true)) gaps.push(`macos-case-missing:${id}`);
  return { schemaVersion: 1, kind: 'nemesis-desktop-macos', status: gaps.length ? 'unproven' : 'pass', terminal: true, matrix: boundMatrix, artifact, receipts: checks, coverageGaps: gaps.sort() };
}

export async function executeMacosPlatform({ host, ...input } = {}) { if (!host?.check) return evaluateMacosPlatform(input); const checks = []; for (const id of MACOS_CASES) checks.push(await host.check({ os: 'macos', id, artifact: input.artifact })); return evaluateMacosPlatform({ ...input, checks }); }
