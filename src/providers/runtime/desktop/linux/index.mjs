export const LINUX_CASES = Object.freeze(['xdg', 'x11-wayland', 'libraries', 'appimage', 'flatpak', 'snap', 'deb-rpm', 'desktop-entry', 'mime-protocol', 'polkit', 'sandbox', 'distribution-desktop']);
export function evaluateLinuxPlatform({ matrix = {}, artifact = {}, checks = [], capability = {} } = {}) {
  const boundMatrix = { os: 'linux', version: matrix.version ?? null, architecture: matrix.architecture ?? null };
  const gaps = [];
  if (!boundMatrix.version || !boundMatrix.architecture) gaps.push('linux-matrix-incomplete');
  if (capability.status !== 'available') gaps.push(`linux-capability-unavailable:${capability.reason ?? capability.status ?? 'missing'}`);
  for (const check of checks) if (check.terminal !== true) gaps.push(`linux-check-nonterminal:${check.id}`);
  if (capability.status === 'available') for (const id of LINUX_CASES) if (!checks.some((item) => item.id === id && item.terminal === true)) gaps.push(`linux-case-missing:${id}`);
  return { schemaVersion: 1, kind: 'legion-desktop-linux', status: gaps.length ? 'unproven' : 'pass', terminal: true, matrix: boundMatrix, artifact, receipts: checks, coverageGaps: gaps.sort() };
}

export async function executeLinuxPlatform({ host, ...input } = {}) { if (!host?.check) return evaluateLinuxPlatform(input); const checks = []; for (const id of LINUX_CASES) checks.push(await host.check({ os: 'linux', id, artifact: input.artifact })); return evaluateLinuxPlatform({ ...input, checks }); }
