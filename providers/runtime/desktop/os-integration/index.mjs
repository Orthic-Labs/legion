const ALLOWED = new Set(['pass', 'fail', 'partial', 'unproven', 'blocked', 'error', 'unsupported']);
const HOST_UNAVAILABLE_TYPES = new Set(['remote-host', 'device-not-present', 'os-version-unavailable', 'license-restricted']);
export const DESKTOP_OS_CASES = Object.freeze(['single-instance', 'multi-window', 'focus-modal', 'tray-menu', 'autostart', 'notifications', 'shortcuts', 'exit', 'window-restore', 'missing-monitor', 'mixed-dpi', 'display-hotplug', 'high-contrast', 'reduced-motion', 'ime', 'non-us-keyboard', 'screen-reader', 'keyboard-only', 'installer-keyboard', 'updater-screen-reader', 'sleep-resume', 'permission-revocation', 'non-admin']);

export function compileDesktopOsMatrix({ required = DESKTOP_OS_CASES, cases = [] } = {}) {
  const requested = Array.isArray(required) ? [...new Set(required)] : [];
  const supplied = Array.isArray(cases) ? cases : [];
  const byId = new Map(supplied.map((item) => [item.id, item]));
  const receipts = requested.map((id) => byId.get(id) ?? { id, status: 'unproven', terminal: true, synthesized: true });
  const gaps = [];
  for (const item of supplied) {
    if (!requested.includes(item.id)) gaps.push(`caller-defined-matrix-case:${item.id}`);
  }
  if (requested.length === 0) gaps.push('matrix-denominator-empty');
  for (const item of receipts) {
    if (item.terminal !== true || !ALLOWED.has(item.status)) gaps.push(`terminal-status-invalid:${item.id}`);
    if (!item.os || !item.version || !item.architecture) gaps.push(`platform-binding-incomplete:${item.id}`);
    if (!item.state || typeof item.state !== 'object') gaps.push(`native-state-missing:${item.id}`);
    if (!(item.controlIds?.length)) gaps.push(`control-binding-missing:${item.id}`);
    if (item.status === 'unsupported') {
      if (!item.reason) gaps.push(`unsupported-reason-missing:${item.id}`);
      if (!item.hostUnavailable || typeof item.hostUnavailable !== 'object') gaps.push(`host-unavailable-evidence-missing:${item.id}`);
      else if (!HOST_UNAVAILABLE_TYPES.has(item.hostUnavailable.type)) gaps.push(`host-unavailable-type-invalid:${item.id}`);
      else if (!item.hostUnavailable.detail) gaps.push(`host-unavailable-detail-missing:${item.id}`);
    }
    if (item.synthesized) gaps.push(`matrix-case-missing:${item.id}`);
  }
  return { schemaVersion: 1, kind: 'nemesis-desktop-os-matrix', status: gaps.length ? 'unproven' : 'pass', terminal: true, receipts,
    denominator: { total: requested.length, required: requested.length, accounted: receipts.filter((item) => !item.synthesized && item.terminal === true && ALLOWED.has(item.status)).length, synthesized: receipts.filter((item) => item.synthesized).length }, coverageGaps: gaps.sort() };
}

export async function executeDesktopOsMatrix({ host, ...input } = {}) {
  if (!host?.probe) return compileDesktopOsMatrix(input);
  const receipts = [];
  for (const id of input.required ?? DESKTOP_OS_CASES) {
    const probe = await host.probe({ id, ...(input.binding ?? {}) });
    receipts.push({ ...probe, id, terminal: true });
  }
  return compileDesktopOsMatrix({ ...input, cases: receipts });
}
