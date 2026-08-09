const DIGEST = /^sha256:[a-f0-9]{64}$/;
export const IPC_CASES = Object.freeze(['allowed', 'denied', 'malformed', 'oversized', 'replayed', 'wrong-caller', 'stale-session', 'shutdown']);

const INVENTORY = ['sockets', 'plugins', 'sidecars'];
const BOUNDARIES = ['navigation', 'remoteContent', 'externalUrl', 'shell', 'process', 'filesystem'];
const DENIED_CASES = new Set(IPC_CASES.filter((id) => id !== 'allowed'));

export function evaluateDesktopIpc({ commands = [], attempts = [], helpers = [], inventory = {}, boundaries = {}, evidence = {} } = {}) {
  const definitions = new Map(commands.map((item) => [item.id, item]));
  const receipts = attempts.map((attempt) => {
    const command = definitions.get(attempt.command);
    if (!command) return { id: attempt.id, status: 'blocked', terminal: true, reason: 'unknown-command' };
    if (!(command.actors ?? []).includes(attempt.actor)) return { id: attempt.id, status: 'blocked', terminal: true, reason: 'caller-denied' };
    if (!(command.capabilities ?? []).every((item) => (attempt.capabilities ?? []).includes(item))) return { id: attempt.id, status: 'blocked', terminal: true, reason: 'capability-denied' };
    if (DENIED_CASES.has(attempt.id) && attempt.observedDenied !== true) return { id: attempt.id, status: 'fail', terminal: true, reason: 'denial-bypassed' };
    return { id: attempt.id, status: 'pass', terminal: true };
  });
  const gaps = [];
  for (const helper of helpers) {
    if (!DIGEST.test(helper.digest ?? '')) gaps.push(`helper-identity-unproven:${helper.id ?? 'unknown'}`);
    if (helper.stopped !== true) gaps.push(`helper-outlived-parent:${helper.id ?? 'unknown'}`);
    if (helper.inheritedHandles?.length) gaps.push(`helper-handles-inherited:${helper.id ?? 'unknown'}`);
    if (!helper.workingDirectory || helper.environmentBound !== true) gaps.push(`helper-context-unproven:${helper.id ?? 'unknown'}`);
  }
  for (const command of commands) if (!command.schema || !command.arguments || !command.privilege || !command.identity) gaps.push(`command-contract-incomplete:${command.id ?? 'unknown'}`);
  for (const id of IPC_CASES) if (!attempts.some((item) => item.id === id && item.terminal === true)) gaps.push(`ipc-case-missing:${id}`);
  for (const key of INVENTORY) if (!Array.isArray(inventory[key])) gaps.push(`inventory-missing:${key}`);
  for (const key of BOUNDARIES) if (boundaries[key] !== true) gaps.push(`boundary-unproven:${key}`);
  if (evidence.source !== 'native-host' || evidence.terminal !== true) gaps.push('native-ipc-receipt-missing');
  return { schemaVersion: 1, kind: 'legion-desktop-ipc', status: gaps.length ? 'unproven' : 'pass', terminal: true,
    commands: commands.map(({ id, actors = [], capabilities = [] }) => ({ id, actors, capabilities })), receipts, helpers, inventory, boundaries, evidence, coverageGaps: [...new Set(gaps)].sort() };
}

export async function executeDesktopIpc({ host, commands = [], helpers = [], inventory = {}, boundaries = {} } = {}) {
  if (!host?.exercise) return evaluateDesktopIpc({ commands, helpers, inventory, boundaries });
  const attempts = [];
  for (const caseId of IPC_CASES) attempts.push(await host.exercise({ caseId, commands, inventory, boundaries }));
  const evidence = typeof host.receipt === 'function' ? await host.receipt() : {};
  return evaluateDesktopIpc({ commands, attempts, helpers, inventory, boundaries, evidence });
}
