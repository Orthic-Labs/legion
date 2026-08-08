const CASES = Object.freeze([
  ['fresh-install', 'clean-install-state'], ['first-launch', 'deterministic-onboarding'], ['authentication', 'authorized-session'],
  ['primary-journey', 'durable-completion'], ['save-resume', 'durable-state-restored'], ['share-export', 'bounded-user-visible-effect'],
  ['purchase-restore', 'server-verified-entitlement'], ['logout-deletion', 'actor-data-cleared'], ['reinstall-recovery', 'account-state-reconstructed'],
  ['background-foreground', 'operation-bounded'], ['lock-unlock', 'sensitive-state-protected'], ['rotate', 'state-preserved'],
  ['fold-unfold', 'state-preserved'], ['split-screen-resize', 'state-preserved'], ['system-interruption', 'recover-or-cancel'],
  ['audio-route-change', 'media-state-consistent'], ['process-death', 'durable-state-restored'], ['force-stop', 'durable-state-restored'],
  ['reboot', 'durable-state-restored'], ['os-upgrade', 'user-data-preserved'], ['app-upgrade', 'user-data-preserved'],
  ['cold-deep-link', 'authorization-rechecked'], ['cold-notification', 'authorization-rechecked'], ['duplicate-event', 'idempotent-effect'],
  ['background-job', 'bounded-execution'], ['corrupt-partial-state', 'safe-recovery'],
]);

export function planMobileLifecycle({ targetId = null, journeyId = null, deviceCapability = {}, binding = {} } = {}) {
  const available = deviceCapability.status === 'available';
  const scenarios = CASES.map(([id, expectedOutcome]) => ({ id, targetId, journeyId, expectedOutcome,
    status: available ? 'unproven' : 'blocked', terminal: true, binding, captures: ['crash', 'hang', 'visible-state', 'backend-effects', 'recovery'] }));
  return { schemaVersion: 1, kind: 'nemesis-mobile-lifecycle-plan', targetId, journeyId,
    status: available ? 'unproven' : 'blocked', terminal: true, scenarios,
    coverageGaps: available ? ['device-execution-not-run'] : [`device-capability-${deviceCapability.status ?? 'missing'}`] };
}
