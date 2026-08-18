const REQUIRED_STATES = ['default', 'loading', 'empty', 'error', 'success', 'disabled', 'focused', 'opened', 'offline'];
export function buildRuntimeSpecs(inventory, options = {}) {
  const specs = (inventory?.surfaces ?? []).filter((surface) => surface.runtimeEligible).map((surface) => {
    const states = [...new Set([...(surface.states ?? []), ...REQUIRED_STATES.filter((state) => options.requiredStates?.includes(state))])];
    const risky = surface.controls.filter((control) => control.destructive || control.external || control.nativeDialog);
    return { surfaceId: surface.id, entryRoute: surface.route, states, viewports: options.viewports ?? ['desktop'], authentication: options.authentication?.[surface.id] ?? 'unknown',
      actions: risky.map((control) => ({ id: control.id, selector: control.selector ?? null, prohibited: true })), terminalState: options.terminalStates?.[surface.id] ?? null };
  });
  return { schemaVersion: 1, kind: 'legion-runtime-surface-spec', specs, coverageGaps: specs.filter((spec) => !spec.entryRoute).map((spec) => `route-missing:${spec.surfaceId}`) };
}
