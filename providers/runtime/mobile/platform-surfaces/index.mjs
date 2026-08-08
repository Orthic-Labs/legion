const PERMISSION_STATES = Object.freeze(['not-requested', 'granted', 'denied', 'permanently-denied', 'later-granted', 'settings-revoked', 'restricted', 'limited', 'approximate']);
const LINK_STATES = Object.freeze(['logged-out', 'expired', 'background', 'terminated', 'duplicate', 'malicious', 'wrong-account', 'hijack-risk']);
const CHANNEL_STATES = Object.freeze(['foreground', 'background', 'terminated', 'stale', 'replayed']);
const WEBVIEW_CASES = Object.freeze(['origin', 'navigation', 'javascript', 'bridge', 'file-access', 'cookies', 'logout']);
const IPC_CASES = Object.freeze(['android-exported-component', 'android-intent', 'android-provider', 'ios-handler', 'ios-shared-container', 'cross-platform-channel']);

export function planMobilePlatformSurfaces({ permissions = [], links = [], channels = [], extensions = [] } = {}) {
  const scenarios = [
    ...permissions.flatMap((permission) => PERMISSION_STATES.map((state) => ({ id: `permission:${permission}:${state}`, family: 'permission', state, expected: state === 'denied' || state === 'permanently-denied' ? 'graceful-degradation' : 'bounded-behavior', status: 'unproven' }))),
    ...links.flatMap((link) => LINK_STATES.map((state) => ({ id: `link:${link}:${state}`, family: 'link', state, requirements: ['route-validation', 'server-authorization-recheck'], status: 'unproven' }))),
    ...channels.flatMap((channel) => CHANNEL_STATES.map((state) => ({ id: `${channel}:${state}`, family: channel, state, payloadAuthority: false, requirements: ['schema-validation', 'authorization-recheck'], status: 'unproven' }))),
    ...WEBVIEW_CASES.map((id) => ({ id: `webview:${id}`, family: 'webview', payloadAuthority: false, requirements: ['trusted-origin', 'least-privilege-bridge', 'account-state-isolation'], status: 'unproven' })),
    ...IPC_CASES.map((id) => ({ id: `ipc:${id}`, family: 'ipc', payloadAuthority: false, requirements: ['schema-validation', 'authorization-recheck', 'non-exported-by-default'], status: 'unproven' })),
    ...extensions.map((extension) => ({ id: `extension:${extension}`, family: 'extension', sharedContainerAuthority: false, status: 'unproven' })),
  ];
  return { schemaVersion: 1, kind: 'nemesis-mobile-platform-surface-plan', status: 'unproven', terminal: true, scenarios,
    denominator: { total: scenarios.length, accounted: scenarios.length }, coverageGaps: scenarios.map((item) => `${item.id}:device-execution-missing`) };
}
