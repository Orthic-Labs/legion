export const DESKTOP_ADAPTERS = Object.freeze({
  electron: { processRoles: ['main', 'renderer'], nativeSurface: 'window' },
  tauri: { processRoles: ['main', 'webview'], nativeSurface: 'window' },
  apple: { processRoles: ['application'], nativeSurface: 'nswindow' },
  dotnet: { processRoles: ['application'], nativeSurface: 'hwnd' },
  'qt-native': { processRoles: ['application'], nativeSurface: 'qwindow' },
  flutter: { processRoles: ['application'], nativeSurface: 'engine-view' },
});
const FRAMEWORKS = new Set(Object.keys(DESKTOP_ADAPTERS));
const sameArtifact = (expected, actual) => expected?.path === actual?.path && expected?.digest === actual?.digest;

export function collectDesktopRuntime({ target = {}, artifact = {}, capability = {}, observations = {} } = {}) {
  const gaps = [];
  if (!target.id) gaps.push('target-id-missing');
  if (!FRAMEWORKS.has(target.framework)) gaps.push('framework-unsupported');
  if (!artifact.path || !/^sha256:[a-f0-9]{64}$/.test(artifact.digest ?? '')) gaps.push('artifact-binding-incomplete');
  if (capability.status !== 'available' || capability.receipt?.cleanEnvironment !== true) gaps.push(`native-capability-${capability.status ?? 'missing'}`);
  if (capability.receipt?.nativeSurface !== true || observations.browserOnly === true) gaps.push('native-surface-unproven');
  if (observations.source !== 'native-host' || observations.receipt?.terminal !== true) gaps.push('native-observation-receipt-missing');
  if (observations.executable && !sameArtifact(artifact, observations.executable)) gaps.push('executable-binding-mismatch');
  if (!observations.executable && !observations.browserOnly) gaps.push('executable-observation-missing');
  if (!(observations.processes?.length)) gaps.push('process-inventory-empty');
  if (!(observations.windows?.length)) gaps.push('window-inventory-empty');
  if (observations.shutdown?.clean !== true) gaps.push('shutdown-unproven');
  if (observations.environment?.isolated !== true) gaps.push('environment-isolation-unproven');
  const components = {
    processes: observations.processes ?? [], windows: observations.windows ?? [], helpers: observations.helpers ?? [],
    services: observations.services ?? [], sidecars: observations.sidecars ?? [], localServers: observations.localServers ?? [],
    webviews: observations.webviews ?? [], gpuProcesses: observations.gpuProcesses ?? [],
  };
  const status = gaps.includes('executable-binding-mismatch') ? 'unproven' : gaps.length ? 'partial' : 'pass';
  return { schemaVersion: 1, kind: 'legion-desktop-runtime', status, terminal: true,
    binding: { targetId: target.id ?? null, artifactPath: artifact.path ?? null, artifactDigest: artifact.digest ?? null, framework: target.framework ?? null },
    components, lifecycle: { startup: observations.startup ?? null, firstUsable: observations.firstUsable ?? null, shutdown: observations.shutdown ?? null, crashes: observations.crashes ?? [], orphans: observations.orphans ?? [] },
    environment: observations.environment ?? null, logs: observations.logs ?? [], coverageGaps: [...new Set(gaps)].sort() };
}

export async function executeDesktopRuntime({ target = {}, artifact = {}, capability = {}, host = null, attach = false } = {}) {
  if (!host || typeof host[attach ? 'attach' : 'launch'] !== 'function') return collectDesktopRuntime({ target, artifact, capability: { ...capability, status: capability.status ?? 'unavailable' }, observations: { browserOnly: false } });
  const observations = await host[attach ? 'attach' : 'launch']({ target, artifact, adapter: { id: target.framework, ...DESKTOP_ADAPTERS[target.framework] }, capture: ['executable', 'processes', 'windows', 'helpers', 'services', 'sidecars', 'localServers', 'webviews', 'gpuProcesses', 'startup', 'firstUsable', 'logs', 'crashes', 'orphans', 'shutdown', 'environment', 'receipt'] });
  return collectDesktopRuntime({ target, artifact, capability, observations });
}
