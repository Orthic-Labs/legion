import { fixedHost } from './fixed-host.mjs';

export function runtimeToolchains() {
  return { state: 'ready', tools: [{ name: 'node', executable: process.execPath, version: process.version }] };
}

export function createHost(overrides = {}) {
  const value = { ...overrides, browser: overrides.browser ?? null, reviewer: overrides.reviewer ?? null,
    toolchain: overrides.toolchain ?? { discover: runtimeToolchains }, allowedExecutables: overrides.allowedExecutables ?? new Set(),
    capabilities: { networkSandbox: { active: false, receipt: null }, mutation: false, browser: false, signing: false, reviewing: false,
      nativeSurface: false, mobileDevice: false, externalEvidence: false, ...(overrides.capabilities ?? {}) } };
  for (const key of Object.keys(value)) if (value[key] === undefined) delete value[key];
  return fixedHost(value);
}
