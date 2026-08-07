import { profileConfig } from './index.mjs';
export function sealedProfile(name, overrides = {}) { const profile = profileConfig(name); return Object.freeze({ ...profile, resources: { providerConcurrency: 4, projectExecution: 1, browser: 1, nativeSurface: 1, reviewer: 2, signing: 1, ...(overrides.resources ?? {}) }, reasoning: overrides.reasoning ?? 'auto' }); }
