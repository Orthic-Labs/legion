// Compatibility shim. The authoritative loader now lives in provider-registry.mjs and
// always merges the complete declarative registry before validation.
export * from './provider-registry.mjs';
