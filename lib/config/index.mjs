// Versioned configuration with safe precedence:
//   built-in defaults < user config < repository config < CLI flags < sealed plan.
// Repository config may never weaken host-owned controls.

import { readFileSync, existsSync } from 'node:fs';
import { resolve, win32 } from 'node:path';

export const CONFIG_SCHEMA_VERSION = 1;

const HOST_OWNED = new Set([
  'networkGuard',
  'planSigningKey',
  'modelCredentials',
  'mutation',
  'externalToolAllowlist',
  'releaseSigning',
]);

export const DEFAULT_CONFIG = Object.freeze({
  schemaVersion: CONFIG_SCHEMA_VERSION,
  profile: 'standard',
  providers: { require: [], disable: [] },
  limits: { providerTimeoutMs: 120000, maxOutputBytes: 8388608, maxConcurrency: 4 },
  policy: { failOn: ['critical', 'high'], baseline: null, acceptedRisk: null },
  outputs: ['json', 'sarif', 'markdown'],
});

export const PROFILES = Object.freeze({
  fast: {
    profile: 'fast',
    providers: { require: [], disable: ['runtime.app', 'visual.core'] },
    limits: { providerTimeoutMs: 30000, maxOutputBytes: 2097152, maxConcurrency: 2 },
    policy: { failOn: ['critical', 'high'], baseline: null, acceptedRisk: null },
    outputs: ['json', 'sarif'],
  },
  standard: { ...DEFAULT_CONFIG },
  full: {
    profile: 'full',
    providers: { require: [], disable: [] },
    limits: { providerTimeoutMs: 300000, maxOutputBytes: 16777216, maxConcurrency: 8 },
    policy: { failOn: ['critical', 'high'], baseline: null, acceptedRisk: null },
    outputs: ['json', 'sarif', 'markdown'],
  },
  release: {
    profile: 'release',
    providers: { require: [], disable: [] },
    limits: { providerTimeoutMs: 600000, maxOutputBytes: 33554432, maxConcurrency: 16 },
    policy: { failOn: ['critical', 'high', 'medium'], baseline: null, acceptedRisk: null },
    outputs: ['json', 'sarif', 'markdown', 'html'],
  },
});

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function deepMerge(target, ...sources) {
  for (const source of sources) {
    if (!source) continue;
    for (const [key, value] of Object.entries(source)) {
      if (isObject(value) && isObject(target[key])) deepMerge(target[key], value);
      else if (Array.isArray(value)) target[key] = [...value];
      else target[key] = value;
    }
  }
  return target;
}

export function mergeConfig({ defaults, user, repository, cli }) {
  for (const key of HOST_OWNED) {
    if (repository && Object.hasOwn(repository, key)) {
      throw new Error(`repository config may not set host-owned key: ${key}`);
    }
  }
  const merged = deepMerge({}, defaults, user ?? {}, repository ?? {}, cli ?? {});
  validateConfig(merged);
  return merged;
}

const KNOWN_KEYS = new Set([
  'schemaVersion', 'profile', 'providers', 'limits', 'policy', 'outputs',
  'require', 'disable', 'providerTimeoutMs', 'maxOutputBytes', 'maxConcurrency',
  'failOn', 'baseline', 'acceptedRisk',
]);

export function validateConfig(config, label = 'config') {
  if (!isObject(config)) throw new Error(`${label} must be an object`);
  if (config.schemaVersion !== CONFIG_SCHEMA_VERSION) {
    throw new Error(`${label}.schemaVersion must be ${CONFIG_SCHEMA_VERSION}; got ${JSON.stringify(config.schemaVersion)}`);
  }
  if (config.profile && !Object.hasOwn(PROFILES, config.profile)) {
    throw new Error(`${label}.profile must be one of ${Object.keys(PROFILES).join(', ')}; got ${JSON.stringify(config.profile)}`);
  }
  for (const key of Object.keys(config)) {
    if (!KNOWN_KEYS.has(key)) throw new Error(`${label} has unknown key: ${key}`);
  }
  for(const [section,keys]of Object.entries({providers:['require','disable'],limits:['providerTimeoutMs','maxOutputBytes','maxConcurrency'],policy:['failOn','baseline','acceptedRisk']}))if(config[section])for(const key of Object.keys(config[section]))if(!keys.includes(key))throw new Error(`${label}.${section} has unknown key: ${key}`);
  return config;
}

export function profileConfig(name) {
  const profile = PROFILES[name];
  if (!profile) throw new Error(`unknown profile ${name}`);
  return JSON.parse(JSON.stringify(profile));
}

export function loadUserConfig(path) {
  if (!path || !existsSync(path)) return {};
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  validateConfig(raw, `user config ${path}`);
  return raw;
}

export function loadRepositoryConfig(root) {
  const candidates = ['nemesis.config.json', 'nemesis.config.jsonc'];
  for (const name of candidates) {
    const path = resolve(root, name);
    if (!existsSync(path)) continue;
    const raw = JSON.parse(readFileSync(path, 'utf8'));
    validateConfig(raw, `repository config ${path}`);
    return raw;
  }
  return {};
}

export function normalizePath(value, cwd) {
  // Windows drive/case/UNC, macOS symlinked temp, POSIX separators: resolve to
  // an absolute canonical path using realpath where the path exists.
  const raw = String(value ?? '');
  const windowsRoot = /^[a-zA-Z]:[\\/]/.test(raw) || /^[a-zA-Z]:[\\/]/.test(String(cwd ?? ''));
  const once = windowsRoot ? raw.replace(/^([a-zA-Z]:)[\\/]\1(?=[\\/])/i, '$1') : raw;
  return windowsRoot ? win32.resolve(cwd, once) : resolve(cwd, once);
}

export { HOST_OWNED };
