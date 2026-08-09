import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DEFAULT_REGISTRY = fileURLToPath(new URL('./providers.json', import.meta.url));
const DEFAULT_EXTENSION = fileURLToPath(new URL('./providers-runtime.json', import.meta.url));
const DEFAULT_SECURITY_LENSES = fileURLToPath(new URL('./security-lenses.json', import.meta.url));
const RUNNER_KINDS = new Set(['legacy-check', 'runtime-script', 'reasoning-contract']);
const QUALIFICATION_RANK = new Map([['unproven', 0], ['partial', 1], ['complete', 2]]);

// Security lens registry loader (Security Appendix §15.2). Lenses become
// candidate-generator provider records; no provider ID may exist in both the
// runtime registry and the lens registry.
export function loadSecurityLensRegistry(path = DEFAULT_SECURITY_LENSES) {
  const registry = JSON.parse(readFileSync(path, 'utf8'));
  if (registry?.schemaVersion !== 1 || registry?.kind !== 'security-lens-registry') {
    throw new Error('security lens registry must be security-lens-registry schemaVersion=1');
  }
  if (!Array.isArray(registry.lenses)) throw new Error('security lens registry must declare lenses');
  const ids = new Set();
  for (const lens of registry.lenses) {
    if (!lens?.id || ids.has(lens.id)) throw new Error(`duplicate or missing security lens id: ${lens?.id}`);
    if (!['planned', 'implemented', 'measured'].includes(lens.implementationState)) {
      throw new Error(`lens ${lens.id} has invalid implementationState ${lens.implementationState}`);
    }
    ids.add(lens.id);
  }
  return registry;
}

export function expandSecurityLensProviders(lensRegistry) {
  return (lensRegistry.lenses ?? []).map((lens) => ({
    id: lens.id,
    providerVersion: lens.version ?? '1',
    role: 'candidate-generator',
    phase: 'runtime',
    selector: lens.selector,
    allowWithoutCortex: false,
    runner: {
      kind: 'runtime-script',
      script: 'providers/security/candidate-engine.mjs',
      module: lens.module,
    },
    benchmark: lens.benchmark,
    producesSecurityCandidates: true,
    mayCloseOwnCandidates: false,
    modelRequirements: lens.modelRequirements,
    denominatorKind: lens.denominatorKind,
    implementationState: lens.implementationState,
  }));
}

export function extendRegistryWithSecurityLenses(registry, lensRegistry) {
  const merged = structuredClone(registry);
  const providerIds = new Set(merged.providers.map((provider) => provider.id));
  for (const provider of expandSecurityLensProviders(lensRegistry)) {
    if (providerIds.has(provider.id)) throw new Error(`security lens duplicates provider id: ${provider.id}`);
    providerIds.add(provider.id);
    merged.providers.push(provider);
  }
  return merged;
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  return value;
}
export function canonicalJson(value) { return JSON.stringify(canonicalize(value)); }
export function sha256(value) {
  const bytes = typeof value === 'string' ? value : canonicalJson(value);
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function expandSelector(selector) {
  if (typeof selector === 'string') {
    if (['always', 'securityCandidatesSelected', 'confirmedSecurityFinding'].includes(selector)) return { op: selector };
    throw new Error(`unsupported compact selector ${selector}`);
  }
  if (selector?.paths) return { op: 'anyPath', patterns: selector.paths };
  if (selector?.ext) return { op: 'anyExtension', extensions: selector.ext };
  if (selector?.deps) return { op: 'anyDependency', names: selector.deps };
  if (selector?.scripts) return { op: 'anyPackageScript', names: selector.scripts };
  if (selector?.sourceAtLeast !== undefined) return { op: 'sourceFilesAtLeast', count: selector.sourceAtLeast };
  if (selector?.any) return { op: 'any', selectors: selector.any.map(expandSelector) };
  if (selector?.all) return { op: 'all', selectors: selector.all.map(expandSelector) };
  if (selector?.op) return selector;
  throw new Error(`unsupported compact selector ${JSON.stringify(selector)}`);
}
function benchmark(status = 'not_applicable') { return { status, requiredForCleanClaim: status !== 'not_applicable' }; }

export function expandProviderRegistry(raw) {
  if (Array.isArray(raw.providers)) return raw;
  const providers = [];
  for (const item of raw.legacy ?? []) {
    providers.push({
      id: item.id, role: item.role, phase: 'facts', selector: expandSelector(item.selector),
      allowWithoutCortex: Boolean(item.allowWithoutCortex), runner: { kind: 'legacy-check', check: item.check },
      manifest: {
        check: item.check, tool: item.tool, required_when: item.required, applies: item.applies,
        parallel: item.parallel, backs: item.backs ?? [],
        ...(item.flagIfAbsent ? { flag_if_absent: true } : {}),
        ...(item.manifestPhase ? { phase: item.manifestPhase } : {}),
      },
      benchmark: benchmark(item.benchmark), ...(item.covers ? { covers: item.covers } : {}),
      ...(item.role === 'candidate-generator' ? { producesSecurityCandidates: true, mayCloseOwnCandidates: false } : {}),
    });
  }
  for (const item of raw.runtime ?? []) {
    providers.push({
      id: item.id, role: item.role, phase: 'runtime', selector: expandSelector(item.selector),
      allowWithoutCortex: Boolean(item.allowWithoutCortex),
      runner: { kind: 'runtime-script', script: item.script, ...(item.pack ? { pack: item.pack } : {}) },
      manifest: item.manifest, benchmark: benchmark(item.benchmark), ...(item.covers ? { covers: item.covers } : {}),
      ...(item.role === 'candidate-generator' ? { producesSecurityCandidates: true, mayCloseOwnCandidates: false } : {}),
    });
  }
  for (const item of raw.reasoning ?? []) {
    providers.push({
      id: item.id, role: item.role, phase: 'reasoning', selector: expandSelector(item.selector),
      allowWithoutCortex: Boolean(item.allowWithoutCortex), runner: { kind: 'reasoning-contract', contract: item.contract },
      benchmark: benchmark(item.benchmark), ...(item.freshContextRequired ? { freshContextRequired: true } : {}),
      ...(item.mayCloseOwnCandidates === false ? { mayCloseOwnCandidates: false } : {}),
    });
  }
  return {
    schemaVersion: raw.schemaVersion, kind: raw.kind, discoveryOwner: raw.discoveryOwner,
    planSeal: raw.planSeal, concurrency: raw.concurrency, candidateAdjudication: raw.candidateAdjudication,
    providers,
    coverageFamilies: (raw.coverageFamilies ?? []).map((family) => ({ ...family, selector: expandSelector(family.selector) })),
  };
}

function qualificationAtMost(current = 'unproven', ceiling = 'unproven') {
  return (QUALIFICATION_RANK.get(current) ?? 0) <= (QUALIFICATION_RANK.get(ceiling) ?? 0) ? current : ceiling;
}
export function loadProviderRegistryExtension(path = DEFAULT_EXTENSION) {
  const extension = JSON.parse(readFileSync(path, 'utf8'));
  if (extension?.schemaVersion !== 1 || extension?.kind !== 'audit-provider-registry-extension') throw new Error('provider registry extension must be audit-provider-registry-extension schemaVersion=1');
  if (!Array.isArray(extension.providers)) throw new Error('provider registry extension must declare providers');
  return extension;
}
export function extendRegistryWithNativeFamilies(registry, extension = loadProviderRegistryExtension()) {
  const merged = structuredClone(registry);
  const providerIds = new Set(merged.providers.map((provider) => provider.id));
  for (const provider of extension.providers) {
    if (!provider?.id || providerIds.has(provider.id)) throw new Error(`duplicate or missing extension provider id: ${provider?.id}`);
    providerIds.add(provider.id); merged.providers.push(provider);
  }
  const familyIds = new Set(merged.coverageFamilies.map((family) => family.id));
  for (const family of extension.coverageFamilies ?? []) {
    if (!family?.id || familyIds.has(family.id)) throw new Error(`duplicate or missing extension coverage family id: ${family?.id}`);
    familyIds.add(family.id); merged.coverageFamilies.push(family);
  }
  for (const augmentation of extension.familyAugmentations ?? []) {
    if (!providerIds.has(augmentation.provider)) throw new Error(`family augmentation names unknown provider ${augmentation.provider}`);
    const targets = new Set(augmentation.familyIds ?? []);
    merged.coverageFamilies = merged.coverageFamilies.map((family) => targets.has(family.id) ? {
      ...family,
      qualification: qualificationAtMost(family.qualification, augmentation.qualificationCeiling),
      providers: [...new Set([...(family.providers ?? []), augmentation.provider])],
    } : family);
  }
  return merged;
}
function adaptProviderV2Registry(raw) {
  const providers = raw.providers
    .filter((provider) => provider.selectable !== false)
    .map((provider) => {
      const canonicalId = provider.id;
      const id = provider.id.startsWith('legacy.') ? provider.id.slice('legacy.'.length) : provider.id;
      const runner = provider.runner;
      const candidate = provider.role === 'candidate-generator';
      return {
        id,
        canonicalId,
        providerVersion: provider.providerVersion,
        role: provider.role,
        phase: provider.phase === 'source' ? 'facts' : provider.phase,
        selector: provider.selector,
        allowWithoutCortex: id === 'core.repo',
        runner: runner.kind === 'legacy-check'
          ? { kind: 'legacy-check', check: runner.check }
          : runner,
        ...(runner.kind === 'legacy-check' ? { manifest: {
          check: runner.check,
          tool: runner.tool,
          required_when: runner.requiredWhen,
          applies: runner.applies,
          parallel: runner.parallel !== false,
          backs: runner.backs ?? provider.lensIds ?? [],
          ...(provider.phase === 'runtime' ? { phase: 'P2' } : {})
        } } : {}),
        benchmark: { ...(typeof provider.benchmark === 'object' ? provider.benchmark : { status: provider.benchmark }), requiredForCleanClaim: true },
        producesSecurityCandidates: candidate,
        mayCloseOwnCandidates: candidate ? false : true,
        ...(provider.role === 'adjudicator' ? { freshContextRequired: true } : {})
      };
    });
  const ids = new Set(providers.map(({ id }) => id));
  const coverageFamilies = [
    { id: 'framework.react', kind: 'framework', qualification: 'unproven', selector: { op: 'anyDependency', names: ['react','react-dom'] }, providers: ['react.hooks-config'].filter((id) => ids.has(id)) },
    { id: 'framework.tauri', kind: 'framework', qualification: 'unproven', selector: { op: 'anyPath', patterns: ['src-tauri/**'] }, providers: ['tauri.contract-mirror','tauri.capabilities'].filter((id) => ids.has(id)) }
  ];
  return { schemaVersion: 1, kind: 'audit-provider-registry', discoveryOwner: 'cortex', planSeal: 'sha256', concurrency: 'min(cpus-1,4)', candidateAdjudication: 'separate-context', providers, coverageFamilies };
}
export function loadProviderRegistry(path = DEFAULT_REGISTRY, extensionPath = DEFAULT_EXTENSION) {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  if (raw?.schemaVersion === 2 && raw?.kind === 'nemesis-provider-registry') {
    const registry = adaptProviderV2Registry(raw);
    validateProviderRegistry(registry);
    return registry;
  }
  let registry = expandProviderRegistry(raw);
  if (extensionPath && existsSync(extensionPath)) registry = extendRegistryWithNativeFamilies(registry, loadProviderRegistryExtension(extensionPath));
  validateProviderRegistry(registry); return registry;
}

export function validateProviderRegistry(registry) {
  if (registry?.schemaVersion !== 1 || registry?.kind !== 'audit-provider-registry') throw new Error('provider registry must be audit-provider-registry schemaVersion=1');
  if (registry.discoveryOwner !== 'cortex') throw new Error('provider registry discoveryOwner must be cortex');
  if (!Array.isArray(registry.providers) || !registry.providers.length) throw new Error('provider registry must declare providers');
  const ids = new Set(); const checks = new Set();
  for (const provider of registry.providers) {
    if (!provider.id || ids.has(provider.id)) throw new Error(`duplicate or missing provider id: ${provider.id}`);
    ids.add(provider.id);
    if (!provider.selector?.op) throw new Error(`provider ${provider.id} has no selector`);
    if (!RUNNER_KINDS.has(provider.runner?.kind)) throw new Error(`provider ${provider.id} has unsupported runner kind ${provider.runner?.kind}`);
    if (provider.role === 'candidate-generator' && provider.mayCloseOwnCandidates !== false) throw new Error(`candidate generator ${provider.id} must set mayCloseOwnCandidates=false`);
    if (provider.runner.kind === 'legacy-check') {
      const check = provider.runner.check;
      if (!check || checks.has(check)) throw new Error(`duplicate or missing legacy check: ${check}`);
      checks.add(check);
      if (provider.manifest?.check !== check) throw new Error(`provider ${provider.id} manifest.check must equal runner.check`);
    }
  }
  for (const family of registry.coverageFamilies ?? []) {
    if (!family.id || ids.has(family.id)) throw new Error(`duplicate coverage family id: ${family.id}`);
    ids.add(family.id);
    if (!family.selector?.op) throw new Error(`coverage family ${family.id} has no selector`);
    for (const providerId of family.providers ?? []) {
      if (!registry.providers.some((provider) => provider.id === providerId)) throw new Error(`coverage family ${family.id} names unknown provider ${providerId}`);
    }
  }
  return registry;
}

function normalizePath(value) { return String(value ?? '').replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+$/, ''); }
function globToRegExp(pattern) {
  const normalized = normalizePath(pattern); let source = '^';
  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index]; const next = normalized[index + 1];
    if (char === '*' && next === '*') {
      const slash = normalized[index + 2] === '/'; source += slash ? '(?:.*/)?' : '.*'; index += slash ? 2 : 1;
    } else if (char === '*') source += '[^/]*';
    else if (char === '?') source += '[^/]';
    else source += char.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
  }
  return new RegExp(`${source}$`);
}
function pathMatches(path, patterns) { const normalized = normalizePath(path); return patterns.some((pattern) => globToRegExp(pattern).test(normalized)); }

export function buildSelectionContext(projection) {
  const files = [...new Set((projection?.files ?? []).map(normalizePath).filter(Boolean))].sort();
  const dependencies = new Set(); const packageScripts = new Set(); const dependencyEvidence = new Map(); const scriptEvidence = new Map();
  for (const record of projection?.auditFacts?.packageManifests ?? []) {
    for (const dependency of record.dependencies ?? []) {
      dependencies.add(dependency); if (!dependencyEvidence.has(dependency)) dependencyEvidence.set(dependency, []); dependencyEvidence.get(dependency).push(record.path);
    }
    for (const script of record.scripts ?? []) {
      packageScripts.add(script); if (!scriptEvidence.has(script)) scriptEvidence.set(script, []); scriptEvidence.get(script).push(record.path);
    }
  }
  const extensionToPaths = new Map();
  for (const path of files) {
    const base = path.split('/').at(-1) ?? path; const dot = base.lastIndexOf('.'); if (dot < 0) continue;
    const extension = base.slice(dot + 1).toLowerCase(); if (!extensionToPaths.has(extension)) extensionToPaths.set(extension, []); extensionToPaths.get(extension).push(path);
  }
  const parsed = new Set(projection?.parsedExtensions ?? []);
  const sourceFiles = files.filter((path) => { const base = path.split('/').at(-1) ?? path; const dot = base.lastIndexOf('.'); return dot >= 0 && parsed.has(base.slice(dot + 1).toLowerCase()); });
  return { ready: projection?.state === 'ready', files, fileSet: new Set(files), sourceFiles, sourceFileCount: sourceFiles.length, extensionToPaths, dependencies, dependencyEvidence, packageScripts, scriptEvidence };
}
function unionPaths(parts) { return [...new Set(parts.flatMap((part) => part.paths ?? []))].sort(); }
function sourceDenominator(context, evidencePaths) { return context.sourceFiles.length ? context.sourceFiles : evidencePaths; }

export function evaluateSelector(selector, context, selectedProviders = []) {
  const op = selector?.op;
  if (op === 'always') return { matched: true, paths: [], reason: 'always' };
  if (op === 'anyPath') { const paths = context.files.filter((path) => pathMatches(path, selector.patterns ?? [])); return { matched: paths.length > 0, paths, reason: paths.length ? 'path-match' : 'no-path-match' }; }
  if (op === 'anyExtension') { const paths = unionPaths((selector.extensions ?? []).map((extension) => ({ paths: context.extensionToPaths.get(String(extension).toLowerCase()) ?? [] }))); return { matched: paths.length > 0, paths, reason: paths.length ? 'extension-match' : 'no-extension-match' }; }
  if (op === 'anyDependency') {
    const names = selector.names ?? []; const matchedNames = names.filter((name) => context.dependencies.has(name));
    const evidencePaths = unionPaths(matchedNames.map((name) => ({ paths: context.dependencyEvidence.get(name) ?? [] })));
    const paths = matchedNames.length ? sourceDenominator(context, evidencePaths) : [];
    return { matched: matchedNames.length > 0, paths, reason: matchedNames.length ? `dependencies:${matchedNames.join(',')};manifest-evidence:${evidencePaths.join(',')}` : 'no-dependency-match' };
  }
  if (op === 'anyPackageScript') {
    const names = selector.names ?? []; const matchedNames = names.filter((name) => context.packageScripts.has(name));
    const evidencePaths = unionPaths(matchedNames.map((name) => ({ paths: context.scriptEvidence.get(name) ?? [] })));
    const paths = matchedNames.length ? sourceDenominator(context, evidencePaths) : [];
    return { matched: matchedNames.length > 0, paths, reason: matchedNames.length ? `scripts:${matchedNames.join(',')};manifest-evidence:${evidencePaths.join(',')}` : 'no-script-match' };
  }
  if (op === 'sourceFilesAtLeast') { const count = Number(selector.count ?? 1); return { matched: context.sourceFileCount >= count, paths: context.sourceFiles, reason: `source-files:${context.sourceFileCount}/${count}` }; }
  if (op === 'any' || op === 'all') { const parts = (selector.selectors ?? []).map((part) => evaluateSelector(part, context, selectedProviders)); const matched = op === 'any' ? parts.some((part) => part.matched) : parts.every((part) => part.matched); return { matched, paths: unionPaths(parts.filter((part) => part.matched)), reason: `${op}:${parts.map((part) => part.reason).join('|')}` }; }
  if (op === 'securityCandidatesSelected') { const candidates = selectedProviders.filter((provider) => provider.producesSecurityCandidates); return { matched: candidates.length > 0, paths: unionPaths(candidates.map((provider) => provider.denominator)), reason: `security-candidate-providers:${candidates.length}` }; }
  if (op === 'confirmedSecurityFinding') return { matched: false, paths: [], reason: 'runtime-trigger-only' };
  throw new Error(`unsupported provider selector op: ${op}`);
}
function denominator(paths, projection) {
  const normalized = [...new Set(paths.map(normalizePath))].sort();
  return normalized.length ? { source: 'cortex-selector', pathCount: normalized.length, pathDigest: sha256(normalized), paths: normalized } : { source: 'repository', pathCount: projection?.files?.length ?? 0, pathDigest: projection?.fileSetDigest ?? sha256([]) };
}

export function selectProviders(registry, projection, options = {}) {
  validateProviderRegistry(registry);
  const context = buildSelectionContext(projection); const only = new Set((options.only ?? []).filter(Boolean)); const skip = new Set((options.skip ?? []).filter(Boolean)); const selected = []; const excluded = [];
  for (const provider of registry.providers) {
    if (['securityCandidatesSelected', 'confirmedSecurityFinding'].includes(provider.selector.op)) continue;
    const check = provider.runner.kind === 'legacy-check' ? provider.runner.check : null;
    if (only.size && check && !only.has(check)) { excluded.push({ id: provider.id, check, reason: 'not-in-only-filter' }); continue; }
    if (check && skip.has(check)) { excluded.push({ id: provider.id, check, reason: 'skipped-by-request' }); continue; }
    if (!context.ready && !provider.allowWithoutCortex) { excluded.push({ id: provider.id, check, reason: 'cortex-unproven' }); continue; }
    const verdict = evaluateSelector(provider.selector, context, selected);
    if (!verdict.matched) { excluded.push({ id: provider.id, check, reason: verdict.reason }); continue; }
    selected.push({ ...provider, selectionReason: verdict.reason, denominator: denominator(verdict.paths, projection) });
  }
  const adjudicator = registry.providers.find((provider) => provider.id === 'security.adjudication'); let adjudicatorRecord = null;
  if (adjudicator) { const verdict = evaluateSelector(adjudicator.selector, context, selected); if (verdict.matched) { adjudicatorRecord = { ...adjudicator, selectionReason: verdict.reason, denominator: denominator(verdict.paths, projection) }; selected.push(adjudicatorRecord); } else excluded.push({ id: adjudicator.id, reason: verdict.reason }); }
  const variant = registry.providers.find((provider) => provider.id === 'security.variant-analysis');
  if (variant && adjudicatorRecord) selected.push({ ...variant, selectionReason: 'conditional-on-confirmed-security-finding', conditionalActivation: 'confirmed-security-finding', denominator: adjudicatorRecord.denominator });
  else if (variant) excluded.push({ id: variant.id, reason: 'no-security-adjudication-planned' });
  return { context, selected, excluded };
}

export function evaluateCoverageFamilies(registry, projection, selectedProviders) {
  const context = buildSelectionContext(projection); const selectedIds = new Set(selectedProviders.map((provider) => provider.id)); const families = []; const gaps = [];
  for (const family of registry.coverageFamilies ?? []) {
    const verdict = evaluateSelector(family.selector, context, selectedProviders); if (!verdict.matched) continue;
    const missingProviders = (family.providers ?? []).filter((id) => !selectedIds.has(id));
    const record = { id: family.id, kind: family.kind, qualification: family.qualification, providers: family.providers ?? [], missingProviders, denominator: denominator(verdict.paths, projection) };
    families.push(record);
    if (family.qualification !== 'complete' || missingProviders.length) gaps.push({ kind: 'provider-coverage', family: family.id, qualification: family.qualification, missingProviders, evidence: record.denominator });
  }
  return { families, gaps };
}
export function registryDigest(registry) { return sha256(registry); }

export function renderManifest(registry) {
  const checks = registry.providers.filter((provider) => provider.manifest?.check).map((provider) => ({
    provider: provider.id, check: provider.manifest.check, tool: provider.manifest.tool,
    required_when: provider.manifest.required_when, applies: provider.manifest.applies,
    parallel: provider.manifest.parallel, ...(provider.manifest.flag_if_absent ? { flag_if_absent: true } : {}),
    ...(provider.manifest.phase ? { phase: provider.manifest.phase } : {}), backs: provider.manifest.backs,
    benchmark_status: provider.benchmark?.status ?? 'unproven',
  }));
  const providers = registry.providers.map((provider) => ({
    id: provider.id, role: provider.role, phase: provider.phase, runner: provider.runner,
    benchmark_status: provider.benchmark?.status ?? 'unproven', required_for_clean_claim: Boolean(provider.benchmark?.requiredForCleanClaim),
    allow_without_cortex: Boolean(provider.allowWithoutCortex), produces_security_candidates: Boolean(provider.producesSecurityCandidates),
    fresh_context_required: Boolean(provider.freshContextRequired), may_close_own_candidates: provider.role === 'candidate-generator' ? false : provider.mayCloseOwnCandidates !== false,
  }));
  return {
    version: 3, generated_from: 'registry/providers.json', generated_sources: ['registry/providers.json', 'registry/providers-runtime.json'],
    discovery_owner: registry.discoveryOwner, concurrency: registry.concurrency,
    notes: 'Generated from the complete declarative provider registry. Scanner checks remain backward-compatible; providers mirrors every executable provider contract.',
    checks, providers,
  };
}
