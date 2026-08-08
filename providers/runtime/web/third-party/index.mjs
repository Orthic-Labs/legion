import { createHash, verify as verifySignature } from 'node:crypto';
import { isCanonicalBase64 } from '../../../../lib/platform/artifact-sanitize.mjs';
import { validateExternalEvidence } from '../../../../lib/platform/external/validate.mjs';
import { canonicalize, denominator, exactBinding, finalize, redact, sameBinding, sortById } from '../shared.mjs';

const utcMillis = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null;
const CONDITIONAL_PROVIDERS = Object.freeze(['analytics', 'commerce', 'email', 'payments']);
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;

function applicabilitySourceValid(source, binding) {
  if (source?.kind !== 'frozen-conditional-provider-applicability' || source.id !== 'web:conditional-providers' || !sameBinding(binding, source.binding ?? {}) || !Array.isArray(source.providers) || !source.providers.every((item) => item && typeof item === 'object' && !Array.isArray(item) && typeof item.id === 'string' && typeof item.applicable === 'boolean' && typeof item.reason === 'string')) return false;
  const providers = [...source.providers].sort((left, right) => String(left.id).localeCompare(String(right.id)));
  if (JSON.stringify(providers.map((item) => item.id)) !== JSON.stringify(CONDITIONAL_PROVIDERS) || providers.some((item) => item.applicable !== false || typeof item.reason !== 'string' || !item.reason)) return false;
  return source.digest === `sha256:${createHash('sha256').update(JSON.stringify(canonicalize(providers))).digest('hex')}`;
}

function signedNotApplicable(envelope, binding, trustedProducers) {
  const gaps = [];
  const trusted = trustedProducers.find((item) => item.id === envelope?.producer);
  let payload = null;
  if (!trusted || typeof envelope?.signedContent !== 'string' || typeof envelope?.signature !== 'string') gaps.push('signature-unproven');
  else if (!isCanonicalBase64(envelope.signature)) gaps.push('signature-noncanonical');
  else { try { if (!verifySignature(null, Buffer.from(envelope.signedContent), trusted.publicKey, Buffer.from(envelope.signature, 'base64'))) gaps.push('signature-invalid'); else payload = JSON.parse(envelope.signedContent); } catch { gaps.push('signature-invalid'); } }
  if (!payload || payload.status !== 'not-applicable' || typeof payload.provider !== 'string' || !payload.provider || typeof payload.reason !== 'string' || !payload.reason || !sameBinding(binding, payload.binding ?? {}) || payload.producer !== envelope?.producer) gaps.push('not-applicable-receipt-invalid');
  return { provider: payload?.provider ?? envelope?.provider, payload, valid: gaps.length === 0, gaps };
}

export function verifyThirdPartyExercise({ binding = {}, configuredProviders = [], applicableProviders = [], exercises = [], applicabilitySource = null, notApplicableReceipts = [], trustedProducers = [], now = null, maxAgeMs = null } = {}) {
  const collections = [configuredProviders, applicableProviders, exercises, notApplicableReceipts, trustedProducers];
  if (collections.some((items) => !Array.isArray(items)) || [configuredProviders, exercises, notApplicableReceipts, trustedProducers].some((items) => items.some((item) => !item || typeof item !== 'object' || Array.isArray(item)))) return finalize('nemesis-web-third-party-exercise', { status: 'error', terminal: true, claimLevel: 'external', suppliedOnly: true, networkAttempted: false, binding, denominator: denominator([], []), receipts: [], coverageGaps: [...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), 'third-party-collections-invalid'].sort() });
  const identifiers = [...applicableProviders, ...configuredProviders.flatMap((item) => [item.key, item.adapterId]), ...exercises.flatMap((item) => [item.adapterKey ?? item.provider, item.provider, item.producer].filter((value) => value !== undefined)), ...notApplicableReceipts.flatMap((item) => [item.provider, item.producer].filter((value) => value !== undefined)), ...trustedProducers.map((item) => item.id)];
  if (identifiers.some((id) => typeof id !== 'string' || !SAFE_IDENTIFIER.test(id))) return finalize('nemesis-web-third-party-exercise', { status: 'error', terminal: true, claimLevel: 'external', suppliedOnly: true, networkAttempted: false, binding, denominator: denominator([], []), receipts: [], coverageGaps: ['third-party-identifiers-invalid'] });
  const configKeys = configuredProviders.map((item) => item.key);
  const adapterIds = configuredProviders.map((item) => item.adapterId);
  const duplicateConfigKeys = [...new Set(configKeys.filter((key, index) => configKeys.indexOf(key) !== index))].sort();
  const duplicateAdapterIds = [...new Set(adapterIds.filter((id, index) => adapterIds.indexOf(id) !== index))].sort();
  const configured = duplicateConfigKeys.length || duplicateAdapterIds.length ? null : new Map(configuredProviders.map((item) => [item.key, item]));
  const sourceValid = applicabilitySourceValid(applicabilitySource, binding);
  const policyExcludes = (id) => sourceValid && applicabilitySource.providers.some((item) => item.id === id && item.applicable === false);
  const conditionalFallback = applicableProviders.length === 0 && configKeys.length === 0;
  const expected = conditionalFallback ? [...CONDITIONAL_PROVIDERS] : [...new Set([...applicableProviders, ...configKeys])].sort();
  const exclusions = notApplicableReceipts.map((item) => signedNotApplicable(item, binding, trustedProducers));
  const grouped = new Map();
  for (const exercise of exercises) {
    const key = exercise.adapterKey ?? exercise.provider;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(exercise);
  }
  const globalGaps = [];
  if (conditionalFallback && !applicabilitySource && !notApplicableReceipts.length) globalGaps.push('conditional-provider-applicability-source-missing');
  if (conditionalFallback && applicabilitySource && !sourceValid) globalGaps.push('conditional-provider-applicability-source-invalid');
  for (const id of configKeys.filter((key) => policyExcludes(key))) globalGaps.push(`provider-applicability-contradiction:${id}`);
  for (const exclusion of exclusions) for (const gap of exclusion.gaps) globalGaps.push(`provider-not-applicable-${gap}:${exclusion.provider ?? 'missing'}`);
  for (const exclusion of exclusions.filter((item) => item.valid && (applicableProviders.includes(item.provider) || configKeys.includes(item.provider)))) globalGaps.push(`provider-applicability-contradiction:${exclusion.provider}`);
  globalGaps.push(...duplicateConfigKeys.map((key) => `provider-config-key-duplicate:${key}`), ...duplicateAdapterIds.map((id) => `provider-config-adapter-duplicate:${id}`));
  for (const provider of configuredProviders) if (typeof provider.key !== 'string' || !provider.key || typeof provider.adapterId !== 'string' || !provider.adapterId) globalGaps.push('provider-config-invalid');
  const receipts = sortById(expected.flatMap((id) => {
    const matches = grouped.get(id) ?? [];
    if (!matches.length) {
      const exclusion = exclusions.find((item) => item.provider === id && item.valid && !applicableProviders.includes(id) && !configKeys.includes(id));
      if (exclusion) return [{ id, provider: id, status: 'unsupported', terminal: true, reason: exclusion.payload.reason, applicabilityEvidence: 'signed-not-applicable-receipt', coverageGaps: [] }];
      if (sourceValid && policyExcludes(id) && !configKeys.includes(id)) return [{ id, provider: id, status: 'unsupported', terminal: true, reason: applicabilitySource.providers.find((item) => item.id === id).reason, applicabilityEvidence: applicabilitySource.id, coverageGaps: [] }];
      return [];
    }
    const raw = matches[0];
    const provider = configured?.get(id);
    const validation = validateExternalEvidence(raw, {
      trustedProducers,
      scope: 'third-party',
      targetId: binding.targetId,
      environment: provider?.environment ?? raw.environment,
      artifactDigest: binding.artifactDigest,
      controlId: id,
      binding,
      requiresExercise: true,
      now,
      maxAgeMs,
    });
    const source = validation.payload ?? raw;
    const item = { id, ...redact(source) };
    const gaps = [...validation.gaps];
    if (!provider) gaps.push('provider-not-configured');
    if (!raw.adapterKey) gaps.push('adapter-key-missing');
    if (source.adapterKey !== id) gaps.push('adapter-key-mismatch');
    if (source.provider !== id) { gaps.push('provider-identity-spoof'); globalGaps.push(`provider-identity-spoof:${id}`); }
    if (provider?.producerId && source.producer !== provider.producerId) gaps.push('producer-config-mismatch');
    if (matches.length > 1) { gaps.push('provider-duplicate'); globalGaps.push(`provider-duplicate:${id}`); }
    if (!['sandbox', 'test'].includes(item.environment)) gaps.push('non-test-environment');
    for (const key of ['client', 'backend', 'providerState', 'userState', 'consent', 'webhook', 'idempotency', 'quota', 'cost']) if (item[key] === undefined || item[key] === null) gaps.push(`missing-${key}`);
    if (!sameBinding(binding, item.binding ?? {})) gaps.push('binding-mismatch');
    const issued = utcMillis(raw.issuedAt), checked = utcMillis(raw.checkedAt), expires = utcMillis(raw.expiresAt), current = utcMillis(now);
    for (const [key, value] of [['issuedAt', issued], ['checkedAt', checked], ['expiresAt', expires], ['now', current]]) if (value === null) gaps.push(`${key}-timestamp-invalid`);
    if (checked !== null && current !== null && checked > current) gaps.push('checked-in-future');
    if (current !== null && expires !== null && current > expires) gaps.push('evidence-expired');
    if (checked !== null && current !== null && Number.isFinite(maxAgeMs) && current - checked > maxAgeMs) gaps.push('evidence-stale');
    if (new Set([item.client, item.backend, item.providerState, item.userState].map((value) => JSON.stringify(canonicalize(value)))).size !== 1) gaps.push('state-divergence');
    for (const key of ['consent', 'webhook', 'idempotency']) if (item[key] !== true) gaps.push(`${key}-unproven`);
    return [{ ...item, provider: id, adapterId: provider?.adapterId ?? null, status: gaps.length ? 'unproven' : 'pass', terminal: true, coverageGaps: [...new Set(gaps)].sort() }];
  }));
  const counts = denominator(expected, receipts);
  const unplanned = [...grouped.keys()].filter((id) => !expected.includes(id)).sort();
  const gaps = [...globalGaps, ...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), ...counts.missing.map((id) => `provider-missing:${id}`), ...unplanned.map((id) => `provider-unplanned:${id}`), ...receipts.flatMap((item) => item.coverageGaps.map((gap) => `${item.id}:${gap}`))];
  return finalize('nemesis-web-third-party-exercise', { status: gaps.length ? 'unproven' : 'pass', terminal: true, claimLevel: 'external', suppliedOnly: true, networkAttempted: false, binding, denominator: counts, receipts, coverageGaps: [...new Set(gaps)].sort() });
}
