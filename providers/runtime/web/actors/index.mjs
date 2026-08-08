import { denominator, digest, exactBinding, finalize, sameBinding, sortById } from '../shared.mjs';

const REQUIRED = ['role', 'tier', 'tenantId', 'accountState'];
const ACCOUNT_STATES = new Set(['active', 'disabled', 'expired', 'locked', 'revoked']);
const REFERENCE_TYPES = new Set(['vault', 'env', 'secret-manager', 'keychain']);
const reference = (value) => { if (value && typeof value === 'object' && REFERENCE_TYPES.has(value.type) && /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(value.id ?? '')) return { type: value.type, id: value.id }; if (typeof value !== 'string') return null; const match = /^([a-z-]+):\/\/([A-Za-z0-9][A-Za-z0-9._:/-]*)$/.exec(value); return match && REFERENCE_TYPES.has(match[1]) ? { type: match[1], id: match[2] } : null; };
const utcMillis = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null;
const freeze = (value) => { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; };
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;

export function buildActorFixtures({ binding = {}, actors = [], required = [], now = null, identityCapability = { status: 'available' }, environmentCapability = { status: 'available' } } = {}) {
  if (!Array.isArray(actors) || !Array.isArray(required)
    || actors.some((item) => !item || typeof item !== 'object' || Array.isArray(item)
      || (Array.isArray(item.transitionCapabilities) && item.transitionCapabilities.some((transition) => !transition || typeof transition !== 'object' || Array.isArray(transition))))
    || required.some((item) => !item || typeof item !== 'object' || Array.isArray(item))) return freeze(finalize('nemesis-web-actor-fixtures', { status: 'error', complete: false, proof: false, terminal: true, binding, actors: [], denominator: denominator([], []), coverageGaps: ['actor-collections-invalid'] }));
  const hostileIdentifier = (value) => ['symbol', 'bigint', 'function'].includes(typeof value) || typeof value === 'string' && value.length > 0 && !SAFE_IDENTIFIER.test(value);
  const identifiersHostile = actors.some((actor) => hostileIdentifier(actor.id) || ['identityId', 'credentialPolicyId', 'sessionPolicyId', 'role', 'tier', 'tenantId'].some((key) => hostileIdentifier(actor[key]))
    || Array.isArray(actor.serverAuthorizations) && actor.serverAuthorizations.some(hostileIdentifier)
    || Array.isArray(actor.uiVisibility) && actor.uiVisibility.some(hostileIdentifier)
    || Array.isArray(actor.transitionCapabilities) && actor.transitionCapabilities.some((item) => ['id', 'toActorId', 'fromTenantId', 'toTenantId', 'authorizationId'].some((key) => hostileIdentifier(item[key]))))
    || required.some((item) => REQUIRED.some((key) => hostileIdentifier(item[key])));
  if (identifiersHostile) return freeze(finalize('nemesis-web-actor-fixtures', { status: 'error', complete: false, proof: false, terminal: true, binding, actors: [], denominator: denominator([], []), coverageGaps: ['actor-identifiers-invalid'] }));
  const blocked = [];
  if (identityCapability?.status !== 'available') blocked.push(`identity-capability-${identityCapability?.status ?? 'missing'}`);
  if (environmentCapability?.status !== 'available') blocked.push(`environment-capability-${environmentCapability?.status ?? 'missing'}`);
  if (blocked.length) return freeze(finalize('nemesis-web-actor-fixtures', { status: 'blocked', complete: false, proof: false, terminal: true, binding, actors: [], denominator: denominator(required.map((item) => REQUIRED.map((key) => item[key]).join(':')), []), coverageGaps: blocked.sort() }));
  const sortedActors = sortById(actors);
  const normalized = sortedActors.map((actor) => ({
    id: actor.id, identityId: actor.identityId ?? null, credentialPolicyId: actor.credentialPolicyId ?? null, sessionPolicyId: actor.sessionPolicyId ?? null, role: actor.role, tier: actor.tier, tenantId: actor.tenantId, accountState: actor.accountState,
    credential: reference(actor.secretRef), issuedAt: actor.issuedAt ?? null, expiresAt: actor.expiresAt ?? null,
    revokedAt: actor.revokedAt ?? null, serverAuthorizations: Array.isArray(actor.serverAuthorizations) ? [...actor.serverAuthorizations].sort() : [],
    uiVisibility: Array.isArray(actor.uiVisibility) ? [...actor.uiVisibility].sort() : [], transitionCapabilities: Array.isArray(actor.transitionCapabilities) ? sortById(actor.transitionCapabilities).map((item) => ({ id: item.id, toActorId: item.toActorId, fromTenantId: item.fromTenantId, toTenantId: item.toTenantId, authorizationId: item.authorizationId })) : [], concurrencyKey: actor.concurrencyKey ?? `${actor.tenantId}:${actor.id}`,
  }));
  const expected = required.map((item) => REQUIRED.map((key) => item[key]).join(':'));
  const actual = normalized.map((item) => REQUIRED.map((key) => item[key]).join(':'));
  const receipts = actual.filter((id) => expected.includes(id)).map((id) => ({ id }));
  const gaps = [...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`)];
  if (now === null) gaps.push('actor-clock-unbound');
  if (required.length === 0) gaps.push('required-actor-denominator-empty');
  const actorIds = normalized.map((actor) => actor.id);
  for (const id of new Set(actorIds)) if (actorIds.filter((value) => value === id).length > 1) gaps.push(`actor-id-duplicate:${id}`);
  const transitionIds = normalized.flatMap((actor) => actor.transitionCapabilities.map((transition) => transition.id));
  for (const id of new Set(transitionIds)) if (transitionIds.filter((value) => value === id).length > 1) gaps.push(`actor-transition-id-duplicate:${id}`);
  for (const [actorIndex, actor] of normalized.entries()) {
    const sourceActor = sortedActors[actorIndex];
    for (const key of ['id', 'role', 'tier', 'tenantId', 'identityId', 'credentialPolicyId', 'sessionPolicyId']) if (typeof actor[key] !== 'string' || actor[key].length === 0) gaps.push(`actor-${key}-invalid:${actor.id}`);
    if (!ACCOUNT_STATES.has(actor.accountState)) gaps.push(`actor-accountState-invalid:${actor.id}`);
    for (const key of ['serverAuthorizations', 'uiVisibility', 'transitionCapabilities']) if (!Array.isArray(sourceActor[key])) gaps.push(`actor-${key}-invalid:${actor.id}`);
    if (actor.serverAuthorizations.some((item) => typeof item !== 'string' || !item)) gaps.push(`actor-serverAuthorizations-entry-invalid:${actor.id}`);
    if (actor.uiVisibility.some((item) => typeof item !== 'string' || !item)) gaps.push(`actor-uiVisibility-entry-invalid:${actor.id}`);
    if (!actor.credential) gaps.push(`credential-reference-invalid:${actor.id}`);
    const current = utcMillis(now), issued = actor.issuedAt === null ? null : utcMillis(actor.issuedAt), expires = actor.expiresAt === null ? null : utcMillis(actor.expiresAt), revoked = actor.revokedAt === null ? null : utcMillis(actor.revokedAt);
    if (now !== null && current === null) gaps.push(`credential-now-timestamp-invalid:${actor.id}`);
    for (const [key, raw, parsed] of [['issuedAt', actor.issuedAt, issued], ['expiresAt', actor.expiresAt, expires], ['revokedAt', actor.revokedAt, revoked]]) if (raw !== null && parsed === null) gaps.push(`credential-${key}-timestamp-invalid:${actor.id}`);
    if (actor.accountState === 'active' && actor.expiresAt === null) gaps.push(`credential-expiry-unbound:${actor.id}`);
    if (actor.accountState === 'active' && expires !== null && current !== null && expires <= current) gaps.push(`credential-expired:${actor.id}`);
    if (actor.accountState === 'revoked' && actor.revokedAt === null) gaps.push(`revocation-unbound:${actor.id}`);
    if (issued !== null && current !== null && issued > current) gaps.push(`credential-issued-in-future:${actor.id}`);
    if (revoked !== null && current !== null && revoked > current) gaps.push(`credential-revoked-in-future:${actor.id}`);
    if (issued !== null && expires !== null && issued > expires) gaps.push(`credential-issued-after-expiry:${actor.id}`);
    if (issued !== null && revoked !== null && issued > revoked) gaps.push(`credential-issued-after-revocation:${actor.id}`);
    if (expires !== null && revoked !== null && expires < revoked) gaps.push(`credential-revoked-after-expiry:${actor.id}`);
    for (const transition of actor.transitionCapabilities) {
      const target = normalized.find((candidate) => candidate.id === transition.toActorId);
      if (typeof transition.id !== 'string' || !transition.id || transition.fromTenantId !== actor.tenantId || !target || transition.toTenantId !== target?.tenantId || typeof transition.authorizationId !== 'string' || !transition.authorizationId) gaps.push(`actor-transition-invalid:${actor.id}:${transition.id ?? 'missing'}`);
      if (!actor.identityId || !target?.identityId || !actor.credentialPolicyId || actor.credentialPolicyId !== target?.credentialPolicyId || !actor.sessionPolicyId || actor.sessionPolicyId !== target?.sessionPolicyId) gaps.push(`actor-transition-policy-mismatch:${actor.id}:${transition.id ?? 'missing'}`);
      if (!actor.serverAuthorizations.includes(transition.authorizationId) || !target?.serverAuthorizations.includes(transition.authorizationId)) gaps.push(`actor-transition-authorization-ungranted:${actor.id}:${transition.id ?? 'missing'}`);
    }
  }
  const counts = denominator(expected, receipts);
  gaps.push(...counts.missing.map((id) => `actor-fixture-missing:${id}`));
  const status = gaps.length ? 'unproven' : 'pass';
  return freeze(finalize('nemesis-web-actor-fixtures', { status, complete: status === 'pass', proof: status === 'pass', terminal: true, binding, actors: normalized, denominator: counts, coverageGaps: [...new Set(gaps)].sort() }));
}

export function switchActor({ receipt, from, to, currentActorId, sessionBinding = {}, concurrentActorIds = [], transitionCapabilityId = null, serverAuthorization = null } = {}) {
  const { digest: receiptDigest, ...receiptBody } = receipt ?? {};
  if (!receiptDigest || digest(receiptBody) !== receiptDigest) return { status: 'blocked', reason: 'actor-fixture-digest-mismatch' };
  if (receipt.status !== 'pass' || receipt.terminal !== true || receipt.complete !== true || receipt.proof !== true || exactBinding(receipt.binding ?? {}).gaps.length > 0) return { status: 'blocked', reason: 'actor-fixture-proof-unproven' };
  const source = receipt?.actors?.find((actor) => actor.id === from);
  const target = receipt?.actors?.find((actor) => actor.id === to);
  if (!source) return { status: 'blocked', reason: 'source-actor-missing' };
  if (!target) return { status: 'blocked', reason: 'target-actor-missing' };
  if (currentActorId !== from) return { status: 'blocked', reason: 'current-actor-mismatch' };
  if (!sameBinding(receipt.binding ?? {}, sessionBinding) || sessionBinding.actorId !== from || sessionBinding.tenantId !== source.tenantId) return { status: 'blocked', reason: 'session-binding-mismatch' };
  if (source.accountState !== 'active') return { status: 'blocked', reason: 'source-actor-not-active' };
  const authorizationRequired = source.identityId !== target.identityId || target.tenantId !== source.tenantId || target.role !== source.role || target.accountState !== source.accountState;
  if (authorizationRequired) {
    const transition = source.transitionCapabilities?.find((item) => item.id === transitionCapabilityId && item.toActorId === to && item.fromTenantId === source.tenantId && item.toTenantId === target.tenantId);
    if (!transition) return { status: 'blocked', reason: target.tenantId !== source.tenantId ? 'cross-tenant-transition-capability-missing' : 'actor-transition-capability-missing' };
    if (!source.identityId || !target.identityId || !source.credentialPolicyId || source.credentialPolicyId !== target.credentialPolicyId || !source.sessionPolicyId || source.sessionPolicyId !== target.sessionPolicyId) return { status: 'blocked', reason: target.tenantId !== source.tenantId ? 'cross-tenant-transition-policy-mismatch' : 'actor-transition-policy-mismatch' };
    const authorizationBound = serverAuthorization?.kind === 'server-authorization-evidence' && serverAuthorization.transitionId === transition.id && serverAuthorization.controlId === transition.id && serverAuthorization.authorizationId === transition.authorizationId && serverAuthorization.fromActorId === from && serverAuthorization.toActorId === to && serverAuthorization.actorId === from && serverAuthorization.fromTenantId === source.tenantId && serverAuthorization.toTenantId === target.tenantId && serverAuthorization.tenantId === source.tenantId && serverAuthorization.fromAccountState === source.accountState && serverAuthorization.toAccountState === target.accountState && serverAuthorization.sessionPolicyId === source.sessionPolicyId && sameBinding(sessionBinding, serverAuthorization.sessionBinding ?? {});
    if (!authorizationBound || serverAuthorization.status !== 'pass' || serverAuthorization.terminal !== true || !sameBinding(receipt.binding ?? {}, serverAuthorization.binding ?? {}) || !source.serverAuthorizations.includes(transition.authorizationId) || !target.serverAuthorizations.includes(transition.authorizationId)) return { status: 'blocked', reason: target.tenantId !== source.tenantId ? 'cross-tenant-server-authorization-unproven' : 'actor-server-authorization-unproven' };
  }
  if (concurrentActorIds.includes(from)) return { status: 'blocked', reason: 'source-actor-concurrent-session-active' };
  if (target.accountState !== 'active') return { status: 'blocked', reason: 'target-actor-not-active' };
  return { status: 'pass', from, to, tenantId: target.tenantId, concurrencyKey: target.concurrencyKey, sessionBinding: { ...sessionBinding, actorId: to, tenantId: target.tenantId } };
}
