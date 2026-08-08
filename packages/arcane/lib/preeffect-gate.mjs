// Deliverable 6 — the PRE-EFFECT GATE.
//
// ARCHITECTURE §24a names exactly what this gate checks:
//   "capability check, path ownership, effect-class authorization,
//    contract version, latitude class (EXACT/BOUNDED)"
// and exactly how it degrades:
//   "If the pre-effect gate is unavailable, mutation-bearing operations fail
//    closed; read-only operations may continue with a recorded
//    enforcement-health downgrade."
//
// It is the enforcement point for G2 (no product-state mutation without a
// bounded executable contract) and G9 (open questions make a contract
// non-executable).
//
// Two decisions worth stating, because both are places the legacy system got
// it wrong:
//
//   1. **Unavailability is not permission.** Forge's dispatcher marked a
//      verifier that blew its 1500ms budget as `bypassed_delayed_verifier` and
//      then CONTINUED (S00: lib/dispatcher.js:29-37). Enforcement was skipped
//      on a stopwatch. Here, an unavailable gate denies every mutation, and
//      the policy bundle has no representable value meaning "allow on
//      degradation".
//   2. **The gate holds no policy of its own.** Every allow/deny threshold
//      comes from lib/policy.mjs. This module contributes ordering, path
//      arithmetic, and contract arithmetic — never a rule. That is what makes
//      "changing a valid policy changes runtime behavior without code edits"
//      true rather than aspirational.
//
// Check order is deliberate: cheapest and most structural first, so a
// malformed request never reaches policy, and a request with no authority
// never reaches the capability store.

import { decision } from './errors.mjs';
import { validateAgainst } from './validate.mjs';
import { requireAuthority } from './authority.mjs';

/**
 * Every value in the frozen EFFECT_CLASS enum either mutates product state or
 * may do so (COMMAND_EXEC is a carrier; NETWORK_EGRESS leaves the machine).
 * There is no read class to exclude — which is precisely why FILE_READ is a
 * proposed amendment (see EFFECT_CLASS_RECONCILIATION in lib/policy.mjs).
 *
 * Read-only work therefore does NOT arrive as an effect request at all; it
 * goes through `evaluateReadOnly`. Read-only-ness is a property of the call
 * site, never something inferred from a tool name inside a request.
 */
export const MUTATING_EFFECT_CLASSES = Object.freeze([
  'FILE_WRITE', 'FILE_DELETE', 'FILE_MOVE', 'COMMAND_EXEC', 'NETWORK_EGRESS',
  'PROCESS_SPAWN', 'CREDENTIAL_ACCESS', 'DEPENDENCY_INSTALL', 'VCS_COMMIT',
  'VCS_PUSH', 'PUBLISH', 'EXTERNAL_SIDE_EFFECT',
]);

export function isMutating(effectClass) {
  return MUTATING_EFFECT_CLASSES.includes(effectClass);
}

/** Effect classes whose request carries a second path that must also be owned. */
const TWO_PATH_EFFECTS = Object.freeze(['FILE_MOVE']);

function normalizePath(p) {
  return String(p).replaceAll('\\', '/').replace(/\/{2,}/g, '/');
}

/**
 * Glob matching for scope patterns.
 *
 * Supported: `**` (any number of segments), `*` (within one segment), a
 * trailing `/` (directory prefix), and literal paths. Deliberately small —
 * a scope pattern language with surprises in it is an ownership bug waiting
 * to happen.
 *
 * A target containing a `..` segment never matches anything: path traversal
 * must not be able to walk out of an owned prefix while still matching it.
 */
export function pathMatches(pattern, target) {
  const t = normalizePath(target);
  if (t.split('/').includes('..')) return false;
  let p = normalizePath(pattern);
  if (p.endsWith('/')) p = `${p}**`;

  const rx = p
    .split(/(\*\*|\*)/)
    .map((part) => {
      if (part === '**') return '.*';
      if (part === '*') return '[^/]*';
      return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('');
  return new RegExp(`^${rx}$`).test(t);
}

function matchesAny(patterns, target) {
  return (patterns ?? []).some((p) => pathMatches(p, target));
}

export class PreEffectGate {
  #policy;

  #capabilityStore;

  #authority;

  #clock;

  /**
   * @param {object} deps
   * @param {object} deps.policy a PolicyEngine, or failClosedEngine(...)
   * @param {object|null} deps.capabilityStore S03's CapabilityStore
   * @param {object} deps.authorityLedger
   */
  constructor({ policy, capabilityStore, authorityLedger, clock = () => Date.now() }) {
    this.#policy = policy;
    this.#capabilityStore = capabilityStore ?? null;
    this.#authority = authorityLedger;
    this.#clock = clock;
  }

  /** True when the gate can actually enforce. */
  available() {
    return Boolean(this.#policy && !this.#policy.failClosed && this.#capabilityStore && this.#authority);
  }

  /**
   * The pre-effect decision.
   *
   * @param {object} effectRequest an `effect-request-v1` instance
   * @param {object} ctx
   * @param {object|null} ctx.contract an `execution-contract-v1` instance
   * @param {string} ctx.turnId
   * @param {string|null} ctx.capabilityId
   * @param {string|null} [ctx.approvalDigest]
   * @param {string|null} [ctx.destination] second path for FILE_MOVE
   * @param {number} [ctx.expectedContractVersion]
   * @returns {object} decision
   */
  evaluate(effectRequest, ctx) {
    const {
      contract = null,
      turnId,
      capabilityId = null,
      approvalDigest = null,
      destination = null,
      expectedContractVersion = null,
    } = ctx ?? {};

    // 1. Structure. A malformed request is refused before any policy is read —
    //    there is no point asking whether an unparseable thing is authorized.
    const structural = validateAgainst('effect-request-v1', effectRequest);
    if (!structural.valid) {
      return decision({
        allowed: false,
        code: 'ARC_SCHEMA_INVALID',
        message: 'effect request does not satisfy effect-request-v1',
        detail: { issues: structural.issues },
      });
    }

    // 2. Enforcement availability. Mutation-bearing work fails closed.
    if (!this.available()) {
      return decision({
        allowed: false,
        code: 'ARC_GATE_UNAVAILABLE',
        message: 'pre-effect gate unavailable; mutation-bearing operations fail closed (ARCHITECTURE §24a)',
        detail: {
          policy: Boolean(this.#policy && !this.#policy.failClosed),
          capabilityStore: Boolean(this.#capabilityStore),
          authorityLedger: Boolean(this.#authority),
          effectClass: effectRequest.effectClass,
        },
        enforcementHealth: 'unsupported',
      });
    }

    // 3. Authority — kernel-asserted for this turn, and the request's own
    //    `requestedBy` must agree with it rather than replace it.
    const auth = requireAuthority(this.#authority, turnId, ['alchemist', 'sage', 'seer', 'legion'], {
      claimedAuthority: effectRequest.requestedBy,
      requirePerMessage: true,
    });
    if (!auth.allowed) return auth;

    // 4. G2 — no mutation without a contract.
    if (!contract) {
      return decision({
        allowed: false,
        code: 'ARC_NO_CONTRACT',
        message: 'mutation requested with no execution contract (G2)',
        detail: { contractId: effectRequest.contractId, effectClass: effectRequest.effectClass },
      });
    }

    // 5. Contract identity, version, and revision binding.
    if (contract.contractId !== effectRequest.contractId) {
      return decision({
        allowed: false,
        code: 'ARC_CONTRACT_VERSION_MISMATCH',
        message: 'effect request names a different contract than the one supplied',
        detail: { requested: effectRequest.contractId, supplied: contract.contractId },
      });
    }
    if (expectedContractVersion !== null && contract.version !== expectedContractVersion) {
      return decision({
        allowed: false,
        code: 'ARC_CONTRACT_VERSION_MISMATCH',
        message: 'contract version does not match the version this effect was authorized against',
        detail: { expected: expectedContractVersion, actual: contract.version },
      });
    }
    if (contract.sourceRevision !== effectRequest.sourceRevision) {
      return decision({
        allowed: false,
        code: 'ARC_CONTRACT_VERSION_MISMATCH',
        message: 'effect request source revision does not match the contract it cites',
        detail: { request: effectRequest.sourceRevision, contract: contract.sourceRevision },
      });
    }

    // 6. G9 — open questions make a contract non-executable.
    if (Array.isArray(contract.openQuestions) && contract.openQuestions.length > 0) {
      return decision({
        allowed: false,
        code: 'ARC_CONTRACT_NOT_EXECUTABLE',
        message: `contract ${contract.contractId} has ${contract.openQuestions.length} open question(s) (G9)`,
        detail: { openQuestions: contract.openQuestions.map((q) => q.id) },
      });
    }

    // 7. Path ownership. Forbidden is checked first and wins outright — an
    //    overlapping own[] pattern must never be able to re-open a forbidden
    //    path.
    const paths = [{ which: 'target', value: effectRequest.target }];
    if (TWO_PATH_EFFECTS.includes(effectRequest.effectClass) && destination) {
      paths.push({ which: 'destination', value: destination });
    }
    for (const { which, value } of paths) {
      if (matchesAny(contract.scope.forbidden, value)) {
        return decision({
          allowed: false,
          code: 'ARC_PATH_FORBIDDEN',
          message: `${which} path is in the contract's forbidden scope`,
          detail: { which, path: value, forbidden: [...contract.scope.forbidden] },
        });
      }
      if (!matchesAny(contract.scope.own, value)) {
        return decision({
          allowed: false,
          code: 'ARC_PATH_NOT_OWNED',
          message: `${which} path is not inside the contract's own[] scope`,
          detail: { which, path: value, own: [...contract.scope.own] },
        });
      }
    }

    // 8. Effect-class authorization — the contract first (it is the narrower,
    //    task-specific grant), then policy (the global ceiling).
    if (!contract.authorizedEffectClasses.includes(effectRequest.effectClass)) {
      return decision({
        allowed: false,
        code: 'ARC_EFFECT_CLASS_UNAUTHORIZED',
        message: `contract ${contract.contractId} does not authorize ${effectRequest.effectClass}`,
        detail: {
          deniedBy: 'contract',
          effectClass: effectRequest.effectClass,
          authorized: [...contract.authorizedEffectClasses],
        },
      });
    }
    const policyCall = this.#policy.effectDecision(effectRequest.effectClass, { approvalDigest });
    if (!policyCall.allowed) {
      return decision({
        allowed: false,
        code: policyCall.code,
        message: policyCall.message,
        detail: { ...policyCall.detail, deniedBy: 'policy' },
        enforcementHealth: policyCall.enforcementHealth,
      });
    }

    // 9. Latitude. The request's declared latitude must match the artifact unit
    //    the contract actually defines for that path. A path the contract owns
    //    but never named as an artifact can only be touched at BOUNDED
    //    latitude — claiming EXACT means claiming the contract fully determined
    //    content it never mentioned.
    const latitudeCall = this.#checkLatitude(contract, effectRequest);
    if (!latitudeCall.allowed) return latitudeCall;

    // 10. Capability.
    if (!capabilityId) {
      return decision({
        allowed: false,
        code: 'ARC_CAPABILITY_UNKNOWN',
        message: 'mutation requires an Arcane-issued capability',
        detail: { effectClass: effectRequest.effectClass },
      });
    }
    const capCall = this.#capabilityStore.check(capabilityId, {
      operation: effectRequest.operation,
      effectClass: effectRequest.effectClass,
      target: effectRequest.target,
      runId: effectRequest.runId,
      taskId: effectRequest.taskId,
      // CapabilityStore compares `now` against an ISO `expiresAt` with `>=`.
      // Passing the raw epoch millis from #clock() would compare a number to a
      // string, which is always false — expiry would silently never fire.
      // Normalize at the seam.
      now: new Date(this.#clock()).toISOString(),
    });
    if (!capCall.allowed) return capCall;

    return decision({
      allowed: true,
      message: 'authorized',
      detail: {
        contractId: contract.contractId,
        contractVersion: contract.version,
        effectClass: effectRequest.effectClass,
        target: effectRequest.target,
        latitude: effectRequest.latitude,
        capabilityId,
        policyId: this.#policy.policyId,
        policyDigest: this.#policy.digest,
      },
      enforcementHealth: 'strong',
    });
  }

  #checkLatitude(contract, effectRequest) {
    const exact = contract.artifacts.exact.find((a) => normalizePath(a.path) === normalizePath(effectRequest.target));
    const bounded = contract.artifacts.bounded.find((a) => normalizePath(a.path) === normalizePath(effectRequest.target));
    const declared = exact ? 'EXACT' : bounded ? 'BOUNDED' : null;

    if (declared === null) {
      if (effectRequest.latitude === 'BOUNDED') {
        // Owned but unnamed: mechanical work inside scope, no artifact promise.
        return decision({ allowed: true, detail: { latitude: 'BOUNDED', artifact: null } });
      }
      return decision({
        allowed: false,
        code: 'ARC_LATITUDE_VIOLATION',
        message: 'EXACT latitude claimed for a path the contract declares no artifact unit for',
        detail: { target: effectRequest.target, requested: effectRequest.latitude, declared: null },
      });
    }
    if (declared !== effectRequest.latitude) {
      return decision({
        allowed: false,
        code: 'ARC_LATITUDE_VIOLATION',
        message: `contract declares ${declared} latitude for this artifact; request claims ${effectRequest.latitude}`,
        detail: {
          target: effectRequest.target,
          requested: effectRequest.latitude,
          declared,
          artifactId: (exact ?? bounded).id,
        },
      });
    }
    return decision({ allowed: true, detail: { latitude: declared, artifact: (exact ?? bounded).id } });
  }

  /**
   * The read-only path. §24a permits read-only operations to continue when the
   * gate is unavailable, provided the downgrade is *recorded* — so this returns
   * an allow whose enforcementHealth is honestly reduced and whose detail says
   * `degraded: true`. A caller that logs the decision cannot later claim strong
   * enforcement over the window in which this ran.
   */
  evaluateReadOnly({ target, turnId, contract = null }) {
    if (!this.available()) {
      return decision({
        allowed: true,
        message: 'read-only operation continuing with degraded enforcement (ARCHITECTURE §24a)',
        detail: { target, turnId, degraded: true, reason: this.#policy?.reason ?? 'gate unavailable' },
        enforcementHealth: 'read_only',
      });
    }
    if (contract && matchesAny(contract.scope.forbidden, target)) {
      return decision({
        allowed: false,
        code: 'ARC_PATH_FORBIDDEN',
        message: 'read target is in the contract\'s forbidden scope',
        detail: { target },
      });
    }
    return decision({
      allowed: true,
      detail: { target, turnId, degraded: false },
      enforcementHealth: 'strong',
    });
  }

  /** Per-capability enforcement health, reported honestly and typed (§24a). */
  health() {
    return Object.freeze({
      policy: this.#policy && !this.#policy.failClosed ? 'strong' : 'unsupported',
      capability: this.#capabilityStore ? 'strong' : 'unsupported',
      authority: this.#authority ? 'strong' : 'unsupported',
      overall: this.available() ? 'strong' : 'unsupported',
    });
  }
}
