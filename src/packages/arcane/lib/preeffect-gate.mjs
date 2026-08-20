// Deliverable 6 — the PRE-EFFECT GATE.
//
// Arcane's canonical enforcement boundary names exactly what this gate checks:
//   "capability check, path ownership, effect-class authorization,
//    contract version, latitude class (EXACT/BOUNDED)"
// and exactly how it degrades:
//   "If the pre-effect gate is unavailable, mutation-bearing operations fail
//    closed; read-only operations may continue with a recorded
//    enforcement-health downgrade."
//
// It enforces contract requirements where governed execution applies & always
// refuses execution while unresolved questions remain.
//
// Two decisions worth stating, because both are places the legacy system got
// it wrong:
//
//   1. **Unavailability is not permission.** predecessor's dispatcher marked a
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
import { ulid } from './ids.mjs';

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
  const segments = p.split('/');
  const rx = segments.map((segment, index) => {
    const separator = index && segments[index - 1] !== '**' ? '/' : '';
    if (segment === '**') return `${separator}${index === segments.length - 1 ? '.*' : '(?:[^/]+/)*'}`;
    return `${separator}${segment.split(/(\*)/).map((part) => part === '*' ? '[^/]*' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('')}`;
  }).join('');
  return new RegExp(`^${rx}$`).test(t);
}

function matchesAny(patterns, target) {
  return (patterns ?? []).some((p) => pathMatches(p, target));
}

/**
 * Bring a host-supplied path into the same frame as `scope.own`.
 *
 * Contracts are authored with workspace-relative paths, but Write/Edit always
 * report an absolute `file_path`. Comparing the two directly made every owned
 * path look unowned, so `ARC_PATH_NOT_OWNED` denied every FILE_WRITE under
 * every sealed contract — the gate was closed against all work, not merely
 * against unauthorized work.
 *
 * A path outside the workspace is returned unchanged, so it still fails to
 * match `own[]` and is still denied. Traversal is unaffected: `pathMatches`
 * rejects any `..` segment after this runs.
 */
export function workspaceRelative(target, workspace) {
  const t = normalizePath(target);
  if (!workspace) return t;
  const root = normalizePath(workspace).replace(/\/$/, '');
  if (!root) return t;
  const prefix = `${root}/`;
  // Drive-letter case differs between the host payload and the contract.
  const same = t.slice(0, prefix.length).toLowerCase() === prefix.toLowerCase();
  return same ? t.slice(prefix.length) : t;
}

export class PreEffectGate {
  #policy;

  #capabilityStore;

  #authority;

  #clock;

  #enforcementMode;

  #approvalAuthority;

  /**
   * @param {object} deps
   * @param {object} deps.policy a PolicyEngine, or failClosedEngine(...)
   * @param {object|null} deps.capabilityStore S03's CapabilityStore
   * @param {object} deps.authorityLedger
   * @param {'enforcing'|'advisory'} [deps.enforcementMode] governs `authorize()`
   *   only — `evaluate()` is unaffected and always enforces. Default
   *   'enforcing' so nothing changes for existing callers. In 'advisory',
   *   `authorize()` still runs every real check and still mints a capability,
   *   but a check that would deny is not enforced — the denial is instead
   *   carried verbatim under `detail.wouldHaveDenied` and the response is
   *   `enforcementHealth: 'advisory'`, which ARC's enforcement ranking makes
   *   structurally unable to satisfy any claim level requiring read_only+.
   */
  constructor({ policy, capabilityStore, authorityLedger, approvalAuthority = null, clock = () => Date.now(), enforcementMode = 'enforcing' }) {
    this.#policy = policy;
    this.#capabilityStore = capabilityStore ?? null;
    this.#authority = authorityLedger;
    this.#clock = clock;
    this.#enforcementMode = enforcementMode;
    this.#approvalAuthority = approvalAuthority;
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
    const { capabilityId = null } = ctx ?? {};

    const chk = this.#runChecks(effectRequest, ctx);
    if (chk.hardFail) return chk.decision;
    if (chk.deny) return chk.deny;
    const { contract } = chk;

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
      workspace: ctx?.workspace,
      contractId: effectRequest.contractId,
      contractVersion: ctx?.expectedContractVersion ?? contract.version,
      contractDigest: ctx?.contractDigest,
      sourceRevision: effectRequest.sourceRevision,
      authority: this.#authority.current(ctx?.turnId)?.authority,
      turnId: ctx?.turnId,
      advisoryProfile: contract.advisoryProfile ?? null,
      // CapabilityStore compares `now` against an ISO `expiresAt` with `>=`.
      // Passing the raw epoch millis from #clock() would compare a number to a
      // string, which is always false — expiry would silently never fire.
      // Normalize at the seam.
      now: new Date(this.#clock()).toISOString(),
    });
    if (!capCall.allowed) return capCall;

    try {
      this.#capabilityStore.consume(capabilityId, { requestId: ctx?.requestId ?? null, now: new Date(this.#clock()).toISOString() });
    } catch (error) {
      return decision({ allowed: false, code: error.code ?? 'ARC_CAPABILITY_EXHAUSTED', message: error.message, detail: { capabilityId }, enforcementHealth: 'strong' });
    }
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

  /**
   * CONTRACT A — the capability mint authority. Runs the identical checks
   * `evaluate()` runs (steps 1-9, via `#runChecks`), then — where `evaluate()`
   * requires a capability to already exist — mints one itself, scoped to
   * exactly the validated fields, and immediately self-checks it through the
   * same `CapabilityStore.check()` a real effect would go through. This is
   * additive: `evaluate()` is untouched and remains the way to authorize an
   * effect against an already-issued capability.
   *
   * @returns {object} decision. On success, `detail.capabilityId` names a
   *   capability nobody supplied — Arcane minted it because the request
   *   passed every check.
   */
  authorize(effectRequest, ctx) {
    const chk = this.#runChecks(effectRequest, ctx);
    if (chk.hardFail) return chk.decision;
    if (chk.deny && this.#enforcementMode !== 'advisory') return chk.deny;
    const { contract } = chk;

    const workspace = ctx?.workspace ?? null;
    const destination = ctx?.destination ?? null;
    const targets = [effectRequest.target];
    if (TWO_PATH_EFFECTS.includes(effectRequest.effectClass) && destination) targets.push(destination);

    const limits = this.#policy.capabilityLimits();
    const nowMs = this.#clock();
    const nowIso = new Date(nowMs).toISOString();
    const expiresAt = limits.ttlSeconds ? new Date(nowMs + limits.ttlSeconds * 1000).toISOString() : null;
    const capabilityId = `cap_${ulid(nowMs)}`;

    this.#capabilityStore.issue({
      capabilityId,
      runId: effectRequest.runId,
      taskId: effectRequest.taskId,
      workspace,
      contractId: effectRequest.contractId,
      contractVersion: contract.version,
      contractDigest: ctx?.contractDigest,
      sourceRevision: effectRequest.sourceRevision,
      authority: this.#authority.current(ctx?.turnId)?.authority,
      turnId: ctx?.turnId,
      operation: effectRequest.operation,
      effectClass: effectRequest.effectClass,
      targets,
      policyDigest: this.#policy.digest,
      policyId: this.#policy.policyId,
      policyVersion: this.#policy.version,
      advisoryProfile: contract.advisoryProfile ?? null,
      approvalEvidence: chk.approvalEvidence,
      issuedAt: nowIso,
      expiresAt,
      maxUses: limits.maxUses ?? null,
    });

    // Self-check: a capability this method just minted must itself pass the
    // same binding checks a real effect would be held to. If it doesn't, the
    // mint is worthless and the decision must fail closed rather than hand
    // back a capability nobody could actually use.
    const selfCheck = this.#capabilityStore.check(capabilityId, {
      operation: effectRequest.operation,
      effectClass: effectRequest.effectClass,
      target: effectRequest.target,
      runId: effectRequest.runId,
      taskId: effectRequest.taskId,
      workspace,
      contractId: effectRequest.contractId,
      contractVersion: contract.version,
      contractDigest: ctx?.contractDigest,
      sourceRevision: effectRequest.sourceRevision,
      authority: this.#authority.current(ctx?.turnId)?.authority,
      turnId: ctx?.turnId,
      advisoryProfile: contract.advisoryProfile ?? null,
      now: nowIso,
    });
    if (!selfCheck.allowed) {
      return decision({
        allowed: false,
        code: selfCheck.code,
        message: `minted capability failed its own self-check: ${selfCheck.message}`,
        detail: { ...selfCheck.detail, capabilityId },
        enforcementHealth: 'unsupported',
      });
    }

    const detail = {
      contractId: chk.contract ? chk.contract.contractId : null,
      contractVersion: chk.contract ? chk.contract.version : null,
      effectClass: effectRequest.effectClass,
      target: effectRequest.target,
      latitude: effectRequest.latitude,
      capabilityId,
      policyId: this.#policy.policyId,
      policyDigest: this.#policy.digest,
    };

    if (chk.deny) {
      // Advisory mode: the real decision would have denied, but advisory
      // enforcement skips ENFORCING the deny, not the minting. The denial is
      // carried verbatim so nothing about it is silently lost.
      return decision({
        allowed: true,
        message: 'authorized under advisory enforcement; the underlying check would have denied',
        detail: {
          ...detail,
          wouldHaveDenied: { code: chk.deny.code, message: chk.deny.message, detail: chk.deny.detail },
        },
        enforcementHealth: 'advisory',
      });
    }

    return decision({ allowed: true, message: 'authorized', detail, enforcementHealth: 'strong' });
  }

  /**
   * Steps 1-9 of the pre-effect decision, shared by `evaluate()` and
   * `authorize()`. Mechanical extraction — no behavioural change to the
   * checks themselves.
   *
   * @returns {{hardFail:true, decision:object}} when enforcement could not
   *   even run (structural failure or gate unavailability) — never
   *   advisory-overridable, because there is nothing valid to mint from.
   * @returns {{hardFail:false, deny:object|null, contract:object|null}} when
   *   the checks ran to completion; `deny` is the first failing decision, or
   *   null when every check passed.
   */
  #runChecks(effectRequest, ctx) {
    const {
      contract = null,
      turnId,
      approvalDigest = null,
      destination = null,
      expectedContractVersion = null,
    } = ctx ?? {};

    // 1. Structure. A malformed request is refused before any policy is read —
    //    there is no point asking whether an unparseable thing is authorized.
    const structural = validateAgainst('effect-request-v1', effectRequest);
    if (!structural.valid) {
      return {
        hardFail: true,
        decision: decision({
          allowed: false,
          code: 'ARC_SCHEMA_INVALID',
          message: 'effect request does not satisfy effect-request-v1',
          detail: { issues: structural.issues },
        }),
      };
    }

    // 2. Enforcement availability. Mutation-bearing work fails closed.
    if (!this.available()) {
      return {
        hardFail: true,
        decision: decision({
          allowed: false,
          code: 'ARC_GATE_UNAVAILABLE',
          message: 'pre-effect gate unavailable; mutation-bearing operations fail closed',
          detail: {
            policy: Boolean(this.#policy && !this.#policy.failClosed),
            capabilityStore: Boolean(this.#capabilityStore),
            authorityLedger: Boolean(this.#authority),
            effectClass: effectRequest.effectClass,
          },
          enforcementHealth: 'unsupported',
        }),
      };
    }

    // 3. Authority — kernel-asserted for this turn, and the request's own
    //    `requestedBy` must agree with it rather than replace it.
    const auth = requireAuthority(this.#authority, turnId, ['alchemist', 'sage', 'oracle', 'legion'], {
      claimedAuthority: effectRequest.requestedBy,
      requirePerMessage: true,
    });
    if (!auth.allowed) return { hardFail: false, deny: auth, contract };

    // 4. G2 — no mutation without a contract.
    if (!contract) {
      return {
        hardFail: false,
        deny: decision({
          allowed: false,
          code: 'ARC_NO_CONTRACT',
          message: 'mutation requested with no execution contract (G2)',
          detail: { contractId: effectRequest.contractId, effectClass: effectRequest.effectClass },
        }),
        contract,
      };
    }

    // 5. Contract identity, version, and revision binding.
    if (contract.contractId !== effectRequest.contractId) {
      return {
        hardFail: false,
        deny: decision({
          allowed: false,
          code: 'ARC_CONTRACT_VERSION_MISMATCH',
          message: 'effect request names a different contract than the one supplied',
          detail: { requested: effectRequest.contractId, supplied: contract.contractId },
        }),
        contract,
      };
    }
    if (expectedContractVersion !== null && contract.version !== expectedContractVersion) {
      return {
        hardFail: false,
        deny: decision({
          allowed: false,
          code: 'ARC_CONTRACT_VERSION_MISMATCH',
          message: 'contract version does not match the version this effect was authorized against',
          detail: { expected: expectedContractVersion, actual: contract.version },
        }),
        contract,
      };
    }
    if (contract.sourceRevision !== effectRequest.sourceRevision) {
      return {
        hardFail: false,
        deny: decision({
          allowed: false,
          code: 'ARC_CONTRACT_VERSION_MISMATCH',
          message: 'effect request source revision does not match the contract it cites',
          detail: { request: effectRequest.sourceRevision, contract: contract.sourceRevision },
        }),
        contract,
      };
    }

    // 6. Open questions make a contract non-executable.
    if (Array.isArray(contract.openQuestions) && contract.openQuestions.length > 0) {
      return {
        hardFail: false,
        deny: decision({
          allowed: false,
          code: 'ARC_CONTRACT_NOT_EXECUTABLE',
          message: `contract ${contract.contractId} has ${contract.openQuestions.length} unresolved open question(s)`,
          detail: { openQuestions: contract.openQuestions.map((q) => q.id) },
        }),
        contract,
      };
    }

    // 7. Path ownership. Forbidden is checked first and wins outright — an
    //    overlapping own[] pattern must never be able to re-open a forbidden
    //    path.
    const root = ctx?.workspace ?? null;
    const paths = [{ which: 'target', value: workspaceRelative(effectRequest.target, root) }];
    if (TWO_PATH_EFFECTS.includes(effectRequest.effectClass) && destination) {
      paths.push({ which: 'destination', value: workspaceRelative(destination, root) });
    }
    for (const { which, value } of paths) {
      if (matchesAny(contract.scope.forbidden, value)) {
        return {
          hardFail: false,
          deny: decision({
            allowed: false,
            code: 'ARC_PATH_FORBIDDEN',
            message: `${which} path is in the contract's forbidden scope`,
            detail: { which, path: value, forbidden: [...contract.scope.forbidden] },
          }),
          contract,
        };
      }
      if (!matchesAny(contract.scope.own, value)) {
        return {
          hardFail: false,
          deny: decision({
            allowed: false,
            code: 'ARC_PATH_NOT_OWNED',
            message: `${which} path is not inside the contract's own[] scope`,
            detail: { which, path: value, own: [...contract.scope.own] },
          }),
          contract,
        };
      }
    }

    // 8. Effect-class authorization — the contract first (it is the narrower,
    //    task-specific grant), then policy (the global ceiling).
    if (!contract.authorizedEffectClasses.includes(effectRequest.effectClass)) {
      return {
        hardFail: false,
        deny: decision({
          allowed: false,
          code: 'ARC_EFFECT_CLASS_UNAUTHORIZED',
          message: `contract ${contract.contractId} does not authorize ${effectRequest.effectClass}`,
          detail: {
            deniedBy: 'contract',
            effectClass: effectRequest.effectClass,
            authorized: [...contract.authorizedEffectClasses],
          },
        }),
        contract,
      };
    }
    const advisoryProfile = contract.advisoryProfile ?? null;
    const deniedProfileField = advisoryProfile && effectRequest.effectClass === 'PUBLISH' && !advisoryProfile.publishAllowed
      ? 'publishAllowed'
      : advisoryProfile && isMutating(effectRequest.effectClass) && !advisoryProfile.mutationAllowed
        ? 'mutationAllowed'
        : null;
    if (deniedProfileField) {
      return {
        hardFail: false,
        deny: decision({
          allowed: false,
          code: 'ARC_PROFILE_EFFECT_FORBIDDEN',
          message: `advisory profile ${advisoryProfile.bundleId}/${advisoryProfile.profileId} forbids ${effectRequest.effectClass}`,
          detail: { deniedBy: 'advisory-profile', effectClass: effectRequest.effectClass, profileDigest: advisoryProfile.profileDigest, restriction: deniedProfileField },
        }),
        contract,
      };
    }
    // Approval is host-derived only. Ignore any digest carried by the caller;
    // only the injected host authority can mint & immediately consume evidence.
    let derivedApprovalDigest = null; let approvalEvidence = null;
    if (this.#policy.effectDecision(effectRequest.effectClass).code === 'ARC_APPROVAL_REQUIRED') {
      const approval = this.#approvalAuthority?.derive(effectRequest, ctx);
      if (!approval?.allowed) return { hardFail: false, deny: approval ?? decision({ allowed: false, code: 'ARC_APPROVAL_REQUIRED', message: 'required approval authority unavailable', detail: {} }), contract };
      derivedApprovalDigest = approval.detail.approvalDigest;
      approvalEvidence = approval.detail.evidence;
    }
    const policyCall = this.#policy.effectDecision(effectRequest.effectClass, { approvalDigest: derivedApprovalDigest });
    if (!policyCall.allowed) {
      return {
        hardFail: false,
        deny: decision({
          allowed: false,
          code: policyCall.code,
          message: policyCall.message,
          detail: { ...policyCall.detail, deniedBy: 'policy' },
          enforcementHealth: policyCall.enforcementHealth,
        }),
        contract,
      };
    }

    // 9. Latitude. The request's declared latitude must match the artifact unit
    //    the contract actually defines for that path. A path the contract owns
    //    but never named as an artifact can only be touched at BOUNDED
    //    latitude — claiming EXACT means claiming the contract fully determined
    //    content it never mentioned.
    const latitudeCall = this.#checkLatitude(contract, effectRequest);
    if (!latitudeCall.allowed) return { hardFail: false, deny: latitudeCall, contract };

    return { hardFail: false, deny: null, contract, approvalEvidence };
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
        message: 'read-only operation continuing with recorded degraded enforcement',
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
