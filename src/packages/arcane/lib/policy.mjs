// S02 — the policy plane. Arcane's single source of allow/deny.
//
// S02's acceptance criteria are really one property stated four ways: policy
// must live in data, in exactly one place, and be unable to fail open.
//
//   - "changing a valid policy changes runtime behavior without code edits"
//     -> every limit, rule, and threshold is read from the bundle at call time.
//   - "malformed/unknown policy fields fail closed for protected operations"
//     -> the bundle schema is additionalProperties:false throughout, and a
//        validation failure throws a failClosed ArcaneError rather than
//        yielding a partially-understood engine.
//   - "model/API payload cannot set trusted authority" -> lib/authority.mjs.
//   - "adapters do not contain divergent allow/deny logic" ->
//     policyDuplicationAudit(), asserted over the adapter modules in tests.
//
// Note the shape of `degradation`: its schema admits only 'fail-closed' and
// 'downgrade'. There is no representable value meaning "allow". That is the
// deliberate divergence from predecessor, whose dispatcher continued past a
// timed-out verifier (S00: lib/dispatcher.js:29-37) — enforcement skipped on a
// stopwatch.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ArcaneError, decision } from './errors.mjs';
import { digestValue } from './canonical.mjs';
import { validateSchema } from '../../../lib/qualification/schema-validator.mjs';
import { pathMatches } from './preeffect-gate.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const policyDir = path.join(path.dirname(here), 'policy');

export const DEFAULT_POLICY_PATH = path.join(policyDir, 'arcane-policy-v1.json');
const BUNDLE_SCHEMA = JSON.parse(readFileSync(path.join(policyDir, 'policy-bundle-v1.schema.json'), 'utf8'));

/** Structural validation of a policy bundle. */
export function validatePolicyBundle(bundle) {
  const issues = validateSchema(BUNDLE_SCHEMA, bundle);
  return { valid: issues.length === 0, issues };
}

/**
 * Read and validate a bundle from disk.
 * @returns {{bundle: object, policyId: string, version: number, digest: string}}
 */
export function loadPolicy({ path: bundlePath = DEFAULT_POLICY_PATH } = {}) {
  let raw;
  try {
    raw = readFileSync(bundlePath, 'utf8');
  } catch (err) {
    throw new ArcaneError('ARC_POLICY_UNAVAILABLE', `policy bundle unreadable: ${bundlePath}`, {
      path: bundlePath,
      cause: err.code ?? String(err),
    });
  }
  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch (err) {
    throw new ArcaneError('ARC_POLICY_MALFORMED', `policy bundle is not valid JSON: ${bundlePath}`, {
      path: bundlePath,
      cause: String(err.message ?? err),
    });
  }
  const { valid, issues } = validatePolicyBundle(bundle);
  if (!valid) {
    throw new ArcaneError('ARC_POLICY_MALFORMED', `policy bundle failed validation: ${bundlePath}`, {
      path: bundlePath,
      issues,
    });
  }
  return {
    bundle,
    policyId: bundle.policyId,
    version: bundle.version,
    // Digest over the canonical form, so formatting changes do not churn the
    // identity that gets bound into every capability and receipt.
    digest: digestValue(bundle),
  };
}

export class PolicyEngine {
  #bundle;

  #rules;

  #approvalRequired;

  policyId;

  version;

  digest;

  /**
   * @throws {ArcaneError} ARC_POLICY_UNKNOWN_FIELD / ARC_POLICY_MALFORMED
   *   (both failClosed) when the bundle does not validate. Constructing a
   *   partially-understood engine is not an option: a policy Arcane cannot
   *   fully read must not authorize a mutation.
   */
  constructor({ bundle, policyId, version, digest }) {
    const { valid, issues } = validatePolicyBundle(bundle);
    if (!valid) {
      const unknownField = issues.some((i) => /additional-property/.test(i));
      throw new ArcaneError(
        unknownField ? 'ARC_POLICY_UNKNOWN_FIELD' : 'ARC_POLICY_MALFORMED',
        unknownField
          ? 'policy bundle declares a field Arcane does not understand'
          : 'policy bundle is structurally invalid',
        { issues },
      );
    }
    this.#bundle = bundle;
    this.#rules = new Map(bundle.effectRules.map((r) => [r.effectClass, r]));
    this.#approvalRequired = Object.freeze(bundle.effectRules.filter((rule) => rule.approvalRequired).map((rule) => rule.effectClass));
    this.policyId = policyId;
    this.version = version;
    this.digest = digest;
  }

  get bundle() {
    return this.#bundle;
  }

  /** The rule for an effect class, or null when the bundle does not name it. */
  effectRule(effectClass) {
    return this.#rules.get(effectClass) ?? null;
  }

  approvalRequiredEffectClasses() {
    return this.#approvalRequired;
  }

  /**
   * Should this effect class be authorized at all?
   * Path ownership and latitude are the gate's job — this answers only the
   * class-level question plus its approval requirement.
   */
  effectDecision(effectClass, { approvalDigest = null } = {}) {
    const rule = this.effectRule(effectClass);
    if (!rule) {
      // unclassifiedEffect is pinned to 'deny' by the bundle schema.
      return decision({
        allowed: false,
        code: 'ARC_EFFECT_CLASS_UNAUTHORIZED',
        message: `no policy rule for effect class '${effectClass}'; unclassified effects are denied by name, never bucketed`,
        detail: { effectClass, unclassifiedEffect: this.#bundle.unclassifiedEffect },
      });
    }
    if (rule.rule === 'deny') {
      return decision({
        allowed: false,
        code: 'ARC_EFFECT_CLASS_UNAUTHORIZED',
        message: `policy ${this.policyId} v${this.version} denies ${effectClass}`,
        detail: { effectClass, rule: rule.rule },
      });
    }
    if (rule.approvalRequired && !approvalDigest) {
      return decision({
        allowed: false,
        code: 'ARC_APPROVAL_REQUIRED',
        message: `${effectClass} requires a bound approval digest`,
        detail: { effectClass },
      });
    }
    return decision({
      allowed: true,
      detail: {
        effectClass,
        trustMinimum: rule.trustMinimum,
        requiredEnforcement: rule.requiredEnforcement,
      },
    });
  }

  capabilityLimits() {
    return { ...this.#bundle.capability };
  }

  replayLimits() {
    return { ...this.#bundle.replay };
  }

  trustMinima() {
    return { ...this.#bundle.trustMinima };
  }

  hostEnforcement() {
    return { ...this.#bundle.hostEnforcement };
  }

  claimLevel(name) {
    return this.#bundle.claimLevels[name] ?? null;
  }

  /**
   * S02 (locked domains) — pure lookup of which claim levels a set of touched
   * paths force, per the bundle's `lockedDomains`. Reuses `pathMatches` from
   * the pre-effect gate rather than reimplementing glob matching, which is
   * exactly the duplication `policyDuplicationAudit` now also guards against.
   */
  lockedDomainsFor(paths) {
    const locked = this.#bundle.lockedDomains ?? [];
    const matches = [];
    for (const p of paths ?? []) {
      for (const entry of locked) {
        if (pathMatches(entry.pattern, p)) {
          matches.push({ path: p, pattern: entry.pattern, claimLevel: entry.claimLevel, note: entry.note ?? null });
        }
      }
    }
    return matches;
  }

  /** 'fail-closed' | 'downgrade'. Never 'allow' — not a representable value. */
  degradation(capability) {
    return this.#bundle.degradation[capability] ?? 'fail-closed';
  }

  evidencePolicy() {
    return { ...this.#bundle.evidence };
  }

  retentionPolicy() {
    return { ...this.#bundle.retention };
  }

  /** May `authority` waive a claim prerequisite? */
  mayWaive(authority) {
    if (this.#bundle.waiverAuthority.includes(authority)) {
      return decision({ allowed: true, detail: { authority } });
    }
    return decision({
      allowed: false,
      code: 'ARC_CLAIM_PREREQUISITE_UNMET',
      message: `authority '${authority}' is not a waiver authority under ${this.policyId}`,
      detail: { authority, waiverAuthority: [...this.#bundle.waiverAuthority] },
    });
  }

  /**
   * S02 deliverable: claim-prerequisite evaluation.
   *
   * Arcane does not invent claims and does not decide their engineering
   * meaning (ARCHITECTURE §25/§26) — it checks whether the mechanical
   * prerequisites the policy names are satisfied, and controls release.
   */
  evaluateClaimPrerequisites(levelName, ctx) {
    const level = this.claimLevel(levelName);
    if (!level) {
      return decision({
        allowed: false,
        code: 'ARC_CLAIM_PREREQUISITE_UNMET',
        message: `no claim level '${levelName}' in ${this.policyId}`,
        detail: { levelName },
      });
    }
    const {
      evidenceClasses = [],
      staleEvidenceCount = 0,
      enforcementHealth = 'unsupported',
      covenantVerdict = null,
      fields = {},
      waivedBy = null,
    } = ctx ?? {};

    if (!level.allowStaleEvidence && staleEvidenceCount > 0) {
      return decision({
        allowed: false,
        code: 'ARC_EVIDENCE_STALE',
        message: `${staleEvidenceCount} supporting evidence record(s) are stale`,
        detail: { levelName, staleEvidenceCount },
      });
    }

    const missingClasses = level.requiredEvidenceClasses.filter((c) => !evidenceClasses.includes(c));
    if (missingClasses.length > 0) {
      return decision({
        allowed: false,
        code: 'ARC_EVIDENCE_INSUFFICIENT',
        message: `missing required evidence class(es): ${missingClasses.join(', ')}`,
        detail: { levelName, missingClasses },
      });
    }

    if (!enforcementAtLeast(enforcementHealth, level.requiredEnforcement)) {
      return decision({
        allowed: false,
        code: 'ARC_CLAIM_PREREQUISITE_UNMET',
        message: `claim '${levelName}' requires ${level.requiredEnforcement} enforcement; host is ${enforcementHealth}`,
        detail: { levelName, required: level.requiredEnforcement, actual: enforcementHealth },
        enforcementHealth,
      });
    }

    if (level.requiresCovenant && covenantVerdict === null) {
      return decision({
        allowed: false,
        code: 'ARC_CLAIM_PREREQUISITE_UNMET',
        message: `claim '${levelName}' requires a Covenant verdict`,
        detail: { levelName },
      });
    }

    const missingFields = level.requiredFields.filter((f) => !fields[f]);
    if (missingFields.length > 0) {
      if (waivedBy && this.mayWaive(waivedBy).allowed) {
        return decision({
          allowed: true,
          detail: { levelName, waivedBy, waivedFields: missingFields },
        });
      }
      return decision({
        allowed: false,
        code: 'ARC_CLAIM_PREREQUISITE_UNMET',
        message: `claim '${levelName}' is missing required field(s): ${missingFields.join(', ')}`,
        detail: { levelName, missingFields },
      });
    }

    return decision({ allowed: true, detail: { levelName }, enforcementHealth });
  }

  /** S02 action 3 — bind policy identity into a capability or receipt. */
  bindPolicy(record) {
    return { ...record, policyId: this.policyId, policyVersion: this.version, policyDigest: this.digest };
  }
}

// Single source of truth for enforcement ordering. Exported so no other module
// re-declares it: a divergent copy would silently let 'advisory' satisfy claim
// levels it must never satisfy.
export const ENFORCEMENT_RANK = Object.freeze({ unsupported: 0, advisory: 1, read_only: 2, observed: 3, strong: 4 });

function enforcementAtLeast(actual, required) {
  return (ENFORCEMENT_RANK[actual] ?? 0) >= (ENFORCEMENT_RANK[required] ?? 0);
}

/**
 * The engine to use when no valid policy exists. Every protected answer is a
 * fail-closed denial, and it says so honestly rather than reporting an
 * enforcement strength it does not have.
 */
export function failClosedEngine(reason) {
  const deny = (message, code = 'ARC_POLICY_UNAVAILABLE') =>
    decision({ allowed: false, code, message: `${message} (${reason})`, detail: { reason }, enforcementHealth: 'unsupported' });
  return {
    policyId: null,
    version: null,
    digest: null,
    failClosed: true,
    reason,
    effectRule: () => null,
    approvalRequiredEffectClasses: () => Object.freeze([]),
    effectDecision: (effectClass) => deny(`no policy available to authorize ${effectClass}`),
    evaluateClaimPrerequisites: (levelName) => deny(`no policy available to evaluate claim '${levelName}'`),
    mayWaive: () => deny('no policy available to name a waiver authority'),
    // Conservative defaults so a caller that reads a limit without checking
    // gets the strictest possible value, never a permissive one.
    capabilityLimits: () => ({ ttlSeconds: 0, maxUses: 0, delegable: false }),
    replayLimits: () => ({ freshnessWindowSeconds: 0, maxSkewSeconds: 0, nonceRequired: true, sequenceRequired: true }),
    trustMinima: () => ({ mutation: 'capability-signature', readOnly: 'capability-signature', claimRelease: 'capability-signature', legacyImport: 'unauthenticated' }),
    hostEnforcement: () => ({ requiredForMutation: 'strong', requiredForReadOnly: 'strong' }),
    claimLevel: () => null,
    lockedDomainsFor: () => [],
    degradation: () => 'fail-closed',
    evidencePolicy: () => ({ freshnessSeconds: 0, unlinkedCandidateExpirySeconds: 0, requireDependencyBinding: true }),
    retentionPolicy: () => ({ excerptMaxBytes: 0, storePayloads: false }),
    bindPolicy: (record) => ({ ...record, policyId: null, policyVersion: null, policyDigest: null }),
  };
}

/**
 * S02 action 5 — drift/conformance check that adapters do not duplicate policy.
 *
 * Structural, not semantic: it looks for the syntactic shapes an independent
 * allow/deny would have to take (minting a permissive decision, or reading the
 * bundle's rule table). A module that needs an answer must call the engine.
 */
export function policyDuplicationAudit(files) {
  const FORBIDDEN = [
    { pattern: /\ballowed\s*:\s*true\b/, why: 'mints an allow decision outside the policy engine' },
    { pattern: /\beffectRules\b/, why: 'reads the policy rule table directly' },
    { pattern: /\bwaiverAuthority\b/, why: 'reimplements waiver authority' },
    { pattern: /\bclaimLevels\b/, why: 'reimplements claim-level policy' },
    { pattern: /\blockedDomains\b/, why: 'reimplements locked-domain policy' },
    { pattern: /ENFORCEMENT_RANK\s*=/, why: 're-declares the enforcement ordering instead of importing it' },
  ];
  const violations = [];
  const scanned = [];
  for (const file of files) {
    const src = readFileSync(file, 'utf8');
    scanned.push(file);
    for (const { pattern, why } of FORBIDDEN) {
      if (pattern.test(src)) violations.push({ file, pattern: String(pattern), why });
    }
  }
  return { scanned, violations };
}

/**
 * Drift/conformance check that only the two modules trusted to mint
 * capabilities (the pre-effect gate that authorizes them, and the capability
 * store that records them) ever mint one via `issue(...)`. Anything else calling it
 * would be minting a capability outside the authorization path — exactly the
 * defect CONTRACT A's `authorize()` closes structurally; this audit closes it
 * conformance-wise.
 */
export function capabilityIssuanceAudit(files) {
  const ALLOWED_BASENAMES = new Set(['preeffect-gate.mjs', 'receipt-store.mjs']);
  const PATTERN = /\.issue\(/;
  const violations = [];
  const scanned = [];
  for (const file of files) {
    const src = readFileSync(file, 'utf8');
    scanned.push(file);
    const basename = path.basename(file);
    if (ALLOWED_BASENAMES.has(basename)) continue;
    // AuthorityInvocationProofIssuer has an unrelated `issue()` API. Exempt
    // only const-bound instances of that exact type; every other receiver
    // still fails the capability mint audit.
    const proofIssuers = new Set([...src.matchAll(/\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+AuthorityInvocationProofIssuer\s*\(/g)].map((match) => match[1]));
    const unexempted = src.split(/\r?\n/).some((line) => {
      const receiver = line.match(/\b([A-Za-z_$][\w$]*)\.issue\(/)?.[1];
      return PATTERN.test(line) && !proofIssuers.has(receiver);
    });
    if (unexempted) {
      violations.push({ file, pattern: String(PATTERN), why: 'mints a capability outside lib/preeffect-gate.mjs and lib/receipt-store.mjs' });
    }
  }
  return { scanned, violations };
}


/**
 * SEAL Q4 — EFFECT_CLASS reconciliation, owned by this lane.
 *
 * FREEZE.md J-8 records that the twelve frozen values were synthesized from
 * the containment nouns ARCHITECTURE §24/§24a names, with "reasonable
 * confidence this is complete enough ... low confidence it is the final set
 * Arcane will enforce." Having now built the broker, here is the answer, with
 * each frozen value tied to the surface that actually enforces it and each
 * proposed addition tied to something the current set cannot express.
 *
 * This is a PROPOSAL. packages/contracts/ is read-only to this lane; the
 * additions below are filed as amendments for the coordinator seal, and the
 * shipped bundle rules only the twelve frozen values.
 */
export const EFFECT_CLASS_RECONCILIATION = Object.freeze({
  sealQuestion: 'Q4',
  owner: 'E-ARCANE',
  verdict: 'The twelve frozen values are sound and all twelve are enforceable. The set is incomplete in one structurally important way (no read class) and over-broad in one (EXTERNAL_SIDE_EFFECT as a catch-all).',
  frozenValues: [
    { effectClass: 'FILE_WRITE', disposition: 'keep', brokerSurface: 'PreToolUse on Write/Edit/MultiEdit; gate checks path against contract scope.own[]' },
    { effectClass: 'FILE_DELETE', disposition: 'keep', brokerSurface: 'PreToolUse on Bash rm / fs unlink; approval-bound in the shipped bundle' },
    { effectClass: 'FILE_MOVE', disposition: 'keep', brokerSurface: 'PreToolUse on rename/mv; gate checks BOTH source and destination ownership' },
    { effectClass: 'COMMAND_EXEC', disposition: 'keep-with-caveat', brokerSurface: 'PreToolUse matcher Bash|Shell|PowerShell; the caveat is that exec is a carrier for every other class, so the gate must classify the command, not just authorize the exec' },
    { effectClass: 'NETWORK_EGRESS', disposition: 'keep-with-caveat', brokerSurface: 'no host adapter in this baseline can broker egress; the bundle records requiredEnforcement:observed rather than claiming strong' },
    { effectClass: 'PROCESS_SPAWN', disposition: 'keep', brokerSurface: 'PreToolUse on background/detached invocation' },
    { effectClass: 'CREDENTIAL_ACCESS', disposition: 'split-proposed', brokerSurface: 'denied by default in the shipped bundle; conflates reading a secret with minting/rotating one, which have different blast radii' },
    { effectClass: 'DEPENDENCY_INSTALL', disposition: 'keep', brokerSurface: 'PreToolUse on package-manager commands; stales the lockfile dependency dimension (S05)' },
    { effectClass: 'VCS_COMMIT', disposition: 'keep', brokerSurface: 'PreToolUse on git commit; approval-bound' },
    { effectClass: 'VCS_PUSH', disposition: 'keep', brokerSurface: 'PreToolUse on git push; denied by default — outward-facing and hard to reverse' },
    { effectClass: 'PUBLISH', disposition: 'keep', brokerSurface: 'release/upload operations; denied by default' },
    { effectClass: 'EXTERNAL_SIDE_EFFECT', disposition: 'keep-with-caveat', brokerSurface: 'denied by default; the caveat is that it must NOT be the fallback bucket for unclassified operations — the bundle pins unclassifiedEffect:deny so an unmodelled operation is refused by name instead' },
  ],
  proposedAdditions: [
    {
      name: 'FILE_READ',
      why: 'ARCHITECTURE §24a states that when the pre-effect gate is unavailable, "read-only operations may continue with a recorded enforcement-health downgrade." With no read effect class, "read-only" is not representable in an effect request, so the gate cannot distinguish the operations that may continue from the ones that must fail closed — it must fall back to inferring intent from the tool name. Path ownership on reads (reading outside scope.read[]) is likewise inexpressible.',
      evidence: 'ARCHITECTURE §24a degradation rule; execution-contract-v1.scope.read[] exists but no effect class can be checked against it.',
    },
    {
      name: 'CREDENTIAL_WRITE',
      why: 'CREDENTIAL_ACCESS currently covers both reading an existing secret and creating, rotating, or revoking one. Those have materially different blast radii and different reversibility, and a policy that wants to permit reading a token while forbidding rotating it cannot express that today.',
      evidence: 'shipped bundle must deny CREDENTIAL_ACCESS wholesale precisely because it cannot separate the two.',
    },
    {
      name: 'PROCESS_KILL',
      why: 'Terminating a running process is a mutation of live system state and is not a PROCESS_SPAWN. It is currently only expressible as COMMAND_EXEC, which makes it indistinguishable from any other command at policy level.',
      evidence: 'PROCESS_SPAWN is the only process-related class in the frozen enum.',
    },
  ],
  amendmentNote: 'If the coordinator adopts these, EFFECT_CLASS gains three values and effect-request-v1 / effect-receipt-v1 / execution-contract-v1.authorizedEffectClasses inherit them automatically (all three inline the same enum). No existing value changes meaning, so the amendment is additive and does not invalidate evidence bound to the current digest.',
});
