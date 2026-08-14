// EC-B — host-agnostic hook-adapter core, shared by every Arcane host adapter
// (Claude Code, Codex, and any future host).
//
// This module owns everything downstream of a host-specific `normalize`
// function: event signing, the ingest handler, touched-path derivation, the
// Stop -> completion-gate evaluation, and the stdin `main()` loop. Every
// function here is extracted VERBATIM from `claude-code-adapter.mjs`
// (EC-2/EC-3/EC-4), renamed to host-neutral identifiers, and PARAMETERIZED
// only where the original inlined a host-specific call (`normalizeClaudeCodeEvent`)
// — that parameter is supplied by each host adapter's own thin wrapper.
//
// AC-B1: this file contains ZERO Claude-Code-specific field names
// (`hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`, `session_id`,
// `cwd`, the literal `'claude-code'`, etc.) — grep it to confirm. It knows
// nothing about any one host's raw hook JSON shape; that knowledge lives
// entirely in each host's own `build-raw-*`/`normalize-*` functions.

import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

import { ArcaneError, decision } from '../lib/errors.mjs';
import { classifyObservation, HOST_EVENT_BOUND_FIELDS } from '../lib/host-event.mjs';
import { signRecord } from '../lib/receipt-auth.mjs';
import { HostIngestor, POST_EFFECT_TYPES } from '../lib/ingest.mjs';
import { loadHostKeyRing } from '../lib/keys.mjs';
import { evaluateCompletion } from '../lib/completion-gate.mjs';
import { stopOutcome } from '../lib/stop-disposition.mjs';
import { evaluateCodexEscalation } from '../lib/codex-escalation.mjs';
import { auditSuccessfulCommit, preEffectDiscipline } from '../lib/discipline-controls.mjs';
import { serializeHostRuntimeOutput } from './host-runtime-output.mjs';

/**
 * EC-5 item 5 — honest `sourceRevision`. Neither adapter's `buildRaw*Event`
 * has ever set this field (see each adapter's own header: "no Claude Code
 * source ... stays null"), which meant `HostIngestor#ingest`'s post-effect
 * gate (`!hostEvent.sourceRevision` -> refused) silently refused EVERY
 * post-effect event in production — there was no path that ever set it.
 * Computed here, once, host-neutral, from `git rev-parse HEAD` scoped to the
 * event's own `workspace` (already normalized by the time this runs). Never
 * a placeholder: a missing/failed git (not a repo, git not on PATH, detached
 * weirdness, timeout) leaves `sourceRevision` at whatever `normalize()` set
 * (`null`), so the event stays honestly refused by the existing gate rather
 * than being stamped with a fabricated revision.
 *
 * @returns {string|null}
 */
export function resolveSourceRevision(workspace) {
  if (typeof workspace !== 'string' || workspace.length === 0) return null;
  try {
    const result = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: workspace, encoding: 'utf8', windowsHide: true, timeout: 5000 });
    if (result.error || result.status !== 0 || typeof result.stdout !== 'string') return null;
    const rev = result.stdout.trim();
    return rev.length > 0 ? rev : null;
  } catch {
    return null; // git unavailable/unspawnable -> honest null, never a placeholder
  }
}

/**
 * Sign `hostEvent` with `keyRing`. Never throws on an unavailable key —
 * returns the degraded state instead, so callers cannot accidentally let a
 * fail-closed condition escape as an uncaught exception.
 *
 * @returns {{authorityAssertion: object|null, enforcementHealth: 'strong'|'degraded', signError: ArcaneError|null}}
 */
export function signHostEvent(hostEvent, keyRing) {
  if (!keyRing) {
    return { authorityAssertion: null, enforcementHealth: 'degraded', signError: null };
  }
  try {
    const keyId = keyRing.activeKeyId();
    const receipt = signRecord(hostEvent, { keyRing, keyId, boundFields: HOST_EVENT_BOUND_FIELDS });
    return { authorityAssertion: { assertedBy: 'host', receipt }, enforcementHealth: 'strong', signError: null };
  } catch (err) {
    if (err instanceof ArcaneError && err.code === 'ARC_AUTH_KEY_UNAVAILABLE') {
      return { authorityAssertion: null, enforcementHealth: 'degraded', signError: err };
    }
    throw err;
  }
}

// Unconditionally blocked: no approval path, by design. These destroy state that
// no later step can reconstruct, so there is nothing an approval could make safe.
const DESTRUCTIVE_COMMAND = /(?:^|[;&|]\s*)(?:rm\s+(?:-[^\s]*r|--recursive)|remove-item\b[^\n]*-recurse|git\s+clean\b|dropdb\b|terraform\s+(?:apply|destroy)\b|curl\b[^\n|]*\|\s*(?:sh|bash)\b)/i;

export function isDestructiveCommand(hookPayload) {
  const command = hookPayload?.command ?? hookPayload?.tool_input?.command;
  return typeof command === 'string' && DESTRUCTIVE_COMMAND.test(command);
}

// Git history rewrite was in the list above, which made it unappealable: the operator
// could ask for a force-push, and nothing — not a contract, not a policy change,
// not his own instruction — could authorize it, because this branch returns
// before any of them are consulted. That is a dead end rather than enforcement.
// It is separated here so it can carry a TARGET-BOUND approval instead: an
// approval for origin/main must never authorize a push to a different ref.
const VCS_PUSH_RE = /git\s+push\s+([^\n;&|]*)/i;
const VCS_FORCE_FLAG = /(?:--force(?:-with-lease)?\b|(?:^|\s)-f\b)/;
const VCS_DELETE_FLAG = /(?:--delete\b|(?:^|\s)-d\b)/;

/**
 * `{operation, rewrite, remote, ref}` for a `git push`, or null when the command
 * is not one. `rewrite` marks the history-destroying forms. When a rewrite flag
 * is present but the target cannot be isolated, `remote`/`ref` stay null and the
 * caller must refuse — an approval is never bound to a guessed target.
 */
export function classifyVcsPush(command) {
  const match = typeof command === 'string' ? command.match(VCS_PUSH_RE) : null;
  if (!match) return null;
  const tail = match[1];
  const isForce = VCS_FORCE_FLAG.test(tail);
  const isDelete = VCS_DELETE_FLAG.test(tail);
  if (!isForce && !isDelete) return { operation: 'git-push', rewrite: false, remote: null, ref: null };
  const operands = tail.split(/\s+/).filter((token) => token && !token.startsWith('-'));
  const [remote = null, ref = null] = operands;
  return { operation: isForce ? 'git-push-force' : 'git-push-delete', rewrite: true, remote, ref };
}

/** The approval-store key a rewrite must present. Null when the target is ambiguous. */
export function vcsRewriteApprovalKey(sessionId, pushInfo) {
  if (!pushInfo?.rewrite || !pushInfo.remote || !pushInfo.ref || !sessionId) return null;
  return `${sessionId}|VCS_PUSH|${pushInfo.remote}/${pushInfo.ref}`;
}

/**
 * Full pipeline for a single host hook invocation: normalize (via the
 * host-supplied `deps.normalize`), classify, sign, and (when signing
 * succeeded, or the observation does not bear a mutation) ingest via
 * `HostIngestor`.
 *
 * @param {object} hookPayload parsed native hook stdin JSON for whichever host is calling
 * @param {object} deps
 * @param {(hookPayload: object) => object} deps.normalize host-specific hookPayload -> schema-valid host event
 * @param {object} deps.keyRing an Arcane `KeyRing` (may be unavailable-throwing already loaded)
 * @param {object} deps.receiptStore S03's ReceiptStore
 * @param {object} deps.replayGuard S03's ReplayGuard
 * @param {object} deps.policy a PolicyEngine, or failClosedEngine(...)
 * @param {object|null} [deps.capabilityStore]
 * @param {object|null} [deps.dependencyLedger]
 * @param {() => number} [deps.clock]
 * @param {object|null} [deps.sessionBinding] EC-5 item 1's `SessionBindingStore`
 *   (../lib/session-binding.mjs). Optional and defaulted to `null` so every
 *   existing caller that does not pass one gets EXACTLY today's behaviour —
 *   see the ambient-binding block below.
 * @param {object|null} [deps.preEffectCorrelation] EC-5 item 5's
 *   `PreEffectCorrelationStore` (../lib/preeffect-correlation.mjs). Optional,
 *   defaulted to `null` — see the correlation-minting block below.
 * @returns {{hostEvent: object, observationClass: string, enforcementHealth: 'strong'|'degraded',
 *   accepted: boolean, receipt: object|null, decision: object}}
 */
export function handleHookEvent(hookPayload, deps) {
  const {
    normalize, keyRing, verificationKeyRing = keyRing, receiptStore, replayGuard, policy,
    capabilityStore = null, dependencyLedger = null, clock = () => Date.now(),
    sessionBinding = null, preEffectCorrelation = null,
    // Optional and default-null: a host that has not wired an approval store
    // refuses every rewrite, which is exactly today's behaviour.
    approvalStore = null,
  } = deps;

  const hostEvent = normalize(hookPayload);
  const observationClass = classifyObservation(hostEvent, { policy });

  if (hostEvent.eventType === 'pre-effect' && isDestructiveCommand(hookPayload)) {
    return {
      hostEvent, observationClass, enforcementHealth: 'strong', accepted: false, receipt: null,
      decision: decision({
        allowed: false,
        code: 'ARC_EFFECT_CLASS_UNAUTHORIZED',
        message: 'destructive command class is blocked; use a bounded, reversible alternative',
        detail: {},
        enforcementHealth: 'strong',
      }),
    };
  }

  // Escalation ladder (absorbed from gate_codex_escalation.py): dispatching to
  // `codex exec` is the "then dispatch" half of resolve-it-yourself-then-
  // dispatch, so the prompt must carry two attempts and what each one hit.
  // Refusable by fixing the prompt, so no approval path is needed — unlike the
  // destructive class above, nothing here is unreconstructable.
  if (hostEvent.eventType === 'pre-effect') {
    const command = hookPayload?.command ?? hookPayload?.tool_input?.command;
    const escalation = evaluateCodexEscalation(command ?? '', (path) => {
      try { return path ? readFileSync(path, 'utf8') : null; } catch { return null; }
    });
    if (!escalation.allowed) {
      return {
        hostEvent, observationClass, enforcementHealth: 'strong', accepted: false, receipt: null,
        decision: decision({
          allowed: false,
          code: 'ARC_ESCALATION_UNEVIDENCED',
          message: escalation.reason,
          detail: { evidence: escalation.evidence ?? 0, required: 2 },
          enforcementHealth: 'strong',
        }),
      };
    }
  }

  // History rewrite: appealable, but only against a specific target. Without a
  // store the behaviour is identical to before this change — refused — so a host
  // that has not wired one up loses nothing and gains no silent permission.
  if (hostEvent.eventType === 'pre-effect') {
    const push = classifyVcsPush(hookPayload?.command ?? hookPayload?.tool_input?.command);
    if (push?.rewrite) {
      const key = vcsRewriteApprovalKey(hostEvent.sessionId, push);
      const approved = key && approvalStore ? approvalStore.consume(key) : null;
      if (!approved) {
        return {
          hostEvent, observationClass, enforcementHealth: 'strong', accepted: false, receipt: null,
          decision: decision({
            allowed: false,
            code: 'ARC_APPROVAL_REQUIRED',
            message: key
              ? `${push.operation} rewrites published history on ${push.remote}/${push.ref} and needs a target-bound approval`
              : `${push.operation} rewrites published history, and its remote/ref could not be isolated from the command; an approval is never bound to a guessed target`,
            detail: { operation: push.operation, remote: push.remote, ref: push.ref, approvalKey: key },
            enforcementHealth: 'strong',
          }),
        };
      }
    }
  }

  // EC-5 items 2+4 — ambient run/task/contract binding. Host-neutral on
  // purpose: both adapters normalize `sessionId` identically, so this lives
  // once, here, rather than duplicated per adapter. `session-start` mints or
  // self-heals the binding (H-11's missing writer); every other event only
  // reads whatever is already bound. A session with no binding at all (no
  // `sessionBinding` deps, or `hostEvent.sessionId` null) leaves `runId`/
  // `taskId`/`contractId` exactly as `normalize()` set them — today's
  // already-supported null case, unchanged.
  if (sessionBinding && hostEvent.sessionId) {
    const binding = hostEvent.eventType === 'session-start'
      ? sessionBinding.ensureBinding(hostEvent.sessionId)
      : sessionBinding.getBinding(hostEvent.sessionId);
    if (binding) {
      hostEvent.runId = binding.runId;
      hostEvent.taskId = binding.taskId;
      hostEvent.contractId = binding.contractId;
    }
  }

  if (hostEvent.eventType === 'pre-effect') {
    const control = preEffectDiscipline(hookPayload, {
      workspace: hostEvent.workspace,
      policy,
      contracted: hostEvent.contractId !== null,
    });
    if (control) {
      return {
        hostEvent, observationClass, enforcementHealth: 'strong', accepted: false, receipt: null,
        decision: decision({ allowed: false, code: control.code, message: control.message, detail: {}, enforcementHealth: 'strong' }),
      };
    }
  }

  // EC-5 item 5 — honest sourceRevision. Only fills a gap `normalize()` left
  // null; never overwrites a value an adapter/normalize already supplied.
  if (!hostEvent.sourceRevision) {
    hostEvent.sourceRevision = resolveSourceRevision(hostEvent.workspace);
  }

  // EC-5 item 5 — pre-effect/post-effect correlation (see
  // lib/preeffect-correlation.mjs's header for the full argument). Keyed on
  // `idempotencyKey`, which both adapters already set to the host's
  // tool_use_id for every tool-carrying event — session-level events
  // (SessionStart/UserPromptSubmit/Stop) carry none and are untouched here.
  // `pre-effect` reserves; post-effect prefers a completed finalization.
  // Ambient effects have no capability to finalize, so they may cite their
  // immutable reservation only. Contracted effects stay fail-closed.
  if (preEffectCorrelation && hostEvent.idempotencyKey) {
    if (hostEvent.eventType === 'pre-effect') {
      preEffectCorrelation.ensureRequestId(hostEvent.idempotencyKey);
    } else if (POST_EFFECT_TYPES.includes(hostEvent.eventType)) {
      const finalized = preEffectCorrelation.getFinalized(hostEvent.idempotencyKey);
      const requestId = finalized ? null : preEffectCorrelation.getRequestId(hostEvent.idempotencyKey);
      hostEvent.priorCorrelation = finalized
        ? { ...finalized, priorReceiptId: null }
        : requestId && hostEvent.contractId === null
          ? { requestId, capabilityId: null, requestedEffect: null, authorizedEffect: null, priorReceiptId: null }
          : null;
    }
  }

  const { authorityAssertion, enforcementHealth, signError } = signHostEvent(hostEvent, keyRing);

  if (!authorityAssertion) {
    // Degraded: never sign with a fallback key, never silently skip signing
    // and pretend success. Mutation-bearing observations fail closed
    // (ARCHITECTURE §24a); non-mutating observations are honestly reported
    // as unsigned/un-ingested rather than forced through HostIngestor with
    // no real trust material.
    return {
      hostEvent,
      observationClass,
      enforcementHealth,
      accepted: false,
      receipt: null,
      decision: decision({
        allowed: false,
        code: 'ARC_AUTH_KEY_UNAVAILABLE',
        message: signError ? signError.message : 'no key ring available to sign the host event',
        detail: { eventId: hostEvent.eventId, observationClass },
        enforcementHealth: 'degraded',
      }),
    };
  }

  const ingestor = new HostIngestor({ receiptStore, capabilityStore, replayGuard, keyRing: verificationKeyRing, policy, clock, dependencyLedger });
  const result = ingestor.ingest(hostEvent, { authorityAssertion });
  if (result.decision.allowed) auditSuccessfulCommit(hookPayload, hostEvent, { workspace: hostEvent.workspace });
  return { hostEvent, observationClass, enforcementHealth, ...result };
}

// ---------------------------------------------------------------------------
// Stop -> completion gate wiring.
// ---------------------------------------------------------------------------

/**
 * `touchedPaths` for a completion claim must come from what Arcane actually
 * recorded for the run — never from the Stop event payload itself, which a
 * completing agent could understate. Derived from `receiptStore.list({runId})`'s
 * `observed.target` on every effect receipt for the run.
 */
export function deriveTouchedPaths(receiptStore, runId) {
  if (!runId) return [];
  const records = receiptStore.list({ runId });
  const paths = new Set();
  for (const record of records) {
    const target = record?.observed?.target ?? null;
    if (typeof target === 'string' && target.length > 0) paths.add(target);
  }
  return [...paths];
}

/**
 * Evaluate a host `Stop` event against Arcane's completion gate
 * (../lib/completion-gate.mjs). No host's hook JSON carries a notion of a
 * claimed completion level, so `claimedLevel` defaults to `null`: a bare Stop
 * asserts no level of its own. Only the levels `lockedDomainsFor(touchedPaths)`
 * forces are evaluated, so a turn that touched a locked domain must still earn
 * that domain's level, while an ordinary turn has nothing to certify and is not
 * refused. A caller with more context (e.g. Legion/Alchemist declaring
 * `signoff`/`highRisk`/`release`) passes `claimedLevel` explicitly and that
 * level is checked exactly as before.
 *
 * The prior default was `'signoff'`, which required evidence class
 * `deterministic`. Hook-emitted receipts are effect receipts and carry no
 * `evidenceClass` at all, so that default could never be satisfied by any
 * hook-driven session — contracted or not — and blocked every turn.
 *
 * `hostEvent.runId` has no source in a bare host hook payload (see each
 * adapter's module header) and is therefore null for a bare hook-driven
 * Stop; `evaluateCompletion` then sees no receipts for that run and fails
 * closed (`enforcementHealth: 'unsupported'`) rather than granting an
 * ungrounded pass. A caller that has a real runId (from its own
 * session/task binding) should normalize the event with that runId set for
 * a meaningful result.
 *
 * @returns {object} the completion-gate decision (see completion-gate.mjs)
 */
export function evaluateHostStop(hostEvent, { policy, receiptStore, assuranceStore = null, keyRing = null, authorityBindingStore = null, currentProof = null, binding = null, execution = null, completionClaim = null, authorityProofIssuer = null, integratedState = null, latestMaterialChange = null, now = new Date(), claimedLevel = null, disposition = null, intent = 'UNKNOWN', authenticatedClaim = false }) {
  // Direct callers with an explicit legacy claimedLevel retain gate semantics;
  // authenticated host dispatch always supplies disposition and remains disposition-first.
  const terminal = disposition === null && claimedLevel !== null ? null : stopOutcome({ disposition, claimedLevel, intent, authenticatedClaim });
  if (terminal?.certification === 'not_claimed') return { allowed: true, code: null, message: 'Stop does not claim completion', detail: { ...terminal }, enforcementHealth: 'strong' };
  const touchedPaths = deriveTouchedPaths(receiptStore, hostEvent.runId);
  const certification = evaluateCompletion(
    { runId: hostEvent.runId, taskId: hostEvent.taskId, claimedLevel, touchedPaths, contractId: execution?.contractId ?? hostEvent.contractId ?? null, contractVersion: execution?.contractVersion ?? hostEvent.contractVersion ?? null, contractDigest: execution?.contractDigest ?? hostEvent.contractDigest ?? null, sourceRevision: execution?.sourceRevision ?? null, completionClaim },
    { policy, receiptStore, assuranceStore, keyRing, authorityBindingStore, currentProof, binding, execution, authorityProofIssuer, integratedState, latestMaterialChange, requireAcceptanceEvidence: terminal?.certification === 'genuine', now },
  );
  return { ...certification, detail: { ...certification.detail, ...(terminal ? { termination: terminal.termination, certification: certification.allowed ? 'certified' : 'rejected', disposition: terminal.disposition } : {}) } };
}

// EC-5 item 6 — surfaced when a Stop is refused for having no earnable path
// at all (`enforcementHealth: 'unsupported'` — completion-gate.mjs derives
// this from zero receipts for the run, e.g. a session that was never bound
// to a contract). Points at the item 3 CLI command that is the actual fix,
// rather than leaving the agent to rediscover `legion run open` on its own.
const UNSUPPORTED_RUN_GUIDANCE = "Run 'legion run open --contract <id> [--task <id>]' to bind this session to a contract, then produce the required evidence before Stop.";

/**
 * Render a completion-gate decision as the documented Stop-blocking shape
 * shared by every host adapter, mirroring how `predecessor/hooks/generic/hook.js`
 * blocks on `Stop` (`{decision:'block', reason}` on stdout; nothing printed
 * means allow — the host lets the turn end).
 *
 * @returns {{decision:'block', reason:string}|null} null when the gate allowed the claim.
 */
export function hostStopHookOutput(completionDecision) {
  if (completionDecision.allowed) return null;
  const label = completionDecision.code ? `${completionDecision.code}: ` : '';
  let reason = `${label}${completionDecision.message || 'completion claim denied by Arcane completion gate'}`;
  if (completionDecision.enforcementHealth === 'unsupported') {
    reason = `${reason} ${UNSUPPORTED_RUN_GUIDANCE}`;
  }
  return { decision: 'block', reason: reason.slice(0, 500) };
}

// ---------------------------------------------------------------------------
// CLI entry point — reads one hook payload from stdin, ingests it, and (for
// Stop) writes the block/allow response the host expects on stdout. Kept
// separate from the functions above so tests exercise the pure functions
// directly without touching stdio or the real key directory.
// ---------------------------------------------------------------------------

export function readStdinJson() {
  const raw = readFileSync(0, 'utf8');
  return JSON.parse(raw);
}


/**
 * Shared stdin-driven main loop for every host adapter's CLI entry point.
 *
 * @param {object} opts
 * @param {(hookPayload: object) => object} opts.normalize host-specific hookPayload -> schema-valid host event
 * @param {string} opts.keyDir
 * @param {object} opts.receiptStore
 * @param {object} opts.replayGuard
 * @param {object} opts.policy
 * @param {object|null} [opts.capabilityStore]
 * @param {object|null} [opts.dependencyLedger]
 * @param {object|null} [opts.sessionBinding] EC-5 item 1's `SessionBindingStore`; see `handleHookEvent`.
 * @param {object|null} [opts.preEffectCorrelation] EC-5 item 5's `PreEffectCorrelationStore`; see `handleHookEvent`.
 */
export function runHookMain({ dispatchHookInvocation }) {
  if (typeof dispatchHookInvocation !== 'function') throw new TypeError('runHookMain requires dispatchHookInvocation');
  let hookPayload;
  try {
    hookPayload = readStdinJson();
  } catch {
    return; // malformed/absent stdin: nothing this adapter can safely act on.
  }

  const result = dispatchHookInvocation(hookPayload);
  if (result && Object.hasOwn(result, 'stdout')) process.stdout.write(serializeHostRuntimeOutput(result.stdout));
  return result;
}
