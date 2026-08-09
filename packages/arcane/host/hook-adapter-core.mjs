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
    normalize, keyRing, receiptStore, replayGuard, policy,
    capabilityStore = null, dependencyLedger = null, clock = () => Date.now(),
    sessionBinding = null, preEffectCorrelation = null,
  } = deps;

  const hostEvent = normalize(hookPayload);
  const observationClass = classifyObservation(hostEvent, { policy });

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
  // `pre-effect` mints (or self-heals); every post-effect type only reads,
  // and never overwrites a `priorCorrelation.requestId` a normalize() already
  // supplied.
  if (preEffectCorrelation && hostEvent.idempotencyKey) {
    if (hostEvent.eventType === 'pre-effect') {
      preEffectCorrelation.ensureRequestId(hostEvent.idempotencyKey);
    } else if (POST_EFFECT_TYPES.includes(hostEvent.eventType) && !hostEvent.priorCorrelation?.requestId) {
      const requestId = preEffectCorrelation.getRequestId(hostEvent.idempotencyKey);
      if (requestId) {
        hostEvent.priorCorrelation = {
          requestId,
          capabilityId: hostEvent.priorCorrelation?.capabilityId ?? null,
          priorReceiptId: hostEvent.priorCorrelation?.priorReceiptId ?? null,
          requestedEffect: hostEvent.priorCorrelation?.requestedEffect ?? null,
          authorizedEffect: hostEvent.priorCorrelation?.authorizedEffect ?? null,
        };
      }
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

  const ingestor = new HostIngestor({ receiptStore, capabilityStore, replayGuard, keyRing, policy, clock, dependencyLedger });
  const result = ingestor.ingest(hostEvent, { authorityAssertion });
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
 * claimed completion level, so `claimedLevel` defaults to `'signoff'` — the
 * policy bundle's weakest defined level (deterministic evidence, strong
 * enforcement, no Covenant/narrative fields) — as the honest floor every Stop
 * implicitly asserts ("this turn is done"); a caller with more context (e.g.
 * Legion/Alchemist declaring `highRisk`/`release`) may pass a different
 * `claimedLevel` explicitly. `lockedDomainsFor(touchedPaths)` may still force
 * a higher level regardless of what is claimed.
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
export function evaluateHostStop(hostEvent, { policy, receiptStore, claimedLevel = 'signoff' }) {
  const touchedPaths = deriveTouchedPaths(receiptStore, hostEvent.runId);
  return evaluateCompletion(
    { runId: hostEvent.runId, taskId: hostEvent.taskId, claimedLevel, touchedPaths },
    { policy, receiptStore },
  );
}

// EC-5 item 6 — surfaced when a Stop is refused for having no earnable path
// at all (`enforcementHealth: 'unsupported'` — completion-gate.mjs derives
// this from zero receipts for the run, e.g. a session that was never bound
// to a contract). Points at the item 3 CLI command that is the actual fix,
// rather than leaving the agent to rediscover `legion run open` on its own.
const UNSUPPORTED_RUN_GUIDANCE = "Run 'legion run open --contract <id> [--task <id>]' to bind this session to a contract, then produce the required evidence before Stop.";

/**
 * Render a completion-gate decision as the documented Stop-blocking shape
 * shared by every host adapter, mirroring how `forge/hooks/generic/hook.js`
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
export function runHookMain({ normalize, keyDir, receiptStore, replayGuard, policy, capabilityStore = null, dependencyLedger = null, sessionBinding = null, preEffectCorrelation = null }) {
  let hookPayload;
  try {
    hookPayload = readStdinJson();
  } catch {
    return; // malformed/absent stdin: nothing this adapter can safely act on.
  }

  let keyRing = null;
  if (existsSync(keyDir)) {
    try {
      keyRing = loadHostKeyRing({ dir: keyDir });
    } catch {
      keyRing = null; // ARC_AUTH_KEY_UNAVAILABLE -> handleHookEvent's degraded path.
    }
  }

  const outcome = handleHookEvent(hookPayload, { normalize, keyRing, receiptStore, replayGuard, policy, capabilityStore, dependencyLedger, sessionBinding, preEffectCorrelation });

  if (outcome.hostEvent.eventType === 'stop') {
    const completionDecision = evaluateHostStop(outcome.hostEvent, { policy, receiptStore });
    const output = hostStopHookOutput(completionDecision);
    if (output) process.stdout.write(`${JSON.stringify(output)}\n`);
  }
}
