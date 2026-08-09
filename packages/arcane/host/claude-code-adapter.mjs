// EC-2 — Claude Code host adapter.
//
// Reads Claude Code's native hook stdin JSON (fields: `hook_event_name`,
// `session_id`, `cwd`, `tool_name`, `tool_input`, `tool_response`,
// `tool_use_id`) and turns it into the pre-normalization `raw` object
// `normalizeHostEvent` (../lib/host-event.mjs) expects, then runs it through
// `classifyObservation` and the `HostIngestor` ingestion path
// (../lib/ingest.mjs), signing with a `KeyRing` (../lib/keys.mjs,
// provisioned by ./provision-keys.mjs).
//
// `HOST_EVENT_SCHEMA` is CLOSED (additionalProperties:false), so every field
// below is either directly sourced from the Claude Code payload, honestly
// derivable from this process's own environment (pid, platform), or left
// `null` where the schema allows it and Claude Code's hook JSON carries no
// such information — the schema's own nullability is the signal for "no
// source, and that is fine"; nowhere does this module invent a value for a
// non-nullable field it cannot actually source.
//
// Fields intentionally left null (no Claude Code source, and schema allows
// null): runId, taskId, requestId, contractId, sourceRevision, subject,
// pathMeta, networkMeta, priorCorrelation, checkCorrelation, replaySequence.
// `effect` (the proposed/observed effect identity) is also left null: Claude
// Code's `tool_name` (e.g. "Write", "Bash", "Read") has no documented,
// exact 1:1 mapping onto Arcane's 12-value EFFECT_CLASS enum, and guessing
// one per tool is exactly the kind of new engineering decision this module
// must not make silently — it is recorded below as an open item for Sage,
// not invented here. Without an effect class, `classifyObservation` cannot
// call an event a mutation-observation, which is the safe direction (no
// unearned mutation claim), never the dangerous one.
//
// Degraded mode (mandatory, honest): if the KeyRing cannot produce an active
// key (`ARC_AUTH_KEY_UNAVAILABLE`), this module never falls back to signing
// with a different key and never silently skips signing. It marks the
// result `enforcementHealth: 'degraded'` and, for anything classified as a
// mutation-observation, refuses to proceed to ingestion at all (ARCHITECTURE
// §24a: mutation-bearing operations fail closed when enforcement is
// unavailable). Non-mutating observations are also left unsigned/un-ingested
// in that state — there is no partial-trust path in HostIngestor to hand
// them to.

import { existsSync, readFileSync } from 'node:fs';
import { homedir, platform, release } from 'node:os';
import { join } from 'node:path';

import { ArcaneError, decision } from '../lib/errors.mjs';
import {
  normalizeHostEvent,
  classifyObservation,
  HOST_EVENT_BOUND_FIELDS,
} from '../lib/host-event.mjs';
import { canonicalJson, digest } from '../lib/canonical.mjs';
import { signRecord } from '../lib/receipt-auth.mjs';
import { HostIngestor } from '../lib/ingest.mjs';
import { loadHostKeyRing } from '../lib/keys.mjs';
import { evaluateCompletion } from '../lib/completion-gate.mjs';

export const ADAPTER_NAME = 'claude-code';
export const ADAPTER_VERSION = process.env.CLAUDE_CODE_VERSION || 'unknown';
export const DEFAULT_KEY_DIR = join(homedir(), '.claude', 'arcane-keys');

/** Claude Code hook names that carry `tool_name`/`tool_input`/`tool_response`. */
const TOOL_HOOK_EVENTS = Object.freeze(['PreToolUse', 'PostToolUse', 'PostToolUseFailure']);
const POST_TOOL_HOOK_EVENTS = Object.freeze(['PostToolUse', 'PostToolUseFailure']);
const SUPPORTED_HOOK_EVENTS = Object.freeze([
  'SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop',
]);

/**
 * Build the pre-normalization `raw` object `normalizeHostEvent` expects, from
 * a Claude Code hook's native stdin JSON. Exported so callers/tests can
 * inspect the exact field mapping without going through normalization.
 *
 * @param {object} hookPayload parsed Claude Code hook stdin JSON
 * @throws {ArcaneError} ARC_HOST_EVENT_INVALID if `hook_event_name` is not
 *   one of the six documented Claude Code hook events.
 */
export function buildRawHostEvent(hookPayload) {
  const eventType = hookPayload?.hook_event_name;
  if (typeof eventType !== 'string' || !SUPPORTED_HOOK_EVENTS.includes(eventType)) {
    throw new ArcaneError('ARC_HOST_EVENT_INVALID', `unsupported or missing Claude Code hook_event_name: ${eventType}`, {
      hookEventName: eventType ?? null,
    });
  }

  const isToolEvent = TOOL_HOOK_EVENTS.includes(eventType);
  const isPostTool = POST_TOOL_HOOK_EVENTS.includes(eventType);

  const raw = {
    eventType,
    time: new Date().toISOString(),

    // adapter/client/host (§3.2 bullet 2) — required, non-nullable by
    // HOST_EVENT_SCHEMA, so every field here must come from somewhere real:
    // adapter/client identity is this module's own static identity; host
    // platform/version is this process's own `os` view, not invented.
    adapter: { name: ADAPTER_NAME, version: ADAPTER_VERSION },
    client: { name: ADAPTER_NAME, version: ADAPTER_VERSION },
    host: { platform: platform(), version: release() },

    // session binding (§3.2 bullet 3) — session_id is the only such field
    // Claude Code's hook JSON documents. runId/taskId/requestId/contractId
    // have no Claude Code source and stay null (schema allows it).
    sessionId: hookPayload.session_id ?? null,

    // workspace/subject (§3.2 bullet 4) — cwd is the workspace directory.
    workspace: hookPayload.cwd ?? '',

    // actor/issuer identity (§3.2 bullet 5) — a process/connection identity
    // only, never an authority claim (that travels via authorityAssertion,
    // never in the event itself). issuerId is derived from session_id;
    // processIdentity from this observing process's own pid, both real.
    actor: {
      issuerId: hookPayload.session_id ? `claude-code-session:${hookPayload.session_id}` : 'claude-code-session:unknown',
      processIdentity: `pid:${process.pid}`,
    },

    // process metadata — this process's own identity, not invented.
    processMeta: { pid: process.pid, parentPid: process.ppid ?? null, executablePath: process.execPath ?? null },

    // replay/idempotency — tool_use_id is Claude Code's own per-invocation
    // identifier and is the only field available to key these on. Session-
    // level events (SessionStart/UserPromptSubmit/Stop) carry no
    // tool_use_id, so these stay null for them (schema allows it).
    idempotencyKey: hookPayload.tool_use_id ?? null,
    replayNonce: hookPayload.tool_use_id ?? null,
  };

  // operation/tool identity + argument digest (§3.2 bullets 6-7). Only
  // present on the three tool-carrying hook events; normalizeHostEvent
  // supplies the {toolId:'unknown', operationId:'unknown', argumentDigest:
  // null} default for the other three (SessionStart/UserPromptSubmit/Stop),
  // which is honest — there is no tool operation on those events at all.
  if (isToolEvent && typeof hookPayload.tool_name === 'string') {
    raw.operation = {
      // toolId is Claude Code's own tool identity (e.g. "Write"); operationId
      // reuses it verbatim rather than guessing a normalized verb Claude
      // Code's hook JSON never supplies — see module header on `effect`.
      toolId: hookPayload.tool_name,
      operationId: hookPayload.tool_name,
      argumentDigest: hookPayload.tool_input !== undefined && hookPayload.tool_input !== null
        ? digest(canonicalJson(hookPayload.tool_input))
        : null,
    };
  }

  // result/exit/terminal metadata (§3.2 bullet 10). Only present on the two
  // post-tool hook events, where Claude Code actually reports an outcome.
  // exitCode has no Claude Code source (never in the documented payload
  // fields) and stays null.
  if (isPostTool) {
    raw.result = {
      outcome: eventType === 'PostToolUseFailure' ? 'failure' : 'success',
      exitCode: null,
      terminal: true,
      observedDigest: hookPayload.tool_response !== undefined && hookPayload.tool_response !== null
        ? digest(canonicalJson(hookPayload.tool_response))
        : null,
    };
  }

  return raw;
}

/** `buildRawHostEvent` + `normalizeHostEvent`, so callers get a schema-valid host event directly. */
export function normalizeClaudeCodeEvent(hookPayload) {
  const raw = buildRawHostEvent(hookPayload);
  return normalizeHostEvent(raw, { adapter: { name: ADAPTER_NAME, version: ADAPTER_VERSION } });
}

/**
 * Sign `hostEvent` with `keyRing`. Never throws on an unavailable key —
 * returns the degraded state instead, so callers cannot accidentally let a
 * fail-closed condition escape as an uncaught exception.
 *
 * @returns {{authorityAssertion: object|null, enforcementHealth: 'strong'|'degraded', signError: ArcaneError|null}}
 */
export function signClaudeCodeEvent(hostEvent, keyRing) {
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
 * Full pipeline for a single Claude Code hook invocation: normalize,
 * classify, sign, and (when signing succeeded, or the observation does not
 * bear a mutation) ingest via `HostIngestor`.
 *
 * @param {object} hookPayload parsed Claude Code hook stdin JSON
 * @param {object} deps
 * @param {object} deps.keyRing an Arcane `KeyRing` (may be unavailable-throwing already loaded)
 * @param {object} deps.receiptStore S03's ReceiptStore
 * @param {object} deps.replayGuard S03's ReplayGuard
 * @param {object} deps.policy a PolicyEngine, or failClosedEngine(...)
 * @param {object|null} [deps.capabilityStore]
 * @param {object|null} [deps.dependencyLedger]
 * @param {() => number} [deps.clock]
 * @returns {{hostEvent: object, observationClass: string, enforcementHealth: 'strong'|'degraded',
 *   accepted: boolean, receipt: object|null, decision: object}}
 */
export function handleClaudeCodeHookEvent(hookPayload, deps) {
  const { keyRing, receiptStore, replayGuard, policy, capabilityStore = null, dependencyLedger = null, clock = () => Date.now() } = deps;

  const hostEvent = normalizeClaudeCodeEvent(hookPayload);
  const observationClass = classifyObservation(hostEvent, { policy });
  const { authorityAssertion, enforcementHealth, signError } = signClaudeCodeEvent(hostEvent, keyRing);

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
 * Evaluate a Claude Code `Stop` event against Arcane's completion gate
 * (../lib/completion-gate.mjs). Claude Code's hook JSON carries no notion of
 * a claimed completion level, so `claimedLevel` defaults to `'signoff'` —
 * the policy bundle's weakest defined level (deterministic evidence, strong
 * enforcement, no Covenant/narrative fields) — as the honest floor every
 * Stop implicitly asserts ("this turn is done"); a caller with more context
 * (e.g. Legion/Alchemist declaring `highRisk`/`release`) may pass a
 * different `claimedLevel` explicitly. `lockedDomainsFor(touchedPaths)` may
 * still force a higher level regardless of what is claimed.
 *
 * `hostEvent.runId` has no Claude Code source (see module header) and is
 * therefore null for a bare hook-driven Stop; `evaluateCompletion` then sees
 * no receipts for that run and fails closed (`enforcementHealth: 'unsupported'`)
 * rather than granting an ungrounded pass. A caller that has a real runId
 * (from its own session/task binding) should normalize the event with that
 * runId set for a meaningful result.
 *
 * @returns {object} the completion-gate decision (see completion-gate.mjs)
 */
export function evaluateClaudeCodeStop(hostEvent, { policy, receiptStore, claimedLevel = 'signoff' }) {
  const touchedPaths = deriveTouchedPaths(receiptStore, hostEvent.runId);
  return evaluateCompletion(
    { runId: hostEvent.runId, taskId: hostEvent.taskId, claimedLevel, touchedPaths },
    { policy, receiptStore },
  );
}

/**
 * Render a completion-gate decision as Claude Code's documented Stop-blocking
 * shape, mirroring how `forge/hooks/adapter.js` blocks on `Stop`
 * (`{decision:'block', reason}` on stdout; nothing printed means allow —
 * Claude Code lets the turn end).
 *
 * @returns {{decision:'block', reason:string}|null} null when the gate allowed the claim.
 */
export function claudeCodeStopHookOutput(completionDecision) {
  if (completionDecision.allowed) return null;
  const label = completionDecision.code ? `${completionDecision.code}: ` : '';
  const reason = `${label}${completionDecision.message || 'completion claim denied by Arcane completion gate'}`.slice(0, 500);
  return { decision: 'block', reason };
}

// ---------------------------------------------------------------------------
// CLI entry point — reads one hook payload from stdin, ingests it, and (for
// Stop) writes the block/allow response Claude Code expects on stdout. Kept
// separate from the functions above so tests exercise the pure functions
// directly without touching stdio or the real key directory.
// ---------------------------------------------------------------------------

function readStdinJson() {
  const raw = readFileSync(0, 'utf8');
  return JSON.parse(raw);
}

export function main({ keyDir = DEFAULT_KEY_DIR, receiptStore, replayGuard, policy, capabilityStore = null, dependencyLedger = null } = {}) {
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
      keyRing = null; // ARC_AUTH_KEY_UNAVAILABLE -> handleClaudeCodeHookEvent's degraded path.
    }
  }

  const outcome = handleClaudeCodeHookEvent(hookPayload, { keyRing, receiptStore, replayGuard, policy, capabilityStore, dependencyLedger });

  if (outcome.hostEvent.eventType === 'stop') {
    const completionDecision = evaluateClaudeCodeStop(outcome.hostEvent, { policy, receiptStore });
    const output = claudeCodeStopHookOutput(completionDecision);
    if (output) process.stdout.write(`${JSON.stringify(output)}\n`);
  }
}

const isMainModule = typeof process !== 'undefined' && process.argv[1]
  && import.meta.url === `file://${process.argv[1].replaceAll('\\', '/')}`;
if (isMainModule) {
  // Real host-config wiring (receiptStore/replayGuard/policy instances) is
  // deliberately out of scope for this task (no settings.json / live
  // wiring) — this branch exists so the module is a valid CLI entry point
  // once a caller wires those deps, not to run today.
  main();
}
