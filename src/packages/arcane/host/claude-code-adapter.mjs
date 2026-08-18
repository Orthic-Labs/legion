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
//
// `effect` (the proposed/observed effect identity) is populated ONLY on
// post-effect events (PostToolUse / PostToolUseFailure), and only for the
// small set of tools below where the mapping from Claude Code's `tool_name`
// to Arcane's EFFECT_CLASS enum is direct and honest — an observation of
// what already happened, never a pre-execution claim. `effect` stays null on
// PreToolUse unconditionally (invariant I-1): a pre-effect event describing
// what the model merely *proposed* is exactly the kind of ungrounded
// mutation claim this adapter must not manufacture.
//
// For everything NOT in EFFECT_TOOL_MAP below, `effect` stays null — this is
// deliberate, not an omission, and is pinned by regression tests:
//   - Bash: a command string is not a path. Any parser could be defeated by
//     a command shaped to look benign, so parsing is refused on purpose.
//     Named consequence: shell-driven mutations (rm, mv, >, sed -i) are
//     invisible to locked-domain enforcement through this adapter.
//   - MultiEdit: the frozen EFFECT_IDENTITY_SCHEMA takes a SINGLE `target`
//     string, not an array. Picking one path out of MultiEdit's multiple
//     edits and dropping the rest would look partially fixed while silently
//     missing files — worse than an honest null.
//   - Read/Grep/Glob: the frozen EFFECT_CLASS enum has no read class, and
//     PreEffectGate doctrine forbids inferring read effects from a tool
//     name.
//   - mcp__*/unrecognized tools: side-effect shape is unknown; guessing one
//     is the exact invention this module has always refused to do.
// Without an effect class, `classifyObservation` cannot call an event a
// mutation-observation, which is the safe direction (no unearned mutation
// claim), never the dangerous one.
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

import { homedir, platform, release } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { normalizeHookEvent } from '@rightkit/hooks';

import { ArcaneError } from '../lib/errors.mjs';
import { normalizeHostEvent } from '../lib/host-event.mjs';
import { canonicalJson, digest } from '../lib/canonical.mjs';
import {
  signHostEvent as signClaudeCodeEvent,
  handleHookEvent,
  deriveTouchedPaths,
  evaluateHostStop as evaluateClaudeCodeStop,
  hostStopHookOutput as claudeCodeStopHookOutput,
  runHookMain,
  readStdinJson,
} from './hook-adapter-core.mjs';
import { dispatchHookInvocation } from './host-runtime.mjs';
import { serializeHostRuntimeOutput } from './host-runtime-output.mjs';

export { signClaudeCodeEvent, deriveTouchedPaths, evaluateClaudeCodeStop, claudeCodeStopHookOutput };

export const ADAPTER_NAME = 'claude-code';
export const ADAPTER_VERSION = process.env.CLAUDE_CODE_VERSION || 'unknown';
export const DEFAULT_KEY_DIR = join(homedir(), '.claude', 'arcane-keys');

/** Claude Code hook names that carry `tool_name`/`tool_input`/`tool_response`. */
const TOOL_HOOK_EVENTS = Object.freeze(['PreToolUse', 'PostToolUse', 'PostToolUseFailure']);
const POST_TOOL_HOOK_EVENTS = Object.freeze(['PostToolUse', 'PostToolUseFailure']);
const SUPPORTED_HOOK_EVENTS = Object.freeze([
  'SessionStart', 'SubagentStart', 'UserPromptSubmit', 'PostCompact', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop',
]);

const PRE_EFFECT_TOOL_MAP = Object.freeze({
  Write: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
  Edit: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
});

/**
 * Direct, honest tool_name -> effect mappings for POST-EFFECT events only
 * (see module header). `targetField` names the `tool_input` property that
 * carries the observed target; a missing/empty value degrades the whole
 * event to `effect: null` (EFFECT_IDENTITY_SCHEMA requires non-empty
 * `target` — never substitute an empty string or a placeholder like
 * "unknown").
 *
 * NOTE: WebSearch's `target` (`tool_input.query`) is a search query string,
 * NOT a filesystem path. It is structurally inert against locked-domain glob
 * matching (harmless), but must never be "fixed" into a fake path by a
 * future reader.
 */
const EFFECT_TOOL_MAP = Object.freeze({
  Write: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
  Edit: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
  NotebookEdit: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
  WebFetch: { effectClass: 'NETWORK_EGRESS', targetField: 'url' },
  WebSearch: { effectClass: 'NETWORK_EGRESS', targetField: 'query' },
});

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
  try { hookPayload = normalizeHookEvent(hookPayload).payload; } catch { throw new ArcaneError('ARC_HOST_EVENT_INVALID', 'invalid HookHost payload'); }
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

    // See EFFECT_TOOL_MAP above and the module header: only the mapped
    // tools get a populated `effect`; everything else (Bash, MultiEdit,
    // Task/Agent, Read/Grep/Glob, mcp__*, unrecognized) stays null on
    // purpose.
    const mapping = typeof hookPayload.tool_name === 'string' ? EFFECT_TOOL_MAP[hookPayload.tool_name] : undefined;
    if (mapping) {
      const target = hookPayload.tool_input?.[mapping.targetField];
      raw.effect = typeof target === 'string' && target.length > 0
        ? { effectClass: mapping.effectClass, target, operation: hookPayload.tool_name }
        : null; // missing/empty source field degrades to null, never "" or "unknown".
    } else {
      raw.effect = null;
    }
  }

  return raw;
}

/** `buildRawHostEvent` + `normalizeHostEvent`, so callers get a schema-valid host event directly. */
export function normalizeClaudeCodeEvent(hookPayload) {
  const raw = buildRawHostEvent(hookPayload);
  return normalizeHostEvent(raw, { adapter: { name: ADAPTER_NAME, version: ADAPTER_VERSION } });
}

// signClaudeCodeEvent, deriveTouchedPaths, evaluateClaudeCodeStop, and
// claudeCodeStopHookOutput are fully host-agnostic and re-exported verbatim
// (under their existing names) from ./hook-adapter-core.mjs above — see the
// EC-B header comment. Only the two functions below need Claude-Code-specific
// glue: handleClaudeCodeHookEvent supplies normalizeClaudeCodeEvent as the
// core pipeline's `normalize` callback, and main() supplies it to the shared
// stdin loop.

/**
 * Full pipeline for a single Claude Code hook invocation: normalize,
 * classify, sign, and (when signing succeeded, or the observation does not
 * bear a mutation) ingest via `HostIngestor`. Thin Claude-Code-specific
 * wrapper over the shared `handleHookEvent` (./hook-adapter-core.mjs), which
 * owns everything downstream of normalization.
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
  return handleHookEvent(hookPayload, { ...deps, normalize: normalizeClaudeCodeEvent });
}

export function observeClaudeCodeIdentity(hookPayload, { hostEvent } = {}) {
  // UserPromptSubmit has no agent identity; runtime records it untrusted until
  // an external authenticated host bridge exists.
  if (hostEvent?.eventType === 'user-prompt-submit') return { sessionId: hostEvent.sessionId, eventId: hostEvent.eventId, currentUserPrompt: true };
  if (['authority', 'callerAuthority', 'assertedAuthority', 'trust_class', 'trustClass', 'executor'].some((key) => Object.hasOwn(hookPayload ?? {}, key))) return { modelClaimed: true };
  const sessionId = hookPayload?.session_id ?? hookPayload?.sessionId ?? null;
  const agentId = hookPayload?.agent_id ?? hookPayload?.agentId ?? null;
  const agentType = hookPayload?.agent_type ?? hookPayload?.agentType ?? null;
  return sessionId && agentId && agentType ? { sessionId, agentId, agentType, eventId: hostEvent?.eventId } : null;
}

export function mapClaudeCodePreEffect(hookPayload) {
  const mapping = PRE_EFFECT_TOOL_MAP[hookPayload?.tool_name];
  const target = mapping ? hookPayload?.tool_input?.[mapping.targetField] : null;
  if (!mapping || typeof target !== 'string' || target.length === 0 || typeof hookPayload?.tool_use_id !== 'string' || hookPayload.tool_use_id.length === 0) return null;
  return { effectClass: mapping.effectClass, target, operation: hookPayload.tool_name, toolUseId: hookPayload.tool_use_id };
}

export const claudeCodeHostAdapter = Object.freeze({ name: ADAPTER_NAME, normalize: normalizeClaudeCodeEvent, observeIdentity: observeClaudeCodeIdentity, mapPreEffect: mapClaudeCodePreEffect });

// ---------------------------------------------------------------------------
// CLI entry point — reads one hook payload from stdin, ingests it, and (for
// Stop) writes the block/allow response Claude Code expects on stdout. Kept
// separate from the functions above so tests exercise the pure functions
// directly without touching stdio or the real key directory. Delegates to
// the shared `runHookMain` (./hook-adapter-core.mjs).
// ---------------------------------------------------------------------------

export function main({ keyDir, verificationKeyDirs, workspace, stateRoot, receiptStore, replayGuard, policy, capabilityStore = null, dependencyLedger = null, sessionBinding = null, preEffectCorrelation = null } = {}) {
  const configuredKeyDir = keyDir ?? process.env.ARCANE_KEY_DIR ?? DEFAULT_KEY_DIR;
  const configuredWorkspace = workspace ?? process.env.ARCANE_WORKSPACE ?? process.cwd();
  const verifyDirs = verificationKeyDirs ?? (keyDir || process.env.ARCANE_KEY_DIR ? [configuredKeyDir] : [join(homedir(), '.claude', 'arcane-keys'), join(homedir(), '.codex', 'arcane-keys')]);
  return runHookMain({ dispatchHookInvocation: (payload) => dispatchHookInvocation(payload, { adapter: claudeCodeHostAdapter, workspace: configuredWorkspace, keyDir: configuredKeyDir, verificationKeyDirs: verifyDirs, stateRoot: stateRoot ?? process.env.ARCANE_STATE_ROOT }) });
}

const isMainModule = typeof process !== 'undefined' && process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMainModule) {
  // Real host-config wiring (receiptStore/replayGuard/policy instances) is
  // deliberately out of scope for this task (no settings.json / live
  // wiring) — this branch exists so the module is a valid CLI entry point
  // once a caller wires those deps, not to run today.
  main();
}
