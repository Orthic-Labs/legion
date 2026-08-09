// EC-B — Codex host adapter.
//
// Reads Codex's native hook stdin JSON and turns it into the
// pre-normalization `raw` object `normalizeHostEvent` (../lib/host-event.mjs)
// expects, then runs it through the shared pipeline in ./hook-adapter-core.mjs
// (classifyObservation, signing, HostIngestor) exactly as claude-code-adapter.mjs
// does — see that file and ./hook-adapter-core.mjs for the parts common to
// every host.
//
// Field-mapping evidence (forge/hooks/generic/hook.js, the ONE place in this
// tree that reads both hosts' hook JSON defensively):
//   const sessionId = event.session_id ?? event.sessionId ?? process.env.CODEX_SESSION_ID ?? process.env.CLAUDE_SESSION_ID;
//   const command    = String(event.command ?? event.tool_input?.command ?? '');
// This establishes: Codex puts a tool's command at TOP-LEVEL `event.command`
// (Claude Code nests it at `tool_input.command`), and Codex's session id has
// no on-payload guarantee beyond `session_id`/`sessionId` plus an
// environment-variable fallback (`CODEX_SESSION_ID`). Copied verbatim below —
// this is the proven shape, not a guess.
//
// `hook_event_name` and `tool_name`/`tool_input.file_path` (for Write/Edit)
// are shared field names between the two hosts per forge/hooks/codex/hooks.json
// (registers the same eight lifecycle events as Claude Code) and
// forge/hooks/codex/hook.js + forge/hooks/claude-code/hook.js (both just
// `require('../adapter')` — one shared Forge core keyed by these same field
// names across hosts). Nothing here invents a Codex-specific spelling of a
// field this tree gives no evidence for.
//
// `HOST_EVENT_SCHEMA` is CLOSED (additionalProperties:false); the same
// null-where-no-source discipline documented in claude-code-adapter.mjs
// applies here. Fields intentionally left null (no Codex source, schema
// allows null): runId, taskId, requestId, contractId, sourceRevision,
// subject, pathMeta, networkMeta, priorCorrelation, checkCorrelation,
// replaySequence.
//
// `effect` is populated ONLY on post-effect events (PostToolUse /
// PostToolUseFailure), and ONLY for the tools in EFFECT_TOOL_MAP below —
// see that map's comment for the per-tool reasoning, including Codex's own
// `apply_patch`.

import { homedir, platform, release } from 'node:os';
import { join } from 'node:path';

import { ArcaneError } from '../lib/errors.mjs';
import { normalizeHostEvent } from '../lib/host-event.mjs';
import { canonicalJson, digest } from '../lib/canonical.mjs';
import { handleHookEvent, runHookMain } from './hook-adapter-core.mjs';

export const ADAPTER_NAME = 'codex';
export const ADAPTER_VERSION = process.env.CODEX_VERSION || 'unknown';
// Mirrors claude-code-adapter.mjs's DEFAULT_KEY_DIR shape (homedir()-relative
// per-host key directory); this tree carries no evidence of a Codex-specific
// home-directory env var (grepped forge/ — no CODEX_HOME reference exists),
// so this follows the same pattern rather than inventing one.
export const DEFAULT_KEY_DIR = join(homedir(), '.codex', 'arcane-keys');

/** Codex hook names that carry `tool_name`/`tool_input`/`tool_response` (mirrors claude-code-adapter.mjs). */
const TOOL_HOOK_EVENTS = Object.freeze(['PreToolUse', 'PostToolUse', 'PostToolUseFailure']);
const POST_TOOL_HOOK_EVENTS = Object.freeze(['PostToolUse', 'PostToolUseFailure']);
const SUPPORTED_HOOK_EVENTS = Object.freeze([
  'SessionStart', 'SubagentStart', 'UserPromptSubmit', 'PostCompact',
  'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop',
]);

/**
 * Direct, honest tool_name -> effect mappings for POST-EFFECT events only
 * (see module header). `targetField` names the property (top-level or under
 * `tool_input`, depending on the tool) that carries the observed target; a
 * missing/empty value degrades the whole event to `effect: null`
 * (EFFECT_IDENTITY_SCHEMA requires non-empty `target` — never substitute an
 * empty string or a placeholder like "unknown").
 *
 * Write/Edit/MultiEdit follow the decisions already landed for Claude Code
 * (claude-code-adapter.mjs EFFECT_TOOL_MAP): FILE_WRITE for the single-target
 * tools; MultiEdit stays out of this map entirely (falls through to
 * `effect: null` below) for the identical reason — the frozen
 * EFFECT_IDENTITY_SCHEMA holds ONE `target` string, not an array, and
 * picking one path while dropping the rest looks fixed while silently
 * missing files.
 *
 * `shell`/`shell_command`/`Bash`/`PowerShell` are Codex's command-execution
 * tools (per forge/hooks/codex/hooks.json's matcher list) and are excluded
 * from this map for the same reason Claude Code's Bash is excluded in
 * claude-code-adapter.mjs: a command string is not a path, and any parser
 * is defeatable by a command shaped to look benign.
 *
 * `apply_patch` — Codex's own file-edit tool, no Claude Code equivalent — is
 * DELIBERATELY excluded here too. This tree gives no evidence of its payload
 * shape: forge/hooks/codex/hooks.json lists it only as a PreToolUse/
 * PostToolUseFailure matcher string, and no file anywhere in forge/ or
 * packages/ reads an `apply_patch`-specific field (grepped; only the matcher
 * glob itself matches). Guessing whether it carries a single `file_path`
 * (FILE_WRITE-shaped) or a multi-file diff blob (MultiEdit-shaped) would be
 * exactly the invention this module has always refused to do — so it stays
 * `effect: null`, same as any other unrecognized tool, until real evidence
 * of its payload shape exists.
 */
const EFFECT_TOOL_MAP = Object.freeze({
  Write: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
  Edit: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
});

/**
 * Build the pre-normalization `raw` object `normalizeHostEvent` expects, from
 * a Codex hook's native stdin JSON. Exported so callers/tests can inspect the
 * exact field mapping without going through normalization.
 *
 * @param {object} hookPayload parsed Codex hook stdin JSON
 * @throws {ArcaneError} ARC_HOST_EVENT_INVALID if `hook_event_name` is not
 *   one of the eight documented lifecycle events (forge/hooks/codex/hooks.json).
 */
export function buildRawCodexEvent(hookPayload) {
  const eventType = hookPayload?.hook_event_name;
  if (typeof eventType !== 'string' || !SUPPORTED_HOOK_EVENTS.includes(eventType)) {
    throw new ArcaneError('ARC_HOST_EVENT_INVALID', `unsupported or missing Codex hook_event_name: ${eventType}`, {
      hookEventName: eventType ?? null,
    });
  }

  const isToolEvent = TOOL_HOOK_EVENTS.includes(eventType);
  const isPostTool = POST_TOOL_HOOK_EVENTS.includes(eventType);

  // Session id: the full `??` chain from forge/hooks/generic/hook.js,
  // including its env-var fallbacks — copied verbatim, not reinvented.
  const sessionId = hookPayload.session_id ?? hookPayload.sessionId
    ?? process.env.CODEX_SESSION_ID ?? process.env.CLAUDE_SESSION_ID ?? null;

  const raw = {
    eventType,
    time: new Date().toISOString(),

    adapter: { name: ADAPTER_NAME, version: ADAPTER_VERSION },
    client: { name: ADAPTER_NAME, version: ADAPTER_VERSION },
    host: { platform: platform(), version: release() },

    sessionId,

    workspace: hookPayload.cwd ?? '',

    actor: {
      issuerId: sessionId ? `codex-session:${sessionId}` : 'codex-session:unknown',
      processIdentity: `pid:${process.pid}`,
    },

    processMeta: { pid: process.pid, parentPid: process.ppid ?? null, executablePath: process.execPath ?? null },

    // Codex documents no per-invocation id distinct from tool_use_id in the
    // evidence this tree carries (forge/hooks/generic/hook.js never reads
    // one); reuse the same field name as Claude Code on the chance Codex's
    // hook JSON supplies it, else null (schema allows it) rather than
    // inventing a synthetic key.
    idempotencyKey: hookPayload.tool_use_id ?? null,
    replayNonce: hookPayload.tool_use_id ?? null,
  };

  if (isToolEvent && typeof hookPayload.tool_name === 'string') {
    raw.operation = {
      toolId: hookPayload.tool_name,
      operationId: hookPayload.tool_name,
      argumentDigest: hookPayload.tool_input !== undefined && hookPayload.tool_input !== null
        ? digest(canonicalJson(hookPayload.tool_input))
        : null,
    };
  }

  if (isPostTool) {
    raw.result = {
      outcome: eventType === 'PostToolUseFailure' ? 'failure' : 'success',
      exitCode: null,
      terminal: true,
      observedDigest: hookPayload.tool_response !== undefined && hookPayload.tool_response !== null
        ? digest(canonicalJson(hookPayload.tool_response))
        : null,
    };

    const mapping = typeof hookPayload.tool_name === 'string' ? EFFECT_TOOL_MAP[hookPayload.tool_name] : undefined;
    if (mapping) {
      // Only `command` has tree evidence of a top-level/tool_input dual
      // shape (forge/hooks/generic/hook.js's `event.command ?? event.tool_input?.command`).
      // Write/Edit's target has no such evidence — Codex registers the same
      // tool names as Claude Code (forge/hooks/codex/hooks.json) through the
      // same shared Forge core, so `tool_input.file_path` is read exactly as
      // claude-code-adapter.mjs reads it, with no invented top-level fallback.
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

/** `buildRawCodexEvent` + `normalizeHostEvent`, so callers get a schema-valid host event directly. */
export function normalizeCodexEvent(hookPayload) {
  const raw = buildRawCodexEvent(hookPayload);
  return normalizeHostEvent(raw, { adapter: { name: ADAPTER_NAME, version: ADAPTER_VERSION } });
}

/**
 * Full pipeline for a single Codex hook invocation. Thin Codex-specific
 * wrapper over the shared `handleHookEvent` (./hook-adapter-core.mjs) —
 * mirrors `handleClaudeCodeHookEvent` in claude-code-adapter.mjs.
 */
export function handleCodexHookEvent(hookPayload, deps) {
  return handleHookEvent(hookPayload, { ...deps, normalize: normalizeCodexEvent });
}

// ---------------------------------------------------------------------------
// CLI entry point — mirrors claude-code-adapter.mjs's main(). Delegates to
// the shared `runHookMain` (./hook-adapter-core.mjs).
// ---------------------------------------------------------------------------

export function main({ keyDir = DEFAULT_KEY_DIR, receiptStore, replayGuard, policy, capabilityStore = null, dependencyLedger = null, sessionBinding = null, preEffectCorrelation = null } = {}) {
  return runHookMain({ normalize: normalizeCodexEvent, keyDir, receiptStore, replayGuard, policy, capabilityStore, dependencyLedger, sessionBinding, preEffectCorrelation });
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
