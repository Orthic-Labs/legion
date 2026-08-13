// EC-B — Codex host adapter.
//
// Reads Codex's native hook stdin JSON and turns it into the
// pre-normalization `raw` object `normalizeHostEvent` (../lib/host-event.mjs)
// expects, then runs it through the shared pipeline in ./hook-adapter-core.mjs
// (classifyObservation, signing, HostIngestor) exactly as claude-code-adapter.mjs
// does — see that file and ./hook-adapter-core.mjs for the parts common to
// every host.
//
// Codex hook stdin supplies session_id plus agent_id/agent_type on subagent
// events. Desktop exposes the durable thread identity as CODEX_THREAD_ID. It
// is authoritative over transient payload session ids; a supplied thread id
// must match it or the event fails closed.
//
// `hook_event_name` and `tool_name`/`tool_input.file_path` (for Write/Edit)
// are shared field names between the two hosts per predecessor/hooks/codex/hooks.json
// (registers all eight Codex lifecycle events; Claude Code registers the six shared events) and
// predecessor/hooks/codex/hook.js + predecessor/hooks/claude-code/hook.js (both just
// `require('../adapter')` — one shared predecessor core keyed by these same field
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
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { normalizeHookEvent } from '@rightkit/hooks';

import { ArcaneError } from '../lib/errors.mjs';
import { normalizeHostEvent } from '../lib/host-event.mjs';
import { canonicalJson, digest } from '../lib/canonical.mjs';
import { handleHookEvent, runHookMain, readStdinJson } from './hook-adapter-core.mjs';
import { dispatchHookInvocation } from './host-runtime.mjs';
import { serializeHostRuntimeOutput } from './host-runtime-output.mjs';

export const ADAPTER_NAME = 'codex';
export const ADAPTER_VERSION = process.env.CODEX_VERSION || 'unknown';
// Mirrors claude-code-adapter.mjs's DEFAULT_KEY_DIR shape (homedir()-relative
// per-host key directory); this tree carries no evidence of a Codex-specific
// home-directory env var (grepped predecessor/ — no CODEX_HOME reference exists),
// so this follows the same pattern rather than inventing one.
export const DEFAULT_KEY_DIR = join(homedir(), '.codex', 'arcane-keys');

/** Codex hook names that carry `tool_name`/`tool_input`/`tool_response` (mirrors claude-code-adapter.mjs). */
const TOOL_HOOK_EVENTS = Object.freeze(['PreToolUse', 'PostToolUse', 'PostToolUseFailure']);
const POST_TOOL_HOOK_EVENTS = Object.freeze(['PostToolUse', 'PostToolUseFailure']);
const SUPPORTED_HOOK_EVENTS = Object.freeze([
  'SessionStart', 'SubagentStart', 'UserPromptSubmit', 'PostCompact',
  'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop',
]);

const PRE_EFFECT_TOOL_MAP = Object.freeze({
  Write: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
  Edit: { effectClass: 'FILE_WRITE', targetField: 'file_path' },
});

function payloadThreadId(hookPayload) {
  const snake = hookPayload?.thread_id;
  const camel = hookPayload?.threadId;
  if (snake !== undefined && camel !== undefined && snake !== camel) {
    throw new ArcaneError('ARC_BINDING_MISMATCH', 'conflicting Codex payload thread identities');
  }
  return snake ?? camel ?? null;
}

/** Resolve Codex identity without allowing a transient hook session to split a durable thread binding. */
export function resolveCodexSessionId(hookPayload, env = process.env) {
  const durableThreadId = env.CODEX_THREAD_ID ?? null;
  const threadId = payloadThreadId(hookPayload);
  if (durableThreadId) {
    if (threadId !== null && threadId !== durableThreadId) {
      throw new ArcaneError('ARC_BINDING_MISMATCH', 'Codex payload thread identity conflicts with CODEX_THREAD_ID');
    }
    return durableThreadId;
  }
  return hookPayload?.session_id ?? hookPayload?.sessionId ?? threadId
    ?? env.CODEX_SESSION_ID ?? env.CLAUDE_SESSION_ID ?? null;
}

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
 * tools (per predecessor/hooks/codex/hooks.json's matcher list) and are excluded
 * from this map for the same reason Claude Code's Bash is excluded in
 * claude-code-adapter.mjs: a command string is not a path, and any parser
 * is defeatable by a command shaped to look benign.
 *
 * `apply_patch` is expanded by the runtime from its exact
 * `tool_input.command` patch text. It remains absent here because this closed
 * single-effect event schema cannot represent its ordered plural receipt set.
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
 *   one of the eight documented lifecycle events (predecessor/hooks/codex/hooks.json).
 */
export function buildRawCodexEvent(hookPayload) {
  try { hookPayload = normalizeHookEvent(hookPayload).payload; } catch { throw new ArcaneError('ARC_HOST_EVENT_INVALID', 'invalid HookHost payload'); }
  const eventType = hookPayload?.hook_event_name;
  if (typeof eventType !== 'string' || !SUPPORTED_HOOK_EVENTS.includes(eventType)) {
    throw new ArcaneError('ARC_HOST_EVENT_INVALID', `unsupported or missing Codex hook_event_name: ${eventType}`, {
      hookEventName: eventType ?? null,
    });
  }

  const isToolEvent = TOOL_HOOK_EVENTS.includes(eventType);
  const isPostTool = POST_TOOL_HOOK_EVENTS.includes(eventType);

  const sessionId = resolveCodexSessionId(hookPayload);

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
    // evidence this tree carries (predecessor/hooks/generic/hook.js never reads
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
      // shape (predecessor/hooks/generic/hook.js's `event.command ?? event.tool_input?.command`).
      // Write/Edit's target has no such evidence — Codex registers the same
      // tool names as Claude Code (predecessor/hooks/codex/hooks.json) through the
      // same shared predecessor core, so `tool_input.file_path` is read exactly as
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

export function observeCodexIdentity(hookPayload, { hostEvent } = {}) {
  if (['authority', 'callerAuthority', 'assertedAuthority', 'trust_class', 'trustClass', 'executor'].some((key) => Object.hasOwn(hookPayload ?? {}, key))) return { modelClaimed: true };
  const sessionId = hostEvent?.sessionId ?? resolveCodexSessionId(hookPayload);
  const agentId = hookPayload?.agent_id ?? hookPayload?.agentId ?? hookPayload?.subagent?.agent_id ?? hookPayload?.subagent?.agentId ?? null;
  const agentType = hookPayload?.agent_type ?? hookPayload?.agentType ?? hookPayload?.subagent?.agent_type ?? hookPayload?.subagent?.agentType ?? null;
  return sessionId && agentId && agentType ? { sessionId, agentId, agentType, eventId: hostEvent?.eventId } : null;
}

const PATCH_LIMIT_BYTES = 1024 * 1024;
const PATCH_LIMIT_EFFECTS = 256;

function patchPath(path, workspace) {
  if (typeof path !== 'string' || path.length === 0 || path !== path.trim() || /[\\\0\r\n]/.test(path)
    || path.startsWith('/') || path.startsWith('//') || /^[A-Za-z]:/.test(path)
    || path.split('/').some((part) => part === '' || part === '.' || part === '..')) return null;
  if (workspace && typeof workspace === 'string') {
    const root = workspace.replaceAll('\\', '/').replace(/\/$/, '');
    const resolved = join(root, path).replaceAll('\\', '/');
    if (!resolved.startsWith(`${root}/`)) return null;
  }
  return path;
}

/** Parse only Codex's exact `tool_input.command` patch text, never a model projection. */
export function parseCodexApplyPatch(command, { workspace } = {}) {
  if (typeof command !== 'string' || Buffer.byteLength(command, 'utf8') > PATCH_LIMIT_BYTES) return null;
  const lines = command.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  if (lines.length < 3 || lines[0] !== '*** Begin Patch' || lines.at(-1) !== '*** End Patch') return null;
  const effects = [];
  const seen = new Set();
  for (let i = 1; i < lines.length - 1;) {
    const header = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(lines[i]);
    if (!header) return null;
    const [, action, rawTarget] = header;
    const target = patchPath(rawTarget, workspace);
    if (!target) return null;
    i += 1;
    let destination = null;
    if (action === 'Update' && i < lines.length - 1) {
      const move = /^\*\*\* Move to: (.+)$/.exec(lines[i]);
      if (move) { destination = patchPath(move[1], workspace); if (!destination) return null; i += 1; }
    }
    while (i < lines.length - 1 && !lines[i].startsWith('*** ')) i += 1;
    if (i < lines.length - 1 && !/^\*\*\* (Add|Update|Delete) File: /.test(lines[i])) return null;
    const add = (effectClass, value) => {
      if (seen.has(value) || effects.length >= PATCH_LIMIT_EFFECTS) return false;
      seen.add(value); effects.push({ effectClass, target: value, operation: 'apply_patch' }); return true;
    };
    if (destination) {
      if (destination === target || !add('FILE_DELETE', target) || !add('FILE_WRITE', destination)) return null;
    } else if (!add(action === 'Delete' ? 'FILE_DELETE' : 'FILE_WRITE', target)) return null;
  }
  return effects.length > 0 ? effects : null;
}

function derivedPatchToolId(hostToolId, patchDigest, index, effect) {
  return createHash('sha256').update(`${hostToolId}\n${patchDigest}\n${index}\n${canonicalJson(effect)}`, 'utf8').digest('hex');
}

function mapCodexApplyPatch(command, toolUseId, workspace) {
  if (typeof toolUseId !== 'string' || toolUseId.length === 0) return null;
  const effects = parseCodexApplyPatch(command, { workspace });
  if (!effects) return null;
  const patchDigest = digest(command);
  return { operation: 'apply_patch', toolUseId, patchDigest, effects: effects.map((effect, index) => ({ ...effect, toolUseId: derivedPatchToolId(toolUseId, patchDigest, index, effect) })) };
}

export function mapCodexPreEffect(hookPayload, { workspace } = {}) {
  if (hookPayload?.tool_name === 'apply_patch') return mapCodexApplyPatch(hookPayload?.tool_input?.command, hookPayload?.tool_use_id, workspace);
  const mapping = PRE_EFFECT_TOOL_MAP[hookPayload?.tool_name];
  const target = mapping ? hookPayload?.tool_input?.[mapping.targetField] : null;
  if (!mapping || typeof target !== 'string' || target.length === 0 || typeof hookPayload?.tool_use_id !== 'string' || hookPayload.tool_use_id.length === 0) return null;
  return { effectClass: mapping.effectClass, target, operation: hookPayload.tool_name, toolUseId: hookPayload.tool_use_id };
}

export const codexHostAdapter = Object.freeze({ name: ADAPTER_NAME, normalize: normalizeCodexEvent, observeIdentity: observeCodexIdentity, mapPreEffect: mapCodexPreEffect });

// ---------------------------------------------------------------------------
// CLI entry point — mirrors claude-code-adapter.mjs's main(). Delegates to
// the shared `runHookMain` (./hook-adapter-core.mjs).
// ---------------------------------------------------------------------------

export function main({ keyDir, verificationKeyDirs, workspace, stateRoot, receiptStore, replayGuard, policy, capabilityStore = null, dependencyLedger = null, sessionBinding = null, preEffectCorrelation = null } = {}) {
  const configuredKeyDir = keyDir ?? process.env.ARCANE_KEY_DIR ?? DEFAULT_KEY_DIR;
  const configuredWorkspace = workspace ?? process.env.ARCANE_WORKSPACE ?? process.cwd();
  const verifyDirs = verificationKeyDirs ?? (keyDir || process.env.ARCANE_KEY_DIR ? [configuredKeyDir] : [join(homedir(), '.claude', 'arcane-keys'), join(homedir(), '.codex', 'arcane-keys')]);
  return runHookMain({ dispatchHookInvocation: (payload) => dispatchHookInvocation(payload, { adapter: codexHostAdapter, workspace: configuredWorkspace, keyDir: configuredKeyDir, verificationKeyDirs: verifyDirs, stateRoot: stateRoot ?? process.env.ARCANE_STATE_ROOT }) });
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
