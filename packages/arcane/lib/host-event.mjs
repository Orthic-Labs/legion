// S04 — host-event ingestion contract: normalize native adapter events into
// one versioned, closed host-event schema, and classify what a completed
// operation actually observed.
//
// Detailed plan §3.2 requires a single canonical host-event contract with:
// event id/type/time; adapter/client/host identity+versions; request/run/
// task/session binding; workspace/subject binding; actor/issuer identity;
// operation/tool identity; a redacted/canonical argument digest (never raw
// content); a proposed/observed effect descriptor; path/process/network
// metadata where available; result/exit/terminal metadata; prior event/
// receipt correlation; and host enforcement capabilities + known bypasses.
// "Unknown fields are rejected or contained in an explicit extensions
// object" — this schema is closed (additionalProperties:false) with exactly
// one open bag, `extensions`, exactly like legacy predecessor's ONE hard
// closed-schema validator, orthic.observable-event.v1
// (legacy-semantic-inventory.json #hook_enforcement_points /
// #record_types): "validateObservableEvent... rejects any field not in its
// allowlist — this is the one record type in the repo with a hard
// closed-schema validator at the boundary." Every other legacy record type
// is open. This module adopts that ONE discipline as the rule, not the
// exception.
//
// Credential metadata is deliberately NOT a field here (dispatch
// instruction: never read or print a credential). "Known bypasses" records
// that a capability is absent/weak, never the secret itself.
//
// classifyObservation never decides trust — closing S00 finding 5 (host
// authority is not automatically evidence) is lib/ingest.mjs's job. This
// module only names what kind of observation a completed operation is.

import { ArcaneError } from './errors.mjs';
import { validateSchema } from '../../../lib/qualification/schema-validator.mjs';
import { DIGEST_PATTERN } from './canonical.mjs';
import { ulid } from './ids.mjs';
import { EFFECT_CLASS } from '../../contracts/index.mjs';

const DATE_TIME_RE = '^\\d{4}-\\d{2}-\\d{2}[Tt]\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?([Zz]|[+-]\\d{2}:\\d{2})$';
const DIGEST_RE = DIGEST_PATTERN.source;

/**
 * Canonical event classes (detailed plan §7.2 required lifecycle hooks,
 * normalized). `normalizeHostEvent` translates real adapter-native names
 * (Claude Code / Codex hook events — legacy-semantic-inventory.json
 * #hook_enforcement_points) into these via LEGACY_HOST_EVENT_TYPE.
 */
export const EVENT_TYPE = Object.freeze([
  'session-start', // SessionStart — bind authority identity for the turn
  'subagent-start', // SubagentStart — bind subagent identity for the turn
  'user-prompt-submit', // UserPromptSubmit
  'post-compact', // PostCompact — context compaction boundary
  'pre-effect', // PreToolUse
  'post-effect', // PostToolUse
  'post-effect-failure', // PostToolUseFailure
  'stop', // Stop — final completion intent
  'ci-boundary', // CI/commit/release boundary, as the host permits
]);

/** Real host hook event names -> canonical EVENT_TYPE (§7.2, hook_enforcement_points). */
export const LEGACY_HOST_EVENT_TYPE = Object.freeze({
  SessionStart: 'session-start',
  SubagentStart: 'subagent-start',
  UserPromptSubmit: 'user-prompt-submit',
  PostCompact: 'post-compact',
  PreToolUse: 'pre-effect',
  PostToolUse: 'post-effect',
  PostToolUseFailure: 'post-effect-failure',
  Stop: 'stop',
});

/** Lifecycle telemetry with no effect class — never a check candidate, never a mutation. */
export const LIFECYCLE_TELEMETRY_EVENT_TYPES = Object.freeze(['session-start', 'user-prompt-submit', 'stop', 'ci-boundary', 'subagent-start', 'post-compact']);

/** effectClass/target/operation — the proposed effect (pre-effect events) or the observed effect (post-effect events). */
const EFFECT_IDENTITY_SCHEMA = Object.freeze({
  type: ['object', 'null'],
  additionalProperties: false,
  required: ['effectClass', 'target', 'operation'],
  properties: {
    effectClass: { enum: [...EFFECT_CLASS] },
    target: { type: 'string', minLength: 1 },
    operation: { type: 'string', minLength: 1 },
  },
});

/**
 * Closed host-event schema (§3.2). `extensions` is the one open bag — every
 * other field is named, typed, and additionalProperties:false at every
 * object level, so an unknown field is always ARC_HOST_EVENT_INVALID.
 */
export const HOST_EVENT_SCHEMA = Object.freeze({
  $id: 'arcane-host-event-v1',
  type: 'object',
  additionalProperties: false,
  required: [
    'schemaVersion', 'kind', 'eventId', 'eventType', 'time',
    'adapter', 'client', 'host',
    'runId', 'taskId', 'sessionId', 'requestId', 'contractId',
    'workspace', 'subject',
    'actor', 'operation', 'sourceRevision',
    'effect', 'result',
    'pathMeta', 'processMeta', 'networkMeta',
    'priorCorrelation', 'checkCorrelation', 'hostEnforcement',
    'replayNonce', 'replaySequence', 'idempotencyKey',
  ],
  properties: {
    schemaVersion: { const: 1 },
    kind: { const: 'arcane-host-event' },
    // event id/type/time (§3.2 bullet 1)
    eventId: { type: 'string', pattern: '^hev_[0-9A-HJKMNP-TV-Z]{26}$' },
    eventType: { enum: [...EVENT_TYPE] },
    time: { type: 'string', pattern: DATE_TIME_RE },

    // adapter/client/host identity + versions (§3.2 bullet 2)
    adapter: {
      type: 'object', additionalProperties: false, required: ['name', 'version'],
      properties: { name: { type: 'string', minLength: 1 }, version: { type: 'string', minLength: 1 } },
    },
    client: {
      type: 'object', additionalProperties: false, required: ['name', 'version'],
      properties: { name: { type: 'string', minLength: 1 }, version: { type: 'string', minLength: 1 } },
    },
    host: {
      type: 'object', additionalProperties: false, required: ['platform', 'version'],
      properties: { platform: { type: 'string', minLength: 1 }, version: { type: 'string', minLength: 1 } },
    },

    // request/run/task/session binding (§3.2 bullet 3)
    runId: { type: ['string', 'null'], pattern: '^run_[0-9A-HJKMNP-TV-Z]{26}$' },
    taskId: { type: ['string', 'null'], pattern: '^T-\\d+(\\.\\d+)*$' },
    sessionId: { type: ['string', 'null'], minLength: 1 },
    requestId: { type: ['string', 'null'], pattern: '^req_[0-9A-HJKMNP-TV-Z]{26}$' },
    contractId: { type: ['string', 'null'], pattern: '^EC-\\d+$' },

    // workspace/subject binding (§3.2 bullet 4)
    workspace: { type: 'string', minLength: 1 },
    subject: { type: ['string', 'null'] },

    // actor/issuer identity (§3.2 bullet 5) — never an authority claim, only
    // a process/connection identity; authority itself travels out of band
    // via HostIngestor's `authorityAssertion` parameter, never in the event.
    actor: {
      type: 'object', additionalProperties: false, required: ['issuerId', 'processIdentity'],
      properties: { issuerId: { type: 'string', minLength: 1 }, processIdentity: { type: ['string', 'null'] } },
    },

    // operation/tool identity + redacted/canonical argument digest (§3.2 bullets 6-7)
    operation: {
      type: 'object', additionalProperties: false, required: ['toolId', 'operationId', 'argumentDigest'],
      properties: {
        toolId: { type: 'string', minLength: 1 },
        operationId: { type: 'string', minLength: 1 },
        argumentDigest: { type: ['string', 'null'], pattern: DIGEST_RE },
      },
    },

    sourceRevision: { type: ['string', 'null'], minLength: 7 },

    // proposed/observed effect descriptor (§3.2 bullet 8)
    effect: EFFECT_IDENTITY_SCHEMA,

    // result/exit/terminal metadata (§3.2 bullet 10). observedDigest is an
    // "output/artifact digest" — a content digest, never raw content.
    result: {
      type: ['object', 'null'], additionalProperties: false, required: ['outcome', 'exitCode', 'terminal', 'observedDigest'],
      properties: {
        outcome: { enum: ['success', 'failure', 'blocked', 'no-op'] },
        exitCode: { type: ['integer', 'null'] },
        terminal: { type: 'boolean' },
        observedDigest: { type: ['string', 'null'], pattern: DIGEST_RE },
      },
    },

    // path/process/network metadata where available (§3.2 bullet 9).
    // Deliberately no credential metadata field — never read or print one.
    pathMeta: {
      type: ['object', 'null'], additionalProperties: false,
      properties: { path: { type: 'string' }, exists: { type: 'boolean' } },
    },
    processMeta: {
      type: ['object', 'null'], additionalProperties: false,
      properties: { pid: { type: 'integer' }, parentPid: { type: ['integer', 'null'] }, executablePath: { type: ['string', 'null'] } },
    },
    networkMeta: {
      type: ['object', 'null'], additionalProperties: false,
      properties: { host: { type: 'string' }, port: { type: ['integer', 'null'] }, protocol: { type: ['string', 'null'] } },
    },

    // prior event/receipt correlation (§3.2 bullet 11) — a post-effect event
    // must be able to name the pre-effect request it completes; HostIngestor
    // refuses ARC_INGEST_CORRELATION_MISSING when this is absent.
    priorCorrelation: {
      type: ['object', 'null'], additionalProperties: false,
      properties: {
        requestId: { type: ['string', 'null'], pattern: '^req_[0-9A-HJKMNP-TV-Z]{26}$' },
        capabilityId: { type: ['string', 'null'] },
        priorReceiptId: { type: ['string', 'null'] },
        requestedEffect: EFFECT_IDENTITY_SCHEMA,
        authorizedEffect: EFFECT_IDENTITY_SCHEMA,
      },
    },

    // Host-observed correlation to a Sage-declared check (WP4 action 7). Set
    // only by the adapter, from the capability it already brokered at the
    // pre-effect gate — never model-suppliable, since the model never sees
    // or controls this event.
    checkCorrelation: {
      type: ['object', 'null'], additionalProperties: false,
      properties: { declaredCheckId: { type: 'string', minLength: 1 }, method: { type: 'string', minLength: 1 } },
    },

    // host enforcement capabilities and known bypasses (§3.2 bullet 12)
    hostEnforcement: {
      type: 'object', additionalProperties: false, required: ['capabilities', 'knownBypasses'],
      properties: {
        capabilities: { type: 'array', items: { type: 'string' } },
        knownBypasses: { type: 'array', items: { type: 'string' } },
      },
    },

    // message-level replay defense on the event itself (S03 ReplayGuard).
    replayNonce: { type: ['string', 'null'] },
    replaySequence: { type: ['integer', 'null'] },

    idempotencyKey: { type: ['string', 'null'] },

    // The one open bag (§3.2: "unknown fields are rejected or contained in
    // an explicit extensions object"). No properties/additionalProperties
    // constraint inside it, on purpose.
    extensions: { type: 'object' },
  },
});

/**
 * Fields an S03 auth envelope covers when a host signs its own event, so
 * HostIngestor can call `verifyRecord` over a real bound-field list rather
 * than trusting an unstructured `receipt` (S00 finding 5).
 */
export const HOST_EVENT_BOUND_FIELDS = Object.freeze([
  'schemaVersion', 'kind', 'eventId', 'eventType', 'time',
  'runId', 'taskId', 'requestId', 'contractId', 'workspace',
  'operation', 'effect', 'result', 'sourceRevision', 'idempotencyKey',
]);

/** Structural validation only. @returns {{valid: boolean, issues: string[]}} */
export function validateHostEvent(e) {
  if (e === null || typeof e !== 'object' || Array.isArray(e)) {
    return { valid: false, issues: ['$:type'] };
  }
  const issues = validateSchema(HOST_EVENT_SCHEMA, e);
  return { valid: issues.length === 0, issues };
}

/**
 * Normalize a raw, adapter-native event into the canonical host-event shape.
 * `adapter` names which native surface produced `raw` when `raw` does not
 * already carry its own `adapter` block. `raw.eventType` may be a real hook
 * name (PreToolUse, PostToolUse, ...) or an already-canonical EVENT_TYPE
 * value.
 * @throws {ArcaneError} ARC_HOST_EVENT_INVALID when the normalized result
 *   does not satisfy HOST_EVENT_SCHEMA.
 */
export function normalizeHostEvent(raw, { adapter } = {}) {
  const eventType = LEGACY_HOST_EVENT_TYPE[raw?.eventType] ?? raw?.eventType ?? null;
  const candidate = {
    schemaVersion: 1,
    kind: 'arcane-host-event',
    eventId: raw?.eventId ?? `hev_${ulid()}`,
    eventType,
    time: raw?.time ?? new Date().toISOString(),

    adapter: raw?.adapter ?? adapter ?? null,
    client: raw?.client ?? null,
    host: raw?.host ?? null,

    runId: raw?.runId ?? null,
    taskId: raw?.taskId ?? null,
    sessionId: raw?.sessionId ?? null,
    requestId: raw?.requestId ?? null,
    contractId: raw?.contractId ?? null,

    workspace: raw?.workspace ?? '',
    subject: raw?.subject ?? null,

    actor: raw?.actor ?? { issuerId: 'unknown', processIdentity: null },
    operation: raw?.operation ?? { toolId: 'unknown', operationId: 'unknown', argumentDigest: null },
    sourceRevision: raw?.sourceRevision ?? null,

    effect: raw?.effect ?? null,
    result: raw?.result ?? null,

    pathMeta: raw?.pathMeta ?? null,
    processMeta: raw?.processMeta ?? null,
    networkMeta: raw?.networkMeta ?? null,

    priorCorrelation: raw?.priorCorrelation ?? null,
    checkCorrelation: raw?.checkCorrelation ?? null,
    hostEnforcement: raw?.hostEnforcement ?? { capabilities: [], knownBypasses: [] },

    replayNonce: raw?.replayNonce ?? null,
    replaySequence: raw?.replaySequence ?? null,
    idempotencyKey: raw?.idempotencyKey ?? null,

    ...(raw?.extensions !== undefined ? { extensions: raw.extensions } : {}),
  };

  const { valid, issues } = validateHostEvent(candidate);
  if (!valid) {
    throw new ArcaneError('ARC_HOST_EVENT_INVALID', 'normalized host event does not satisfy HOST_EVENT_SCHEMA', { issues });
  }
  return candidate;
}

// ---------------------------------------------------------------------------
// Classification (detailed plan §3.2 action 5; WP4 actions 5 and 8).
// ---------------------------------------------------------------------------

export const EFFECT_OBSERVATION_CLASS = Object.freeze([
  'mutation-observation',
  'deterministic-check-candidate',
  'source-observation',
  'failure',
  'non-qualifying-telemetry',
]);

const FILE_MUTATION_CLASSES = Object.freeze(['FILE_WRITE', 'FILE_DELETE', 'FILE_MOVE']);

// Every other effect class the frozen 12-value EFFECT_CLASS enum names is
// also a mutation once it succeeds: it leaves the machine (NETWORK_EGRESS),
// changes live process state (PROCESS_SPAWN), or is otherwise irreversible
// (CREDENTIAL_ACCESS, DEPENDENCY_INSTALL, VCS_COMMIT, VCS_PUSH, PUBLISH,
// EXTERNAL_SIDE_EFFECT). COMMAND_EXEC is excluded on purpose — it is a
// carrier, not a mutation in itself (lib/policy.mjs EFFECT_CLASS_RECONCILIATION).
const OTHER_MUTATING_CLASSES = Object.freeze([
  'NETWORK_EGRESS', 'PROCESS_SPAWN', 'CREDENTIAL_ACCESS', 'DEPENDENCY_INSTALL',
  'VCS_COMMIT', 'VCS_PUSH', 'PUBLISH', 'EXTERNAL_SIDE_EFFECT',
]);

/**
 * Classify a completed observation. Purely structural over the host event's
 * own fields — it never decides trust (HostIngestor does that) and never
 * proves a criterion by itself.
 *
 * Rules table (S04 acceptance):
 *  1. outcome=failure/blocked, or a non-zero exitCode -> 'failure'. Checked
 *     first: a failed FILE_WRITE is a failure, not a mutation that happened.
 *  2. FILE_WRITE/FILE_DELETE/FILE_MOVE (successful) -> 'mutation-observation',
 *     unconditionally — never a check candidate, never proof of correctness.
 *  3. Any other mutating effect class (NETWORK_EGRESS, PROCESS_SPAWN,
 *     CREDENTIAL_ACCESS, DEPENDENCY_INSTALL, VCS_COMMIT, VCS_PUSH, PUBLISH,
 *     EXTERNAL_SIDE_EFFECT) -> 'mutation-observation'.
 *  4. COMMAND_EXEC (successful, exit 0) -> 'deterministic-check-candidate'
 *     ONLY when the event carries a host-observed `checkCorrelation` naming
 *     a declared check (set by the adapter from the capability it already
 *     brokered pre-effect, never model-suppliable) — otherwise
 *     'source-observation'. An UNKNOWN command exiting 0 is therefore never
 *     a check candidate (WP4 action 8).
 *  5. No effect class at all: a named non-qualifying event type (session
 *     start, prompt submit, stop, ci boundary) -> 'non-qualifying-telemetry';
 *     anything else with observable content -> 'source-observation'.
 *  6. An effect class the single policy engine does not even recognize ->
 *     'non-qualifying-telemetry' (currently unreachable against the frozen
 *     12-value EFFECT_CLASS enum, which rules 2-4 already exhaust in full;
 *     it activates only if that enum grows — e.g. the FILE_READ amendment
 *     lib/policy.mjs's EFFECT_CLASS_RECONCILIATION proposes).
 */
export function classifyObservation(event, { policy } = {}) {
  if (!event || typeof event !== 'object') {
    throw new ArcaneError('ARC_HOST_EVENT_INVALID', 'classifyObservation requires a host event object', {});
  }

  const outcome = event.result?.outcome ?? null;
  const exitCode = event.result?.exitCode ?? null;
  const effectClass = event.effect?.effectClass ?? null;

  if (outcome === 'failure' || outcome === 'blocked' || (typeof exitCode === 'number' && exitCode !== 0)) {
    return 'failure';
  }

  if (effectClass && FILE_MUTATION_CLASSES.includes(effectClass)) {
    return 'mutation-observation';
  }
  if (effectClass && OTHER_MUTATING_CLASSES.includes(effectClass)) {
    return 'mutation-observation';
  }
  if (effectClass === 'COMMAND_EXEC') {
    return event.checkCorrelation?.declaredCheckId ? 'deterministic-check-candidate' : 'source-observation';
  }
  if (!effectClass) {
    return LIFECYCLE_TELEMETRY_EVENT_TYPES.includes(event.eventType) ? 'non-qualifying-telemetry' : 'source-observation';
  }
  if (policy && typeof policy.effectRule === 'function' && !policy.effectRule(effectClass)) {
    return 'non-qualifying-telemetry';
  }
  return 'source-observation';
}
