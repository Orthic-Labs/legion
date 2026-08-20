import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { ArcaneError, decision } from '../lib/errors.mjs';
import { loadHostKeyRing, loadVerificationKeyRing } from '../lib/keys.mjs';
import { loadPolicy, PolicyEngine, failClosedEngine } from '../lib/policy.mjs';
import { ReceiptStore } from '../lib/receipt-store.mjs';
import { ReplayGuard } from '../lib/replay.mjs';
import { CapabilityStore } from '../lib/capability-store.mjs';
import { ContractSealStore } from '../lib/contract-seal-store.mjs';
import { AuthorityBindingStore } from '../lib/authority-binding-store.mjs';
import { AuthorityLedger } from '../lib/authority.mjs';
import { SessionBindingStore } from '../lib/session-binding.mjs';
import { PreEffectCorrelationStore } from '../lib/preeffect-correlation.mjs';
import { PreEffectGate } from '../lib/preeffect-gate.mjs';
import { UserApprovalAuthority } from '../lib/user-approval.mjs';
import { handleHookEvent, evaluateHostStop } from './hook-adapter-core.mjs';
import { RuntimeSchemaSet } from '../lib/runtime-schema.mjs';
import { renderHostRuntimeOutput } from './host-runtime-output.mjs';
import { buildPolicyInjection } from './policy-inject.mjs';
import { preEffectDiscipline } from '../lib/discipline-controls.mjs';
import { evaluateTranscriptStop } from '../../../../hooks/stop-shape.mjs';
import { stopOutcome } from '../lib/stop-disposition.mjs';
import { classifyLatestUserIntent } from '../../../../hooks/user-intent.mjs';
import { HostEventLedger } from '../lib/host-event-ledger.mjs';
import { PendingTerminalOperationStore } from '../lib/pending-terminal-operation-store.mjs';
import { digestValue } from '../lib/canonical.mjs';
import { AuthorityInvocationProofIssuer } from '../lib/authority-invocation-proof.mjs';
import { createDecisionEnvelope } from '../lib/decision-envelope.mjs';
import { DenialCircuit, applyDenialCircuit } from '../lib/denial-circuit.mjs';
import { BudgetGovernanceStore } from '../lib/budget-governance-store.mjs';
import { TaskBudgetSealStore } from '../lib/task-budget-seal-store.mjs';
import { ArchitectureEventStore } from '../lib/architecture-event-store.mjs';
import { consumeHostArchitectureLifecycle } from '../lib/continuity.mjs';
import { completionIntegratedStateForRepositories, latestScopedMaterialChange } from '../lib/completion-state.mjs';

const POLICY_INJECT_EVENTS = new Set(['SessionStart', 'SubagentStart', 'UserPromptSubmit', 'PostCompact']);

const schema = new RuntimeSchemaSet();
const EVENT_TYPES = new Set(['SessionStart', 'SubagentStart', 'UserPromptSubmit', 'PostCompact', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop']);
const OBSERVED_AGENT_AUTHORITIES = new Set(['sage', 'alchemist', 'oracle']);
const isoClock = (clock) => () => new Date(clock()).toISOString();
const denial = (code, message, enforcementHealth = 'strong') => decision({ allowed: false, code, message, detail: {}, enforcementHealth });
const latitudeFor = (contract, target) => contract.artifacts.exact.some((artifact) => artifact.path === target) ? 'EXACT' : 'BOUNDED';

function hostRetry(hookPayload, eventType) {
  if (eventType !== 'PostToolUseFailure') return null;
  return {
    method: String(hookPayload?.tool_name ?? 'unknown'),
    inputState: digestValue(hookPayload?.tool_input ?? null),
    error: digestValue(hookPayload?.tool_response ?? hookPayload?.error ?? null),
  };
}

function hostProgress(eventType) { return eventType === 'PostToolUse'; }

function observedAuthorityFor(eventType, identity, authorityBindings, adapter, sessionId = identity?.sessionId) {
  // SessionStart authenticates Legion only after its host adapter observed the
  // durable root identity & persisted its immutable root binding. UserPromptSubmit
  // remains current-user provenance, never Legion authority.
  if (eventType === 'SessionStart') {
    const root = authorityBindings.get({ adapter, sessionId, agentId: 'legion-session-root' });
    if (adapter === 'codex' && identity?.rootThreadId === sessionId) return 'legion';
    return root?.authority === 'legion' ? 'legion' : null;
  }
  if (!identity?.sessionId || !identity?.agentId || !OBSERVED_AGENT_AUTHORITIES.has(identity?.agentType)) return null;
  const root = authorityBindings.get({ adapter, sessionId: identity.sessionId, agentId: 'legion-session-root' });
  if (root?.authority !== 'legion') return null;
  const binding = authorityBindings.get({ adapter, sessionId: identity.sessionId, agentId: identity.agentId });
  if (adapter === 'codex' && identity.rootThreadId === identity.sessionId) return identity.agentType;
  return binding?.authority === identity.agentType ? binding.authority : null;
}

export function evaluateLatestStopShape(hookPayload) {
  return evaluateTranscriptStop(hookPayload);
}

function codeOf(error) {
  return error instanceof ArcaneError ? error.code : 'ARC_STORE_CORRUPT';
}

const READ_ONLY_STOP_INTENTS = new Set(['QUESTION', 'PLAN', 'REVOKE', 'SCOPE_NARROW']);
const AVAILABILITY_CODES = new Set(['ARC_STORE_CORRUPT', 'ARC_AUTH_KEY_UNAVAILABLE']);

/** Latest user intent classifies a Stop only; it never authorizes an effect. */
export function readOnlyStopIntent(hookPayload) {
  const transcriptPath = hookPayload?.transcript_path;
  if (typeof transcriptPath !== 'string' || transcriptPath.length === 0) return { intent: 'UNKNOWN', readOnly: false };
  try {
    const intent = classifyLatestUserIntent(readFileSync(transcriptPath, 'utf8')).intent;
    return { intent, readOnly: READ_ONLY_STOP_INTENTS.has(intent) };
  } catch {
    return { intent: 'UNKNOWN', readOnly: false };
  }
}

function readOnlyStoreDiagnostic(eventType, hookPayload, error, stores, identity, adapterName) {
  if (eventType !== 'Stop' || !readOnlyStopIntent(hookPayload).readOnly || codeOf(error) !== 'ARC_STORE_CORRUPT') return null;
  if (identity?.sessionId && identity?.agentId) stores.authorityBinding.recover({ adapter: adapterName, sessionId: identity.sessionId, agentId: identity.agentId });
  return runtimeResult(eventType, { decision: decision({ allowed: true, code: 'ARC_STORE_CORRUPT', message: 'read-only Stop observed unavailable Arcane state', detail: {}, enforcementHealth: 'degraded' }), enforcementHealth: 'degraded' });
}

function runtimeResult(eventType, result) {
  const detail = result.decision.detail ?? {};
  const envelope = createDecisionEnvelope({ allowed: result.decision.allowed, code: result.decision.code, detail, enforcementHealth: result.enforcementHealth ?? result.decision.enforcementHealth ?? 'strong' });
  const value = {
    schemaVersion: 1,
    kind: 'arcane-host-runtime-result',
    eventType,
    allowed: envelope.allowed,
    code: envelope.code,
    publicReason: envelope.publicReason,
    enforcementHealth: envelope.enforcementHealth,
    receiptId: result.receipt?.receiptId ?? null,
    capabilityId: result.capabilityId ?? null,
    retrySignature: envelope.retrySignature,
    termination: envelope.termination,
    certification: envelope.certification,
    missingClasses: envelope.missingClasses,
    responsibleProducer: envelope.responsibleProducer,
    remediationRoutes: envelope.remediationRoutes,
    missingEvidence: envelope.missingEvidence,
    stdout: renderHostRuntimeOutput({ eventType, allowed: result.decision.allowed, code: result.decision.code, detail, enforcementHealth: envelope.enforcementHealth, escalate: Boolean(result.decision.escalate) }),
  };
  schema.assert('arcane-host-runtime-result-v1', value);
  return value;
}

function availabilityFallback({ eventType, code, contracted, hookPayload, adapter, policy, workspace }) {
  if (!AVAILABILITY_CODES.has(code)) return null;
  if (eventType === 'PreToolUse') {
    const control = preEffectDiscipline(hookPayload, { workspace, policy, contracted, checkCommit: false });
    if (control) return runtimeResult(eventType, { decision: denial(control.code, control.message), enforcementHealth: 'strong' });
    const mapped = typeof adapter.mapPreEffect === 'function' ? adapter.mapPreEffect(hookPayload, { workspace }) : null;
    const effects = mapped?.effects ?? (mapped ? [mapped] : []);
    const locked = effects.length > 0 && policy.lockedDomainsFor(effects.map(({ target }) => target)).length > 0;
    if (contracted || locked) return runtimeResult(eventType, { decision: denial(code, 'Arcane unavailable for governed effect'), enforcementHealth: 'unsupported' });
  } else if (contracted) {
    return runtimeResult(eventType, { decision: denial(code, 'Arcane unavailable for governed work'), enforcementHealth: 'unsupported' });
  }
  return runtimeResult(eventType, { decision: decision({ allowed: true, code, message: 'Arcane unavailable; ambient operation bypassed', detail: {}, enforcementHealth: 'degraded' }), enforcementHealth: 'degraded' });
}

/**
 * Compose Arcane's native host boundary. `adapter` must provide `normalize`;
 * optional host-only `observeIdentity` & `mapPreEffect` hooks supply evidence
 * that a generic runtime cannot invent.
 */
export function createHostRuntime({ adapter, workspace, keyDir, verificationKeyDirs = [keyDir], stateRoot = join(workspace, '.audit', 'arcane'), clock = () => Date.now() }) {
  if (!adapter || typeof adapter.normalize !== 'function' || typeof workspace !== 'string' || workspace.length === 0) {
    throw new TypeError('createHostRuntime requires adapter.normalize and workspace');
  }
  let policy;
  try { policy = new PolicyEngine(loadPolicy()); } catch (error) { policy = failClosedEngine(codeOf(error)); }
  let keyRing = null;
  try { keyRing = loadHostKeyRing({ dir: keyDir }); } catch { keyRing = null; }
  let verificationKeyRing = null;
  try { verificationKeyRing = loadVerificationKeyRing({ dirs: verificationKeyDirs }); } catch { verificationKeyRing = null; }
  const paths = {
    receipts: join(stateRoot, 'receipts'),
    replay: join(stateRoot, 'replay'),
    capabilities: join(stateRoot, 'capabilities'),
    seals: join(stateRoot, 'contract-seals'),
    authority: join(stateRoot, 'authority-bindings'),
    sessions: join(stateRoot, 'session-bindings'),
    correlations: join(stateRoot, 'pre-effect-correlations'),
    events: join(stateRoot, 'host-events'),
    terminalOperations: join(stateRoot, 'terminal-operations'),
    authorityInvocations: join(stateRoot, 'authority-invocations'),
    denialCircuit: join(stateRoot, 'denial-circuit'),
    budgets: join(stateRoot, 'budget-governance'),
    taskBudgets: join(stateRoot, 'task-budget-seals'),
  };
  const denialCircuit = keyRing ? new DenialCircuit({ root: paths.denialCircuit, keyRing, keyId: keyRing.activeKeyId(), clock: isoClock(clock) }) : null;
  const stores = {
    receiptStore: new ReceiptStore({ root: paths.receipts }),
    replayGuard: new ReplayGuard({ ...policy.replayLimits(), clock }),
    capabilityStore: new CapabilityStore({ root: paths.capabilities, clock }),
    sealStore: new ContractSealStore({ root: paths.seals, clock: isoClock(clock) }),
    authorityBinding: new AuthorityBindingStore({ root: paths.authority, clock: isoClock(clock) }),
    authorityLedger: new AuthorityLedger({ clock }),
    sessionBinding: new SessionBindingStore({ root: paths.sessions }),
    preEffectCorrelation: new PreEffectCorrelationStore({ root: paths.correlations }),
    budgetGovernance: keyRing ? new BudgetGovernanceStore({ root: paths.budgets, keyRing, monotonicNow: () => Number(process.hrtime.bigint() / 1000000n) }) : null,
    taskBudgetSeals: keyRing ? new TaskBudgetSealStore({ root: paths.taskBudgets, keyRing, keyId: keyRing.activeKeyId(), clock: isoClock(clock) }) : null,
  };
  const architectureEvents = keyRing ? new ArchitectureEventStore({ receiptStore: stores.receiptStore, keyRing, keyId: keyRing.activeKeyId(), clock: isoClock(clock) }) : null;
  const userApproval = new UserApprovalAuthority({ keyRing, policy, clock });
  const gate = new PreEffectGate({ policy, capabilityStore: stores.capabilityStore, authorityLedger: stores.authorityLedger, approvalAuthority: userApproval, clock });
  Object.assign(stores, { policy, keyRing, verificationKeyRing, userApproval, gate, denialCircuit });
  let receiptSequence = 0;

  // This is the sole runtime circuit projection. Every path returns through
  // `finish` once host binding exists; it cannot change allowed/effect state.
  const finish = (eventType, result, { binding = null, hostEvent = null, hookPayload = null, target = null } = {}) => {
    const governed = Boolean(binding?.contractId);
    if (!result.decision.allowed && AVAILABILITY_CODES.has(result.decision.code)) {
      const fallback = availabilityFallback({ eventType, code: result.decision.code, contracted: governed, hookPayload, adapter, policy, workspace });
      if (fallback) return fallback;
    }
    if (!result.decision.allowed && denialCircuit && binding?.runId && binding?.taskId && hostEvent?.sessionId) {
      try {
        result = { ...result, decision: applyDenialCircuit(result.decision, denialCircuit, {
          eventType, sessionId: hostEvent.sessionId, runId: binding.runId, taskId: binding.taskId,
          target: target ?? hostEvent.effect?.target ?? hookPayload?.tool_input?.file_path ?? hookPayload?.tool_name ?? null,
        }) };
      } catch (error) {
        result = { ...result, decision: denial(codeOf(error), 'authenticated denial circuit unavailable', 'unsupported'), enforcementHealth: 'unsupported' };
      }
    }
    // Persist & verify host-observed lifecycle after ingress has been
    // authenticated. This is telemetry/control-plane continuity only; it
    // never upgrades an effect decision or consumes model-supplied state.
    if (architectureEvents && hostEvent && (eventType !== 'PreToolUse' || result.decision.allowed)) {
      try {
        consumeHostArchitectureLifecycle({ eventStore: architectureEvents, hostEvent, binding, workspace, stopIntent: eventType === 'Stop' ? readOnlyStopIntent(hookPayload).intent : 'UNKNOWN' });
      } catch (error) {
        const fallback = availabilityFallback({ eventType, code: codeOf(error), contracted: governed, hookPayload, adapter, policy, workspace });
        if (fallback) return fallback;
        result = { ...result, decision: denial(codeOf(error), 'architecture lifecycle unavailable', 'unsupported'), enforcementHealth: 'unsupported' };
      }
    }
    return runtimeResult(eventType, result);
  };

  const handle = (hookPayload) => {
    const eventType = hookPayload?.hook_event_name;
    let identity = null;
    let contracted = false;
    if (!EVENT_TYPES.has(eventType)) {
      return runtimeResult('PreToolUse', { decision: denial('ARC_HOST_EVENT_INVALID', 'invalid host event'), enforcementHealth: 'strong' });
    }
    try {
      const hostEvent = adapter.normalize(hookPayload);
      identity = typeof adapter.observeIdentity === 'function' ? adapter.observeIdentity(hookPayload, { hostEvent }) : null;
      if (identity?.modelClaimed) return runtimeResult(eventType, { decision: denial('ARC_AUTHORITY_MODEL_CLAIMED', 'payload authority claim refused'), enforcementHealth: 'strong' });
      if (eventType === 'SessionStart' && hostEvent.sessionId) {
        // Codex authority requires native hook identity. A session_id-less or
        // wrapper-only invocation remains ambient & cannot mint Legion.
        // A wrapper-only SessionStart remains ambient and may be recorded, but
        // it cannot create a Legion binding. Authority-bearing consumers below
        // require the native root and the durable binding.
      }
      if (eventType === 'SubagentStart' && adapter.name === 'codex' && (!identity?.rootThreadId || identity.rootThreadId !== hostEvent.sessionId)) {
        return runtimeResult(eventType, { decision: denial('ARC_AUTHORITY_NOT_ASSERTED', 'Codex SubagentStart requires native session_id'), enforcementHealth: 'strong' });
      }
      if (eventType === 'SubagentStart' && identity?.sessionId && identity?.agentId && identity?.agentType) {
        const root = stores.authorityBinding.get({ adapter: adapter.name, sessionId: identity.sessionId, agentId: 'legion-session-root' });
        if (adapter.name === 'codex' && (identity.rootThreadId !== identity.sessionId || root?.authority !== 'legion')) {
          return runtimeResult(eventType, { decision: denial('ARC_AUTHORITY_NOT_ASSERTED', 'Codex subagent requires current observed Legion root'), enforcementHealth: 'strong' });
        }
      }
      const binding = hostEvent.sessionId ? stores.sessionBinding.getBinding(hostEvent.sessionId) : null;
      if (binding?.contractId) {
        if (hostEvent.contractId && hostEvent.contractId !== binding.contractId) {
          return finish(eventType, { decision: denial('ARC_CONTRACT_VERSION_MISMATCH', 'session contract differs'), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload });
        }
        const seal = stores.sealStore.get(binding.contractId, binding.contractVersion);
        if (!seal || seal.contractDigest !== binding.contractDigest) {
          return finish(eventType, { decision: denial('ARC_CONTRACT_VERSION_MISMATCH', 'sealed session contract differs'), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload });
        }
      }
      const boundSeal = binding?.contractId ? stores.sealStore.get(binding.contractId, binding.contractVersion) : null;
      contracted = Boolean(boundSeal && boundSeal.contractDigest === binding.contractDigest);
      // Host-derived ledger metadata is persisted before any policy dispatch;
      // adapters never supply sequence, correlation, or Stop ordinal fields.
      if (!keyRing) return availabilityFallback({ eventType, code: 'ARC_AUTH_KEY_UNAVAILABLE', contracted, hookPayload, adapter, policy, workspace });
      let lifecycleBinding = null;
      try {
        const ledger = new HostEventLedger({ root: paths.events, keyRing, keyId: keyRing.activeKeyId(), verificationKeyRing, clock: isoClock(clock) });
        const continuity = ledger.verify();
        if (!continuity.allowed) return availabilityFallback({ eventType, code: continuity.code, contracted, hookPayload, adapter, policy, workspace });
        if (adapter.name === 'codex' && ['SessionStart', 'SubagentStart'].includes(eventType)) {
          const payloadDigest = digestValue(hookPayload);
          if (ledger.records().some((event) => event.adapter === adapter.name && event.eventType === eventType && event.sessionId === hostEvent.sessionId && event.payloadDigest === payloadDigest)) {
            return runtimeResult(eventType, { decision: denial('ARC_REPLAY_NONCE_SEEN', 'duplicate Codex lifecycle observation'), enforcementHealth: 'strong' });
          }
        }
        // Bind lifecycle authority before appending its signed observation. A
        // failed binding therefore cannot leave an authority-bearing ledger
        // record. If append fails after a new binding, rollback that binding
        // so both stores remain empty for this observation.
        if (eventType === 'SessionStart' && hostEvent.sessionId && (adapter.name !== 'codex' || identity?.rootThreadId === hostEvent.sessionId)) {
          lifecycleBinding = stores.authorityBinding.observeLegionSession({ adapter: adapter.name, sessionId: hostEvent.sessionId, eventId: hostEvent.eventId });
        } else if (eventType === 'SubagentStart' && identity?.sessionId && identity?.agentId && identity?.agentType) {
          lifecycleBinding = stores.authorityBinding.observe({ adapter: adapter.name, eventId: hostEvent.eventId, ...identity });
        }
        hostEvent.ledger = ledger.append({ eventId: identity?.eventId ?? hostEvent.eventId, adapter: adapter.name, eventType, sessionId: hostEvent.sessionId, binding, sourceRevision: boundSeal?.sourceRevision ?? null, observedAuthority: observedAuthorityFor(eventType, identity, stores.authorityBinding, adapter.name, hostEvent.sessionId), payload: hookPayload });
      } catch (error) {
        if (lifecycleBinding?.created) {
          try {
            stores.authorityBinding.rollback({ adapter: adapter.name, sessionId: hostEvent.sessionId, agentId: eventType === 'SessionStart' ? 'legion-session-root' : identity?.agentId, record: lifecycleBinding.record });
          } catch (rollbackError) {
            return runtimeResult(eventType, { decision: denial(codeOf(rollbackError), 'lifecycle binding rollback failed'), enforcementHealth: 'unsupported' });
          }
        }
        if (codeOf(error) === 'ARC_STORE_CORRUPT' && identity?.sessionId && identity?.agentId) {
          stores.authorityBinding.recover({ adapter: adapter.name, sessionId: identity.sessionId, agentId: identity.agentId });
        }
        const fallback = availabilityFallback({ eventType, code: codeOf(error), contracted, hookPayload, adapter, policy, workspace });
        if (fallback) return fallback;
        return runtimeResult(eventType, { decision: denial(codeOf(error), 'authenticated event ledger unavailable'), enforcementHealth: 'unsupported' });
      }
      if (contracted) {
        try {
          let taskBudget = null;
          try { taskBudget = stores.taskBudgetSeals.require(binding.contractId, binding.taskId); } catch {}
          // Legacy direct bindings have no task-budget seal. `run open` is
          // now exact-budget-gated, so every new governed run has one; retain
          // receipt-only compatibility for existing sealed runtime fixtures.
          if (!taskBudget) taskBudget = null;
          else if (taskBudget.contractVersion !== binding.contractVersion || taskBudget.contractDigest !== binding.contractDigest) {
            return finish(eventType, { decision: denial('ARC_BINDING_MISMATCH', 'task budget differs from session contract'), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload });
          }
          if (taskBudget) {
            const runBudget = stores.budgetGovernance.begin({ contractId: binding.contractId, version: binding.contractVersion, taskId: binding.taskId, runId: binding.runId, activeTimeCapMs: taskBudget.activeTimeCapMs, progressDeadlineMs: taskBudget.progressDeadlineMs });
            const observedBudget = stores.budgetGovernance.observe(runBudget, { progress: hostProgress(eventType), retry: hostRetry(hookPayload, eventType) });
            if (observedBudget.kind === 'BUDGET_STOP') {
              return finish(eventType, { decision: denial(observedBudget.code, 'task budget stopped further effects'), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload });
            }
          }
        } catch (error) { return finish(eventType, { decision: denial(codeOf(error), 'authenticated task budget unavailable'), enforcementHealth: 'unsupported' }, { binding, hostEvent, hookPayload }); }
      }
      if (eventType === 'PreToolUse') {
        const control = preEffectDiscipline(hookPayload, { workspace, policy, checkCommit: false });
        if (control) return finish(eventType, { decision: denial(control.code, control.message), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload });
      }
      let observed = typeof adapter.mapPreEffect === 'function' && eventType === 'PreToolUse'
        ? adapter.mapPreEffect(hookPayload, { hostEvent, binding, workspace }) : null;

      // `apply_patch` is one host call with ordered singular effects. Its exact
      // command is parsed here on both sides of execution; no payload-provided
      // target or authority claim can widen that list.
      const patch = typeof adapter.mapPreEffect === 'function' && hookPayload?.tool_name === 'apply_patch'
        ? adapter.mapPreEffect(hookPayload, { hostEvent, binding, workspace }) : null;
      if (hookPayload?.tool_name === 'apply_patch' && !patch) {
        return runtimeResult(eventType, { decision: denial('ARC_HOST_EVENT_INVALID', 'malformed apply_patch payload'), enforcementHealth: 'strong' });
      }

      // Ambient tier (canon A-ER-1: evidence is not authorization). A session
      // with no sealed contract still observes its effects and earns receipts;
      // it authorizes nothing, so there is no capability to mint and the gated
      // branch below does not apply. Locked domains are the exception and keep
      // failing closed: mutating the enforcement plane or sealed qualification
      // evidence still requires a sealed contract. Denying every uncontracted
      // effect instead (the prior behaviour) made ordinary user-requested work
      // impossible on every harness while protecting nothing the locked-domain
      // check does not already protect.
      const observedEffects = patch?.effects ?? (observed ? [observed] : []);
      if (eventType === 'PreToolUse' && observedEffects.length > 0 && !contracted) {
        if (policy.lockedDomainsFor(observedEffects.map((effect) => effect.target)).length > 0) {
          return finish(eventType, { decision: denial('ARC_NO_CONTRACT', 'locked-domain effect requires a sealed contract'), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload });
        }
        observed = null;
      }

      if (eventType === 'PreToolUse' && observedEffects.length > 0 && contracted) {
        const seal = boundSeal;
        const prepared = [];
        for (const effect of observedEffects) {
          const reservation = stores.preEffectCorrelation.reserve(effect.toolUseId);
          if (!reservation) return finish(eventType, { decision: denial('ARC_STORE_CORRUPT', 'pre-effect correlation unavailable'), enforcementHealth: 'unsupported' }, { binding, hostEvent, hookPayload, target: effect.target });
          if (!reservation.created) return finish(eventType, { decision: denial('ARC_REPLAY_NONCE_SEEN', 'pre-effect delivery already reserved'), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload, target: effect.target });
          const authority = identity?.sessionId && identity?.agentId
            ? stores.authorityBinding.assertForTurn({ adapter: adapter.name, sessionId: identity.sessionId, agentId: identity.agentId, turnId: reservation.requestId, authorityLedger: stores.authorityLedger, keyId: keyRing?.activeKeyId() }) : null;
          if (!authority) return finish(eventType, { decision: denial('ARC_NO_CONTRACT', 'sealed contract unavailable'), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload, target: effect.target });
          const request = { schemaVersion: 1, kind: 'legion-effect-request', requestId: reservation.requestId, runId: binding.runId, contractId: seal.contractId, taskId: binding.taskId, requestedBy: authority.authority, effectClass: effect.effectClass, target: effect.target, operation: effect.operation, latitude: latitudeFor(seal.contract, effect.target), sourceRevision: seal.contract.sourceRevision, requestedAt: new Date(clock()).toISOString() };
          const context = { contract: seal.contract, contractDigest: seal.contractDigest, turnId: reservation.requestId, workspace, expectedContractVersion: seal.version, requestId: reservation.requestId, sessionId: hostEvent.sessionId, transcriptPath: hookPayload?.transcript_path };
          const authorized = gate.authorize(request, context);
          if (!authorized.allowed) return finish(eventType, { decision: authorized, enforcementHealth: authorized.enforcementHealth }, { binding, hostEvent, hookPayload, target: effect.target });
          prepared.push({ request, context, capabilityId: authorized.detail.capabilityId, toolUseId: effect.toolUseId });
        }
        for (const item of prepared) {
          const consumed = gate.evaluate(item.request, { ...item.context, capabilityId: item.capabilityId });
          if (!consumed.allowed) return finish(eventType, { decision: consumed, enforcementHealth: consumed.enforcementHealth }, { binding, hostEvent, hookPayload, target: effect.target });
          const requestedEffect = { effectClass: item.request.effectClass, target: item.request.target, operation: item.request.operation };
          const authorizedEffect = { effectClass: item.request.effectClass, target: item.request.target, operation: item.request.operation };
          const finalized = stores.preEffectCorrelation.finalize(item.toolUseId, { requestId: item.request.requestId, capabilityId: item.capabilityId, requestedEffect, authorizedEffect });
          if (!finalized) return finish(eventType, { decision: denial('ARC_STORE_CORRUPT', 'pre-effect correlation finalization failed'), enforcementHealth: 'strong' }, { binding, hostEvent, hookPayload, target: effect.target });
        }
        return finish(eventType, { decision: { allowed: true, code: null, message: 'authorized', detail: {}, enforcementHealth: 'strong' }, capabilityId: prepared[0]?.capabilityId ?? null }, { binding, hostEvent, hookPayload });
      }
      if (patch?.effects?.length && eventType !== 'PreToolUse') {
        const outcomes = patch.effects.map((effect) => handleHookEvent(hookPayload, {
          normalize: (payload) => ({ ...adapter.normalize(payload), effect: { effectClass: effect.effectClass, target: effect.target, operation: effect.operation }, idempotencyKey: effect.toolUseId, replayNonce: effect.toolUseId, replaySequence: ++receiptSequence }),
          keyRing, verificationKeyRing, receiptStore: stores.receiptStore, replayGuard: stores.replayGuard, policy,
          capabilityStore: stores.capabilityStore, clock, sessionBinding: stores.sessionBinding, preEffectCorrelation: stores.preEffectCorrelation,
        }));
        const failed = outcomes.find((outcome) => !outcome.decision.allowed);
        const outcome = failed ?? outcomes.at(-1);
        return finish(eventType, { decision: outcome.decision, receipt: outcome.receipt, enforcementHealth: outcome.enforcementHealth }, { binding, hostEvent, hookPayload });
      }
      const outcome = handleHookEvent(hookPayload, {
        normalize: adapter.normalize, keyRing, verificationKeyRing, receiptStore: stores.receiptStore, replayGuard: stores.replayGuard, policy,
        capabilityStore: stores.capabilityStore, clock, sessionBinding: stores.sessionBinding, preEffectCorrelation: stores.preEffectCorrelation,
      });
      if (eventType === 'Stop' && outcome.decision.allowed) {
        const terminalStore = new PendingTerminalOperationStore({ root: paths.terminalOperations, keyRing, keyId: keyRing.activeKeyId(), clock: isoClock(clock) });
        const stopIntent=readOnlyStopIntent(hookPayload).intent;
        const claim = terminalStore.matching({ turnCorrelationDigest: hostEvent.ledger?.turnCorrelationDigest, stopOrdinal: hostEvent.ledger?.stopOrdinal });
        const terminal=!['QUESTION','PLAN','PAUSE','REVOKE','SCOPE_NARROW'].includes(stopIntent);
        const consumed = claim ? terminalStore.resolve({ claimId: claim.claimId, stopEventDigest: digestValue(hostEvent.ledger), turnCorrelationDigest: hostEvent.ledger.turnCorrelationDigest, stopOrdinal: hostEvent.ledger.stopOrdinal, terminal }) : null;
        const stop = stopOutcome({ intent: stopIntent, authenticatedClaim: Boolean(consumed?.allowed&&terminal) });
        // A host Stop without an explicit completion claim always terminates;
        // failed certification is reported independently and cannot trap it.
        const issuer = new AuthorityInvocationProofIssuer({ root: paths.authorityInvocations, keyRing, keyId: keyRing.activeKeyId(), ledgerStore: new HostEventLedger({ root: paths.events, keyRing, keyId: keyRing.activeKeyId(), verificationKeyRing, clock: isoClock(clock) }) });
        const currentProof = claim ? issuer.findByDigest(claim.invocationProofDigest) : null;
        const execution = boundSeal ? { runId: binding.runId, taskId: binding.taskId, contractId: binding.contractId, contractVersion: binding.contractVersion, contractDigest: binding.contractDigest, sourceRevision: boundSeal.sourceRevision, acceptanceCriteria: boundSeal.contract.acceptanceCriteria } : null;
        const completionRepos = execution ? (binding?.delivery?.repositories?.length ? binding.delivery.repositories.map((repo) => ({ cwd: repo.root, scope: boundSeal.contract.scope.own })) : [{ cwd: workspace, scope: boundSeal.contract.scope.own }]) : [];
        const latestCompletionChange = completionRepos.map(({ cwd, scope }) => latestScopedMaterialChange(stores.receiptStore, execution.runId, scope, cwd)).filter(Boolean).sort().at(-1) ?? null;
        const stopped = evaluateHostStop(outcome.hostEvent, { policy, receiptStore: stores.receiptStore, keyRing, authorityBindingStore: stores.authorityBinding, currentProof, binding: binding ? { ...binding, sessionId: hostEvent.sessionId } : null, execution, completionClaim: claim, authorityProofIssuer: issuer, integratedState: execution ? completionIntegratedStateForRepositories(completionRepos) : null, latestMaterialChange: latestCompletionChange, now: new Date(clock()), disposition: stop.disposition, intent: stopIntent, authenticatedClaim: Boolean(consumed?.allowed && consumed.detail?.certification === 'genuine') });
        if (stop.certification === 'genuine' && !stopped.allowed) outcome.decision = stopped;
        if (outcome.decision.allowed) {
          const shaped = evaluateLatestStopShape(hookPayload);
          if (shaped.block) outcome.decision = denial('ARC_STOP_SHAPE', shaped.instruction, 'advisory');
        }
      }
      const result = finish(eventType, outcome, { binding, hostEvent, hookPayload });
      // renderHostRuntimeOutput returns null when allowed, which is exactly why
      // the standalone Python injectors (brief/minimize/ccx) existed. Fire the
      // same injection here, independent of the allow/deny branch above, so it
      // reaches allowed SessionStart/SubagentStart without a parallel path.
      if (result.allowed && result.stdout === null && POLICY_INJECT_EVENTS.has(eventType)) {
        const injection = buildPolicyInjection({ workspace, prompt: hookPayload?.prompt ?? hookPayload?.user_prompt ?? null, gotchasOnly: eventType === 'UserPromptSubmit' });
        if (injection) {
          const envelope = createDecisionEnvelope({ allowed: true, code: null });
          const stdout = { hookSpecificOutput: { hookEventName: eventType, additionalContext: injection.additionalContext }, code: envelope.code, publicReason: envelope.publicReason, enforcementHealth: envelope.enforcementHealth, retrySignature: envelope.retrySignature, termination: envelope.termination, certification: envelope.certification, missingClasses: envelope.missingClasses, responsibleProducer: envelope.responsibleProducer, remediationRoutes: envelope.remediationRoutes, missingEvidence: envelope.missingEvidence };
          if (injection.systemMessage) stdout.systemMessage = injection.systemMessage;
          schema.assert('arcane-host-runtime-output-v1', stdout);
          result.stdout = stdout;
        }
      }
      return result;
    } catch (error) {
      const diagnostic = readOnlyStoreDiagnostic(eventType, hookPayload, error, stores, identity, adapter.name);
      if (diagnostic) return diagnostic;
      const fallback = availabilityFallback({ eventType, code: codeOf(error), contracted, hookPayload, adapter, policy, workspace });
      if (fallback) return fallback;
      return runtimeResult(eventType, { decision: denial(codeOf(error), 'runtime failure'), enforcementHealth: 'unsupported' });
    }
  };
  return { handle, stores, stateRoot };
}

/** Single authenticated ingress used by every adapter and legacy hook entrypoint. */
export function dispatchHookInvocation(hookPayload, { adapter, workspace, keyDir, verificationKeyDirs = [keyDir], stateRoot, clock = () => Date.now(), runtime = null } = {}) {
  const hostRuntime = runtime ?? createHostRuntime({ adapter, workspace, keyDir, verificationKeyDirs, ...(stateRoot ? { stateRoot } : {}), clock });
  return hostRuntime.handle(hookPayload);
}
