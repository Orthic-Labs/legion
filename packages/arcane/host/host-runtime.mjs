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
import { handleHookEvent, evaluateHostStop } from './hook-adapter-core.mjs';
import { RuntimeSchemaSet } from '../lib/runtime-schema.mjs';
import { renderHostRuntimeOutput } from './host-runtime-output.mjs';

const schema = new RuntimeSchemaSet();
const EVENT_TYPES = new Set(['SessionStart', 'SubagentStart', 'UserPromptSubmit', 'PostCompact', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop']);
const isoClock = (clock) => () => new Date(clock()).toISOString();
const denial = (code, message, enforcementHealth = 'strong') => decision({ allowed: false, code, message, detail: {}, enforcementHealth });
const latitudeFor = (contract, target) => contract.artifacts.exact.some((artifact) => artifact.path === target) ? 'EXACT' : 'BOUNDED';

function codeOf(error) {
  return error instanceof ArcaneError ? error.code : 'ARC_STORE_CORRUPT';
}

function runtimeResult(eventType, result) {
  const value = {
    schemaVersion: 1,
    kind: 'arcane-host-runtime-result',
    eventType,
    allowed: result.decision.allowed,
    code: result.decision.code,
    enforcementHealth: result.enforcementHealth ?? result.decision.enforcementHealth ?? 'strong',
    receiptId: result.receipt?.receiptId ?? null,
    capabilityId: result.capabilityId ?? null,
    stdout: renderHostRuntimeOutput({ eventType, allowed: result.decision.allowed, code: result.decision.code }),
  };
  schema.assert('arcane-host-runtime-result-v1', value);
  return value;
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
  };
  const stores = {
    receiptStore: new ReceiptStore({ root: paths.receipts }),
    replayGuard: new ReplayGuard({ ...policy.replayLimits(), clock }),
    capabilityStore: new CapabilityStore({ root: paths.capabilities, clock }),
    sealStore: new ContractSealStore({ root: paths.seals, clock: isoClock(clock) }),
    authorityBinding: new AuthorityBindingStore({ root: paths.authority, clock: isoClock(clock) }),
    authorityLedger: new AuthorityLedger({ clock }),
    sessionBinding: new SessionBindingStore({ root: paths.sessions }),
    preEffectCorrelation: new PreEffectCorrelationStore({ root: paths.correlations }),
  };
  const gate = new PreEffectGate({ policy, capabilityStore: stores.capabilityStore, authorityLedger: stores.authorityLedger, clock });
  Object.assign(stores, { policy, keyRing, verificationKeyRing, gate });

  const handle = (hookPayload) => {
    const eventType = hookPayload?.hook_event_name;
    if (!EVENT_TYPES.has(eventType)) {
      return runtimeResult('PreToolUse', { decision: denial('ARC_HOST_EVENT_INVALID', 'invalid host event'), enforcementHealth: 'strong' });
    }
    try {
      const hostEvent = adapter.normalize(hookPayload);
      const identity = typeof adapter.observeIdentity === 'function' ? adapter.observeIdentity(hookPayload, { hostEvent }) : null;
      if (identity?.modelClaimed) return runtimeResult(eventType, { decision: denial('ARC_AUTHORITY_MODEL_CLAIMED', 'payload authority claim refused'), enforcementHealth: 'strong' });
      if (identity?.sessionId && identity?.agentId && identity?.agentType) {
        stores.authorityBinding.observe({ adapter: adapter.name, eventId: identity.eventId ?? `host:${eventType}`, ...identity });
      }
      const binding = hostEvent.sessionId ? stores.sessionBinding.getBinding(hostEvent.sessionId) : null;
      if (binding?.contractId) {
        if (hostEvent.contractId && hostEvent.contractId !== binding.contractId) {
          return runtimeResult(eventType, { decision: denial('ARC_CONTRACT_VERSION_MISMATCH', 'session contract differs'), enforcementHealth: 'strong' });
        }
        const seal = stores.sealStore.get(binding.contractId, binding.contractVersion);
        if (!seal || seal.contractDigest !== binding.contractDigest) {
          return runtimeResult(eventType, { decision: denial('ARC_CONTRACT_VERSION_MISMATCH', 'sealed session contract differs'), enforcementHealth: 'strong' });
        }
      }
      const boundSeal = binding?.contractId ? stores.sealStore.get(binding.contractId, binding.contractVersion) : null;
      const contracted = Boolean(boundSeal && boundSeal.contractDigest === binding.contractDigest);
      let observed = typeof adapter.mapPreEffect === 'function' && eventType === 'PreToolUse'
        ? adapter.mapPreEffect(hookPayload, { hostEvent, binding, workspace }) : null;

      // Ambient tier (canon A-ER-1: evidence is not authorization). A session
      // with no sealed contract still observes its effects and earns receipts;
      // it authorizes nothing, so there is no capability to mint and the gated
      // branch below does not apply. Locked domains are the exception and keep
      // failing closed: mutating the enforcement plane or sealed qualification
      // evidence still requires a sealed contract. Denying every uncontracted
      // effect instead (the prior behaviour) made ordinary user-requested work
      // impossible on every harness while protecting nothing the locked-domain
      // check does not already protect.
      if (observed && !contracted) {
        if (policy.lockedDomainsFor([observed.target]).length > 0) {
          return runtimeResult(eventType, { decision: denial('ARC_NO_CONTRACT', 'locked-domain effect requires a sealed contract'), enforcementHealth: 'strong' });
        }
        observed = null;
      }

      if (observed) {
        const reservation = stores.preEffectCorrelation.reserve(observed.toolUseId);
        if (!reservation) return runtimeResult(eventType, { decision: denial('ARC_STORE_CORRUPT', 'pre-effect correlation unavailable'), enforcementHealth: 'unsupported' });
        if (!reservation.created) return runtimeResult(eventType, { decision: denial('ARC_REPLAY_NONCE_SEEN', 'pre-effect delivery already reserved'), enforcementHealth: 'strong' });
        const seal = boundSeal;
        const authority = identity?.sessionId && identity?.agentId
          ? stores.authorityBinding.assertForTurn({ adapter: adapter.name, sessionId: identity.sessionId, agentId: identity.agentId, turnId: reservation.requestId, authorityLedger: stores.authorityLedger, keyId: keyRing?.activeKeyId() }) : null;
        if (!authority) {
          return runtimeResult(eventType, { decision: denial('ARC_NO_CONTRACT', 'sealed contract unavailable'), enforcementHealth: 'strong' });
        }
        const request = {
          schemaVersion: 1, kind: 'legion-effect-request', requestId: reservation.requestId,
          runId: binding.runId, contractId: seal.contractId, taskId: binding.taskId,
          requestedBy: authority.authority, effectClass: observed.effectClass, target: observed.target,
          operation: observed.operation, latitude: latitudeFor(seal.contract, observed.target),
          sourceRevision: seal.contract.sourceRevision, requestedAt: new Date(clock()).toISOString(),
        };
        const context = { contract: seal.contract, contractDigest: seal.contractDigest, turnId: reservation.requestId, workspace, expectedContractVersion: seal.version, requestId: reservation.requestId };
        const authorized = gate.authorize(request, context);
        if (!authorized.allowed) return runtimeResult(eventType, { decision: authorized, enforcementHealth: authorized.enforcementHealth });
        const consumed = gate.evaluate(request, { ...context, capabilityId: authorized.detail.capabilityId });
        if (!consumed.allowed) return runtimeResult(eventType, { decision: consumed, enforcementHealth: consumed.enforcementHealth });
        return runtimeResult(eventType, { decision: consumed, capabilityId: authorized.detail.capabilityId });
      }
      const outcome = handleHookEvent(hookPayload, {
        normalize: adapter.normalize, keyRing, verificationKeyRing, receiptStore: stores.receiptStore, replayGuard: stores.replayGuard, policy,
        capabilityStore: stores.capabilityStore, clock, sessionBinding: stores.sessionBinding, preEffectCorrelation: stores.preEffectCorrelation,
      });
      if (eventType === 'Stop' && outcome.decision.allowed) {
        const stopped = evaluateHostStop(outcome.hostEvent, { policy, receiptStore: stores.receiptStore });
        if (!stopped.allowed) outcome.decision = stopped;
      }
      return runtimeResult(eventType, outcome);
    } catch (error) {
      return runtimeResult(eventType, { decision: denial(codeOf(error), 'runtime failure'), enforcementHealth: 'unsupported' });
    }
  };
  return { handle, stores, stateRoot };
}
