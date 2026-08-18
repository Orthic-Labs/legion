import { parseArgs } from 'node:util';

import { EXIT, LegionError } from '../../../errors.mjs';
import {
  applyScopedRecheck, filterFindingsByThreshold, verifyFindingClosure,
} from '../../../../packages/arcane/lib/finding-lifecycle.mjs';
import {
  acknowledgeDownstreamDeficits, classifyAcceptanceDeficits,
  convertDeficitsToDebt, evaluateOutcomeClosure,
} from '../../../../packages/arcane/lib/deficit-governance.mjs';
import {
  findCurrentAdvisoryJudgment, persistAdvisoryJudgment,
} from '../../../../packages/arcane/lib/advisory-judgment.mjs';
import {
  consumeCurrentUserScopeAmendment, verifyCurrentUserScopeAmendment,
} from '../../../../packages/arcane/lib/current-user-scope-amendment.mjs';

const capabilities = new WeakMap();
const invalid = (message) => { throw new LegionError(message, { code: 'USAGE', exitCode: EXIT.USAGE }); };
const diagnosticOnly = (operation) => Object.freeze({ allowed: false, code: 'ARC_DIAGNOSTIC_ONLY', consumable: false, diagnostic: Object.freeze({ operation, reason: 'private host judgment-control capability required' }) });
const failed = (error) => Object.freeze({ allowed: false, code: error?.code ?? 'ARC_INTERNAL_ERROR', message: error?.message ?? 'governance judgment operation failed', detail: {} });
const exactInput = (value) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === 2 && Object.hasOwn(value, 'operation') && Object.hasOwn(value, 'payload')
  && typeof value.operation === 'string' && value.operation.length > 0
  && value.payload && typeof value.payload === 'object' && !Array.isArray(value.payload);
const has = (value, name) => typeof value?.[name] === 'function';

function requireCapability(capability) {
  const state = capabilities.get(capability);
  if (!state) throw Object.assign(new TypeError('private host judgment-control capability is unavailable'), { code: 'ARC_DIAGNOSTIC_ONLY' });
  return state;
}
function judgmentOptions(state) {
  if (!state.receiptStore || !state.keyRing || !state.authorityBindingStore) throw Object.assign(new TypeError('authenticated judgment stores are unavailable'), { code: 'ARC_STORE_CORRUPT' });
  return { receiptStore: state.receiptStore, keyRing: state.keyRing, authorityBindingStore: state.authorityBindingStore, ...(state.now ? { now: state.now } : {}), ...(state.freshnessMs ? { freshnessMs: state.freshnessMs } : {}) };
}
function scopeOptions(state) {
  if (!state.receiptStore || !state.ledgerStore || !state.keyRing) throw Object.assign(new TypeError('authenticated scope stores are unavailable'), { code: 'ARC_STORE_CORRUPT' });
  return { receiptStore: state.receiptStore, ledgerStore: state.ledgerStore, keyRing: state.keyRing, ...(state.now ? { now: state.now } : {}) };
}
function durableFindings(state) {
  if (!state.findingStore || !has(state.findingStore, 'upsert') || !has(state.findingStore, 'records') || !has(state.findingPersistence, 'save') || !has(state.findingPersistence, 'load')) throw Object.assign(new TypeError('durable finding store and persistence hooks are required'), { code: 'ARC_STORE_CORRUPT' });
  return state.findingStore;
}
function persistFindings(state, records) { state.findingPersistence.save(records); }
function result(value) { return value?.allowed === undefined ? Object.freeze({ allowed: true, detail: value }) : value; }

/**
 * Creates opaque host control capability. WeakMap state is unreachable through
 * JSON, so a raw CLI payload cannot become authority, evidence, or admission.
 */
export function createJudgmentControlCapability(host) {
  if (!host || typeof host !== 'object' || Array.isArray(host)) throw new TypeError('host judgment control configuration is required');
  if (host.findingStore && (!has(host.findingPersistence, 'load') || !has(host.findingPersistence, 'save'))) throw new TypeError('finding store requires durable persistence hooks');
  for (const key of ['closureEvidence', 'acceptanceItems', 'deficitAcknowledgements', 'acceptanceSurface']) if (host[key] !== undefined && !has(host, key)) throw new TypeError(`${key} must be a host function`);
  const capability = Object.freeze({});
  capabilities.set(capability, Object.freeze({ ...host }));
  return capability;
}

/** Registry receives only private host state, never raw dispatcher context. */
export const governanceJudgmentRegistry = Object.freeze({
  // `upsertFinding` derives OPEN for new records and ignores presentation or
  // caller-supplied status; only host evidence can reach a closure operation.
  'finding.upsert': ({ finding, reviewRoundId, review_round_id }, state) => {
    const store = durableFindings(state); const output = store.upsert({ finding, reviewRoundId, review_round_id }); persistFindings(state, store.records()); return output;
  },
  'finding.records': (_payload, state) => { const store = durableFindings(state); return Object.freeze({ allowed: true, detail: { records: store.records() } }); },
  'finding.verify-closure': (_payload, state) => verifyFindingClosure(state.closureEvidence()),
  'finding.filter-threshold': (payload) => filterFindingsByThreshold(payload),
  'finding.scoped-recheck': (_payload, state) => {
    if (!has(state, 'scopedRecheckEvidence')) return Object.freeze({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'host-scoped independently verified recheck evidence is required', detail: {} });
    const input = state.scopedRecheckEvidence();
    if (!input || typeof input !== 'object' || Array.isArray(input)) return Object.freeze({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'host-scoped recheck evidence is unavailable', detail: {} });
    const output = applyScopedRecheck(input);
    if (has(state, 'recordScopedRecheck')) state.recordScopedRecheck(output);
    return output;
  },
  'deficit.classify': (_payload, state) => classifyAcceptanceDeficits({ acceptanceItems: state.acceptanceItems() }),
  'deficit.convert': (_payload, state) => {
    const output = convertDeficitsToDebt({ acceptanceItems: state.acceptanceItems() });
    if (output.allowed && has(state, 'recordDebtConversion')) state.recordDebtConversion(output.detail);
    return output;
  },
  'deficit.acknowledge': (_payload, state) => {
    const source = state.deficitAcknowledgements();
    const output = acknowledgeDownstreamDeficits(source);
    if (output.allowed && has(state, 'recordDeficitAcknowledgement')) state.recordDeficitAcknowledgement(output.detail);
    return output;
  },
  'outcome.evaluate-closure': (_payload, state) => evaluateOutcomeClosure({ acceptanceSurface: state.acceptanceSurface() }),
  'advisory.consume': ({ receipt }, state) => persistAdvisoryJudgment(receipt, judgmentOptions(state)),
  'advisory.query': ({ expected }, state) => { const options = judgmentOptions(state); return findCurrentAdvisoryJudgment({ receiptStore: options.receiptStore, expected }, options); },
  'scope.verify': (expected, state) => verifyCurrentUserScopeAmendment(expected, scopeOptions(state)),
  'scope.consume': (expected, state) => consumeCurrentUserScopeAmendment(expected, scopeOptions(state)),
});

/** Raw inputs are always diagnostic-only until host passes opaque capability. */
export function dispatchGovernanceJudgment(input, { capability = null } = {}) {
  if (!exactInput(input)) return Object.freeze({ allowed: false, code: 'ARC_SCHEMA_INVALID', consumable: false, detail: {} });
  const operation = governanceJudgmentRegistry[input.operation];
  if (!operation) return Object.freeze({ allowed: false, code: 'ARC_OPERATION_UNKNOWN', consumable: false, detail: { operation: input.operation } });
  if (!capabilities.has(capability)) return diagnosticOnly(input.operation);
  try { return result(operation(input.payload, requireCapability(capability))); }
  catch (error) { return error?.code === 'ARC_DIAGNOSTIC_ONLY' ? diagnosticOnly(input.operation) : failed(error); }
}

export function runGovernanceJudgment(argv, { stdout, governanceContext } = {}) {
  const [sub, ...rest] = argv;
  if (sub === '--help' || sub === 'help') { stdout.write('Usage: legion governance judgment --json <{"operation":"...","payload":{...}}>\n'); return { exitCode: EXIT.PASS }; }
  if (sub !== 'judgment') invalid(`governance requires judgment (got ${sub ?? '<none>'})`);
  let values; try { ({ values } = parseArgs({ args: rest, strict: true, options: { json: { type: 'string' } } })); } catch (error) { invalid(error.message); }
  if (!values.json) invalid('governance judgment requires --json <structured-input>');
  let input; try { input = JSON.parse(values.json); } catch { invalid('governance judgment --json must be valid JSON'); }
  const output = dispatchGovernanceJudgment(input, { capability: governanceContext?.capability });
  stdout.write(`${JSON.stringify(output)}\n`);
  return { exitCode: output.allowed ? EXIT.PASS : EXIT.INCOMPLETE };
}
