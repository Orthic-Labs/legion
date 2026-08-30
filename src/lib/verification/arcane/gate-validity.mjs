// Gate validity is a precondition to blocking, never a product-result substitute.
import { digestValue } from '../../contracts/arcane/canonical.mjs';
import { decision } from '../../contracts/arcane/errors.mjs';

const CASES = ['knownGood', 'knownBad', 'empty', 'malformed'];
const VALIDITY_RECEIPTS = new WeakSet();
export function validateGate({ contract, fixtures, execute }) {
  const required = ['id', 'inspectedScope', 'discoveryBreadth', 'blockingFilter', 'threshold', 'gates', 'authority', 'failureSemantics'];
  const missing = required.filter((key) => !contract?.[key]);
  if (missing.length || typeof execute !== 'function') return decision({ allowed: false, code: 'ARC_GATE_INVALID', message: 'gate contract is incomplete', detail: { missing } });
  const results = CASES.map((name) => ({ name, fixture: fixtures?.[name], result: fixtures?.[name] ? execute(fixtures[name]) : null }));
  const invalid = results.filter(({ name, result }) => !result || (name === 'knownGood' && result.status !== 'PASS') || (name !== 'knownGood' && result.status !== 'FAIL'));
  if (invalid.length) return decision({ allowed: false, code: 'ARC_GATE_INVALID', message: 'blocking gate self-test failed', detail: { machineryDefect: 'OUT_OF_SCOPE_MACHINERY_DEFECT', invalid: invalid.map(({ name, result }) => ({ name, status: result?.status ?? null })) } });
  const receipt = decision({ allowed: true, message: 'blocking gate self-test passed', detail: { gateId: contract.id, gateContractDigest: digestValue(contract), fixtureBindings: results.map(({ name, fixture }) => ({ name, id: fixture.id, digest: digestValue(fixture) })), gateStatus: 'VALID' } });
  VALIDITY_RECEIPTS.add(receipt);
  return receipt;
}

export function executeValidatedGate({ contract, validity, inspected = [], matches = [] }) {
  if (contract?.gates !== true) return decision({ allowed: true, message: 'informational check cannot block', detail: { gateStatus: 'INFORMATIONAL' } });
  if (!validity?.allowed) return decision({ allowed: false, code: 'ARC_GATE_INVALID', message: 'unvalidated blocking gate cannot block delivery', detail: { machineryDefect: validity?.detail?.machineryDefect ?? 'OUT_OF_SCOPE_MACHINERY_DEFECT' } });
  if (!VALIDITY_RECEIPTS.has(validity) || validity.detail?.gateId !== contract.id || validity.detail?.gateContractDigest !== digestValue(contract) || !Array.isArray(validity.detail?.fixtureBindings) || validity.detail.fixtureBindings.length !== CASES.length) return decision({ allowed: false, code: 'ARC_GATE_INVALID', message: 'gate validity receipt does not bind this gate contract and fixtures', detail: { machineryDefect: 'OUT_OF_SCOPE_MACHINERY_DEFECT' } });
  if (inspected.length === 0) return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'zero eligible inspected items cannot produce CLEAN', detail: { gateStatus: 'INCONCLUSIVE', inspectionCount: 0 } });
  if (matches.length) return decision({ allowed: false, code: 'ARC_CLAIM_PREREQUISITE_UNMET', message: 'validated gate rejected matching observations', detail: { gateStatus: 'FAIL', inspectionCount: inspected.length, matchedRule: matches[0].ruleId ?? null, rejectionReason: matches[0].reason ?? null } });
  return decision({ allowed: true, message: 'validated gate passed inspected scope', detail: { gateStatus: 'PASS', inspectionCount: inspected.length, matchedRule: null, rejectionReason: null } });
}
