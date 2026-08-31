import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { EXIT, LegionError } from '../../errors.mjs';
import { loadCanonicalHostKeyRing, loadHostKeyRing } from '../../guard/compat/host/keys.mjs';
import { digestValue, isDigest } from '../../contracts/arcane/canonical.mjs';
import { SessionBindingStore } from '../../host/arcane/session-binding.mjs';
import { ContractSealStore } from './governance/delivery/contract-seal-store.mjs';
import { HostEventLedger } from '../../host/arcane/host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from '../../contracts/arcane/authority-invocation-proof.mjs';
import { PendingTerminalOperationStore } from '../../verification/arcane/pending-terminal-operation-store.mjs';
import { requireCanonicalAdvisoryProfile } from '../../verification/arcane/advisory-profile.mjs';
import { ReceiptStore } from '../../guard/compat/audit/receipt-store.mjs';
import { sealEvidence } from '../../verification/arcane/evidence-envelope.mjs';
import { signRecord, EVIDENCE_RECEIPT_BOUND_FIELDS } from '../../guard/compat/audit/receipt-auth.mjs';
import { completionIntegratedStateForRepositories, latestScopedMaterialChange } from '../../verification/arcane/completion-state.mjs';
import { DependencyLedger } from '../../verification/arcane/invalidation.mjs';

const session = (value, env) => value || env.CODEX_THREAD_ID || env.CLAUDE_CODE_SESSION_ID || env.CLAUDE_SESSION_ID || env.CODEX_SESSION_ID || null;

function advisoryClaimFor(outcome, seal) {
  const requested = outcome?.advisoryClaim;
  if (requested == null) return null;
  if (!requested || typeof requested !== 'object' || Object.keys(requested).sort().join(',') !== 'artifactDigest,briefDigest' || !isDigest(requested.artifactDigest) || !isDigest(requested.briefDigest)) {
    throw new LegionError('ARC_SCHEMA_INVALID: advisory claim requires exact artifactDigest & briefDigest', { code: 'ARC_SCHEMA_INVALID', exitCode: EXIT.USAGE });
  }
  const profile = requireCanonicalAdvisoryProfile(seal.contract?.advisoryProfile);
  return {
    required: true,
    artifactDigest: requested.artifactDigest,
    briefDigest: requested.briefDigest,
    bundleId: profile.bundleId,
    bundleVersion: profile.bundleVersion,
    profileId: profile.profileId,
    manifestDigest: profile.manifestDigest,
    profileDigest: profile.profileDigest,
  };
}
function highRiskContextFor(outcome) {
  const context = outcome?.highRiskContext;
  if (context == null) return null;
  const fields = ['blastRadius', 'intentRestatement', 'whySafe'];
  if (!context || typeof context !== 'object' || Object.keys(context).sort().join(',') !== fields.sort().join(',') || fields.some((field) => typeof context[field] !== 'string' || !context[field].trim())) {
    throw new LegionError('ARC_SCHEMA_INVALID: highRiskContext requires exact non-empty blastRadius, intentRestatement, & whySafe', { code: 'ARC_SCHEMA_INVALID', exitCode: EXIT.USAGE });
  }
  return Object.fromEntries(fields.map((field) => [field, context[field]]));
}
function completionRepositories(cwd, binding, scope) {
  const roots = binding.delivery?.repositories?.map((repo) => repo.root).filter(Boolean);
  return (roots?.length ? roots : [cwd]).map((root) => ({ cwd: root, scope }));
}
function latestCompletionChange(receiptStore, runId, repositories) {
  return repositories.map(({ cwd, scope }) => latestScopedMaterialChange(receiptStore, runId, scope, cwd)).filter(Boolean).sort().at(-1) ?? null;
}

export async function runCompletion(argv, { stdout, env, cwd }) {
  const [sub, ...rest] = argv;
  if (sub === '--help' || sub === 'help') {
    stdout.write('Usage: legion completion claim|evidence --file <outcome.json> [--session <id>]\n');
    return { exitCode: EXIT.PASS };
  }
  if (sub === 'evidence') return runEvidence(rest, { stdout, env, cwd });
  if (sub !== 'claim') throw new LegionError('completion requires claim', { code: 'USAGE', exitCode: EXIT.USAGE });
  const values = parseArgs({ args: rest, strict: true, options: { file: { type: 'string' }, session: { type: 'string' }, 'key-dir': { type: 'string' } } }).values;
  const sessionId = session(values.session, env);
  if (!values.file || !sessionId) throw new LegionError('completion claim requires --file & known session', { code: 'USAGE', exitCode: EXIT.USAGE });

  const keys = values['key-dir'] || env.ARCANE_KEY_DIR ? loadHostKeyRing({ dir: values['key-dir'] || env.ARCANE_KEY_DIR }) : loadCanonicalHostKeyRing();
  const binding = new SessionBindingStore({ root: join(cwd, '.audit', 'arcane', 'session-bindings') }).getBinding(sessionId);
  if (!binding?.contractId || !binding.taskId) throw new LegionError('ARC_NO_CONTRACT', { code: 'ARC_NO_CONTRACT', exitCode: EXIT.INCOMPLETE });
  const seal = new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }).get(binding.contractId, binding.contractVersion);
  if (!seal || seal.contractDigest !== binding.contractDigest) throw new LegionError('ARC_CONTRACT_VERSION_MISMATCH', { code: 'ARC_CONTRACT_VERSION_MISMATCH', exitCode: EXIT.INCOMPLETE });

  const ledger = new HostEventLedger({ root: join(cwd, '.audit', 'arcane', 'host-events'), keyRing: keys, keyId: keys.activeKeyId() });
  if (!ledger.verify().allowed) throw new LegionError('ARC_STORE_CORRUPT: legion host events inspect', { code: 'ARC_STORE_CORRUPT', exitCode: EXIT.INCOMPLETE });
  const event = ledger.records().reverse().find((record) => record.sessionId === sessionId);
  if (!event || !['legion', 'alchemist'].includes(event.observedAuthority)) throw new LegionError('ARC_AUTHORITY_NOT_ASSERTED: current Legion or assigned Alchemist event required', { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INCOMPLETE });

  const rootKeyId = keys.activeKeyId();
  const issuer = new AuthorityInvocationProofIssuer({ root: join(cwd, '.audit', 'arcane', 'authority-invocations'), keyRing: keys, keyId: rootKeyId, ledgerStore: ledger });
  const proof = issuer.issue({ ledger: event, binding: { ...binding, sessionId }, purpose: 'completion-claim', role: event.observedAuthority }).proof;
  const store = new PendingTerminalOperationStore({ root: join(cwd, '.audit', 'arcane', 'terminal-operations'), keyRing: keys, keyId: keys.activeKeyId() });
  const outcome = JSON.parse(readFileSync(values.file, 'utf8'));
  const claim = store.mint({
    invocationProofDigest: digestValue(proof),
    producerAuthority: event.observedAuthority,
    runId: binding.runId,
    taskId: binding.taskId,
    contractId: binding.contractId,
    contractVersion: binding.contractVersion,
    contractDigest: binding.contractDigest,
    sourceRevision: seal.sourceRevision,
    turnCorrelationDigest: event.turnCorrelationDigest,
    expectedStopOrdinal: (event.stopOrdinal || 0) + 1,
    outcomeSummaryDigest: digestValue(outcome.outcomeSummary || ''),
    artifactStateDigest: digestValue(outcome.artifactState || ''),
    advisoryClaim: advisoryClaimFor(outcome, seal),
    highRiskContext: highRiskContextFor(outcome),
  });
  const consumed = issuer.consume(proof, { artifactDigest: digestValue(claim) });
  if (!consumed.allowed) throw new LegionError(consumed.code, { code: consumed.code, exitCode: EXIT.INCOMPLETE });
  const stored = store.append(claim);
  if (!stored.allowed) throw new LegionError(stored.code, { code: stored.code, exitCode: EXIT.INCOMPLETE });
  stdout.write(`${JSON.stringify({ claimId: stored.detail.claimId, invocationProofDigest: digestValue(proof) })}\n`);
  return { exitCode: EXIT.PASS };
}

function runEvidence(argv, { stdout, env, cwd }) {
  const values = parseArgs({ args: argv, strict: true, options: { file: { type: 'string' }, session: { type: 'string' }, 'key-dir': { type: 'string' } } }).values;
  const sessionId = session(values.session, env); if (!values.file || !sessionId) throw new LegionError('completion evidence requires --file & known session', { code: 'USAGE', exitCode: EXIT.USAGE });
  const keys = values['key-dir'] || env.ARCANE_KEY_DIR ? loadHostKeyRing({ dir: values['key-dir'] || env.ARCANE_KEY_DIR }) : loadCanonicalHostKeyRing();
  const binding = new SessionBindingStore({ root: join(cwd, '.audit', 'arcane', 'session-bindings') }).getBinding(sessionId);
  const seal = binding?.contractId ? new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }).get(binding.contractId, binding.contractVersion) : null;
  if (!binding?.taskId || !seal || seal.contractDigest !== binding.contractDigest) throw new LegionError('ARC_NO_CONTRACT', { code: 'ARC_NO_CONTRACT', exitCode: EXIT.INCOMPLETE });
  const ledger = new HostEventLedger({ root: join(cwd, '.audit', 'arcane', 'host-events'), keyRing: keys, keyId: keys.activeKeyId() });
  const event = ledger.records().reverse().find((record) => record.sessionId === sessionId);
  if (!ledger.verify().allowed || !event || event.observedAuthority !== 'oracle') throw new LegionError('ARC_AUTHORITY_NOT_ASSERTED: current Oracle host event required', { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INCOMPLETE });
  const rootKeyId = keys.activeKeyId();
  const issuer = new AuthorityInvocationProofIssuer({ root: join(cwd, '.audit', 'arcane', 'authority-invocations'), keyRing: keys, keyId: rootKeyId, ledgerStore: ledger });
  const authorityProof = issuer.issue({ ledger: event, binding: { ...binding, sessionId }, purpose: 'completion-claim', role: 'oracle' }).proof;
  const report = JSON.parse(readFileSync(values.file, 'utf8')); const item = report?.evidence;
  const criterion = seal.contract.acceptanceCriteria.find((entry) => entry.id === item?.acceptanceId);
  if (!criterion || !item || !['requirementId','productionSymbol','liveConsumer','acceptanceSurface'].every((key) => typeof item[key] === 'string' && item[key])) throw new LegionError('ARC_SCHEMA_INVALID: evidence must map sealed acceptance to requirement, symbol, consumer, & surface', { code: 'ARC_SCHEMA_INVALID', exitCode: EXIT.USAGE });
  const receipts = new ReceiptStore({ root: join(cwd, '.audit', 'arcane', 'receipts') });
  const repositories = completionRepositories(cwd, binding, seal.contract.scope.own);
  const latest = latestCompletionChange(receipts, binding.runId, repositories);
  const observation = { acceptanceId: criterion.id, requirementId: item.requirementId, productionSymbol: item.productionSymbol, liveConsumer: item.liveConsumer, acceptanceSurface: item.acceptanceSurface, integratedState: completionIntegratedStateForRepositories(repositories), latestMaterialChange: latest, contractVersion: binding.contractVersion, contractDigest: binding.contractDigest, sourceRevision: seal.sourceRevision, validUntil: item.validUntil, authorityProofDigest: digestValue(authorityProof) };
  const dependencies = [
    { dimension: 'source-digest', ref: item.liveConsumer, digest: digestValue(seal.sourceRevision) },
    { dimension: 'upstream-contract-revision', ref: binding.contractId, digest: binding.contractDigest },
  ];
  const { receipt } = sealEvidence({ runId: binding.runId, taskId: binding.taskId, contractId: binding.contractId, producerAuthority: 'oracle', capability: 'oracle-acceptance-observation', observation, evidenceClass: 'deterministic', sourceRevision: seal.sourceRevision, dependencies, authentication: { issuerIdentity: 'oracle', verificationMethod: 'capability-signature', perMessage: true, verifiedAt: new Date().toISOString() }, replayDefense: { nonce: authorityProof.invocationId, sequence: 1, freshnessWindowSeconds: 3600, freshAt: new Date().toISOString() }, observedAt: new Date().toISOString() });
  receipt.authentication = { ...receipt.authentication, ...signRecord(receipt, { keyRing: keys, keyId: rootKeyId, boundFields: EVIDENCE_RECEIPT_BOUND_FIELDS }) };
  const consumed = issuer.consume(authorityProof, { artifactDigest: digestValue(receipt) });
  if (!consumed.allowed) throw new LegionError(consumed.code, { code: consumed.code, exitCode: EXIT.INCOMPLETE });
  receipts.append(receipt);
  const dependenciesLedger = new DependencyLedger({ root: join(cwd, '.audit', 'arcane', 'dependency-ledger') });
  dependenciesLedger.register(receipt.evidenceId, dependencies);
  dependenciesLedger.link(receipt.evidenceId, { criterionId: criterion.id });
  stdout.write(`${JSON.stringify({ evidenceId: receipt.evidenceId, acceptanceId: criterion.id })}\n`); return { exitCode: EXIT.PASS };
}
