import { parseArgs } from 'node:util';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { readFileSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { EXIT, LegionError } from '../../errors.mjs';
import { loadHostKeyRing } from '../../../packages/arcane/lib/keys.mjs';
import { adoptionIntegratedState, completionIntegratedStateForRepositories } from '../../../packages/arcane/lib/completion-state.mjs';
import { ADOPTION_MANIFEST_RECEIPT_BOUND_FIELDS, readVerifiedStageFile, transitionVerifiedLedgerFile, validateOracleAdoptionManifest } from '../../../packages/arcane/lib/adoption-ledger.mjs';
import { SessionBindingStore } from '../../../packages/arcane/lib/session-binding.mjs';
import { ContractSealStore } from '../../../packages/arcane/lib/contract-seal-store.mjs';
import { HostEventLedger } from '../../../packages/arcane/lib/host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from '../../../packages/arcane/lib/authority-invocation-proof.mjs';
import { ReceiptStore } from '../../../packages/arcane/lib/receipt-store.mjs';
import { digestValue } from '../../../packages/arcane/lib/canonical.mjs';
import { signRecord } from '../../../packages/arcane/lib/receipt-auth.mjs';

function usage(message) { throw new LegionError(message, { code: 'USAGE', exitCode: EXIT.USAGE }); }
const resolveAdoptionSessionId = (value, env) => value || env.CODEX_THREAD_ID || env.CLAUDE_CODE_SESSION_ID || env.CLAUDE_SESSION_ID || env.CODEX_SESSION_ID || null;

function commonOptions() {
  return {
    file: { type: 'string' }, ledger: { type: 'string' }, stage: { type: 'string' }, session: { type: 'string' }, repository: { type: 'string', multiple: true },
    'parent-repository': { type: 'string' }, 'legion-repository': { type: 'string' }, 'skill-architecture': { type: 'string' }, 's11-evidence': { type: 'string' }, 'key-dir': { type: 'string' },
  };
}

function parse(rest) {
  try { return parseArgs({ args: rest, allowPositionals: false, strict: true, options: commonOptions() }).values; }
  catch (error) { usage(error.message); }
}

function loadAdoptionExecution(cwd, values, env) {
  const sessionId = resolveAdoptionSessionId(values.session, env);
  if (!sessionId) usage('adoption command requires --session or host session environment');
  const keyDir = values['key-dir'] || env.ARCANE_KEY_DIR || join(homedir(), '.claude', 'arcane-keys');
  const keyRing = loadHostKeyRing({ dir: keyDir });
  const binding = new SessionBindingStore({ root: join(cwd, '.audit', 'arcane', 'session-bindings') }).getBinding(sessionId);
  const seal = binding?.contractId ? new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }).get(binding.contractId, binding.contractVersion) : null;
  if (!binding?.taskId || !seal || seal.contractDigest !== binding.contractDigest) throw new LegionError('ARC_NO_CONTRACT', { code: 'ARC_NO_CONTRACT', exitCode: EXIT.INCOMPLETE });
  const execution = { runId: binding.runId, taskId: binding.taskId, contractId: binding.contractId, contractVersion: binding.contractVersion, contractDigest: binding.contractDigest, sourceRevision: seal.sourceRevision };
  const hostLedger = new HostEventLedger({ root: join(cwd, '.audit', 'arcane', 'host-events'), keyRing, keyId: keyRing.activeKeyId() });
  if (!hostLedger.verify().allowed) throw new LegionError('ARC_STORE_CORRUPT: host event ledger', { code: 'ARC_STORE_CORRUPT', exitCode: EXIT.INCOMPLETE });
  const authorityProofIssuer = new AuthorityInvocationProofIssuer({ root: join(cwd, '.audit', 'arcane', 'authority-invocations'), keyRing, keyId: keyRing.activeKeyId(), ledgerStore: hostLedger });
  const receiptStore = new ReceiptStore({ root: join(cwd, '.audit', 'arcane', 'receipts') });
  return { sessionId, keyRing, binding, seal, execution, hostLedger, authorityProofIssuer, receiptStore };
}

function formalState(cwd, values, ledgerPath) {
  const parentRepository = realpathSync(resolve(cwd, values['parent-repository'] || '.'));
  const legionRepository = realpathSync(resolve(cwd, values['legion-repository'] || 'legion'));
  const skillArchitecturePath = resolve(cwd, values['skill-architecture'] || 'docs/SKILL-ARCHITECTURE.md');
  const s11EvidencePath = resolve(cwd, values['s11-evidence'] || 'docs/plans/legion/evidence/2026-08-14-s11-architecture-evals.json');
  return adoptionIntegratedState({ parentRepository, legionRepository, ledgerPath, skillArchitecturePath, s11EvidencePath });
}

function verifyManifestSourceBytes(cwd, manifest) {
  for (const item of manifest?.items ?? []) for (const source of item?.evidence?.sources ?? []) {
    let bytes;
    try { bytes = readFileSync(resolve(cwd, source.path)); } catch { throw new LegionError(`ARC_EVIDENCE_INSUFFICIENT: unreadable Oracle evidence source ${source.path}`, { code: 'ARC_EVIDENCE_INSUFFICIENT', exitCode: EXIT.INCOMPLETE }); }
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    if (digest !== source.digest) throw new LegionError(`ARC_BINDING_MISMATCH: Oracle evidence source drift ${source.path}`, { code: 'ARC_BINDING_MISMATCH', exitCode: EXIT.INCOMPLETE });
  }
}

function runManifest(values, context) {
  if (!values.file || !values.ledger) usage('adoption manifest requires --file <manifest.json> & --ledger <ledger.json>');
  const { cwd, stdout, env } = context;
  const runtime = loadAdoptionExecution(cwd, values, env);
  const manifest = JSON.parse(readFileSync(resolve(cwd, values.file), 'utf8'));
  const ledger = JSON.parse(readFileSync(resolve(cwd, values.ledger), 'utf8'));
  const integratedState = formalState(cwd, values, resolve(cwd, values.ledger));
  if (!integratedState) throw new LegionError('ARC_EVIDENCE_INSUFFICIENT: adoption state unavailable', { code: 'ARC_EVIDENCE_INSUFFICIENT', exitCode: EXIT.INCOMPLETE });
  const validated = validateOracleAdoptionManifest(ledger, manifest, { execution: runtime.execution, integratedState, now: new Date() });
  if (!validated.allowed) throw new LegionError(validated.code, { code: validated.code, exitCode: EXIT.INCOMPLETE });
  verifyManifestSourceBytes(cwd, manifest);
  const event = runtime.hostLedger.records().reverse().find((record) => record.sessionId === runtime.sessionId);
  if (!event || event.observedAuthority !== 'oracle') throw new LegionError('ARC_AUTHORITY_NOT_ASSERTED: current Oracle host event required', { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INCOMPLETE });
  const authorityProof = runtime.authorityProofIssuer.issue({ ledger: event, binding: { ...runtime.binding, sessionId: runtime.sessionId }, purpose: 'completion-claim', role: 'oracle' }).proof;
  const receipt = {
    schemaVersion: 1, kind: 'arcane-adoption-manifest-receipt', receiptId: digestValue({ kind: 'arcane-adoption-manifest-receipt', manifestDigest: digestValue(manifest), authorityProofDigest: digestValue(authorityProof) }),
    manifestDigest: digestValue(manifest), itemSetDigest: validated.detail.itemSetDigest, ...runtime.execution,
    acceptanceFingerprint: ledger.acceptance_fingerprint, integratedState, authorityProofDigest: digestValue(authorityProof), observedAt: manifest.observedAt,
  };
  receipt.authentication = signRecord(receipt, { keyRing: runtime.keyRing, keyId: runtime.keyRing.activeKeyId(), boundFields: ADOPTION_MANIFEST_RECEIPT_BOUND_FIELDS, macDomain: 'arcane-adoption-manifest-v1' });
  const consumed = runtime.authorityProofIssuer.consume(authorityProof, { artifactDigest: digestValue(receipt) });
  if (!consumed.allowed) throw new LegionError(consumed.code, { code: consumed.code, exitCode: EXIT.INCOMPLETE });
  runtime.receiptStore.append(receipt);
  stdout.write(`${JSON.stringify({ kind: receipt.kind, receiptId: receipt.receiptId, manifestDigest: receipt.manifestDigest, itemCount: manifest.items.length, integratedState })}\n`);
  return { exitCode: EXIT.PASS };
}

function runAdmit(values, context) {
  if (!values.file || !values.ledger) usage('adoption admit requires --file <manifest.json> & --ledger <ledger.json>');
  const { cwd, stdout, env } = context;
  const runtime = loadAdoptionExecution(cwd, values, env);
  const ledgerPath = resolve(cwd, values.ledger);
  const manifest = JSON.parse(readFileSync(resolve(cwd, values.file), 'utf8'));
  const integratedState = formalState(cwd, values, ledgerPath);
  const result = transitionVerifiedLedgerFile(ledgerPath, manifest, { ...runtime, execution: runtime.execution, integratedState, now: new Date() });
  if (!result.allowed) throw new LegionError(result.code, { code: result.code, exitCode: EXIT.INCOMPLETE });
  stdout.write(`${JSON.stringify({ kind: 'legion-adoption-admission', stageCount: result.detail.stageIds.length, integratedState, manifestReceiptId: result.detail.manifestReceiptId })}\n`);
  return { exitCode: EXIT.PASS };
}

function runStatus(values, context) {
  const { cwd, stdout, env } = context;
  if (!values.file) usage('adoption status requires --file <ledger.json>');
  if (!values.stage) usage('adoption status requires --stage <stage-id>');
  let integratedState;
  const formal = values['parent-repository'] || values['legion-repository'] || values['skill-architecture'] || values['s11-evidence'];
  if (formal) integratedState = formalState(cwd, values, resolve(cwd, values.file));
  else {
    try {
      const roots = values.repository?.length ? values.repository : [cwd];
      const normalized = roots.map((repository) => realpathSync(resolve(cwd, repository)).replaceAll('\\', '/'));
      if (new Set(normalized).size !== normalized.length) usage('adoption status repositories must be unique after normalization');
      integratedState = completionIntegratedStateForRepositories(normalized.map((root) => ({ cwd: root, scope: ['**/*'] })));
    } catch (error) { if (error instanceof LegionError) throw error; usage('adoption status requires readable repository paths'); }
  }
  if (!integratedState) throw new LegionError('ARC_EVIDENCE_INSUFFICIENT: adoption status requires current integrated state', { code: 'ARC_EVIDENCE_INSUFFICIENT', exitCode: EXIT.INCOMPLETE });
  let keyRing;
  try { keyRing = loadHostKeyRing({ dir: values['key-dir'] || env.ARCANE_KEY_DIR || join(homedir(), '.claude', 'arcane-keys') }); }
  catch { throw new LegionError('ARC_AUTH_KEY_UNAVAILABLE: adoption status requires host verification key', { code: 'ARC_AUTH_KEY_UNAVAILABLE', exitCode: EXIT.INCOMPLETE }); }
  const result = readVerifiedStageFile(resolve(cwd, values.file), values.stage, { keyRing, integratedState });
  const terminal = result.allowed && result.detail?.doneState === 'VERIFIED';
  stdout.write(`${JSON.stringify({ kind: 'legion-adoption-status', stageId: values.stage, doneState: terminal ? 'VERIFIED' : 'CANDIDATE', ...(terminal ? {} : { code: result.code ?? 'ARC_EVIDENCE_INSUFFICIENT' }) })}\n`);
  return { exitCode: terminal ? EXIT.PASS : EXIT.INCOMPLETE };
}

export function runAdoption(argv, context) {
  const [sub, ...rest] = argv;
  if (sub === '--help' || sub === 'help') { context.stdout.write('Usage: legion adoption manifest|admit|status [options]\n'); return { exitCode: EXIT.PASS }; }
  const values = parse(rest);
  if (sub === 'manifest') return runManifest(values, context);
  if (sub === 'admit') return runAdmit(values, context);
  if (sub === 'status') return runStatus(values, context);
  usage(`adoption requires manifest, admit, or status (got ${sub ?? '<none>'})`);
}
