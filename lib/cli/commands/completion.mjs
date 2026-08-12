import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { EXIT, LegionError } from '../../errors.mjs';
import { loadHostKeyRing } from '../../../packages/arcane/lib/keys.mjs';
import { digestValue, isDigest } from '../../../packages/arcane/lib/canonical.mjs';
import { SessionBindingStore } from '../../../packages/arcane/lib/session-binding.mjs';
import { ContractSealStore } from '../../../packages/arcane/lib/contract-seal-store.mjs';
import { HostEventLedger } from '../../../packages/arcane/lib/host-event-ledger.mjs';
import { AuthorityInvocationProofIssuer } from '../../../packages/arcane/lib/authority-invocation-proof.mjs';
import { PendingTerminalOperationStore } from '../../../packages/arcane/lib/pending-terminal-operation-store.mjs';
import { requireCanonicalAdvisoryProfile } from '../../../packages/arcane/lib/advisory-profile.mjs';

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

export async function runCompletion(argv, { stdout, env, cwd }) {
  const [sub, ...rest] = argv;
  if (sub === '--help' || sub === 'help') {
    stdout.write('Usage: legion completion claim --file <outcome.json> [--session <id>]\n');
    return { exitCode: EXIT.PASS };
  }
  if (sub !== 'claim') throw new LegionError('completion requires claim', { code: 'USAGE', exitCode: EXIT.USAGE });
  const values = parseArgs({ args: rest, strict: true, options: { file: { type: 'string' }, session: { type: 'string' }, 'key-dir': { type: 'string' } } }).values;
  const sessionId = session(values.session, env);
  if (!values.file || !sessionId) throw new LegionError('completion claim requires --file & known session', { code: 'USAGE', exitCode: EXIT.USAGE });

  const keys = loadHostKeyRing({ dir: values['key-dir'] || env.ARCANE_KEY_DIR || join(homedir(), '.claude', 'arcane-keys') });
  const binding = new SessionBindingStore({ root: join(cwd, '.audit', 'arcane', 'session-bindings') }).getBinding(sessionId);
  if (!binding?.contractId || !binding.taskId) throw new LegionError('ARC_NO_CONTRACT', { code: 'ARC_NO_CONTRACT', exitCode: EXIT.INCOMPLETE });
  const seal = new ContractSealStore({ root: join(cwd, '.audit', 'arcane', 'contract-seals') }).get(binding.contractId, binding.contractVersion);
  if (!seal || seal.contractDigest !== binding.contractDigest) throw new LegionError('ARC_CONTRACT_VERSION_MISMATCH', { code: 'ARC_CONTRACT_VERSION_MISMATCH', exitCode: EXIT.INCOMPLETE });

  const ledger = new HostEventLedger({ root: join(cwd, '.audit', 'arcane', 'host-events'), keyRing: keys, keyId: keys.activeKeyId() });
  if (!ledger.verify().allowed) throw new LegionError('ARC_STORE_CORRUPT: legion host events inspect', { code: 'ARC_STORE_CORRUPT', exitCode: EXIT.INCOMPLETE });
  const event = ledger.records().reverse().find((record) => record.sessionId === sessionId);
  if (!event || !['legion', 'alchemist'].includes(event.observedAuthority)) throw new LegionError('ARC_AUTHORITY_NOT_ASSERTED: current Legion or assigned Alchemist event required', { code: 'ARC_AUTHORITY_NOT_ASSERTED', exitCode: EXIT.INCOMPLETE });

  const issuer = new AuthorityInvocationProofIssuer({ root: join(cwd, '.audit', 'arcane', 'authority-invocations'), keyRing: keys, keyId: keys.activeKeyId(), ledgerStore: ledger });
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
  });
  const consumed = issuer.consume(proof, { artifactDigest: digestValue(claim) });
  if (!consumed.allowed) throw new LegionError(consumed.code, { code: consumed.code, exitCode: EXIT.INCOMPLETE });
  const stored = store.append(claim);
  if (!stored.allowed) throw new LegionError(stored.code, { code: stored.code, exitCode: EXIT.INCOMPLETE });
  stdout.write(`${JSON.stringify({ claimId: stored.detail.claimId, invocationProofDigest: digestValue(proof) })}\n`);
  return { exitCode: EXIT.PASS };
}
