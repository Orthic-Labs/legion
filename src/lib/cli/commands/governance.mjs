import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { EXIT, LegionError } from '../../errors.mjs';
import { AuthorityBindingStore } from '../../../packages/arcane/lib/authority-binding-store.mjs';
import { upsertFinding } from '../../../packages/arcane/lib/finding-lifecycle.mjs';
import { HostEventLedger } from '../../../packages/arcane/lib/host-event-ledger.mjs';
import { loadHostKeyRing } from '../../../packages/arcane/lib/keys.mjs';
import { ReceiptStore } from '../../../packages/arcane/lib/receipt-store.mjs';
import { createDeliveryGovernanceDispatcher, runDeliveryGovernance } from './governance/delivery.mjs';
import { dispatchExecutionControl } from './governance/execution.mjs';
import { createJudgmentControlCapability, dispatchGovernanceJudgment } from './governance/judgment.mjs';

const usage = (message) => { throw new LegionError(message, { code: 'USAGE', exitCode: EXIT.USAGE }); };
const parseRequest = (argv) => {
  let values;
  try {
    ({ values } = parseArgs({ args: argv, allowPositionals: false, strict: true, options: {
      json: { type: 'string' }, 'key-dir': { type: 'string' },
    } }));
  } catch (error) { usage(error.message); }
  if (!values.json) usage('governance requires --json <structured-request>');
  try { return { request: JSON.parse(values.json), values }; }
  catch { usage('governance --json must be valid JSON'); }
};

function authenticatedContext({ cwd, env, values }) {
  const keyRing = loadHostKeyRing({ dir: values['key-dir'] || env.ARCANE_KEY_DIR || join(homedir(), '.claude', 'arcane-keys') });
  return {
    keyRing,
    receiptStore: new ReceiptStore({ root: join(cwd, '.audit', 'arcane', 'receipts') }),
    authorityBindingStore: new AuthorityBindingStore({ root: join(cwd, '.audit', 'arcane', 'authority-bindings') }),
    ledgerStore: new HostEventLedger({ root: join(cwd, '.audit', 'arcane', 'host-events'), keyRing, keyId: keyRing.activeKeyId() }),
  };
}

function durableFindingContext(receiptStore) {
  const latest = receiptStore.list().filter((record) => record.kind === 'arcane-governance-finding-state').at(-1);
  let records = Array.isArray(latest?.records) ? latest.records : [];
  const findingStore = {
    records: () => Object.freeze([...records]),
    upsert: (input) => {
      const result = upsertFinding({ ...input, records });
      records = [...result.records];
      return result;
    },
  };
  const findingPersistence = {
    load: () => Object.freeze([...records]),
    save: (next) => { receiptStore.append({ kind: 'arcane-governance-finding-state', records: next, recordedAt: new Date().toISOString() }); },
  };
  return { findingStore, findingPersistence };
}

/** Live structured ingress for Arcane governance controls used by S11. */
export function runGovernance(argv, { stdout, env, cwd, host = {} }) {
  const [domain, ...rest] = argv;
  if (domain === '--help' || domain === 'help') {
    stdout.write('Usage: legion governance execution|delivery|judgment --json <structured-request> [--key-dir <dir>]\n');
    return { exitCode: EXIT.PASS };
  }
  if (!['execution', 'delivery', 'judgment'].includes(domain)) usage(`governance requires execution, delivery, or judgment (got ${domain ?? '<none>'})`);
  const { request, values } = parseRequest(rest);
  if (domain === 'delivery') {
    const dispatcher = createDeliveryGovernanceDispatcher({
      providerCapability: host.deliveryProviderCapability ?? null,
      packetCapability: host.packetAdmissionCapability ?? null,
    });
    return runDeliveryGovernance(request, { stdout, dispatcher });
  }
  if (domain === 'execution') {
    const result = dispatchExecutionControl(request, {
      capability: host.executionControlCapability,
    });
    stdout.write(`${JSON.stringify(result)}\n`);
    return { exitCode: result.result?.allowed ? EXIT.PASS : EXIT.INCOMPLETE };
  }
  let context;
  const receiptStore = new ReceiptStore({ root: join(cwd, '.audit', 'arcane', 'receipts') });
  const capabilityState = { ...durableFindingContext(receiptStore), receiptStore };
  if (/^(?:advisory|scope)\./.test(request?.operation ?? '')) {
    try { Object.assign(capabilityState, authenticatedContext({ cwd, env, values })); }
    catch (error) {
      const result = { allowed: false, code: error?.code ?? 'ARC_AUTH_KEY_UNAVAILABLE', message: 'authenticated governance stores are unavailable', detail: {} };
      stdout.write(`${JSON.stringify(result)}\n`);
      return { exitCode: EXIT.INCOMPLETE };
    }
  }
  try { context = { capability: host.judgmentControlCapability ?? createJudgmentControlCapability(capabilityState) }; }
  catch { context = { capability: null }; }
  const result = dispatchGovernanceJudgment(request, context);
  stdout.write(`${JSON.stringify(result)}\n`);
  return { exitCode: result.allowed ? EXIT.PASS : EXIT.INCOMPLETE };
}
