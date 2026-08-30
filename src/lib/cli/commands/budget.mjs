import { parseArgs } from 'node:util';
import { join } from 'node:path';

import { EXIT, LegionError } from '../../errors.mjs';
import { loadHostKeyRing } from '../../guard/compat/host/keys.mjs';
import { BudgetGovernanceStore } from './governance/execution/budget-governance-store.mjs';
import { TaskBudgetSealStore } from './governance/execution/task-budget-seal-store.mjs';

function usage(message) { throw new LegionError(message, { code: 'USAGE', exitCode: EXIT.USAGE }); }

/** Oracle projection only: this command has no store mutation path. */
export function runBudget(argv, { stdout, env, cwd }) {
  const [sub, ...rest] = argv;
  if (sub !== 'inspect') usage(`budget requires inspect (got ${sub ?? '<none>'})`);
  let values;
  try {
    ({ values } = parseArgs({ args: rest, allowPositionals: false, strict: true, options: {
      contract: { type: 'string' }, version: { type: 'string' }, task: { type: 'string' }, run: { type: 'string' },
    } }));
  } catch (error) { usage(error.message); }
  if (!values.contract || !/^EC-\d+$/.test(values.contract)) usage('budget inspect requires --contract <EC-#>');
  if (!/^\d+$/.test(values.version ?? '') || Number(values.version) < 1) usage('budget inspect requires --version <positive integer>');
  if (!values.task || !/^T-\d+(?:\.\d+)*$/.test(values.task)) usage('budget inspect requires --task <T-#(.#)*>');
  if (!env.ARCANE_KEY_DIR) throw new LegionError('ARC_AUTH_KEY_UNAVAILABLE: budget inspect requires ARCANE_KEY_DIR', { code: 'ARC_AUTH_KEY_UNAVAILABLE', exitCode: EXIT.INCOMPLETE });
  try {
    const keyRing = loadHostKeyRing({ dir: env.ARCANE_KEY_DIR });
    const budget = new BudgetGovernanceStore({ root: join(cwd, '.audit', 'arcane', 'budget-governance'), keyRing }).require(values.contract, Number(values.version));
    const task = new TaskBudgetSealStore({ root: join(cwd, '.audit', 'arcane', 'task-budget-seals'), keyRing }).require(values.contract, values.task);
    if (task.contractVersion !== Number(values.version) || task.contractDigest == null) throw new LegionError('ARC_BINDING_MISMATCH: task budget differs from requested contract version', { code: 'ARC_BINDING_MISMATCH', exitCode: EXIT.INCOMPLETE });
    const projection = typeof budget.inspect === 'function'
      ? budget.inspect({ contractId: values.contract, version: Number(values.version), taskId: values.task, ...(values.run ? { runId: values.run } : {}) })
      : { allowed: true, events: [], stopped: null };
    stdout.write(`${JSON.stringify({ kind: 'legion-budget-inspection', readOnly: true, contract: budget, task, projection })}\n`);
    return { exitCode: projection.allowed === false ? EXIT.INCOMPLETE : EXIT.PASS };
  } catch (error) {
    if (error instanceof LegionError) throw error;
    throw new LegionError(`${error.code ?? 'ARC_STORE_CORRUPT'}: budget inspection unavailable`, { code: error.code ?? 'ARC_STORE_CORRUPT', exitCode: EXIT.INCOMPLETE });
  }
}
