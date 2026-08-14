import { parseArgs } from 'node:util';
import { homedir } from 'node:os';
import { realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { EXIT, LegionError } from '../../errors.mjs';
import { loadHostKeyRing } from '../../../packages/arcane/lib/keys.mjs';
import { completionIntegratedStateForRepositories } from '../../../packages/arcane/lib/completion-state.mjs';
import { readVerifiedStageFile } from '../../../packages/arcane/lib/adoption-ledger.mjs';

function usage(message) { throw new LegionError(message, { code: 'USAGE', exitCode: EXIT.USAGE }); }

// Read-only production consumer: terminal state is projected only after the
// ledger's authenticated admission matches this checkout's current identity.
export function runAdoption(argv, { stdout, env, cwd }) {
  const [sub, ...rest] = argv;
  if (sub === '--help' || sub === 'help') {
    stdout.write('Usage: legion adoption status --file <ledger.json> --stage <stage-id> [--repository <path>]... [--key-dir <dir>]\n');
    return { exitCode: EXIT.PASS };
  }
  if (sub !== 'status') usage(`adoption requires status (got ${sub ?? '<none>'})`);
  let values;
  try {
    ({ values } = parseArgs({ args: rest, allowPositionals: false, strict: true, options: {
      file: { type: 'string' }, stage: { type: 'string' }, repository: { type: 'string', multiple: true }, 'key-dir': { type: 'string' },
    } }));
  } catch (error) { usage(error.message); }
  if (!values.file) usage('adoption status requires --file <ledger.json>');
  if (!values.stage) usage('adoption status requires --stage <stage-id>');
  let repositories;
  try {
    const roots = values.repository?.length ? values.repository : [cwd];
    const normalized = roots.map((repository) => realpathSync(resolve(cwd, repository)).replaceAll('\\', '/'));
    if (new Set(normalized).size !== normalized.length) usage('adoption status repositories must be unique after normalization');
    repositories = normalized.map((root) => ({ cwd: root, scope: ['**/*'] }));
  } catch (error) {
    if (error instanceof LegionError) throw error;
    throw new LegionError('adoption status requires readable repository paths', { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  const integratedState = completionIntegratedStateForRepositories(repositories);
  if (!integratedState) throw new LegionError('ARC_EVIDENCE_INSUFFICIENT: adoption status requires current integrated repository state', { code: 'ARC_EVIDENCE_INSUFFICIENT', exitCode: EXIT.INCOMPLETE });
  let keyRing;
  try { keyRing = loadHostKeyRing({ dir: values['key-dir'] || env.ARCANE_KEY_DIR || join(homedir(), '.claude', 'arcane-keys') }); }
  catch { throw new LegionError('ARC_AUTH_KEY_UNAVAILABLE: adoption status requires host verification key', { code: 'ARC_AUTH_KEY_UNAVAILABLE', exitCode: EXIT.INCOMPLETE }); }
  let result;
  try { result = readVerifiedStageFile(values.file, values.stage, { keyRing, integratedState }); }
  catch (error) { throw new LegionError(`${error.code ?? 'ARC_STORE_CORRUPT'}: adoption status unavailable`, { code: error.code ?? 'ARC_STORE_CORRUPT', exitCode: EXIT.INCOMPLETE }); }
  const terminal = result.allowed && result.detail?.doneState === 'VERIFIED';
  stdout.write(`${JSON.stringify({ kind: 'legion-adoption-status', stageId: values.stage, doneState: terminal ? 'VERIFIED' : 'CANDIDATE', ...(terminal ? {} : { code: result.code ?? 'ARC_EVIDENCE_INSUFFICIENT' }) })}\n`);
  return { exitCode: terminal ? EXIT.PASS : EXIT.INCOMPLETE };
}
