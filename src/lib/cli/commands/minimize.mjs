// `legion minimize` — the commit gate, now inside Legion rather than beside it.
//
// It was `tools/lib/minimize/minimize_gate.py`: workspace-owned Python doing
// Arcane's job (bind a review to the staged tree, mint a receipt, refuse the
// effect when the receipt does not describe what is being committed) from
// outside Arcane, in a second language, with none of Arcane's guarantees.
//
// Subcommands mirror the Python CLI exactly so the pre-commit hook and every
// existing habit keep working:
//   legion minimize commit init-review <review.json>
//   legion minimize commit receipt <review.json> <receipt.json>
//   legion minimize commit verify <receipt.json>

import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { EXIT, LegionError } from '../../errors.mjs';
import {
  MinimizeError,
  buildReceipt,
  buildReview,
  decisionReceipt,
  fileExists,
  readJson,
  validateDecision,
  verifyDecision,
  verifyReceipt,
  writeJson,
} from '../../cognitive/arcane/minimize.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ARCANE_LIB = resolve(HERE, '../../cognitive/arcane/minimize.mjs');
const POLICY = resolve(HERE, '../../cognitive/arcane/policy/minimize-policy.md');

function paths() {
  return { policyPath: POLICY, validatorPath: ARCANE_LIB };
}

export async function runMinimize(argv, { stdout, cwd }) {
  const [domain, action, ...rest] = argv;
  if (domain !== 'commit' && domain !== 'decision') {
    throw new LegionError(`minimize requires a domain: commit|decision (got ${domain ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  let parsed;
  try {
    parsed = parseArgs({ args: rest, allowPositionals: true, strict: true, options: {} });
  } catch (error) {
    throw new LegionError(error.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  const positionals = parsed.positionals.map((value) => resolve(cwd ?? process.cwd(), value));

  try {
    if (domain === 'decision') {
      if (action === 'validate') {
        if (positionals.length !== 1) throw new LegionError('usage: legion minimize decision validate <decision.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
        validateDecision(readJson(positionals[0]));
        stdout.write('MINIMIZE PASS\n');
        return { exitCode: EXIT.PASS };
      }
      if (action === 'receipt') {
        if (positionals.length !== 2) throw new LegionError('usage: legion minimize decision receipt <decision.json> <receipt.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
        writeJson(positionals[1], decisionReceipt(positionals[0], paths()));
        stdout.write('MINIMIZE PASS\n');
        return { exitCode: EXIT.PASS };
      }
      if (action === 'verify') {
        if (positionals.length !== 2) throw new LegionError('usage: legion minimize decision verify <decision.json> <receipt.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
        verifyDecision(positionals[0], positionals[1], paths());
        stdout.write('MINIMIZE PASS\n');
        return { exitCode: EXIT.PASS };
      }
      throw new LegionError(`minimize decision requires an action: validate|receipt|verify (got ${action ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
    }
    if (action === 'init-review') {
      if (positionals.length !== 1) throw new LegionError('usage: legion minimize commit init-review <review.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
      writeJson(positionals[0], buildReview());
      stdout.write('MINIMIZE PASS\n');
      return { exitCode: EXIT.PASS };
    }
    if (action === 'receipt') {
      if (positionals.length !== 2) throw new LegionError('usage: legion minimize commit receipt <review.json> <receipt.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
      writeJson(positionals[1], buildReceipt(positionals[0], paths()));
      stdout.write('MINIMIZE PASS\n');
      return { exitCode: EXIT.PASS };
    }
    if (action === 'verify') {
      if (positionals.length !== 1) throw new LegionError('usage: legion minimize commit verify <receipt.json>', { code: 'USAGE', exitCode: EXIT.USAGE });
      if (!fileExists(positionals[0])) throw new MinimizeError(`missing commit receipt: ${positionals[0]}`);
      verifyReceipt(readJson(positionals[0]), paths());
      stdout.write('MINIMIZE PASS\n');
      return { exitCode: EXIT.PASS };
    }
  } catch (error) {
    if (error instanceof MinimizeError) {
      // Same wording the Python gate used, so the hook's output and every
      // troubleshooting note about it stay accurate.
      throw new LegionError(`MINIMIZE FAIL: ${error.message}`, { code: 'MINIMIZE_FAIL', exitCode: EXIT.POLICY_FAIL });
    }
    throw error;
  }
  throw new LegionError(`minimize commit requires an action: init-review|receipt|verify (got ${action ?? '<none>'})`, { code: 'USAGE', exitCode: EXIT.USAGE });
}
