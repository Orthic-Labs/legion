import { parseArgs } from 'node:util';
import { resolve, dirname } from 'node:path';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { EXIT, LegionError } from '../../errors.mjs';
import { LEGION_VERSION } from '../../version.mjs';
import * as claudeCode from './bind/claude-code.mjs';
import * as codex from './bind/codex.mjs';
import * as agentsMd from './bind/agents-md.mjs';
import { bindingReceiptPath, driftForHarness, readBindingReceipt } from './bind/drift.mjs';
import { enumerateRegistrations } from './bind/registrations.mjs';

const HARNESS_NAMES = ['claude-code', 'codex', 'agents-md'];
const HARNESS_MODULES = { 'claude-code': claudeCode, codex, 'agents-md': agentsMd };

function detectHarnesses(root) {
  return HARNESS_NAMES.filter((name) => HARNESS_MODULES[name].detect(root));
}

// legion bind [root] --check|--write [--harness <name>...]
// --check (default when neither flag is given) previews per-harness targets
// and drift against any prior receipt; --write performs the writes and
// records .legion/binding.json. Mirrors init.mjs's dry-run-default style.
export function runBind(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      check: { type: 'boolean' },
      write: { type: 'boolean' },
      harness: { type: 'string', multiple: true },
      registrations: { type: 'boolean' },
    },
    strict: true,
  });

  // --registrations answers "what is registered on THIS host, by what
  // mechanism, and is anything doubled" — across settings files AND plugins.
  // Read-only, and deliberately independent of any binding receipt: the 2026-08-10
  // incident was a wrong conclusion drawn from reading one settings file while
  // a plugin supplied the same hooks (see ./bind/registrations.mjs).
  if (parsed.values.registrations) {
    const root = resolve(parsed.positionals[0] ?? cwd);
    const { sources, registrations, duplicates } = enumerateRegistrations({ root });
    stdout.write(`${JSON.stringify({ schemaVersion: 1, kind: 'legion-bind-registrations', root, sources, registrations, duplicates }, null, 2)}\n`);
    if (duplicates.length > 0) {
      stderr.write(`DUPLICATE HOOK REGISTRATION: ${duplicates.length}\n`);
      for (const d of duplicates) stderr.write(`  ${d.detail}\n`);
      stderr.write('Hooks are additive — each duplicate runs every event. Remove it from one source.\n');
      return { exitCode: EXIT.POLICY_FAIL };
    }
    return { exitCode: EXIT.PASS };
  }
  if (parsed.values.check && parsed.values.write) {
    throw new LegionError('bind accepts either --check or --write, not both', { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  for (const name of parsed.values.harness ?? []) {
    if (!HARNESS_NAMES.includes(name)) {
      throw new LegionError(`unknown harness: ${name} (expected one of ${HARNESS_NAMES.join('|')})`, { code: 'USAGE', exitCode: EXIT.USAGE });
    }
  }
  const root = resolve(parsed.positionals[0] ?? cwd);
  if (!existsSync(root)) throw new LegionError(`root does not exist: ${root}`, { code: 'USAGE', exitCode: EXIT.USAGE });

  const dryRun = !parsed.values.write;
  const targetNames = parsed.values.harness?.length ? parsed.values.harness : detectHarnesses(root);

  const priorReceipt = readBindingReceipt(root);
  const priorByName = new Map((priorReceipt?.harnesses ?? []).map((h) => [h.name, h]));

  const harnesses = targetNames.map((name) => {
    const mod = HARNESS_MODULES[name];
    const wouldWrite = mod.plan(root);
    const priorEntry = priorByName.get(name);
    const drift = priorEntry ? driftForHarness(root, priorEntry) : [];
    return {
      name,
      present: mod.detect(root),
      fidelityTier: mod.FIDELITY_TIER,
      wouldWrite,
      drift,
    };
  });

  let hasDrift = harnesses.some((h) => h.drift.length > 0);

  const report = {
    schemaVersion: 1,
    kind: dryRun ? 'legion-bind-preview' : 'legion-bind-result',
    root,
    harnesses,
    dryRun,
  };

  if (!dryRun) {
    const receiptHarnesses = [];
    for (const entry of report.harnesses) {
      const mod = HARNESS_MODULES[entry.name];
      const { wrote } = mod.write(root);
      entry.wrote = wrote;
      receiptHarnesses.push({ name: entry.name, fidelityTier: entry.fidelityTier, files: wrote, writtenAt: new Date().toISOString() });
    }
    const receipt = {
      schemaVersion: 1,
      kind: 'legion-binding-receipt',
      packageVersion: LEGION_VERSION,
      harnesses: receiptHarnesses,
    };
    const receiptPath = bindingReceiptPath(root);
    mkdirSync(dirname(receiptPath), { recursive: true });
    writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
    hasDrift = false;
  }

  stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  return { exitCode: hasDrift ? EXIT.POLICY_FAIL : EXIT.PASS };
}
