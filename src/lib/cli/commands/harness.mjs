// `legion harness ...` — the thin renderer/installer over the data-driven adapter
// seam. It carries no semantics: every subcommand delegates to the registry,
// which delegates to the descriptor-driven engine.
import { parseArgs } from 'node:util';
import { EXIT, LegionError } from '../../errors.mjs';
import * as reg from '../../host/registry.mjs';

const USAGE = `Usage:
  legion harness list                         known adapters
  legion harness detect [root]                harnesses detected in a repo
  legion harness capabilities <id> [root]     declared surface fidelity
  legion harness matrix [root]                fidelity across every harness
  legion harness install <id> [root]          project skills + register surfaces
  legion harness verify <id> [root]           check an installation
  legion harness uninstall <id> [root]        remove what install wrote
`;

export async function runHarness(argv, { stdout, stderr, env, cwd }) {
  const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, strict: true, options: { json: { type: 'boolean', default: true } } });
  const [sub, ...rest] = positionals;
  const emit = (value) => stdout.write(`${JSON.stringify(value, null, 2)}\n`);

  if (!sub || sub === 'help' || values.help) { stdout.write(USAGE); return { exitCode: EXIT.PASS }; }

  if (sub === 'list') { emit({ kind: 'legion-harness-list', adapters: reg.ADAPTER_IDS }); return { exitCode: EXIT.PASS }; }
  if (sub === 'detect') { emit({ kind: 'legion-harness-detect', detected: reg.detectHarnesses(rest[0] ?? cwd, env) }); return { exitCode: EXIT.PASS }; }
  if (sub === 'matrix') { emit({ kind: 'legion-harness-matrix', harnesses: reg.fidelityMatrix({ root: rest[0] ?? cwd, env }) }); return { exitCode: EXIT.PASS }; }

  const id = rest[0];
  const root = rest[1] ?? cwd;
  if (!id) throw new LegionError(`harness ${sub} requires a harness id (one of ${reg.ADAPTER_IDS.join(', ')})`, { code: 'USAGE', exitCode: EXIT.USAGE });

  try {
    if (sub === 'capabilities') { emit({ kind: 'legion-harness-capabilities', ...reg.capabilities(id, { root, env }) }); return { exitCode: EXIT.PASS }; }
    if (sub === 'install') { emit({ kind: 'legion-harness-install', ...reg.install(id, { root, env }) }); return { exitCode: EXIT.PASS }; }
    if (sub === 'uninstall') { emit({ kind: 'legion-harness-uninstall', ...reg.uninstall(id, { root, env }) }); return { exitCode: EXIT.PASS }; }
    if (sub === 'verify') { const v = reg.verify(id, { root, env }); emit({ kind: 'legion-harness-verify', ...v }); return { exitCode: v.ok ? EXIT.PASS : EXIT.INCOMPLETE }; }
  } catch (err) {
    if (err instanceof LegionError) throw err;
    throw new LegionError(err.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  throw new LegionError(`unknown harness subcommand: ${sub}`, { code: 'USAGE', exitCode: EXIT.USAGE });
}
