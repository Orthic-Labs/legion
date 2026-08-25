#!/usr/bin/env node
// Compatibility entrypoint for host configurations that still invoke Node.
// It deliberately contains no Legion semantics and resolves only the installed
// native adapter; source-checkout/module fallbacks would undermine command
// provenance and can execute an unreviewed tree.
import { spawnSync } from 'node:child_process';

const result = spawnSync('legion-hook', [], { stdio: 'inherit', shell: false });
if (result.error) {
  process.stderr.write(`arcane-hook: installed native legion-hook is unavailable: ${result.error.message}\n`);
  process.exitCode = 1;
} else {
  process.exitCode = result.status ?? 1;
}
