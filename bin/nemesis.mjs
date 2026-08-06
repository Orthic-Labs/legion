#!/usr/bin/env node
import { runCli } from '../lib/cli/run.mjs';

try {
  const result = await runCli(process.argv.slice(2), {
    stdout: process.stdout,
    stderr: process.stderr,
    env: process.env,
    cwd: process.cwd(),
  });
  process.exitCode = result.exitCode;
} catch (error) {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = Number.isInteger(error.exitCode) ? error.exitCode : 3;
}
