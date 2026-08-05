// Canonical CLI dispatcher. The root parser accepts only --help, --version,
// --json, and the first positional subcommand; each subcommand owns its own
// strict parseArgs schema. Unknown options return exit 4.

import { parseArgs } from 'node:util';
import { EXIT, NemesisError } from '../errors.mjs';
import { NEMESIS_VERSION } from '../version.mjs';
import { loadProviderRegistry } from '../../registry/provider-registry.mjs';

const SUBCOMMANDS = [
  'init', 'doctor', 'languages', 'providers', 'plan', 'audit',
  'verify', 'explain', 'report', 'hooks', 'mcp',
];

const ROOT_HELP = `nemesis — evidence-governed repository audit

Usage: nemesis <command> [options]

Commands:
  init [root]        Initialize repository audit configuration (dry-run preview)
  doctor [root]      Report repository, Cortex, coverage, provider, and host state
  languages [root]   Report detected languages and coverage tiers
  providers [root]   Report selected providers
  plan [root]        Build and seal an audit plan
  audit [root]       Run a complete audit
  verify <run>       Verify a prior run out of band
  explain <id>       Explain a finding or gap
  report <file>      Render a report (json/sarif/markdown/html)
  hooks              Install or uninstall git hooks
  mcp                Print MCP server configuration

Options:
  --help             Show this help
  --version          Print the version
  --json             Machine-readable JSON output on stdout
`;

function rootArgs(argv) {
  try {
    // The root parser accepts only --help/--version/--json and the first
    // positional subcommand; subcommand-specific options are passed through
    // untouched (each subcommand owns its own strict parseArgs schema).
    return parseArgs({
      args: argv,
      allowPositionals: true,
      options: { help: { type: 'boolean' }, version: { type: 'boolean' }, json: { type: 'boolean' } },
      strict: false,
    });
  } catch (error) {
    throw new NemesisError(error.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
}

async function dispatch(command, argv, { stdout, stderr, env, cwd }) {
  switch (command) {
    case 'init': {
      const { runInit } = await import('./commands/init.mjs');
      return runInit(argv, { stdout, stderr, env, cwd });
    }
    case 'doctor': {
      const { runDoctor } = await import('./commands/doctor.mjs');
      return runDoctor(argv, { stdout, stderr, env, cwd });
    }
    case 'languages': {
      const { runLanguages } = await import('./commands/languages.mjs');
      return runLanguages(argv, { stdout, stderr, env, cwd });
    }
    case 'providers': {
      const { runProviders } = await import('./commands/providers.mjs');
      return runProviders(argv, { stdout, stderr, env, cwd });
    }
    case 'plan': {
      const { runPlan } = await import('./commands/plan.mjs');
      return runPlan(argv, { stdout, stderr, env, cwd });
    }
    case 'audit': {
      const { runAudit } = await import('./commands/audit.mjs');
      return runAudit(argv, { stdout, stderr, env, cwd });
    }
    case 'verify': {
      const { runVerify } = await import('./commands/verify.mjs');
      return runVerify(argv, { stdout, stderr, env, cwd });
    }
    case 'explain': {
      const { runExplain } = await import('./commands/explain.mjs');
      return runExplain(argv, { stdout, stderr, env, cwd });
    }
    case 'report': {
      const { runReport } = await import('./commands/report.mjs');
      return runReport(argv, { stdout, stderr, env, cwd });
    }
    case 'hooks': {
      const { runHooks } = await import('./commands/hooks.mjs');
      return runHooks(argv, { stdout, stderr, env, cwd });
    }
    case 'mcp': {
      const { runMcp } = await import('./commands/mcp.mjs');
      return runMcp(argv, { stdout, stderr, env, cwd });
    }
    default:
      throw new NemesisError(`unknown command: ${command}`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
}

export async function runCli(argv, { stdout = process.stdout, stderr = process.stderr, env = process.env, cwd = process.cwd() } = {}) {
  const parsed = rootArgs(argv);
  if (parsed.values.version) {
    stdout.write(`${NEMESIS_VERSION}\n`);
    return { exitCode: EXIT.PASS };
  }
  if (parsed.values.help || parsed.positionals.length === 0) {
    stdout.write(ROOT_HELP);
    return { exitCode: parsed.values.help ? EXIT.PASS : EXIT.USAGE };
  }
  const command = parsed.positionals[0];
  if (!SUBCOMMANDS.includes(command)) {
    stderr.write(`unknown command: ${command}\n`);
    return { exitCode: EXIT.USAGE };
  }
  try {
    return await dispatch(command, argv.slice(argv.indexOf(command) + 1), { stdout, stderr, env, cwd });
  } catch (error) {
    if (error instanceof NemesisError) {
      stderr.write(`${error.message}\n`);
      return { exitCode: error.exitCode };
    }
    stderr.write(`${error.stack ?? error.message}\n`);
    return { exitCode: EXIT.INTERNAL_ERROR };
  }
}
