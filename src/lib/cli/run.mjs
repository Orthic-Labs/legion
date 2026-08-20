// Canonical CLI dispatcher. The root parser accepts only --help, --version,
// --json, and the first positional subcommand; each subcommand owns its own
// strict parseArgs schema. Unknown options return exit 4.

import { parseArgs } from 'node:util';
import { EXIT, LegionError } from '../errors.mjs';
import { LEGION_VERSION } from '../version.mjs';
import { loadProviderRegistry } from '../../registry/provider-registry.mjs';
import { createHost } from '../host/index.mjs';
import { COMMANDS, renderHelp } from './help.mjs';
const SUBCOMMANDS=COMMANDS.map(({name})=>name);

const ROOT_HELP = `legion — evidence-governed repository audit

Usage: legion <command> [options]

Commands:
  init [root]        Initialize repository audit configuration (dry-run preview)
  doctor [root]      Report repository, Blueprint and Membrane context, coverage, provider, and host state
  bind [root]        Write or check per-harness bindings (agents, MCP, doctrine)
  languages [root]   Report detected languages and coverage tiers
  providers [root]   Report selected providers
  plan [root]        Build and seal an audit plan
  inspect [root]     Inspect product topology
  audit [root]       Run a complete audit
  verify <run>       Verify a prior run out of band
  explain <id>       Explain a finding or gap
  report <file>      Render a report (json/sarif/markdown/html)
  hooks              Install or uninstall git hooks
  mcp                Print MCP server configuration
  run open|close     Bind or release this session's run against a contract/task
  budget inspect     Read immutable budget bindings & run budget projection
  governance         Execute typed Arcane governance controls

Options:
  --help             Show this help
  --version          Print the version
  --json             Machine-readable JSON output on stdout
`;

function rootArgs(argv) {
  try {
    const commandIndex = argv.findIndex((value) => !value.startsWith('-'));
    const root = commandIndex === -1 ? argv : argv.slice(0, commandIndex);
    const parsed = parseArgs({
      args: root,
      allowPositionals: true,
      options: { help: { type: 'boolean' }, version: { type: 'boolean' }, json: { type: 'boolean' } },
      strict: true,
    });
    return { ...parsed, positionals: commandIndex === -1 ? [] : [argv[commandIndex]] };
  } catch (error) {
    throw new LegionError(error.message, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
}

async function dispatch(command, argv, { stdout, stderr, env, cwd, host }) {
  switch (command) {
    case 'init': {
      const { runInit } = await import('./commands/init.mjs');
      return runInit(argv, { stdout, stderr, env, cwd });
    }
    case 'doctor': {
      const { runDoctor } = await import('./commands/doctor.mjs');
      return runDoctor(argv, { stdout, stderr, env, cwd, host });
    }
    case 'bind': {
      const { runBind } = await import('./commands/bind.mjs');
      return runBind(argv, { stdout, stderr, env, cwd });
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
      return runPlan(argv, { stdout, stderr, env, cwd, host });
    }
    case 'inspect': { const { runInspect } = await import('./commands/inspect.mjs'); return runInspect(argv, { stdout, stderr, env, cwd }); }
    case 'targets': { const { runTargets } = await import('./commands/targets.mjs'); return runTargets(argv, { stdout, stderr, env, cwd }); }
    case 'components': { const { runComponents } = await import('./commands/components.mjs'); return runComponents(argv, { stdout, stderr, env, cwd }); }
    case 'stacks': { const { runStacks } = await import('./commands/stacks.mjs'); return runStacks(argv, { stdout, stderr, env, cwd }); }
    case 'controls': { const { runControls } = await import('./commands/controls.mjs'); return runControls(argv, { stdout, stderr, env, cwd }); }
    case 'governance': { const { runGovernance } = await import('./commands/governance.mjs'); return runGovernance(argv, { stdout, env, cwd, host }); }
    case 'skills': { const { runSkills } = await import('./commands/skills.mjs'); return runSkills(argv, { stdout, stderr, env, cwd }); }
    case 'rules': { const { runRules } = await import('./commands/rules.mjs'); return runRules(argv, { stdout, stderr, env, cwd }); }
    case 'schedule': { const { runSchedule } = await import('./commands/schedule.mjs'); return runSchedule(argv, { stdout, stderr, env, cwd }); }
    case 'audit': {
      const { runAudit } = await import('./commands/audit.mjs');
      return runAudit(argv, { stdout, stderr, env, cwd, host });
    }
    case 'verify': {
      const { runVerify } = await import('./commands/verify.mjs');
      return runVerify(argv, { stdout, stderr, env, cwd, host });
    }
    case 'explain': {
      const { runExplain } = await import('./commands/explain.mjs');
      return runExplain(argv, { stdout, stderr, env, cwd });
    }
    case 'report': {
      const { runReport } = await import('./commands/report.mjs');
      return runReport(argv, { stdout, stderr, env, cwd });
    }
    case 'fix': { const { runFix } = await import('./commands/fix.mjs'); return runFix(argv, { stdout, stderr, env, cwd }); }
    case 'hooks': {
      const { runHooks } = await import('./commands/hooks.mjs');
      return runHooks(argv, { stdout, stderr, env, cwd });
    }
    case 'mcp': {
      const { runMcp } = await import('./commands/mcp.mjs');
      return runMcp(argv, { stdout, stderr, env, cwd });
    }
    case 'run': {
      const { runRun } = await import('./commands/run.mjs');
      return runRun(argv, { stdout, stderr, env, cwd });
    }
    case 'budget': {
      const { runBudget } = await import('./commands/budget.mjs');
      return runBudget(argv, { stdout, env, cwd });
    }
    case 'contract': {
      const { runContract } = await import('./commands/contract.mjs');
      return runContract(argv, { stdout, stderr, env, cwd });
    }
    case 'completion': {
      const { runCompletion } = await import('./commands/completion.mjs');
      return runCompletion(argv, { stdout, env, cwd });
    }
    case 'host': { const { runHostEvents } = await import('./commands/host-events.mjs'); return runHostEvents(argv, { stdout, env, cwd }); }
    case 'harness': { const { runHarness } = await import('./commands/harness.mjs'); return runHarness(argv, { stdout, stderr, env, cwd }); }
    case 'authority': { const { runAuthorityProof } = await import('./commands/authority-proof.mjs'); return runAuthorityProof(argv, { stdout, env, cwd }); }
    case 'state': {
      const { runState } = await import('./commands/state.mjs');
      return runState(argv, { stdout, stderr, env, cwd });
    }
    case 'minimize': {
      const { runMinimize } = await import('./commands/minimize.mjs');
      return runMinimize(argv, { stdout, stderr, env, cwd });
    }
    default:
      throw new LegionError(`unknown command: ${command}`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
}

export async function runCli(argv, { stdout = process.stdout, stderr = process.stderr, env = process.env, cwd = process.cwd(), host = createHost() } = {}) {
  const parsed = rootArgs(argv);
  if (parsed.values.version) {
    stdout.write(`${LEGION_VERSION}\n`);
    return { exitCode: EXIT.PASS };
  }
  if (parsed.values.help || parsed.positionals.length === 0) {
    stdout.write(renderHelp());
    return { exitCode: parsed.values.help ? EXIT.PASS : EXIT.USAGE };
  }
  const command = parsed.positionals[0];
  if (!SUBCOMMANDS.includes(command)) {
    stderr.write(`unknown command: ${command}\n`);
    return { exitCode: EXIT.USAGE };
  }
  try {
    return await dispatch(command, argv.slice(argv.indexOf(command) + 1), { stdout, stderr, env, cwd, host });
  } catch (error) {
    if (error instanceof LegionError) {
      stderr.write(`${error.message}\n`);
      return { exitCode: error.exitCode };
    }
    if(String(error?.code??'').startsWith('ERR_PARSE_ARGS')){stderr.write(`${error.message}\n`);return{exitCode:EXIT.USAGE};}
    stderr.write(`${error.stack ?? error.message}\n`);
    return { exitCode: EXIT.INTERNAL_ERROR };
  }
}
