// `contract` and `state` dispatch in lib/cli/run.mjs but were absent here, and
// SUBCOMMANDS is derived from this list — so `legion contract seal` and
// `legion state snapshot` both answered "unknown command" despite being
// implemented. That made the documented locked-domain path (HANDOFF §4:
// contract seal -> run open) unreachable, i.e. the gate blocked its own repair.
export const COMMANDS = Object.freeze(['init','doctor','bind','inspect','targets','components','stacks','controls','governance','skills','languages','providers','rules','schedule','plan','audit','verify','explain','report','fix','hooks','mcp','run','budget','adoption','contract','assurance','completion','host','authority','state','minimize'].map((name) => Object.freeze({ name })));
const ROOT_OPTIONS = new Set(['--help', '--version', '--json']);
export function parseRootArguments(argv = []) { const command = argv.find((value) => !value.startsWith('-')) ?? null; if (command && !COMMANDS.some((entry) => entry.name === command)) throw new TypeError(`unknown command: ${command}`); for (const value of argv) if (value.startsWith('-') && !ROOT_OPTIONS.has(value)) throw new TypeError(`unknown option: ${value}`); return { command, help: argv.includes('--help'), version: argv.includes('--version'), json: argv.includes('--json') }; }
export function renderHelp() { return `Usage: legion <command> [options]\n\nCommands:\n${COMMANDS.map(({ name }) => `  ${name}`).join('\n')}\n`; }
