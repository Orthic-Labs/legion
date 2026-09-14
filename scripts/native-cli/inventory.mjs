#!/usr/bin/env node
/**
 * Step 1 — freeze CLI behavior inventory from authoritative sources.
 * Node: src/lib/cli/help.mjs + run.mjs dispatch
 * Rust: engine/bins/legion/src/cli.rs Command enum + dispatch match
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT_DIR = resolve(ROOT, 'dist', 'native-cli');
const OUT_JSON = resolve(OUT_DIR, 'behavior-inventory.json');
const OUT_MD = resolve(ROOT, 'docs', 'plans', 'native-cli-behavior-inventory.md');

const NODE_HELP = readFileSync(resolve(ROOT, 'src/lib/cli/help.mjs'), 'utf8');
const NODE_RUN = readFileSync(resolve(ROOT, 'src/lib/cli/run.mjs'), 'utf8');
const RUST_CLI = readFileSync(resolve(ROOT, 'engine/bins/legion/src/cli.rs'), 'utf8');
const FIXTURES = JSON.parse(readFileSync(resolve(ROOT, 'tests/native-cli-characterization/fixtures.json'), 'utf8')).fixtures;

function nodeCommands() {
	const match = NODE_HELP.match(/COMMANDS = Object\.freeze\(\[([^\]]+)\]/);
	if (!match) throw new Error('cannot parse Node COMMANDS from help.mjs');
	return [...match[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
}

function nodeDispatched() {
	const dispatched = new Set();
	for (const match of NODE_RUN.matchAll(/case '([^']+)':/g)) dispatched.add(match[1]);
	return [...dispatched].sort();
}

function rustCommands() {
	const block = RUST_CLI.match(/enum Command \{([\s\S]*?)\n\}/);
	if (!block) throw new Error('cannot parse Rust Command enum');
	const names = [];
	for (const match of block[1].matchAll(/^\s+([A-Z][A-Za-z0-9]*)\(/gm)) {
		const name = match[1];
		if (name === 'M1ConfigArgs' || name === 'ServeArgs') continue;
		names.push(name.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase());
	}
	return names.sort();
}

function rustDispatchMap() {
	const map = {};
	const dispatchBlock = RUST_CLI.match(/async fn dispatch\([\s\S]*?let result: CommandResult = match command \{([\s\S]*?)\n    \};/);
	if (!dispatchBlock) throw new Error('cannot parse Rust dispatch');
	for (const match of dispatchBlock[1].matchAll(/Command::([A-Za-z]+)\([^)]*\) => ([^\n,]+)/g)) {
		const command = match[1].replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();
		const handler = match[2].trim();
		map[command] = handler;
	}
	return map;
}

function classifyRust(handler) {
	if (handler.includes('root_projection!')) return { tier: 'stub', handler: 'native_root_projection' };
	if (handler.includes('common_projection!')) return { tier: 'stub', handler: 'native_common_projection' };
	if (handler.includes('native_doctor')) return { tier: 'partial', handler: 'native_doctor' };
	if (handler.includes('native_plan')) return { tier: 'partial', handler: 'native_plan' };
	if (handler.includes('native_run')) return { tier: 'partial', handler: 'native_run' };
	if (handler.includes('native_verify')) return { tier: 'partial', handler: 'native_verify' };
	if (handler.includes('native_report')) return { tier: 'partial', handler: 'native_report' };
	if (handler.includes('native_completion')) return { tier: 'partial', handler: 'native_completion' };
	if (handler.includes('native_state')) return { tier: 'partial', handler: 'native_state' };
	if (handler.includes('native_host')) return { tier: 'partial', handler: 'native_host' };
	if (handler.includes('native_schedule')) return { tier: 'divergent', handler: 'native_schedule' };
	if (handler.includes('commands::audit::run')) return { tier: 'partial', handler: 'audit' };
	if (handler.includes('commands::rules::run')) return { tier: 'divergent', handler: 'rules' };
	if (handler.includes('commands::setup::run')) return { tier: 'native', handler: 'setup' };
	if (handler.includes('commands::assurance::run')) return { tier: 'partial', handler: 'assurance' };
	if (handler.startsWith('commands::')) return { tier: 'native', handler };
	if (handler.includes('native_m1_')) return { tier: 'native', handler };
	if (handler.includes('native_skills')) return { tier: 'partial', handler: 'native_skills' };
	if (handler.includes('providers()')) return { tier: 'static', handler: 'providers' };
	if (handler.includes('languages()')) return { tier: 'static', handler: 'languages' };
	return { tier: 'unknown', handler };
}

const node = nodeCommands();
const dispatched = nodeDispatched();
const rust = rustCommands();
const dispatch = rustDispatchMap();
const union = [...new Set([...node, ...rust])].sort();
const characterized = new Set(FIXTURES.map((fixture) => fixture.command));

const rows = union.map((command) => {
	const inNode = node.includes(command);
	const inRust = rust.includes(command);
	const nodeDispatches = dispatched.includes(command);
	const rustInfo = dispatch[command] ? classifyRust(dispatch[command]) : null;
	let gap = 'none';
	if (inNode && !nodeDispatches) gap = 'node-help-only';
	else if (inNode && inRust && rustInfo?.tier === 'stub') gap = 'rust-stub';
	else if (inNode && inRust && ['partial', 'divergent'].includes(rustInfo?.tier)) gap = `rust-${rustInfo.tier}`;
	else if (!inNode && inRust) gap = 'rust-only';
	else if (inNode && !inRust) gap = 'node-only';
	return {
		command,
		node: inNode,
		nodeDispatched: nodeDispatches,
		nodeImpl: inNode ? `src/lib/cli/commands/${command}.mjs` : null,
		rust: inRust,
		rustHandler: dispatch[command] ?? null,
		rustTier: rustInfo?.tier ?? null,
		gap,
	};
});

const inventory = {
	schemaVersion: 1,
	kind: 'legion-native-cli-behavior-inventory',
	generatedAt: new Date().toISOString(),
	counts: {
		nodeHelp: node.length,
		nodeDispatched: dispatched.length,
		rust: rust.length,
		union: union.length,
		rustStubs: rows.filter((r) => r.rustTier === 'stub').length,
		rustPartial: rows.filter((r) => r.rustTier === 'partial').length,
		characterizationFixtures: FIXTURES.length,
		characterizationCommands: union.filter((command) => characterized.has(command)).length,
		characterizationSubcommands: FIXTURES.filter((fixture) => fixture.subcommand).length,
		uncharacterizedNodeCommands: node.filter((command) => !characterized.has(command)).length,
	},
	invariants: {
		productCompositionSource:
			'legion.exe loads Legion assets only from installed/staged release root; cwd is the operated-on repository, never an alternate runtime source.',
		jsPermittedOnly: 'build, generation, lint, test harness — not Legion CLI semantics',
	},
	commands: rows,
};

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(OUT_JSON, `${JSON.stringify(inventory, null, 2)}\n`);

const md = [
	'# Native CLI behavior inventory',
	'',
	`Generated by \`node scripts/native-cli/inventory.mjs\`. Do not hand-edit.`,
	'',
	`| Metric | Count |`,
	`| --- | ---: |`,
	`| Node commands (help) | ${inventory.counts.nodeHelp} |`,
	`| Node dispatched | ${inventory.counts.nodeDispatched} |`,
	`| Rust commands | ${inventory.counts.rust} |`,
	`| Union target | ${inventory.counts.union} |`,
	`| Rust stubs | ${inventory.counts.rustStubs} |`,
	`| Rust partial | ${inventory.counts.rustPartial} |`,
	`| Characterization fixtures | ${inventory.counts.characterizationFixtures} |`,
	`| Characterized commands | ${inventory.counts.characterizationCommands} |`,
	`| Characterized subcommands | ${inventory.counts.characterizationSubcommands} |`,
	`| Node commands without fixture proof | ${inventory.counts.uncharacterizedNodeCommands} |`,
	'',
	'## Invariants',
	'',
	`- **Product composition:** ${inventory.invariants.productCompositionSource}`,
	`- **JavaScript permitted for:** ${inventory.invariants.jsPermittedOnly}`,
	'',
	'## Command matrix',
	'',
	`| Command | Node | Dispatched | Rust | Rust tier | Gap |`,
	`| --- | --- | --- | --- | --- | --- |`,
	...rows.map(
		(r) =>
			`| \`${r.command}\` | ${r.node ? 'yes' : 'no'} | ${r.nodeDispatched ? 'yes' : 'no'} | ${r.rust ? 'yes' : 'no'} | ${r.rustTier ?? '—'} | ${r.gap} |`,
	),
	'',
	`Uncharacterized Node commands: ${node.filter((command) => !characterized.has(command)).map((command) => `\`${command}\``).join(', ') || 'none'}.`,
	'',
].join('\n');

mkdirSync(dirname(OUT_MD), { recursive: true });
writeFileSync(OUT_MD, md);

console.log(JSON.stringify({ ok: true, outJson: OUT_JSON, outMd: OUT_MD, counts: inventory.counts }, null, 2));
