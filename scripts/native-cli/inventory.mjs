#!/usr/bin/env node
/** Freeze the Node/Rust CLI command and nested-route inventory. */
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventoryClosure } from './gate.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT_DIR = resolve(ROOT, 'dist', 'native-cli');
const OUT_JSON = resolve(OUT_DIR, 'behavior-inventory.json');
const OUT_MD = resolve(ROOT, 'docs', 'plans', 'native-cli-behavior-inventory.md');
const kebab = (value) => value.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();

export function nodeCommands(source) {
  const match = source.match(/COMMANDS = Object\.freeze\(\[([^\]]+)\]/);
  if (!match) throw new Error('cannot parse Node COMMANDS from help.mjs');
  return [...match[1].matchAll(/'([^']+)'/g)].map((match) => match[1]);
}

export function nodeDispatchRoutes(source) {
  const routes = [];
  const blocks = /case\s+'([^']+)'\s*:\s*([\s\S]*?)(?=\n\s*case\s+'|\n\s*default\s*:)/g;
  for (const match of source.matchAll(blocks)) {
    const imported = match[2].match(/import\(['"]([^'"]+)['"]\)/);
    const handler = match[2].match(/const\s*\{\s*(\w+)/)?.[1] ?? null;
    routes.push({ command: match[1], source: imported?.[1] ?? null, handler });
  }
  return routes.sort((a, b) => a.command.localeCompare(b.command));
}

function nestedValues(source, variable) {
  const values = new Set();
  const expression = new RegExp(`\\b${variable}\\s*(?:===|!==)\\s*['"]([^'"]+)['"]`, 'g');
  for (const match of source.matchAll(expression)) if (!['help', '--help'].includes(match[1])) values.add(match[1]);
  return values;
}

/** Return route keys such as `run.open` and `host.events.inspect`. */
export function nodeNestedRoutes(sources, dispatchRoutes) {
  const routes = [];
  for (const dispatch of dispatchRoutes) {
    const source = sources[dispatch.command] ?? '';
    const values = new Set([...nestedValues(source, 'sub'), ...nestedValues(source, 'domain')]);
    for (const match of source.matchAll(/\bargv\[0\]\s*===\s*['"]([^'"]+)['"]/g)) values.add(match[1]);
    const promoted = [];
    const promote = /\b(sub|domain)\s*===\s*['"]([^'"]+)['"][\s\S]{0,180}?\b\1\s*=\s*rest\.shift\(\)/g;
    for (const match of source.matchAll(promote)) promoted.push(match[2]);
    for (const parent of promoted) values.delete(parent);
    for (const value of values) {
      if (promoted.length && source.includes('rest.shift()') && value !== 'help') {
        for (const parent of promoted) routes.push({ route: `${dispatch.command}.${parent}.${value}`, command: dispatch.command, subcommand: `${parent}.${value}`, source: dispatch.source });
      } else routes.push({ route: `${dispatch.command}.${value}`, command: dispatch.command, subcommand: value, source: dispatch.source });
    }
  }
  return [...new Map(routes.map((route) => [route.route, route])).values()].sort((a, b) => a.route.localeCompare(b.route));
}

export function rustCommands(source) {
  const block = source.match(/enum Command \{([\s\S]*?)\n\}/);
  if (!block) throw new Error('cannot parse Rust Command enum');
  const names = [];
  for (const match of block[1].matchAll(/^\s+([A-Z][A-Za-z0-9]*)\(/gm)) if (!['M1ConfigArgs', 'ServeArgs'].includes(match[1])) names.push(kebab(match[1]));
  return names.sort();
}

export function rustDispatchMap(source) {
  const map = {};
  const dispatchBlock = source.match(/async fn dispatch\([\s\S]*?let result: CommandResult = match command \{([\s\S]*?)\n    \};/);
  if (!dispatchBlock) throw new Error('cannot parse Rust dispatch');
  for (const match of dispatchBlock[1].matchAll(/Command::([A-Za-z]+)\([^)]*\) => ([^\n,]+)/g)) map[kebab(match[1])] = match[2].trim();
  for (const match of dispatchBlock[1].matchAll(/Command::([A-Za-z]+)\([^)]*\) => \{([\s\S]*?)\n\s*\}(?=,?\n\s*Command::|$)/g)) {
    const handler = match[2].match(/(commands::[a-z_]+::run)/)?.[1];
    if (handler) map[kebab(match[1])] = handler;
  }
  return map;
}

function enumValues(source, name) {
  const block = source.match(new RegExp(`enum ${name} \\{([\\s\\S]*?)\\n\\}`));
  return block ? [...block[1].matchAll(/^\s+([A-Z][A-Za-z0-9]*)\(/gm)].map((match) => kebab(match[1])) : [];
}

/** Enumerate typed Rust nested enums, plus string-routed CommonArgs modules. */
export function rustNestedRoutes(source, moduleSources = {}, expectedRoutes = []) {
  const routes = [];
  const expected = new Set(expectedRoutes.map((route) => typeof route === 'string' ? route : route.route));
  const typed = { run: 'RunCommand', completion: 'CompletionCommand', host: 'HostCommand', state: 'StateCommand' };
  for (const [command, enumName] of Object.entries(typed)) for (const value of enumValues(source, enumName)) routes.push({ route: `${command}.${value}`, command, subcommand: value, source: `enum ${enumName}` });
  for (const value of enumValues(source, 'HostEventsCommand')) routes.push({ route: `host.events.${value}`, command: 'host', subcommand: `events.${value}`, source: 'enum HostEventsCommand' });
  for (const [command, moduleSource] of Object.entries(moduleSources)) {
    for (const match of moduleSource.matchAll(/Some\("([a-z][a-z-]*)"\)/g)) {
      const route = `${command}.${match[1]}`;
      if (match[1] !== 'help' && (!expected.size || expected.has(route))) routes.push({ route, command, subcommand: match[1], source: `commands/${command}.rs` });
    }
    if (command === 'authority' && expected.has('authority.proof.inspect')) routes.push({ route: 'authority.proof.inspect', command, subcommand: 'proof.inspect', source: 'commands/authority.rs' });
  }
  return [...new Map(routes.map((route) => [route.route, route])).values()].sort((a, b) => a.route.localeCompare(b.route));
}

export function routeMismatches(nodeRoutes, rustRoutes) {
  const rust = new Set(rustRoutes.map((route) => typeof route === 'string' ? route : route.route));
  return nodeRoutes.map((route) => typeof route === 'string' ? route : route.route).filter((route, index, all) => !rust.has(route) && all.indexOf(route) === index).sort();
}

function allRustModuleSources() {
  const sources = {};
  for (const entry of readdirSync(resolve(ROOT, 'engine/bins/legion/src/commands'), { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.rs')) sources[entry.name.slice(0, -3).replaceAll('_', '-')] = readFileSync(resolve(ROOT, 'engine/bins/legion/src/commands', entry.name), 'utf8');
  }
  return sources;
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
  if (handler.startsWith('commands::')) return { tier: 'native', handler };
  if (handler.includes('native_m1_')) return { tier: 'native', handler };
  if (handler.includes('providers()')) return { tier: 'static', handler: 'providers' };
  if (handler.includes('languages()')) return { tier: 'static', handler: 'languages' };
  return { tier: 'unknown', handler };
}

function main() {
  const frozenNode = JSON.parse(readFileSync(resolve(ROOT, 'tests/native-cli-characterization/node-surface.json'), 'utf8'));
  if (frozenNode.schemaVersion !== 1 || frozenNode.kind !== 'legion-frozen-node-cli-surface') throw new Error('frozen Node CLI surface is invalid');
  const rustCli = readFileSync(resolve(ROOT, 'engine/bins/legion/src/cli.rs'), 'utf8');
  const fixtures = JSON.parse(readFileSync(resolve(ROOT, 'tests/native-cli-characterization/fixtures.json'), 'utf8')).fixtures;
  const node = frozenNode.commands, dispatchedRoutes = frozenNode.dispatchRoutes, dispatched = dispatchedRoutes.map((route) => route.command);
  const nestedNode = frozenNode.nestedRoutes;
  const rust = rustCommands(rustCli), dispatch = rustDispatchMap(rustCli), nestedRust = rustNestedRoutes(rustCli, allRustModuleSources(), nestedNode);
  const nestedRouteMismatches = routeMismatches(nestedNode, nestedRust), union = [...new Set([...node, ...rust])].sort(), characterized = new Set(fixtures.map((fixture) => fixture.command));
  const rows = union.map((command) => {
    const inNode = node.includes(command), inRust = rust.includes(command), nodeDispatches = dispatched.includes(command), rustInfo = dispatch[command] ? classifyRust(dispatch[command]) : null;
    let gap = 'none';
    if (inNode && !nodeDispatches) gap = 'node-help-only';
    else if (inNode && inRust && rustInfo?.tier === 'stub') gap = 'rust-stub';
    else if (inNode && inRust && ['partial', 'divergent'].includes(rustInfo?.tier)) gap = `rust-${rustInfo.tier}`;
    else if (inNode && inRust && rustInfo?.tier === 'unknown') gap = 'rust-unknown';
    else if (!inNode && inRust) gap = 'rust-only';
    else if (inNode && !inRust) gap = 'node-only';
    return { command, node: inNode, nodeDispatched: nodeDispatches, nodeRoute: dispatchedRoutes.find((route) => route.command === command)?.source ?? null, rust: inRust, rustHandler: dispatch[command] ?? null, rustTier: rustInfo?.tier ?? null, gap };
  });
  const counts = { nodeHelp: node.length, nodeDispatched: dispatched.length, rust: rust.length, union: union.length, nodeRuntimeRoutes: dispatchedRoutes.length, nestedNodeRoutes: nestedNode.length, nestedRustRoutes: nestedRust.length, nestedRouteMismatches: nestedRouteMismatches.length, rustStubs: rows.filter((row) => row.rustTier === 'stub').length, rustPartial: rows.filter((row) => row.rustTier === 'partial').length, rustDivergent: rows.filter((row) => row.rustTier === 'divergent').length, rustUnknown: rows.filter((row) => row.rustTier === 'unknown').length, characterizationFixtures: fixtures.length, characterizationCommands: union.filter((command) => characterized.has(command)).length, characterizationSubcommands: fixtures.filter((fixture) => fixture.subcommand).length, uncharacterizedNodeCommands: node.filter((command) => !characterized.has(command)).length };
  const inventory = { schemaVersion: 1, kind: 'legion-native-cli-behavior-inventory', generatedAt: new Date().toISOString(), counts, invariants: { productCompositionSource: 'legion.exe loads Legion assets only from installed/staged release root; cwd is the operated-on repository, never an alternate runtime source.', jsPermittedOnly: 'build, generation, lint, test harness — not Legion CLI semantics' }, commands: rows, routes: { node: nestedNode, rust: nestedRust, mismatches: nestedRouteMismatches } };
  inventory.closure = inventoryClosure(counts);
  if (nestedRouteMismatches.length) { inventory.closure.ok = false; inventory.closure.blockers.nestedRouteMismatches = nestedRouteMismatches.length; }
  mkdirSync(OUT_DIR, { recursive: true }); writeFileSync(OUT_JSON, `${JSON.stringify(inventory, null, 2)}\n`);
  const md = ['# Native CLI behavior inventory', '', 'Generated by `node scripts/native-cli/inventory.mjs`. Do not hand-edit.', '', '| Metric | Count |', '| --- | ---: |', ...Object.entries(counts).map(([key, value]) => `| ${key} | ${value} |`), '', '## Nested routes', '', `Node routes: ${nestedNode.map((route) => `\`${route.route}\``).join(', ') || 'none'}.`, '', `Rust routes: ${nestedRust.map((route) => `\`${route.route}\``).join(', ') || 'none'}.`, '', `Route mismatches: ${nestedRouteMismatches.map((route) => `\`${route}\``).join(', ') || 'none'}.`, '', '## Command matrix', '', '| Command | Node | Dispatched | Rust | Rust tier | Gap |', '| --- | --- | --- | --- | --- | --- |', ...rows.map((row) => `| \`${row.command}\` | ${row.node ? 'yes' : 'no'} | ${row.nodeDispatched ? 'yes' : 'no'} | ${row.rust ? 'yes' : 'no'} | ${row.rustTier ?? '—'} | ${row.gap} |`), '', `Uncharacterized Node commands: ${node.filter((command) => !characterized.has(command)).map((command) => `\`${command}\``).join(', ') || 'none'}.`, ''].join('\n');
  mkdirSync(dirname(OUT_MD), { recursive: true }); writeFileSync(OUT_MD, md);
  console.log(JSON.stringify({ ok: inventory.closure.ok, outJson: OUT_JSON, outMd: OUT_MD, counts, blockers: inventory.closure.blockers }, null, 2));
  if (!inventory.closure.ok) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
