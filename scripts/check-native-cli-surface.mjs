#!/usr/bin/env node
/**
 * Step 7 — hard gate: JavaScript may build/generate/lint/test-harness only.
 * Fails on Node Legion CLI entrypoints, semantic command handlers, and product tests
 * that invoke src/bin/legion.mjs once cutover phase allows.
 */
import { readFileSync, readdirSync, lstatSync } from 'node:fs';
import { dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PHASE = process.argv.includes('--phase=enforce') ? 'enforce' : 'record';

const FORBIDDEN_RUNTIME_PATHS = [
	'src/bin/legion.mjs',
	'src/lib/cli/run.mjs',
];

const ALLOWED_JS_PREFIXES = [
	'scripts/',
	'tools/',
	'tests/native-cli-characterization/',
	'node_modules/',
];
const PRODUCT_CLI_TESTS = ['tests/bind.test.mjs'];
const NODE_RUNTIME_EXTENSIONS = new Set(['.cjs', '.js', '.mjs']);

const issues = [];

function present(path) {
	try { return lstatSync(path); }
	catch (error) {
		if (error.code === 'ENOENT') return null;
		throw error; // An unreadable path is not evidence of deletion.
	}
}

function walk(dir, visitor) {
	const directory = present(dir);
	if (!directory?.isDirectory() || directory.isSymbolicLink()) return;
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue;
		const path = resolve(dir, entry.name);
		if (entry.isDirectory()) walk(path, visitor);
		else visitor(path);
	}
}

function isNodeRuntimeFile(path) {
	const file = path.toLowerCase();
	return [...NODE_RUNTIME_EXTENSIONS].some((extension) => file.endsWith(extension)) && !file.endsWith('.test.mjs');
}

function nodeRuntimeFiles(root) {
	const files = [];
	for (const relativeRoot of ['src/bin', 'src/lib/cli']) {
		walk(resolve(root, relativeRoot), (path) => {
			if (isNodeRuntimeFile(path)) files.push(path);
		});
	}
	return files.sort();
}

const reportedRuntimeFiles = new Set();
function reportRuntimeFile(path) {
	const rel = relative(ROOT, path).replaceAll('\\', '/');
	if (reportedRuntimeFiles.has(rel)) return;
	reportedRuntimeFiles.add(rel);
	if (rel === 'src/bin/legion.mjs' || rel === 'src/lib/cli/run.mjs') {
		issues.push(`forbidden Node Legion entrypoint still present: ${rel}`);
	} else if (rel.startsWith('src/lib/cli/commands/') && !rel.slice('src/lib/cli/commands/'.length).includes('/')) {
		issues.push(`forbidden Node Legion command handler: ${rel}`);
	} else {
		issues.push(`forbidden Node Legion runtime file: ${rel}`);
	}
}

for (const rel of FORBIDDEN_RUNTIME_PATHS) {
	const path = resolve(ROOT, rel);
	if (present(path)) reportRuntimeFile(path);
}

const commandDirectory = present(resolve(ROOT, 'src/lib/cli/commands'));
if (commandDirectory?.isSymbolicLink()) issues.push('forbidden Node Legion command directory is a symlink');
for (const path of nodeRuntimeFiles(ROOT)) reportRuntimeFile(path);

walk(resolve(ROOT, 'tests'), (path) => {
	if (!path.endsWith('.test.mjs') && !path.endsWith('.mjs')) return;
	const text = readFileSync(path, 'utf8');
	if (
		text.includes('src/bin/legion.mjs') ||
		text.includes("from '../bin/legion.mjs'")
	) {
		const rel = relative(ROOT, path);
		issues.push(`product test still invokes Node CLI: ${rel}`);
	}
});

for (const rel of PRODUCT_CLI_TESTS) {
	const text = readFileSync(resolve(ROOT, rel), 'utf8');
	if (!text.includes("scripts/native-cli/test-helper.mjs")) {
		issues.push(`product CLI test must use native executable helper: ${rel}`);
	}
}

const pkg = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8'));
if (pkg.bin?.legion || pkg.bin?.['@orthic-labs/legion']) {
	issues.push('package.json must not register npm bin legion');
}

const contract = JSON.parse(readFileSync(resolve(ROOT, 'release/distribution-contract.json'), 'utf8'));
if (contract.nodePackage?.access !== 'private-development-tooling') {
	issues.push('distribution contract must label Node package as private-development-tooling (build/test tooling only)');
}

const summary = {
	schemaVersion: 1,
	kind: 'legion-native-cli-surface-check',
	phase: PHASE,
	ok: issues.length === 0,
	issues,
	note:
		PHASE === 'record'
			? 'record phase documents remaining Node runtime surface; pass --phase=enforce after cutover'
			: 'enforce phase fails on any remaining Node Legion runtime semantics',
};

console.log(JSON.stringify(summary, null, 2));
if (!summary.ok && PHASE === 'enforce') process.exit(1);
