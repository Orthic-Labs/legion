#!/usr/bin/env node
/**
 * Step 7 — hard gate: JavaScript may build/generate/lint/test-harness only.
 * Fails on Node Legion CLI entrypoints, semantic command handlers, and product tests
 * that invoke src/bin/legion.mjs once cutover phase allows.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
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
const PRODUCT_CLI_TESTS = ['tests/cli.test.mjs', 'tests/doctor.test.mjs', 'tests/bind.test.mjs'];

const issues = [];

function walk(dir, visitor) {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue;
		const path = resolve(dir, entry.name);
		if (entry.isDirectory()) walk(path, visitor);
		else visitor(path);
	}
}

for (const rel of FORBIDDEN_RUNTIME_PATHS) {
	const path = resolve(ROOT, rel);
	try {
		statSync(path);
		if (PHASE === 'enforce') issues.push(`forbidden Node Legion entrypoint still present: ${rel}`);
	} catch {
		// deleted — good for enforce phase
	}
}

if (statSync(resolve(ROOT, 'src/lib/cli/commands')).isDirectory()) {
	for (const entry of readdirSync(resolve(ROOT, 'src/lib/cli/commands'), { withFileTypes: true })) {
		if (!entry.isFile() || !entry.name.endsWith('.mjs')) continue;
		const rel = relative(ROOT, resolve(ROOT, 'src/lib/cli/commands', entry.name));
		if (PHASE === 'enforce') issues.push(`forbidden Node Legion command handler: ${rel}`);
	}
}

walk(resolve(ROOT, 'tests'), (path) => {
	if (!path.endsWith('.test.mjs') && !path.endsWith('.mjs')) return;
	const text = readFileSync(path, 'utf8');
	if (
		text.includes('src/bin/legion.mjs') ||
		text.includes("from '../bin/legion.mjs'")
	) {
		const rel = relative(ROOT, path);
		if (PHASE === 'enforce') issues.push(`product test still invokes Node CLI: ${rel}`);
	}
});

for (const rel of PRODUCT_CLI_TESTS) {
	const text = readFileSync(resolve(ROOT, rel), 'utf8');
	if (!text.includes("scripts/native-cli/test-helper.mjs")) {
		if (PHASE === 'enforce') issues.push(`product CLI test must use native executable helper: ${rel}`);
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
