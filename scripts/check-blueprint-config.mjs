#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CONFIG_PATH = resolve(ROOT, '.agent', 'config.json');

const REQUIRED_IGNORED_PREFIXES = [
	'.agent/',
	'.audit/',
	'.cache/',
	'.workbuddy-ai/',
	'docs/product.md',
	'docs/architecture.md',
];

export function blueprintConfigReport(root = ROOT) {
	const path = resolve(root, '.agent', 'config.json');
	const issues = [];
	let config;
	try {
		const stat = statSync(path);
		if (!stat.isFile()) {
			issues.push({ path: '.agent/config.json', reason: 'blueprint config is not a regular file' });
			return { schemaVersion: 1, kind: 'legion-blueprint-config-report', status: 'fail', issues };
		}
		config = JSON.parse(readFileSync(path, 'utf8'));
	} catch (error) {
		issues.push({
			path: '.agent/config.json',
			reason: `blueprint config is missing or invalid: ${error?.message ?? error}`,
		});
		return { schemaVersion: 1, kind: 'legion-blueprint-config-report', status: 'fail', issues };
	}

	if (!Array.isArray(config.ignoredPrefixes)) {
		issues.push({ path: '.agent/config.json', reason: 'ignoredPrefixes must be an array' });
	} else {
		for (const prefix of REQUIRED_IGNORED_PREFIXES) {
			if (!config.ignoredPrefixes.includes(prefix)) {
				issues.push({
					path: '.agent/config.json',
					reason: `ignoredPrefixes must exclude ${prefix} from Blueprint indexing`,
				});
			}
		}
	}

	return {
		schemaVersion: 1,
		kind: 'legion-blueprint-config-report',
		status: issues.length ? 'fail' : 'pass',
		issues,
	};
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
	const report = blueprintConfigReport();
	if (process.argv.includes('--json')) {
		process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
	} else if (report.status === 'pass') {
		process.stdout.write('blueprint config: PASS\n');
	} else {
		for (const issue of report.issues) {
			process.stderr.write(`${issue.path}: ${issue.reason}\n`);
		}
	}
	process.exitCode = report.status === 'pass' ? 0 : 1;
}
