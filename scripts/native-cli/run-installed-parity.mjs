#!/usr/bin/env node
/**
 * Step 6 — run characterization corpus against installed legion.exe.
 * Requires LEGION_EXE or stable current install path.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import os from 'node:os';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE_INDEX = resolve(ROOT, 'tests', 'native-cli-characterization', 'fixtures.json');
const NODE_CAPTURE = resolve(ROOT, 'dist', 'native-cli', 'node-characterization');
const OUT_DIR = resolve(ROOT, 'dist', 'native-cli', 'installed-parity');

function defaultExe() {
	const local = process.env.LOCALAPPDATA;
	if (local) {
		const candidate = resolve(local, 'Orthic Labs', 'Legion', 'current', 'bin', 'legion.exe');
		if (existsSync(candidate)) return candidate;
	}
	return null;
}

function sha256(text) {
	return createHash('sha256').update(text).digest('hex');
}

function runExe(executable, argv, { cwd, env = {} }) {
	const result = spawnSync(executable, argv, {
		cwd,
		env: { ...process.env, ...env },
		encoding: 'utf8',
		maxBuffer: 8 * 1024 * 1024,
	});
	return {
		exitCode: result.status ?? 3,
		stdout: result.stdout ?? '',
		stderr: result.stderr ?? '',
	};
}

function main() {
	const executable = process.env.LEGION_EXE ?? defaultExe();
	if (!executable || !existsSync(executable)) {
		console.error(JSON.stringify({ ok: false, error: 'installed legion.exe not found; set LEGION_EXE' }));
		process.exit(1);
	}
	const index = JSON.parse(readFileSync(FIXTURE_INDEX, 'utf8'));
	mkdirSync(OUT_DIR, { recursive: true });
	const results = [];
	for (const fixture of index.fixtures) {
		const cwd = resolve(ROOT, fixture.cwd ?? '.');
		const observation = runExe(executable, fixture.argv, { cwd, env: fixture.env ?? {} });
		const nodeBaselinePath = resolve(NODE_CAPTURE, `${fixture.id}.json`);
		let nodeBaseline = null;
		if (existsSync(nodeBaselinePath)) {
			nodeBaseline = JSON.parse(readFileSync(nodeBaselinePath, 'utf8'));
		}
		const record = {
			id: fixture.id,
			executable,
			exitCode: observation.exitCode,
			stdoutSha256: sha256(observation.stdout),
			stderrSha256: sha256(observation.stderr),
			nodeExitCode: nodeBaseline?.exitCode ?? null,
			nodeStdoutSha256: nodeBaseline?.stdoutSha256 ?? null,
			mismatch: null,
		};
		if (nodeBaseline) {
			if (record.exitCode !== nodeBaseline.exitCode) {
				record.mismatch = `exit ${record.exitCode} != node ${nodeBaseline.exitCode}`;
			} else if (
				fixture.id !== 'doctor-json' &&
				fixture.id !== 'providers-json' &&
				fixture.id !== 'languages-json' &&
				record.stdoutSha256 !== nodeBaseline.stdoutSha256
			) {
				record.mismatch = 'stdout digest differs from Node baseline';
			}
		}
		results.push(record);
	}
	const summary = {
		schemaVersion: 1,
		kind: 'legion-installed-parity',
		generatedAt: new Date().toISOString(),
		executable,
		host: os.hostname(),
		total: results.length,
		failed: results.filter((item) => item.mismatch).length,
		skippedBaseline: results.filter((item) => item.nodeExitCode === null).length,
		results,
	};
	writeFileSync(resolve(OUT_DIR, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
	console.log(JSON.stringify(summary, null, 2));
	if (summary.failed) process.exit(1);
}

main();
