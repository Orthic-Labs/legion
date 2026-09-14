#!/usr/bin/env node
/**
 * Step 5 — run characterization corpus against native legion.exe (dev build or installed).
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE_INDEX = resolve(ROOT, 'tests', 'native-cli-characterization', 'fixtures.json');
const OUT_DIR = resolve(ROOT, 'dist', 'native-cli', 'rust-characterization');

function resolveExe() {
	if (process.env.LEGION_EXE && existsSync(process.env.LEGION_EXE)) {
		return process.env.LEGION_EXE;
	}
	const built = resolve(
		ROOT,
		'dist',
		'native',
		'windows-x86_64',
		`legion-${readVersion()}`,
		'bin',
		'legion.exe',
	);
	if (existsSync(built)) return built;
	const local = process.env.LOCALAPPDATA;
	if (local) {
		const installed = resolve(local, 'Orthic Labs', 'Legion', 'current', 'bin', 'legion.exe');
		if (existsSync(installed)) return installed;
	}
	return null;
}

function readVersion() {
	const version = JSON.parse(
		readFileSync(resolve(ROOT, 'release', 'version.json'), 'utf8'),
	);
	return version.version;
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
	const executable = resolveExe();
	if (!executable) {
		console.error(
			JSON.stringify({
				ok: false,
				error: 'legion.exe not found; set LEGION_EXE or run release:build:win:unsigned',
			}),
		);
		process.exit(1);
	}
	const index = JSON.parse(readFileSync(FIXTURE_INDEX, 'utf8'));
	mkdirSync(OUT_DIR, { recursive: true });
	const results = [];
	for (const fixture of index.fixtures) {
		if (fixture.rust === false) continue;
		const cwd = resolve(ROOT, fixture.cwd ?? '.');
		const observation = runExe(executable, fixture.argv, { cwd, env: fixture.env ?? {} });
		const record = {
			id: fixture.id,
			executable,
			exitCode: observation.exitCode,
			stdoutSha256: sha256(observation.stdout),
			stderrSha256: sha256(observation.stderr),
			stdout: observation.stdout,
			stderr: observation.stderr,
			mismatch: null,
		};
		const expect = fixture.rustExpect ?? fixture.expect ?? {};
		const captureOnly = fixture.captureOnly || fixture.rustExpect?.captureOnly;
		if (!captureOnly && expect.exitCode !== undefined) {
			if (record.exitCode !== expect.exitCode) {
				record.mismatch = `expected exit ${expect.exitCode}, got ${record.exitCode}`;
			}
		}
		if (!captureOnly && expect.kind) {
			try {
				const json = JSON.parse(record.stdout);
				if (json.kind !== expect.kind) {
					record.mismatch = `expected kind ${expect.kind}, got ${json.kind}`;
				}
			} catch {
				record.mismatch = 'stdout is not JSON';
			}
		}
		if (!captureOnly && expect.stdoutIncludes) {
			for (const needle of expect.stdoutIncludes) {
				if (!record.stdout.includes(needle)) record.mismatch = `stdout missing: ${needle}`;
			}
		}
		if (!captureOnly && expect.stderrIncludes) {
			for (const needle of expect.stderrIncludes) {
				if (!record.stderr.includes(needle)) record.mismatch = `stderr missing: ${needle}`;
			}
		}
		writeFileSync(resolve(OUT_DIR, `${fixture.id}.json`), `${JSON.stringify(record, null, 2)}\n`);
		results.push({ id: fixture.id, exitCode: record.exitCode, mismatch: record.mismatch });
	}
	const summary = {
		schemaVersion: 1,
		kind: 'legion-rust-characterization',
		generatedAt: new Date().toISOString(),
		executable,
		total: results.length,
		failed: results.filter((item) => item.mismatch).length,
		results,
	};
	writeFileSync(resolve(OUT_DIR, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
	console.log(JSON.stringify(summary, null, 2));
	if (summary.failed) process.exit(1);
}

main();
