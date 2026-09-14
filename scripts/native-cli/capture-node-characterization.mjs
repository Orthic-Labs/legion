#!/usr/bin/env node
/**
 * Step 2 — capture Node CLI black-box characterization before deletion.
 * Records stdout, stderr, exit code per fixture case.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE_INDEX = resolve(ROOT, 'tests', 'native-cli-characterization', 'fixtures.json');
const OUT_DIR = resolve(ROOT, 'dist', 'native-cli', 'node-characterization');

function sha256(text) {
	return createHash('sha256').update(text).digest('hex');
}

function runNode(argv, { cwd, env = {} }) {
	const result = spawnSync(process.execPath, [resolve(ROOT, 'src/bin/legion.mjs'), ...argv], {
		cwd,
		env: { ...process.env, ...env },
		encoding: 'utf8',
		maxBuffer: 8 * 1024 * 1024,
	});
	return {
		exitCode: result.status ?? 3,
		stdout: result.stdout ?? '',
		stderr: result.stderr ?? '',
		error: result.error?.message ?? null,
	};
}

function main() {
	const index = JSON.parse(readFileSync(FIXTURE_INDEX, 'utf8'));
	mkdirSync(OUT_DIR, { recursive: true });
	const captured = [];
	for (const fixture of index.fixtures) {
		const cwd = resolve(ROOT, fixture.cwd ?? '.');
		const observation = runNode(fixture.argv, { cwd, env: fixture.env ?? {} });
		const record = {
			id: fixture.id,
			command: fixture.command,
			argv: fixture.argv,
			cwd: fixture.cwd ?? '.',
			exitCode: observation.exitCode,
			stdoutSha256: sha256(observation.stdout),
			stderrSha256: sha256(observation.stderr),
			stdout: observation.stdout,
			stderr: observation.stderr,
			error: observation.error,
			expect: fixture.expect ?? {},
		};
		if (!fixture.captureOnly && fixture.expect?.exitCode !== undefined && record.exitCode !== fixture.expect.exitCode) {
			record.mismatch = `expected exit ${fixture.expect.exitCode}, got ${record.exitCode}`;
		}
		if (fixture.expect?.stdoutIncludes) {
			for (const needle of fixture.expect.stdoutIncludes) {
				if (!record.stdout.includes(needle)) record.mismatch = `stdout missing: ${needle}`;
			}
		}
		if (fixture.expect?.stderrIncludes) {
			for (const needle of fixture.expect.stderrIncludes) {
				if (!record.stderr.includes(needle)) record.mismatch = `stderr missing: ${needle}`;
			}
		}
		if (fixture.expect?.kind) {
			try {
				const json = JSON.parse(record.stdout);
				if (json.kind !== fixture.expect.kind) {
					record.mismatch = `expected kind ${fixture.expect.kind}, got ${json.kind}`;
				}
			} catch {
				record.mismatch = 'stdout is not JSON';
			}
		}
		const outPath = resolve(OUT_DIR, `${fixture.id}.json`);
		writeFileSync(outPath, `${JSON.stringify(record, null, 2)}\n`);
		captured.push({ id: fixture.id, exitCode: record.exitCode, mismatch: record.mismatch ?? null, path: outPath });
	}
	const summary = {
		schemaVersion: 1,
		kind: 'legion-node-characterization-capture',
		generatedAt: new Date().toISOString(),
		total: captured.length,
		failed: captured.filter((item) => item.mismatch).length,
		results: captured,
	};
	writeFileSync(resolve(OUT_DIR, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
	console.log(JSON.stringify(summary, null, 2));
	if (summary.failed) process.exit(1);
}

main();
