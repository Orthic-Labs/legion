#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { commandDiagnostic, releaseSpawnOptions } from "../process-boundary.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = join(HERE, "finalize-installer.mjs");
const SHA = /^[a-f0-9]{64}$/i;
const REVISION = /^[a-f0-9]{40,64}$/i;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const ARCHITECTURES = new Set(["x86_64", "arm64"]);

function fail(message) { throw new Error(`windows-finalize-adapter: ${message}`); }
function file(path, label) {
	if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) fail(`${label} is missing or unsafe: ${path}`);
	return path;
}
function directory(path, label) {
	if (!existsSync(path) || !lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink()) fail(`${label} is missing or unsafe: ${path}`);
	return path;
}
function below(root, path, label) {
	const rel = relative(resolve(root), resolve(path));
	if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) fail(`${label} escapes root`);
	return resolve(path);
}
function sha256(path) { return createHash("sha256").update(readFileSync(file(path, "file"))).digest("hex"); }
function record(path, role) { return { path: resolve(path), role, size: statSync(path).size, sha256: sha256(path) }; }
function argument(name) { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; }
function required(value, label) { if (!value) fail(`${label} is required`); return value; }
function runJson(runner, command, args, options, label) {
	const result = runner(command, args, releaseSpawnOptions(options));
	if (result?.error || result?.status !== 0) fail(`${label} failed: ${commandDiagnostic(result)}`);
	try { return JSON.parse(String(result.stdout ?? "").trim()); } catch { fail(`${label} did not emit JSON`); }
}
function portableEvidence(root, extension) {
	directory(root, "portable root");
	const entries = readdirSync(root, { withFileTypes: true });
	if (entries.some((entry) => !entry.isFile() || entry.isSymbolicLink())) fail("portable root contains unsafe nested entry");
	const one = (suffix, label) => {
		const matches = entries.filter((entry) => entry.name.endsWith(suffix));
		if (matches.length !== 1) fail(`portable root must contain exactly one ${label}`);
		return file(join(root, matches[0].name), label);
	};
	return { archive: one(extension, "portable archive"), sbom: one(".cdx.json", "SBOM"), provenance: one(".intoto.jsonl", "provenance") };
}
function extract({ archive, destination, commandRunner }) {
	mkdirSync(destination, { recursive: true });
	const result = commandRunner("tar", ["-xf", archive, "-C", destination], releaseSpawnOptions());
	if (result?.error || result?.status !== 0) fail(`portable extraction failed: ${commandDiagnostic(result)}`);
	directory(destination, "extracted portable payload");
	for (const name of ["bin", "plugin", "share"]) directory(join(destination, name), `extracted ${name}`);
	return destination;
}
function copyEvidence(input, output) {
	const root = join(output, "evidence"); mkdirSync(root, { recursive: true });
	const copy = (path) => { const target = join(root, basename(path)); copyFileSync(path, target); if (sha256(target) !== sha256(path)) fail(`portable evidence copy mismatch: ${basename(path)}`); return target; };
	return { archive: copy(input.archive), sbom: copy(input.sbom), provenance: copy(input.provenance) };
}

export function finalizeWindows({ portableRoot, outputRoot, sourceRevision, version, architecture, commandRunner = spawnSync, env = process.env } = {}) {
	if (!VERSION.test(String(version ?? ""))) fail("stable version is required");
	if (!REVISION.test(String(sourceRevision ?? ""))) fail("source revision is invalid");
	if (!ARCHITECTURES.has(architecture)) fail("architecture must be x86_64 or arm64");
	const portable = resolve(required(portableRoot, "--portable-root"));
	const output = resolve(required(outputRoot, "--output-root"));
	directory(portable, "portable root");
	mkdirSync(output, { recursive: true });
	if (readdirSync(output).length) fail("output root must be empty");
	const portableInput = portableEvidence(portable, ".zip");
	const evidence = copyEvidence(portableInput, output);
	const payload = extract({ archive: portableInput.archive, destination: join(output, ".payload"), commandRunner });
	const installerOutput = join(output, ".installer");
	const receipt = join(installerOutput, "installer-signing.json");
	const response = runJson(commandRunner, "node", [WORKER, "--input-root", payload, "--output", installerOutput, "--version", version, "--architecture", architecture, "--receipt", receipt], { cwd: resolve(HERE, "../../.."), env }, "Windows installer worker");
	if (response.status !== "signed" || !response.identity || response.identity.version !== version || response.identity.architecture !== architecture || !SHA.test(String(response.sha256 ?? "")) || !Number.isSafeInteger(response.sizeBytes)) fail("Windows installer worker response is invalid");
	const installer = below(installerOutput, response.installer, "installer");
	file(installer, "installer");
	if (sha256(installer) !== response.sha256.toLowerCase() || statSync(installer).size !== response.sizeBytes) fail("Windows installer worker digest mismatch");
	const signingReceipt = below(installerOutput, response.receipt, "signing receipt");
	file(signingReceipt, "signing receipt");
	const result = {
		schemaVersion: 1, kind: "legion-windows-installer-finalization", status: "finalized", product: "legion",
		version, sourceRevision: sourceRevision.toLowerCase(), architecture,
		assets: [record(installer, "installer")],
		evidence: [record(evidence.archive, "portable-archive"), record(evidence.sbom, "sbom"), record(evidence.provenance, "provenance"), record(signingReceipt, "installer-signing-receipt")],
	};
	return result;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
	try { process.stdout.write(`${JSON.stringify(finalizeWindows({ portableRoot: argument("--portable-root"), outputRoot: argument("--output-root"), sourceRevision: argument("--source-revision"), version: argument("--version"), architecture: argument("--architecture") }))}\n`); }
	catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
