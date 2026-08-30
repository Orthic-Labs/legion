#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REVISION = /^[a-f0-9]{40,64}$/i;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
function fail(message) { throw new Error(`windows-installed-qualification: ${message}`); }
function file(path, label) { if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) fail(`${label} is missing or unsafe: ${path}`); return path; }
function json(path, label) { try { return JSON.parse(readFileSync(file(path, label), "utf8")); } catch (error) { fail(`${label} is invalid JSON: ${error.message}`); } }
function sha256(path) { return createHash("sha256").update(readFileSync(file(path, "file"))).digest("hex"); }
function argument(name) { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; }
function required(value, label) { if (!value) fail(`${label} is required`); return value; }
function execute(commandRunner, executable, args, options, label) {
	const result = commandRunner(executable, args, { encoding: "utf8", windowsHide: true, ...options });
	if (result?.error || result?.status !== 0) fail(`${label} failed: ${String(result?.stderr ?? result?.error?.message ?? result?.stdout ?? "").trim()}`);
	return { stdout: String(result?.stdout ?? "").trim(), stderr: String(result?.stderr ?? "").trim() };
}
function finalization(path, version, sourceRevision) {
	const value = json(path, "Windows finalization manifest");
	if (value.schemaVersion !== 1 || value.kind !== "legion-installer-finalization" || value.product !== "legion" || value.platform !== "windows" || value.version !== version || String(value.sourceRevision ?? "").toLowerCase() !== sourceRevision || !Array.isArray(value.assets)) fail("Windows finalization manifest identity is invalid");
	const installers = value.assets.filter((asset) => asset?.role === "installer");
	if (installers.length !== 1) fail("Windows finalization must contain exactly one installer");
	return value;
}
export function qualifyInstalledWindows({ setup, outputRoot, finalizationPath, sourceRevision, version, commandRunner = spawnSync, platform = process.platform, temporaryRoot = tmpdir() } = {}) {
	if (platform !== "win32") fail("qualification requires Windows");
	if (!VERSION.test(String(version ?? ""))) fail("stable version is required");
	if (!REVISION.test(String(sourceRevision ?? ""))) fail("source revision is invalid");
	const revision = sourceRevision.toLowerCase();
	const installer = resolve(required(setup, "--setup")); file(installer, "setup EXE");
	if (!installer.toLowerCase().endsWith(".exe")) fail("setup must be an EXE");
	const output = resolve(required(outputRoot, "--output-root")); mkdirSync(output, { recursive: true });
	if (existsSync(join(output, "qualification.json"))) fail("qualification evidence already exists");
	const finalizationFile = resolve(required(finalizationPath, "--finalization")); finalization(finalizationFile, version, revision);
	const finalizationSha256 = sha256(finalizationFile);
	const workspace = mkdtempSync(join(resolve(temporaryRoot), "legion-installed-qualification-"));
	const installRoot = join(workspace, "Legion");
	try {
		execute(commandRunner, installer, ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", `/DIR=${installRoot}`], { cwd: workspace }, "silent setup");
		const executable = join(installRoot, "current", "bin", "legion.exe");
		file(executable, "installed legion.exe");
		const versionRun = execute(commandRunner, executable, ["--version"], { cwd: installRoot }, "installed legion --version");
		const doctorRun = execute(commandRunner, executable, ["doctor"], { cwd: installRoot }, "installed legion doctor");
		const uninstaller = join(installRoot, "unins000.exe");
		file(uninstaller, "installed uninstaller");
		execute(commandRunner, uninstaller, ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], { cwd: workspace }, "silent uninstall");
		if (existsSync(installRoot)) fail("silent uninstall left installed product behind");
		const evidencePath = join(output, "qualification.json");
		const evidence = { schemaVersion: 1, kind: "legion-windows-installed-installer-qualification", status: "qualified", product: "legion", version, sourceRevision: revision, windowsFinalizationSha256: finalizationSha256, setup: { name: installer.split(/[\\/]/).at(-1), sha256: sha256(installer), size: statSync(installer).size }, commands: { version: versionRun, doctor: doctorRun, uninstall: "removed" } };
		writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
		return { ...evidence, evidence: { path: evidencePath, role: "qualification", size: statSync(evidencePath).size, sha256: sha256(evidencePath) } };
	} finally { rmSync(workspace, { recursive: true, force: true }); }
}
if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
	try { process.stdout.write(`${JSON.stringify(qualifyInstalledWindows({ setup: argument("--setup"), outputRoot: argument("--output-root"), finalizationPath: argument("--finalization"), sourceRevision: argument("--source-revision"), version: argument("--version") }))}\n`); }
	catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
