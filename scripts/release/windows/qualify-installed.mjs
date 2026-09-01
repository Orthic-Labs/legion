#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	commandDiagnostic,
	commandEvidence,
	INSTALLED_COMMAND_TIMEOUT_MS,
	releaseSpawnOptions,
} from "../process-boundary.mjs";

const REVISION = /^[a-f0-9]{40,64}$/i;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
function fail(message) { throw new Error(`windows-installed-qualification: ${message}`); }
function file(path, label) { if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) fail(`${label} is missing or unsafe: ${path}`); return path; }
function json(path, label) { try { return JSON.parse(readFileSync(file(path, label), "utf8")); } catch (error) { fail(`${label} is invalid JSON: ${error.message}`); } }
function sha256(path) { return createHash("sha256").update(readFileSync(file(path, "file"))).digest("hex"); }
function argument(name) { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; }
function required(value, label) { if (!value) fail(`${label} is required`); return value; }
function execute(commandRunner, executable, args, options, label) {
	const result = commandRunner(executable, args, releaseSpawnOptions(options, INSTALLED_COMMAND_TIMEOUT_MS));
	if (result?.error || result?.status !== 0) fail(`${label} failed: ${commandDiagnostic(result)}`);
	return {
		stdout: String(result?.stdout ?? "").trim(),
		stderr: String(result?.stderr ?? "").trim(),
		evidence: commandEvidence(result),
	};
}
function setupPayload(run, kind, executable, label) {
	let value;
	try { value = JSON.parse(run.stdout); }
	catch (error) { fail(`${label} did not return JSON: ${error.message}`); }
	if (value?.kind !== kind || value?.status !== "complete" || value?.origin !== "installed") fail(`${label} did not report complete installed activation`);
	if (resolve(String(value.executable ?? "")) !== resolve(executable) || value.stableCurrent !== true) fail(`${label} did not bind stable current executable`);
	const clients = kind === "legion-setup-execution" ? value.execution?.clients : value.clients;
	for (const clientId of ["claude-code", "codex"]) {
		const client = clients?.find((item) => (item?.clientId ?? item?.client_id) === clientId);
		if (!client?.installed || client?.fidelity !== "Full") fail(`${label} did not structurally activate ${clientId}`);
	}
	for (const projection of ["claudePlugin", "codexPlugin"]) {
		if (value.liveIdentity?.projections?.[projection]?.state !== "current") fail(`${label} did not verify current ${projection}`);
	}
	return {
		kind: value.kind,
		status: value.status,
		origin: value.origin,
		executable: value.executable,
		stableCurrent: value.stableCurrent,
		clients: clients.map((client) => ({ clientId: client.clientId ?? client.client_id, installed: client.installed, fidelity: client.fidelity })),
		projections: Object.fromEntries(Object.entries(value.liveIdentity?.projections ?? {}).map(([name, projection]) => [name, projection?.state ?? null])),
		authenticatedLiveQualification: value.authenticatedLiveQualification?.status ?? null,
	};
}
function disappears(path, timeoutMs = 3000) {
	const wake = new Int32Array(new SharedArrayBuffer(4));
	const deadline = Date.now() + timeoutMs;
	while (existsSync(path) && Date.now() < deadline) Atomics.wait(wake, 0, 0, 100);
	return !existsSync(path);
}
function finalization(path, version, sourceRevision) {
	const value = json(path, "Windows finalization manifest");
	if (value.schemaVersion !== 1 || value.kind !== "legion-installer-finalization" || value.product !== "legion" || value.platform !== "windows" || value.version !== version || String(value.sourceRevision ?? "").toLowerCase() !== sourceRevision || !Array.isArray(value.assets)) fail("Windows finalization manifest identity is invalid");
	const installers = value.assets.filter((asset) => asset?.role === "installer");
	if (installers.length !== 1) fail("Windows finalization must contain exactly one installer");
	return value;
}
// Installed-tree inventory captured before cleanup. Stable-pointer defects are
// invisible without link types and resolved targets, and the workspace that
// holds them is deleted by the finally block below.
function inventory(root, depth = 0) {
	if (!existsSync(root) || depth > 3) return [];
	let entries;
	try { entries = readdirSync(root, { withFileTypes: true }); } catch { return []; }
	return entries.map((entry) => {
		const path = join(root, entry.name);
		let link = null;
		let linkType = null;
		try {
			const stat = lstatSync(path);
			if (stat.isSymbolicLink()) { linkType = "link"; link = readlinkSync(path); }
		} catch { /* inventory is best-effort evidence, never a failure path */ }
		const record = { name: entry.name, kind: entry.isDirectory() ? "directory" : "file", linkType, target: link };
		if (entry.isDirectory()) record.children = inventory(path, depth + 1);
		return record;
	});
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
	const localAppData = join(workspace, "local-app-data");
	const installRoot = join(localAppData, "Orthic Labs", "Legion");
	const profile = join(workspace, "profile");
	for (const clientRoot of [".claude", ".codex"]) mkdirSync(join(profile, clientRoot), { recursive: true });
	const executable = join(installRoot, "current", "bin", "legion.exe");
	const environment = {
		...process.env,
		LOCALAPPDATA: localAppData,
		USERPROFILE: profile,
		PATH: `${join(installRoot, "current", "bin")}${delimiter}${process.env.PATH ?? ""}`,
	};
	const stages = [];
	let currentStage = "setup";
	const step = (stage, run) => { currentStage = stage; const result = run(); stages.push({ stage, ...result.evidence }); return result; };
	try {
		const installRun = step("install", () => execute(commandRunner, installer, ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", `/DIR=${installRoot}`], { cwd: workspace, env: environment }, "silent setup"));
		file(executable, "installed legion.exe");
		const versionRun = step("version", () => execute(commandRunner, executable, ["--version"], { cwd: installRoot, env: environment }, "installed legion --version"));
		const repairRun = step("repair", () => execute(commandRunner, executable, ["--json", "setup", "repair", "--confirm"], { cwd: installRoot, env: environment }, "installed legion setup repair"));
		const repair = setupPayload(repairRun, "legion-setup-execution", executable, "installed legion setup repair");
		const statusRun = step("status", () => execute(commandRunner, executable, ["--json", "setup", "status"], { cwd: installRoot, env: environment }, "installed legion setup status"));
		const status = setupPayload(statusRun, "legion-setup-status", executable, "installed legion setup status");
		const doctorRun = step("doctor", () => execute(commandRunner, executable, ["doctor"], { cwd: installRoot, env: environment }, "installed legion doctor"));
		const uninstaller = join(installRoot, "unins000.exe");
		file(uninstaller, "installed uninstaller");
		const uninstallRun = step("uninstall", () => execute(commandRunner, uninstaller, ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], { cwd: workspace, env: environment }, "silent uninstall"));
		if (!disappears(installRoot)) fail("silent uninstall left installed product behind");
		const evidencePath = join(output, "qualification.json");
		const evidence = { schemaVersion: 1, kind: "legion-windows-installed-installer-qualification", status: "qualified", product: "legion", version, sourceRevision: revision, windowsFinalizationSha256: finalizationSha256, setup: { name: installer.split(/[\\/]/).at(-1), sha256: sha256(installer), size: statSync(installer).size }, commands: { install: installRun.evidence, version: versionRun.evidence, repair: repairRun.evidence, status: statusRun.evidence, doctor: doctorRun.evidence, uninstall: uninstallRun.evidence }, activation: { repair, status } };
		writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
		return { ...evidence, evidence: { path: evidencePath, role: "qualification", size: statSync(evidencePath).size, sha256: sha256(evidencePath) } };
	} catch (error) {
		// Phase A item 9: a failed qualification must leave a readable receipt.
		// Previously the finally block deleted the workspace and the run produced
		// no diagnostic bundle at all, forcing signed-artifact re-download.
		try {
			const failurePath = join(output, "qualification-failure.json");
			const failure = {
				schemaVersion: 1,
				kind: "legion-windows-installed-installer-qualification-failure",
				status: "failed",
				product: "legion",
				version,
				sourceRevision: revision,
				failedStage: currentStage,
				error: String(error?.message ?? error),
				setup: { name: installer.split(/[\/]/).at(-1), sha256: sha256(installer), size: statSync(installer).size },
				completedStages: stages,
				installRoot,
				installTree: inventory(installRoot),
				recordedAt: new Date().toISOString(),
			};
			writeFileSync(failurePath, `${JSON.stringify(failure, null, 2)}
`);
		} catch { /* evidence is best-effort; never mask the original failure */ }
		throw error;
	} finally { rmSync(workspace, { recursive: true, force: true }); }
}
if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
	try { process.stdout.write(`${JSON.stringify(qualifyInstalledWindows({ setup: argument("--setup"), outputRoot: argument("--output-root"), finalizationPath: argument("--finalization"), sourceRevision: argument("--source-revision"), version: argument("--version") }))}\n`); }
	catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
