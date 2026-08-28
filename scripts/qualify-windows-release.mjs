#!/usr/bin/env node

/**
 * Qualify one Windows portable release without touching a developer machine.
 *
 * Production execution is deliberately native: archives are extracted with
 * Windows tar.exe and the three installed EXEs are invoked from an isolated
 * HOME/USERPROFILE. Tests can inject an archive extractor and command runner;
 * the lifecycle and receipt rules remain the same.
 */

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
	copyFileSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	realpathSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { delimiter, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { WINDOWS_ARCHITECTURES } from "../right-release.config.mjs";

const REQUIRED_BINARIES = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"];
const REQUIRED_GATES = [
	"installed-product",
	"command-resolution",
	"client-integration",
	"update",
	"rollback",
	"uninstall",
];
const NATIVE_ARCHITECTURES = Object.freeze({ x86_64: "x64", arm64: "arm64" });
const QUALIFICATION_SCHEMA_VERSION = 2;
const QUALIFICATION_MECHANISM = "agent-plugins-bare-command";
const QUALIFICATION_SERVER = "legion";
const QUALIFICATION_TOOL = "legion_m1_status";
const QUALIFICATION_MCP_ARGS = ["serve", "--stdio"];
const ARCHITECTURE_ALIASES = new Map([
	["x64", "x86_64"],
	["amd64", "x86_64"],
	["x86_64", "x86_64"],
	["windows-x86_64", "x86_64"],
	["arm64", "arm64"],
	["aarch64", "arm64"],
	["windows-arm64", "arm64"],
]);
const COMMAND_TIMEOUT_MS = 60_000;
const TOOL_OUTPUT_LIMIT = 4 * 1024 * 1024;
let runSequence = 0;

function sha256(bytes) {
	return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function bareDigest(value) {
	return String(value ?? "").replace(/^sha256:/i, "").toLowerCase();
}

function digestMatches(observed, expected) {
	return typeof observed === "string" && bareDigest(observed) === bareDigest(expected);
}

function normalizeArchitecture(value) {
	const normalized = ARCHITECTURE_ALIASES.get(String(value ?? "").trim().toLowerCase());
	if (!normalized || !WINDOWS_ARCHITECTURES[normalized]) {
		throw new Error(`unsupported Windows architecture: ${value}; expected x86_64 or arm64`);
	}
	return normalized;
}

function assertSourceRevision(value) {
	const revision = String(value ?? "").trim();
	if (!/^[0-9a-f]{7,64}$/i.test(revision)) {
		throw new Error(`source revision must be a hexadecimal Git revision: ${value ?? "<missing>"}`);
	}
	return revision.toLowerCase();
}

function assertVersion(value, label = "release version") {
	if (typeof value !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value)) {
		throw new Error(`invalid ${label}: ${value}`);
	}
	return value;
}

function targetIdentity(architecture) {
	const normalized = normalizeArchitecture(architecture);
	const configured = WINDOWS_ARCHITECTURES[normalized];
	return {
		platform: "windows",
		architecture: normalized,
		targetTriple: configured.targetTriple,
		wingetArchitecture: configured.wingetArchitecture,
		executable: "legion.exe",
		artifactId: configured.artifactId,
	};
}

export {
	normalizeArchitecture as normalizeWindowsArchitecture,
	targetIdentity as windowsTargetIdentity,
};

function isSameOrInside(root, candidate, { allowEqual = true, platform = process.platform } = {}) {
	const rootPath = resolve(root);
	const candidatePath = resolve(candidate);
	const rel = relative(rootPath, candidatePath);
	if (rel.includes("\0") || (!allowEqual && !rel)) return false;
	if (!rel) return allowEqual;
	if (rel === ".." || rel.startsWith(`..${sep}`) || /^[A-Za-z]:/.test(rel)) return false;
	return platform === "win32" ? !rel.startsWith("/") : true;
}

function assertInside(root, candidate, label, options = {}) {
	if (!isSameOrInside(root, candidate, options)) {
		throw new Error(`${label} escapes isolated root: ${candidate}`);
	}
	return resolve(candidate);
}

function assertRegularFile(path, label) {
	if (!existsSync(path)) throw new Error(`${label} is missing: ${path}`);
	const metadata = lstatSync(path);
	if (!metadata.isFile() || metadata.isSymbolicLink()) {
		throw new Error(`${label} is not a regular file: ${path}`);
	}
}

function assertDirectory(path, label, { create = false } = {}) {
	if (!existsSync(path)) {
		if (!create) throw new Error(`${label} is missing: ${path}`);
		mkdirSync(path, { recursive: true });
	}
	const metadata = lstatSync(path);
	if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
		throw new Error(`${label} is not a regular directory: ${path}`);
	}
}

function readJson(path, label) {
	assertRegularFile(path, label);
	try {
		return JSON.parse(requireUtf8(path));
	} catch (error) {
		throw new Error(`${label} is not valid JSON: ${path} (${error.message})`);
	}
}

function requireUtf8(path) {
	// Keep file access in one small seam so injected tests only need filesystem
	// fixtures and cannot accidentally turn a missing file into evidence.
	return readFileSync(path, "utf8");
}

function walkFiles(root, current = root, output = []) {
	const metadata = lstatSync(current);
	if (metadata.isSymbolicLink()) throw new Error(`symlink/reparse escape in extracted archive: ${current}`);
	let canonicalRoot;
	let canonical;
	try {
		canonicalRoot = realpathSync(root);
		canonical = realpathSync(current);
	} catch (error) {
		throw new Error(`cannot resolve extracted archive path ${current}: ${error.message}`);
	}
	if (!isSameOrInside(canonicalRoot, canonical, { platform: process.platform })) {
		throw new Error(`extracted archive path escapes isolated root: ${current}`);
	}
	if (metadata.isDirectory()) {
		for (const entry of readdirSync(current)) walkFiles(root, join(current, entry), output);
		return output;
	}
	if (!metadata.isFile()) throw new Error(`extracted archive path is not a regular file: ${current}`);
	output.push(relative(resolve(root), resolve(current)).split(sep).join("/"));
	return output.sort();
}

function assertExtractedTree(root, label = "extracted archive") {
	assertDirectory(root, label);
	// realpathSync catches directory junctions/reparse points even when lstat
	// reports them as directories; walkFiles also rejects ordinary symlinks.
	walkFiles(root);
}

function safeArchiveEntry(name) {
	const normalized = String(name ?? "").replaceAll("\\", "/");
	if (!normalized || normalized.includes("\0") || normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)) {
		return false;
	}
	const parts = normalized.split("/").filter(Boolean);
	return parts.length > 0 && !parts.includes("..") && !parts.includes(".");
}

function nativeTool(command, args, options = {}) {
	const result = spawnSync(command, args, {
		cwd: options.cwd,
		env: options.env,
		encoding: "utf8",
		windowsHide: true,
		timeout: options.timeout ?? COMMAND_TIMEOUT_MS,
		maxBuffer: TOOL_OUTPUT_LIMIT,
	});
	return {
		exitCode: Number.isInteger(result.status) ? result.status : null,
		stdout: typeof result.stdout === "string" ? result.stdout : "",
		stderr: typeof result.stderr === "string" ? result.stderr : "",
		error: result.error ? result.error.message : null,
		signal: result.signal ?? null,
	};
}

export function extractWithNativeWindowsTar(archivePath, destination) {
	const listing = nativeTool("tar.exe", ["-tf", archivePath], { cwd: dirname(archivePath) });
	if (listing.exitCode !== 0) {
		throw new Error(`Windows tar.exe could not list archive ${archivePath}: ${listing.error ?? listing.stderr}`);
	}
	for (const entry of listing.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)) {
		if (!safeArchiveEntry(entry)) throw new Error(`portable archive contains unsafe entry: ${entry}`);
	}
	const extraction = nativeTool("tar.exe", ["-xf", archivePath, "-C", destination], { cwd: destination });
	if (extraction.exitCode !== 0) {
		throw new Error(`Windows tar.exe could not extract archive ${archivePath}: ${extraction.error ?? extraction.stderr}`);
	}
}

function normalizeCommandResult(result) {
	if (!result || typeof result !== "object") {
		return { exitCode: null, stdout: "", stderr: "", error: "command runner returned no result", signal: null };
	}
	const rawExit = result.exitCode ?? result.status;
	const exitCode = rawExit == null || rawExit === "" ? null : Number(rawExit);
	return {
		exitCode: Number.isInteger(exitCode) ? exitCode : null,
		stdout: typeof result.stdout === "string" ? result.stdout : result.stdout == null ? "" : String(result.stdout),
		stderr: typeof result.stderr === "string" ? result.stderr : result.stderr == null ? "" : String(result.stderr),
		error: result.error ? String(result.error.message ?? result.error) : null,
		signal: result.signal ?? null,
	};
}

function invocationRecord(command, args, result) {
	const normalized = normalizeCommandResult(result);
	const stdout = normalized.stdout;
	const stderr = normalized.stderr;
	return {
		command,
		args: [...args],
		exitCode: normalized.exitCode,
		stdoutSha256: sha256(Buffer.from(stdout, "utf8")),
		stderrSha256: sha256(Buffer.from(stderr, "utf8")),
		outputSha256: sha256(Buffer.from(`${stdout}${stderr}`, "utf8")),
		stdout,
		stderr,
		...(normalized.error ? { error: normalized.error } : {}),
		...(normalized.signal ? { signal: normalized.signal } : {}),
	};
}

function commandSucceeded(invocation) {
	return invocation.exitCode === 0 && !invocation.error && !invocation.signal;
}

function parseJsonOutput(invocation) {
	if (!invocation.stdout.trim()) return null;
	try {
		return JSON.parse(invocation.stdout);
	} catch {
		return null;
	}
}

function exactCompleteJson(invocation, kind) {
	if (!commandSucceeded(invocation)) return null;
	const payload = parseJsonOutput(invocation);
	return payload
		&& typeof payload === "object"
		&& !Array.isArray(payload)
		&& payload.schemaVersion === 1
		&& payload.kind === kind
		&& payload.status === "complete"
		? payload
		: null;
}

function isHexDigest(value) {
	const digest = bareDigest(value);
	return /^[0-9a-f]{64}$/i.test(digest);
}

function canonicalPath(path) {
	try {
		return realpathSync(path);
	} catch {
		return resolve(path);
	}
}

function pathsEqual(left, right) {
	if (typeof left !== "string" || typeof right !== "string") return false;
	return canonicalPath(left).toLowerCase() === canonicalPath(right).toLowerCase();
}

function resolveCodexExecutable(pathValue, platform) {
	const pathSeparator = platform === "win32" ? ";" : delimiter;
	const names = platform === "win32" ? ["codex.exe", "codex.cmd", "codex.bat", "codex"] : ["codex"];
	for (const entry of String(pathValue ?? "").split(pathSeparator).filter(Boolean)) {
		for (const name of names) {
			const candidate = resolve(entry, name);
			try {
				const actual = realpathSync(candidate);
				const metadata = lstatSync(actual);
				if (metadata.isFile() && !metadata.isSymbolicLink()) return actual;
			} catch {
				// Continue searching each original PATH entry.
			}
		}
	}
	return null;
}

function commandEnvironment(workRoot, { codexExecutable = null, hostPath = "" } = {}) {
	const home = join(workRoot, "home");
	const codexRoot = join(home, ".codex");
	const local = join(home, "local");
	const roaming = join(home, "roaming");
	const data = join(home, "data");
	const state = join(home, "state", "Legion");
	const temp = join(home, "temp");
	for (const directory of [home, codexRoot, local, roaming, data, state, temp]) assertDirectory(directory, "isolated environment directory", { create: true });
	if (codexExecutable) assertRegularFile(codexExecutable, "Codex executable");
	const inherited = { ...process.env };
	delete inherited.LEGION_M1_CONFIG;
	delete inherited.LEGION_NATIVE_APPLICATION_CONFIG;
	const codexPath = codexExecutable ? dirname(codexExecutable) : null;
	return {
		home,
		codexRoot,
		state,
		codexExecutable,
		environment: {
			...inherited,
			HOME: home,
			USERPROFILE: home,
			CODEX_HOME: codexRoot,
			LOCALAPPDATA: local,
			APPDATA: roaming,
			XDG_DATA_HOME: data,
			LEGION_STATE_ROOT: state,
			TEMP: temp,
			TMP: temp,
			PATH: [codexPath, hostPath].filter(Boolean).join(";"),
		},
	};
}

function proofReleaseMatches(proof, current) {
	const release = proof?.release;
	return release
		&& typeof release === "object"
		&& !Array.isArray(release)
		&& release.releaseVersion === current.releaseVersion
		&& digestMatches(release.runtimeDigest, current.runtimeSha256);
}

function proofClientRecord(payload, execution = false) {
	const clients = execution ? payload?.execution?.clients : payload?.clients;
	if (!Array.isArray(clients)) return null;
	return clients.find((client) => client?.clientId === "codex") ?? null;
}

function proofRecordComplete(record) {
	return Boolean(
		record
		&& record.clientId === "codex"
		&& record.installed === true
		&& record.fidelity === "Full",
	);
}

function codexProjectionCurrent(payload) {
	return payload?.liveIdentity?.projections?.codexSkills?.state === "current";
}

function liveExecutableMatches(payload, installedLauncher, current, architecture) {
	const executable = payload?.liveIdentity?.executable;
	if (!executable || typeof executable !== "object" || Array.isArray(executable)) return false;
	const runtimePlatform = String(executable.runtimePlatform ?? "").toLowerCase();
	return executable.state === "current"
		&& pathsEqual(executable.path, installedLauncher)
		&& pathsEqual(executable.manifestPath, join(dirname(dirname(installedLauncher)), "share", "legion", "release.json"))
		&& executable.releaseVersion === current.releaseVersion
		&& executable.expectedReleaseVersion === current.releaseVersion
		&& digestMatches(executable.runtimeDigest, current.runtimeSha256)
		&& ["windows", "win32", "win"].includes(runtimePlatform)
		&& executable.runtimeArchitecture === architecture;
}

function proofRefsMatch(record, commandPath, qualificationPath) {
	if (!record) return false;
	return pathsEqual(record.commandProofRef, commandPath)
		&& pathsEqual(record.qualificationEvidenceRef, qualificationPath);
}

function validateLiveCodexProofs({ state, installedLauncher, codexExecutable, current }) {
	const qualificationRoot = join(state, "qualification");
	const commandPath = join(qualificationRoot, "codex-command.json");
	const qualificationPath = join(qualificationRoot, "codex-qualification.json");
	let command;
	let qualification;
	try {
		command = readJson(commandPath, "Codex command proof");
		qualification = readJson(qualificationPath, "Codex qualification proof");
	} catch (error) {
		return { valid: false, commandPath, qualificationPath, reason: error.message };
	}
	const installedDigest = sha256(readFileSync(installedLauncher));
	const codexDigest = sha256(readFileSync(codexExecutable));
	const commandValid = command.schemaVersion === QUALIFICATION_SCHEMA_VERSION
		&& command.kind === "legion-command-resolution-proof"
		&& command.clientId === "codex"
		&& command.mechanism === QUALIFICATION_MECHANISM
		&& proofReleaseMatches(command, current)
		&& pathsEqual(command.launcherPath, codexExecutable)
		&& digestMatches(command.launcherSha256, codexDigest)
		&& command.resolved === true
		&& command.exitCode === 0
		&& isHexDigest(command.outputSha256)
		&& command.legionCommand === "legion --version"
		&& command.legionResolved === true
		&& command.legionExitCode === 0
		&& pathsEqual(command.legionLauncherPath, installedLauncher)
		&& digestMatches(command.legionLauncherSha256, installedDigest)
		&& isHexDigest(command.legionOutputSha256)
		&& command.mcpCommand === QUALIFICATION_SERVER
		&& JSON.stringify(command.mcpArgs) === JSON.stringify(QUALIFICATION_MCP_ARGS);
	const qualificationValid = qualification.schemaVersion === QUALIFICATION_SCHEMA_VERSION
		&& qualification.kind === "legion-real-client-qualification"
		&& qualification.clientId === "codex"
		&& qualification.mechanism === QUALIFICATION_MECHANISM
		&& proofReleaseMatches(qualification, current)
		&& pathsEqual(qualification.launcherPath, codexExecutable)
		&& qualification.mcpServer === QUALIFICATION_SERVER
		&& qualification.mcpTool === QUALIFICATION_TOOL
		&& qualification.invocationStatus === "complete"
		&& qualification.observedReleaseVersion === current.releaseVersion
		&& Number.isInteger(qualification.capabilityCount)
		&& qualification.capabilityCount > 0
		&& Array.isArray(qualification.hostRequirements)
		&& Array.isArray(qualification.capabilities)
		&& qualification.capabilities.length === qualification.capabilityCount
		&& qualification.hostRequirements.every((value) => value && typeof value === "object" && !Array.isArray(value))
		&& qualification.capabilities.every((value) => value && typeof value === "object" && !Array.isArray(value))
		&& Number.isInteger(qualification.degradedCount)
		&& qualification.degradedCount >= 0
		&& qualification.degradedCount <= qualification.capabilityCount
		&& qualification.completed === true
		&& isHexDigest(qualification.outputSha256)
		&& pathsEqual(qualification.legionLauncherPath, installedLauncher)
		&& digestMatches(qualification.legionLauncherSha256, installedDigest)
		&& qualification.mcpCommand === QUALIFICATION_SERVER
		&& JSON.stringify(qualification.mcpArgs) === JSON.stringify(QUALIFICATION_MCP_ARGS);
	return {
		valid: commandValid && qualificationValid,
		commandPath,
		qualificationPath,
		command,
		qualification,
		reason: commandValid && qualificationValid ? null : "Codex command or completed M1 qualification proof is invalid",
	};
}

function releaseMetadata(root, architecture, label) {
	const releasePath = join(root, "share", "legion", "release.json");
	const metadata = readJson(releasePath, `${label} release identity`);
	const releaseVersion = assertVersion(metadata.releaseVersion, `${label} release version`);
	if (!metadata.runtime || typeof metadata.runtime !== "object") {
		throw new Error(`${label} release identity has no runtime object: ${releasePath}`);
	}
	const runtimePlatform = String(metadata.runtime.platform ?? "").toLowerCase();
	if (!["windows", "win32", "win"].includes(runtimePlatform)) {
		throw new Error(`${label} release identity platform is not Windows: ${metadata.runtime.platform}`);
	}
	if (metadata.runtime.architecture !== architecture) {
		throw new Error(`${label} release architecture mismatch: expected ${architecture}, got ${metadata.runtime.architecture}`);
	}
	const runtimePath = join(root, "bin", "legion.exe");
	assertRegularFile(runtimePath, `${label} runtime binary`);
	const runtimeSha256 = sha256(readFileSync(runtimePath));
	if (!digestMatches(metadata.runtime.sha256, runtimeSha256)) {
		throw new Error(`${label} runtime digest mismatch: ${metadata.runtime.sha256} != ${runtimeSha256}`);
	}
	return { metadata, releaseVersion, runtimeSha256, releasePath };
}

function validateProductRoot(root, architecture, label) {
	assertExtractedTree(root, label);
	for (const binary of REQUIRED_BINARIES) {
		assertRegularFile(join(root, "bin", binary), `${label} binary ${binary}`);
	}
	return releaseMetadata(root, architecture, label);
}

function copyTree(source, destination, workRoot) {
	assertInside(workRoot, source, "copy source", { platform: process.platform });
	assertInside(workRoot, destination, "copy destination", { platform: process.platform });
	assertExtractedTree(source, "copy source");
	if (existsSync(destination)) throw new Error(`copy destination already exists: ${destination}`);
	mkdirSync(destination, { recursive: true });
	for (const entry of readdirSync(source)) {
		const sourcePath = join(source, entry);
		const destinationPath = join(destination, entry);
		const metadata = lstatSync(sourcePath);
		if (metadata.isSymbolicLink() || !metadata.isFile() && !metadata.isDirectory()) {
			throw new Error(`cannot copy unsafe extracted path: ${sourcePath}`);
		}
		if (metadata.isDirectory()) copyTree(sourcePath, destinationPath, workRoot);
		else copyFileSync(sourcePath, destinationPath);
	}
}

function treeDigest(root) {
	const files = walkFiles(root).sort();
	const hash = createHash("sha256");
	for (const name of files) {
		hash.update(Buffer.from(name, "utf8"));
		hash.update(Buffer.from([0]));
		hash.update(readFileSync(join(root, ...name.split("/"))));
		hash.update(Buffer.from([0]));
	}
	return `sha256:${hash.digest("hex")}`;
}

function removeExact(path, workRoot, label) {
	assertInside(workRoot, path, label, { platform: process.platform });
	if (existsSync(path)) rmSync(path, { recursive: true, force: true });
}

function atomicReplaceProduct(source, productRoot, workRoot, { injectFailure = null } = {}) {
	const parent = dirname(productRoot);
	assertInside(workRoot, productRoot, "product root", { platform: process.platform });
	assertInside(workRoot, parent, "product parent", { platform: process.platform });
	mkdirSync(parent, { recursive: true });
	const suffix = `${process.pid}-${runSequence++}`;
	const stage = join(parent, `.legion-incoming-${suffix}`);
	const backup = join(parent, `.legion-backup-${suffix}`);
	let hadOriginal = false;
	let backupMoved = false;
	let committed = false;
	try {
		copyTree(source, stage, workRoot);
		if (existsSync(productRoot)) {
			assertExtractedTree(productRoot, "existing product root");
			renameSync(productRoot, backup);
			hadOriginal = true;
			backupMoved = true;
		}
		if (injectFailure) injectFailure({ phase: "after-backup", source, productRoot, stage, backup });
		renameSync(stage, productRoot);
		committed = true;
		if (hadOriginal) removeExact(backup, workRoot, "product backup");
		return { success: true, backupMoved, committed: true, rolledBack: false, stage, backup };
	} catch (error) {
		try {
			if (committed && existsSync(productRoot)) removeExact(productRoot, workRoot, "failed product replacement");
			if (hadOriginal && existsSync(backup) && !existsSync(productRoot)) renameSync(backup, productRoot);
			if (existsSync(stage)) removeExact(stage, workRoot, "failed product staging");
		} catch (restoreError) {
			throw new Error(`product replacement failed and rollback failed: ${error.message}; ${restoreError.message}`);
		}
		return {
			success: false,
			backupMoved,
			committed,
			rolledBack: hadOriginal && existsSync(productRoot),
			error: error.message,
			stage,
			backup,
		};
	}
}

function resolvePathCommand(productRoot, executable, platform, pathValue) {
	const expected = resolve(productRoot, "bin", executable);
	if (!existsSync(expected)) return null;
	const pathSeparator = platform === "win32" ? ";" : delimiter;
	const pathEntries = String(pathValue ?? "").split(pathSeparator).filter(Boolean);
	const matchingEntry = pathEntries.find((entry) => resolve(entry, executable).toLowerCase() === expected.toLowerCase());
	return matchingEntry ? expected : null;
}

function gate(name, status, details = {}) {
	return { name, status, ...details };
}

function unprovenGate(name, reason, details = {}) {
	return gate(name, "unproven", { reason, ...details });
}

function failedGate(name, reason, details = {}) {
	return gate(name, "fail", { reason, ...details });
}

function allGatesPass(gates) {
	return REQUIRED_GATES.every((name) => gates[name]?.status === "pass");
}

function writeReceipt(path, receipt) {
	const output = resolve(path);
	if (existsSync(output) && lstatSync(output).isDirectory()) throw new Error(`qualification receipt path is a directory: ${output}`);
	mkdirSync(dirname(output), { recursive: true });
	const temporary = `${output}.${process.pid}.tmp`;
	try {
		writeFileSync(temporary, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
		renameSync(temporary, output);
	} finally {
		if (existsSync(temporary)) rmSync(temporary, { force: true });
	}
	return output;
}

/**
 * Qualify a Windows portable archive.
 *
 * `archiveExtractor` receives `(archivePath, destination, context)` and may
 * be injected by tests. `commandRunner` receives `(command, args, options)`
 * and may return `{ exitCode, stdout, stderr }` (or child-process fields).
 */
export function qualifyWindowsRelease({
	currentZip: currentZipInput,
	currentArchive: currentArchiveInput = null,
	priorZip: priorZipInput = null,
	priorArchive: priorArchiveInput = null,
	previousZip = null,
	architecture: architectureInput,
	expectedArchitecture = null,
	sourceRevision: sourceRevisionInput,
	revision: revisionInput = null,
	output: outputInput,
	receiptPath: receiptPathInput = null,
	workRoot: workRootInput,
	isolatedRoot: isolatedRootInput = null,
	platform = process.platform,
	runnerArchitecture: runnerArchitectureInput = process.arch,
	processArchitecture = null,
	archiveExtractor = extractWithNativeWindowsTar,
	commandRunner = nativeTool,
	codexExecutable: codexExecutableInput = null,
	} = {}) {
	const currentZip = currentZipInput ?? currentArchiveInput;
	const priorZip = priorZipInput ?? priorArchiveInput ?? previousZip;
	const architecture = architectureInput ?? expectedArchitecture;
	const sourceRevision = sourceRevisionInput ?? revisionInput;
	const output = outputInput ?? receiptPathInput;
	const workRoot = workRootInput ?? isolatedRootInput;
	const runnerArchitecture = processArchitecture ?? runnerArchitectureInput;
	const hostPath = process.env.PATH ?? process.env.Path ?? "";
	const codexExecutable = codexExecutableInput
		? canonicalPath(resolve(codexExecutableInput))
		: resolveCodexExecutable(hostPath, platform);
	const simulated = archiveExtractor !== extractWithNativeWindowsTar
		|| commandRunner !== nativeTool;
	if (platform !== "win32") throw new Error(`Windows qualification requires a Windows host; observed ${platform}`);
	const normalizedArchitecture = normalizeArchitecture(architecture);
	const nativeArchitecture = NATIVE_ARCHITECTURES[normalizedArchitecture];
	if (runnerArchitecture !== nativeArchitecture) {
		throw new Error(`Windows qualification architecture mismatch: ${normalizedArchitecture} requires process.arch ${nativeArchitecture}, observed ${runnerArchitecture}`);
	}
	if (!currentZip) throw new Error("current Windows portable ZIP is required");
	if (!output) throw new Error("qualification output receipt is required");
	if (!workRoot) throw new Error("isolated work root is required");
	const revision = assertSourceRevision(sourceRevision);
	const identity = targetIdentity(normalizedArchitecture);
	const currentArchive = resolve(currentZip);
	const priorArchive = priorZip ? resolve(priorZip) : null;
	assertRegularFile(currentArchive, "current Windows portable ZIP");
	if (priorArchive) assertRegularFile(priorArchive, "prior Windows portable ZIP");
	if (!currentArchive.toLowerCase().endsWith(".zip")) throw new Error(`current archive must be a ZIP: ${currentArchive}`);
	if (priorArchive && !priorArchive.toLowerCase().endsWith(".zip")) throw new Error(`prior archive must be a ZIP: ${priorArchive}`);
	const isolatedRoot = resolve(workRoot);
	assertDirectory(isolatedRoot, "isolated work root", { create: true });
	const runRoot = join(isolatedRoot, `qualification-${process.pid}-${Date.now()}-${runSequence++}`);
	assertInside(isolatedRoot, runRoot, "qualification run root", { platform });
	mkdirSync(runRoot, { recursive: true });
	const currentRoot = join(runRoot, "current");
	const priorRoot = join(runRoot, "prior");
	const productRoot = join(runRoot, "product");
	const foreignMarker = join(runRoot, "foreign-marker.txt");
	const archiveSha256 = sha256(readFileSync(currentArchive));
	const priorArchiveSha256 = priorArchive ? sha256(readFileSync(priorArchive)) : null;

	const extraction = (archivePath, destination, label) => {
		assertInside(runRoot, destination, `${label} extraction root`, { platform });
		mkdirSync(destination, { recursive: true });
		if (readdirSync(destination).length > 0) throw new Error(`${label} extraction root is not empty: ${destination}`);
		archiveExtractor(archivePath, destination, { platform, runRoot, commandRunner });
		assertExtractedTree(destination, `${label} extracted archive`);
	};
	extraction(currentArchive, currentRoot, "current");
	const current = validateProductRoot(currentRoot, normalizedArchitecture, "current");
	let prior = null;
	if (priorArchive) {
		extraction(priorArchive, priorRoot, "prior");
		prior = validateProductRoot(priorRoot, normalizedArchitecture, "prior");
	}

	const env = commandEnvironment(runRoot, { codexExecutable, hostPath });
	const environment = {
		...env.environment,
		PATH: `${join(productRoot, "bin")};${env.environment.PATH ?? ""}`,
	};
	const runCommand = (command, args, options = {}) => {
		try {
			return invocationRecord(command, args, commandRunner(command, args, {
				cwd: options.cwd ?? productRoot,
				env: options.env ?? environment,
				timeout: COMMAND_TIMEOUT_MS,
				windowsHide: true,
			}));
		} catch (error) {
			return invocationRecord(command, args, { exitCode: null, error: error.message });
		}
	};

	const installCurrent = atomicReplaceProduct(currentRoot, productRoot, runRoot);
	const installedLauncher = join(productRoot, "bin", "legion.exe");
	const versionInvocation = runCommand(installedLauncher, ["--version"]);
	const versionMatches = versionInvocation.stdout.includes(current.releaseVersion) || versionInvocation.stderr.includes(current.releaseVersion);
	const repairArgs = ["--json", "setup", "repair", "--client", "codex", "--confirm"];
	const repairInvocation = runCommand(installedLauncher, repairArgs);
	const repairPayload = exactCompleteJson(repairInvocation, "legion-setup-execution");
	const statusArgs = ["--json", "setup", "status", "--client", "codex"];
	const statusInvocation = runCommand(installedLauncher, statusArgs);
	const statusPayload = exactCompleteJson(statusInvocation, "legion-setup-status");
	const qualificationProofs = codexExecutable
		? validateLiveCodexProofs({
			state: env.state,
			installedLauncher,
			codexExecutable,
			current,
		})
		: {
			valid: false,
			commandPath: join(env.state, "qualification", "codex-command.json"),
			qualificationPath: join(env.state, "qualification", "codex-qualification.json"),
			reason: "a real Codex executable was not resolved from the host PATH",
		};
	const repairClient = proofClientRecord(repairPayload, true);
	const statusClient = proofClientRecord(statusPayload);
	const setupComplete = Boolean(
		repairPayload
		&& statusPayload
		&& proofRecordComplete(repairClient)
		&& proofRecordComplete(statusClient)
		&& liveExecutableMatches(repairPayload, installedLauncher, current, normalizedArchitecture)
		&& liveExecutableMatches(statusPayload, installedLauncher, current, normalizedArchitecture)
		&& codexProjectionCurrent(repairPayload)
		&& codexProjectionCurrent(statusPayload)
		&& qualificationProofs.valid
		&& (proofRefsMatch(repairClient, qualificationProofs.commandPath, qualificationProofs.qualificationPath)
			|| proofRefsMatch(statusClient, qualificationProofs.commandPath, qualificationProofs.qualificationPath)),
	);
	const installedPass = Boolean(
		installCurrent.success
		&& commandSucceeded(versionInvocation)
		&& versionMatches
		&& setupComplete,
	);
	const gates = {
		"installed-product": installedPass
			? gate("installed-product", "pass", {
				productRoot,
				releaseVersion: current.releaseVersion,
				runtimeSha256: current.runtimeSha256,
				install: { success: installCurrent.success, atomicReplacement: installCurrent.committed },
				commands: [versionInvocation, repairInvocation, statusInvocation],
				codexExecutable,
				qualificationProofs: {
					commandPath: qualificationProofs.commandPath,
					qualificationPath: qualificationProofs.qualificationPath,
				},
			})
			: failedGate("installed-product", "installed binary lifecycle command failed or returned an unexpected release", {
				productRoot,
				commands: [versionInvocation, repairInvocation, statusInvocation],
				codexExecutable,
				setupComplete,
				qualificationProofs: {
					valid: qualificationProofs.valid,
					reason: qualificationProofs.reason,
				},
			}),
		"command-resolution": (() => {
			const resolved = resolvePathCommand(productRoot, "legion.exe", platform, environment.PATH);
			const invocation = runCommand("legion.exe", ["--version"], {
				env: { ...environment, PATH: `${join(productRoot, "bin")};${environment.PATH ?? ""}` },
			});
			return resolved && commandSucceeded(invocation) && (invocation.stdout.includes(current.releaseVersion) || invocation.stderr.includes(current.releaseVersion))
				? gate("command-resolution", "pass", { resolvedPath: resolved, command: invocation })
				: failedGate("command-resolution", "installed legion.exe was not resolved and executed from isolated PATH", { resolvedPath: resolved, command: invocation });
		})(),
		"client-integration": (() => {
			const projectionSuccess = setupComplete;
			return projectionSuccess
				? gate("client-integration", "pass", {
					client: "codex",
					repair: repairInvocation,
					setupStatus: statusInvocation,
					codexExecutable,
					qualificationProofs: {
						commandPath: qualificationProofs.commandPath,
						qualificationPath: qualificationProofs.qualificationPath,
					},
				})
				: failedGate("client-integration", "isolated Codex repair, status, projection, or live M1 evidence did not complete", {
					client: "codex",
					repair: repairInvocation,
					setupStatus: statusInvocation,
					codexExecutable,
					qualificationProofs: {
						valid: qualificationProofs.valid,
						reason: qualificationProofs.reason,
					},
				});
		})(),
	};

	let priorTreeSha256 = null;
	if (!prior) {
		gates.update = unprovenGate("update", "prior archive was not supplied; update cannot be proven");
		gates.rollback = unprovenGate("rollback", "prior archive was not supplied; rollback cannot be proven");
	} else {
		priorTreeSha256 = treeDigest(priorRoot);
		const archivesDiffer = !digestMatches(priorArchiveSha256, archiveSha256);
		const runtimesDiffer = !digestMatches(prior.runtimeSha256, current.runtimeSha256);
		const seedPrior = atomicReplaceProduct(priorRoot, productRoot, runRoot);
		const updateAttempt = atomicReplaceProduct(currentRoot, productRoot, runRoot);
		const updatedIdentity = releaseMetadata(productRoot, normalizedArchitecture, "updated product");
		const updatePass = seedPrior.success
			&& updateAttempt.success
			&& updatedIdentity.releaseVersion === current.releaseVersion
			&& digestMatches(updatedIdentity.runtimeSha256, current.runtimeSha256)
			&& updateAttempt.backupMoved
			&& archivesDiffer
			&& runtimesDiffer;
		gates.update = updatePass
			? gate("update", "pass", {
				from: prior.releaseVersion,
				to: current.releaseVersion,
				backupAndAtomicReplacement: true,
				archivesDiffer,
				runtimesDiffer,
				productRoot,
			})
			: failedGate("update", "backup plus atomic replacement must install different current archive and runtime bytes", {
				seedPrior,
				updateAttempt,
				archivesDiffer,
				runtimesDiffer,
				priorArchiveSha256,
				archiveSha256,
				priorRuntimeSha256: prior.runtimeSha256,
				runtimeSha256: current.runtimeSha256,
				productRoot,
			});

		const seedPriorForRollback = atomicReplaceProduct(priorRoot, productRoot, runRoot);
		const rollbackAttempt = atomicReplaceProduct(currentRoot, productRoot, runRoot, {
			injectFailure: ({ phase }) => {
				if (phase === "after-backup") throw new Error("injected qualification failure after backup rename");
			},
		});
		const restoredPrior = existsSync(productRoot) ? treeDigest(productRoot) : null;
		const rollbackPass = seedPriorForRollback.success
			&& !rollbackAttempt.success
			&& rollbackAttempt.rolledBack
			&& restoredPrior === priorTreeSha256
			&& archivesDiffer
			&& runtimesDiffer;
		gates.rollback = rollbackPass
			? gate("rollback", "pass", {
				injectedFailure: true,
				restoredPriorSha256: restoredPrior,
				archivesDiffer,
				runtimesDiffer,
				productRoot,
			})
			: failedGate("rollback", "injected update failure must restore a different prior product after distinct archive/runtime bytes", {
				seedPriorForRollback,
				rollbackAttempt,
				restoredPrior,
				expectedPrior: priorTreeSha256,
				archivesDiffer,
				runtimesDiffer,
				productRoot,
			});
		// Leave product in current state before uninstall, proving a successful
		// update remains available after rollback recovery.
		atomicReplaceProduct(currentRoot, productRoot, runRoot);
	}

	const markerBytes = Buffer.from("foreign marker\n", "utf8");
	if (!existsSync(foreignMarker)) writeFileSync(foreignMarker, markerBytes);
	else assertRegularFile(foreignMarker, "foreign marker");
	const markerBefore = readFileSync(foreignMarker);
	removeExact(productRoot, runRoot, "product root for uninstall");
	const markerAfter = readFileSync(foreignMarker);
	const uninstallPass = !existsSync(productRoot) && Buffer.compare(markerBefore, markerAfter) === 0;
	gates.uninstall = uninstallPass
		? gate("uninstall", "pass", { productRootRemoved: true, foreignMarkerPreserved: true, foreignMarker })
		: failedGate("uninstall", "product root was not removed or foreign marker changed", { productRoot, foreignMarker });

	const lifecyclePass = allGatesPass(gates);
	const status = lifecyclePass && !simulated ? "qualified" : "blocked";
	const receipt = {
		schemaVersion: 1,
		kind: "legion-windows-installed-product-qualification",
		status,
		nativeExecution: !simulated,
		executionMode: simulated ? "simulated" : "native",
		targetIdentity: identity,
		releaseVersion: current.releaseVersion,
		sourceRevision: revision,
		archiveSha256,
		runtimeSha256: current.runtimeSha256,
		runner: { os: platform, architecture: runnerArchitecture, simulated },
		gates,
		archive: {
			current: { path: currentArchive, sha256: archiveSha256 },
			...(priorArchive ? { prior: { path: priorArchive, sha256: priorArchiveSha256 } } : {}),
		},
		isolatedWorkRoot: runRoot,
		...(prior
			? {
				priorReleaseVersion: prior.releaseVersion,
				priorArchiveSha256,
				priorRuntimeSha256: prior.runtimeSha256,
			}
			: {}),
		...(status === "qualified"
			? {}
			: {
				reason: simulated
					? "injected archive or command seams are simulated and cannot qualify a native Windows release"
					: "all six lifecycle gates must pass; unproven gates cannot qualify",
			}),
	};
	const receiptPath = writeReceipt(output, receipt);
	return { ...receipt, receiptPath };
}

function parseArguments(argv) {
	const options = {};
	for (let index = 0; index < argv.length; index += 1) {
		const raw = argv[index];
		if (raw === "--") continue;
		if (raw === "--help" || raw === "-h") return { help: true };
		const equal = raw.indexOf("=");
		const key = equal === -1 ? raw.slice(2) : raw.slice(2, equal);
		if (!raw.startsWith("--") || !key) throw new Error(`unknown argument: ${raw}`);
		const normalized = key.replaceAll("-", "").toLowerCase();
		const value = equal === -1 ? argv[++index] : raw.slice(equal + 1);
		if (!value || value.startsWith("--")) throw new Error(`${raw} requires a value`);
		options[normalized] = value;
	}
	return options;
}

function usage(code = 0) {
	console.error("usage: node scripts/qualify-windows-release.mjs --current-zip <zip> [--prior-zip <zip>] --architecture x86_64|arm64 --source-revision <sha> --output <receipt.json> --work-root <isolated-dir>");
	process.exit(code);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
	try {
		const options = parseArguments(process.argv.slice(2));
		if (options.help) usage(0);
		const currentZip = options.currentzip ?? options.currentarchive ?? options.current ?? options.archive;
		const priorZip = options.priorzip ?? options.priorarchive ?? options.prior ?? options.previouszip ?? options.previousarchive ?? null;
		const architecture = options.architecture ?? options.expectedarchitecture;
		const sourceRevision = options.sourcerevision ?? options.revision;
		const output = options.output ?? options.outputreceipt ?? options.receipt ?? options.receiptpath;
		const workRoot = options.workroot ?? options.work ?? options.isolatedworkroot ?? options.isolatedroot;
		const receipt = qualifyWindowsRelease({ currentZip, priorZip, architecture, sourceRevision, output, workRoot });
		process.stdout.write(`${JSON.stringify({ status: receipt.status, receiptPath: receipt.receiptPath, archiveSha256: receipt.archiveSha256, runtimeSha256: receipt.runtimeSha256 }, null, 2)}\n`);
	} catch (error) {
		console.error(`qualify-windows-release: ${error.message}`);
		process.exit(1);
	}
}
