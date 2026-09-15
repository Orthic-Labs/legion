#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest, sha256File, sourceIdentity } from "../native-cli/gate.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const ARCHITECTURE = "x86_64";
const TARGET = "x86_64-pc-windows-msvc";
const OUTPUT_ROOT = join(ROOT, "dist", "local-windows");
const INSTALL_ROOT = join(process.env.LOCALAPPDATA ?? "", "Orthic Labs", "Legion");

function fail(message) {
	throw new Error(`local-windows-development: ${message}`);
}

function assertBelow(root, path, label) {
	const rel = relative(resolve(root), resolve(path));
	if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) fail(`${label} escapes ${root}`);
	return resolve(path);
}

function assertFile(path, label) {
	if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) fail(`${label} is missing or unsafe: ${path}`);
	return path;
}

function sha256(path) {
	return createHash("sha256").update(readFileSync(assertFile(path, "file"))).digest("hex");
}

function record(path, role) {
	return { path: resolve(path), role, size: statSync(path).size, sha256: sha256(path) };
}

function run(command, args, { cwd = ROOT, env = process.env, capture = false, label = command } = {}) {
	const result = spawnSync(command, args, {
		cwd,
		env,
		encoding: "utf8",
		stdio: capture ? "pipe" : "inherit",
		windowsHide: true,
		maxBuffer: 64 * 1024 * 1024,
	});
	if (result.error || result.status !== 0) {
		const detail = [result.error?.message, result.stderr, result.stdout].filter(Boolean).join("\n").trim();
		fail(`${label} failed${detail ? `: ${detail}` : ` with exit ${result.status}`}`);
	}
	return result;
}

function runJson(command, args, options) {
	const result = run(command, args, { ...options, capture: true });
	try {
		return JSON.parse(String(result.stdout ?? "").trim());
	} catch {
		fail(`${options.label} did not emit JSON: ${String(result.stdout ?? "").trim()}`);
	}
}

function phase(name, action) {
	const started = performance.now();
	try {
		return action();
	} finally {
		process.stdout.write(`${JSON.stringify({ schema: "legion.local-windows-phase.v1", phase: name, elapsedMs: Math.round(performance.now() - started) })}\n`);
	}
}

function version() {
	const value = JSON.parse(readFileSync(join(ROOT, "release", "version.json"), "utf8"));
	if (value.schemaVersion !== 1 || value.kind !== "legion-release-version" || !/^\d+\.\d+\.\d+$/.test(String(value.version ?? ""))) {
		fail("release/version.json is invalid");
	}
	return value.version;
}

function sourceState() {
	const revision = run("git", ["rev-parse", "HEAD"], { capture: true, label: "source revision" }).stdout.trim().toLowerCase();
	if (!/^[a-f0-9]{40,64}$/.test(revision)) fail("source revision is invalid");
	const dirty = run("git", ["status", "--porcelain", "--untracked-files=normal"], { capture: true, label: "source status" }).stdout.trim().length > 0;
	return { revision, dirty };
}

function assertLocalAuthorization() {
	const path = join(ROOT, ".rightkit-local-development.json");
	const value = JSON.parse(readFileSync(assertFile(path, "local development declaration"), "utf8"));
	if (value.schemaVersion !== 1 || value.repository !== "Orthic-Labs/legion" || value.platform !== "win32" || value.purpose !== "unsigned-installer") {
		fail("local development declaration does not authorize Legion Windows unsigned installer work");
	}
}

export function resolveInnoCompiler(env = process.env) {
	const candidates = [
		env.INNO_SETUP_PATH,
		env.ChocolateyInstall ? join(env.ChocolateyInstall, "bin", "iscc.exe") : null,
		env.LOCALAPPDATA ? join(env.LOCALAPPDATA, "Programs", "Inno", "ISCC.exe") : null,
		env.LOCALAPPDATA ? join(env.LOCALAPPDATA, "Programs", "Inno Setup 6", "ISCC.exe") : null,
		env.ProgramFiles ? join(env.ProgramFiles, "Inno Setup 6", "ISCC.exe") : null,
		env["ProgramFiles(x86)"] ? join(env["ProgramFiles(x86)"], "Inno Setup 6", "ISCC.exe") : null,
	].filter(Boolean);
	for (const candidate of candidates) {
		if (existsSync(candidate) && lstatSync(candidate).isFile()) return resolve(candidate);
	}
	const command = spawnSync("where.exe", ["iscc.exe"], { encoding: "utf8", windowsHide: true });
	const discovered = String(command.stdout ?? "").split(/\r?\n/u).map((entry) => entry.trim()).find(Boolean);
	if (command.status === 0 && discovered && existsSync(discovered)) return resolve(discovered);
	fail("Inno Setup 6 compiler is missing; install workspace Windows installer prerequisite or set INNO_SETUP_PATH");
}

export function localFinalization({ installer, releaseVersion, sourceRevision }) {
	return {
		schemaVersion: 1,
		kind: "legion-installer-finalization",
		status: "local-unsigned",
		profile: "internal-unsigned",
		product: "legion",
		platform: "windows",
		version: releaseVersion,
		sourceRevision,
		architecture: ARCHITECTURE,
		signing: { status: "unsigned", reason: "internal_local_unsigned_route" },
		assets: [record(installer, "installer")],
		evidence: [],
	};
}

export function runLocalWindowsDevelopment({ buildOnly = false } = {}) {
	if (process.platform !== "win32") fail("Windows host is required");
	if (!process.env.LOCALAPPDATA) fail("LOCALAPPDATA is required");
	assertLocalAuthorization();
	const started = performance.now();
	const releaseVersion = version();
	const source = sourceState();
	const sourceTree = sourceIdentity(ROOT);
	const behaviorManifest = loadManifest(join(ROOT, "tests", "native-cli-characterization", "fixtures.json"));
	const assemblyRoot = join(ROOT, "dist", "native", `windows-${ARCHITECTURE}`, `legion-${releaseVersion}`);
	const installerRoot = assertBelow(OUTPUT_ROOT, join(OUTPUT_ROOT, "installer"), "installer output");
	const qualificationRoot = assertBelow(OUTPUT_ROOT, join(OUTPUT_ROOT, "qualification"), "qualification output");
	for (const path of [installerRoot, qualificationRoot]) rmSync(path, { recursive: true, force: true });
	mkdirSync(installerRoot, { recursive: true });

	phase("native-release-build", () => run(process.env.ComSpec ?? "cmd.exe", [
		"/d", "/s", "/c", "rightkit.cmd", "cargo", "build", "--manifest-path", "engine/Cargo.toml", "--locked", "--release", "--bins", "--target", TARGET,
	], { label: "managed native release build" }));
	phase("native-assembly", () => run(process.execPath, [
		join(ROOT, "scripts", "assemble-native-release.mjs"),
		"--profile", "release", "--platform", "windows", "--architecture", ARCHITECTURE,
		"--target", TARGET, "--out", assemblyRoot, "--force",
	], { label: "native assembly" }));
	const inno = resolveInnoCompiler();
	const installer = phase("unsigned-installer", () => runJson(process.execPath, [
		join(ROOT, "scripts", "release", "windows", "finalize-installer.mjs"),
		"--unsigned", "--input-root", assemblyRoot, "--output", installerRoot,
		"--version", releaseVersion, "--architecture", ARCHITECTURE,
	], { env: { ...process.env, INNO_SETUP_PATH: inno }, label: "unsigned installer build" }));
	if (installer.status !== "unsigned") fail("installer worker did not report unsigned output");
	assertFile(installer.installer, "unsigned installer");
	if (installer.sha256 !== sha256(installer.installer)) fail("unsigned installer digest mismatch");
	const finalizationPath = join(installerRoot, "installer-finalization.json");
	writeFileSync(finalizationPath, `${JSON.stringify(localFinalization({ installer: installer.installer, releaseVersion, sourceRevision: source.revision }), null, 2)}\n`);

	if (buildOnly) {
		return {
			status: "built",
			profile: "internal-unsigned",
			installer: installer.installer,
			installerSha256: installer.sha256,
			finalization: finalizationPath,
			sourceRevision: source.revision,
			dirty: source.dirty,
			elapsedMs: Math.round(performance.now() - started),
		};
	}

	mkdirSync(qualificationRoot, { recursive: true });
	const qualification = phase("installed-qualification", () => runJson(process.execPath, [
		join(ROOT, "scripts", "release", "windows", "qualify-installed.mjs"),
		"--setup", installer.installer, "--output-root", qualificationRoot,
		"--finalization", finalizationPath, "--source-revision", source.revision,
		"--version", releaseVersion,
	], { label: "isolated installed qualification" }));
	if (qualification.status !== "qualified") fail("installed qualification did not pass");

	const installLog = join(OUTPUT_ROOT, "install.log");
	phase("stable-install", () => run(installer.installer, [
		"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", `/DIR=${INSTALL_ROOT}`, `/LOG=${installLog}`,
	], { label: "stable installer" }));
	const executable = assertFile(join(INSTALL_ROOT, "current", "bin", "legion.exe"), "stable Legion executable");
	const installedVersion = run(executable, ["--version"], { capture: true, cwd: INSTALL_ROOT, label: "installed version" }).stdout.trim();
	if (installedVersion !== releaseVersion) fail(`installed version mismatch: ${installedVersion}`);
	const status = runJson(executable, ["--json", "setup", "status"], { cwd: INSTALL_ROOT, label: "installed setup status" });
	if (status.kind !== "legion-setup-status" || status.status !== "complete" || status.origin !== "installed" || status.stableCurrent !== true) {
		fail("installed setup status is not complete at stable current");
	}
	if (status.liveIdentity?.projections?.claudePlugin?.state !== "current") fail("Claude projection is not current");
	const codexOptIn = existsSync(join(process.env.USERPROFILE ?? "", ".codex", "plugins", "legion"));
	if (codexOptIn && status.liveIdentity?.projections?.codexPlugin?.state !== "current") fail("Codex opt-in projection is not current");

	const result = {
		status: "pass",
		origin: "installed",
		profile: "internal-unsigned",
		installer: installer.installer,
		installerSha256: installer.sha256,
		finalization: finalizationPath,
		qualification: qualification.evidence?.path ?? join(qualificationRoot, "qualification.json"),
		installedRoot: INSTALL_ROOT,
		installedExecutable: executable,
		executableSha256: sha256File(executable),
		installedVersion,
		sourceRevision: source.revision,
		sourceTreeSha256: sourceTree.sourceTreeSha256,
		manifestSha256: behaviorManifest.manifestSha256,
		dirty: source.dirty,
		codexOptIn,
		elapsedMs: Math.round(performance.now() - started),
	};
	writeFileSync(join(OUTPUT_ROOT, "local-verification.json"), `${JSON.stringify(result, null, 2)}\n`);
	return result;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
	try {
		const result = runLocalWindowsDevelopment({ buildOnly: process.argv.includes("--build-only") });
		process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
	} catch (error) {
		process.stderr.write(`${error.message}\n`);
		process.exitCode = 1;
	}
}
