#!/usr/bin/env node
/**
 * One deliberately narrow seam between RightRelease portable candidates &
 * Legion's platform installer finalizers.  It never guesses artifacts: every
 * hand-off is a digest-bound manifest owned by its producing platform.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
	copyFileSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const PRODUCT = "legion";
const REPOSITORY = "Orthic-Labs/legion";
const SHA = /^[a-f0-9]{64}$/i;
const REVISION = /^[a-f0-9]{40,64}$/i;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const FINALIZER = Object.freeze({
	windows: "scripts/release/windows/finalize.mjs",
	macos: "scripts/release/macos/finalize.mjs",
	qualify: "scripts/release/windows/qualify-installed.mjs",
});

function fail(message) { throw new Error(message); }
function digest(path) {
	assertFile(path, "artifact");
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}
function assertFile(path, label) {
	if (!existsSync(path)) fail(`${label} is missing: ${path}`);
	const entry = lstatSync(path);
	if (!entry.isFile() || entry.isSymbolicLink()) fail(`${label} is not a regular file: ${path}`);
}
function assertDirectory(path, label, create = false) {
	if (!existsSync(path)) {
		if (!create) fail(`${label} is missing: ${path}`);
		mkdirSync(path, { recursive: true });
	}
	const entry = lstatSync(path);
	if (!entry.isDirectory() || entry.isSymbolicLink()) fail(`${label} is not a regular directory: ${path}`);
}
function inside(root, candidate, label, { allowRoot = false } = {}) {
	const base = resolve(root);
	const value = resolve(candidate);
	const rel = relative(base, value);
	if ((!allowRoot && !rel) || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) fail(`${label} escapes root: ${candidate}`);
	return value;
}
function pathFrom(root, value, label) {
	if (typeof value !== "string" || !value || value.includes("\0")) fail(`${label} path is invalid`);
	return inside(root, isAbsolute(value) ? value : join(root, value), label);
}
function json(path, label) {
	assertFile(path, label);
	try { return JSON.parse(readFileSync(path, "utf8")); }
	catch (error) { fail(`${label} is invalid JSON: ${error.message}`); }
}
function required(env, name) {
	const value = String(env[name] ?? "").trim();
	if (!value) fail(`${name} is required`);
	return value;
}
function stableVersion(value, label = "version") {
	if (!VERSION.test(String(value))) fail(`${label} is invalid: ${value}`);
	return String(value);
}
function sourceRevision(value) {
	if (!REVISION.test(String(value))) fail(`source revision is invalid: ${value}`);
	return String(value).toLowerCase();
}
function entryRecord(root, value, label) {
	if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} record is invalid`);
	const path = pathFrom(root, value.path, label);
	assertFile(path, label);
	const observed = { path, name: basename(path), size: statSync(path).size, sha256: digest(path) };
	if (!SHA.test(String(value.sha256 ?? "")) || observed.sha256 !== String(value.sha256).toLowerCase()) fail(`${label} digest mismatch`);
	if (!Number.isSafeInteger(value.size) || value.size !== observed.size) fail(`${label} size mismatch`);
	if (typeof value.role !== "string" || !value.role) fail(`${label} role is missing`);
	return { role: value.role, ...observed };
}
function copyRecord(fromRoot, toRoot, record) {
	const rel = relative(resolve(fromRoot), record.path);
	inside(fromRoot, record.path, "finalizer artifact");
	const target = inside(toRoot, join(toRoot, rel), "finalized output");
	mkdirSync(dirname(target), { recursive: true });
	if (existsSync(target)) fail(`finalized output already exists: ${target}`);
	copyFileSync(record.path, target);
	if (digest(target) !== record.sha256) fail(`copied artifact digest mismatch: ${record.name}`);
	return { ...record, path: relative(toRoot, target).replaceAll("\\", "/") };
}
function defaultRun(command, args, options) {
	return spawnSync(command, args, { cwd: ROOT, encoding: "utf8", windowsHide: true, ...options });
}
function runJson(run, command, args, options, label) {
	const result = run(command, args, options);
	if (result?.status !== 0) fail(`${label} failed: ${String(result?.stderr ?? result?.error?.message ?? "unknown error").trim()}`);
	const output = String(result?.stdout ?? "").trim();
	try { return JSON.parse(output); }
	catch { fail(`${label} must emit one JSON object`); }
}
function rightReleaseEnvironment(env, platform) {
	const source = sourceRevision(required(env, "RIGHT_GIT_SOURCE_REVISION"));
	const candidate = required(env, "RIGHT_GIT_UNSIGNED_CANDIDATE_ROOT");
	const architecture = required(env, "RIGHT_GIT_RELEASE_ARCHITECTURE");
	if (required(env, "RIGHT_GIT_RELEASE_PLATFORM") !== platform) fail(`RIGHT_GIT_RELEASE_PLATFORM must be ${platform}`);
	return {
		...env,
		LEGION_SOURCE_REVISION: source,
		LEGION_UNSIGNED_CANDIDATE_ROOT: resolve(candidate),
		RIGHT_GIT_SOURCE_REVISION: source,
		RIGHT_GIT_RELEASE_PLATFORM: platform,
		RIGHT_GIT_RELEASE_ARCHITECTURE: architecture,
	};
}
function finalizationManifest({ platform, env, run = defaultRun, repositoryRoot = ROOT }) {
	const mapped = rightReleaseEnvironment(env, platform);
	const version = stableVersion(json(join(repositoryRoot, "release", "version.json"), "release version").version);
	const finalRootName = platform === "windows" ? "RIGHT_GIT_FINALIZED_WINDOWS_ROOT" : "RIGHT_GIT_FINALIZED_MACOS_ROOT";
	const finalRoot = resolve(required(env, finalRootName));
	assertDirectory(finalRoot, finalRootName, true);
	if (readdirSync(finalRoot).length) fail(`${finalRootName} must be empty`);
	const portableRoot = resolve(repositoryRoot, "dist", "releases", platform === "windows" ? "windows" : "mac", version, mapped.RIGHT_GIT_RELEASE_ARCHITECTURE);
	assertDirectory(mapped.LEGION_UNSIGNED_CANDIDATE_ROOT, "unsigned candidate root");
	// RightRelease is exact signer/notarizer.  No platform finalizer runs until it
	// succeeds. --skip-checks only skips package checks already run by candidate CI.
	const release = run("pnpm", ["exec", "right-release", "build", "--platform", platform === "windows" ? "win" : "mac", "--skip-checks"], { cwd: repositoryRoot, env: mapped });
	if (release?.status !== 0) fail(`RightRelease ${platform} finalization failed: ${String(release?.stderr ?? "").trim()}`);
	assertDirectory(portableRoot, "RightRelease portable output");
	const finalizerPath = join(repositoryRoot, FINALIZER[platform]);
	assertFile(finalizerPath, `${platform} installer finalizer`);
	const staged = join(finalRoot, ".staging");
	mkdirSync(staged, { recursive: true });
	const response = runJson(run, "node", [finalizerPath, "--portable-root", portableRoot, "--output-root", staged, "--source-revision", mapped.LEGION_SOURCE_REVISION, "--version", version, "--architecture", mapped.RIGHT_GIT_RELEASE_ARCHITECTURE], { cwd: repositoryRoot, env: mapped }, `${platform} installer finalizer`);
	if (response.schemaVersion !== 1 || response.kind !== `legion-${platform}-installer-finalization` || response.status !== "finalized" || response.product !== PRODUCT || response.version !== version || sourceRevision(response.sourceRevision) !== mapped.LEGION_SOURCE_REVISION || response.architecture !== mapped.RIGHT_GIT_RELEASE_ARCHITECTURE) fail(`${platform} finalizer identity is invalid`);
	if (!Array.isArray(response.assets) || !Array.isArray(response.evidence) || !response.assets.length || !response.evidence.length) fail(`${platform} finalizer must declare installer assets & portable evidence`);
	const all = [...response.assets, ...response.evidence];
	const records = all.map((item, index) => entryRecord(staged, item, `${platform} finalizer record ${index}`));
	const names = new Set(records.map((record) => record.path.toLowerCase()));
	if (names.size !== records.length) fail(`${platform} finalizer contains duplicate records`);
	const setupCount = records.filter((record) => record.role === "installer").length;
	if (platform === "windows" && setupCount !== 1) fail("Windows finalizer must declare exactly one installer");
	if (platform === "macos" && setupCount !== 1) fail("macOS finalizer must declare exactly one installer");
	const copied = records.map((record) => copyRecord(staged, finalRoot, record));
	rmSync(staged, { recursive: true, force: true });
	const manifest = {
		schemaVersion: 1, kind: "legion-installer-finalization", product: PRODUCT, platform,
		version, sourceRevision: mapped.LEGION_SOURCE_REVISION, architecture: mapped.RIGHT_GIT_RELEASE_ARCHITECTURE,
		assets: copied.filter((record) => response.assets.some((source) => source.role === record.role && basename(source.path) === record.name)),
		evidence: copied.filter((record) => response.evidence.some((source) => source.role === record.role && basename(source.path) === record.name)),
	};
	const manifestPath = join(finalRoot, "installer-finalization.json");
	writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
	return { ...manifest, manifest: manifestPath, digest: digest(manifestPath) };
}
function readFinalization(root, platform) {
	const manifestPath = join(resolve(root), "installer-finalization.json");
	const manifest = json(manifestPath, `${platform} finalization manifest`);
	if (manifest.schemaVersion !== 1 || manifest.kind !== "legion-installer-finalization" || manifest.product !== PRODUCT || manifest.platform !== platform || !VERSION.test(manifest.version) || !REVISION.test(manifest.sourceRevision) || !Array.isArray(manifest.assets) || !Array.isArray(manifest.evidence)) fail(`${platform} finalization manifest is invalid`);
	const records = [...manifest.assets, ...manifest.evidence].map((item, index) => entryRecord(root, item, `${platform} manifest record ${index}`));
	if (new Set(records.map((record) => record.path.toLowerCase())).size !== records.length) fail(`${platform} finalization has duplicate paths`);
	return { ...manifest, root: resolve(root), manifestPath, digest: digest(manifestPath), records };
}
export function qualifyInstalled({ env = process.env, run = defaultRun, repositoryRoot = ROOT } = {}) {
	if (process.platform !== "win32" && env.RIGHT_GIT_TEST_PLATFORM !== "win32") fail("installed qualification requires Windows");
	const finalization = readFinalization(required(env, "RIGHT_GIT_FINALIZED_WINDOWS_ROOT"), "windows");
	const evidenceRoot = resolve(required(env, "RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT"));
	assertDirectory(evidenceRoot, "RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT", true);
	if (readdirSync(evidenceRoot).length) fail("RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT must be empty");
	const installers = finalization.records.filter((record) => record.role === "installer" && record.name.toLowerCase().endsWith(".exe"));
	if (installers.length !== 1) fail("Windows finalization must contain exactly one setup EXE");
	const script = join(repositoryRoot, FINALIZER.qualify);
	assertFile(script, "Windows installed qualification runner");
	const response = runJson(run, "node", [script, "--setup", join(finalization.root, installers[0].path), "--output-root", evidenceRoot, "--finalization", finalization.manifestPath, "--source-revision", finalization.sourceRevision, "--version", finalization.version], { cwd: repositoryRoot, env: { ...env, RIGHT_GIT_WINDOWS_SETUP_SILENT: "1" } }, "Windows installed qualification");
	if (response.schemaVersion !== 1 || response.kind !== "legion-windows-installed-installer-qualification" || response.status !== "qualified" || response.product !== PRODUCT || response.version !== finalization.version || sourceRevision(response.sourceRevision) !== finalization.sourceRevision || String(response.windowsFinalizationSha256 ?? "").toLowerCase() !== finalization.digest) fail("Windows qualification does not bind exact finalization");
	const evidence = entryRecord(evidenceRoot, response.evidence, "Windows qualification evidence");
	return { ...response, evidence, finalizationDigest: finalization.digest };
}
function gh(run, args, options, _label) { return run("gh", args, options ?? {}); }
function ghJson(run, args, options, label) {
	const result = gh(run, args, options, label);
	if (result?.status !== 0) fail(`${label} failed: ${String(result?.stderr ?? "").trim()}`);
	try { return JSON.parse(String(result.stdout ?? "")); } catch { fail(`${label} returned invalid JSON`); }
}
export function publishQualified({ env = process.env, run = defaultRun, repositoryRoot = ROOT, downloadRoot = null } = {}) {
	const token = required(env, "GH_TOKEN");
	const windows = readFinalization(required(env, "RIGHT_GIT_FINALIZED_WINDOWS_ROOT"), "windows");
	const macos = readFinalization(required(env, "RIGHT_GIT_FINALIZED_MACOS_ROOT"), "macos");
	if (windows.version !== macos.version || windows.sourceRevision !== macos.sourceRevision) fail("platform finalizations have mismatched source/version");
	const qualificationRoot = required(env, "RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT");
	const qualificationFiles = readdirSync(qualificationRoot).filter((name) => name.endsWith(".json"));
	if (qualificationFiles.length !== 1) fail("qualification evidence root must contain exactly one JSON evidence file");
	const qualificationPath = join(qualificationRoot, qualificationFiles[0]);
	const qualification = json(qualificationPath, "qualification evidence");
	if (qualification.schemaVersion !== 1 || qualification.kind !== "legion-windows-installed-installer-qualification" || qualification.status !== "qualified" || qualification.product !== PRODUCT || qualification.version !== windows.version || sourceRevision(qualification.sourceRevision) !== windows.sourceRevision || String(qualification.windowsFinalizationSha256 ?? "").toLowerCase() !== windows.digest) fail("qualification does not match Windows finalization");
	const tag = `v${windows.version}`;
	const releaseEnv = { ...env, GH_TOKEN: token };
	let release = gh(run, ["release", "view", tag, "--repo", REPOSITORY, "--json", "tagName,isDraft,isPrerelease,assets"], { cwd: repositoryRoot, env: releaseEnv }, "GitHub release view");
	if (release.status !== 0) {
		release = gh(run, ["release", "create", tag, "--repo", REPOSITORY, "--target", windows.sourceRevision, "--title", `Legion ${tag}`, "--notes", `Qualified installers for ${windows.sourceRevision}.`], { cwd: repositoryRoot, env: releaseEnv }, "GitHub release create");
		if (release.status !== 0) fail(`GitHub release create failed: ${String(release.stderr ?? "").trim()}`);
	}
	const records = [...windows.records, ...macos.records, entryRecord(qualificationRoot, { role: "qualification", path: qualificationPath, size: statSync(qualificationPath).size, sha256: digest(qualificationPath) }, "qualification evidence")];
	const names = new Set();
	for (const record of records) {
		if (names.has(record.name.toLowerCase())) fail(`release asset name is duplicated: ${record.name}`);
		names.add(record.name.toLowerCase());
		const source = record.role === "qualification" ? qualificationPath : record.path;
		const upload = gh(run, ["release", "upload", tag, source, "--repo", REPOSITORY], { cwd: repositoryRoot, env: releaseEnv }, `GitHub release upload ${record.name}`);
		if (upload.status !== 0 && !/already exists|already been taken/i.test(String(upload.stderr ?? ""))) fail(`GitHub release upload failed for ${record.name}: ${String(upload.stderr ?? "").trim()}`);
	}
	const verified = ghJson(run, ["release", "view", tag, "--repo", REPOSITORY, "--json", "tagName,assets"], { cwd: repositoryRoot, env: releaseEnv }, "GitHub release verify");
	if (verified.tagName !== tag || !Array.isArray(verified.assets)) fail("GitHub release identity is invalid");
	const root = downloadRoot ?? join(repositoryRoot, ".right-release", "downloads", tag);
	assertDirectory(root, "download root", true);
	for (const record of records) {
		const asset = verified.assets.filter((item) => item.name === record.name);
		if (asset.length !== 1 || asset[0].size !== record.size) fail(`GitHub release asset is missing or mismatched: ${record.name}`);
		const destination = join(root, record.name);
		if (existsSync(destination)) rmSync(destination, { force: true });
		const download = gh(run, ["release", "download", tag, "--repo", REPOSITORY, "--pattern", record.name, "--dir", root], { cwd: repositoryRoot, env: releaseEnv }, `GitHub release download ${record.name}`);
		if (download.status !== 0 || digest(destination) !== record.sha256) fail(`GitHub release download verification failed: ${record.name}`);
	}
	return { status: "published", tag, version: windows.version, sourceRevision: windows.sourceRevision, windowsFinalizationSha256: windows.digest, macosFinalizationSha256: macos.digest, qualificationSha256: digest(qualificationPath) };
}
export function finalizeWindows(options = {}) { return finalizationManifest({ ...options, platform: "windows" }); }
export function finalizeMacos(options = {}) { return finalizationManifest({ ...options, platform: "macos" }); }
function main() {
	const command = process.argv[2];
	const map = { "finalize-windows": finalizeWindows, "finalize-macos": finalizeMacos, "qualify-installed": qualifyInstalled, "publish-qualified": publishQualified };
	if (!map[command]) fail("usage: installer-release-chain.mjs <finalize-windows|finalize-macos|qualify-installed|publish-qualified>");
	process.stdout.write(`${JSON.stringify(map[command](), null, 2)}\n`);
}
if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) main();
