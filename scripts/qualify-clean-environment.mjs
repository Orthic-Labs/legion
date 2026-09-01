#!/usr/bin/env node

/**
 * Qualify a release in an environment that cannot borrow the operator's
 * checkout, state, configuration, or development tools.
 *
 * The script does not create a VM and does not install a harness. The caller
 * supplies an already isolated root, a release artifact, and proof that the
 * harness was installed by its normal installer. This keeps the acceptance
 * contract useful for both a VM/container wrapper and an equivalent isolated
 * filesystem fixture. Every contamination check is exported so tests can use
 * filesystem fixtures without a network, VM, or installation.
 */

import { createHash } from "node:crypto";
import { readFileSync, lstatSync, existsSync, mkdirSync, renameSync, rmSync, writeFileSync, realpathSync, readdirSync } from "node:fs";
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = 1;
const INSTALLATION_KIND = "legion-clean-environment-harness-installation";
const QUALIFICATION_KIND = "legion-clean-environment-qualification";
const RELEASE_EXTENSIONS = [".zip", ".tar", ".tgz", ".gz", ".msi", ".exe", ".pkg", ".dmg"];
const PRIVATE_ENV_PATTERNS = [
	/^(?:LEGION|RHOOK|OMNIROUTE|MEMBRANE)(?:_|$)/i,
	/^CODEX_HOME$/i,
	/^(?:CLAUDE_CODE|ANTHROPIC|OPENAI)(?:_|$)/i,
	/(?:API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY)$/i,
];
const DEV_ONLY_BINARIES = Object.freeze({
	legion: ["legion", "legion.exe", "legion.cmd", "legion.bat"],
	"legion-hook": ["legion-hook", "legion-hook.exe"],
	"legion-mcp": ["legion-mcp", "legion-mcp.exe"],
	rhook: ["rhook", "rhook.exe", "rhook.cmd", "rhook.bat"],
	omniroute: ["omniroute", "omniroute.exe", "omniroute.cmd", "omniroute.bat"],
	membrane: ["membrane", "membrane.exe", "membrane.cmd", "membrane.bat", "membrane-cli", "membrane-cli.exe"],
});
const STATE_RELATIVE_PATHS = Object.freeze([
	".legion",
	".codex",
	".config/legion",
	".local/share/legion",
	".local/state/legion",
	"AppData/Local/Legion",
	"AppData/Roaming/Legion",
	"Library/Application Support/Orthic Labs/Legion",
	"Library/Application Support/Legion",
	"state/Legion",
	"state/legion",
	"Legion",
]);

// A small seam keeps every detector injectable while production uses the real
// filesystem. Tests can replace these three operations with fixture-backed ones.
const nativeFs = { existsSync, lstatSync, realpathSync, readdirSync };

function fsExists(fsOps, path) {
	try { return fsOps.existsSync(path); } catch { return false; }
}

function regularFile(fsOps, path) {
	try {
		const stat = fsOps.lstatSync(path);
		return stat.isFile() && !stat.isSymbolicLink();
	} catch {
		return false;
	}
}

function emptyRegularFile(fsOps, path) {
	try {
		const stat = fsOps.lstatSync(path);
		return stat.isFile() && !stat.isSymbolicLink() && stat.size === 0;
	} catch {
		return false;
	}
}

function directory(fsOps, path) {
	try {
		const stat = fsOps.lstatSync(path);
		return stat.isDirectory() && !stat.isSymbolicLink();
	} catch {
		return false;
	}
}

function canonicalPath(fsOps, path) {
	const absolute = resolve(String(path));
	try { return fsOps.realpathSync(absolute); } catch { return absolute; }
}

function inside(root, candidate, fsOps = nativeFs, allowEqual = true) {
	if (typeof root !== "string" || typeof candidate !== "string") return false;
	const rootPath = canonicalPath(fsOps, root);
	const candidatePath = canonicalPath(fsOps, candidate);
	const remainder = relative(rootPath, candidatePath);
	if (!allowEqual && !remainder) return false;
	return !remainder || (remainder !== ".." && !remainder.startsWith(`..${sep}`) && !isAbsolute(remainder));
}

function issue(kind, path, detail) {
	return { kind, path: path == null ? null : String(path), ...(detail ? { detail } : {}) };
}

export function detectInheritedPrivateEnv(env = process.env, { patterns = PRIVATE_ENV_PATTERNS } = {}) {
	return Object.keys(env ?? {})
		.filter((name) => patterns.some((pattern) => pattern.test(name)))
		.sort()
		.map((name) => issue("inherited-private-environment", name, "private environment variable is present"));
}

function workspaceMarkers(root, fsOps) {
	if (fsExists(fsOps, join(root, ".git"))) return [".git"];
	if (fsExists(fsOps, join(root, "docs", "pending"))) return ["docs/pending"];
	if (fsExists(fsOps, join(root, "engine")) || fsExists(fsOps, join(root, "src"))) return ["engine/src"];
	if (fsExists(fsOps, join(root, "pnpm-workspace.yaml"))) return ["pnpm-workspace.yaml"];
	if (fsExists(fsOps, join(root, "AGENTS.md"))
		&& (fsExists(fsOps, join(root, "package.json")) || fsExists(fsOps, join(root, "skills")))) {
		return ["AGENTS.md"];
	}
	return [];
}

function nestedWorkspaceRoots(root, fsOps, depth = 0, found = []) {
	if (!directory(fsOps, root) || depth > 4) return found;
	if (workspaceMarkers(root, fsOps).length) {
		found.push(root);
		return found;
	}
	// Failure to inspect an isolated mount is itself a failed qualification;
	// never turn an unreadable workspace into a clean result.
	for (const entry of fsOps.readdirSync(root)) nestedWorkspaceRoots(join(root, entry), fsOps, depth + 1, found);
	return found;
}

export function findWorkspaceRoot(start, { fsOps = nativeFs } = {}) {
	if (typeof start !== "string" || !start) return null;
	let current = canonicalPath(fsOps, start);
	if (!directory(fsOps, current)) current = dirname(current);
	while (true) {
		if (workspaceMarkers(current, fsOps).length) return current;
		const parent = dirname(current);
		if (parent === current) return null;
		current = parent;
	}
}

/** Detects both an explicitly mounted checkout and a checkout reachable via cwd/PATH. */
export function detectReachableWorkspace({ cwd = process.cwd(), workspaceRoots = [], scanRoots = [], pathValue = "", platform = process.platform, fsOps = nativeFs } = {}) {
	const candidates = [...workspaceRoots];
	if (cwd) candidates.push(cwd);
	const pathSeparator = platform === "win32" ? ";" : delimiter;
	for (const entry of String(pathValue ?? "").split(pathSeparator)) candidates.push(entry || cwd);
	// Keep the caller-visible spelling of a finding. On macOS, /var commonly
	// resolves to /private/var; canonical paths are for identity/deduplication,
	// not for rewriting the path reported to the caller.
	const found = new Map();
	const record = (root) => {
		const key = canonicalPath(fsOps, root);
		if (!found.has(key)) found.set(key, root);
	};
	for (const candidate of candidates) {
		const root = findWorkspaceRoot(candidate, { fsOps });
		if (root) record(root);
	}
	for (const root of scanRoots) {
		for (const nested of nestedWorkspaceRoots(root, fsOps)) record(nested);
	}
	return [...found.values()].sort().map((root) => issue("reachable-workspace", root, "workspace checkout is reachable"));
}

export function detectPreexistingState({ roots = [], statePaths = [], fsOps = nativeFs } = {}) {
	const candidates = [...statePaths];
	for (const root of roots) {
		// Qualification fixtures and isolated harnesses commonly place the
		// simulated home beneath their root. Inspect both levels; existence is
		// contamination even when the state directory has no entries.
		for (const stateRoot of [root, join(root, "home")]) {
			for (const relativePath of STATE_RELATIVE_PATHS) candidates.push(join(stateRoot, ...relativePath.split("/")));
		}
	}
	// As above, canonicalize only to deduplicate aliases; report the path that
	// was actually inspected so macOS symlinked system prefixes stay stable.
	const found = new Map();
	for (const candidate of candidates) {
		if (fsExists(fsOps, candidate)) {
			const key = canonicalPath(fsOps, candidate);
			if (!found.has(key)) found.set(key, candidate);
		}
	}
	return [...found.values()].sort().map((path) => issue("preexisting-state", path, "state directory or file exists before qualification"));
}

function capabilityForBinary(name) {
	const lower = name.toLowerCase();
	return Object.entries(DEV_ONLY_BINARIES).find(([, names]) => names.includes(lower))?.[0] ?? null;
}

function allowedPath(path, allowedPaths, fsOps) {
	return allowedPaths.some((allowed) => {
		const allowedCanonical = canonicalPath(fsOps, allowed);
		const candidateCanonical = canonicalPath(fsOps, path);
		return candidateCanonical === allowedCanonical || dirname(candidateCanonical) === allowedCanonical;
	});
}

export function detectDevOnlyPathBinaries({ pathValue = "", platform = process.platform, explicitlyInstalled = [], allowedPaths = [], cwd = process.cwd(), fsOps = nativeFs } = {}) {
	const pathSeparator = platform === "win32" ? ";" : delimiter;
	const entries = String(pathValue ?? "").split(pathSeparator);
	const installed = new Set(explicitlyInstalled.map((value) => String(value).toLowerCase()));
	const findings = [];
	const seen = new Set();
	for (const entry of entries) {
		const entryRoot = entry || cwd;
		for (const names of Object.values(DEV_ONLY_BINARIES)) {
			for (const name of names) {
				const candidate = join(entryRoot, name);
				if (!regularFile(fsOps, candidate)) continue;
				const capability = capabilityForBinary(name);
				const pathIsAllowed = allowedPath(candidate, allowedPaths, fsOps);
				const releaseBinary = capability?.startsWith("legion") === true;
				if (pathIsAllowed && (releaseBinary || installed.has(capability))) continue;
				const key = `${capability}:${canonicalPath(fsOps, candidate)}`;
				if (seen.has(key)) continue;
				seen.add(key);
				findings.push(issue("dev-only-path-binary", candidate, `${capability} development binary is reachable on PATH`));
			}
		}
	}
	return findings.sort((left, right) => left.path.localeCompare(right.path));
}

export function inspectCleanEnvironment({
	env = process.env,
	pathValue = env?.PATH ?? env?.Path ?? "",
	cwd = process.cwd(),
	isolatedRoot = null,
	workspaceRoots = [],
	stateRoots = [],
	statePaths = [],
	platform = process.platform,
	explicitlyInstalled = [],
	allowedPathEntries = [],
	fsOps = nativeFs,
} = {}) {
	const issues = [
		...detectInheritedPrivateEnv(env),
		...detectReachableWorkspace({
			cwd,
			workspaceRoots,
			scanRoots: [isolatedRoot, ...workspaceRoots].filter(Boolean),
			pathValue,
			platform,
			fsOps,
		}),
		...detectPreexistingState({ roots: stateRoots, statePaths, fsOps }),
		...detectDevOnlyPathBinaries({ pathValue, platform, explicitlyInstalled, allowedPaths: allowedPathEntries, cwd, fsOps }),
	];
	return { clean: issues.length === 0, issues };
}

function assertReleaseArtifact(artifactPath, { workspaceRoots = [], fsOps = nativeFs } = {}) {
	if (!regularFile(fsOps, artifactPath)) return [issue("release-artifact", artifactPath, "release artifact must be an existing regular file")];
	if (emptyRegularFile(fsOps, artifactPath)) return [issue("release-artifact", artifactPath, "release artifact must not be empty")];
	const lower = String(artifactPath).toLowerCase();
	if (!RELEASE_EXTENSIONS.some((extension) => lower.endsWith(extension))) {
		return [issue("release-artifact", artifactPath, "input is not a recognized release artifact")];
	}
	const possibleWorkspaceRoots = [...workspaceRoots, findWorkspaceRoot(artifactPath, { fsOps })].filter(Boolean);
	for (const root of possibleWorkspaceRoots) {
		if (inside(root, artifactPath, fsOps)) return [issue("release-artifact", artifactPath, "release artifact is inside a workspace checkout")];
	}
	return [];
}

function readJson(path, label) {
	try { return JSON.parse(readFileSync(path, "utf8")); }
	catch (error) { throw new Error(`${label} is not valid JSON: ${path} (${error.message})`); }
}

function validateHarnessInstallation({ manifest, harnessPath, installRoot, isolatedRoot, artifactSha256, fsOps = nativeFs }) {
	const issues = [];
	if (!regularFile(fsOps, harnessPath)) issues.push(issue("harness-installation", harnessPath, "harness must be an existing regular file"));
	if (!directory(fsOps, installRoot)) issues.push(issue("harness-installation", installRoot, "harness install root must be an existing directory"));
	if (!inside(isolatedRoot, installRoot, fsOps) || !inside(installRoot, harnessPath, fsOps, false)) {
		issues.push(issue("harness-installation", harnessPath, "harness is not installed inside the isolated root"));
	}
	if (!manifest || manifest.schemaVersion !== SCHEMA_VERSION || manifest.kind !== INSTALLATION_KIND) {
		issues.push(issue("harness-installation", null, `installation proof must be ${INSTALLATION_KIND} schemaVersion=${SCHEMA_VERSION}`));
		return issues;
	}
	if (manifest.method !== "normal" || manifest.status !== "installed") {
		issues.push(issue("harness-installation", null, "harness installation was not completed by the normal installer"));
	}
	if (!["normal-installer", "release-artifact"].includes(manifest.source)) {
		issues.push(issue("harness-installation", null, "harness source is not a normal installer or the supplied release artifact"));
	}
	if (manifest.source === "normal-installer" && (typeof manifest.installer !== "string" || !manifest.installer.trim())) {
		issues.push(issue("harness-installation", null, "normal harness installation must name its installer"));
	}
	if (manifest.source === "release-artifact" && manifest.artifactSha256 !== artifactSha256) {
		issues.push(issue("harness-installation", null, "harness installation artifact digest does not match the release artifact"));
	}
	if (typeof manifest.installedPath !== "string" || canonicalPath(fsOps, manifest.installedPath) !== canonicalPath(fsOps, harnessPath)) {
		issues.push(issue("harness-installation", manifest.installedPath ?? null, "installation proof does not identify the supplied harness"));
	}
	return issues;
}

function sha256File(path) {
	return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function writeReceipt(path, receipt) {
	const output = resolve(path);
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

export function qualifyCleanEnvironment({
	releaseArtifact,
	isolatedRoot,
	harnessPath,
	harnessInstallRoot,
	harnessInstallation,
	harnessManifest = null,
	harnessManifestPath = null,
	output,
	workspaceRoots = [],
	stateRoots = [],
	statePaths = [],
	env = process.env,
	pathValue = env?.PATH ?? env?.Path ?? "",
	cwd = process.cwd(),
	platform = process.platform,
	explicitlyInstalled = [],
	allowedPathEntries = [],
	fsOps = nativeFs,
} = {}) {
	if (!releaseArtifact) throw new Error("release artifact is required");
	if (!isolatedRoot) throw new Error("isolated root is required");
	if (!output) throw new Error("qualification output receipt is required");
	const artifactIssues = assertReleaseArtifact(releaseArtifact, { workspaceRoots, fsOps });
	const artifactSha256 = artifactIssues.length ? null : sha256File(releaseArtifact);
	const isolationIssues = directory(fsOps, isolatedRoot)
		? []
		: [issue("isolated-root", isolatedRoot, "isolated root must be an existing regular directory")];
	const inheritedStateRoots = [
		env?.HOME,
		env?.USERPROFILE,
		env?.LOCALAPPDATA,
		env?.APPDATA,
		env?.XDG_CONFIG_HOME,
		env?.XDG_DATA_HOME,
	].filter(Boolean);
	const environment = inspectCleanEnvironment({
		env,
		pathValue,
		cwd,
		isolatedRoot,
		workspaceRoots,
		stateRoots: [isolatedRoot, ...inheritedStateRoots, ...stateRoots],
		statePaths,
		platform,
		explicitlyInstalled,
		allowedPathEntries: allowedPathEntries.filter((path) => inside(isolatedRoot, path, fsOps)),
		fsOps,
	});
	const installation = harnessInstallation ?? harnessManifest;
	const installationIssues = validateHarnessInstallation({
		manifest: installation,
		harnessPath,
		installRoot: harnessInstallRoot,
		isolatedRoot,
		artifactSha256,
		fsOps,
	});
	if (harnessManifestPath && findWorkspaceRoot(harnessManifestPath, { fsOps })) {
		installationIssues.push(issue("harness-installation", harnessManifestPath, "harness installation proof is inside a workspace checkout"));
	}
	const issues = [...artifactIssues, ...isolationIssues, ...environment.issues, ...installationIssues];
	const receipt = {
		schemaVersion: SCHEMA_VERSION,
		kind: QUALIFICATION_KIND,
		status: issues.length === 0 ? "qualified" : "blocked",
		contract: {
			isolatedRoot: resolve(isolatedRoot),
			workspaceFiles: "forbidden",
			inheritedPrivateEnvironment: "forbidden",
			operatorState: "forbidden",
			developmentPathBinaries: "forbidden",
			harnessInstallation: "normal-installer-or-release-artifact",
		},
		releaseArtifact: resolve(releaseArtifact),
		releaseArtifactSha256: artifactSha256,
		harness: harnessPath ? resolve(harnessPath) : null,
		checks: {
			environment: environment.clean,
			artifact: artifactIssues.length === 0,
			harnessInstallation: installationIssues.length === 0,
		},
		issues,
	};
	receipt.receiptPath = writeReceipt(output, receipt);
	return receipt;
}

function parseArguments(argv) {
	const options = { workspaceRoots: [], stateRoots: [], explicitlyInstalled: [] };
	for (let index = 0; index < argv.length; index += 1) {
		const raw = argv[index];
		if (raw === "--") continue;
		if (raw === "--help" || raw === "-h") return { help: true };
		if (!raw.startsWith("--")) throw new Error(`unknown argument: ${raw}`);
		const equal = raw.indexOf("=");
		const key = equal === -1 ? raw.slice(2) : raw.slice(2, equal);
		const normalized = key.replaceAll("-", "").toLowerCase();
		const value = equal === -1 ? argv[++index] : raw.slice(equal + 1);
		if (!value || value.startsWith("--")) throw new Error(`${raw} requires a value`);
		const field = {
			releaseartifact: "releaseArtifact", artifact: "releaseArtifact", archive: "releaseArtifact", release: "releaseArtifact",
			isolatedroot: "isolatedRoot", environmentroot: "isolatedRoot", cleanroot: "isolatedRoot", workroot: "isolatedRoot",
			harness: "harnessPath", harnesspath: "harnessPath", harnessinstallroot: "harnessInstallRoot", harnessinstall: "harnessInstallRoot",
			harnessmanifest: "harnessManifest", installationproof: "harnessManifest", output: "output", receipt: "output",
			workspaceroot: "workspaceRoots", stateroot: "stateRoots", statepath: "statePaths", path: "pathValue",
			allowinstalled: "explicitlyInstalled", allowcapability: "explicitlyInstalled", allowpath: "allowedPathEntries",
		}[normalized];
		if (!field) throw new Error(`unknown argument: ${raw}`);
		if (["workspaceRoots", "stateRoots", "statePaths", "explicitlyInstalled", "allowedPathEntries"].includes(field)) options[field].push(...value.split(",").filter(Boolean));
		else options[field] = value;
	}
	return options;
}

function usage(code = 0) {
	console.error("usage: node scripts/qualify-clean-environment.mjs --release-artifact <artifact> --isolated-root <root> --harness <path> --harness-install-root <root> --harness-manifest <json> --output <receipt.json> [--workspace-root <path>] [--state-root <path>] [--allow-installed <rhook,omniroute,membrane>] [--allow-path <path>]");
	process.exit(code);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
	try {
		const options = parseArguments(process.argv.slice(2));
		if (options.help) usage(0);
		if (!options.harnessManifest) throw new Error("--harness-manifest is required");
		const installation = readJson(options.harnessManifest, "harness installation proof");
		const receipt = qualifyCleanEnvironment({
			...options,
			harnessInstallation: installation,
			harnessManifestPath: options.harnessManifest,
		});
		process.stdout.write(`${JSON.stringify({ status: receipt.status, receiptPath: receipt.receiptPath, issues: receipt.issues.length }, null, 2)}\n`);
		process.exit(receipt.status === "qualified" ? 0 : 1);
	} catch (error) {
		console.error(`qualify-clean-environment: ${error.message}`);
		process.exit(1);
	}
}
