import {
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	realpathSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
	collectReleaseAsset,
	createPortableArchive,
	createWranglerR2Client,
	materializeDirectRelease,
	planBootstrapPublication,
	publishBootstrapPlan,
	renderPowerShellBootstrap,
	sha256File,
	validatePowerShellBootstrap,
} from "@rightkit/release/direct-bootstrap.mjs";
import {
	prepareGitHubDirectRelease,
	publishGitHubRelease,
} from "@rightkit/release/github-release.mjs";
import {
	materializeCycloneDxSbom,
	materializeInTotoSlsaProvenance,
} from "@rightkit/release/supply-chain-evidence.mjs";
import {
	WINDOWS_ARCHITECTURES,
	WINDOWS_INSTALL_CONTRACT,
} from "../right-release.config.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PRODUCT = "legion";
const GITHUB_REPOSITORY = "Orthic-Labs/legion";
const SOURCE_REPOSITORY = "https://github.com/Orthic-Labs/legion";
const BOOTSTRAP_VERSION = "0.1.0";
const REQUIRED_BINARIES = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"];
const REQUIRED_QUALIFICATION_GATES = [
	"installed-product",
	"command-resolution",
	"client-integration",
	"update",
	"rollback",
	"uninstall",
];
const SOURCE_REVISION = /^[a-f0-9]{40,64}$/i;
const FORBIDDEN_BINDING_SEGMENTS = new Set([
	...WINDOWS_INSTALL_CONTRACT.forbiddenBindingSegments,
	".git",
]);

function readJson(path, label) {
	assertRegularFile(path, label);
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		throw new Error(`${label} is invalid JSON: ${error.message}`);
	}
}

function bareDigest(value) {
	return String(value ?? "").replace(/^sha256:/i, "").toLowerCase();
}

function digestMatches(observed, expected) {
	const left = bareDigest(observed);
	const right = bareDigest(expected);
	return /^[a-f0-9]{64}$/.test(left) && /^[a-f0-9]{64}$/.test(right) && left === right;
}

function releaseGeneration(metadata, version, runtimeSha256) {
	const explicit = metadata?.generation
		?? metadata?.installGeneration
		?? metadata?.runtime?.generation;
	if (typeof explicit === "string" && explicit.trim()) return explicit.trim();
	const assetsDigest = metadata?.declarativeAssetsSha256
		?? metadata?.declarative_assets_sha256;
	if (typeof assetsDigest === "string" && /^[a-f0-9]{64}$/i.test(bareDigest(assetsDigest))) {
		return `${version}:${bareDigest(assetsDigest)}`;
	}
	return `${version}:${bareDigest(runtimeSha256)}`;
}

function normalizedPath(value) {
	return resolve(String(value ?? "")).replaceAll("\\", "/").toLowerCase();
}

function pathsEqual(left, right) {
	return typeof left === "string"
		&& typeof right === "string"
		&& normalizedPath(left) === normalizedPath(right);
}

function canonicalPath(value) {
	try {
		return realpathSync(String(value));
	} catch {
		return resolve(String(value));
	}
}

function canonicalPathsEqual(left, right) {
	return typeof left === "string"
		&& typeof right === "string"
		&& canonicalPath(left).replaceAll("\\", "/").toLowerCase()
			=== canonicalPath(right).replaceAll("\\", "/").toLowerCase();
}

function hasForbiddenBindingSegment(value) {
	const path = String(value ?? "").replaceAll("\\", "/").toLowerCase();
	return path.split("/").some((segment) => FORBIDDEN_BINDING_SEGMENTS.has(segment));
}

function pathInside(root, candidate) {
	if (typeof root !== "string" || typeof candidate !== "string") return false;
	const rel = relative(canonicalPath(root), canonicalPath(candidate));
	return Boolean(rel)
		&& rel !== ".."
		&& !rel.startsWith(`..${sep}`)
		&& !isAbsolute(rel);
}

function versionRootMatches(root, version, archiveDigest) {
	if (typeof root !== "string" || typeof version !== "string") return false;
	const prefix = `${version}-${bareDigest(archiveDigest).slice(0, 12)}`.toLowerCase();
	const name = basename(root.replaceAll("\\", "/")).toLowerCase();
	return name === prefix || name.startsWith(`${prefix}-`);
}

function stableInstallBinding(value, generation) {
	const install = value?.install;
	if (!install || typeof install !== "object" || Array.isArray(install)) return false;
	const installRoot = install.root ?? install.installRoot;
	const currentPath = install.currentPath;
	const executable = install.executable;
	return install.origin === WINDOWS_INSTALL_CONTRACT.origin
		&& typeof installRoot === "string"
		&& typeof currentPath === "string"
		&& typeof executable === "string"
		&& isAbsolute(installRoot)
		&& isAbsolute(currentPath)
		&& isAbsolute(executable)
		&& pathsEqual(currentPath, join(installRoot, WINDOWS_INSTALL_CONTRACT.stableCurrentName))
		&& pathsEqual(executable, join(currentPath, WINDOWS_INSTALL_CONTRACT.executablePath))
		&& install.generation === generation
		&& !hasForbiddenBindingSegment(installRoot)
		&& !hasForbiddenBindingSegment(currentPath)
		&& !hasForbiddenBindingSegment(executable);
}

function assertRegularFile(path, label) {
	if (!existsSync(path)) throw new Error(`${label} is missing: ${path}`);
	const metadata = lstatSync(path);
	if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`${label} is not a regular file: ${path}`);
}

function fileRecord(path) {
	assertRegularFile(path, "release artifact");
	return {
		name: basename(path),
		size: statSync(path).size,
		sha256: sha256File(path),
	};
}

function resolveInside(root, relativePath, label) {
	const base = realpathSync(root);
	const candidate = resolve(base, ...relativePath.split("/"));
	const rel = relative(base, candidate);
	if (rel === ".." || rel.startsWith(`..${sep}`) || resolve(candidate) === resolve(base)) {
		throw new Error(`${label} escapes release root: ${relativePath}`);
	}
	return candidate;
}

function assertReleaseOutputPath(outputDir, repositoryRoot, inputRoot) {
	const resolvedOutput = resolve(outputDir);
	const resolvedInput = resolve(inputRoot);
	const relativeInput = relative(resolvedInput, resolvedOutput);
	if (
		resolvedOutput === resolve(repositoryRoot)
		|| !relativeInput
		|| (!relativeInput.startsWith(`..${sep}`) && relativeInput !== ".." && !isAbsolute(relativeInput))
	) {
		throw new Error(`unsafe release output path: ${resolvedOutput}`);
	}
}

export function normalizeWindowsArchitecture(value) {
	const normalized = String(value ?? "").trim().toLowerCase().replace(/^windows-/, "");
	if (normalized === "x64" || normalized === "amd64") return "x86_64";
	if (normalized === "aarch64") return "arm64";
	if (!WINDOWS_ARCHITECTURES[normalized]) {
		throw new Error(`unsupported Windows architecture: ${value}; expected x86_64 or arm64`);
	}
	return normalized;
}

export function windowsTargetIdentity(architecture) {
	const normalized = normalizeWindowsArchitecture(architecture);
	const configured = WINDOWS_ARCHITECTURES[normalized];
	return {
		platform: configured.platform,
		architecture: configured.architecture,
		nativeArchitecture: configured.nativeArchitecture,
		targetTriple: configured.targetTriple,
		executable: "legion.exe",
		artifactId: configured.artifactId,
	};
}

function releaseVersion(repositoryRoot) {
	const record = readJson(join(repositoryRoot, "release", "version.json"), "release version");
	if (
		record.schemaVersion !== 1
		|| record.kind !== "legion-release-version"
		|| !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(record.version ?? "")
	) {
		throw new Error("release/version.json must declare one stable SemVer");
	}
	return record.version;
}

function sourceRevision(repositoryRoot, supplied) {
	if (supplied !== undefined && supplied !== null) {
		const revision = String(supplied).trim();
		if (!SOURCE_REVISION.test(revision)) throw new Error("source revision must be a 40-64 character git SHA");
		return revision.toLowerCase();
	}
	const result = spawnSync("git", ["rev-parse", "HEAD"], {
		cwd: repositoryRoot,
		encoding: "utf8",
		windowsHide: true,
	});
	const revision = String(result.stdout ?? "").trim();
	if (result.status !== 0 || !SOURCE_REVISION.test(revision)) {
		throw new Error("release source revision is unavailable");
	}
	return revision.toLowerCase();
}

function assembledRelease(inputRoot, architecture, version) {
	if (!existsSync(inputRoot) || !lstatSync(inputRoot).isDirectory()) {
		throw new Error(`assembled release root is missing: ${inputRoot}`);
	}
	const identity = windowsTargetIdentity(architecture);
	const metadata = readJson(
		resolveInside(inputRoot, "share/legion/release.json", "release metadata"),
		"assembled release metadata",
	);
	if (
		metadata.releaseVersion !== version
		|| metadata.runtime?.platform !== "windows"
		|| metadata.runtime?.architecture !== identity.architecture
	) {
		throw new Error("assembled release identity does not match requested Windows target");
	}
	const binaries = REQUIRED_BINARIES.map((name) => {
		const path = resolveInside(inputRoot, `bin/${name}`, "release binary");
		if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
			throw new Error(`release binary is missing or unsafe: ${path}`);
		}
		return path;
	});
	const runtimeSha256 = sha256File(binaries[0]);
	if (bareDigest(metadata.runtime.sha256) !== runtimeSha256) {
		throw new Error("assembled release runtime digest mismatch");
	}
	return {
		identity,
		metadata,
		binaries,
		runtimeSha256,
		generation: releaseGeneration(metadata, version, runtimeSha256),
	};
}

function signatureEvidence({ receiptPath, inputRoot, binaries }) {
	if (!receiptPath || !existsSync(receiptPath)) {
		return { status: "missing", reason: "RightRelease Authenticode receipt is required" };
	}
	let receipt;
	try {
		receipt = readJson(receiptPath, "RightRelease Authenticode receipt");
	} catch (error) {
		return { status: "invalid", reason: error.message };
	}
	if (!receipt || typeof receipt !== "object" || Array.isArray(receipt) || receipt.schema !== 1 || !Array.isArray(receipt.files) || receipt.files.length !== binaries.length) {
		return { status: "invalid", reason: "RightRelease Authenticode receipt schema is invalid" };
	}
	const receiptDirectory = dirname(resolve(receiptPath));
	for (const binary of binaries) {
		const matches = receipt.files.filter((entry) => {
			if (!entry?.file) return false;
			return [resolve(entry.file), resolve(receiptDirectory, entry.file)].includes(resolve(binary));
		});
		if (matches.length !== 1) return { status: "invalid", reason: `receipt does not bind ${basename(binary)}` };
		const entry = matches[0];
		if (
			bareDigest(entry.after?.sha256) !== sha256File(binary)
			|| entry.after?.sizeBytes !== statSync(binary).size
			|| entry.authenticode !== "Valid"
			|| entry.subject !== "CN=Damned Ventures LLC"
			|| entry.timestampPresent !== true
		) {
			return { status: "invalid", reason: `receipt does not prove final signed bytes for ${basename(binary)}` };
		}
	}
	return { status: "verified", receipt: resolve(receiptPath), root: resolve(inputRoot) };
}

function qualificationTargetIdentityMatches(observed, expected) {
	if (!observed || typeof observed !== "object" || Array.isArray(observed)) return false;
	const keys = ["platform", "architecture", "nativeArchitecture", "targetTriple", "executable", "artifactId"];
	return Object.keys(observed).length === keys.length
		&& keys.every((key) => observed[key] === expected[key]);
}

function qualificationGatesPass(value) {
	const gates = value?.gates;
	if (!gates || typeof gates !== "object") return false;
	const entries = Array.isArray(gates)
		? gates.map((item) => [item?.name, item])
		: Object.entries(gates);
	if (entries.length !== REQUIRED_QUALIFICATION_GATES.length) return false;
	return REQUIRED_QUALIFICATION_GATES.every((name) => {
		const gate = entries.find(([entryName]) => entryName === name)?.[1];
		return gate?.name === name && gate.status === "pass";
	});
}

export function qualificationEvidence({
	evidencePath,
	archiveDigest,
	runtimeDigest,
	identity,
	releaseVersion: version,
	sourceRevision: revision,
	generation,
}) {
	if (!evidencePath || !existsSync(evidencePath)) {
		return { status: "missing", reason: "native installed-product qualification is required" };
	}
	let value;
	try {
		value = readJson(evidencePath, "Windows qualification evidence");
	} catch (error) {
		return { status: "invalid", reason: error.message };
	}
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return { status: "invalid", reason: "qualification evidence must be a JSON object" };
	}
	if (!SOURCE_REVISION.test(String(revision ?? ""))) {
		return { status: "invalid", reason: "qualification source revision is missing or invalid" };
	}
	const expectedGeneration = generation ?? `${version}:${bareDigest(runtimeDigest)}`;
	const runnerArchitecture = identity.architecture === "x86_64" ? "x64" : "arm64";
	const valid = value.schemaVersion === 1
		&& value.kind === "legion-windows-installed-product-qualification"
		&& value.status === "qualified"
		&& value.nativeExecution === true
		&& value.executionMode === "native"
		&& qualificationTargetIdentityMatches(value.targetIdentity, identity)
		&& value.releaseVersion === version
		&& String(value.sourceRevision).toLowerCase() === revision.toLowerCase()
		&& value.runner?.os === "win32"
		&& value.runner?.architecture === runnerArchitecture
		&& value.runner?.simulated === false
		&& value.origin === WINDOWS_INSTALL_CONTRACT.origin
		&& pathsEqual(value.installRoot, value.install?.root)
		&& pathsEqual(value.executable, value.install?.executable)
		&& value.generation === expectedGeneration
		&& stableInstallBinding(value, expectedGeneration)
		&& stableInstallBinding({ install: value.binding }, expectedGeneration)
		&& pathsEqual(value.binding?.resolvedVersionRoot, value.install?.currentVersionRoot)
		&& isAbsolute(String(value.install?.currentVersionRoot ?? ""))
		&& pathInside(value.install?.versionsRoot, value.install?.currentVersionRoot)
		&& versionRootMatches(value.install?.currentVersionRoot, version, archiveDigest)
		&& !hasForbiddenBindingSegment(value.install?.currentVersionRoot)
		&& pathsEqual(value.install?.versionsRoot, join(value.install?.root ?? "", "versions"))
		&& canonicalPathsEqual(value.install?.versionsRoot, join(value.install?.root ?? "", "versions"))
		&& pathsEqual(value.install?.integrationJournal, join(value.install?.root ?? "", WINDOWS_INSTALL_CONTRACT.integrationJournalName))
		&& value.integrationJournal?.kind === "legion-integration-journal"
		&& value.integrationJournal?.origin === WINDOWS_INSTALL_CONTRACT.origin
		&& pathsEqual(value.integrationJournal?.installRoot, value.install?.root)
		&& pathsEqual(value.integrationJournal?.executable, value.install?.executable)
		&& value.integrationJournal?.generation === expectedGeneration
		&& pathsEqual(value.integrationJournal?.activeVersionRoot, value.install?.currentVersionRoot)
		&& stableInstallBinding({ install: value.integrationJournal?.binding }, expectedGeneration)
		&& pathsEqual(value.integrationJournal?.binding?.resolvedVersionRoot, value.install?.currentVersionRoot)
		&& digestMatches(value.archiveSha256, archiveDigest)
		&& digestMatches(value.runtimeSha256, runtimeDigest)
		&& qualificationGatesPass(value);
	return valid
		? { status: "verified", source: value }
		: { status: "invalid", reason: "qualification is not exact native target/version/source/digest-bound evidence" };
}

export function prepareWindowsArchive({
	input,
	output,
	architecture,
	sourceRevision: suppliedSourceRevision,
	force = false,
	repositoryRoot = REPOSITORY_ROOT,
	createArchive = createPortableArchive,
} = {}) {
	if (!input) throw new Error("--input is required");
	const inputRoot = resolve(input);
	const version = releaseVersion(repositoryRoot);
	const revision = sourceRevision(repositoryRoot, suppliedSourceRevision);
	const assembled = assembledRelease(inputRoot, architecture, version);
	const outputDir = resolve(output ?? join(repositoryRoot, "dist", "releases", "windows", version, assembled.identity.architecture));
	assertReleaseOutputPath(outputDir, repositoryRoot, inputRoot);
	if (existsSync(outputDir) && force) rmSync(outputDir, { recursive: true, force: true });
	mkdirSync(outputDir, { recursive: true });
	const archivePath = join(outputDir, `legion-${version}-windows-${assembled.identity.architecture}.zip`);
	if (existsSync(archivePath) && !force) throw new Error(`release archive exists: ${archivePath}; pass --force to replace it`);
	createArchive({ sourceDir: inputRoot, outputPath: archivePath });
	if (!existsSync(archivePath) || !statSync(archivePath).isFile()) {
		throw new Error(`portable archive is missing: ${archivePath}`);
	}
	const archive = fileRecord(archivePath);
	return {
		status: "archive-prepared",
		outputDir,
		archive: archivePath,
		archiveSha256: archive.sha256,
		runtimeSha256: assembled.runtimeSha256,
		generation: assembled.generation,
		releaseVersion: version,
		sourceRevision: revision,
		targetIdentity: assembled.identity,
	};
}

export function finalizeWindowsDirectRelease({
	input,
	output,
	architecture,
	sourceRevision: suppliedSourceRevision,
	signatureReceipt,
	qualification,
	publishGitHub = false,
	publishBootstrap = false,
	dryRun = false,
	repositoryRoot = REPOSITORY_ROOT,
	createdAt = new Date().toISOString(),
	materializeRelease = materializeDirectRelease,
	publishGitHubFn = publishGitHubRelease,
	publishBootstrapFn = publishBootstrapPlan,
} = {}) {
	if (!input) throw new Error("--input is required");
	if (publishBootstrap && !publishGitHub) throw new Error("bootstrap publication requires GitHub release publication first");
	const inputRoot = resolve(input);
	const version = releaseVersion(repositoryRoot);
	const revision = sourceRevision(repositoryRoot, suppliedSourceRevision);
	const assembled = assembledRelease(inputRoot, architecture, version);
	const outputDir = resolve(output ?? join(repositoryRoot, "dist", "releases", "windows", version, assembled.identity.architecture));
	assertReleaseOutputPath(outputDir, repositoryRoot, inputRoot);
	const archivePath = join(outputDir, `legion-${version}-windows-${assembled.identity.architecture}.zip`);
	if (!existsSync(archivePath) || !statSync(archivePath).isFile()) {
		throw new Error(`prepared release archive is missing: ${archivePath}`);
	}
	const archive = fileRecord(archivePath);
	const signature = signatureEvidence({
		receiptPath: signatureReceipt ? resolve(repositoryRoot, signatureReceipt) : join(repositoryRoot, ".right-release", "receipts", `windows-${assembled.identity.architecture}-raw-exe.json`),
		inputRoot,
		binaries: assembled.binaries,
	});
	if (signature.status !== "verified") throw new Error(`Windows release signing is not verified: ${signature.reason}`);
	const qualificationRecord = qualificationEvidence({
		evidencePath: qualification ? resolve(repositoryRoot, qualification) : join(repositoryRoot, ".right-release", "receipts", `windows-${assembled.identity.architecture}-qualification.json`),
		archiveDigest: archive.sha256,
		runtimeDigest: assembled.runtimeSha256,
		identity: assembled.identity,
		releaseVersion: version,
		sourceRevision: revision,
		generation: assembled.generation,
	});
	if (qualificationRecord.status !== "verified") throw new Error(`Windows release qualification is not verified: ${qualificationRecord.reason}`);

	const evidenceStem = `legion-${version}-windows-${assembled.identity.architecture}`;
	const sbomPath = join(outputDir, `${evidenceStem}.cdx.json`);
	const provenancePath = join(outputDir, `${evidenceStem}.intoto.jsonl`);
	materializeCycloneDxSbom({
		outputPath: sbomPath,
		product: PRODUCT,
		version,
		target: `windows-${assembled.identity.architecture}`,
		sourceCommit: revision,
		files: [archive],
		createdAt,
	});
	materializeInTotoSlsaProvenance({
		outputPath: provenancePath,
		product: PRODUCT,
		version,
		target: `windows-${assembled.identity.architecture}`,
		sourceCommit: revision,
		sourceRepository: SOURCE_REPOSITORY,
		subjects: [archive],
		startedAt: createdAt,
		finishedAt: createdAt,
	});
	const releaseBase = `https://github.com/${GITHUB_REPOSITORY}/releases/download/v${version}`;
	const asset = collectReleaseAsset({
		target: `windows-${assembled.identity.architecture}`,
		name: archive.name,
		url: `${releaseBase}/${archive.name}`,
		archivePath,
		executablePath: "bin/legion.exe",
		nativeSignaturePolicy: "authenticode-valid",
		provenancePath,
		sbomPath,
	});
	if (
		asset.target !== assembled.identity.artifactId
		|| asset.name !== `legion-${version}-windows-${assembled.identity.architecture}.zip`
		|| asset.url !== `${releaseBase}/${archive.name}`
		|| asset.executablePath !== "bin/legion.exe"
		|| asset.nativeSignaturePolicy !== "authenticode-valid"
	) {
		throw new Error("direct release asset identity is not exact for requested Windows target");
	}
	const direct = materializeRelease({
		outputDir,
		manifestInput: {
			product: PRODUCT,
			version,
			sourceCommit: revision,
			minimumBootstrapVersion: BOOTSTRAP_VERSION,
			assets: [asset],
		},
	});
	const checksumsPath = join(outputDir, "checksums.json");
	const bootstrap = renderPowerShellBootstrap({
		product: PRODUCT,
		repository: GITHUB_REPOSITORY,
		bootstrapVersion: BOOTSTRAP_VERSION,
		acceptedManifestSigners: [direct.signing.signer],
		installRootSubdir: WINDOWS_INSTALL_CONTRACT.installRootSubdir,
		executablePath: WINDOWS_INSTALL_CONTRACT.executablePath,
		activationArgs: ["--json", "setup", "repair", "--confirm"],
		statusArgs: ["--json", "setup", "status"],
		healthAssertions: [
			{ path: "kind", equals: "legion-setup-status" },
			{ path: "status", equals: "complete" },
			{ path: "liveIdentity.origin", equals: WINDOWS_INSTALL_CONTRACT.origin },
			{ path: "liveIdentity.executablePath", equals: `{current}/${WINDOWS_INSTALL_CONTRACT.executablePath}` },
			{ path: "liveIdentity.installRoot", equals: "{installRoot}" },
			{ path: "liveIdentity.generation", nonempty: true },
			{ path: "liveIdentity.executable.state", equals: "current" },
			{ path: "liveIdentity.executable.origin", equals: WINDOWS_INSTALL_CONTRACT.origin },
			{ path: "liveIdentity.executable.path", equals: `{current}/${WINDOWS_INSTALL_CONTRACT.executablePath}` },
			{ path: "liveIdentity.executable.installRoot", equals: "{installRoot}" },
			{ path: "liveIdentity.executable.generation", nonempty: true },
			{ path: "liveIdentity.executable.releaseVersion", equals: "{version}" },
			{ path: "liveIdentity.executable.expectedReleaseVersion", equals: "{version}" },
			{ path: "liveIdentity.executable.manifestPath", nonempty: true },
			{ path: "liveIdentity.executable.runtimeDigest", nonempty: true },
		],
	});
	const bootstrapPath = join(outputDir, "install.ps1");
	writeFileSync(bootstrapPath, bootstrap, "utf8");
	const bootstrapValidation = validatePowerShellBootstrap(bootstrap, {
		product: PRODUCT,
		acceptedSignerIds: [direct.signing.signer.id],
	});
	if (!bootstrapValidation.valid) throw new Error(`generated bootstrap is invalid: ${bootstrapValidation.errors.join("; ")}`);

	const githubPlan = prepareGitHubDirectRelease({
		repoRoot: repositoryRoot,
		repo: GITHUB_REPOSITORY,
		product: PRODUCT,
		version,
		manifestPath: direct.manifestPath,
		signaturePath: direct.signaturePath,
		checksumsPath,
		archivePaths: [archivePath],
		provenancePaths: [provenancePath],
		sbomPaths: [sbomPath],
		signing: direct.signing,
	});
	const bootstrapPlan = planBootstrapPublication({
		product: PRODUCT,
		bootstrapVersion: BOOTSTRAP_VERSION,
		scriptPath: bootstrapPath,
	});
	const github = publishGitHub
		? publishGitHubFn(githubPlan, { repo: GITHUB_REPOSITORY, dryRun })
		: { status: "prepared", tag: githubPlan.tag };
	let r2 = { status: "prepared", ...bootstrapPlan };
	if (publishBootstrap && !dryRun) {
		const verificationPath = join(outputDir, ".r2-bootstrap-verification.ps1");
		r2 = publishBootstrapFn(bootstrapPlan, createWranglerR2Client(), { verificationPath });
		rmSync(verificationPath, { force: true });
	} else if (publishBootstrap && dryRun) {
		r2 = { status: "would-publish", ...bootstrapPlan };
	}
	return {
		status: "qualified",
		outputDir,
		archive: archivePath,
		manifest: direct.manifestPath,
		signature: direct.signaturePath,
		checksums: checksumsPath,
		provenance: provenancePath,
		sbom: sbomPath,
		bootstrap: bootstrapPath,
		releaseVersion: version,
	sourceRevision: revision,
	targetIdentity: assembled.identity,
	archiveSha256: archive.sha256,
		runtimeSha256: assembled.runtimeSha256,
		github,
		r2,
	};
}

export function buildWindowsReleasePackage(options = {}) {
	return options.finalize === true
		? finalizeWindowsDirectRelease(options)
		: prepareWindowsArchive(options);
}

function parseArguments(argv) {
	const options = {};
	for (let index = 0; index < argv.length; index += 1) {
		const raw = argv[index];
		if (raw === "--") continue;
		if (["--force", "--finalize", "--publish-github", "--publish-bootstrap", "--dry-run", "--json"].includes(raw)) {
			options[raw.slice(2).replaceAll("-", "")] = true;
			continue;
		}
		if (!raw.startsWith("--")) throw new Error(`unknown argument: ${raw}`);
		const equal = raw.indexOf("=");
		const key = equal === -1 ? raw.slice(2) : raw.slice(2, equal);
		const value = equal === -1 ? argv[++index] : raw.slice(equal + 1);
		if (!value || value.startsWith("--")) throw new Error(`${raw} requires a value`);
		options[key.replaceAll("-", "")] = value;
	}
	return options;
}

function usage(code = 0) {
	console.error("usage: node scripts/package-windows-release.mjs --architecture x86_64|arm64 --input <assembled-root> [--output <dir>] [--source-revision <sha>] [--force] [--finalize --signature-receipt <json> --qualification <json> [--publish-github] [--publish-bootstrap] [--dry-run]] [--json]");
	process.exit(code);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
	try {
		if (process.argv.includes("--help") || process.argv.includes("-h")) usage(0);
		const options = parseArguments(process.argv.slice(2));
		const architecture = options.architecture ?? process.env.LEGION_WINDOWS_ARCH;
		if (!architecture) throw new Error("--architecture is required");
		const normalized = normalizeWindowsArchitecture(architecture);
		const configured = WINDOWS_ARCHITECTURES[normalized];
		const result = buildWindowsReleasePackage({
			input: options.input ?? join(REPOSITORY_ROOT, configured.assemblyRoot),
			output: options.output ?? options.out,
			architecture: normalized,
			sourceRevision: options.sourcerevision,
			signatureReceipt: options.signaturereceipt,
			qualification: options.qualification,
			force: options.force === true,
			finalize: options.finalize === true,
			publishGitHub: options.publishgithub === true,
			publishBootstrap: options.publishbootstrap === true,
			dryRun: options.dryrun === true,
		});
		if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
		else process.stdout.write(`windows direct release ${result.status}: ${result.archive}\n`);
	} catch (error) {
		console.error(`package-windows-release: ${error.message}`);
		process.exit(1);
	}
}
