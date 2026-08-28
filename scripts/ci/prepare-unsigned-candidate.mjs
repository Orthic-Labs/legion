import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	statSync,
	writeFileSync,
} from "node:fs";
import {
	basename,
	dirname,
	join,
	relative,
	resolve,
	sep,
} from "node:path";
import { fileURLToPath } from "node:url";
import { createPortableArchive } from "@rightkit/release/direct-bootstrap.mjs";
import {
	materializeCycloneDxSbom,
	materializeInTotoSlsaProvenance,
	validateCycloneDxSbom,
	validateInTotoSlsaProvenance,
} from "@rightkit/release/supply-chain-evidence.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const PRODUCT = "legion";
const SOURCE_REPOSITORY = "https://github.com/Orthic-Labs/legion";
const CANDIDATE_ROOT_NAME = "legion-unsigned-candidate";
const CANDIDATE_FILE = "candidate.json";
const CANDIDATE_KIND = "legion-unsigned-release-candidate";
const STABLE_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const SOURCE_REVISION = /^[a-f0-9]{40,64}$/i;
const SHA256 = /^[a-f0-9]{64}$/;

function normalizePlatform(value) {
	const platform = String(value ?? "").trim().toLowerCase();
	if (platform === "win32" || platform === "win" || platform === "windows") return "windows";
	if (platform === "darwin" || platform === "mac" || platform === "macos") return "macos";
	return null;
}

export function normalizeArchitecture(value) {
	const architecture = String(value ?? "").trim().toLowerCase();
	if (["x64", "amd64", "x86_64"].includes(architecture)) return "x86_64";
	if (["arm64", "aarch64"].includes(architecture)) return "arm64";
	return null;
}

export function inferTarget({ platform = process.platform, architecture = process.arch } = {}) {
	const normalizedPlatform = normalizePlatform(platform);
	if (!normalizedPlatform) return null;
	const normalizedArchitecture = normalizeArchitecture(architecture);
	if (!normalizedArchitecture) {
		throw new Error(`unsupported ${normalizedPlatform} architecture: ${architecture}`);
	}
	return {
		platform: normalizedPlatform,
		architecture: normalizedArchitecture,
		target: `${normalizedPlatform}-${normalizedArchitecture}`,
	};
}

function readStableVersion(repositoryRoot, suppliedVersion) {
	const record = JSON.parse(readFileSync(join(repositoryRoot, "release", "version.json"), "utf8"));
	if (record.schemaVersion !== 1 || record.kind !== "legion-release-version") {
		throw new Error("release/version.json must be the canonical release version record");
	}
	const version = suppliedVersion ?? record.version;
	if (!STABLE_VERSION.test(String(version ?? ""))) {
		throw new Error(`release version must be stable SemVer: ${version}`);
	}
	return String(version);
}

function readSourceRevision(repositoryRoot, suppliedSourceRevision) {
	if (suppliedSourceRevision !== undefined && suppliedSourceRevision !== null) {
		const revision = String(suppliedSourceRevision).trim().toLowerCase();
		if (!SOURCE_REVISION.test(revision)) {
			throw new Error("source revision must be a 40-64 character git SHA");
		}
		return revision;
	}
	const result = spawnSync("git", ["rev-parse", "HEAD"], {
		cwd: repositoryRoot,
		encoding: "utf8",
		windowsHide: true,
	});
	const revision = String(result.stdout ?? "").trim().toLowerCase();
	if (result.status !== 0 || !SOURCE_REVISION.test(revision)) {
		throw new Error("release source revision is unavailable");
	}
	return revision;
}

function configuredPath(value, label) {
	const path = String(value ?? "").trim();
	if (!path) throw new Error(`${label} is required`);
	return resolve(path);
}

function resolveInputRoot(input, env) {
	return configuredPath(input ?? (env.RUNNER_TEMP ? join(env.RUNNER_TEMP, "legion-install") : null), "assembled install root");
}

export function resolveArtifactRoot(outputRoot, env = process.env) {
	const configured = outputRoot
		?? env.RIGHT_GIT_ARTIFACT_ROOT
		?? (env.RUNNER_TEMP ? join(env.RUNNER_TEMP, CANDIDATE_ROOT_NAME) : null);
	return configuredPath(configured, "RIGHT_GIT_ARTIFACT_ROOT or RUNNER_TEMP");
}

function assertDirectory(path, label) {
	if (!existsSync(path) || !statSync(path).isDirectory()) {
		throw new Error(`${label} is missing: ${path}`);
	}
}

function assertRegularFile(path, label) {
	if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
		throw new Error(`${label} is missing or unsafe: ${path}`);
	}
}

function assertOutside(sourceRoot, destinationRoot) {
	const rel = relative(sourceRoot, destinationRoot);
	if (!rel || (rel !== ".." && !rel.startsWith(`..${sep}`))) {
		throw new Error(`candidate artifacts must be outside assembled install root: ${destinationRoot}`);
	}
}

function sha256File(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function fileRecord(path) {
	return {
		name: basename(path),
		size: statSync(path).size,
		sha256: sha256File(path),
	};
}

function timestamp(value, env) {
	if (value) return String(value);
	if (env.SOURCE_DATE_EPOCH) {
		const epoch = Number(env.SOURCE_DATE_EPOCH);
		if (Number.isSafeInteger(epoch) && epoch >= 0) return new Date(epoch * 1000).toISOString();
	}
	return new Date().toISOString();
}

function property(properties, name) {
	return properties?.find((entry) => entry?.name === name)?.value;
}

function argument(args, names) {
	for (const name of names) {
		const index = args.indexOf(name);
		if (index === -1) continue;
		const value = args[index + 1];
		if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
		return value;
	}
	return undefined;
}

function runCommand(command, args, options, label, commandRunner) {
	const result = commandRunner(command, args, options);
	if (result?.error) throw result.error;
	if (result?.status !== 0) throw new Error(`${label} failed with exit code ${result?.status ?? "unknown"}`);
}

function assembleAndSmoke({ inputRoot, identity, repositoryRoot, env, commandRunner }) {
	const commandEnv = { ...process.env, ...env };
	const targetTriple = identity.platform === "windows"
		? identity.architecture === "arm64" ? "aarch64-pc-windows-msvc" : "x86_64-pc-windows-msvc"
		: null;
	runCommand(
		"pnpm",
		["legion:check"],
		{ cwd: repositoryRoot, env: commandEnv, stdio: "inherit", windowsHide: true },
		"Legion consistency gate",
		commandRunner,
	);
	runCommand(
		"pnpm",
		["test"],
		{ cwd: repositoryRoot, env: commandEnv, stdio: "inherit", windowsHide: true },
		"Node tests",
		commandRunner,
	);
	runCommand(
		"cargo",
		["test", "--locked"],
		{ cwd: join(repositoryRoot, "engine"), env: commandEnv, stdio: "inherit", windowsHide: true },
		"Cargo tests",
		commandRunner,
	);
	runCommand(
		"cargo",
		["build", "--locked", "--bins", ...(targetTriple ? ["--target", targetTriple] : [])],
		{ cwd: join(repositoryRoot, "engine"), env: commandEnv, stdio: "inherit", windowsHide: true },
		"cargo build",
		commandRunner,
	);
	runCommand(
		"pnpm",
		[
			"native:assemble",
			"--",
			"--profile",
			"debug",
			"--platform",
			identity.platform,
			"--architecture",
			identity.architecture,
			...(targetTriple ? ["--target", targetTriple] : []),
			"--out",
			inputRoot,
			"--force",
		],
		{ cwd: repositoryRoot, env: commandEnv, stdio: "inherit", windowsHide: true },
		"native assembly",
		commandRunner,
	);
	runCommand(
		process.execPath,
		[join(repositoryRoot, "scripts", "ci", "native-installed-smoke.mjs"), inputRoot],
		{ cwd: repositoryRoot, env: commandEnv, stdio: "inherit", windowsHide: true },
		"installed-product smoke",
		commandRunner,
	);
}

/**
 * Prepare an unsigned public CI candidate from an already assembled install.
 * This seam intentionally stops at archive, SBOM, and provenance materialization.
 */
export function prepareUnsignedCandidate({
	input,
	outputRoot,
	platform,
	architecture,
	repositoryRoot = REPOSITORY_ROOT,
	sourceRevision,
	version,
	createdAt,
	env = process.env,
	createArchive = createPortableArchive,
	commandRunner = spawnSync,
} = {}) {
	const identity = inferTarget({ platform, architecture });
	if (!identity) {
		throw new Error(`unsigned public candidates require Windows or macOS: ${platform ?? process.platform}`);
	}

	const inputRoot = resolveInputRoot(input, env);
	const artifactRoot = resolveArtifactRoot(outputRoot, env);
	assertOutside(inputRoot, artifactRoot);
	if (input === undefined && !existsSync(inputRoot)) {
		assembleAndSmoke({ inputRoot, identity, repositoryRoot, env, commandRunner });
	}
	assertDirectory(inputRoot, "assembled install root");
	mkdirSync(artifactRoot, { recursive: true });

	const releaseVersion = readStableVersion(repositoryRoot, version);
	const revision = readSourceRevision(repositoryRoot, sourceRevision);
	const target = identity.target;
	const stem = `${PRODUCT}-${releaseVersion}-${target}`;
	const archivePath = join(artifactRoot, `${stem}${identity.platform === "macos" ? ".tar.gz" : ".zip"}`);
	const sbomPath = join(artifactRoot, `${stem}.cdx.json`);
	const provenancePath = join(artifactRoot, `${stem}.intoto.jsonl`);

	const archiveResult = createArchive({ sourceDir: inputRoot, outputPath: archivePath });
	assertRegularFile(archivePath, "portable archive");
	const archiveSize = statSync(archivePath).size;
	if (!Number.isSafeInteger(archiveSize) || archiveSize < 1) {
		throw new Error(`portable archive is empty: ${archivePath}`);
	}
	const archiveSha256 = sha256File(archivePath);
	if (archiveResult?.sha256 && String(archiveResult.sha256).replace(/^sha256:/i, "").toLowerCase() !== archiveSha256) {
		throw new Error(`portable archive digest changed during preparation: ${archivePath}`);
	}
	const archive = { name: basename(archivePath), size: archiveSize, sha256: archiveSha256 };
	const evidenceTimestamp = timestamp(createdAt, env);

	materializeCycloneDxSbom({
		outputPath: sbomPath,
		product: PRODUCT,
		version: releaseVersion,
		target,
		sourceCommit: revision,
		files: [archive],
		createdAt: evidenceTimestamp,
	});
	materializeInTotoSlsaProvenance({
		outputPath: provenancePath,
		product: PRODUCT,
		version: releaseVersion,
		target,
		sourceCommit: revision,
		sourceRepository: SOURCE_REPOSITORY,
		subjects: [archive],
		startedAt: evidenceTimestamp,
		finishedAt: evidenceTimestamp,
	});
	const candidate = {
		schemaVersion: 1,
		kind: CANDIDATE_KIND,
		product: PRODUCT,
		version: releaseVersion,
		target,
		sourceRevision: revision,
		files: {
			archive: fileRecord(archivePath),
			sbom: fileRecord(sbomPath),
			provenance: fileRecord(provenancePath),
		},
	};
	const candidatePath = join(artifactRoot, CANDIDATE_FILE);
	writeFileSync(candidatePath, `${JSON.stringify(candidate, null, 2)}\n`);

	return {
		status: "complete",
		product: PRODUCT,
		version: releaseVersion,
		target,
		platform: identity.platform,
		architecture: identity.architecture,
		sourceRevision: revision,
		inputRoot,
		outputRoot: artifactRoot,
		archive: archivePath,
		archiveSha256,
		sbom: sbomPath,
		provenance: provenancePath,
		candidate: candidatePath,
	};
}

/**
 * Independently verify the expected unsigned candidate files already present
 * in the CI artifact root. This performs no build or materialization.
 */
export function checkUnsignedCandidate({
	outputRoot,
	platform,
	architecture,
	repositoryRoot = REPOSITORY_ROOT,
	sourceRevision,
	version,
	env = process.env,
} = {}) {
	const identity = inferTarget({ platform, architecture });
	if (!identity) {
		throw new Error(`unsigned public candidates require Windows or macOS: ${platform ?? process.platform}`);
	}

	const artifactRoot = resolveArtifactRoot(outputRoot, env);
	const releaseVersion = readStableVersion(repositoryRoot, version);
	const revision = readSourceRevision(repositoryRoot, sourceRevision);
	const target = identity.target;
	const stem = `${PRODUCT}-${releaseVersion}-${target}`;
	const archivePath = join(artifactRoot, `${stem}${identity.platform === "macos" ? ".tar.gz" : ".zip"}`);
	const sbomPath = join(artifactRoot, `${stem}.cdx.json`);
	const provenancePath = join(artifactRoot, `${stem}.intoto.jsonl`);
	const candidatePath = join(artifactRoot, CANDIDATE_FILE);
	if (!existsSync(artifactRoot) || !statSync(artifactRoot).isDirectory()) {
		throw new Error(`candidate artifact root is missing: ${artifactRoot}`);
	}
	const expectedRootFiles = new Set([CANDIDATE_FILE, basename(archivePath), basename(sbomPath), basename(provenancePath)]);
	const rootEntries = readdirSync(artifactRoot, { withFileTypes: true });
	if (rootEntries.length !== expectedRootFiles.size || rootEntries.some((entry) => !expectedRootFiles.has(entry.name))) {
		throw new Error("candidate artifact root must contain exactly candidate.json, archive, SBOM, and provenance");
	}
	for (const [path, label] of [
		[candidatePath, CANDIDATE_FILE],
		[archivePath, "portable archive"],
		[sbomPath, "CycloneDX SBOM"],
		[provenancePath, "in-toto provenance"],
	]) {
		assertRegularFile(path, label);
	}

	const candidate = JSON.parse(readFileSync(candidatePath, "utf8"));
	const candidateKeys = Object.keys(candidate).sort();
	if (candidateKeys.join(",") !== "files,kind,product,schemaVersion,sourceRevision,target,version") {
		throw new Error("candidate.json schema is invalid");
	}
	if (
		candidate.schemaVersion !== 1
		|| candidate.kind !== CANDIDATE_KIND
		|| candidate.product !== PRODUCT
		|| candidate.version !== releaseVersion
		|| candidate.target !== target
		|| candidate.sourceRevision !== revision
	) {
		throw new Error("candidate.json identity does not match unsigned candidate");
	}
	const fileRoles = ["archive", "sbom", "provenance"];
	if (!candidate.files || typeof candidate.files !== "object" || Array.isArray(candidate.files) || Object.keys(candidate.files).sort().join(",") !== [...fileRoles].sort().join(",")) {
		throw new Error("candidate.json files must contain exactly archive, sbom, and provenance");
	}
	const archive = {
		name: basename(archivePath),
		size: statSync(archivePath).size,
		sha256: sha256File(archivePath),
	};
	if (!Number.isSafeInteger(archive.size) || archive.size < 1) throw new Error(`portable archive is empty: ${archivePath}`);
	for (const [role, path] of [["archive", archivePath], ["sbom", sbomPath], ["provenance", provenancePath]]) {
		const expected = candidate.files[role];
		const observed = fileRecord(path);
		if (
			!expected
			|| Object.keys(expected).sort().join(",") !== "name,sha256,size"
			|| expected.name !== observed.name
			|| expected.size !== observed.size
			|| !SHA256.test(expected.sha256 ?? "")
			|| expected.sha256 !== observed.sha256
		) {
			throw new Error(`candidate file digest or size mismatch: ${role}`);
		}
	}
	const sbom = validateCycloneDxSbom(sbomPath, { expectedFile: archive });
	if (
		sbom.metadata?.component?.name !== PRODUCT
		|| sbom.metadata.component.version !== releaseVersion
		|| property(sbom.metadata.component.properties, "rightkit:target") !== target
		|| property(sbom.metadata.component.properties, "rightkit:sourceCommit") !== revision
	) {
		throw new Error("CycloneDX identity does not match unsigned candidate");
	}
	const provenance = validateInTotoSlsaProvenance(provenancePath, {
		expectedSubject: { name: archive.name, sha256: archive.sha256 },
	});
	const buildDefinition = provenance.predicate?.buildDefinition;
	const dependency = buildDefinition?.resolvedDependencies?.[0];
	if (
		buildDefinition?.externalParameters?.product !== PRODUCT
		|| buildDefinition.externalParameters.version !== releaseVersion
		|| buildDefinition.externalParameters.target !== target
		|| dependency?.digest?.gitCommit !== revision
		|| dependency?.uri !== `git+${SOURCE_REPOSITORY}@${revision}`
	) {
		throw new Error("in-toto identity does not match unsigned candidate");
	}

	return {
		status: "verified",
		product: PRODUCT,
		version: releaseVersion,
		target,
		platform: identity.platform,
		architecture: identity.architecture,
		sourceRevision: revision,
		outputRoot: artifactRoot,
		archive: archivePath,
		archiveSha256: archive.sha256,
		sbom: sbomPath,
		provenance: provenancePath,
		candidate: candidatePath,
	};
}

function main() {
	const args = process.argv.slice(2);
	const options = {
		input: argument(args, ["--input"]),
		outputRoot: argument(args, ["--output", "--out"]),
		platform: argument(args, ["--platform"]),
		architecture: argument(args, ["--architecture", "--arch"]),
		sourceRevision: argument(args, ["--source-revision", "--source-sha"]),
		version: argument(args, ["--version"]),
		createdAt: argument(args, ["--created-at"]),
	};
	const result = args.includes("--check") ? checkUnsignedCandidate(options) : prepareUnsignedCandidate(options);
	process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) main();
