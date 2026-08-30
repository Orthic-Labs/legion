import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	cpSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createPortableArchive } from "@rightkit/release/direct-bootstrap.mjs";
import {
	materializeCycloneDxSbom,
	materializeInTotoSlsaProvenance,
} from "@rightkit/release/supply-chain-evidence.mjs";
import { checkUnsignedCandidate } from "./ci/prepare-unsigned-candidate.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXECUTABLES = Object.freeze(["legion", "legion-hook", "legion-mcp"]);

function argument(name) {
	const index = process.argv.indexOf(name);
	return index >= 0 ? process.argv[index + 1] : undefined;
}

function assertBelow(path, root, label) {
	const value = resolve(path);
	const rel = relative(resolve(root), value);
	if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new Error(`${label} must be below ${resolve(root)}`);
	return value;
}

function sha256File(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function assertSafeArchiveEntries(archive, commandRunner) {
	const listed = commandRunner("tar", ["-tzf", basename(archive)], {
		cwd: dirname(archive),
		encoding: "utf8",
		windowsHide: true,
	});
	if (listed.error) throw listed.error;
	if (listed.status !== 0) throw new Error(`candidate listing failed: ${(listed.stderr || listed.stdout || "").trim()}`);
	for (const raw of String(listed.stdout).split(/\r?\n/).filter(Boolean)) {
		if (raw === "./" || raw === ".") continue;
		const entry = raw.replace(/^\.\//, "");
		if (!entry || entry.startsWith("/") || /^[A-Za-z]:/.test(entry) || entry.split("/").includes("..")) {
			throw new Error(`unsafe candidate archive entry: ${raw}`);
		}
	}
}

function assertSafeTree(root, directory = root) {
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		const path = join(directory, entry.name);
		const metadata = lstatSync(path);
		if (metadata.isSymbolicLink()) throw new Error(`candidate archive contains symlink: ${relative(root, path)}`);
		if (metadata.isDirectory()) assertSafeTree(root, path);
		else if (!metadata.isFile()) throw new Error(`candidate archive contains non-file: ${relative(root, path)}`);
	}
}

function findReleaseRoot(extracted) {
	const candidates = [extracted];
	for (const name of readdirSync(extracted)) {
		const path = join(extracted, name);
		if (lstatSync(path).isDirectory()) candidates.push(path);
	}
	const matches = candidates.filter((path) => existsSync(join(path, "bin", "legion")));
	if (matches.length !== 1) throw new Error("candidate archive must contain exactly one Legion release root");
	return matches[0];
}

function executableRecords(root) {
	return EXECUTABLES.map((name) => {
		const path = join(root, "bin", name);
		if (!existsSync(path) || !statSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
			throw new Error(`candidate executable missing or unsafe: ${name}`);
		}
		return { file: `bin/${name}`, sha256: sha256File(path), sizeBytes: statSync(path).size };
	});
}

export function prepareMacosCandidateFinalization({
	candidateRoot,
	outputRoot,
	architecture = "arm64",
	sourceRevision,
	version,
	receiptPath,
	repositoryRoot = REPOSITORY_ROOT,
	commandRunner = spawnSync,
} = {}) {
	if (!candidateRoot) throw new Error("LEGION_UNSIGNED_CANDIDATE_ROOT or --candidate is required");
	const output = assertBelow(outputRoot, join(repositoryRoot, "dist", "native"), "candidate extraction output");
	const checked = checkUnsignedCandidate({
		outputRoot: resolve(candidateRoot),
		repositoryRoot,
		platform: "macos",
		architecture,
		sourceRevision,
		version,
		env: {},
	});
	assertSafeArchiveEntries(checked.archive, commandRunner);
	const staging = `${output}.candidate-extract-${process.pid}`;
	rmSync(staging, { recursive: true, force: true });
	rmSync(output, { recursive: true, force: true });
	mkdirSync(staging, { recursive: true });
	try {
		const extracted = commandRunner("tar", ["-xzf", basename(checked.archive), "-C", staging], {
			cwd: dirname(checked.archive),
			encoding: "utf8",
			windowsHide: true,
		});
		if (extracted.error) throw extracted.error;
		if (extracted.status !== 0) throw new Error(`candidate extraction failed: ${(extracted.stderr || extracted.stdout || "").trim()}`);
		assertSafeTree(staging);
		cpSync(findReleaseRoot(staging), output, { recursive: true, errorOnExist: true });
	} finally {
		rmSync(staging, { recursive: true, force: true });
	}
	const files = executableRecords(output);
	const receipt = {
		schema: 1,
		kind: "legion-macos-candidate-input",
		status: "verified",
		candidateArchive: checked.archive,
		candidateArchiveSha256: checked.archiveSha256,
		sourceRevision: checked.sourceRevision,
		version: checked.version,
		architecture: checked.architecture,
		output,
		files,
	};
	if (receiptPath) {
		const resolvedReceipt = resolve(receiptPath);
		mkdirSync(dirname(resolvedReceipt), { recursive: true });
		writeFileSync(resolvedReceipt, `${JSON.stringify(receipt, null, 2)}\n`);
	}
	return { ...receipt, receipt: receiptPath ? resolve(receiptPath) : null };
}

export function packageMacosCandidate({
	inputRoot,
	outputRoot,
	notarizationArchive,
	version,
	architecture = "arm64",
	sourceRevision,
	repositoryRoot = REPOSITORY_ROOT,
	createdAt = new Date().toISOString(),
	commandRunner = spawnSync,
	createArchive = createPortableArchive,
} = {}) {
	const input = assertBelow(inputRoot, join(repositoryRoot, "dist", "native"), "signed macOS input");
	const output = assertBelow(outputRoot, join(repositoryRoot, "dist", "releases", "mac"), "signed macOS output");
	const notaryZip = assertBelow(notarizationArchive, join(repositoryRoot, ".right-release", "notary"), "notarization archive");
	if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(String(version ?? ""))) throw new Error("stable version is required");
	if (!/^[a-f0-9]{40,64}$/i.test(String(sourceRevision ?? ""))) throw new Error("source revision is required");
	executableRecords(input);
	mkdirSync(output, { recursive: true });
	mkdirSync(dirname(notaryZip), { recursive: true });
	const stem = `legion-${version}-macos-${architecture}`;
	const archive = join(output, `${stem}.tar.gz`);
	const sbom = join(output, `${stem}.cdx.json`);
	const provenance = join(output, `${stem}.intoto.jsonl`);
	createArchive({ sourceDir: input, outputPath: archive, commandRunner });
	const zipped = commandRunner("ditto", ["-c", "-k", "--keepParent", input, notaryZip], {
		cwd: repositoryRoot,
		encoding: "utf8",
		windowsHide: true,
	});
	if (zipped.error) throw zipped.error;
	if (zipped.status !== 0) throw new Error(`notarization archive failed: ${(zipped.stderr || zipped.stdout || "").trim()}`);
	if (!existsSync(notaryZip) || !statSync(notaryZip).isFile()) throw new Error(`notarization archive missing: ${notaryZip}`);
	const signedArchive = { name: basename(archive), size: statSync(archive).size, sha256: sha256File(archive) };
	materializeCycloneDxSbom({
		outputPath: sbom,
		product: "legion",
		version,
		target: `macos-${architecture}`,
		sourceCommit: sourceRevision,
		files: [signedArchive],
		createdAt,
	});
	materializeInTotoSlsaProvenance({
		outputPath: provenance,
		product: "legion",
		version,
		target: `macos-${architecture}`,
		sourceCommit: sourceRevision,
		sourceRepository: "https://github.com/Orthic-Labs/legion",
		subjects: [signedArchive],
		startedAt: createdAt,
		finishedAt: createdAt,
	});
	return { archive, archiveSha256: signedArchive.sha256, sbom, provenance, notarizationArchive: notaryZip };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const mode = process.argv.includes("--package") ? "package" : "prepare";
	const result = mode === "prepare"
		? prepareMacosCandidateFinalization({
			candidateRoot: argument("--candidate") ?? process.env.LEGION_UNSIGNED_CANDIDATE_ROOT,
			outputRoot: argument("--output"),
			architecture: argument("--architecture") ?? "arm64",
			sourceRevision: argument("--source-revision") ?? process.env.LEGION_SOURCE_REVISION,
			version: argument("--version"),
			receiptPath: argument("--receipt"),
		})
		: packageMacosCandidate({
			inputRoot: argument("--input"),
			outputRoot: argument("--output"),
			notarizationArchive: argument("--notarization-archive"),
			architecture: argument("--architecture") ?? "arm64",
			sourceRevision: argument("--source-revision") ?? process.env.LEGION_SOURCE_REVISION,
			version: argument("--version"),
		});
	process.stdout.write(`${JSON.stringify(result)}\n`);
}
