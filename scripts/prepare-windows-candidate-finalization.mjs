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
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkUnsignedCandidate } from "./ci/prepare-unsigned-candidate.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function argument(name) {
	const index = process.argv.indexOf(name);
	return index >= 0 ? process.argv[index + 1] : undefined;
}

function assertOwnedOutput(path, repositoryRoot) {
	const root = resolve(repositoryRoot, "dist", "native");
	const value = resolve(path);
	const rel = relative(root, value);
	if (!rel || rel.startsWith("..") || isAbsolute(rel)) {
		throw new Error(`candidate extraction output must be below ${root}`);
	}
	return value;
}

function findReleaseRoot(extracted) {
	const candidates = [extracted];
	for (const name of readdirSync(extracted)) {
		const path = join(extracted, name);
		if (lstatSync(path).isDirectory()) candidates.push(path);
	}
	const matches = candidates.filter((path) => existsSync(join(path, "bin", "legion.exe")));
	if (matches.length !== 1) throw new Error("candidate archive must contain exactly one Legion release root");
	return matches[0];
}

export function prepareWindowsCandidateFinalization({
	candidateRoot,
	outputRoot,
	architecture,
	sourceRevision,
	version,
	receiptPath,
	repositoryRoot = REPOSITORY_ROOT,
} = {}) {
	if (!candidateRoot) throw new Error("LEGION_UNSIGNED_CANDIDATE_ROOT or --candidate is required");
	const output = assertOwnedOutput(outputRoot, repositoryRoot);
	const checked = checkUnsignedCandidate({
		outputRoot: resolve(candidateRoot),
		repositoryRoot,
		platform: "windows",
		architecture,
		sourceRevision,
		version,
		env: {},
	});
	const staging = `${output}.candidate-extract-${process.pid}`;
	rmSync(staging, { recursive: true, force: true });
	rmSync(output, { recursive: true, force: true });
	mkdirSync(staging, { recursive: true });
	try {
		const command = spawnSync(
			"powershell.exe",
			[
				"-NoLogo",
				"-NoProfile",
				"-NonInteractive",
				"-Command",
				"Expand-Archive -LiteralPath $env:LEGION_CANDIDATE_ARCHIVE -DestinationPath $env:LEGION_CANDIDATE_STAGING -Force",
			],
			{
				cwd: repositoryRoot,
				encoding: "utf8",
				windowsHide: true,
				env: { ...process.env, LEGION_CANDIDATE_ARCHIVE: checked.archive, LEGION_CANDIDATE_STAGING: staging },
			},
		);
		if (command.error) throw command.error;
		if (command.status !== 0) throw new Error(`candidate extraction failed: ${(command.stderr || command.stdout || "").trim()}`);
		cpSync(findReleaseRoot(staging), output, { recursive: true, errorOnExist: true });
	} finally {
		rmSync(staging, { recursive: true, force: true });
	}
	const files = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"].map((name) => {
		const path = join(output, "bin", name);
		if (!existsSync(path) || !statSync(path).isFile()) throw new Error(`candidate executable missing: ${name}`);
		return {
			file: `bin/${name}`,
			sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
			sizeBytes: statSync(path).size,
		};
	});
	const receipt = {
		schema: 1,
		kind: "legion-windows-candidate-input",
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

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const result = prepareWindowsCandidateFinalization({
		candidateRoot: argument("--candidate") ?? process.env.LEGION_UNSIGNED_CANDIDATE_ROOT,
		outputRoot: argument("--output"),
		architecture: argument("--architecture") ?? process.env.LEGION_WINDOWS_ARCH ?? "x86_64",
		sourceRevision: argument("--source-revision") ?? process.env.LEGION_SOURCE_REVISION,
		version: argument("--version"),
		receiptPath: argument("--receipt"),
	});
	process.stdout.write(`${JSON.stringify(result)}\n`);
}
