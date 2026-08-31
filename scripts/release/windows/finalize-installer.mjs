import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { commandDiagnostic, releaseSpawnOptions } from "../process-boundary.mjs";

const MODULE_ROOT = dirname(fileURLToPath(import.meta.url));
const TEMPLATE_PATH = join(MODULE_ROOT, "legion.iss");
const REQUIRED_DIRECTORIES = ["bin", "plugin", "share"];
const REQUIRED_BINARIES = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"];
const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const ARCHITECTURES = new Set(["x86_64", "arm64"]);
const RIGHT_RELEASE_CLI = join(resolve(MODULE_ROOT, "../../.."), "node_modules", "@rightkit", "release", "cli", "right-release.mjs");

function fail(message) { throw new Error(`windows-installer: ${message}`); }

function assertBelow(root, candidate, label) {
	const base = resolve(root);
	const value = resolve(candidate);
	const rel = relative(base, value);
	if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) fail(`${label} must be below ${base}`);
	return value;
}

function assertSafeTree(root, directory = root) {
	for (const entry of readDirectory(directory)) {
		const path = join(directory, entry);
		const metadata = lstatSync(path);
		if (metadata.isSymbolicLink()) fail(`payload contains symlink: ${relative(root, path)}`);
		if (metadata.isDirectory()) assertSafeTree(root, path);
		else if (!metadata.isFile()) fail(`payload contains non-file: ${relative(root, path)}`);
	}
}

function readDirectory(path) {
	return readdirSync(path).sort((a, b) => a.localeCompare(b));
}

function sha256(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function assertRegular(path, label) {
	if (!existsSync(path)) fail(`${label} is missing: ${path}`);
	const metadata = lstatSync(path);
	if (!metadata.isFile() || metadata.isSymbolicLink()) fail(`${label} is not a regular file: ${path}`);
}

function releaseMetadata(root, version, architecture) {
	const path = join(root, "share", "legion", "release.json");
	assertRegular(path, "release metadata");
	let value;
	try { value = JSON.parse(readFileSync(path, "utf8")); } catch { fail("release metadata is invalid JSON"); }
	if (value?.releaseVersion !== version || value?.runtime?.platform !== "windows" || value?.runtime?.architecture !== architecture) {
		fail("release metadata does not match requested Windows identity");
	}
	const runtime = join(root, "bin", "legion.exe");
	if (String(value.runtime.sha256 ?? "").replace(/^sha256:/i, "").toLowerCase() !== sha256(runtime)) fail("release runtime digest mismatch");
	return value;
}

export function installerIdentity({ version, architecture }) {
	if (!SEMVER.test(String(version ?? ""))) fail("version must be stable SemVer");
	if (!ARCHITECTURES.has(architecture)) fail("architecture must be x86_64 or arm64");
	return {
		version,
		architecture,
		name: `Legion-${version}-windows-${architecture}-setup.exe`,
	};
}

export function renderInnoTemplate({ sourceRoot, outputRoot, version, architecture }) {
	const identity = installerIdentity({ version, architecture });
	for (const [label, value] of [["source", sourceRoot], ["output", outputRoot]]) {
		if (!isAbsolute(value)) fail(`${label} root must be absolute`);
		if (/[\r\n"]/u.test(value)) fail(`${label} root contains unsafe Inno directive characters`);
	}
	const template = readFileSync(TEMPLATE_PATH, "utf8");
	const replacements = {
		"@@VERSION@@": version,
		"@@SOURCE_ROOT@@": resolve(sourceRoot),
		"@@OUTPUT_ROOT@@": resolve(outputRoot),
		"@@SETUP_NAME@@": identity.name.replace(/\.exe$/i, ""),
	};
	return Object.entries(replacements).reduce((text, [needle, value]) => text.replaceAll(needle, value), template);
}

export function innoCommand({ scriptPath, isccPath = process.env.INNO_SETUP_PATH ?? "iscc.exe" }) {
	if (!scriptPath || !isAbsolute(scriptPath)) fail("rendered Inno script path must be absolute");
	return { command: isccPath, args: ["/Qp", scriptPath] };
}

export function outerSigningCommand({ installer, receipt }) {
	if (!installer || !isAbsolute(installer) || !receipt || !isAbsolute(receipt)) fail("installer & receipt paths must be absolute");
	return {
		command: process.execPath,
		args: [RIGHT_RELEASE_CLI, "sign-windows", "--receipt", receipt, installer],
	};
}

export function verifySigningCommand({ installer }) {
	if (!installer || !isAbsolute(installer)) fail("installer path must be absolute");
	return { command: process.execPath, args: [RIGHT_RELEASE_CLI, "sign-windows", "--verify-only", installer] };
}

function execute(commandRunner, command, args, cwd) {
	const result = commandRunner(command, args, releaseSpawnOptions({ cwd }));
	if (result?.error || (result?.status !== 0 && result?.exitCode !== 0)) fail(`${basename(command)} failed: ${commandDiagnostic(result)}`);
}

export function finalizeWindowsInstaller({
	inputRoot,
	outputRoot,
	version,
	architecture = "x86_64",
	receiptPath,
	renderedScriptPath,
	commandRunner = spawnSync,
} = {}) {
	if (!inputRoot || !outputRoot) fail("--input-root & --output are required");
	const source = resolve(inputRoot);
	const output = resolve(outputRoot);
	if (!existsSync(source) || !lstatSync(source).isDirectory() || lstatSync(source).isSymbolicLink()) fail("input root must be a real directory");
	const outputFromSource = relative(source, output);
	if (!outputFromSource || (!outputFromSource.startsWith(`..${sep}`) && outputFromSource !== ".." && !isAbsolute(outputFromSource))) {
		fail("output must not be inside signed payload root");
	}
	for (const directory of REQUIRED_DIRECTORIES) {
		const path = join(source, directory);
		if (!existsSync(path) || !lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink()) fail(`payload directory missing or unsafe: ${directory}`);
	}
	for (const binary of REQUIRED_BINARIES) assertRegular(join(source, "bin", binary), `payload binary ${binary}`);
	assertSafeTree(source);
	const metadata = releaseMetadata(source, version, architecture);
	const identity = installerIdentity({ version, architecture });
	mkdirSync(output, { recursive: true });
	const scriptPath = resolve(renderedScriptPath ?? join(output, `${identity.name}.iss`));
	assertBelow(output, scriptPath, "rendered Inno script");
	const rendered = renderInnoTemplate({ sourceRoot: source, outputRoot: output, version, architecture });
	// Deliberately written by caller-owned integration seam to permit a durable
	// rendered script.  Inno only accepts a file path, never stdin.
	writeFileSync(scriptPath, rendered, "utf8");
	const installer = join(output, identity.name);
	const inno = innoCommand({ scriptPath });
	execute(commandRunner, inno.command, inno.args, output);
	assertRegular(installer, "Inno setup executable");
	const receipt = resolve(receiptPath ?? join(output, `${identity.name}.signing.json`));
	const sign = outerSigningCommand({ installer, receipt });
	execute(commandRunner, sign.command, sign.args, output);
	const verify = verifySigningCommand({ installer });
	execute(commandRunner, verify.command, verify.args, output);
	assertRegular(receipt, "installer signing receipt");
	return {
		status: "signed",
		installer,
		sha256: sha256(installer),
		sizeBytes: statSync(installer).size,
		receipt,
		identity,
		runtimeSha256: String(metadata.runtime.sha256).replace(/^sha256:/i, "").toLowerCase(),
	};
}

function option(name) {
	const index = process.argv.indexOf(name);
	return index < 0 ? undefined : process.argv[index + 1];
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		const result = finalizeWindowsInstaller({
			inputRoot: option("--input-root") ?? process.env.LEGION_SIGNED_RELEASE_ROOT,
			outputRoot: option("--output") ?? process.env.LEGION_WINDOWS_INSTALLER_OUTPUT,
			version: option("--version") ?? process.env.LEGION_RELEASE_VERSION,
			architecture: option("--architecture") ?? process.env.RIGHT_GIT_RELEASE_ARCHITECTURE ?? "x86_64",
			receiptPath: option("--receipt") ?? process.env.LEGION_WINDOWS_INSTALLER_RECEIPT,
		});
		process.stdout.write(`${JSON.stringify(result)}\n`);
	} catch (error) {
		process.stderr.write(`${error.message}\n`);
		process.exitCode = 1;
	}
}
