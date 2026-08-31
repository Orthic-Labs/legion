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
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(HERE, "../../..");
const EXECUTABLES = Object.freeze(["legion", "legion-hook", "legion-mcp"]);
const APP_NAME = "Legion Installer.app";
const APP_IDENTIFIER = "com.orthiclabs.legion.installer";

function safeVersion(value) {
	if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(String(value ?? ""))) {
		throw new Error("stable version is required");
	}
	return String(value);
}

function required(value, name) {
	if (!value) throw new Error(`${name} is required`);
	return value;
}

function below(path, root, label) {
	const result = resolve(path);
	const rel = relative(resolve(root), result);
	if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new Error(`${label} must be below ${resolve(root)}`);
	return result;
}

function sha256(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function safeTree(root, directory = root) {
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		const path = join(directory, entry.name);
		const metadata = lstatSync(path);
		if (metadata.isSymbolicLink()) throw new Error(`portable release contains symlink: ${relative(root, path)}`);
		if (metadata.isDirectory()) safeTree(root, path);
		else if (!metadata.isFile()) throw new Error(`portable release contains non-file: ${relative(root, path)}`);
	}
}

export function assertFinalizedPortableRelease({ inputRoot, version } = {}) {
	const root = resolve(required(inputRoot, "RIGHT_GIT_FINALIZED_MACOS_ROOT"));
	if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`finalized macOS release root missing: ${root}`);
	safeVersion(version);
	safeTree(root);
	for (const directory of ["bin", "plugin", "share"]) {
		const path = join(root, directory);
		if (!existsSync(path) || !statSync(path).isDirectory()) throw new Error(`finalized macOS release missing ${directory}/`);
	}
	for (const executable of EXECUTABLES) {
		const path = join(root, "bin", executable);
		if (!existsSync(path) || !statSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
			throw new Error(`finalized macOS release missing safe bin/${executable}`);
		}
	}
	return root;
}

export function macosInstallerPlan({ inputRoot, outputRoot, version, developerId, apiKeyPath, apiKey, apiIssuer } = {}) {
	const stableVersion = safeVersion(version);
	const input = assertFinalizedPortableRelease({ inputRoot, version: stableVersion });
	const output = resolve(required(outputRoot, "RIGHT_GIT_FINALIZED_MACOS_ROOT output"));
	const app = join(output, APP_NAME);
	const dmg = join(output, `legion-${stableVersion}-macos-installer.dmg`);
	const receipt = join(output, `legion-${stableVersion}-macos-installer-finalization.json`);
	if (!developerId) throw new Error("APPLE_DEVELOPER_ID is required");
	if (!apiKeyPath || !apiKey || !apiIssuer) throw new Error("APPLE_API_KEY_PATH, APPLE_API_KEY, & APPLE_API_ISSUER are required");
	return Object.freeze({
		input,
		output,
		version: stableVersion,
		app,
		dmg,
		receipt,
		commands: Object.freeze([
			Object.freeze({ file: "swiftc", args: ["-parse-as-library", join(HERE, "LegionInstaller.swift"), "-framework", "Cocoa", "-o", join(app, "Contents", "MacOS", "Legion Installer")] }),
			Object.freeze({ file: "codesign", args: ["--force", "--options", "runtime", "--timestamp", "--sign", developerId, app] }),
			Object.freeze({ file: "hdiutil", args: ["create", "-ov", "-fs", "HFS+", "-volname", "Legion Installer", "-srcfolder", app, dmg] }),
			Object.freeze({ file: "codesign", args: ["--force", "--options", "runtime", "--timestamp", "--sign", developerId, dmg] }),
			Object.freeze({ file: "xcrun", args: ["notarytool", "submit", dmg, "--key", apiKeyPath, "--key-id", apiKey, "--issuer", apiIssuer, "--wait", "--output-format", "json"] }),
			Object.freeze({ file: "xcrun", args: ["stapler", "staple", dmg] }),
			Object.freeze({ file: "spctl", args: ["--assess", "--type", "open", "--context", "context:primary-signature", "--verbose=4", dmg] }),
		]),
	});
}

function invoke(command, commandRunner) {
	const result = commandRunner(command.file, command.args, { encoding: "utf8", windowsHide: true });
	if (result?.error) throw result.error;
	if (result?.status !== 0) throw new Error(`${command.file} failed: ${(result?.stderr || result?.stdout || "").trim()}`);
	return result;
}

export function materializeMacosInstaller({ plan, commandRunner = spawnSync, now = () => new Date().toISOString() } = {}) {
	if (!plan) throw new Error("installer plan is required");
	rmSync(plan.app, { recursive: true, force: true });
	rmSync(plan.dmg, { force: true });
	mkdirSync(join(plan.app, "Contents", "MacOS"), { recursive: true });
	mkdirSync(join(plan.app, "Contents", "Resources"), { recursive: true });
	writeFileSync(join(plan.app, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Legion Installer</string><key>CFBundleExecutable</key><string>Legion Installer</string><key>CFBundleIdentifier</key><string>${APP_IDENTIFIER}</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>${plan.version}</string></dict></plist>\n`);
	writeFileSync(join(plan.app, "Contents", "Resources", "version.txt"), `${plan.version}\n`);
	cpSync(plan.input, join(plan.app, "Contents", "Resources", "payload"), { recursive: true, dereference: false, errorOnExist: true });
	const outputs = plan.commands.map((command) => ({ command, result: invoke(command, commandRunner) }));
	if (!existsSync(plan.dmg) || !statSync(plan.dmg).isFile()) throw new Error(`DMG missing after finalization: ${plan.dmg}`);
	const receipt = Object.freeze({
		schema: 1,
		kind: "legion-macos-installer-finalization",
		status: "verified",
		version: plan.version,
		installer: plan.dmg,
		installerSha256: sha256(plan.dmg),
		app: plan.app,
		portableRelease: plan.input,
		createdAt: now(),
		notarization: { tool: "xcrun notarytool", status: "accepted" },
	});
	writeFileSync(plan.receipt, `${JSON.stringify(receipt, null, 2)}\n`);
	return Object.freeze({ ...receipt, receipt: plan.receipt, commands: outputs.map(({ command }) => command) });
}

function argument(name) {
	const index = process.argv.indexOf(name);
	return index >= 0 ? process.argv[index + 1] : undefined;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const output = argument("--output") ?? process.env.RIGHT_GIT_FINALIZED_MACOS_ROOT;
	const plan = macosInstallerPlan({
		inputRoot: argument("--input") ?? process.env.RIGHT_GIT_FINALIZED_PORTABLE_MACOS_ROOT,
		outputRoot: output,
		version: argument("--version") ?? process.env.RIGHT_GIT_RELEASE_VERSION,
		developerId: process.env.APPLE_DEVELOPER_ID,
		apiKeyPath: process.env.APPLE_API_KEY_PATH,
		apiKey: process.env.APPLE_API_KEY,
		apiIssuer: process.env.APPLE_API_ISSUER,
	});
	process.stdout.write(`${JSON.stringify(materializeMacosInstaller({ plan }))}\n`);
}
