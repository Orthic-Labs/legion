#!/usr/bin/env node

/**
 * Build one deterministic Windows portable archive plus its evidence seams.
 *
 * This script intentionally produces a BLOCKED manifest when signing,
 * provenance, or qualification receipts are absent. It never upgrades a
 * local-build reference into release evidence and never changes the WinGet
 * channel ledger. `--require-signature` / `--require-evidence` are the
 * fail-closed gates used by a release invocation.
 */

import { createHash } from "node:crypto";
import {
	copyFileSync,
	existsSync,
	mkdirSync,
	lstatSync,
	readFileSync,
	readdirSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { WINDOWS_ARCHITECTURES } from "../right-release.config.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REQUIRED_BINARIES = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"];
const SIGNING_CONTRACT = "windows-raw-exe-authenticode-before-portable-v1";
const WINDOWS_PLATFORM = "windows";
const CHANNEL_ID = "winget";
const CHANNEL_PACKAGE_ID = "OrthicLabs.Legion";
const EVIDENCE_STATUS = Object.freeze({
	missing: "missing",
	invalid: "invalid",
	verified: "verified",
});

const ARCHITECTURE_ALIASES = new Map([
	["x64", "x86_64"],
	["amd64", "x86_64"],
	["x86_64", "x86_64"],
	["windows-x86_64", "x86_64"],
	["arm64", "arm64"],
	["aarch64", "arm64"],
	["windows-arm64", "arm64"],
]);
const REQUIRED_QUALIFICATION_GATES = Object.freeze([
	"installed-product",
	"command-resolution",
	"client-integration",
	"update",
	"rollback",
	"uninstall",
]);

export function normalizeWindowsArchitecture(value) {
	const key = String(value ?? "").trim().toLowerCase();
	const architecture = ARCHITECTURE_ALIASES.get(key);
	if (!architecture || !WINDOWS_ARCHITECTURES[architecture]) {
		throw new Error(`unsupported Windows architecture: ${value}; expected x86_64 or arm64`);
	}
	return architecture;
}

export function windowsTargetIdentity(value) {
	const architecture = normalizeWindowsArchitecture(value);
	const configured = WINDOWS_ARCHITECTURES[architecture];
	return {
		platform: WINDOWS_PLATFORM,
		architecture,
		targetTriple: configured.targetTriple,
		wingetArchitecture: configured.wingetArchitecture,
		executable: "legion.exe",
		artifactId: configured.artifactId,
	};
}

function sha256(bytes) {
	return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function fileDigest(path) {
	return sha256(readFileSync(path));
}

function bareDigest(value) {
	return String(value ?? "").replace(/^sha256:/i, "").toLowerCase();
}

function readJson(path, label) {
	if (!existsSync(path)) throw new Error(`${label} is missing: ${path}`);
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		throw new Error(`${label} is not valid JSON: ${path} (${error.message})`);
	}
}

function resolveInside(root, candidate, label = "path") {
	const resolvedRoot = resolve(root);
	const resolved = resolve(resolvedRoot, candidate);
	const rel = relative(resolvedRoot, resolved);
	if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || rel.includes("\0")) {
		throw new Error(`${label} escapes its root: ${candidate}`);
	}
	return resolved;
}

function relativePortablePath(root, file) {
	const rel = relative(resolve(root), resolve(file)).split(sep).join("/");
	if (!rel || rel === ".." || rel.startsWith("../") || rel.includes("\0")) {
		throw new Error(`portable path escapes release root: ${file}`);
	}
	if (rel.split("/").some((part) => part === ".git" || part === "node_modules")) {
		throw new Error(`development-only path cannot ship in portable archive: ${rel}`);
	}
	return rel;
}

function filesBelow(root, directory = root, output = []) {
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		const path = join(directory, entry.name);
		const metadata = lstatSync(path);
		if (metadata.isSymbolicLink()) throw new Error(`portable release asset is symlink: ${path}`);
		if (metadata.isDirectory()) filesBelow(root, path, output);
		else if (metadata.isFile()) output.push(relativePortablePath(root, path));
		else throw new Error(`portable release asset is not a regular file: ${path}`);
	}
	return output.sort();
}

function crc32(bytes) {
	let crc = 0xffffffff;
	for (const byte of bytes) {
		crc ^= byte;
		for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

function zipEntry(name, bytes, offset) {
	const filename = Buffer.from(name, "utf8");
	if (!filename.length || filename.length > 0xffff) throw new Error(`invalid ZIP entry name: ${name}`);
	if (bytes.length > 0xffffffff || offset > 0xffffffff) throw new Error(`ZIP32 limit exceeded by ${name}`);
	const checksum = crc32(bytes);
	const local = Buffer.alloc(30 + filename.length);
	local.writeUInt32LE(0x04034b50, 0);
	local.writeUInt16LE(20, 4);
	local.writeUInt16LE(0x800, 6);
	local.writeUInt16LE(0, 8);
	local.writeUInt16LE(0, 10);
	local.writeUInt16LE(0, 12);
	local.writeUInt32LE(checksum, 14);
	local.writeUInt32LE(bytes.length, 18);
	local.writeUInt32LE(bytes.length, 22);
	local.writeUInt16LE(filename.length, 26);
	local.writeUInt16LE(0, 28);
	filename.copy(local, 30);

	const central = Buffer.alloc(46 + filename.length);
	central.writeUInt32LE(0x02014b50, 0);
	central.writeUInt16LE(20, 4);
	central.writeUInt16LE(20, 6);
	central.writeUInt16LE(0x800, 8);
	central.writeUInt16LE(0, 10);
	central.writeUInt16LE(0, 12);
	central.writeUInt16LE(0, 14);
	central.writeUInt32LE(checksum, 16);
	central.writeUInt32LE(bytes.length, 20);
	central.writeUInt32LE(bytes.length, 24);
	central.writeUInt16LE(filename.length, 28);
	central.writeUInt16LE(0, 30);
	central.writeUInt16LE(0, 32);
	central.writeUInt16LE(0, 34);
	central.writeUInt16LE(0, 36);
	central.writeUInt32LE(0, 38);
	central.writeUInt32LE(offset, 42);
	filename.copy(central, 46);
	return { local, central };
}

/**
 * Write a deterministic, store-only ZIP. Node has no built-in archive writer;
 * keeping this writer dependency-free avoids a package/install step in the
 * Windows release lane. Entries are sorted and carry a fixed DOS timestamp.
 */
export function createPortableZip(root, files = filesBelow(root)) {
	const sortedFiles = [...files].sort();
	if (new Set(sortedFiles).size !== sortedFiles.length) throw new Error("portable ZIP entries must be unique");
	const locals = [];
	const centrals = [];
	let offset = 0;
	for (const name of sortedFiles) {
		if (name.includes("\\") || name.split("/").some((part) => part === ".." || part === "")) {
			throw new Error(`unsafe portable ZIP entry: ${name}`);
		}
		const bytes = readFileSync(resolveInside(root, name, "portable ZIP entry"));
		const entry = zipEntry(name, bytes, offset);
		locals.push(entry.local, bytes);
		centrals.push(entry.central);
		offset += entry.local.length + bytes.length;
	}
	const centralDirectory = Buffer.concat(centrals);
	if (sortedFiles.length > 0xffff || centralDirectory.length > 0xffffffff || offset > 0xffffffff) {
		throw new Error("portable ZIP exceeds ZIP32 limits");
	}
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50, 0);
	end.writeUInt16LE(0, 4);
	end.writeUInt16LE(0, 6);
	end.writeUInt16LE(sortedFiles.length, 8);
	end.writeUInt16LE(sortedFiles.length, 10);
	end.writeUInt32LE(centralDirectory.length, 12);
	end.writeUInt32LE(offset, 16);
	end.writeUInt16LE(0, 20);
	return Buffer.concat([...locals, centralDirectory, end]);
}

function atomicWrite(path, bytes, { force = false } = {}) {
	if (existsSync(path) && !force) throw new Error(`release output exists: ${path}; pass --force to replace exact output`);
	mkdirSync(dirname(path), { recursive: true });
	const temporary = `${path}.${process.pid}.tmp`;
	try {
		writeFileSync(temporary, bytes);
		renameSync(temporary, path);
	} finally {
		if (existsSync(temporary)) rmSync(temporary, { force: true });
	}
}

function assertVersion(value) {
	if (typeof value !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value)) {
		throw new Error(`invalid release version: ${value}`);
	}
	if (/-dev\./i.test(value)) throw new Error(`development release version cannot be packaged: ${value}`);
	return value;
}

function assertSourceRevision(value) {
	if (!/^[0-9a-f]{7,64}$/i.test(String(value ?? ""))) {
		throw new Error(`source revision must be a hexadecimal Git revision: ${value ?? "<missing>"}`);
	}
	return String(value).toLowerCase();
}

function sourceRevision(provided, root) {
	const value = provided ?? process.env.GITHUB_SHA ?? process.env.SOURCE_REVISION;
	if (value) return assertSourceRevision(value);
	try {
		return assertSourceRevision(execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim());
	} catch (error) {
		throw new Error(`source revision is required; pass --source-revision (${error.message})`);
	}
}

function releaseMetadata(inputRoot, expected) {
	const path = resolveInside(inputRoot, "share/legion/release.json", "release identity");
	const metadata = readJson(path, "release identity");
	if (metadata.releaseVersion == null) throw new Error(`release identity has no releaseVersion: ${path}`);
	const releaseVersion = assertVersion(metadata.releaseVersion);
	if (expected && releaseVersion !== expected) throw new Error(`release version mismatch: expected ${expected}, got ${releaseVersion}`);
	const runtime = metadata.runtime;
	if (!runtime || typeof runtime !== "object") throw new Error(`release identity has no runtime: ${path}`);
	const identity = windowsTargetIdentity(runtime.architecture);
	const observedPlatform = String(runtime.platform ?? "").toLowerCase();
	if (observedPlatform !== "windows" && observedPlatform !== "win32" && observedPlatform !== "win") {
		throw new Error(`release identity platform is not Windows: ${runtime.platform}`);
	}
	if (!runtime.sha256) {
		throw new Error(`release identity has no final runtime digest: ${path}`);
	}
	if (
		!["windows", "win32", "win"].includes(String(runtime.platform ?? "").toLowerCase())
		|| runtime.architecture !== identity.architecture
	) {
		throw new Error(`release runtime platform or architecture does not match target identity: ${path}`);
	}
	return { metadata, releaseVersion, identity, path };
}

function assertBinaries(inputRoot, identity) {
	for (const name of REQUIRED_BINARIES) {
		const path = resolveInside(inputRoot, `bin/${name}`, "release binary");
		if (!existsSync(path)) throw new Error(`release binary missing: ${path}`);
	}
	const runtimePath = resolveInside(inputRoot, `bin/${identity.executable}`, "runtime binary");
	const runtimeDigest = fileDigest(runtimePath);
	const declaredDigest = identity.runtimeDigest;
	if (declaredDigest && bareDigest(declaredDigest) !== bareDigest(runtimeDigest)) {
		throw new Error(`release identity runtime digest mismatch: ${declaredDigest} != ${runtimeDigest}`);
	}
	return { runtimePath, runtimeDigest };
}

function signatureEvidence({ receiptPath, inputRoot, identity }) {
	const base = {
		schemaVersion: 1,
		kind: "legion-windows-signature-evidence",
		contract: SIGNING_CONTRACT,
		targetIdentity: identity,
		artifacts: REQUIRED_BINARIES.map((name) => ({ path: `bin/${name}`, sha256: fileDigest(resolveInside(inputRoot, `bin/${name}`, "signed binary")) })),
	};
	if (!receiptPath || !existsSync(receiptPath)) {
		return {
			...base,
			status: EVIDENCE_STATUS.missing,
			reason: "A RightKit Windows signing receipt is required; no local receipt is a signature.",
		};
	}
	let receipt;
	try {
		receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
	} catch (error) {
		return { ...base, status: EVIDENCE_STATUS.invalid, reason: `invalid signing receipt JSON: ${error.message}` };
	}
	if (receipt.schema !== 1 || !Array.isArray(receipt.files) || receipt.files.length !== REQUIRED_BINARIES.length) {
		return { ...base, status: EVIDENCE_STATUS.invalid, reason: "signing receipt schema/files are invalid" };
	}
	const receiptDirectory = dirname(resolve(receiptPath));
	const signed = [];
	for (const name of REQUIRED_BINARIES) {
		const expectedPath = resolveInside(inputRoot, `bin/${name}`, "signed binary");
		const expectedDigest = fileDigest(expectedPath);
		const matches = receipt.files.filter((item) => {
			const candidates = item?.file
				? [resolve(item.file), resolve(receiptDirectory, item.file)]
				: [];
			return candidates.includes(resolve(expectedPath)) && bareDigest(item?.after?.sha256) === bareDigest(expectedDigest);
		});
		if (matches.length !== 1) {
			return { ...base, status: EVIDENCE_STATUS.invalid, reason: `receipt does not bind exactly one final digest for ${name}` };
		}
		const item = matches[0];
		if (
			item.authenticode !== "Valid"
			|| item.subject !== "CN=Damned Ventures LLC"
			|| item.timestampPresent !== true
			|| item.after?.sizeBytes !== lstatSync(expectedPath).size
		) {
			return { ...base, status: EVIDENCE_STATUS.invalid, reason: `receipt lacks Valid Authenticode, expected subject, or trusted timestamp for ${name}` };
		}
		signed.push({ path: `bin/${name}`, file: item.file, sha256: item.after.sha256, sizeBytes: item.after.sizeBytes });
	}
	return {
		...base,
		status: EVIDENCE_STATUS.verified,
		receipt: { schema: receipt.schema, files: signed },
	};
}

function provenanceEvidence({ evidencePath, archiveDigest, runtimeDigest, identity, releaseVersion, sourceRevision }) {
	const base = {
		schemaVersion: 1,
		kind: "legion-windows-provenance-evidence",
		targetIdentity: identity,
		releaseVersion,
		sourceRevision,
		archiveSha256: archiveDigest,
		runtimeSha256: runtimeDigest,
		requiredScheme: "rightkit-release://",
	};
	if (!evidencePath || !existsSync(evidencePath)) {
		return { ...base, status: EVIDENCE_STATUS.missing, reason: "RightKit provenance evidence is required for publication." };
	}
	const value = readJson(evidencePath, "provenance evidence");
	const locator = value.provenance ?? value.locator ?? value.uri;
	const observedArchive = value.archiveSha256 ?? value.artifact?.sha256;
	const valid = (value.status === "verified" || value.status === "complete" || value.status === "pass")
		&& typeof locator === "string"
		&& locator.startsWith("rightkit-release://")
		&& typeof observedArchive === "string"
		&& bareDigest(observedArchive) === bareDigest(archiveDigest);
	return valid
		? { ...base, status: EVIDENCE_STATUS.verified, source: value }
		: { ...base, status: EVIDENCE_STATUS.invalid, reason: "provenance must be verified, rightkit-release:// bound, and archive-digest bound", source: value };
}

function qualificationTargetIdentityMatches(observed, expected) {
	if (!observed || typeof observed !== "object" || Array.isArray(observed)) return false;
	const keys = ["platform", "architecture", "targetTriple", "wingetArchitecture", "executable", "artifactId"];
	return JSON.stringify(Object.keys(observed).sort()) === JSON.stringify([...keys].sort())
		&& keys.every((key) => observed[key] === expected[key]);
}

function qualificationGatesPass(value) {
	const gates = value?.gates;
	if (!gates || typeof gates !== "object") return false;
	const entries = Array.isArray(gates)
		? gates.map((item) => [item?.name, item])
		: Object.entries(gates);
	if (entries.length !== REQUIRED_QUALIFICATION_GATES.length) return false;
	const names = entries.map(([name]) => name);
	if (new Set(names).size !== REQUIRED_QUALIFICATION_GATES.length) return false;
	return REQUIRED_QUALIFICATION_GATES.every((name) => {
		const gate = entries.find(([entryName]) => entryName === name)?.[1];
		return gate && typeof gate === "object" && gate.status === "pass" && (gate.name == null || gate.name === name);
	});
}

export function qualificationEvidence({ evidencePath, archiveDigest, runtimeDigest, identity, releaseVersion, sourceRevision }) {
	const base = {
		schemaVersion: 1,
		kind: "legion-windows-qualification-evidence",
		targetIdentity: identity,
		releaseVersion,
		sourceRevision,
		archiveSha256: archiveDigest,
		runtimeSha256: runtimeDigest,
		requiredGates: ["installed-product", "command-resolution", "client-integration", "update", "rollback", "uninstall"],
	};
	if (!evidencePath || !existsSync(evidencePath)) {
		return { ...base, status: EVIDENCE_STATUS.missing, reason: "installed-product qualification evidence is required for publication." };
	}
	const value = readJson(evidencePath, "qualification evidence");
	const expectedRunnerArchitecture = identity.architecture === "x86_64" ? "x64" : "arm64";
	const runner = value.runner;
	const valid = value.schemaVersion === 1
		&& value.kind === "legion-windows-installed-product-qualification"
		&& value.nativeExecution === true
		&& qualificationTargetIdentityMatches(value.targetIdentity, identity)
		&& value.releaseVersion === releaseVersion
		&& typeof value.sourceRevision === "string"
		&& value.sourceRevision.toLowerCase() === String(sourceRevision).toLowerCase()
		&& runner
		&& typeof runner === "object"
		&& runner.os === "win32"
		&& runner.architecture === expectedRunnerArchitecture
		&& runner.simulated === false
		&& value.executionMode === "native"
		&& value.status === "qualified"
		&& qualificationGatesPass(value)
		&& typeof value.archiveSha256 === "string"
		&& typeof value.runtimeSha256 === "string"
		&& bareDigest(value.archiveSha256) === bareDigest(archiveDigest)
		&& bareDigest(value.runtimeSha256) === bareDigest(runtimeDigest);
	return valid
		? { ...base, status: EVIDENCE_STATUS.verified, source: value }
		: { ...base, status: EVIDENCE_STATUS.invalid, reason: "qualification must be a native, target/version/source/digest-bound receipt with exactly six passing lifecycle gates", source: value };
}

function buildSbom({ identity, releaseVersion, sourceRevision, files, inputRoot }) {
	const components = files
		.filter((name) => name.toLowerCase().endsWith(".exe"))
		.map((name) => ({
			type: "application",
			name: basename(name, ".exe"),
			version: releaseVersion,
			bomRef: `legion:${identity.architecture}:${name}`,
			hashes: [{ alg: "SHA-256", content: bareDigest(fileDigest(resolveInside(inputRoot, name))) }],
			properties: [
				{ name: "legion.platform", value: identity.platform },
				{ name: "legion.architecture", value: identity.architecture },
				{ name: "legion.targetTriple", value: identity.targetTriple },
			],
		}));
	return {
		bomFormat: "CycloneDX",
		specVersion: "1.5",
		serialNumber: `urn:legion:windows:${identity.architecture}:${sourceRevision}`,
		version: 1,
		metadata: {
			component: { type: "application", name: "@orthic-labs/legion", version: releaseVersion },
			properties: [
				{ name: "legion.platform", value: identity.platform },
				{ name: "legion.architecture", value: identity.architecture },
				{ name: "legion.targetTriple", value: identity.targetTriple },
			],
		},
		components,
	};
}

function writeChecksums(outputDir, names, { force }) {
	const lines = names
		.sort()
		.map((name) => `${bareDigest(fileDigest(join(outputDir, name)))}  ${name}`);
	const path = join(outputDir, "SHA256SUMS");
	atomicWrite(path, Buffer.from(`${lines.join("\n")}\n`, "utf8"), { force });
	return { path, digest: fileDigest(path) };
}

function statusReady(evidence) {
	return evidence.signature.status === EVIDENCE_STATUS.verified
		&& evidence.provenance.status === EVIDENCE_STATUS.verified
		&& evidence.qualification.status === EVIDENCE_STATUS.verified;
}

export function buildWindowsReleasePackage({
	input,
	output,
	architecture,
	sourceRevision: suppliedSourceRevision,
	signatureReceipt,
	provenance,
	qualification,
	notices,
	force = false,
	requireSignature = false,
	requireEvidence = false,
	repositoryRoot = REPOSITORY_ROOT,
} = {}) {
	if (!input) throw new Error("--input is required; package an assembled release root, never a source checkout");
	const inputRoot = resolve(input);
	if (!existsSync(inputRoot) || !lstatSync(inputRoot).isDirectory()) throw new Error(`assembled release root is missing: ${inputRoot}`);
	const identity = windowsTargetIdentity(architecture);
	const expectedVersionRecord = readJson(join(repositoryRoot, "release", "version.json"), "release version record");
	const expectedVersion = assertVersion(expectedVersionRecord.version);
	const release = releaseMetadata(inputRoot, expectedVersion);
	if (release.identity.architecture !== identity.architecture || release.identity.targetTriple !== identity.targetTriple) {
		throw new Error(`assembled release target does not match requested ${identity.architecture}`);
	}
	const binaries = assertBinaries(inputRoot, { ...identity, runtimeDigest: release.metadata.runtime.sha256 });
	const files = filesBelow(inputRoot);
	const revision = sourceRevision(suppliedSourceRevision, repositoryRoot);
	const outputDir = resolve(output ?? join(repositoryRoot, "dist", "releases", "windows", release.releaseVersion, identity.architecture));
	if (outputDir === resolve(repositoryRoot) || outputDir === inputRoot) {
		throw new Error(`unsafe release output path: ${outputDir}`);
	}
	if (existsSync(outputDir) && !force && readdirSync(outputDir).length > 0) {
		throw new Error(`release output directory is not empty: ${outputDir}; pass --force to replace exact output`);
	}
	if (existsSync(outputDir) && force) rmSync(outputDir, { recursive: true, force: true });
	mkdirSync(outputDir, { recursive: true });
	const archiveName = `legion-${release.releaseVersion}-windows-${identity.architecture}.zip`;
	const archivePath = join(outputDir, archiveName);
	const archiveBytes = createPortableZip(inputRoot, files);
	atomicWrite(archivePath, archiveBytes, { force });
	const archiveDigest = fileDigest(archivePath);

	const sbomName = "SBOM.cdx.json";
	const noticesName = "THIRD_PARTY_NOTICES.md";
	const provenanceName = "provenance.json";
	const qualificationName = "qualification.json";
	const signatureName = "signature.json";
	const notarizationName = "notarization.json";
	const wingetName = "winget-portable.json";
	const manifestName = "release-manifest.json";
	const noticeSource = resolve(repositoryRoot, notices ?? join(repositoryRoot, "docs", "THIRD_PARTY_NOTICES.md"));
	if (!existsSync(noticeSource)) throw new Error(`third-party notice source is missing: ${noticeSource}`);
	const noticeMetadata = lstatSync(noticeSource);
	if (!noticeMetadata.isFile() || noticeMetadata.isSymbolicLink()) {
		throw new Error(`third-party notice source is not a regular file: ${noticeSource}`);
	}
	const noticePath = join(outputDir, noticesName);
	if (existsSync(noticePath) && !force) throw new Error(`release output exists: ${noticePath}; pass --force to replace exact output`);
	copyFileSync(noticeSource, noticePath);

	const sbomPath = join(outputDir, sbomName);
	atomicWrite(sbomPath, Buffer.from(`${JSON.stringify(buildSbom({ identity, releaseVersion: release.releaseVersion, sourceRevision: revision, files, inputRoot }), null, 2)}\n`), { force });
	const signatures = signatureEvidence({
		receiptPath: signatureReceipt
			? resolve(repositoryRoot, signatureReceipt)
			: process.env.LEGION_WINDOWS_SIGNATURE_RECEIPT
				? resolve(repositoryRoot, process.env.LEGION_WINDOWS_SIGNATURE_RECEIPT)
				: join(repositoryRoot, ".right-release", "receipts", `windows-${identity.architecture}-raw-exe.json`),
		inputRoot,
		identity,
	});
	const notarization = {
		schemaVersion: 1,
		kind: "legion-windows-notarization-evidence",
		status: "not-applicable",
		reason: "Windows portable artifacts use Authenticode and trusted timestamp; Apple notarization does not apply.",
		targetIdentity: identity,
	};
	const provenanceRecord = provenanceEvidence({
		evidencePath: provenance ? resolve(repositoryRoot, provenance) : null,
		archiveDigest,
		runtimeDigest: binaries.runtimeDigest,
		identity,
		releaseVersion: release.releaseVersion,
		sourceRevision: revision,
	});
	const qualificationRecord = qualificationEvidence({
		evidencePath: qualification ? resolve(repositoryRoot, qualification) : null,
		archiveDigest,
		runtimeDigest: binaries.runtimeDigest,
		identity,
		releaseVersion: release.releaseVersion,
		sourceRevision: revision,
	});
	for (const [name, value] of [
		[signatureName, signatures],
		[notarizationName, notarization],
		[provenanceName, provenanceRecord],
		[qualificationName, qualificationRecord],
	]) atomicWrite(join(outputDir, name), Buffer.from(`${JSON.stringify(value, null, 2)}\n`), { force });

	const wingetRecord = {
		schemaVersion: 1,
		kind: "legion-winget-portable-artifact",
		status: "BLOCKED",
		packageIdentifier: CHANNEL_PACKAGE_ID,
		installerType: "portable",
		architecture: identity.wingetArchitecture,
		platform: identity.platform,
		version: release.releaseVersion,
		targetTriple: identity.targetTriple,
		installer: { path: archiveName, sha256: archiveDigest, url: null },
		requiredEvidence: ["authenticode", "trusted-timestamp", "provenance", "installed-product-qualification", "channel-authorization"],
		reason: "WinGet publication remains blocked until immutable signed installed-product evidence and channel authorization exist.",
	};
	const wingetPath = join(outputDir, wingetName);
	atomicWrite(wingetPath, Buffer.from(`${JSON.stringify(wingetRecord, null, 2)}\n`), { force });

	const evidence = { signature: signatures, provenance: provenanceRecord, qualification: qualificationRecord };
	const evidenceReady = statusReady(evidence);
	const checksumFiles = [archiveName, sbomName, noticesName, provenanceName, qualificationName, signatureName, notarizationName, wingetName];
	const checksums = writeChecksums(outputDir, checksumFiles, { force });
	const recordFor = (name, extras = {}) => ({ path: name, digest: fileDigest(join(outputDir, name)), ...extras });
	const manifest = {
		schemaVersion: 1,
		kind: "legion-release-manifest",
		releaseType: "windows-portable",
		releaseStatus: evidenceReady ? "QUALIFIED_BUT_UNPUBLISHED" : "BLOCKED",
		version: release.releaseVersion,
		sourceRevision: revision,
		targetIdentity: identity,
		portable: {
			packageManager: "WinGet",
			packageIdentifier: CHANNEL_PACKAGE_ID,
			installerType: "portable",
			archive: recordFor(archiveName, { type: "portable-archive", platform: identity.platform, architecture: identity.architecture, targetTriple: identity.targetTriple, semanticEquivalent: true }),
		},
		artifacts: [recordFor(archiveName, { type: "portable-archive", platform: identity.platform, architecture: identity.architecture, targetTriple: identity.targetTriple, semanticEquivalent: true })],
		checksums: [checksums],
		sboms: [recordFor(sbomName, { format: "CycloneDX" })],
		notices: [recordFor(noticesName)],
		provenance: [recordFor(provenanceName, { status: provenanceRecord.status })],
		attestations: [recordFor(provenanceName, { status: provenanceRecord.status })],
		signatures: [recordFor(signatureName, { status: signatures.status, contract: SIGNING_CONTRACT })],
		notarization: [recordFor(notarizationName, { status: notarization.status })],
		qualificationArtifacts: [recordFor(qualificationName, { status: qualificationRecord.status })],
		packageManagerMetadata: [recordFor(wingetName, { status: wingetRecord.status, channel: CHANNEL_ID })],
		channels: [{
			id: CHANNEL_ID,
			decision: "BLOCKED",
			reason: wingetRecord.reason,
			artifacts: [{ path: archiveName, decision: "BLOCKED" }],
		}],
		requiredEvidence: wingetRecord.requiredEvidence,
	};
	const manifestPath = join(outputDir, manifestName);
	atomicWrite(manifestPath, Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`), { force });

	if (requireSignature && signatures.status !== EVIDENCE_STATUS.verified) {
		throw new Error(`Windows release signing is not verified: ${signatures.reason}`);
	}
	if (requireEvidence && !evidenceReady) {
		throw new Error(`Windows release evidence is incomplete: signature=${signatures.status}, provenance=${provenanceRecord.status}, qualification=${qualificationRecord.status}`);
	}
	return {
		status: manifest.releaseStatus,
		channel: "BLOCKED",
		outputDir,
		archive: archivePath,
		manifest: manifestPath,
		architecture: identity.architecture,
		targetTriple: identity.targetTriple,
		archiveSha256: archiveDigest,
		runtimeSha256: binaries.runtimeDigest,
		evidence: {
			signature: signatures.status,
			provenance: provenanceRecord.status,
			qualification: qualificationRecord.status,
		},
	};
}

function parseArguments(argv) {
	const options = {};
	for (let index = 0; index < argv.length; index += 1) {
		const raw = argv[index];
		if (raw === "--") continue;
		if (raw === "--force" || raw === "--require-signature" || raw === "--require-evidence" || raw === "--json") {
			options[raw.slice(2).replaceAll("-", "")] = true;
			continue;
		}
		const equal = raw.indexOf("=");
		const key = equal === -1 ? raw.slice(2) : raw.slice(2, equal);
		if (!raw.startsWith("--") || !key) throw new Error(`unknown argument: ${raw}`);
		const value = equal === -1 ? argv[++index] : raw.slice(equal + 1);
		if (!value || value.startsWith("--")) throw new Error(`${raw} requires a value`);
		options[key.replaceAll("-", "")] = value;
	}
	return options;
}

function usage(code = 0) {
	console.error("usage: node scripts/package-windows-release.mjs --architecture x86_64|arm64 --input <assembled-root> [--output <dir>] [--source-revision <sha>] [--signature-receipt <json>] [--provenance <json>] [--qualification <json>] [--force] [--require-signature] [--require-evidence] [--json]");
	process.exit(code);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
	try {
		if (process.argv.includes("--help") || process.argv.includes("-h")) usage(0);
		const options = parseArguments(process.argv.slice(2));
		const architecture = options.architecture ?? process.env.LEGION_WINDOWS_ARCH;
		if (!architecture) throw new Error("--architecture is required; choose x86_64 or arm64");
		const normalized = normalizeWindowsArchitecture(architecture);
		const configured = WINDOWS_ARCHITECTURES[normalized];
		const input = options.input ?? join(REPOSITORY_ROOT, configured.assemblyRoot);
		const result = buildWindowsReleasePackage({
			input,
			output: options.output ?? options.out,
			architecture: normalized,
			sourceRevision: options.sourcerevision,
			signatureReceipt: options.signaturereceipt,
			provenance: options.provenance,
			qualification: options.qualification,
			notices: options.notices,
			force: options.force === true,
			requireSignature: options.requiresignature === true,
			requireEvidence: options.requireevidence === true,
		});
		if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
		else process.stdout.write(`windows package ${result.status}: ${result.archive} (${result.architecture}/${result.targetTriple})\n`);
	} catch (error) {
		console.error(`package-windows-release: ${error.message}`);
		process.exit(1);
	}
}
