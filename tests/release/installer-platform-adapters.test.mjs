import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { finalizeWindows } from "../../scripts/release/windows/finalize.mjs";
import { finalizeMacos } from "../../scripts/release/macos/finalize.mjs";
import { qualifyInstalledWindows } from "../../scripts/release/windows/qualify-installed.mjs";

const REVISION = "b".repeat(40);
const sha = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
function portable(root, extension) {
	mkdirSync(root, { recursive: true });
	for (const [name, body] of [[`legion-1.2.3-${extension}`, "archive"], ["legion.cdx.json", "sbom"], ["legion.intoto.jsonl", "provenance"]]) writeFileSync(join(root, name), body);
}
function finalizeRunner(platform) {
	return (command, args) => {
		if (command === "tar") { const target = args.at(-1); for (const path of ["bin", "plugin", "share"]) mkdirSync(join(target, path), { recursive: true }); return { status: 0 }; }
		assert.equal(command, "node");
		const output = args[args.indexOf("--output") + 1]; mkdirSync(output, { recursive: true });
		const installer = join(output, platform === "windows" ? "Legion-1.2.3-windows-x86_64-setup.exe" : "legion-1.2.3-macos-installer.dmg");
		const receipt = join(output, "receipt.json"); writeFileSync(installer, "installer"); writeFileSync(receipt, "receipt");
		return { status: 0, stdout: JSON.stringify(platform === "windows" ? { status: "signed", identity: { version: "1.2.3", architecture: "x86_64" }, installer, sha256: sha(installer), sizeBytes: statSync(installer).size, receipt } : { status: "verified", version: "1.2.3", installer, installerSha256: sha(installer), receipt }) };
	};
}
test("Windows adapter binds worker installer plus copied portable evidence", () => {
	const root = mkdtempSync(join(tmpdir(), "windows-adapter-")); try {
		const input = join(root, "portable"); portable(input, "windows-x86_64.zip"); const output = join(root, "out");
		const result = finalizeWindows({ portableRoot: input, outputRoot: output, version: "1.2.3", sourceRevision: REVISION, architecture: "x86_64", commandRunner: finalizeRunner("windows") });
		assert.equal(result.kind, "legion-windows-installer-finalization"); assert.equal(result.assets.length, 1); assert.equal(result.evidence.length, 4); assert.ok(result.evidence.every((entry) => entry.path.startsWith(output)));
	} finally { rmSync(root, { recursive: true, force: true }); }
});
test("macOS adapter binds notarized installer plus copied portable evidence", () => {
	const root = mkdtempSync(join(tmpdir(), "mac-adapter-")); try {
		const input = join(root, "portable"); portable(input, "macos-arm64.tar.gz"); const output = join(root, "out");
		const result = finalizeMacos({ portableRoot: input, outputRoot: output, version: "1.2.3", sourceRevision: REVISION, architecture: "arm64", commandRunner: finalizeRunner("macos") });
		assert.equal(result.kind, "legion-macos-installer-finalization"); assert.equal(result.assets[0].path.endsWith(".dmg"), true); assert.equal(result.evidence.length, 4);
	} finally { rmSync(root, { recursive: true, force: true }); }
});
test("Windows installed qualification silently installs, checks, uninstalls, & binds finalization digest", () => {
	const root = mkdtempSync(join(tmpdir(), "windows-qualify-")); try {
		const setup = join(root, "Legion-setup.exe"); writeFileSync(setup, "setup"); const finalization = join(root, "installer-finalization.json"); writeFileSync(finalization, JSON.stringify({ schemaVersion: 1, kind: "legion-installer-finalization", product: "legion", platform: "windows", version: "1.2.3", sourceRevision: REVISION, assets: [{ role: "installer" }] }));
		const output = join(root, "evidence");
		let localAppData;
		const result = qualifyInstalledWindows({ setup, outputRoot: output, finalizationPath: finalization, sourceRevision: REVISION, version: "1.2.3", platform: "win32", temporaryRoot: root, commandRunner(command, args, options) {
			if (command === setup) { const dir = args.find((item) => item.startsWith("/DIR=")).slice(5); assert.match(dir.replaceAll("\\", "/"), /local-app-data\/Orthic Labs\/Legion$/); localAppData = options.env.LOCALAPPDATA; assert.equal(dir, join(localAppData, "Orthic Labs", "Legion")); mkdirSync(join(dir, "current", "bin"), { recursive: true }); writeFileSync(join(dir, "current", "bin", "legion.exe"), "legion"); writeFileSync(join(dir, "unins000.exe"), "uninstall"); return { status: 0 }; }
			assert.equal(options.env.LOCALAPPDATA, localAppData); if (command.endsWith("unins000.exe")) { rmSync(join(command, ".."), { recursive: true, force: true }); return { status: 0 }; }
			assert.equal(command.endsWith("current\\bin\\legion.exe"), true); assert.equal(["--version", "doctor"].includes(args[0]), true); return { status: 0, stdout: "ok" };
		} });
		assert.equal(result.status, "qualified"); assert.equal(existsSync(join(output, "qualification.json")), true);
	} finally { rmSync(root, { recursive: true, force: true }); }
});
