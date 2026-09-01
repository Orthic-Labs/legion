import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { assertFinalizedPortableRelease, macosInstallerPlan, materializeMacosInstaller } from "../../scripts/release/macos/build-installer.mjs";

function portableRoot() {
	const root = mkdtempSync(join(tmpdir(), "legion-macos-installer-"));
	for (const name of ["bin", "plugin", "share"]) mkdirSync(join(root, name), { recursive: true });
	for (const name of ["legion", "legion-hook", "legion-mcp"]) writeFileSync(join(root, "bin", name), "binary");
	return root;
}

function credentials() { return { developerId: "Developer ID Application: Orthic Labs (TEAMID)", apiKeyPath: "/tmp/AuthKey.p8", apiKey: "KEYID", apiIssuer: "issuer" }; }

test("macOS installer rejects incomplete or unsafe portable releases", () => {
	const root = portableRoot();
	assert.equal(assertFinalizedPortableRelease({ inputRoot: root, version: "1.2.3" }), root);
	assert.throws(() => assertFinalizedPortableRelease({ inputRoot: root, version: "1.2" }), /stable version/);
	assert.throws(() => macosInstallerPlan({ inputRoot: root, outputRoot: join(root, "out"), version: "1.2.3" }), /APPLE_DEVELOPER_ID/);
});

test("macOS installer lays out app payload & only executes expected signing plan", () => {
	const input = portableRoot();
	const output = join(mkdtempSync(join(tmpdir(), "legion-macos-output-")), "final");
	const plan = macosInstallerPlan({ inputRoot: input, outputRoot: output, version: "1.2.3", ...credentials() });
	assert.equal(plan.commands.length, 7);
	assert.deepEqual(plan.commands.map(({ file }) => file), ["swiftc", "codesign", "hdiutil", "codesign", "xcrun", "xcrun", "spctl"]);
	const seen = [];
	const result = materializeMacosInstaller({ plan, now: () => "2026-08-31T00:00:00.000Z", commandRunner(file, args) {
		seen.push({ file, args });
		if (file === "swiftc") writeFileSync(args.at(-1), "compiled-installer");
		if (file === "hdiutil") writeFileSync(args.at(-1), "dmg");
		return { status: 0, stdout: "ok" };
	} });
	assert.equal(seen.length, 7);
	assert.equal(readFileSync(join(plan.app, "Contents", "Resources", "version.txt"), "utf8"), "1.2.3\n");
	assert.equal(readFileSync(join(plan.app, "Contents", "Resources", "payload", "bin", "legion"), "utf8"), "binary");
	assert.equal(result.status, "verified");
	assert.match(readFileSync(result.receipt, "utf8"), /notarytool/);
	const source = readFileSync(new URL("../../scripts/release/macos/LegionInstaller.swift", import.meta.url), "utf8");
	assert.match(source, /Library\/Application Support\/Orthic Labs\/Legion/);
	assert.doesNotMatch(source, /Library\/Application Support\/Legion/);
	assert.match(source, /let binary = current\.appendingPathComponent\("bin\/legion"\)/);
	const repair = source.indexOf('arguments: ["setup", "repair", "--confirm"]');
	const status = source.indexOf('arguments: ["setup", "status"]');
	const doctor = source.indexOf('arguments: ["doctor"]');
	assert.ok(repair >= 0 && repair < status && status < doctor);
	assert.match(source, /completed\.wait\(timeout: \.now\(\) \+ commandTimeout\)/);
	assert.match(source, /kill\(task\.processIdentifier, SIGKILL\)/);
	assert.match(source, /task\.standardOutput = stdout/);
	assert.match(source, /task\.standardError = stderr/);
	assert.match(source, /\[legion-installer\]/);
});

test("distribution contract binds macOS stable root & bounded activation", () => {
	const contract = JSON.parse(readFileSync(new URL("../../release/distribution-contract.json", import.meta.url), "utf8"));
	assert.equal(contract.nativeRelease.macOSStablePaths.root, "~/Library/Application Support/Orthic Labs/Legion");
	assert.equal(contract.nativeRelease.macOSStablePaths.executable, "~/Library/Application Support/Orthic Labs/Legion/current/bin/legion");
	assert.deepEqual(contract.nativeRelease.activation, [
		"legion setup repair --confirm",
		"legion setup status",
		"legion doctor",
	]);
	assert.equal(contract.nativeRelease.activationTimeoutSeconds, 60);
});

test("macOS installer Swift source compiles as a library", { skip: process.platform !== "darwin" }, () => {
	const output = join(mkdtempSync(join(tmpdir(), "legion-macos-swiftc-")), "Legion Installer");
	try {
		const source = new URL("../../scripts/release/macos/LegionInstaller.swift", import.meta.url);
		const result = spawnSync("swiftc", ["-parse-as-library", source.pathname, "-framework", "Cocoa", "-o", output], { encoding: "utf8" });
		assert.equal(result.status, 0, result.stderr || result.stdout);
	} finally {
		rmSync(join(output, ".."), { recursive: true, force: true });
	}
});
