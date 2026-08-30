import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
	assert.match(readFileSync(new URL("../../scripts/release/macos/LegionInstaller.swift", import.meta.url), "utf8"), /task\.arguments = \["doctor"\]/);
});
