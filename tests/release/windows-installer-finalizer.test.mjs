import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
	finalizeWindowsInstaller,
	installerIdentity,
	innoCommand,
	outerSigningCommand,
	renderInnoTemplate,
	verifySigningCommand,
} from "../../scripts/release/windows/finalize-installer.mjs";

function hash(value) {
	return createHash("sha256").update(value).digest("hex");
}

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "legion-windows-installer-"));
	const source = join(root, "signed-release");
	const output = join(root, "installer-output");
	mkdirSync(join(source, "bin"), { recursive: true });
	mkdirSync(join(source, "plugin"), { recursive: true });
	mkdirSync(join(source, "share", "legion"), { recursive: true });
	const runtime = Buffer.from("signed Legion runtime\n");
	writeFileSync(join(source, "bin", "legion.exe"), runtime);
	writeFileSync(join(source, "bin", "legion-hook.exe"), "signed hook\n");
	writeFileSync(join(source, "bin", "legion-mcp.exe"), "signed mcp\n");
	writeFileSync(join(source, "plugin", "plugin.json"), "{}\n");
	writeFileSync(join(source, "share", "legion", "release.json"), JSON.stringify({
		releaseVersion: "1.2.3",
		runtime: { platform: "windows", architecture: "x86_64", sha256: `sha256:${hash(runtime)}` },
	}));
	return { root, source, output };
}

test("Windows installer identity, template, & commands bind one x64 payload", () => {
	const { source, output } = fixture();
	assert.deepEqual(installerIdentity({ version: "1.2.3", architecture: "x86_64" }), {
		version: "1.2.3", architecture: "x86_64", name: "Legion-1.2.3-windows-x86_64-setup.exe",
	});
	const template = renderInnoTemplate({ sourceRoot: source, outputRoot: output, version: "1.2.3", architecture: "x86_64" });
	assert.match(template, /PrivilegesRequired=lowest/);
	assert.match(template, /Uninstallable=yes/);
	assert.match(template, /DefaultDirName=\{localappdata\}\\Orthic Labs\\Legion/);
	assert.match(template, /Source: "[^"]+\\bin\\\*"/);
	assert.match(template, /Source: "[^"]+\\plugin\\\*"/);
	assert.match(template, /Source: "[^"]+\\share\\\*"/);
	assert.match(template, /mklink \/J/);
	assert.match(template, /current\\bin/);
	assert.doesNotMatch(template, /@@(?:VERSION|SOURCE_ROOT|OUTPUT_ROOT|SETUP_NAME)@@/);
	const script = join(output, "installer.iss");
	assert.deepEqual(innoCommand({ scriptPath: script }), { command: "iscc.exe", args: ["/Qp", script] });
	const setup = join(output, "Legion-1.2.3-windows-x86_64-setup.exe");
	const receipt = join(output, "setup-signing.json");
	assert.deepEqual(outerSigningCommand({ installer: setup, receipt }), {
		command: "pnpm", args: ["exec", "right-release", "sign-windows", "--receipt", receipt, setup],
	});
	assert.deepEqual(verifySigningCommand({ installer: setup }), {
		command: "pnpm", args: ["exec", "right-release", "sign-windows", "--verify-only", setup],
	});
});

test("finalizer constructs, outer-signs, then verifies expected installer", () => {
	const { source, output } = fixture();
	const calls = [];
	const commandRunner = (command, args) => {
		calls.push({ command, args });
		if (command === "iscc.exe") writeFileSync(join(output, "Legion-1.2.3-windows-x86_64-setup.exe"), "inno installer\n");
		if (command === "pnpm" && args.includes("--receipt")) writeFileSync(args[args.indexOf("--receipt") + 1], "{\"schema\":1}\n");
		return { status: 0, stdout: "" };
	};
	const result = finalizeWindowsInstaller({ inputRoot: source, outputRoot: output, version: "1.2.3", commandRunner });
	assert.equal(result.status, "signed");
	assert.ok(existsSync(result.installer));
	assert.equal(readFileSync(result.receipt, "utf8"), "{\"schema\":1}\n");
	assert.deepEqual(calls.map(({ command }) => command), ["iscc.exe", "pnpm", "pnpm"]);
	assert.ok(calls[1].args.includes("sign-windows"));
	assert.ok(calls[2].args.includes("--verify-only"));
});

test("finalizer rejects missing payload or output nested in signed root", () => {
	const { source } = fixture();
	assert.throws(
		() => finalizeWindowsInstaller({ inputRoot: source, outputRoot: join(source, "output"), version: "1.2.3", commandRunner: () => ({ status: 0 }) }),
		/output must not be inside signed payload root/,
	);
	const { source: incomplete, output } = fixture();
	writeFileSync(join(incomplete, "plugin", "not-empty"), "x");
	// The contract rejects a missing required root before it can reach Inno.
	assert.throws(
		() => finalizeWindowsInstaller({ inputRoot: join(incomplete, "missing"), outputRoot: output, version: "1.2.3", commandRunner: () => ({ status: 0 }) }),
		/input root must be a real directory/,
	);
});
