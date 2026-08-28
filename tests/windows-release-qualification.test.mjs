import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";
import { qualifyWindowsRelease } from "../scripts/qualify-windows-release.mjs";

function digest(bytes) {
	return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function fixture(root, version, marker) {
	const bin = join(root, "bin");
	const share = join(root, "share", "legion");
	mkdirSync(bin, { recursive: true });
	mkdirSync(share, { recursive: true });
	const runtime = Buffer.from(`fixture legion ${version} ${marker}\n`, "utf8");
	writeFileSync(join(bin, "legion.exe"), runtime);
	writeFileSync(join(bin, "legion-hook.exe"), Buffer.from(`hook ${marker}\n`, "utf8"));
	writeFileSync(join(bin, "legion-mcp.exe"), Buffer.from(`mcp ${marker}\n`, "utf8"));
	writeFileSync(join(share, "release.json"), JSON.stringify({
		releaseVersion: version,
		runtime: { platform: "windows", architecture: "x86_64", sha256: digest(runtime) },
	}));
}

function qualificationFixture({ withPrior = true } = {}) {
	const root = mkdtempSync(join(tmpdir(), "legion-win-qualification-"));
	const currentTree = join(root, "current-tree");
	const priorTree = join(root, "prior-tree");
	const currentZip = join(root, "current.zip");
	const priorZip = join(root, "prior.zip");
	fixture(currentTree, "1.2.3", "current");
	fixture(priorTree, "1.2.2", "prior");
	const codexExecutable = join(root, "codex.exe");
	writeFileSync(codexExecutable, "fixture codex\n");
	writeFileSync(currentZip, "current archive fixture\n");
	writeFileSync(priorZip, "prior archive fixture\n");
	const trees = new Map([
		[currentZip, currentTree],
		[priorZip, priorTree],
	]);
	const archiveExtractor = (archive, destination) => cpSync(trees.get(archive), destination, { recursive: true });
	const commandRunner = (command, args, options = {}) => {
		assert.equal(options.env?.LEGION_M1_CONFIG, undefined);
		assert.equal(options.env?.LEGION_NATIVE_APPLICATION_CONFIG, undefined);
		assert.equal(options.env?.CODEX_HOME, join(options.env.HOME, ".codex"));
		assert.equal(String(options.env?.PATH ?? "").split(";").includes(dirname(codexExecutable)), true);
		const executable = basename(command).toLowerCase();
		if (args[0] === "--version") return { exitCode: 0, stdout: "legion 1.2.3\n", stderr: "" };
		const installedLauncher = join(options.cwd, "bin", "legion.exe");
		const installedDigest = digest(readFileSync(installedLauncher)).slice("sha256:".length);
		const codexDigest = digest(readFileSync(codexExecutable));
		const qualificationRoot = join(options.env.LEGION_STATE_ROOT, "qualification");
		const commandProofPath = join(qualificationRoot, "codex-command.json");
		const qualificationProofPath = join(qualificationRoot, "codex-qualification.json");
		const client = {
			clientId: "codex",
			installed: true,
			fidelity: "Full",
			commandProofRef: commandProofPath,
			qualificationEvidenceRef: qualificationProofPath,
		};
		const liveIdentity = {
			executable: {
				path: installedLauncher,
				manifestPath: join(options.cwd, "share", "legion", "release.json"),
				releaseVersion: "1.2.3",
				expectedReleaseVersion: "1.2.3",
				state: "current",
				runtimeDigest: installedDigest,
				runtimePlatform: "windows",
				runtimeArchitecture: "x86_64",
			},
			projections: { codexSkills: { state: "current" } },
		};
		if (args.includes("repair")) {
			mkdirSync(qualificationRoot, { recursive: true });
			writeFileSync(commandProofPath, JSON.stringify({
				schemaVersion: 2,
				kind: "legion-command-resolution-proof",
				clientId: "codex",
				mechanism: "agent-plugins-bare-command",
				release: { releaseVersion: "1.2.3", runtimeDigest: installedDigest },
				launcherPath: codexExecutable,
				launcherSha256: codexDigest,
				resolved: true,
				exitCode: 0,
				outputSha256: "a".repeat(64),
				legionCommand: "legion --version",
				legionResolved: true,
				legionExitCode: 0,
				legionLauncherPath: installedLauncher,
				legionLauncherSha256: installedDigest,
				legionOutputSha256: "b".repeat(64),
				mcpCommand: "legion",
				mcpArgs: ["serve", "--stdio"],
			}));
			writeFileSync(qualificationProofPath, JSON.stringify({
				schemaVersion: 2,
				kind: "legion-real-client-qualification",
				clientId: "codex",
				mechanism: "agent-plugins-bare-command",
				release: { releaseVersion: "1.2.3", runtimeDigest: installedDigest },
				launcherPath: codexExecutable,
				mcpServer: "legion",
				mcpTool: "legion_m1_status",
				invocationStatus: "complete",
				observedReleaseVersion: "1.2.3",
				capabilityCount: 1,
				hostRequirements: [],
				capabilities: [{ capabilityId: "fixture" }],
				degradedCount: 0,
				completed: true,
				outputSha256: "c".repeat(64),
				legionLauncherPath: installedLauncher,
				legionLauncherSha256: installedDigest,
				mcpCommand: "legion",
				mcpArgs: ["serve", "--stdio"],
			}));
			return {
				exitCode: 0,
				stdout: JSON.stringify({
					schemaVersion: 1,
					kind: "legion-setup-execution",
					status: "complete",
					execution: { clients: [client] },
					hostIntegrations: { codexSkills: { state: "current" } },
					liveIdentity,
				}) + "\n",
				stderr: "",
			};
		}
		if (args.includes("status")) {
			return {
				exitCode: 0,
				stdout: JSON.stringify({
					schemaVersion: 1,
					kind: "legion-setup-status",
					status: "complete",
					clients: [client],
					hostIntegrations: { codexSkills: { state: "current" } },
					liveIdentity,
				}) + "\n",
				stderr: "",
			};
		}
		return { exitCode: 1, stdout: "", stderr: `unexpected command ${executable}` };
	};
	return {
		root,
		currentZip,
		priorZip: withPrior ? priorZip : null,
		archiveExtractor,
		commandRunner,
		codexExecutable,
	};
}

test("Windows qualification exercises native lifecycle through injected seams", () => {
	const fixtureSet = qualificationFixture();
	try {
		const workRoot = join(fixtureSet.root, "work");
		const output = join(fixtureSet.root, "qualification.json");
		const receipt = qualifyWindowsRelease({
			currentZip: fixtureSet.currentZip,
			priorZip: fixtureSet.priorZip,
			architecture: "x86_64",
			sourceRevision: "a".repeat(40),
			output,
			workRoot,
			platform: "win32",
			runnerArchitecture: "x64",
			archiveExtractor: fixtureSet.archiveExtractor,
			commandRunner: fixtureSet.commandRunner,
			codexExecutable: fixtureSet.codexExecutable,
		});
		assert.equal(receipt.status, "blocked");
		assert.equal(receipt.nativeExecution, false);
		assert.equal(receipt.executionMode, "simulated");
		assert.equal(receipt.runner.simulated, true);
		assert.equal(JSON.parse(readFileSync(output, "utf8")).kind, "legion-windows-installed-product-qualification");
		assert.equal(receipt.archive.prior.sha256, receipt.priorArchiveSha256);
		assert.notEqual(receipt.archive.current.sha256, receipt.archive.prior.sha256);
		assert.notEqual(receipt.runtimeSha256, receipt.priorRuntimeSha256);
		for (const name of ["installed-product", "command-resolution", "client-integration", "update", "rollback", "uninstall"]) {
			assert.equal(receipt.gates[name].status, "pass", `${name} must pass: ${JSON.stringify(receipt.gates[name])}`);
		}
		assert.equal(receipt.gates.rollback.injectedFailure, true);
		assert.equal(receipt.gates.uninstall.foreignMarkerPreserved, true);
	} finally {
		rmSync(fixtureSet.root, { recursive: true, force: true });
	}
});

test("missing prior archive is typed unproven and cannot qualify", () => {
	const fixtureSet = qualificationFixture({ withPrior: false });
	try {
		const receipt = qualifyWindowsRelease({
			currentZip: fixtureSet.currentZip,
			architecture: "x86_64",
			sourceRevision: "b".repeat(40),
			output: join(fixtureSet.root, "qualification.json"),
			workRoot: join(fixtureSet.root, "work"),
			platform: "win32",
			runnerArchitecture: "x64",
			archiveExtractor: fixtureSet.archiveExtractor,
			commandRunner: fixtureSet.commandRunner,
			codexExecutable: fixtureSet.codexExecutable,
		});
		assert.equal(receipt.status, "blocked");
		assert.equal(receipt.gates.update.status, "unproven");
		assert.equal(receipt.gates.rollback.status, "unproven");
	} finally {
		rmSync(fixtureSet.root, { recursive: true, force: true });
	}
});

test("identical prior archive cannot pass update or rollback", () => {
	const fixtureSet = qualificationFixture();
	try {
		writeFileSync(fixtureSet.priorZip, readFileSync(fixtureSet.currentZip));
		const receipt = qualifyWindowsRelease({
			currentZip: fixtureSet.currentZip,
			priorZip: fixtureSet.priorZip,
			architecture: "x86_64",
			sourceRevision: "d".repeat(40),
			output: join(fixtureSet.root, "qualification.json"),
			workRoot: join(fixtureSet.root, "work"),
			platform: "win32",
			runnerArchitecture: "x64",
			archiveExtractor: fixtureSet.archiveExtractor,
			commandRunner: fixtureSet.commandRunner,
			codexExecutable: fixtureSet.codexExecutable,
		});
		assert.equal(receipt.status, "blocked");
		assert.equal(receipt.gates.update.status, "fail");
		assert.equal(receipt.gates.rollback.status, "fail");
		assert.equal(receipt.gates.update.archivesDiffer, false);
		assert.equal(receipt.gates.rollback.archivesDiffer, false);
	} finally {
		rmSync(fixtureSet.root, { recursive: true, force: true });
	}
});

test("qualification refuses non-Windows hosts and runner architecture mismatches", () => {
	assert.throws(
		() => qualifyWindowsRelease({ platform: "linux", architecture: "x86_64" }),
		/Windows qualification requires a Windows host/,
	);
	assert.throws(
		() => qualifyWindowsRelease({ platform: "win32", runnerArchitecture: "x64", architecture: "arm64" }),
		/architecture mismatch/,
	);
});
