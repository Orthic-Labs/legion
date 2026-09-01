import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import {
	detectDevOnlyPathBinaries,
	detectInheritedPrivateEnv,
	detectPreexistingState,
	detectReachableWorkspace,
	qualifyCleanEnvironment,
} from "../scripts/qualify-clean-environment.mjs";

function fixtureRoot() {
	return mkdtempSync(join(tmpdir(), "legion-clean-qualification-"));
}

test("private rescue variables are contamination, without exposing their values", () => {
	const issues = detectInheritedPrivateEnv({
		PATH: "/clean/bin",
		LEGION_NATIVE_APPLICATION_CONFIG: "operator-secret-path",
		MEMBRANE_ENDPOINT: "http://operator-service",
		GITHUB_TOKEN: "operator-token",
	});
	assert.deepEqual(issues.map((finding) => finding.path), [
		"GITHUB_TOKEN",
		"LEGION_NATIVE_APPLICATION_CONFIG",
		"MEMBRANE_ENDPOINT",
	]);
	assert.ok(!JSON.stringify(issues).includes("operator-secret-path"));
	assert.ok(!JSON.stringify(issues).includes("operator-token"));
});

test("a checkout reachable from cwd or PATH is rejected", () => {
	const root = fixtureRoot();
	try {
		mkdirSync(join(root, ".git"));
		const issues = detectReachableWorkspace({
			cwd: join(root, "work"),
			pathValue: join(root, "tools"),
			platform: process.platform,
		});
		assert.equal(issues.length, 1);
		assert.equal(issues[0].kind, "reachable-workspace");
		assert.equal(issues[0].path, root);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("pre-existing Legion state is rejected even when it is empty", () => {
	const root = fixtureRoot();
	try {
		const state = join(root, "home", ".config", "legion");
		mkdirSync(state, { recursive: true });
		const issues = detectPreexistingState({ roots: [root] });
		assert.deepEqual(issues.map((finding) => finding.path), [state]);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("canonical macOS installed root is rejected as pre-existing state", () => {
	const root = fixtureRoot();
	try {
		const installed = join(root, "home", "Library", "Application Support", "Orthic Labs", "Legion");
		mkdirSync(installed, { recursive: true });
		const issues = detectPreexistingState({ roots: [root] });
		assert.ok(issues.some((finding) => finding.path === installed));
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("development binaries on PATH fail unless the capability is explicitly installed", () => {
	const root = fixtureRoot();
	try {
		const bin = join(root, "bin");
		mkdirSync(bin);
		writeFileSync(join(bin, "omniroute"), "development shim\n");
		const contaminated = detectDevOnlyPathBinaries({ pathValue: bin, platform: process.platform });
		assert.equal(contaminated.length, 1);
		assert.equal(contaminated[0].kind, "dev-only-path-binary");
		assert.equal(detectDevOnlyPathBinaries({
			pathValue: bin,
			platform: process.platform,
			explicitlyInstalled: ["omniroute"],
			allowedPaths: [bin],
		}).length, 0);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("a clean fixture qualifies only with a normal release-artifact harness proof", () => {
	const root = fixtureRoot();
	try {
		const artifact = join(root, "legion-release.tgz");
		const installRoot = join(root, "harness-install");
		const harness = join(installRoot, "bin", "harness");
		const output = join(root, "qualification.json");
		const artifactBytes = Buffer.from("release artifact fixture\n");
		writeFileSync(artifact, artifactBytes);
		mkdirSync(join(installRoot, "bin"), { recursive: true });
		writeFileSync(harness, "installed harness fixture\n");
		const receipt = qualifyCleanEnvironment({
			releaseArtifact: artifact,
			isolatedRoot: root,
			harnessPath: harness,
			harnessInstallRoot: installRoot,
			harnessInstallation: {
				schemaVersion: 1,
				kind: "legion-clean-environment-harness-installation",
				method: "normal",
				status: "installed",
				source: "normal-installer",
				installer: "fixture-installer",
				installedPath: harness,
			},
			output,
			cwd: join(root, "clean-cwd"),
			pathValue: join(root, "clean-bin"),
			env: { PATH: join(root, "clean-bin") },
		});
		assert.equal(receipt.status, "qualified");
		assert.deepEqual(receipt.issues, []);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("a harness proof with a copied or mismatched artifact blocks qualification", () => {
	const root = fixtureRoot();
	try {
		const artifact = join(root, "legion-release.tgz");
		const installRoot = join(root, "harness-install");
		const harness = join(installRoot, "harness");
		const output = join(root, "qualification.json");
		writeFileSync(artifact, "release\n");
		mkdirSync(installRoot, { recursive: true });
		writeFileSync(harness, "harness\n");
		const receipt = qualifyCleanEnvironment({
			releaseArtifact: artifact,
			isolatedRoot: root,
			harnessPath: harness,
			harnessInstallRoot: installRoot,
			harnessInstallation: {
				schemaVersion: 1,
				kind: "legion-clean-environment-harness-installation",
				method: "copy",
				status: "installed",
				source: "workspace",
				artifactSha256: "sha256:wrong",
				installedPath: harness,
			},
			output,
			cwd: join(root, "clean-cwd"),
			pathValue: join(root, "clean-bin"),
			env: { PATH: join(root, "clean-bin") },
		});
		assert.equal(receipt.status, "blocked");
		assert.ok(receipt.issues.some((finding) => finding.kind === "harness-installation"));
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
