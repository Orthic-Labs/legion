import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { qualifyInstalledWindows } from "./qualify-installed.mjs";

const VERSION = "0.3.12";
const REVISION = "a".repeat(40);

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "legion-qualify-evidence-"));
	const setup = join(root, "Legion-setup.exe");
	writeFileSync(setup, "not a real installer");
	const finalizationPath = join(root, "finalization.json");
	writeFileSync(finalizationPath, JSON.stringify({
		schemaVersion: 1,
		kind: "legion-installer-finalization",
		product: "legion",
		platform: "windows",
		version: VERSION,
		sourceRevision: REVISION,
		assets: [{ role: "installer", name: "Legion-setup.exe" }],
	}));
	const outputRoot = join(root, "out");
	return { root, setup, finalizationPath, outputRoot };
}

// Phase A item 9: a failed installed qualification previously deleted its
// workspace in `finally` and wrote nothing, so remote failures produced no
// diagnostic bundle and had to be reproduced by re-downloading signed bytes.
test("a failed qualification writes failure evidence before cleanup", () => {
	const { setup, finalizationPath, outputRoot } = fixture();
	const commandRunner = () => ({ status: 1, stdout: "", stderr: "installer exited 2" });

	assert.throws(() => qualifyInstalledWindows({
		setup,
		outputRoot,
		finalizationPath,
		sourceRevision: REVISION,
		version: VERSION,
		commandRunner,
		platform: "win32",
	}));

	const failurePath = join(outputRoot, "qualification-failure.json");
	assert.ok(existsSync(failurePath), "qualification-failure.json must exist after a failed run");
	const failure = JSON.parse(readFileSync(failurePath, "utf8"));
	assert.equal(failure.kind, "legion-windows-installed-installer-qualification-failure");
	assert.equal(failure.status, "failed");
	assert.equal(failure.failedStage, "install");
	assert.equal(failure.version, VERSION);
	assert.equal(failure.sourceRevision, REVISION);
	assert.match(failure.error, /silent setup failed/);
	assert.ok(typeof failure.setup?.sha256 === "string" && failure.setup.sha256.length === 64);
	assert.ok(Array.isArray(failure.installTree));
	assert.ok(typeof failure.recordedAt === "string");
});

test("a successful qualification still writes no failure receipt", () => {
	const { setup, finalizationPath, outputRoot } = fixture();
	// The install step fails, so only the failure receipt is produced; assert the
	// qualified receipt is not fabricated alongside it.
	const commandRunner = () => ({ status: 1, stdout: "", stderr: "boom" });
	assert.throws(() => qualifyInstalledWindows({
		setup, outputRoot, finalizationPath, sourceRevision: REVISION, version: VERSION, commandRunner, platform: "win32",
	}));
	assert.equal(existsSync(join(outputRoot, "qualification.json")), false);
});
