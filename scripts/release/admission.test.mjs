import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { admitRelease, verifyEvidence, writeStageSummary } from "./admission.mjs";

const base = Object.freeze({
	GITHUB_OUTPUT: "",
	RIGHT_GIT_WORKFLOW_REF: "refs/heads/main",
	RIGHT_GIT_RUN_ATTEMPT: "1",
	RIGHT_GIT_RELEASE_VERSION: "0.0.0",
	RIGHT_GIT_SOURCE_REVISION: "0".repeat(40),
});

function scratch(name) {
	return mkdtempSync(join(tmpdir(), `legion-admission-${name}-`));
}

test("admission refuses a dispatch that is not first-attempt on main", () => {
	const output = join(scratch("attempt"), "out.txt");
	writeFileSync(output, "");
	assert.throws(() => admitRelease({ ...base, GITHUB_OUTPUT: output, RIGHT_GIT_WORKFLOW_REF: "refs/heads/topic" }), /refs\/heads\/main/);
	assert.throws(() => admitRelease({ ...base, GITHUB_OUTPUT: output, RIGHT_GIT_RUN_ATTEMPT: "2" }), /first run attempt/);
	assert.throws(() => admitRelease({ ...base, GITHUB_OUTPUT: output, RIGHT_GIT_RELEASE_VERSION: "0.3" }), /exact semver/);
});

test("admission requires GITHUB_OUTPUT before any other work", () => {
	assert.throws(() => admitRelease({ ...base, GITHUB_OUTPUT: "" }), /GITHUB_OUTPUT/);
});

// Gate 0A: version/tag/release contradiction. The dispatched version must be the
// one the frozen source declares, or artifacts carry a version the tag does not.
test("admission rejects a version that contradicts release/version.json", () => {
	const output = join(scratch("version"), "out.txt");
	writeFileSync(output, "");
	const declared = JSON.parse(readFileSync(new URL("../../release/version.json", import.meta.url), "utf8")).version;
	const wrong = declared === "9.9.9" ? "9.9.8" : "9.9.9";
	assert.throws(() => admitRelease({ ...base, GITHUB_OUTPUT: output, RIGHT_GIT_RELEASE_VERSION: wrong }), /contradicts release\/version\.json/);
});

test("admission dry_run accepts any branch ref, skips first-attempt, and refuses publish=true", () => {
	const output = join(scratch("dryrun"), "out.txt");
	writeFileSync(output, "");
	const declared = JSON.parse(readFileSync(new URL("../../release/version.json", import.meta.url), "utf8")).version;
	const dryBase = { ...base, GITHUB_OUTPUT: output, RIGHT_GIT_RELEASE_VERSION: declared, RIGHT_GIT_DRY_RUN: "true" };
	// A real dispatch still requires refs/heads/main + first attempt.
	assert.throws(() => admitRelease({ ...base, GITHUB_OUTPUT: output, RIGHT_GIT_WORKFLOW_REF: "refs/heads/topic" }), /refs\/heads\/main/);
	// A dry run accepts a branch ref and a non-first attempt, reaching source-
	// revision resolution (which only fails because the SHA here is synthetic).
	assert.throws(() => admitRelease({ ...dryBase, RIGHT_GIT_WORKFLOW_REF: "refs/heads/topic", RIGHT_GIT_RUN_ATTEMPT: "4" }), /known commit/);
	// A dry run must never be combined with publish=true.
	assert.throws(() => admitRelease({ ...dryBase, RIGHT_GIT_WORKFLOW_REF: "refs/heads/topic", RIGHT_GIT_PUBLISH: "true" }), /refuses publish=true together with dry_run=true/);
	// A dry run from a non-branch ref is still rejected.
	assert.throws(() => admitRelease({ ...dryBase, RIGHT_GIT_WORKFLOW_REF: "refs/tags/v9.9.9" }), /requires dispatch from a branch/);
});

test("stage-summary cannot mark a nonzero exit code succeeded", () => {
	const root = scratch("stage");
	const env = {
		RIGHT_GIT_STAGE_ACTION: "finalize",
		RIGHT_GIT_STAGE_ROOT: root,
		RIGHT_GIT_STAGE: "candidate",
		RIGHT_GIT_RELEASE_VERSION: "0.3.12",
		RIGHT_GIT_SOURCE_REVISION: "a".repeat(40),
		RIGHT_GIT_STAGE_STATUS: "succeeded",
		RIGHT_GIT_STAGE_EXIT_CODE: "2",
	};
	assert.throws(() => writeStageSummary(env), /nonzero exit code/);
	const ok = writeStageSummary({ ...env, RIGHT_GIT_STAGE_EXIT_CODE: "0" });
	assert.equal(ok.status, "SUCCEEDED");
	assert.equal(JSON.parse(readFileSync(join(root, "stage-summary.json"), "utf8")).stage, "candidate");
});

test("evidence-verification refuses to publish without every required stage", () => {
	const root = scratch("evidence");
	const stage = join(root, "candidate-windows");
	mkdirSync(stage, { recursive: true });
	writeFileSync(join(stage, "stage-summary.json"), JSON.stringify({
		schemaVersion: 1, stage: "candidate", action: "finalize", status: "SUCCEEDED",
		version: "0.3.12", sourceRevision: "a".repeat(40), platform: "windows", architecture: "x86_64",
		runId: "1", runAttempt: "1",
	}));
	assert.throws(() => verifyEvidence({
		RIGHT_GIT_RELEASE_VERSION: "0.3.12",
		RIGHT_GIT_SOURCE_REVISION: "a".repeat(40),
		RIGHT_GIT_RUN_ID: "1",
		RIGHT_GIT_RUN_ATTEMPT: "1",
		RIGHT_GIT_STAGE_SUMMARY_ROOT: root,
	}), /missing a required stage summary/);
});
