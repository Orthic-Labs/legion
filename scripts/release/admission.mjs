#!/usr/bin/env node
/**
 * Gate 0A — static source closure for the Legion release chain.
 *
 * Admission runs before any platform fanout, without release credentials, and
 * refuses a dispatch whose source identity, CI state, or version identity is
 * not already closed. Every check here is deterministic: it reads committed
 * state and completed CI conclusions, never model judgement.
 */
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const REPOSITORY = "Orthic-Labs/legion";
const CI_WORKFLOW = "ci.yml";

// Stages that must each carry a SUCCEEDED finalize stage-summary, bound to this
// exact version + source revision + run, before publication may proceed.
export const REQUIRED_RELEASE_STAGES = Object.freeze([
	{ stage: "candidate", platform: "windows", architecture: "x86_64" },
	{ stage: "candidate", platform: "macos", architecture: "arm64" },
	{ stage: "windows-sign", platform: "windows", architecture: "x86_64" },
	{ stage: "macos-sign", platform: "macos", architecture: "arm64" },
	{ stage: "installed-qualification" },
]);

function fail(message) { throw new Error(message); }

function git(args) {
	return spawnSync("git", args, { cwd: ROOT, windowsHide: true, encoding: "utf8" });
}

function sha256(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function declaredVersion() {
	const path = join(ROOT, "release", "version.json");
	if (!existsSync(path)) fail("release chain admission requires release/version.json");
	const parsed = JSON.parse(readFileSync(path, "utf8"));
	if (typeof parsed.version !== "string") fail("release/version.json does not declare a version");
	return parsed.version;
}

/**
 * The admission job checks out the dispatched revision, so comparing against
 * HEAD would be tautological. Ancestry is proven against the real remote ref,
 * fetching it explicitly when the remote-tracking ref is not present.
 */
export function assertSourceRevisionIsAncestorOfMain(revision, { remote = "origin", branch = "main" } = {}) {
	const ref = `${remote}/${branch}`;
	if (git(["rev-parse", "--verify", "-q", ref]).status !== 0) {
		if (git(["fetch", remote, branch]).status !== 0) fail(`release chain admission could not fetch ${remote} ${branch} to verify ancestry`);
		if (git(["rev-parse", "--verify", "-q", ref]).status !== 0) fail(`release chain admission could not resolve ${ref} after fetch`);
	}
	if (git(["merge-base", "--is-ancestor", revision, ref]).status !== 0) fail(`release chain admission source revision is not an ancestor of ${ref}`);
}

export function tagOrReleaseExists(version) {
	const tag = `v${version}`;
	if (git(["ls-remote", "--exit-code", "--tags", "origin", `refs/tags/${tag}`]).status === 0) return true;
	const view = spawnSync("gh", ["release", "view", tag, "--repo", REPOSITORY, "--json", "tagName"], { cwd: ROOT, windowsHide: true, encoding: "utf8" });
	return view.status === 0;
}

/**
 * Gate 0A: same-SHA CI must be terminal and green. A release admitted while its
 * own CI is still running can be authorized by a run that later turns red, which
 * is exactly how one Membrane release began against a red tree.
 */
export function assertSameShaCiIsGreen(revision) {
	const listed = spawnSync(
		"gh",
		["run", "list", "--repo", REPOSITORY, "--commit", revision, "--workflow", CI_WORKFLOW, "--json", "status,conclusion,databaseId", "--limit", "25"],
		{ cwd: ROOT, windowsHide: true, encoding: "utf8" },
	);
	if (listed.status !== 0) fail(`release chain admission could not read same-SHA CI runs: ${listed.stderr?.trim() ?? "gh failed"}`);
	let runs;
	try { runs = JSON.parse(listed.stdout); } catch { fail("release chain admission could not parse same-SHA CI runs"); }
	if (!Array.isArray(runs) || runs.length === 0) fail(`release chain admission found no ${CI_WORKFLOW} run for ${revision}`);
	const unfinished = runs.filter((run) => run.status !== "completed");
	if (unfinished.length) fail(`release chain admission requires terminal same-SHA CI; ${unfinished.length} run(s) still in progress`);
	if (!runs.some((run) => run.conclusion === "success")) fail(`release chain admission requires a successful ${CI_WORKFLOW} run for ${revision}`);
	const failed = runs.filter((run) => run.conclusion !== "success" && run.conclusion !== "cancelled" && run.conclusion !== "skipped");
	if (failed.length) fail(`release chain admission found a non-green same-SHA CI run: ${failed.map((run) => `${run.databaseId}:${run.conclusion}`).join(", ")}`);
}

export function admitRelease(env = process.env) {
	const outputPath = env.GITHUB_OUTPUT;
	if (!outputPath) fail("release chain admission requires GITHUB_OUTPUT");
	const ref = env.RIGHT_GIT_WORKFLOW_REF;
	if (ref !== "refs/heads/main") fail(`release chain admission requires dispatch from refs/heads/main, got: ${ref}`);
	const runAttempt = env.RIGHT_GIT_RUN_ATTEMPT;
	if (!/^\d+$/.test(runAttempt ?? "") || Number(runAttempt) !== 1) fail(`release chain admission requires the first run attempt, got: ${runAttempt}`);
	const releaseVersion = env.RIGHT_GIT_RELEASE_VERSION ?? "";
	if (!/^\d+\.\d+\.\d+$/.test(releaseVersion)) fail(`release chain admission requires an exact semver release version, got: ${releaseVersion}`);

	// Version/tag/release contradiction: the dispatched version must be the one
	// the frozen source actually declares, or the built artifacts carry a
	// different version than the tag they are published under.
	const declared = declaredVersion();
	if (declared !== releaseVersion) fail(`release chain admission version ${releaseVersion} contradicts release/version.json ${declared}`);

	const revision = env.RIGHT_GIT_SOURCE_REVISION ?? "";
	if (!/^[a-f0-9]{40}$/.test(revision)) fail("release chain admission requires an exact 40-character lowercase source revision SHA");
	if (git(["cat-file", "-e", `${revision}^{commit}`]).status !== 0) fail("release chain admission source revision does not resolve to a known commit");
	assertSourceRevisionIsAncestorOfMain(revision);
	assertSameShaCiIsGreen(revision);

	const signedQualification = env.RIGHT_GIT_SIGNED_QUALIFICATION === "true";
	const publish = env.RIGHT_GIT_PUBLISH === "true";
	if (publish && !signedQualification) fail("release chain admission requires signed_qualification=true whenever publish=true");
	if (tagOrReleaseExists(releaseVersion)) fail(`release chain admission version v${releaseVersion} already has a tag or release (drafts included)`);

	for (const [key, value] of [["version", releaseVersion], ["source_revision", revision], ["signed_qualification", String(signedQualification)], ["publish", String(publish)]]) {
		appendFileSync(outputPath, `${key}=${value}\n`);
	}
	return { status: "admitted", version: releaseVersion, sourceRevision: revision, signedQualification, publish };
}

function collectEvidenceFiles(root) {
	if (!root || !existsSync(root)) return [];
	return readdirSync(root, { recursive: true })
		.filter((entry) => statSync(join(root, entry)).isFile())
		.map((entry) => ({ name: String(entry).replaceAll("\\", "/"), sha256: sha256(join(root, entry)), size: statSync(join(root, entry)).size }));
}

export function writeStageSummary(env = process.env) {
	const action = env.RIGHT_GIT_STAGE_ACTION;
	if (action !== "init" && action !== "finalize") fail(`release chain stage-summary requires RIGHT_GIT_STAGE_ACTION of init or finalize, got: ${action}`);
	const stageRoot = env.RIGHT_GIT_STAGE_ROOT;
	if (!stageRoot) fail("release chain stage-summary requires RIGHT_GIT_STAGE_ROOT");
	const stage = env.RIGHT_GIT_STAGE;
	if (!stage) fail("release chain stage-summary requires RIGHT_GIT_STAGE");
	const releaseVersion = env.RIGHT_GIT_RELEASE_VERSION;
	const revision = env.RIGHT_GIT_SOURCE_REVISION;
	if (!releaseVersion || !revision) fail("release chain stage-summary requires RIGHT_GIT_RELEASE_VERSION & RIGHT_GIT_SOURCE_REVISION");
	let status = "STARTED";
	let exitCode = null;
	if (action === "finalize") {
		status = (env.RIGHT_GIT_STAGE_STATUS ?? "").toUpperCase();
		if (status !== "SUCCEEDED" && status !== "FAILED") fail(`release chain stage-summary requires RIGHT_GIT_STAGE_STATUS of succeeded or failed, got: ${env.RIGHT_GIT_STAGE_STATUS}`);
		const raw = env.RIGHT_GIT_STAGE_EXIT_CODE;
		if (raw === undefined || raw === "" || Number.isNaN(Number(raw))) fail("release chain stage-summary finalize requires a numeric RIGHT_GIT_STAGE_EXIT_CODE");
		exitCode = Number(raw);
		if (status === "SUCCEEDED" && exitCode !== 0) fail("release chain stage-summary cannot mark a nonzero exit code SUCCEEDED");
	}
	mkdirSync(stageRoot, { recursive: true });
	const summary = {
		schemaVersion: 1,
		stage,
		action,
		producer: env.RIGHT_GIT_STAGE_PRODUCER ?? null,
		status,
		exitCode,
		version: releaseVersion,
		sourceRevision: revision,
		platform: env.RIGHT_GIT_RELEASE_PLATFORM ?? null,
		architecture: env.RIGHT_GIT_RELEASE_ARCHITECTURE ?? null,
		runId: env.RIGHT_GIT_RUN_ID ?? null,
		runAttempt: env.RIGHT_GIT_RUN_ATTEMPT ?? null,
		evidence: collectEvidenceFiles(env.RIGHT_GIT_STAGE_EVIDENCE_ROOT),
		recordedAt: new Date().toISOString(),
	};
	writeFileSync(join(stageRoot, "stage-summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
	return summary;
}

function findStageSummaries(root) {
	if (!existsSync(root)) fail(`release chain evidence-verification root is missing: ${root}`);
	return readdirSync(root, { recursive: true })
		.filter((entry) => String(entry).split(/[\\/]/).pop() === "stage-summary.json")
		.map((entry) => JSON.parse(readFileSync(join(root, entry), "utf8")));
}

export function verifyEvidence(env = process.env) {
	const releaseVersion = env.RIGHT_GIT_RELEASE_VERSION;
	const revision = env.RIGHT_GIT_SOURCE_REVISION;
	const runId = env.RIGHT_GIT_RUN_ID;
	const runAttempt = env.RIGHT_GIT_RUN_ATTEMPT;
	const stageSummaryRoot = env.RIGHT_GIT_STAGE_SUMMARY_ROOT;
	if (!releaseVersion || !revision || !runId || !runAttempt || !stageSummaryRoot) {
		fail("release chain evidence-verification requires RIGHT_GIT_RELEASE_VERSION, RIGHT_GIT_SOURCE_REVISION, RIGHT_GIT_RUN_ID, RIGHT_GIT_RUN_ATTEMPT & RIGHT_GIT_STAGE_SUMMARY_ROOT");
	}
	const summaries = findStageSummaries(stageSummaryRoot).filter((summary) =>
		summary.action === "finalize"
		&& summary.version === releaseVersion
		&& summary.sourceRevision === revision
		&& String(summary.runId) === String(runId)
		&& String(summary.runAttempt) === String(runAttempt));
	for (const required of REQUIRED_RELEASE_STAGES) {
		const label = required.platform ? `${required.stage} (${required.platform}/${required.architecture})` : required.stage;
		const summary = summaries.find((entry) => entry.stage === required.stage
			&& (required.platform === undefined || entry.platform === required.platform)
			&& (required.architecture === undefined || entry.architecture === required.architecture));
		if (!summary) fail(`release chain evidence-verification is missing a required stage summary: ${label}`);
		if (summary.status !== "SUCCEEDED") fail(`release chain evidence-verification stage did not succeed: ${label}`);
	}
	return {
		schemaVersion: 1,
		verified: true,
		version: releaseVersion,
		sourceRevision: revision,
		runId: String(runId),
		runAttempt: String(runAttempt),
		stages: summaries.map((summary) => ({ stage: summary.stage, platform: summary.platform, architecture: summary.architecture, status: summary.status })),
	};
}
