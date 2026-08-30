import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import {
	finalizeMacos,
	finalizeWindows,
	publishQualified,
	qualifyInstalled,
} from "../../scripts/release/installer-release-chain.mjs";

const REVISION = "a".repeat(40);

test("direct CLI finalizer reads process environment", () => {
	const result = spawnSync(process.execPath, ["scripts/release/installer-release-chain.mjs", "finalize-windows"], { cwd: process.cwd(), encoding: "utf8", env: {} });
	assert.notEqual(result.status, 0);
	assert.doesNotMatch(result.stderr, /Cannot read properties of undefined/);
	assert.match(result.stderr, /RIGHT_GIT_SOURCE_REVISION is required/);
});

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "legion-installer-chain-"));
	mkdirSync(join(root, "release"), { recursive: true });
	writeFileSync(join(root, "release", "version.json"), JSON.stringify({ version: "1.2.3" }));
	for (const path of ["scripts/release/windows/finalize.mjs", "scripts/release/macos/finalize.mjs", "scripts/release/windows/qualify-installed.mjs"]) {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), "// fixture\n");
	}
	return root;
}
function env(root, platform, architecture) {
	const candidate = join(root, `candidate-${platform}`);
	mkdirSync(candidate, { recursive: true });
	const stem = `legion-1.2.3-${platform}-${architecture}`;
	const sbom = join(candidate, `${stem}.cdx.json`);
	const provenance = join(candidate, `${stem}.intoto.jsonl`);
	writeFileSync(sbom, "sbom\n");
	writeFileSync(provenance, "provenance\n");
	writeFileSync(join(candidate, "candidate.json"), JSON.stringify({
		schemaVersion: 1, kind: "legion-unsigned-release-candidate", product: "legion", version: "1.2.3", target: `${platform}-${architecture}`, sourceRevision: REVISION,
		files: {
			sbom: { name: `${stem}.cdx.json`, size: statSync(sbom).size, sha256: sha(sbom) },
			provenance: { name: `${stem}.intoto.jsonl`, size: statSync(provenance).size, sha256: sha(provenance) },
		},
	}));
	return {
		RIGHT_GIT_SOURCE_REVISION: REVISION,
		RIGHT_GIT_UNSIGNED_CANDIDATE_ROOT: candidate,
		RIGHT_GIT_RELEASE_PLATFORM: platform,
		RIGHT_GIT_RELEASE_ARCHITECTURE: architecture,
		RIGHT_GIT_FINALIZED_WINDOWS_ROOT: join(root, "finalized-windows"),
		RIGHT_GIT_FINALIZED_MACOS_ROOT: join(root, "finalized-macos"),
		RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT: join(root, "qualification"),
	};
}
function sha(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}
function finalizerRun(kind) {
	return (command, args, options = {}) => {
		if (command === process.execPath) {
			const platform = args.at(-2) === "win" ? "windows" : "macos";
			const output = join(options.cwd, "dist", "releases", platform === "windows" ? "windows" : "mac", "1.2.3", options.env.RIGHT_GIT_RELEASE_ARCHITECTURE);
			mkdirSync(output, { recursive: true });
			writeFileSync(join(output, `legion-1.2.3-${platform}-${options.env.RIGHT_GIT_RELEASE_ARCHITECTURE}.${platform === "windows" ? "zip" : "tar.gz"}`), "signed portable\n");
			return { status: 0, stdout: "", stderr: "" };
		}
		if (command !== "node") throw new Error(`unexpected command ${command}`);
		const output = args[args.indexOf("--output-root") + 1];
		const version = args[args.indexOf("--version") + 1];
		const architecture = args[args.indexOf("--architecture") + 1];
		const installer = join(output, kind === "windows" ? `legion-${version}-windows-${architecture}-setup.exe` : `legion-${version}-macos-${architecture}.dmg`);
		const portable = join(output, kind === "windows" ? `legion-${version}-windows-${architecture}.zip` : `legion-${version}-macos-${architecture}.tar.gz`);
		const evidence = join(output, `${kind}-signing.json`);
		mkdirSync(output, { recursive: true });
		writeFileSync(installer, `${kind} installer\n`);
		writeFileSync(portable, `${kind} portable\n`);
		writeFileSync(evidence, `${kind} evidence\n`);
		const record = (path, role) => ({ path, role, size: statSync(path).size, sha256: sha(path) });
		return { status: 0, stdout: JSON.stringify({ schemaVersion: 1, kind: `legion-${kind}-installer-finalization`, status: "finalized", product: "legion", version, sourceRevision: REVISION, architecture, assets: [record(installer, "installer")], evidence: [record(portable, "portable"), record(evidence, "signing-receipt")] }) };
	};
}

test("finalizers map RightGit inputs, run RightRelease, & copy only digest-bound installer evidence", () => {
	const root = fixture();
	try {
		const windows = finalizeWindows({ env: env(root, "windows", "x86_64"), repositoryRoot: root, run: finalizerRun("windows") });
		const macos = finalizeMacos({ env: env(root, "macos", "arm64"), repositoryRoot: root, run: finalizerRun("macos") });
		assert.equal(windows.assets.length, 1);
		assert.equal(windows.evidence.length, 2);
		assert.equal(macos.assets[0].name.endsWith(".dmg"), true);
		assert.equal(JSON.parse(readFileSync(windows.manifest)).sourceRevision, REVISION);
		assert.equal(windows.assets[0].path.includes(".staging"), false);
	} finally { rmSync(root, { recursive: true, force: true }); }
});

test("finalization fails closed on stale output & platform-path escape", () => {
	const root = fixture();
	try {
		const values = env(root, "windows", "x86_64");
		mkdirSync(values.RIGHT_GIT_FINALIZED_WINDOWS_ROOT, { recursive: true });
		writeFileSync(join(values.RIGHT_GIT_FINALIZED_WINDOWS_ROOT, "stale"), "stale");
		assert.throws(() => finalizeWindows({ env: values, repositoryRoot: root, run: finalizerRun("windows") }), /must be empty/);
		rmSync(values.RIGHT_GIT_FINALIZED_WINDOWS_ROOT, { recursive: true, force: true });
		const clean = env(root, "windows", "x86_64");
		const escaping = finalizerRun("windows");
		assert.throws(() => finalizeWindows({ env: clean, repositoryRoot: root, run: (command, args, options) => {
			const value = escaping(command, args, options);
			if (command === "node") value.stdout = JSON.stringify({ schemaVersion: 1, kind: "legion-windows-installer-finalization", status: "finalized", product: "legion", version: "1.2.3", sourceRevision: REVISION, architecture: "x86_64", assets: [{ path: "../escape.exe", role: "installer", size: 1, sha256: "a".repeat(64) }], evidence: [{ path: "../escape.json", role: "portable", size: 1, sha256: "a".repeat(64) }] });
			return value;
		} }), /escapes root/);
	} finally { rmSync(root, { recursive: true, force: true }); }
});

test("RightRelease startup failures retain Windows spawn diagnostics", () => {
	const root = fixture();
	try {
		const values = env(root, "windows", "x86_64");
		assert.throws(
			() => finalizeWindows({ env: values, repositoryRoot: root, run: () => ({ status: null, stdout: "", stderr: "", error: new Error("spawnSync node EINVAL") }) }),
			/spawnSync node EINVAL/,
		);
	} finally { rmSync(root, { recursive: true, force: true }); }
});

test("installed qualification requires exact finalized setup & returns digest-bound evidence", () => {
	const root = fixture();
	try {
		const values = env(root, "windows", "x86_64");
		const finalization = finalizeWindows({ env: values, repositoryRoot: root, run: finalizerRun("windows") });
		const result = qualifyInstalled({ env: { ...values, RIGHT_GIT_TEST_PLATFORM: "win32" }, repositoryRoot: root, run(command, args) {
			assert.equal(command, "node");
			assert.equal(args.includes("--setup"), true);
			const output = args[args.indexOf("--output-root") + 1];
			mkdirSync(output, { recursive: true });
			const evidence = join(output, "installed-qualification.json");
			writeFileSync(evidence, "qualified\n");
			return { status: 0, stdout: JSON.stringify({ schemaVersion: 1, kind: "legion-windows-installed-installer-qualification", status: "qualified", product: "legion", version: "1.2.3", sourceRevision: REVISION, windowsFinalizationSha256: finalization.digest, evidence: { path: evidence, role: "qualification", size: statSync(evidence).size, sha256: sha(evidence) } }) };
		} });
		assert.equal(result.finalizationDigest, finalization.digest);
	} finally { rmSync(root, { recursive: true, force: true }); }
});

test("publish creates/resumes release then downloads every exact asset for digest verification", () => {
	const root = fixture();
	try {
		const windowsEnv = env(root, "windows", "x86_64");
		const windows = finalizeWindows({ env: windowsEnv, repositoryRoot: root, run: finalizerRun("windows") });
		const macos = finalizeMacos({ env: env(root, "macos", "arm64"), repositoryRoot: root, run: finalizerRun("macos") });
		const qualificationRoot = windowsEnv.RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT;
		mkdirSync(qualificationRoot, { recursive: true });
		const qualification = join(qualificationRoot, "qualification.json");
		writeFileSync(qualification, JSON.stringify({ schemaVersion: 1, kind: "legion-windows-installed-installer-qualification", status: "qualified", product: "legion", version: "1.2.3", sourceRevision: REVISION, windowsFinalizationSha256: windows.digest }));
		const uploaded = new Map(); let viewCount = 0;
		const result = publishQualified({ env: { ...windowsEnv, GH_TOKEN: "test-token" }, repositoryRoot: root, downloadRoot: join(root, "downloads"), run(command, args) {
			assert.equal(command, "gh");
			if (args[0] === "release" && args[1] === "view") {
				viewCount += 1;
				if (viewCount === 1) return { status: 1, stderr: "not found" };
				return { status: 0, stdout: JSON.stringify({ tagName: "v1.2.3", assets: [...uploaded].map(([name, path]) => ({ name, size: statSync(path).size })) }) };
			}
			if (args[0] === "release" && args[1] === "create") return { status: 0, stdout: "created" };
			if (args[0] === "release" && args[1] === "upload") { uploaded.set(args[3].split(/[\\/]/).at(-1), args[3]); return { status: 0, stdout: "uploaded" }; }
			if (args[0] === "release" && args[1] === "download") { const name = args[args.indexOf("--pattern") + 1]; const destination = join(args[args.indexOf("--dir") + 1], name); mkdirSync(dirname(destination), { recursive: true }); writeFileSync(destination, readFileSync(uploaded.get(name))); return { status: 0, stdout: "downloaded" }; }
			throw new Error(`unexpected gh command ${args.join(" ")}`);
		} });
		assert.equal(result.status, "published");
		assert.equal(result.macosFinalizationSha256, macos.digest);
	} finally { rmSync(root, { recursive: true, force: true }); }
});
