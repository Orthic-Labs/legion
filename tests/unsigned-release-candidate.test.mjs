import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
	checkUnsignedCandidate,
	inferTarget,
	prepareUnsignedCandidate,
} from "../scripts/ci/prepare-unsigned-candidate.mjs";
import { prepareWindowsCandidateFinalization } from "../scripts/prepare-windows-candidate-finalization.mjs";

test("unsigned candidates require explicit platform and architecture", () => {
	assert.deepEqual(inferTarget({ platform: "win32", architecture: "x64" }), {
		platform: "windows",
		architecture: "x86_64",
		target: "windows-x86_64",
	});
	assert.throws(() => inferTarget(), /explicit platform and architecture/);
});

test("unsigned candidate binds portable archive to CycloneDX 1.6 and SLSA v1 evidence", () => {
	const root = mkdtempSync(join(tmpdir(), "legion-unsigned-candidate-"));
	const repositoryRoot = join(root, "repo");
	const input = join(root, "install");
	const outputRoot = join(root, "artifacts");
	try {
		mkdirSync(join(repositoryRoot, "release"), { recursive: true });
		writeFileSync(
			join(repositoryRoot, "release", "version.json"),
			JSON.stringify({ schemaVersion: 1, kind: "legion-release-version", version: "0.1.0" }),
		);
		mkdirSync(join(input, "bin"), { recursive: true });
		writeFileSync(join(input, "bin", "legion"), "candidate runtime\n");

		const result = prepareUnsignedCandidate({
			input,
			outputRoot,
			repositoryRoot,
			platform: "darwin",
			architecture: "arm64",
			sourceRevision: "a".repeat(40),
			createdAt: "2026-08-28T00:00:00.000Z",
			env: {},
			createArchive: ({ outputPath }) => {
				mkdirSync(dirname(outputPath), { recursive: true });
				writeFileSync(outputPath, "portable archive\n");
				return { path: outputPath };
			},
		});

		assert.equal(result.status, "complete");
		assert.equal(result.target, "macos-arm64");
		assert.equal(result.version, "0.1.0");
		assert.equal(result.sourceRevision, "a".repeat(40));
		assert.ok(result.archive.endsWith("legion-0.1.0-macos-arm64.tar.gz"));
		assert.ok(result.candidate.endsWith("candidate.json"));
		const candidate = JSON.parse(readFileSync(result.candidate, "utf8"));
		assert.deepEqual(Object.keys(candidate.files).sort(), ["archive", "provenance", "sbom"]);
		const sbom = JSON.parse(readFileSync(result.sbom, "utf8"));
		assert.equal(sbom.specVersion, "1.6");
		assert.equal(sbom.components[0].name, "legion-0.1.0-macos-arm64.tar.gz");
		const provenance = JSON.parse(readFileSync(result.provenance, "utf8"));
		assert.equal(provenance.predicateType, "https://slsa.dev/provenance/v1");
		assert.equal(provenance.subject[0].digest.sha256, result.archiveSha256);
		assert.equal(
			checkUnsignedCandidate({
				outputRoot,
				repositoryRoot,
				platform: "darwin",
				architecture: "arm64",
				sourceRevision: "a".repeat(40),
				env: {},
			}).status,
			"verified",
		);
		const originalSbom = readFileSync(result.sbom);
		writeFileSync(result.sbom, Buffer.concat([originalSbom, Buffer.from("tampered\n")]));
		assert.throws(
			() => checkUnsignedCandidate({
				outputRoot,
				repositoryRoot,
				platform: "darwin",
				architecture: "arm64",
				sourceRevision: "a".repeat(40),
				env: {},
			}),
			/candidate file digest or size mismatch/,
		);
		writeFileSync(result.sbom, originalSbom);
		writeFileSync(join(outputRoot, "extra.txt"), "unexpected\n");
		assert.throws(
			() => checkUnsignedCandidate({
				outputRoot,
				repositoryRoot,
				platform: "darwin",
				architecture: "arm64",
				sourceRevision: "a".repeat(40),
				env: {},
			}),
			/exactly candidate\.json, archive, SBOM, and provenance/,
		);
		assert.throws(
			() => prepareUnsignedCandidate({
				input,
				outputRoot: join(input, "nested-artifacts"),
				repositoryRoot,
				platform: "darwin",
				architecture: "arm64",
				sourceRevision: "a".repeat(40),
				env: {},
				createArchive: () => {
					throw new Error("archive should not be created");
				},
			}),
			/candidate artifacts must be outside assembled install root/,
		);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("Windows finalization expands exact verified candidate bytes and records pre-sign identity", { skip: process.platform !== "win32" }, () => {
	const root = mkdtempSync(join(tmpdir(), "legion-windows-candidate-"));
	const repositoryRoot = join(root, "repo");
	const input = join(root, "install");
	const outputRoot = join(root, "candidate");
	const extracted = join(repositoryRoot, "dist", "native", "windows-x86_64", "legion-0.1.0");
	const receiptPath = join(repositoryRoot, ".right-release", "receipts", "candidate.json");
	try {
		mkdirSync(join(repositoryRoot, "release"), { recursive: true });
		writeFileSync(join(repositoryRoot, "release", "version.json"), JSON.stringify({ schemaVersion: 1, kind: "legion-release-version", version: "0.1.0" }));
		mkdirSync(join(input, "bin"), { recursive: true });
		for (const name of ["legion.exe", "legion-hook.exe", "legion-mcp.exe"]) writeFileSync(join(input, "bin", name), `${name}\n`);
		const candidate = prepareUnsignedCandidate({
			input,
			outputRoot,
			repositoryRoot,
			platform: "windows",
			architecture: "x86_64",
			sourceRevision: "b".repeat(40),
			createdAt: "2026-08-28T00:00:00.000Z",
			env: {},
		});
		const result = prepareWindowsCandidateFinalization({
			candidateRoot: outputRoot,
			outputRoot: extracted,
			architecture: "x86_64",
			sourceRevision: "b".repeat(40),
			version: "0.1.0",
			receiptPath,
			repositoryRoot,
		});
		assert.equal(result.candidateArchiveSha256, candidate.archiveSha256);
		assert.deepEqual(result.files.map(({ file }) => file), ["bin/legion.exe", "bin/legion-hook.exe", "bin/legion-mcp.exe"]);
		assert.equal(JSON.parse(readFileSync(receiptPath, "utf8")).candidateArchiveSha256, candidate.archiveSha256);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
