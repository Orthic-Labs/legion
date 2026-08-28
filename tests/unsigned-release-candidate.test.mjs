import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
	checkUnsignedCandidate,
	prepareUnsignedCandidate,
} from "../scripts/ci/prepare-unsigned-candidate.mjs";

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
		assert.ok(result.candidate.endsWith("candidate.json"));
		const candidate = JSON.parse(readFileSync(result.candidate, "utf8"));
		assert.deepEqual(Object.keys(candidate.files).sort(), ["archive", "provenance", "sbom"]);
		const sbom = JSON.parse(readFileSync(result.sbom, "utf8"));
		assert.equal(sbom.specVersion, "1.6");
		assert.equal(sbom.components[0].name, "legion-0.1.0-macos-arm64.zip");
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
