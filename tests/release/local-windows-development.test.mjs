import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { localFinalization, resolveInnoCompiler } from "../../scripts/release/local-windows-development.mjs";

test("local Windows route records unsigned identity & resolves explicit Inno compiler", () => {
	const root = mkdtempSync(join(tmpdir(), "legion-local-windows-"));
	try {
		const compiler = join(root, "ISCC.exe");
		const installer = join(root, "Legion-1.2.3-windows-x86_64-setup.exe");
		mkdirSync(root, { recursive: true });
		writeFileSync(compiler, "compiler");
		writeFileSync(installer, "installer");
		assert.equal(resolveInnoCompiler({ INNO_SETUP_PATH: compiler }), compiler);
		const result = localFinalization({ installer, releaseVersion: "1.2.3", sourceRevision: "a".repeat(40) });
		assert.equal(result.status, "local-unsigned");
		assert.equal(result.profile, "internal-unsigned");
		assert.equal(result.signing.status, "unsigned");
		assert.equal(result.assets[0].role, "installer");
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
