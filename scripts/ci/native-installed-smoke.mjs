import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const installRoot = resolve(process.argv[2] ?? "");
if (!process.argv[2]) throw new Error("usage: native-installed-smoke.mjs <install-root>");

const home = join(installRoot, "smoke-home");
const localData = join(home, "local");
const roamingData = join(home, "roaming");
const xdgData = join(home, "data");
for (const directory of [home, localData, roamingData, xdgData])
	mkdirSync(directory, { recursive: true });
const evidencePath = join(installRoot, "client-evidence.json");
writeFileSync(
	evidencePath,
	`${JSON.stringify(
		[
			{
				client_id: "codex",
				detected: true,
				mechanisms: ["agent-plugins-bare-command"],
				command_proof_ref: null,
				qualification_evidence_ref: null,
			},
		],
		null,
		2,
	)}\n`,
);

const binary = join(installRoot, "bin", process.platform === "win32" ? "legion.exe" : "legion");
const environment = {
	...process.env,
	HOME: home,
	USERPROFILE: home,
	XDG_DATA_HOME: xdgData,
	LOCALAPPDATA: localData,
	APPDATA: roamingData,
	LEGION_STATE_ROOT: join(home, "state", "Legion"),
};

const invocations = [
	{ args: ["--version"] },
	{
		args: ["--json", "setup", "preview", "--client-evidence", evidencePath, "--client", "codex", "--dry-run"],
		allowIncomplete: true,
	},
	{ args: ["--json", "setup", "--check"], allowIncomplete: true },
	{
		args: ["--json", "setup", "repair", "--client-evidence", evidencePath, "--client", "codex", "--dry-run"],
		expectMissingLiveProofs: true,
	},
];

for (const { args, allowIncomplete = false, expectMissingLiveProofs = false } of invocations) {
	const result = spawnSync(binary, args, { env: environment, encoding: "utf8" });
	if (result.stdout) process.stdout.write(result.stdout);
	if (result.stderr) process.stderr.write(result.stderr);
	if (result.error) throw result.error;
	if (result.status === 0) continue;
	if (
		expectMissingLiveProofs &&
		result.status === 2 &&
		result.stderr.includes("requires commandProofRef and qualificationEvidenceRef")
	) {
		continue;
	}
	if (allowIncomplete && [1, 2].includes(result.status)) {
		let payload;
		try {
			payload = JSON.parse(result.stdout);
		} catch {
			throw new Error(`${binary} ${args.join(" ")} returned non-JSON incomplete output`);
		}
		if (payload.status === "incomplete") continue;
	}
	throw new Error(`${binary} ${args.join(" ")} exited ${result.status}`);
}
