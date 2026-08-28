import { spawnSync } from "node:child_process";
import {
	cpSync,
	existsSync,
	lstatSync,
	mkdirSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

function argument(names) {
	for (const name of names) {
		const index = process.argv.indexOf(name);
		if (index === -1) continue;
		const value = process.argv[index + 1];
		if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
		return value;
	}
	return undefined;
}

const candidateArgument = argument(["--candidate", "--input"]) ?? process.argv[2];
const isolatedArgument = argument(["--isolated-root", "--workspace", "--root"]) ?? process.argv[3];
if (!candidateArgument || candidateArgument.startsWith("--")) {
	throw new Error(
		"usage: native-installed-smoke.mjs <candidate-root> [isolated-root] (or --candidate <path> --isolated-root <path>)",
	);
}

const candidateRoot = resolve(candidateArgument);
const isolatedRoot = resolve(
	isolatedArgument
		?? process.env.LEGION_SMOKE_ROOT
		?? join(dirname(candidateRoot), "legion-installed-smoke"),
);

function isWithin(root, candidate) {
	const path = relative(resolve(root), resolve(candidate));
	return (
		path === ""
		|| (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
	);
}

if (!existsSync(candidateRoot) || !lstatSync(candidateRoot).isDirectory()) {
	throw new Error(`assembled candidate root is missing: ${candidateRoot}`);
}
if (isWithin(candidateRoot, isolatedRoot)) {
	throw new Error(`isolated smoke root must be outside assembled candidate root: ${isolatedRoot}`);
}

const home = join(isolatedRoot, "smoke-home");
const localData = join(isolatedRoot, "local-data");
const roamingData = join(isolatedRoot, "roaming-data");
const xdgData = join(isolatedRoot, "xdg-data");
const stateRoot = join(home, "state", "Legion");
for (const directory of [isolatedRoot, home, localData, roamingData, xdgData, stateRoot])
	mkdirSync(directory, { recursive: true });

// directories-next derives the stable product root from the host platform's
// user-data convention. Keep every platform's derived root inside this run.
const productRoot = process.platform === "win32"
	? join(localData, "Orthic Labs", "Legion")
	: process.platform === "darwin"
		? join(home, "Library", "Application Support", "Orthic Labs", "Legion")
		: join(xdgData, "Orthic Labs", "Legion");
const currentRoot = join(productRoot, "current");
if (isWithin(candidateRoot, currentRoot) || isWithin(currentRoot, candidateRoot)) {
	throw new Error(`installed smoke tree overlaps assembled candidate root: ${currentRoot}`);
}

if (existsSync(currentRoot)) {
	if (lstatSync(currentRoot).isSymbolicLink()) {
		throw new Error(`installed smoke current root must not be a symlink: ${currentRoot}`);
	}
	rmSync(currentRoot, { recursive: true, force: true });
}
mkdirSync(productRoot, { recursive: true });
cpSync(candidateRoot, currentRoot, { recursive: true, dereference: true, force: true });

const evidencePath = join(isolatedRoot, "client-evidence.json");
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

const binary = join(currentRoot, "bin", process.platform === "win32" ? "legion.exe" : "legion");
if (!existsSync(binary) || !lstatSync(binary).isFile()) {
	throw new Error(`assembled candidate has no native executable: ${binary}`);
}

const pathKey = Object.keys(process.env).find((key) => key.toLowerCase() === "path") ?? "PATH";
const environment = {
	...process.env,
	HOME: home,
	USERPROFILE: home,
	XDG_DATA_HOME: xdgData,
	LOCALAPPDATA: localData,
	APPDATA: roamingData,
	LEGION_STATE_ROOT: stateRoot,
};
delete environment.LEGION_M1_CONFIG;
environment[pathKey] = [join(currentRoot, "bin"), process.env[pathKey]].filter(Boolean).join(delimiter);

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
	const result = spawnSync(binary, args, { env: environment, encoding: "utf8", windowsHide: true });
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
