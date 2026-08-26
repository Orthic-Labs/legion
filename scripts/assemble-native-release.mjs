import { createHash } from "node:crypto";
import {
	copyFileSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cargoManifest = join(
	repositoryRoot,
	"engine",
	"bins",
	"legion",
	"Cargo.toml",
);

function argument(name, fallback) {
	const index = process.argv.indexOf(name);
	return index === -1 ? fallback : process.argv[index + 1];
}

function sha256(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

function fileSha256(path) {
	return sha256(readFileSync(path));
}

function filesBelow(root, directory = root, output = []) {
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		const path = join(directory, entry.name);
		const metadata = lstatSync(path);
		if (metadata.isSymbolicLink())
			throw new Error(`release asset is symlink: ${path}`);
		if (metadata.isDirectory()) filesBelow(root, path, output);
		else if (metadata.isFile())
			output.push(relative(root, path).split(sep).join("/"));
		else throw new Error(`release asset is not regular file: ${path}`);
	}
	return output;
}

function directorySha256(root) {
	const hash = createHash("sha256");
	for (const path of filesBelow(root).sort()) {
		const bytes = readFileSync(join(root, path));
		const length = Buffer.alloc(8);
		length.writeBigUInt64BE(BigInt(bytes.length));
		hash.update(path);
		hash.update(Buffer.from([0]));
		hash.update(length);
		hash.update(bytes);
	}
	return hash.digest("hex");
}

function writeJson(path, value) {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

const LEGACY_RUNTIME_EXTENSIONS = new Set([
	".cjs",
	".js",
	".mjs",
	".py",
	".pyc",
]);

function copyDeclarativeTree(source, destination) {
	for (const path of filesBelow(source).sort()) {
		const extension = path.slice(path.lastIndexOf(".")).toLowerCase();
		if (LEGACY_RUNTIME_EXTENSIONS.has(extension)) continue;
		const target = join(destination, path);
		mkdirSync(dirname(target), { recursive: true });
		copyFileSync(join(source, path), target);
	}
}

function version() {
	const match = readFileSync(cargoManifest, "utf8").match(
		/^version\s*=\s*"([^"]+)"/m,
	);
	if (!match) throw new Error(`version missing from ${cargoManifest}`);
	return match[1];
}

const platform = process.platform === "win32" ? "windows" : process.platform;
const architecture =
	process.arch === "x64"
		? "x86_64"
		: process.arch === "arm64"
			? "aarch64"
			: process.arch;
const executableSuffix = platform === "windows" ? ".exe" : "";
const releaseVersion = version();
const binDirectory = resolve(
	argument("--bin-dir", join(repositoryRoot, "engine", "target", "release")),
);
const output = resolve(
	argument(
		"--out",
		join(
			repositoryRoot,
			"dist",
			"native",
			`${platform}-${architecture}`,
			`legion-${releaseVersion}`,
		),
	),
);
const force = process.argv.includes("--force");
const finalizeSigned = process.argv.includes("--finalize-signed");

if (existsSync(output)) {
	if (!force && !finalizeSigned)
		throw new Error(
			`release output exists: ${output}; pass --force to replace exact output`,
		);
	if (!finalizeSigned) rmSync(output, { recursive: true, force: true });

} else if (finalizeSigned) {
	throw new Error(`signed release output missing: ${output}`);
}

const binaryNames = ["legion", "legion-hook", "legion-mcp"].map(
	(name) => `${name}${executableSuffix}`,
);
for (const name of binaryNames) {
	const source = finalizeSigned
		? join(output, "bin", name)
		: join(binDirectory, name);
	if (!existsSync(source)) throw new Error(`release binary missing: ${source}`);
	if (!finalizeSigned) {
		mkdirSync(join(output, "bin"), { recursive: true });
		copyFileSync(source, join(output, "bin", name));
	}
}

const share = join(output, "share", "legion");
const assets = join(share, "assets");
const catalogPath = join(assets, "registry", "index.json");
const schemaPath = join(assets, "schemas", "mcp-tools.schema.json");
const policyPath = join(assets, "policy", "arcane-m1-policy.json");
mkdirSync(dirname(catalogPath), { recursive: true });
copyFileSync(
	join(repositoryRoot, "src", "registry", "skills", "index.json"),
	catalogPath,
);
copyDeclarativeTree(join(repositoryRoot, "skills"), join(assets, "skills"));

const mcpToolSchema = {
	schemaVersion: 1,
	kind: "legion-mcp-tool-schema",
	tools: [
		{
			name: "legion_m1_status",
			inputSchema: {
				type: "object",
				required: [],
				additionalProperties: false,
				properties: {},
			},
		},
		{
			name: "legion_m1_invoke",
			inputSchema: {
				type: "object",
				required: ["capabilityId", "policyContext"],
				additionalProperties: false,
				properties: {
					capabilityId: { type: "string", minLength: 1 },
					policyContext: {},
				},
			},
		},
	],
};
writeJson(schemaPath, mcpToolSchema);

const policyPack = {
	schema_version: 1,
	kind: "arcane-policy-pack",
	policy_id: "legion-installed-m1-deny-by-default",
	version: 1,
	contract_versions: [{ name: "m1", major: 1, minor: 0 }],
	unclassified_effect: "deny",
	effect_rules: [],
	capability: {
		effects: [],
		operations: [],
		targets: [],
		max_ttl_seconds: 60,
		max_uses: 1,
		delegable: false,
		trust: "unauthenticated",
	},
	leases: { max_ttl_seconds: 60, max_uses: 1, delegable: false },
	trust_minima: {
		mutation: "capability-signature",
		read_only: "unauthenticated",
		claim_release: "capability-signature",
		legacy_import: "capability-signature",
	},
	host_enforcement: {
		required_for_mutation: "strong",
		required_for_read_only: "read_only",
	},
	receipt_requirements: {
		effect_receipt: true,
		bind_policy_digest: true,
		bind_capability_id: true,
	},
};
writeJson(policyPath, policyPack);

const runtimePath = join(output, "bin", `legion${executableSuffix}`);
const runtimeDigest = fileSha256(runtimePath);
const provenance = argument(
	"--provenance",
	`rightkit-release://${platform}-${architecture}/${runtimeDigest}`,
);
const manifest = {
	releaseVersion,
	runtime: { platform, architecture, sha256: runtimeDigest, provenance },
	capabilityCatalogSha256: fileSha256(catalogPath),
	mcpToolSchemaSha256: fileSha256(schemaPath),
	declarativeAssetsSha256: directorySha256(assets),
	stateSchemaVersion: 1,
	rightkitAx: {
		version: "0.2.0",
		sourceCommit: "01f52555202da3dffc6b649ca44e803b55238081",
	},
};
writeJson(join(share, "release.json"), manifest);
writeJson(join(share, "composition.json"), {
	schemaVersion: 1,
	kind: "legion-m1-composition",
	releaseManifestPath: "release.json",
	catalogRoot: "assets",
	catalogIndexPath: "registry/index.json",
	policyPack,
	releaseBinding: {
		runtimeProvenance: provenance,
		catalogPath: "assets/registry/index.json",
		mcpToolSchemaPath: "assets/schemas/mcp-tools.schema.json",
		declarativeAssetsPath: "assets",
		declarativeAssetsKind: "directory",
	},
});

const pluginRoot = join(output, "plugin");
for (const relativePath of [
	"plugin.json",
	"mcp.json",
	"skills/legion/SKILL.md",
]) {
	const source = join(
		repositoryRoot,
		"engine",
		"assets",
		"legion-plugin",
		relativePath,
	);
	const destination = join(pluginRoot, relativePath);
	mkdirSync(dirname(destination), { recursive: true });
	copyFileSync(source, destination);
}
for (const relativePath of [
	"share/legion/release-binding.json",
	"share/legion/identity/release-identity.json",
]) {
	writeJson(join(pluginRoot, relativePath), manifest);
}
writeJson(
	join(pluginRoot, "share/legion/schemas/mcp-tools.schema.json"),
	mcpToolSchema,
);

process.stdout.write(
	`${JSON.stringify(
		{
			status: "complete",
			output,
			releaseVersion,
			platform,
			architecture,
			finalizedSigned: finalizeSigned,
			runtimeSha256: runtimeDigest,
			assetsSha256: manifest.declarativeAssetsSha256,
			binaries: binaryNames,
		},
		null,
		2,
	)}\n`,
);
