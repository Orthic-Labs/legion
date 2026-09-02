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
import {
	assemblePortableCore,
	CLIENT_PROJECTION_KINDS,
	validatePortableCore,
} from "@rightkit/ax/plugin/portable-core";
import { resolveTargetRoot } from "@rightkit/release/cargo-target.mjs";
import rightReleaseConfig from "../right-release.config.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const releaseVersionRecord = join(repositoryRoot, "release", "version.json");

/**
 * The Windows target names are part of the release identity.  Do not infer an
 * ARM64 artifact from the host process architecture: a cross build must name
 * its target explicitly, otherwise a valid x64 binary can be published under
 * an ARM64 filename (or vice versa).
 */
export const WINDOWS_TARGETS = Object.freeze({
	x86_64: Object.freeze({
		platform: "windows",
		architecture: "x86_64",
		installerArchitecture: "x64",
		targetTriple: "x86_64-pc-windows-msvc",
		executableSuffix: ".exe",
	}),
	arm64: Object.freeze({
		platform: "windows",
		architecture: "arm64",
		installerArchitecture: "arm64",
		targetTriple: "aarch64-pc-windows-msvc",
		executableSuffix: ".exe",
	}),
});

const ARCHITECTURE_ALIASES = new Map([
	["x64", "x86_64"],
	["amd64", "x86_64"],
	["x86_64", "x86_64"],
	["arm64", "arm64"],
	["aarch64", "arm64"],
]);

function argument(name, fallback) {
	const index = process.argv.indexOf(name);
	if (index === -1) return fallback;
	const value = process.argv[index + 1];
	if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
	return value;
}

function normalizePlatform(value) {
	const platform = String(value ?? "").trim().toLowerCase();
	if (platform === "win" || platform === "windows") return "windows";
	if (platform === "mac" || platform === "macos" || platform === "darwin") return "macos";
	if (/^[a-z0-9][a-z0-9_.-]*$/i.test(platform)) return platform;
	throw new Error(`invalid release platform: ${value}`);
}

function normalizeArchitecture(value, platform) {
	const normalized = ARCHITECTURE_ALIASES.get(String(value ?? "").trim().toLowerCase());
	if (platform === "windows") {
		if (!normalized || !WINDOWS_TARGETS[normalized]) {
			throw new Error(`unsupported Windows architecture: ${value}; expected x86_64 or arm64`);
		}
		return normalized;
	}
	if (normalized) return platform === "macos" && normalized === "arm64" ? "aarch64" : normalized;
	if (String(value ?? "").trim() === "") {
		return process.arch === "x64" ? "x86_64" : process.arch === "arm64" ? "aarch64" : process.arch;
	}
	if (!/^[a-z0-9][a-z0-9_.-]*$/i.test(String(value))) {
		throw new Error(`invalid release architecture: ${value}`);
	}
	return String(value);
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

function excludedSkillArtifact(path) {
	const segments = path.toLowerCase().split("/");
	return segments.includes("__pycache__") || path.toLowerCase().endsWith(".pyc");
}

function copySkillTree(source, destination) {
	for (const path of filesBelow(source).sort()) {
		if (excludedSkillArtifact(path)) continue;
		const target = join(destination, path);
		mkdirSync(dirname(target), { recursive: true });
		copyFileSync(join(source, path), target);
	}
}

function version() {
	const record = JSON.parse(readFileSync(releaseVersionRecord, "utf8"));
	if (
		record.schemaVersion !== 1 ||
		record.kind !== "legion-release-version" ||
		typeof record.version !== "string"
	)
		throw new Error(`invalid release version record: ${releaseVersionRecord}`);
	return record.version;
}

const platform = normalizePlatform(
	argument(
		"--platform",
		process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : process.platform,
	),
);
const architecture = normalizeArchitecture(
	argument(
		"--architecture",
		platform === "windows" ? process.env.LEGION_WINDOWS_ARCH ?? "x86_64" : null,
	),
	platform,
);
const explicitWindowsArchitecture = platform === "windows" &&
	(process.argv.includes("--architecture") || Boolean(process.env.LEGION_WINDOWS_ARCH));
if (platform === "windows" && process.platform !== "win32" && !explicitWindowsArchitecture) {
	throw new Error("cross-building Windows requires explicit --architecture x86_64 or arm64");
}
const windowsTarget = platform === "windows" ? WINDOWS_TARGETS[architecture] : null;
const executableSuffix = windowsTarget?.executableSuffix ?? "";
const releaseVersion = version();
const cargoManifest = resolve(
	repositoryRoot,
	rightReleaseConfig.nativeAssembly.cargoManifest,
);
const profile = argument(
	"--profile",
	rightReleaseConfig.nativeAssembly.defaultProfile,
);
if (!/^[a-z0-9][a-z0-9_-]*$/i.test(profile))
	throw new Error(`invalid Cargo profile: ${profile}`);
const requestedCargoTarget = argument("--target", process.env.CARGO_BUILD_TARGET ?? null);
const cargoTarget = windowsTarget && (explicitWindowsArchitecture || requestedCargoTarget)
	? windowsTarget.targetTriple
	: requestedCargoTarget;
const targetTriple = windowsTarget?.targetTriple ?? cargoTarget;
if (cargoTarget && !/^[a-z0-9][a-z0-9_.-]*$/i.test(cargoTarget))
	throw new Error(`invalid Cargo target: ${cargoTarget}`);
if (windowsTarget && requestedCargoTarget && requestedCargoTarget !== windowsTarget.targetTriple) {
	throw new Error(
		`Windows target identity mismatch: architecture ${architecture} requires ${windowsTarget.targetTriple}, received ${requestedCargoTarget}`,
	);
}
const suppliedBinDirectory = argument("--bin-dir", null);
const binDirectory = suppliedBinDirectory
	? resolve(suppliedBinDirectory)
	: resolve(
			join(
				resolveTargetRoot(cargoManifest),
				...(cargoTarget ? [cargoTarget] : []),
				profile,
			),
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
const suppliedProvenance = argument("--provenance", null);

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
const nativeRuleManifestPath = join(assets, "packs", "native", "manifest.v1.json");
mkdirSync(dirname(catalogPath), { recursive: true });
copyFileSync(
	join(repositoryRoot, "src", "registry", "skills", "index.json"),
	catalogPath,
);
copySkillTree(join(repositoryRoot, "skills"), join(assets, "skills"));
mkdirSync(dirname(nativeRuleManifestPath), { recursive: true });
copyFileSync(join(repositoryRoot, "packs", "native", "manifest.v1.json"), nativeRuleManifestPath);

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
if (finalizeSigned && !suppliedProvenance)
	throw new Error("--finalize-signed requires right-release provenance");
if (
	finalizeSigned &&
	!suppliedProvenance.startsWith(
		`${rightReleaseConfig.nativeAssembly.signedProvenanceScheme}://`,
	)
)
	throw new Error("signed provenance must be minted by right-release");
if (
	!finalizeSigned &&
	suppliedProvenance?.startsWith(
		`${rightReleaseConfig.nativeAssembly.signedProvenanceScheme}://`,
	)
)
	throw new Error("right-release provenance is reserved for signed finalization");
const provenance =
	suppliedProvenance ??
	`${rightReleaseConfig.nativeAssembly.localProvenanceScheme}://${platform}-${architecture}/${runtimeDigest}`;
const targetIdentity = {
	platform,
	architecture,
	targetTriple,
	executable: binaryNames[0],
	installerArchitecture: windowsTarget?.installerArchitecture ?? null,
};
const manifest = {
	releaseVersion,
	runtime: { platform, architecture, sha256: runtimeDigest, provenance },
	capabilityCatalogSha256: fileSha256(catalogPath),
	mcpToolSchemaSha256: fileSha256(schemaPath),
	declarativeAssetsSha256: directorySha256(assets),
	stateSchemaVersion: 1,
	rightkitAx: {
		version: "0.2.1",
		sourceCommit: "4c1a414269d8ffdb95b4b1e685440bd34784b41b",
	},
};
writeJson(join(share, "release.json"), manifest);
writeJson(join(share, "composition.json"), {
	schemaVersion: 1,
	kind: "legion-m1-composition",
	releaseManifestPath: "release.json",
	catalogRoot: "assets",
	catalogIndexPath: "registry/index.json",
	providers: [{ id: "m1-native-capability" }],
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
// Agents come from the same declared surface the plugin advertises, so the
// shipped core cannot disagree with what Legion claims to provide.
const pluginSurface = JSON.parse(
	readFileSync(join(repositoryRoot, "src", "registry", "plugin-surface.json"), "utf8"),
);
const publicAgents = (pluginSurface.surface?.agents ?? []).map((agent) => {
	const source = join(repositoryRoot, agent.file);
	if (!existsSync(source)) throw new Error(`declared agent is missing: ${agent.file}`);
	return { name: agent.name, sourceRoot: repositoryRoot, sourceFile: source };
});
if (publicAgents.length !== (pluginSurface.counts?.agents ?? publicAgents.length)) {
	throw new Error("declared agent count does not match the plugin surface");
}
const skillCatalog = JSON.parse(readFileSync(catalogPath, "utf8"));
const publicSkills = skillCatalog.bundles
	.filter((bundle) => bundle.discoverability === "public" || bundle.discoverability === "explicit")
	.map((bundle) => {
		if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(bundle.id) || bundle.name !== bundle.id) {
			throw new Error(`canonical skill must use its plain name: ${bundle.id}`);
		}
		const expectedSource = `skills/${bundle.id}/SKILL.md`;
		if (bundle.source !== expectedSource) {
			throw new Error(`canonical skill source mismatch for ${bundle.id}: ${bundle.source}`);
		}
		return {
			id: bundle.id,
			visibility: "public",
			sourceRoot: join(repositoryRoot, "skills"),
			sourceDir: join(repositoryRoot, "skills", bundle.id),
		};
	});
// The expected set comes from the canonical catalog rather than a frozen count,
// so adding a packaged skill does not require editing the release assembler.
// The check is still exact: every catalog skill that must ship is packaged, and
// packaged exactly once.
const expectedSkillIds = skillCatalog.bundles
	.filter((bundle) => bundle.discoverability === "public" || bundle.discoverability === "explicit")
	.map((bundle) => bundle.id)
	.sort();
const packagedSkillIds = publicSkills.map(({ id }) => id).sort();
if (expectedSkillIds.length === 0) {
	throw new Error("skill catalog declares no shippable skills");
}
if (
	new Set(packagedSkillIds).size !== packagedSkillIds.length ||
	packagedSkillIds.join(",") !== expectedSkillIds.join(",")
) {
	throw new Error(
		`portable core must package every canonical plain-name skill exactly once; expected [${expectedSkillIds.join(", ")}], packaged [${packagedSkillIds.join(", ")}]`,
	);
}
assemblePortableCore({
	outputDir: pluginRoot,
	pluginManifestPath: join(repositoryRoot, "engine", "assets", "legion-plugin", "plugin.json"),
	mcpManifestPath: join(repositoryRoot, "engine", "assets", "legion-plugin", "mcp.json"),
	skills: publicSkills,
	// The plugin surface declares four agents (sage, alchemist, oracle,
	// covenant-seat) and the core shipped none of them, so every agent-only
	// role was unreachable from every client: oracle appeared to work purely
	// because it is also a skill.
	agents: publicAgents,
	clientProjections: CLIENT_PROJECTION_KINDS,
});
const portableCoreValidation = validatePortableCore(pluginRoot);
if (!portableCoreValidation.valid) {
	throw new Error(
		`RightAX portable core validation failed: ${portableCoreValidation.errors.join("; ")}`,
	);
}

// Anchor the shipped portable core to the release manifest: the validator in the
// installed binary recomputes this digest over the on-disk core bytes and refuses
// to trust the core if it does not match. Written here (not with the other
// manifest fields) because the core file only exists after assembly.
manifest.portableCoreSha256 = fileSha256(
	join(pluginRoot, "rightax-portable-core.json"),
);
writeJson(join(share, "release.json"), manifest);

process.stdout.write(
	`${JSON.stringify(
		{
			status: "complete",
			output,
			releaseVersion,
			platform,
			architecture,
			cargoTarget,
			targetTriple,
			targetIdentity,
			finalizedSigned: finalizeSigned,
			runtimeSha256: runtimeDigest,
			assetsSha256: manifest.declarativeAssetsSha256,
			binaries: binaryNames,
		},
		null,
		2,
	)}\n`,
);
