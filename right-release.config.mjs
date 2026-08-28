import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const releaseVersion = JSON.parse(
	readFileSync(fileURLToPath(new URL("./release/version.json", import.meta.url)), "utf8"),
).version;

/**
 * Windows release identity is intentionally explicit. The package script
 * accepts only these two entries and binds every archive to its Cargo target
 * triple, WinGet architecture, and executable name.
 */
export const WINDOWS_ARCHITECTURES = Object.freeze({
	x86_64: Object.freeze({
		platform: "windows",
		architecture: "x86_64",
		wingetArchitecture: "x64",
		targetTriple: "x86_64-pc-windows-msvc",
		artifactId: "windows-x86_64",
		assemblyRoot: `dist/native/windows-x86_64/legion-${releaseVersion}`,
		archive: `legion-${releaseVersion}-windows-x86_64.zip`,
	}),
	arm64: Object.freeze({
		platform: "windows",
		architecture: "arm64",
		wingetArchitecture: "arm64",
		targetTriple: "aarch64-pc-windows-msvc",
		artifactId: "windows-arm64",
		assemblyRoot: `dist/native/windows-arm64/legion-${releaseVersion}`,
		archive: `legion-${releaseVersion}-windows-arm64.zip`,
	}),
});

const windowsX64 = WINDOWS_ARCHITECTURES.x86_64;
const windowsArm64 = WINDOWS_ARCHITECTURES.arm64;
const selectedArchitecture = String(process.env.LEGION_WINDOWS_ARCH ?? "x86_64").trim().toLowerCase();
if (!WINDOWS_ARCHITECTURES[selectedArchitecture]) {
	throw new Error(`unsupported LEGION_WINDOWS_ARCH: ${selectedArchitecture}; expected x86_64 or arm64`);
}
const selectedWindows = WINDOWS_ARCHITECTURES[selectedArchitecture];
const selectedOutput = `dist/releases/windows/${releaseVersion}/${selectedWindows.architecture}`;
const selectedReceipt = `.right-release/receipts/windows-${selectedWindows.architecture}-raw-exe.json`;
const selectedProvenance = `.right-release/receipts/windows-${selectedWindows.architecture}-provenance.json`;
const selectedQualification = `.right-release/receipts/windows-${selectedWindows.architecture}-qualification.json`;

export default {
	schema: 1,
	app: "legion",
	hostedWorkflows: "right-git-ci-only",
	version: releaseVersion,
	packageManager: "pnpm@11.24.0",
	workdir: ".",
	checks: ["legion:check", "test"],
	buildInputs: {
		include: [
			"engine/**",
			"skills/**",
			"packs/native/manifest.v1.json",
			"src/registry/**",
			"scripts/assemble-native-release.mjs",
			"scripts/package-windows-release.mjs",
			"scripts/qualify-windows-release.mjs",
			"release/**",
			"packaging/windows/sign.md",
			"docs/THIRD_PARTY_NOTICES.md",
			"package.json",
			"pnpm-lock.yaml",
		],
	},
	nativeAssembly: {
		cargoManifest: "engine/Cargo.toml",
		defaultProfile: "release",
		localProvenanceScheme: "local-build",
		signedProvenanceScheme: "rightkit-release",
		targetArchitectures: WINDOWS_ARCHITECTURES,
		packageHook: {
			cmd: "pnpm",
			args: ["native:assemble", "--", "--profile", "release"],
		},
		finalizer: {
			cmd: "pnpm",
			args: [
				"native:assemble",
				"--",
				"--profile",
				"release",
				"--platform",
				"windows",
				"--architecture",
				selectedWindows.architecture,
				"--target",
				selectedWindows.targetTriple,
				"--out",
				selectedWindows.assemblyRoot,
				"--finalize-signed",
				"--provenance",
				"{provenance}",
			],
			output: selectedProvenance,
		},
		packageIdentity: {
			name: selectedWindows.archive,
			path: `${selectedOutput}/${selectedWindows.archive}`,
			kind: "portable-zip",
			version: releaseVersion,
			target: selectedWindows.targetTriple,
			platform: "windows",
			architecture: selectedWindows.architecture,
		},
	},
	targets: {
		win: {
			// Portable RightKit signing is enabled, but publication remains blocked
			// until every raw EXE has a matching verified receipt & qualification.
			signed: true,
			platform: "windows",
			packageKind: "portable-zip",
			packageManager: "winget",
			defaultArchitecture: "x86_64",
			selectedArchitecture,
			architectures: WINDOWS_ARCHITECTURES,
			requiredArchitectures: ["x86_64", "arm64"],
			signingContract: "windows-raw-exe-authenticode-before-portable-v1",
			publishBlocked: "Windows channel blocked until both architecture artifacts have real Authenticode, provenance, qualification, and channel evidence",
			prePackage: {
				cmd: "pnpm",
				args: [
					"native:assemble",
					"--",
					"--profile",
					"release",
					"--platform",
					"windows",
					"--architecture",
					selectedWindows.architecture,
					"--target",
					selectedWindows.targetTriple,
					"--out",
					selectedWindows.assemblyRoot,
					"--force",
				],
			},
			sign: {
				// These are evidence seams, not permission to bypass signing. The
				// release remains blocked while these paths lack a Valid receipt.
				prePackageFiles: [
					`${selectedWindows.assemblyRoot}/bin/legion.exe`,
					`${selectedWindows.assemblyRoot}/bin/legion-hook.exe`,
					`${selectedWindows.assemblyRoot}/bin/legion-mcp.exe`,
				],
				receipt: selectedReceipt,
				requiredEnvironment: [
					"AZURE_ARTIFACT_SIGNING_DLIB_PATH",
					"AZURE_ARTIFACT_SIGNING_METADATA",
					"AZURE_ARTIFACT_SIGNING_ENDPOINT",
					"AZURE_ARTIFACT_SIGNING_ACCOUNT",
					"AZURE_ARTIFACT_SIGNING_PROFILE",
				],
			},
			evidence: {
				signature: selectedReceipt,
				provenance: selectedProvenance,
				qualification: selectedQualification,
				artifacts: ["SHA256SUMS", "SBOM.cdx.json", "THIRD_PARTY_NOTICES.md", "winget-portable.json"],
			},
			package: {
				cmd: "pnpm",
				args: [
					"windows:package",
					"--",
					"--architecture",
					selectedWindows.architecture,
					"--input",
					selectedWindows.assemblyRoot,
					"--signature-receipt",
					selectedReceipt,
					"--output",
					selectedOutput,
					"--require-signature",
				],
			},
			packageMatrix: [
				{
					platform: windowsX64.platform,
					architecture: windowsX64.architecture,
					wingetArchitecture: windowsX64.wingetArchitecture,
					targetTriple: windowsX64.targetTriple,
					input: windowsX64.assemblyRoot,
					output: `dist/releases/windows/${releaseVersion}/x86_64`,
					archive: windowsX64.archive,
					receipt: `.right-release/receipts/windows-${windowsX64.architecture}-raw-exe.json`,
					provenance: `.right-release/receipts/windows-${windowsX64.architecture}-provenance.json`,
					qualification: `.right-release/receipts/windows-${windowsX64.architecture}-qualification.json`,
					artifact: `dist/releases/windows/${releaseVersion}/x86_64/${windowsX64.archive}`,
				},
				{
					platform: windowsArm64.platform,
					architecture: windowsArm64.architecture,
					wingetArchitecture: windowsArm64.wingetArchitecture,
					targetTriple: windowsArm64.targetTriple,
					input: windowsArm64.assemblyRoot,
					output: `dist/releases/windows/${releaseVersion}/arm64`,
					archive: windowsArm64.archive,
					receipt: `.right-release/receipts/windows-${windowsArm64.architecture}-raw-exe.json`,
					provenance: `.right-release/receipts/windows-${windowsArm64.architecture}-provenance.json`,
					qualification: `.right-release/receipts/windows-${windowsArm64.architecture}-qualification.json`,
					artifact: `dist/releases/windows/${releaseVersion}/arm64/${windowsArm64.archive}`,
				},
			],
			artifacts: [
				`${selectedOutput}/${selectedWindows.archive}`,
			],
		},
		mac: {
			signed: false,
			publishBlocked: "native signing, notarization, provenance, and channel authorization are incomplete",
			package: { cmd: "pnpm", args: ["native:assemble", "--", "--profile", "release"] },
		},
	},
};
