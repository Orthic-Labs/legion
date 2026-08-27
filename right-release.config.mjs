export default {
	schema: 1,
	app: "legion",
	version: "release/version.json",
	packageManager: "pnpm@11.24.0",
	workdir: ".",
	checks: ["legion:check", "test"],
	buildInputs: {
		include: [
			"engine/**",
			"skills/**",
			"src/registry/**",
			"scripts/assemble-native-release.mjs",
			"release/**",
			"package.json",
			"pnpm-lock.yaml",
		],
	},
	nativeAssembly: {
		cargoManifest: "engine/Cargo.toml",
		defaultProfile: "release",
		localProvenanceScheme: "local-build",
		signedProvenanceScheme: "rightkit-release",
		packageHook: {
			cmd: "pnpm",
			args: ["native:assemble", "--", "--profile", "release"],
		},
	},
	targets: {
		win: {
			signed: false,
			publishBlocked: "native signing, provenance, and channel authorization are incomplete",
			package: { cmd: "pnpm", args: ["native:assemble", "--", "--profile", "release"] },
		},
		mac: {
			signed: false,
			publishBlocked: "native signing, notarization, provenance, and channel authorization are incomplete",
			package: { cmd: "pnpm", args: ["native:assemble", "--", "--profile", "release"] },
		},
	},
};
