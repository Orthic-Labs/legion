//! Port of `src/providers/native/php/index.mjs` (`language.php`).

use super::{
    coverage_for, cwd, files_contains, manifests_contains, normalize_for, parsed_extensions_has,
    CommandSpec, CommandsInput, CoverageResult, ExecutionResult, Fixtures, NormalizeResult,
    Projection,
};

pub const PROVIDER_ID: &str = "language.php";
pub const VERSION: &str = "1.0.0";

/// `detect({ projection })`.
pub fn detect(projection: &Projection) -> bool {
    parsed_extensions_has(projection, "php") || files_contains(&projection.files, "composer.json")
}

/// `commands({ root, files, manifests, profile })`.
pub fn commands(input: &CommandsInput) -> Vec<CommandSpec> {
    let mut out = Vec::new();
    if manifests_contains(&input.manifests, "composer.json") {
        out.push(CommandSpec {
            id: "php.validate",
            executable: "composer",
            args: vec!["validate".to_string(), "--no-check-publish".to_string()],
            cwd: cwd(input),
            kind: "validate",
        });
        if !input.is_fast() {
            out.push(CommandSpec {
                id: "php.test",
                executable: "vendor/bin/phpunit",
                args: Vec::new(),
                cwd: cwd(input),
                kind: "test",
            });
            out.push(CommandSpec {
                id: "php.static",
                executable: "vendor/bin/phpstan",
                args: vec!["analyse".to_string(), "src".to_string()],
                cwd: cwd(input),
                kind: "static",
            });
        }
    }
    out
}

/// `normalize({ commandId, execution, artifacts })`.
pub fn normalize(command_id: &str, execution: Option<&ExecutionResult>) -> NormalizeResult {
    normalize_for(PROVIDER_ID, command_id, execution)
}

/// `coverage({ projection, plan, results })`.
pub fn coverage(projection: &Projection) -> CoverageResult {
    coverage_for(PROVIDER_ID, projection, &["php"])
}

pub fn fixtures() -> Fixtures {
    Fixtures::default()
}
