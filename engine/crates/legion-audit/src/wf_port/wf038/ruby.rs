//! Port of `src/providers/native/ruby/index.mjs` (`language.ruby`).

use super::{
    coverage_for, cwd, normalize_for, parsed_extensions_has, suffix_matches, CommandSpec,
    CommandsInput, CoverageResult, ExecutionResult, Fixtures, NormalizeResult, Projection,
};

pub const PROVIDER_ID: &str = "language.ruby";
pub const VERSION: &str = "1.0.0";

/// JS: `/(Gemfile|\.gemspec)$/`.
const GEM_FILE_SUFFIXES: &[&str] = &["Gemfile", ".gemspec"];

/// `detect({ projection })`.
pub fn detect(projection: &Projection) -> bool {
    parsed_extensions_has(projection, "rb")
        || projection.files.iter().any(|f| suffix_matches(f, GEM_FILE_SUFFIXES))
}

/// `commands({ root, files, manifests, profile })`.
pub fn commands(input: &CommandsInput) -> Vec<CommandSpec> {
    let mut out = Vec::new();
    if input.manifests.iter().any(|m| m.contains("Gemfile")) {
        out.push(CommandSpec {
            id: "ruby.test",
            executable: "bundle",
            args: vec!["exec".to_string(), "rspec".to_string()],
            cwd: cwd(input),
            kind: "test",
        });
        if !input.is_fast() {
            out.push(CommandSpec {
                id: "ruby.lint",
                executable: "bundle",
                args: vec!["exec".to_string(), "rubocop".to_string()],
                cwd: cwd(input),
                kind: "lint",
            });
            out.push(CommandSpec {
                id: "ruby.security",
                executable: "bundle",
                args: vec!["exec".to_string(), "brakeman".to_string(), "-q".to_string()],
                cwd: cwd(input),
                kind: "security",
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
    coverage_for(PROVIDER_ID, projection, &["rb"])
}

pub fn fixtures() -> Fixtures {
    Fixtures::default()
}
