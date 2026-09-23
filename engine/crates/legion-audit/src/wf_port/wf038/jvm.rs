//! Port of `src/providers/native/jvm/index.mjs` (`language.jvm`).

use super::{
    coverage_for, cwd, ext_matches, normalize_for, suffix_matches, CommandSpec, CommandsInput,
    CoverageResult, ExecutionResult, Fixtures, NormalizeResult, Projection,
};

pub const PROVIDER_ID: &str = "language.jvm";
pub const VERSION: &str = "1.0.0";

/// JS: `/(pom\.xml|build\.gradle|build\.gradle\.kts|settings\.gradle)$/`.
const BUILD_FILE_SUFFIXES: &[&str] = &["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"];

/// `detect({ projection })`.
pub fn detect(projection: &Projection) -> bool {
    let files = &projection.files;
    files.iter().any(|f| ext_matches(f, &["java", "kt", "kts", "scala"]))
        || files.iter().any(|f| suffix_matches(f, BUILD_FILE_SUFFIXES))
}

/// `commands({ root, files, manifests, profile })`.
pub fn commands(input: &CommandsInput) -> Vec<CommandSpec> {
    let mut out = Vec::new();
    let has_gradle = input.manifests.iter().any(|m| m.contains("gradle"));
    let has_maven = input.manifests.iter().any(|m| m.contains("pom.xml"));
    if has_gradle {
        out.push(CommandSpec {
            id: "jvm.gradle-wrapper",
            executable: "./gradlew",
            args: vec!["compileJava".to_string(), "--offline".to_string()],
            cwd: cwd(input),
            kind: "build",
        });
    } else if has_maven {
        out.push(CommandSpec {
            id: "jvm.maven-wrapper",
            executable: "./mvnw",
            args: vec!["compile".to_string(), "-o".to_string()],
            cwd: cwd(input),
            kind: "build",
        });
    }
    if !input.is_fast() {
        out.push(CommandSpec {
            id: "jvm.test",
            executable: if has_gradle { "./gradlew" } else { "./mvnw" },
            args: vec!["test".to_string(), "--offline".to_string()],
            cwd: cwd(input),
            kind: "test",
        });
    }
    out
}

/// `normalize({ commandId, execution, artifacts })`.
pub fn normalize(command_id: &str, execution: Option<&ExecutionResult>) -> NormalizeResult {
    normalize_for(PROVIDER_ID, command_id, execution)
}

/// `coverage({ projection, plan, results })`.
pub fn coverage(projection: &Projection) -> CoverageResult {
    coverage_for(PROVIDER_ID, projection, &["java", "kt", "scala"])
}

pub fn fixtures() -> Fixtures {
    Fixtures::default()
}
