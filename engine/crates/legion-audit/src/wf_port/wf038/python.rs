//! Port of `src/providers/native/python/index.mjs` (`language.python`).

use super::{
    coverage_for, cwd, normalize_for, parsed_extensions_has, root_as_arg, CommandSpec,
    CommandsInput, CoverageResult, ExecutionResult, Fixtures, NormalizeResult, Projection,
};

pub const PROVIDER_ID: &str = "language.python";
pub const VERSION: &str = "1.0.0";

/// `detect({ projection })`.
pub fn detect(projection: &Projection) -> bool {
    parsed_extensions_has(projection, "py")
}

/// `commands({ root, files, manifests, profile })`.
pub fn commands(input: &CommandsInput) -> Vec<CommandSpec> {
    let mut out = Vec::new();
    out.push(CommandSpec {
        id: "py.syntax",
        executable: "python3",
        args: vec![
            "-m".to_string(),
            "compileall".to_string(),
            "-q".to_string(),
            root_as_arg(&input.root),
        ],
        cwd: cwd(input),
        kind: "syntax",
    });
    if !input.is_fast() {
        out.push(CommandSpec {
            id: "py.lint",
            executable: "ruff",
            args: vec!["check".to_string(), root_as_arg(&input.root)],
            cwd: cwd(input),
            kind: "lint",
        });
        out.push(CommandSpec {
            id: "py.type",
            executable: "basedpyright",
            args: vec![root_as_arg(&input.root)],
            cwd: cwd(input),
            kind: "type-check",
        });
    }
    if input
        .manifests
        .iter()
        .any(|m| m.contains("pyproject") || m.contains("requirements") || m.contains("setup.py"))
    {
        out.push(CommandSpec {
            id: "py.test",
            executable: "pytest",
            args: vec!["-q".to_string()],
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
    coverage_for(PROVIDER_ID, projection, &["py"])
}

pub fn fixtures() -> Fixtures {
    Fixtures::default()
}
