//! Port of `context.mjs`'s CLI entry point: `cli()` and its helpers
//! (`parseCliOptions`, `hasTargetOption`, `pathExistsForTarget`,
//! `buildResolvedContextDirective`, `shouldWarnMissingTarget`,
//! `buildMissingTargetDirective`, `buildTargetSelectionDirective`), plus the
//! inlined `parseTargetPath`/`parseTargetOptions` it imports from
//! `lib/target-args.mjs` (that sibling file has no other export and no
//! other caller in this packet, so it is folded in here rather than given
//! its own module).
//!
//! This module owns argv parsing and stdout-block assembly; it delegates
//! all context/project resolution to the already-ported
//! [`crate::wf_port::w2_010::context`] and takes the skill-update directive
//! (if any) as a plain `Option<String>` computed by the caller via
//! [`super::update_check`] — keeping the network/cache side effect out of
//! this otherwise pure orchestration layer.
//!
//! Deliberately NOT ported: `process.exit`, `process.stderr.write`, and
//! `invokedAsScript()`'s `import.meta.url` self-detection. Those are
//! process-boundary concerns; [`run_cli`] instead returns a [`CliOutput`]
//! (`stdout` text + `exit_code`) for the embedding binary to act on.

use std::path::Path;

use crate::wf_port::w2_010::context::{
    extract_register, load_context, resolve_target_selection, LoadedContext, TargetOptions,
    TargetSelection,
};

/// Port of the `TargetArgError` thrown by `parseTargetPath`/`parseTargetOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetArgError {
    pub message: String,
    pub code: &'static str,
}

/// Port of `parseTargetPath` (from `lib/target-args.mjs`), always called
/// with `strict: true` by `context.mjs`'s `parseCliOptions`.
pub fn parse_target_path(args: &[String]) -> Result<Option<String>, TargetArgError> {
    let mut target_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--target" || arg == "-t" {
            match args.get(i + 1) {
                Some(next) if !next.starts_with('-') => {
                    target_path = Some(next.clone());
                    i += 1;
                }
                _ => {
                    return Err(TargetArgError {
                        message: "--target requires a path value.".to_string(),
                        code: "TARGET_VALUE_MISSING",
                    });
                }
            }
        } else if let Some(value) = arg.strip_prefix("--target=") {
            if !value.is_empty() {
                target_path = Some(value.to_string());
            } else {
                return Err(TargetArgError {
                    message: "--target requires a path value.".to_string(),
                    code: "TARGET_VALUE_MISSING",
                });
            }
        }
        i += 1;
    }
    Ok(target_path)
}

/// Port of `parseTargetOptions` with `{ strict: true }`, i.e. `parseCliOptions`.
pub fn parse_cli_options(args: &[String]) -> Result<TargetOptions, TargetArgError> {
    let target_path = parse_target_path(args)?;
    Ok(match target_path {
        Some(p) => TargetOptions::with(p),
        None => TargetOptions::none(),
    })
}

/// Port of `hasTargetOption`.
pub fn has_target_option(options: &TargetOptions) -> bool {
    options
        .target_path
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// Port of `pathExistsForTarget`.
pub fn path_exists_for_target(cwd: &Path, target_path: &str) -> bool {
    let abs = if Path::new(target_path).is_absolute() {
        Path::new(target_path).to_path_buf()
    } else {
        cwd.join(target_path)
    };
    abs.exists()
}

/// Port of `shouldWarnMissingTarget`.
pub fn should_warn_missing_target(
    ctx: &LoadedContext,
    target_provided: bool,
    target_exists: Option<bool>,
) -> bool {
    if ctx.is_monorepo && target_provided && target_exists == Some(false) {
        return true;
    }
    ctx.is_monorepo
        && (!target_provided || target_exists == Some(false))
        && ctx.project_root == ctx.repo_root
}

/// Port of `buildMissingTargetDirective`.
pub fn build_missing_target_directive(script_display_name: &str) -> String {
    format!(
        "MONOREPO_TARGET_REQUIRED: This is a monorepo and context.mjs ran without --target. \
If the user named a file, route, or child app, do not answer from this output. \
Rerun `node {script_display_name} --target <path>` and answer from that run's RESOLVED_CONTEXT fields."
    )
}

/// Port of `buildResolvedContextDirective`. `target_path`/`target_exists`
/// mirror the JS `hasTargetOption(options) ? options.targetPath : null` /
/// conditional `targetExists` spread.
pub fn build_resolved_context_directive(
    ctx: &LoadedContext,
    target_path: Option<&str>,
    target_exists: Option<bool>,
) -> String {
    let mut lines = vec!["{".to_string()];
    lines.push(format!(
        "  \"targetPath\": {},",
        opt_str_json(target_path)
    ));
    if target_path.is_some() {
        lines.push(format!(
            "  \"targetExists\": {},",
            opt_bool_json(target_exists)
        ));
    }
    lines.push(format!(
        "  \"projectRoot\": {},",
        str_json(&path_str(&ctx.project_root))
    ));
    lines.push(format!(
        "  \"repoRoot\": {},",
        str_json(&path_str(&ctx.repo_root))
    ));
    lines.push(format!(
        "  \"productPath\": {},",
        opt_str_json(ctx.product_path.as_deref())
    ));
    lines.push(format!(
        "  \"designPath\": {}",
        opt_str_json(ctx.design_path.as_deref())
    ));
    lines.push("}".to_string());
    format!("RESOLVED_CONTEXT:\n{}", lines.join("\n"))
}

/// Port of `buildTargetSelectionDirective`.
pub fn build_target_selection_directive(selection: &TargetSelection) -> String {
    let mut lines = vec!["{".to_string()];
    lines.push(format!(
        "  \"targetPath\": {},",
        opt_str_json(selection.target_path.as_deref())
    ));
    lines.push(format!(
        "  \"projectRoot\": {},",
        str_json(&path_str(&selection.project_root))
    ));
    lines.push(format!(
        "  \"repoRoot\": {},",
        str_json(&path_str(&selection.repo_root))
    ));
    if selection.target_candidates.is_empty() {
        lines.push("  \"targetCandidates\": []".to_string());
    } else {
        lines.push("  \"targetCandidates\": [".to_string());
        let last = selection.target_candidates.len() - 1;
        for (i, c) in selection.target_candidates.iter().enumerate() {
            lines.push("    {".to_string());
            lines.push(format!("      \"name\": {},", str_json(&c.name)));
            lines.push(format!("      \"path\": {},", str_json(&c.path)));
            lines.push(format!(
                "      \"targetExample\": {},",
                str_json(&c.target_example)
            ));
            lines.push(format!(
                "      \"productStatus\": {},",
                str_json(c.product_status)
            ));
            lines.push(format!(
                "      \"productPath\": {},",
                opt_str_json(c.product_path.as_deref())
            ));
            lines.push(format!(
                "      \"designStatus\": {},",
                str_json(c.design_status)
            ));
            lines.push(format!(
                "      \"designPath\": {}",
                opt_str_json(c.design_path.as_deref())
            ));
            lines.push(format!("    }}{}", if i == last { "" } else { "," }));
        }
        lines.push("  ]".to_string());
    }
    lines.push("}".to_string());
    format!(
        "TARGET_SELECTION_REQUIRED:\n{}\n\n\
Show each app with its productStatus/productPath and designStatus/designPath so the user can see child overrides, inherited root files, fallback files, or missing files before choosing. \
Ask the user which app Impeccable should use, then rerun Impeccable helper commands from that child app cwd using this same scripts directory. \
Use `--target <path>` only as a fallback when changing cwd is not possible, or when the user explicitly named a file/path.",
        lines.join("\n")
    )
}

fn opt_str_json(v: Option<&str>) -> String {
    v.map(str_json).unwrap_or_else(|| "null".to_string())
}

fn opt_bool_json(v: Option<bool>) -> String {
    match v {
        Some(true) => "true".to_string(),
        Some(false) => "false".to_string(),
        None => "null".to_string(),
    }
}

fn str_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

/// Result of [`run_cli`]: the text the JS would have written to
/// `process.stdout`/`process.stderr`, and the exit code it would have
/// passed to `process.exit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOutput {
    pub stdout: String,
    pub exit_code: i32,
}

/// Port of `cli()`. `update_directive` stands in for
/// `await computeUpdateDirective()` — the caller runs the (network-backed,
/// best-effort) update check via [`super::update_check::compute_update_directive`]
/// and passes the result in, keeping this function synchronous and pure
/// apart from the filesystem reads already covered by `load_context`.
pub fn run_cli(
    args: &[String],
    cwd: &Path,
    script_display_name: &str,
    update_directive: Option<String>,
) -> CliOutput {
    let cli_options = match parse_cli_options(args) {
        Ok(opts) => opts,
        Err(e) => {
            return CliOutput {
                stdout: format!("{}\n", e.message),
                exit_code: 1,
            };
        }
    };

    let target_provided = has_target_option(&cli_options);
    let target_exists = if target_provided {
        Some(path_exists_for_target(
            cwd,
            cli_options.target_path.as_deref().unwrap_or_default(),
        ))
    } else {
        None
    };

    if let Some(selection) = resolve_target_selection(cwd, &cli_options) {
        return CliOutput {
            stdout: format!("{}\n", build_target_selection_directive(&selection)),
            exit_code: 0,
        };
    }

    let ctx = load_context(cwd, &cli_options);
    // Mirrors the JS `hasTargetOption(options) ? options.targetPath : null`
    // used when building RESOLVED_CONTEXT — a present-but-blank targetPath
    // (which `hasTargetOption` treats as absent) must still report `null`.
    let target_path_for_output = if target_provided {
        cli_options.target_path.as_deref()
    } else {
        None
    };

    if !ctx.has_product {
        let mut parts = vec![
            "NO_PRODUCT_MD: This project has no PRODUCT.md yet. \
Stop the current task, load reference/init.md, and follow its \
instructions to write PRODUCT.md before resuming."
                .to_string(),
        ];
        parts.push(build_resolved_context_directive(
            &ctx,
            target_path_for_output,
            target_exists,
        ));
        if should_warn_missing_target(&ctx, target_provided, target_exists) {
            parts.push(build_missing_target_directive(script_display_name));
        }
        if let Some(d) = &update_directive {
            parts.push(d.clone());
        }
        return CliOutput {
            stdout: format!("{}\n", parts.join("\n\n---\n\n")),
            exit_code: 0,
        };
    }

    let mut parts = vec![format!(
        "# PRODUCT.md\n\n{}",
        ctx.product.as_deref().unwrap_or("").trim()
    )];
    if ctx.has_design {
        parts.push(format!(
            "# DESIGN.md\n\n{}",
            ctx.design.as_deref().unwrap_or("").trim()
        ));
    }
    parts.push(build_resolved_context_directive(
        &ctx,
        target_path_for_output,
        target_exists,
    ));
    if should_warn_missing_target(&ctx, target_provided, target_exists) {
        parts.push(build_missing_target_directive(script_display_name));
    }
    let register = extract_register(ctx.product.as_deref());
    let next = match &register {
        Some(r) => format!(
            "NEXT STEP: This project's register is `{r}`. You MUST now read `reference/{r}.md` before producing any design output."
        ),
        None => "NEXT STEP: You MUST now read the matching register reference (`reference/brand.md` or `reference/product.md`) before producing any design output. Pick based on PRODUCT.md above.".to_string(),
    };
    parts.push(next);
    if let Some(d) = &update_directive {
        parts.push(d.clone());
    }
    CliOutput {
        stdout: format!("{}\n", parts.join("\n\n---\n\n")),
        exit_code: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_project(name: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "r04-cli-{}-{}-{}",
            std::process::id(),
            name,
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn parse_target_path_supports_flag_and_equals_forms() {
        assert_eq!(
            parse_target_path(&s(&["--target", "apps/web"])).unwrap(),
            Some("apps/web".to_string())
        );
        assert_eq!(
            parse_target_path(&s(&["-t", "apps/web"])).unwrap(),
            Some("apps/web".to_string())
        );
        assert_eq!(
            parse_target_path(&s(&["--target=apps/web"])).unwrap(),
            Some("apps/web".to_string())
        );
        assert_eq!(parse_target_path(&s(&[])).unwrap(), None);
    }

    #[test]
    fn parse_target_path_strict_errors_on_missing_value() {
        let err = parse_target_path(&s(&["--target"])).unwrap_err();
        assert_eq!(err.code, "TARGET_VALUE_MISSING");
        let err2 = parse_target_path(&s(&["--target="])).unwrap_err();
        assert_eq!(err2.code, "TARGET_VALUE_MISSING");
        let err3 = parse_target_path(&s(&["--target", "-t"])).unwrap_err();
        assert_eq!(err3.code, "TARGET_VALUE_MISSING");
    }

    #[test]
    fn no_product_md_emits_no_product_block_and_resolved_context() {
        let dir = temp_project("no-product");
        let out = run_cli(&[], &dir, "context.mjs", None);
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.starts_with("NO_PRODUCT_MD:"));
        assert!(out.stdout.contains("RESOLVED_CONTEXT:"));
        assert!(out.stdout.contains("\"productPath\": null"));
    }

    #[test]
    fn product_md_present_emits_block_and_next_step_without_register() {
        let dir = temp_project("has-product");
        std::fs::write(dir.join("PRODUCT.md"), "# My Product\n\nSome text.\n").unwrap();
        let out = run_cli(&[], &dir, "context.mjs", None);
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.starts_with("# PRODUCT.md"));
        assert!(out.stdout.contains("My Product"));
        assert!(out.stdout.contains("NEXT STEP: You MUST now read the matching register"));
        assert!(!out.stdout.contains("# DESIGN.md"));
    }

    #[test]
    fn design_md_present_is_included_and_register_directive_uses_register() {
        let dir = temp_project("has-design-register");
        std::fs::write(
            dir.join("PRODUCT.md"),
            "# P\n\n## Register\n\nbrand\n",
        )
        .unwrap();
        std::fs::write(dir.join("DESIGN.md"), "# Design notes\n").unwrap();
        let out = run_cli(&[], &dir, "context.mjs", None);
        assert!(out.stdout.contains("# DESIGN.md"));
        assert!(out.stdout.contains("Design notes"));
        assert!(out
            .stdout
            .contains("NEXT STEP: This project's register is `brand`. You MUST now read `reference/brand.md`"));
    }

    #[test]
    fn update_directive_is_appended_when_present() {
        let dir = temp_project("update-directive");
        std::fs::write(dir.join("PRODUCT.md"), "# P\n").unwrap();
        let out = run_cli(
            &[],
            &dir,
            "context.mjs",
            Some("UPDATE_AVAILABLE: test".to_string()),
        );
        assert!(out.stdout.trim_end().ends_with("UPDATE_AVAILABLE: test"));
    }

    #[test]
    fn strict_arg_error_returns_nonzero_exit() {
        let dir = temp_project("bad-args");
        let out = run_cli(&s(&["--target"]), &dir, "context.mjs", None);
        assert_eq!(out.exit_code, 1);
        assert!(out.stdout.contains("--target requires a path value."));
    }

    #[test]
    fn should_warn_missing_target_flags_monorepo_root_without_target() {
        let ctx = LoadedContext {
            has_product: true,
            product: None,
            product_path: None,
            has_design: false,
            design: None,
            design_path: None,
            context_dir: std::path::PathBuf::from("/repo"),
            product_context_dir: None,
            design_context_dir: None,
            project_root: std::path::PathBuf::from("/repo"),
            repo_root: std::path::PathBuf::from("/repo"),
            is_monorepo: true,
        };
        assert!(should_warn_missing_target(&ctx, false, None));
        assert!(!should_warn_missing_target(&ctx, true, Some(true)));
        assert!(should_warn_missing_target(&ctx, true, Some(false)));
    }
}
