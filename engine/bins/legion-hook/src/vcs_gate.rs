//! Version-control gate: hook bypasses are refused, and the two shared-state
//! moves that cannot be taken back (merging a pull request, pushing to the
//! repository's default branch) go to the host permission prompt.
//!
//! Guard used to classify `git push`, `git commit` and `gh pr merge` and then
//! allow them, so `git commit --no-verify`, `git config core.hooksPath NUL` and
//! `HUSKY=0 git push` stepped around the repository gate unseen. Every shape
//! here is judged on the simple command the shell would run, after the same
//! wrapper unwrapping the destructive and rewrite gates use (`bash -c`, `sudo`,
//! `env`, `xargs`, ...). Quoted mentions never match: a commit message that
//! says "--no-verify" is one dequoted word, not a flag.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};

use crate::{
    command_segments, program_name, resolve_common_git_dir, resolve_git_dir, shell_words,
    strip_launchers, unwrap_shell_command, GIT_VALUE_FLAGS,
};

pub(crate) const BYPASS_CODE: &str = "ARC_HOOK_BYPASS_DENIED";
pub(crate) const CONFIRM_CODE: &str = "ARC_USER_CONFIRMATION_REQUIRED";

/// Branch names always treated as a default branch, in addition to whatever
/// the remote's `HEAD` symbolic ref names.
const DEFAULT_BRANCH_NAMES: [&str; 2] = ["main", "master"];

/// Subcommands that run repository hooks and accept `--no-verify`.
const HOOKED_SUBCOMMANDS: [&str; 6] = ["commit", "push", "merge", "am", "rebase", "pull"];

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Gate {
    Deny { reason: String },
    Ask { reason: String },
}

/// One simple command: the environment assignments in force and its words.
#[derive(Debug)]
struct Simple {
    env: Vec<(String, String)>,
    words: Vec<String>,
}

/// Evaluate one shell command line. `cwd` is where the host says it runs; a
/// `cd` earlier in the line moves it. Returns the first gate that fires,
/// denials before confirmations.
pub(crate) fn evaluate_command(command: &str, cwd: Option<&Path>) -> Option<Gate> {
    let mut simples = Vec::new();
    collect_simple(command, &[], 0, &mut simples);

    // Denials first, so an ask never masks a bypass later on the same line.
    for simple in &simples {
        if let Some(reason) = bypass_reason(simple) {
            return Some(Gate::Deny { reason });
        }
    }
    let mut dir = cwd.map(Path::to_path_buf);
    for simple in &simples {
        if let Some(next) = change_directory(simple, dir.as_deref()) {
            dir = Some(next);
            continue;
        }
        if let Some(reason) = confirmation_reason(simple, dir.as_deref()) {
            return Some(Gate::Ask { reason });
        }
    }
    None
}

/// The words of every simple command on the line, after wrapper unwrapping.
pub(crate) fn command_words(command: &str) -> Vec<Vec<String>> {
    let mut simples = Vec::new();
    collect_simple(command, &[], 0, &mut simples);
    simples.into_iter().map(|simple| simple.words).collect()
}

/// The git subcommand of every `git` simple command on the line.
pub(crate) fn git_subcommands(command: &str) -> Vec<String> {
    command_words(command)
        .iter()
        .filter_map(|words| parse_git(words))
        .map(|git| git.subcommand)
        .collect()
}

/// A write to a git configuration file that sets or removes `core.hooksPath`,
/// made through a file tool instead of `git config`.
///
/// The file the tool names decides, never the text it writes: a document that
/// only discusses `core.hooksPath` and `.git/config` is an ordinary edit.
/// `Write`, `Edit`, `MultiEdit` and `NotebookEdit` name their file in
/// `file_path`, `path` or `notebook_path`. `apply_patch` names its files in
/// the `*** Update File:`, `*** Add File:` and `*** Move to:` headers of the
/// patch, and only the lines under a header that names a git configuration
/// file are searched.
pub(crate) fn tool_input_edits_hooks_path(
    tool: &str,
    input: &Map<String, Value>,
) -> Option<String> {
    let mut leaves = Vec::new();
    collect_strings(&Value::Object(input.clone()), &mut leaves);
    let names_config_file = ["file_path", "path", "notebook_path"]
        .iter()
        .filter_map(|key| input.get(*key).and_then(Value::as_str))
        .any(is_git_config_path);
    let sets_hooks_path = (names_config_file
        && leaves.iter().any(|leaf| mentions_hooks_path(leaf)))
        || (tool == "apply_patch" && leaves.iter().any(|leaf| patch_sets_hooks_path(leaf)));
    sets_hooks_path.then(|| {
        "this write sets or removes core.hooksPath in a git configuration file, which would route around the repository hooks"
            .into()
    })
}

fn mentions_hooks_path(text: &str) -> bool {
    text.to_ascii_lowercase().contains("hookspath")
}

/// Does an `apply_patch` envelope touch `core.hooksPath` inside a section
/// whose header names a git configuration file?
fn patch_sets_hooks_path(patch: &str) -> bool {
    let mut in_config_file = false;
    for line in patch.lines() {
        let line = line.trim_end_matches('\r');
        let header = |prefix: &str| line.strip_prefix(prefix).map(str::trim);
        if let Some(path) = header("*** Update File:").or_else(|| header("*** Add File:")) {
            in_config_file = is_git_config_path(path);
        } else if let Some(path) = header("*** Move to:") {
            in_config_file = in_config_file || is_git_config_path(path);
        } else if line.starts_with("*** Delete File:")
            || line.starts_with("*** Begin Patch")
            || line.starts_with("*** End Patch")
        {
            in_config_file = false;
        } else if in_config_file && mentions_hooks_path(line) {
            return true;
        }
    }
    false
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| collect_strings(item, out)),
        Value::Object(object) => object.values().for_each(|item| collect_strings(item, out)),
        _ => {}
    }
}

fn is_git_config_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized == ".git/config"
        || normalized.ends_with("/.git/config")
        || normalized.ends_with("/.gitconfig")
        || normalized == ".gitconfig"
        || normalized.ends_with("/.config/git/config")
        || normalized.ends_with("/config.worktree")
}

// ---------------------------------------------------------------------------
// Command decomposition
// ---------------------------------------------------------------------------

fn collect_simple(command: &str, inherited: &[(String, String)], depth: u8, out: &mut Vec<Simple>) {
    for segment in command_segments(command) {
        let (rest, _) = strip_launchers(&segment);
        let offset = (rest.as_ptr() as usize).saturating_sub(segment.as_ptr() as usize);
        let prefix = segment.get(..offset.min(segment.len())).unwrap_or("");
        let mut env: Vec<(String, String)> = inherited.to_vec();
        for word in shell_words(prefix) {
            if let Some((name, value)) = split_assignment(&word) {
                env.push((name, value));
            }
        }
        let unwrapped = unwrap_shell_command(rest);
        if unwrapped != rest && depth < 3 {
            collect_simple(unwrapped, &env, depth + 1, out);
            continue;
        }
        let words = shell_words(rest);
        if words.is_empty() {
            // A bare run of assignments (`HUSKY=0`) keeps them for the next
            // command on the line only in a shell session; record them anyway,
            // so the assignment itself is judged.
            if !env.is_empty() {
                out.push(Simple { env, words });
            }
            continue;
        }
        out.push(Simple { env, words });
    }
}

fn split_assignment(word: &str) -> Option<(String, String)> {
    let (name, value) = word.split_once('=')?;
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        && !name.starts_with(|character: char| character.is_ascii_digit());
    valid.then(|| (name.to_owned(), value.to_owned()))
}

fn program_of(simple: &Simple) -> Option<String> {
    simple
        .words
        .first()
        .map(|word| program_name(word).to_ascii_lowercase())
}

fn change_directory(simple: &Simple, current: Option<&Path>) -> Option<PathBuf> {
    let program = program_of(simple)?;
    if !matches!(program.as_str(), "cd" | "pushd" | "set-location" | "sl") {
        return None;
    }
    let target = simple
        .words
        .iter()
        .skip(1)
        .find(|word| !word.starts_with('-'))?;
    let target = PathBuf::from(target);
    Some(match (target.is_absolute(), current) {
        (true, _) | (false, None) => target,
        (false, Some(base)) => base.join(target),
    })
}

/// Every assignment that applies to this simple command: the leading ones,
/// the arguments of `export`/`set`-style builtins, and PowerShell `$env:`.
fn assignments(simple: &Simple) -> Vec<(String, String)> {
    let mut found = simple.env.clone();
    let program = program_of(simple).unwrap_or_default();
    if matches!(
        program.as_str(),
        "export" | "set" | "declare" | "typeset" | "readonly" | "local" | "setenv"
    ) {
        for word in simple.words.iter().skip(1) {
            if let Some(pair) = split_assignment(word) {
                found.push(pair);
            }
        }
    }
    // PowerShell: `$env:HUSKY=0`, `$env:HUSKY = '0'` (split into three words).
    let words = &simple.words;
    for (index, word) in words.iter().enumerate() {
        let lowered = word.to_ascii_lowercase();
        let Some(rest) = lowered.strip_prefix("$env:") else {
            continue;
        };
        let original = &word[5..];
        if let Some((name, value)) = original.split_once('=') {
            found.push((name.to_owned(), value.to_owned()));
        } else if words.get(index + 1).map(String::as_str) == Some("=") {
            let value = words.get(index + 2).cloned().unwrap_or_default();
            found.push((rest.to_owned().to_ascii_uppercase(), value));
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Denials: hook bypasses
// ---------------------------------------------------------------------------

fn bypass_reason(simple: &Simple) -> Option<String> {
    let git = parse_git(&simple.words);
    for (name, value) in assignments(simple) {
        if let Some(reason) = bypass_env(&name, &value, git.as_ref()) {
            return Some(reason);
        }
    }
    if let Some(git) = &git {
        if git
            .config_keys
            .iter()
            .any(|key| key.eq_ignore_ascii_case("core.hookspath"))
        {
            return Some(
                "git -c core.hooksPath=... routes this command around the repository hooks; the hooks are the gate, so they are not bypassed"
                    .into(),
            );
        }
        if git.subcommand == "config" && config_edits_hooks_path(&git.args) {
            return Some(
                "editing core.hooksPath removes the repository gate from git; leave it set to the committed hooks"
                    .into(),
            );
        }
        if HOOKED_SUBCOMMANDS.contains(&git.subcommand.as_str()) && skips_hooks(git) {
            return Some(format!(
                "git {} --no-verify (or -n) skips the repository hooks, which are the gate; run the gate and fix what it reports instead",
                git.subcommand
            ));
        }
    }
    if edits_git_config_file(simple) {
        return Some(
            "this command rewrites a git configuration file to set core.hooksPath, which would route around the repository hooks"
                .into(),
        );
    }
    None
}

fn truthy(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off"
    )
}

fn bypass_env(name: &str, value: &str, git: Option<&GitInvocation>) -> Option<String> {
    let upper = name.to_ascii_uppercase();
    let hooked_git = git.is_some_and(|git| HOOKED_SUBCOMMANDS.contains(&git.subcommand.as_str()));
    let bypass = match upper.as_str() {
        "HUSKY" | "LEFTHOOK" => value.trim() == "0",
        // pre-commit's own skip list only matters on a git command.
        "SKIP" => hooked_git && truthy(value),
        "GIT_CONFIG_PARAMETERS" => value.to_ascii_lowercase().contains("hookspath"),
        _ if upper.starts_with("GIT_CONFIG_KEY_") => value.eq_ignore_ascii_case("core.hookspath"),
        _ => {
            // `HUSKY_SKIP_HOOKS`, `SKIP_SIMPLE_GIT_HOOKS`, `RIGHTKIT_SKIP_HOOKS`,
            // `LEFTHOOK_EXCLUDE`, ...: a name that says it skips or disables hooks.
            let says_hooks = upper.contains("HOOK") || upper.starts_with("LEFTHOOK");
            let says_skip = ["SKIP", "DISABLE", "BYPASS", "EXCLUDE"]
                .iter()
                .any(|word| upper.contains(word));
            says_hooks && says_skip && truthy(value)
        }
    };
    bypass.then(|| {
        format!(
            "{name}={value} disables the repository hooks, which are the gate; run the gate and fix what it reports instead"
        )
    })
}

/// `git config` arguments that set, add or remove `core.hooksPath`. A read
/// (`--get`, `--list`, the bare key) is not an edit.
fn config_edits_hooks_path(args: &[String]) -> bool {
    const VALUE_FLAGS: [&str; 8] = [
        "-f",
        "--file",
        "--blob",
        "-t",
        "--type",
        "--default",
        "--comment",
        "--fixed-value",
    ];
    const EDIT_FLAGS: [&str; 5] = ["--unset", "--unset-all", "--add", "--replace-all", "--edit"];
    let mut positionals: Vec<&str> = Vec::new();
    let mut edit_flag = false;
    let mut index = 0;
    while index < args.len() {
        let word = args[index].as_str();
        if EDIT_FLAGS.contains(&word) || word == "-e" {
            edit_flag = true;
        }
        if VALUE_FLAGS.contains(&word) {
            index += 2;
            continue;
        }
        if !word.starts_with('-') {
            positionals.push(word);
        }
        index += 1;
    }
    let is_key = |word: &str| word.eq_ignore_ascii_case("core.hookspath");
    if !positionals.iter().any(|word| is_key(word)) {
        return false;
    }
    // git >= 2.46: `git config set|unset <key> ...`.
    if matches!(positionals.first(), Some(&"set") | Some(&"unset")) {
        return true;
    }
    if edit_flag {
        return true;
    }
    // Legacy form: `git config <key> <value>` sets; `git config <key>` reads.
    positionals.first().is_some_and(|word| is_key(word)) && positionals.len() >= 2
}

/// `--no-verify` (or an unambiguous abbreviation of at least `--no-ve`), and,
/// for `commit` only, the short `-n`, alone or bundled (`-anm msg`).
fn skips_hooks(git: &GitInvocation) -> bool {
    const LONG: &str = "--no-verify";
    for word in &git.args {
        if word == "--" {
            break;
        }
        if word.starts_with("--no-ve") && LONG.starts_with(word.as_str()) {
            return true;
        }
    }
    if git.subcommand != "commit" {
        // `git push -n` is --dry-run, `git merge -n` is --no-stat: not a bypass.
        return false;
    }
    let mut skip_next = false;
    for word in &git.args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if word == "--" {
            break;
        }
        if let Some(rest) = word.strip_prefix("--") {
            // Long options that take a separate value.
            if matches!(
                rest,
                "message"
                    | "file"
                    | "reuse-message"
                    | "reedit-message"
                    | "author"
                    | "date"
                    | "template"
                    | "fixup"
                    | "squash"
                    | "cleanup"
                    | "trailer"
            ) {
                skip_next = true;
            }
            continue;
        }
        if let Some(bundle) = word.strip_prefix('-') {
            // Bundled short flags: letters up to the first one that takes a value.
            for flag in bundle.chars() {
                match flag {
                    'n' => return true,
                    'm' | 'F' | 'C' | 'c' | 't' => {
                        // The value is the rest of the word, or the next word.
                        if bundle.ends_with(flag) {
                            skip_next = true;
                        }
                        break;
                    }
                    'S' | 'u' => break, // optional attached value
                    _ => {}
                }
            }
        }
    }
    false
}

/// `sed -i`, `tee`, `echo >>` and the like aimed at a git configuration file
/// with `hooksPath` in the same simple command.
fn edits_git_config_file(simple: &Simple) -> bool {
    let program = program_of(simple).unwrap_or_default();
    if !matches!(
        program.as_str(),
        "sed"
            | "tee"
            | "perl"
            | "ex"
            | "ed"
            | "vi"
            | "vim"
            | "nano"
            | "echo"
            | "printf"
            | "cat"
            | "awk"
            | "python"
            | "python3"
            | "node"
    ) {
        return false;
    }
    let joined = simple
        .words
        .join(" ")
        .to_ascii_lowercase()
        .replace('\\', "/");
    joined.contains("hookspath")
        && [".git/config", ".gitconfig", "git/config", "config.worktree"]
            .iter()
            .any(|marker| joined.contains(marker))
}

// ---------------------------------------------------------------------------
// Confirmations: merge, push to the default branch
// ---------------------------------------------------------------------------

fn confirmation_reason(simple: &Simple, dir: Option<&Path>) -> Option<String> {
    let program = program_of(simple)?;
    match program.as_str() {
        "gh" => merge_reason(&simple.words),
        "git" => {
            let git = parse_git(&simple.words)?;
            if git.subcommand != "push" {
                return None;
            }
            let base = match (&git.dir, dir) {
                (Some(path), Some(base)) => Some(base.join(path)),
                (Some(path), None) => Some(PathBuf::from(path)),
                (None, Some(base)) => Some(base.to_path_buf()),
                (None, None) => std::env::current_dir().ok(),
            };
            let branch = push_default_branch_target(&git.args, base.as_deref())?;
            Some(format!(
                "Guard needs your confirmation: git push targets the repository's default branch ('{branch}'). Approve only if you asked for this push and the repo gate and required CI are green on this head."
            ))
        }
        _ => None,
    }
}

fn merge_reason(words: &[String]) -> Option<String> {
    let positionals = gh_positionals(words);
    let merge = |detail: &str| {
        Some(format!(
            "Guard needs your confirmation: {detail} merges a pull request, which cannot be taken back. Approve only if you asked for this merge and every required CI check is green on the exact head."
        ))
    };
    match positionals.as_slice() {
        [first, second, ..] if first == "pr" && second == "merge" => merge("gh pr merge"),
        [first, endpoint, ..] if first == "api" => {
            let lowered_all = words.join(" ").to_ascii_lowercase();
            if lowered_all.contains("mergepullrequest") {
                return merge("a GraphQL mergePullRequest mutation");
            }
            let endpoint = endpoint.to_ascii_lowercase();
            let merging_endpoint = endpoint.ends_with("/merge") || endpoint.ends_with("/merges");
            let writes = words.windows(2).any(|pair| {
                matches!(pair[0].as_str(), "-X" | "--method")
                    && matches!(pair[1].to_ascii_uppercase().as_str(), "PUT" | "POST")
            }) || words.iter().any(|word| {
                matches!(
                    word.as_str(),
                    "-f" | "-F" | "--field" | "--raw-field" | "--input"
                )
            });
            (merging_endpoint && writes).then(|| {
                "Guard needs your confirmation: this gh api call merges a pull request or branch, which cannot be taken back. Approve only if you asked for this merge and every required CI check is green on the exact head."
                    .to_owned()
            })
        }
        _ => None,
    }
}

/// Non-flag words after `gh`, skipping the repository selector and the other
/// flags that take a separate value (`-X PUT`, `-f key=value`, `-H header`).
fn gh_positionals(words: &[String]) -> Vec<String> {
    const VALUE_FLAGS: [&str; 17] = [
        "-R",
        "--repo",
        "-X",
        "--method",
        "-H",
        "--header",
        "-f",
        "-F",
        "--field",
        "--raw-field",
        "--input",
        "-q",
        "--jq",
        "-t",
        "--template",
        "--hostname",
        "--cache",
    ];
    let mut out = Vec::new();
    let mut index = 1;
    while index < words.len() {
        let word = words[index].as_str();
        if VALUE_FLAGS.contains(&word) {
            index += 2;
            continue;
        }
        if !word.starts_with('-') {
            out.push(word.to_owned());
        }
        index += 1;
    }
    out
}

/// The default-branch name this `git push` would update, if any.
fn push_default_branch_target(args: &[String], dir: Option<&Path>) -> Option<String> {
    const VALUE_FLAGS: [&str; 6] = [
        "-o",
        "--push-option",
        "--repo",
        "--receive-pack",
        "--exec",
        "--recurse-submodules",
    ];
    let mut positionals: Vec<&str> = Vec::new();
    let mut all = false;
    let mut index = 0;
    while index < args.len() {
        let word = args[index].as_str();
        if word == "--dry-run" || word == "-n" {
            // A dry run updates nothing.
            return None;
        }
        if word == "--all" {
            all = true;
        }
        if VALUE_FLAGS.contains(&word) {
            index += 2;
            continue;
        }
        if !word.starts_with('-') {
            positionals.push(word);
        }
        index += 1;
    }
    let view = dir.and_then(repo_view);
    let current = view.as_ref().and_then(|view| current_branch(&view.git_dir));
    let remote = positionals.first().copied().unwrap_or("origin");
    let mut protected: BTreeSet<String> = DEFAULT_BRANCH_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    if let Some(view) = &view {
        protected.extend(remote_default_branch(&view.common, remote));
    }
    if all {
        return protected.iter().next().cloned();
    }
    let refspecs = positionals.get(1..).unwrap_or(&[]);
    if refspecs.is_empty() {
        // `git push` / `git push <remote>`: the current branch goes to its
        // same-named (or tracking) branch.
        let current = current?;
        return protected.contains(&current).then_some(current);
    }
    for refspec in refspecs {
        let refspec = refspec.trim_start_matches('+');
        let destination = refspec.rsplit_once(':').map_or(refspec, |(_, dst)| dst);
        let destination = destination
            .strip_prefix("refs/heads/")
            .unwrap_or(destination);
        let destination = if destination == "HEAD" || destination == "@" {
            match &current {
                Some(branch) => branch.as_str(),
                None => continue,
            }
        } else {
            destination
        };
        if protected.contains(destination) {
            return Some(destination.to_owned());
        }
    }
    None
}

struct RepoView {
    git_dir: PathBuf,
    common: PathBuf,
}

fn repo_view(dir: &Path) -> Option<RepoView> {
    let git_dir = resolve_git_dir(dir)?;
    let common = resolve_common_git_dir(&git_dir).unwrap_or_else(|| git_dir.clone());
    Some(RepoView { git_dir, common })
}

fn current_branch(git_dir: &Path) -> Option<String> {
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let reference = head.trim().strip_prefix("ref: ")?.trim();
    reference.strip_prefix("refs/heads/").map(str::to_owned)
}

/// The branch the remote's `HEAD` symbolic ref names, when it was recorded.
fn remote_default_branch(common_git_dir: &Path, remote: &str) -> Option<String> {
    for name in [remote, "origin"] {
        if name.is_empty() || name.contains(['/', '\\', ':']) {
            continue;
        }
        let path = common_git_dir
            .join("refs")
            .join("remotes")
            .join(name)
            .join("HEAD");
        if let Ok(text) = fs::read_to_string(path) {
            let prefix = format!("ref: refs/remotes/{name}/");
            if let Some(branch) = text.trim().strip_prefix(&prefix) {
                return Some(branch.to_owned());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// git invocation parsing
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct GitInvocation {
    /// Keys set by `-c key=value` and `--config-env=key=ENV`.
    config_keys: Vec<String>,
    /// `-C <dir>`.
    dir: Option<String>,
    subcommand: String,
    args: Vec<String>,
}

fn parse_git(words: &[String]) -> Option<GitInvocation> {
    let first = words.first()?;
    if !program_name(first).eq_ignore_ascii_case("git") {
        return None;
    }
    let mut config_keys = Vec::new();
    let mut dir = None;
    let mut index = 1;
    while index < words.len() {
        let word = words[index].as_str();
        if !word.starts_with('-') {
            return Some(GitInvocation {
                config_keys,
                dir,
                subcommand: word.to_ascii_lowercase(),
                args: words[index + 1..].to_vec(),
            });
        }
        let key_of = |setting: &str| setting.split('=').next().unwrap_or("").to_owned();
        if let Some(setting) = word.strip_prefix("--config-env=") {
            config_keys.push(key_of(setting));
            index += 1;
        } else if word == "-c" || word == "--config-env" {
            if let Some(setting) = words.get(index + 1) {
                config_keys.push(key_of(setting));
            }
            index += 2;
        } else if word == "-C" {
            dir = words.get(index + 1).cloned();
            index += 2;
        } else if GIT_VALUE_FLAGS.contains(&word) {
            index += 2;
        } else {
            index += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(command: &str) -> bool {
        matches!(evaluate_command(command, None), Some(Gate::Deny { .. }))
    }

    fn ask_in(command: &str, dir: &Path) -> bool {
        matches!(evaluate_command(command, Some(dir)), Some(Gate::Ask { .. }))
    }

    fn quiet(command: &str) -> bool {
        evaluate_command(command, None).is_none()
    }

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "legion-vcs-gate-{name}-{}-{}",
            std::process::id(),
            crate::unix_nanos()
        ));
        fs::create_dir_all(root.join(".git")).unwrap();
        root
    }

    fn on_branch(root: &Path, branch: &str) {
        fs::write(
            root.join(".git/HEAD"),
            format!("ref: refs/heads/{branch}\n"),
        )
        .unwrap();
    }

    #[test]
    fn no_verify_is_denied_on_every_hooked_subcommand_and_wrapper() {
        for command in [
            "git commit --no-verify -m x",
            "git commit -m x --no-verify",
            "git push --no-verify origin feature",
            "git push origin feature --no-verify",
            "git merge --no-verify topic",
            "git commit --no-ver -m x",
            "git commit -n -m x",
            "git commit -nm x",
            "git commit -nothing-here",
            "git commit -anm x",
            "git -C repo commit --no-verify",
            "git -c user.name=x commit --no-verify",
            "bash -c 'git commit --no-verify -m x'",
            "sudo git push --no-verify",
            "env FOO=1 git commit -n",
            "cd /tmp && git commit --no-verify",
            "echo ok; git commit --no-verify",
        ] {
            assert!(deny(command), "must be denied: {command}");
        }
    }

    #[test]
    fn ordinary_commits_pushes_and_mentions_of_the_flag_pass() {
        for command in [
            "git commit -m x",
            "git commit -m 'never use --no-verify'",
            "git commit -m \"-n is a flag\"",
            "git commit -am 'a note'",
            "git commit -qm x",
            "git commit --no-edit --amend",
            "git push origin feature",
            "git push -n origin feature",
            "git push --dry-run origin feature",
            "git merge -n topic",
            "echo git commit --no-verify",
            "grep -r -- --no-verify docs",
            "git log --grep=--no-verify",
        ] {
            assert!(
                !deny(command),
                "must not be denied: {command} -> {:?}",
                evaluate_command(command, None)
            );
        }
    }

    #[test]
    fn hooks_path_edits_are_denied_but_reads_are_not() {
        for command in [
            "git config core.hooksPath /dev/null",
            "git config core.hookspath NUL",
            "git config --global core.hooksPath ''",
            "git config --local --unset core.hooksPath",
            "git config --unset-all core.hooksPath",
            "git config --add core.hooksPath x",
            "git config set core.hooksPath x",
            "git config unset core.hooksPath",
            "git config --file .git/config core.hooksPath x",
            "git -c core.hooksPath=/dev/null commit -m x",
            "git -c core.hooksPath=/dev/null push",
            "git --config-env=core.hooksPath=EVIL commit -m x",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x",
            "export GIT_CONFIG_KEY_0=core.hooksPath",
            "bash -c 'git config core.hooksPath /dev/null'",
            "sed -i 's/.*/hooksPath = x/' .git/config",
            "echo '[core] hooksPath = x' >> .git/config",
        ] {
            assert!(deny(command), "must be denied: {command}");
        }
        for command in [
            "git config core.hooksPath",
            "git config --get core.hooksPath",
            "git config --local --get core.hooksPath",
            "git config get core.hooksPath",
            "git config --list",
            "git config user.name x",
            "git config core.autocrlf false",
            "cat .git/config",
            "grep hooksPath .git/config",
        ] {
            assert!(!deny(command), "must not be denied: {command}");
        }
    }

    #[test]
    fn hook_bypass_environment_is_denied_in_every_shell_form() {
        for command in [
            "HUSKY=0 git commit -m x",
            "HUSKY=0 git push",
            "export HUSKY=0",
            "env HUSKY=0 pnpm test",
            "bash -c 'HUSKY=0 git push'",
            "LEFTHOOK=0 git commit -m x",
            "HUSKY_SKIP_HOOKS=1 git commit -m x",
            "SKIP_SIMPLE_GIT_HOOKS=1 git commit -m x",
            "RIGHTKIT_SKIP_HOOKS=1 git push",
            "LEFTHOOK_EXCLUDE=pre-push git push",
            "SKIP=lint git commit -m x",
            "$env:HUSKY=0; git commit -m x",
            "$env:HUSKY = '0'",
            "set HUSKY=0 && git commit -m x",
        ] {
            assert!(deny(command), "must be denied: {command}");
        }
        for command in [
            "HUSKY=1 git commit -m x",
            "SKIP=1 make build",
            "SKIP_HOOKS=0 git commit -m x",
            "RUST_LOG=debug cargo test",
            "echo HUSKY=0",
            "git commit -m 'HUSKY=0 is a bypass'",
        ] {
            assert!(!deny(command), "must not be denied: {command}");
        }
    }

    const FILE_TOOLS: [&str; 4] = ["Write", "Edit", "MultiEdit", "NotebookEdit"];

    fn edit(tool: &str, input: Value) -> Option<String> {
        tool_input_edits_hooks_path(tool, input.as_object().unwrap())
    }

    #[test]
    fn file_tools_cannot_set_hooks_path_in_a_git_config_file() {
        for tool in FILE_TOOLS {
            assert!(edit(
                tool,
                serde_json::json!({
                    "file_path": "/repo/.git/config",
                    "old_string": "[core]",
                    "new_string": "[core]\n\thooksPath = /dev/null"
                })
            )
            .is_some());
            assert!(edit(
                tool,
                serde_json::json!({
                    "file_path": "C:\\Users\\me\\.gitconfig",
                    "content": "[core]\nhooksPath = NUL"
                })
            )
            .is_some());
            // Removing it is an edit too.
            assert!(edit(
                tool,
                serde_json::json!({
                    "file_path": "/repo/.git/config",
                    "old_string": "\thooksPath = .githooks\n",
                    "new_string": ""
                })
            )
            .is_some());
            // The edits of a MultiEdit are searched as well.
            assert!(edit(
                tool,
                serde_json::json!({
                    "file_path": "/repo/.git/config",
                    "edits": [{"old_string": "[core]", "new_string": "[core]\n\thookspath = x"}]
                })
            )
            .is_some());
            // Other keys in a git config file are untouched.
            assert!(edit(
                tool,
                serde_json::json!({
                    "file_path": "/repo/.git/config",
                    "new_string": "[user]\n\tname = x"
                })
            )
            .is_none());
        }
    }

    #[test]
    fn a_document_that_mentions_hooks_path_and_git_config_is_an_ordinary_edit() {
        let prose =
            "Never set core.hooksPath by editing .git/config or ~/.gitconfig; the hook denies it.";
        for tool in FILE_TOOLS {
            for input in [
                serde_json::json!({"file_path": "/repo/docs/guard.md", "new_string": prose}),
                serde_json::json!({"file_path": "/repo/docs/guard.md", "content": prose}),
                serde_json::json!({"path": "C:\\repo\\docs\\guard.md", "content": prose}),
                serde_json::json!({
                    "notebook_path": "/repo/notes.ipynb",
                    "new_source": "core.hooksPath lives in .git/config"
                }),
                serde_json::json!({
                    "file_path": "/repo/README.md",
                    "edits": [{"old_string": "a", "new_string": prose}]
                }),
            ] {
                assert_eq!(edit(tool, input.clone()), None, "{tool}: {input}");
            }
        }
    }

    #[test]
    fn apply_patch_is_judged_by_the_files_its_headers_name() {
        let patch = |body: &str| serde_json::json!({"input": format!("*** Begin Patch\n{body}\n*** End Patch")});
        let denied = |body: &str| edit("apply_patch", patch(body)).is_some();
        assert!(denied("*** Update File: .git/config\n+\thooksPath = x"));
        assert!(denied(
            "*** Update File: C:\\repo\\.git\\config\n@@\n-\thookspath = .githooks"
        ));
        assert!(denied(
            "*** Add File: /home/me/.gitconfig\n+[core]\n+\thooksPath = NUL"
        ));
        assert!(denied(
            "*** Update File: notes.txt\n*** Move to: .git/config\n@@\n+\thooksPath = x"
        ));
        assert!(denied(
            "*** Update File: docs/a.md\n+prose\n*** Update File: .git/config\n@@\n+\thooksPath = x"
        ));
        // The command-array shape carries the same patch text.
        assert!(edit(
            "apply_patch",
            serde_json::json!({"command": ["apply_patch", "*** Begin Patch\n*** Update File: .git/config\n+\thooksPath = x\n*** End Patch"]})
        )
        .is_some());

        // A document that mentions both strings, with or without the patch
        // markers quoted in its text, is an ordinary edit.
        assert!(!denied(
            "*** Update File: docs/guard.md\n+Do not set core.hooksPath by editing .git/config."
        ));
        assert!(!denied(
            "*** Add File: docs/patch-format.md\n+*** Update File: .git/config\n+\thooksPath = x"
        ));
        // Only the section of a git config file is searched.
        assert!(!denied(
            "*** Update File: .git/config\n+[user]\n+\tname = x\n*** Update File: docs/guard.md\n+core.hooksPath is guarded"
        ));
        assert!(!denied(
            "*** Update File: .git/config\n+[user]\n+\tname = x\n*** Delete File: old.md\n*** Update File: docs/guard.md\n+core.hooksPath"
        ));
        // Another tool does not read patch markers out of its text.
        assert_eq!(
            edit(
                "Write",
                serde_json::json!({
                    "file_path": "/repo/docs/patch-format.md",
                    "content": "*** Update File: .git/config\n+\thooksPath = x"
                })
            ),
            None
        );
    }

    #[test]
    fn gh_pr_merge_and_merge_api_calls_ask() {
        let dir = scratch("merge");
        for command in [
            "gh pr merge 12",
            "gh pr merge --squash --auto",
            "gh -R owner/repo pr merge 12",
            "gh pr merge 12 --repo owner/repo",
            "bash -c 'gh pr merge 12'",
            "gh api -X PUT repos/o/r/pulls/12/merge",
            "gh api --method PUT repos/o/r/pulls/12/merge -f merge_method=squash",
            "gh api repos/o/r/merges -f base=main -f head=topic",
            "gh api graphql -f query='mutation { mergePullRequest(input:{pullRequestId:\"x\"}) { clientMutationId } }'",
        ] {
            assert!(ask_in(command, &dir), "must ask: {command}");
        }
        for command in [
            "gh pr view 12",
            "gh pr checks 12",
            "gh pr create --fill",
            "gh api repos/o/r/pulls/12",
            "gh api repos/o/r/pulls/12/merge",
            "gh run list",
            "echo gh pr merge",
        ] {
            assert!(!ask_in(command, &dir), "must not ask: {command}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn push_to_the_default_branch_asks_and_other_pushes_do_not() {
        let dir = scratch("push");
        on_branch(&dir, "feature");
        for command in [
            "git push origin main",
            "git push origin master",
            "git push origin HEAD:main",
            "git push origin feature:main",
            "git push origin refs/heads/main",
            "git push -u origin main",
            "git push --all",
            "git -C . push origin main",
            "bash -c 'git push origin main'",
            "sudo git push origin main",
            "git commit -q -F - && git push origin main",
            "git push origin main 2>&1 | tail -2",
        ] {
            assert!(ask_in(command, &dir), "must ask: {command}");
        }
        for command in [
            "git push",
            "git push origin",
            "git push origin feature",
            "git push origin HEAD",
            "git push -u origin feature",
            "git push --force-with-lease origin feature:topic",
            "git push --dry-run origin main",
            "git push -n origin main",
            "git push --tags",
            "git push origin v1.2.3",
            "git log origin/main",
            "echo git push origin main",
        ] {
            assert!(!ask_in(command, &dir), "must not ask: {command}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bare_push_asks_only_while_the_default_branch_is_checked_out() {
        let dir = scratch("bare");
        on_branch(&dir, "main");
        assert!(ask_in("git push", &dir));
        assert!(ask_in("git push origin", &dir));
        assert!(ask_in("git push origin HEAD", &dir));
        on_branch(&dir, "feature");
        assert!(!ask_in("git push", &dir));
        assert!(!ask_in("git push origin HEAD", &dir));
        // The remote's recorded default branch counts too.
        fs::create_dir_all(dir.join(".git/refs/remotes/origin")).unwrap();
        fs::write(
            dir.join(".git/refs/remotes/origin/HEAD"),
            "ref: refs/remotes/origin/develop\n",
        )
        .unwrap();
        on_branch(&dir, "develop");
        assert!(ask_in("git push", &dir));
        assert!(ask_in("git push origin develop", &dir));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cd_in_the_command_moves_the_repository_the_push_is_judged_in() {
        let on_main = scratch("cd-main");
        on_branch(&on_main, "main");
        let on_feature = scratch("cd-feature");
        on_branch(&on_feature, "feature");
        let command = format!("cd {} && git push", on_main.display());
        assert!(ask_in(&command, &on_feature));
        let command = format!("cd {} && git push", on_feature.display());
        assert!(!ask_in(&command, &on_main));
        let _ = fs::remove_dir_all(on_main);
        let _ = fs::remove_dir_all(on_feature);
    }

    #[test]
    fn denials_win_over_confirmations_on_the_same_line() {
        let dir = scratch("order");
        on_branch(&dir, "feature");
        let both = "git push origin main && git commit --no-verify -m x";
        assert!(matches!(
            evaluate_command(both, Some(&dir)),
            Some(Gate::Deny { .. })
        ));
        assert!(quiet("git status"));
        let _ = fs::remove_dir_all(dir);
    }
}
