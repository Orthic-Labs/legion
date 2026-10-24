//! Hook v2 end to end: the shapes that used to be classified and allowed now
//! deny or ask, Agent/Task launches meet the model ceiling, Stop wants
//! objective evidence, and SessionStart verifies the workspace gate hook.
//! Every test drives the real binary over its stdin/stdout contract.

use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const HEAD: &str = "66c9ddd4d704934d8408f38ef0ab9a09e4817661";

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "legion-hook-v2-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(state: Option<&Path>, payload: &Value) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_legion-hook"));
    command
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .env_remove("LEGION_M1_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(state) = state {
        command.env("LEGION_STATE_ROOT", state);
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn bash(command: &str, cwd: &Path) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": cwd,
        "sourceRevision": REVISION,
        "tool_input": {"command": command}
    })
}

fn decision(result: &Value) -> &str {
    result["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("allow")
}

fn repository(scratch: &Scratch, branch: &str) -> PathBuf {
    let root = scratch.path().join("repo");
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(
        root.join(".git/HEAD"),
        format!("ref: refs/heads/{branch}\n"),
    )
    .unwrap();
    root
}

#[test]
fn hook_bypasses_are_denied_with_a_stable_code() {
    let scratch = Scratch::new("bypass");
    let repo = repository(&scratch, "feature");
    for command in [
        "git push --no-verify origin feature",
        "git commit --no-verify -m x",
        "git commit -n -m x",
        "git config core.hooksPath /dev/null",
        "git config --global core.hooksPath NUL",
        "git -c core.hooksPath=/dev/null commit -m x",
        "HUSKY=0 git push origin feature",
        "bash -c 'git commit --no-verify -m x'",
        "sudo env HUSKY=0 git commit -m x",
    ] {
        let result = invoke(None, &bash(command, &repo));
        assert_eq!(result["allowed"], false, "{command}: {result}");
        assert_eq!(result["code"], "ARC_HOOK_BYPASS_DENIED", "{command}");
        assert_eq!(decision(&result), "deny", "{command}");
    }
}

#[test]
fn ordinary_git_work_is_untouched() {
    let scratch = Scratch::new("ordinary");
    let repo = repository(&scratch, "feature");
    for command in [
        "git commit -m 'document --no-verify'",
        "git push origin feature",
        "git push",
        "git push --force-with-lease=feature origin HEAD",
        "git config core.hooksPath",
        "git config user.name x",
        "git status",
    ] {
        let result = invoke(None, &bash(command, &repo));
        // A rewrite push stays refused by its own older gate; nothing here
        // may be refused by the new ones.
        if command.contains("--force") {
            assert_eq!(result["code"], "ARC_APPROVAL_REQUIRED", "{command}");
            continue;
        }
        assert_eq!(result["allowed"], true, "{command}: {result}");
    }
}

#[test]
fn merging_and_pushing_the_default_branch_ask_the_operator() {
    let scratch = Scratch::new("ask");
    let repo = repository(&scratch, "feature");
    for command in [
        "gh pr merge 12 --squash",
        "gh api -X PUT repos/o/r/pulls/12/merge",
        "git push origin main",
        "git push origin HEAD:main",
        "git push -u origin refs/heads/main",
    ] {
        let result = invoke(None, &bash(command, &repo));
        assert_eq!(result["allowed"], false, "{command}: {result}");
        assert_eq!(
            result["code"], "ARC_USER_CONFIRMATION_REQUIRED",
            "{command}"
        );
        assert_eq!(decision(&result), "ask", "{command}");
        assert!(
            result["reason"].as_str().unwrap().contains("confirmation"),
            "{command}"
        );
    }
    // On the default branch itself a bare push asks too.
    let on_main = Scratch::new("ask-main");
    let main_repo = repository(&on_main, "main");
    let result = invoke(None, &bash("git push", &main_repo));
    assert_eq!(decision(&result), "ask", "{result}");
}

#[test]
fn force_pushes_to_the_default_branch_stay_denied_not_asked() {
    let scratch = Scratch::new("force");
    let repo = repository(&scratch, "feature");
    for command in [
        "git push --force origin main",
        "git push -f origin HEAD:main",
        "git push origin +main",
        "git push --force-with-lease origin main",
        "git push --delete origin main",
    ] {
        let result = invoke(None, &bash(command, &repo));
        assert_eq!(result["allowed"], false, "{command}");
        assert_eq!(
            decision(&result),
            "deny",
            "{command}: must block, not prompt"
        );
    }
}

#[test]
fn git_config_files_cannot_be_edited_to_set_a_hooks_path() {
    let scratch = Scratch::new("config-edit");
    let repo = repository(&scratch, "feature");
    let result = invoke(
        None,
        &json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "cwd": repo,
            "sourceRevision": REVISION,
            "tool_input": {
                "file_path": repo.join(".git/config"),
                "old_string": "[core]",
                "new_string": "[core]\n\thooksPath = /dev/null"
            }
        }),
    );
    assert_eq!(result["code"], "ARC_HOOK_BYPASS_DENIED", "{result}");
    let other = invoke(
        None,
        &json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "cwd": repo,
            "sourceRevision": REVISION,
            "tool_input": {
                "file_path": repo.join("README.md"),
                "old_string": "a",
                "new_string": "b"
            }
        }),
    );
    assert_eq!(other["allowed"], true, "{other}");
}

// ---------------------------------------------------------------------------
// Agent / Task model ceiling
// ---------------------------------------------------------------------------

fn tiers() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/config/model-tiers.json"
    )))
    .unwrap()
}

fn tier_model(tier: &str) -> String {
    tiers()["tiers"][tier]["hosts"]["claude-code"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn marker() -> String {
    tiers()["subagents"]["approvalMarker"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn launch(tool: &str, input: Value) -> Value {
    invoke(
        None,
        &json!({"hook_event_name":"PreToolUse","tool_name":tool,"sourceRevision":REVISION,"tool_input":input}),
    )
}

#[test]
fn agent_and_task_launches_above_the_ceiling_are_refused() {
    for tool in ["Agent", "Task"] {
        for tier in ["frontier-judgment", "deliberation"] {
            let model = tier_model(tier);
            // `frontier-judgment` shares the ceiling model on this host; only
            // tiers that really rank above it are refused.
            let ranks_above = model != tier_model("balanced-executor");
            let result = launch(
                tool,
                json!({"description":"d","prompt":"review","subagent_type":"general-purpose","model":model}),
            );
            if ranks_above {
                assert_eq!(result["allowed"], false, "{tool}/{tier}: {result}");
                assert_eq!(result["code"], "ARC_MODEL_CEILING_EXCEEDED");
                assert_eq!(decision(&result), "deny");
                assert!(result["reason"].as_str().unwrap().contains(&marker()));
            } else {
                assert_eq!(result["allowed"], true, "{tool}/{tier}: {result}");
            }
        }
    }
}

#[test]
fn an_operator_approval_marker_in_the_prompt_admits_the_named_model_only() {
    let high = tier_model("deliberation");
    let prompt = format!("Adjudicate.\n{}: {high}\n", marker());
    let admitted = launch(
        "Agent",
        json!({"description":"d","prompt":prompt,"subagent_type":"general-purpose","model":high}),
    );
    assert_eq!(admitted["allowed"], true, "{admitted}");
    let wrong = launch(
        "Agent",
        json!({"description":"d","prompt":format!("{}: some-other-model", marker()),
               "subagent_type":"general-purpose","model":high}),
    );
    assert_eq!(wrong["allowed"], false, "{wrong}");
}

#[test]
fn a_launch_with_no_model_gets_the_default_through_updated_input() {
    let default = tier_model("mechanical-cheap");
    let result = launch(
        "Agent",
        json!({"description":"look","prompt":"find usages","subagent_type":"Explore"}),
    );
    assert_eq!(result["allowed"], true, "{result}");
    let output = &result["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse");
    assert_eq!(output["permissionDecision"], "allow");
    assert_eq!(output["updatedInput"]["model"], json!(default));
    // The replacement is the whole input, not a patch.
    assert_eq!(output["updatedInput"]["prompt"], "find usages");
    assert_eq!(output["updatedInput"]["subagent_type"], "Explore");
    assert_eq!(output["updatedInput"]["description"], "look");
}

#[test]
fn packaged_roles_keep_their_card_model_and_are_not_overridden() {
    for role in [
        "legion:alchemist",
        "legion:alchemist-specialist",
        "legion:oracle",
        "legion:sage",
    ] {
        let result = launch(
            "Agent",
            json!({"description":"d","prompt":"p","subagent_type":role}),
        );
        assert_eq!(result["allowed"], true, "{role}: {result}");
        assert!(
            result["hookSpecificOutput"]["updatedInput"].is_null(),
            "{role} must not be rewritten: {result}"
        );
    }
}

#[test]
fn hooks_json_registers_the_pre_tool_use_hook_for_agent_and_task() {
    let hooks: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../hooks/hooks.json"
    )))
    .unwrap();
    let matcher = hooks["hooks"]["PreToolUse"][0]["matcher"].as_str().unwrap();
    let names: Vec<&str> = matcher.split('|').collect();
    assert!(
        names.contains(&"Agent") && names.contains(&"Task"),
        "{matcher}"
    );
}

// ---------------------------------------------------------------------------
// Stop evidence
// ---------------------------------------------------------------------------

struct Session {
    scratch: Scratch,
    repo: PathBuf,
    transcript: PathBuf,
    lines: Vec<String>,
}

impl Session {
    fn new(name: &str) -> Self {
        let scratch = Scratch::new(name);
        let repo = scratch.path().join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join(".git/HEAD"), format!("{HEAD}\n")).unwrap();
        let transcript = scratch.path().join("transcript.jsonl");
        Self {
            scratch,
            repo,
            transcript,
            lines: Vec::new(),
        }
    }

    fn push(&mut self, line: Value) -> &mut Self {
        self.lines.push(line.to_string());
        self.write();
        self
    }

    fn write(&self) {
        fs::write(&self.transcript, self.lines.join("\n")).unwrap();
    }

    fn prompt(&mut self, text: &str) -> &mut Self {
        self.push(json!({"type":"user","message":{"role":"user","content":text}}))
    }

    fn tool(&mut self, id: &str, name: &str, input: Value, output: &str) -> &mut Self {
        self.push(
            json!({"type":"assistant","message":{"role":"assistant","content":[
            {"type":"tool_use","id":id,"name":name,"input":input}]}}),
        );
        self.push(json!({"type":"user","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":id,"content":output,"is_error":false}]}}))
    }

    fn edit(&mut self, id: &str) -> &mut Self {
        self.tool(
            id,
            "Edit",
            json!({"file_path":"src/lib.rs","old_string":"a","new_string":"b"}),
            "edited",
        )
    }

    fn gate(&mut self, id: &str) -> &mut Self {
        self.tool(
            id,
            "Bash",
            json!({"command":"pnpm exec right-release check"}),
            "check: 66c9ddd4d704 passed 12 rules in 6.2s",
        )
    }

    fn stop(&self, message: &str) -> Value {
        invoke(
            Some(&self.scratch.state()),
            &json!({
                "hook_event_name": "Stop",
                "session_id": "stop-gate-session",
                "cwd": self.repo,
                "transcript_path": self.transcript,
                "last_assistant_message": message
            }),
        )
    }
}

#[test]
fn stop_is_denied_once_for_an_edit_turn_that_claims_done_with_no_gate_run() {
    let mut session = Session::new("stop-a");
    session.prompt("fix the parser").edit("t1");
    let denied = session.stop("Done. The parser is fixed.");
    assert_eq!(denied["allowed"], false, "{denied}");
    assert_eq!(denied["code"], "ARC_COMPLETION_EVIDENCE_MISSING");
    assert_eq!(denied["decision"], "block");
    let reason = denied["reason"].as_str().unwrap();
    assert!(reason.contains("right-release check"), "{reason}");
    assert!(reason.contains("CI run URL"), "{reason}");
    assert!(reason.contains("receipt"), "{reason}");
}

#[test]
fn stop_is_allowed_after_a_green_gate_run_that_follows_the_last_edit() {
    let mut session = Session::new("stop-b");
    session.prompt("fix the parser").edit("t1").gate("t2");
    let allowed = session.stop("Done. The parser is fixed; the gate is green.");
    assert_eq!(allowed["allowed"], true, "{allowed}");
}

#[test]
fn stop_still_denies_when_the_gate_ran_before_the_last_edit() {
    let mut session = Session::new("stop-stale");
    session.prompt("fix the parser").gate("t1").edit("t2");
    let denied = session.stop("Done.");
    assert_eq!(
        denied["code"], "ARC_COMPLETION_EVIDENCE_MISSING",
        "{denied}"
    );
}

#[test]
fn stop_wording_about_tests_is_not_evidence() {
    let mut session = Session::new("stop-c");
    session.prompt("fix the parser").edit("t1").tool(
        "t2",
        "Bash",
        json!({"command":"cargo test"}),
        "test result: ok. 12 passed; 0 failed",
    );
    let denied = session.stop("All tests passed. Done.");
    assert_eq!(
        denied["code"], "ARC_COMPLETION_EVIDENCE_MISSING",
        "{denied}"
    );
}

#[test]
fn stop_is_unaffected_for_read_only_turns_and_for_honest_incomplete_ones() {
    let mut read_only = Session::new("stop-d");
    read_only.prompt("what does the parser do?").tool(
        "t1",
        "Read",
        json!({"file_path":"src/lib.rs"}),
        "contents",
    );
    assert_eq!(
        read_only.stop("It is done by the tokenizer.")["allowed"],
        true
    );

    let mut honest = Session::new("stop-honest");
    honest.prompt("fix the parser").edit("t1");
    for message in [
        "Not done: I changed the parser but have not run the gate, so completion is not verified.",
        "Which of the two fixes do you want?",
        "Blocked on the failing fixture; partial change only.",
    ] {
        assert_eq!(honest.stop(message)["allowed"], true, "{message}");
    }
}

#[test]
fn an_earlier_turns_edits_do_not_hold_a_later_conversational_turn() {
    let mut session = Session::new("stop-turns");
    session
        .prompt("fix the parser")
        .edit("t1")
        .prompt("why did it break?")
        .tool("t2", "Read", json!({"file_path":"notes"}), "x");
    assert_eq!(session.stop("It was done by a typo.")["allowed"], true);
}

#[test]
fn a_ci_run_url_on_the_exact_head_or_a_host_receipt_also_satisfies_stop() {
    let mut ci = Session::new("stop-ci");
    ci.prompt("ship it").edit("t1").tool(
        "t2",
        "Bash",
        json!({"command":"gh run view 9 --json conclusion,headSha,url"}),
        &format!(
            "{{\"conclusion\":\"success\",\"headSha\":\"{HEAD}\",\"url\":\"https://github.com/o/r/actions/runs/9\"}}"
        ),
    );
    assert_eq!(ci.stop("Done, CI is green.")["allowed"], true);

    let mut other_head = Session::new("stop-ci-other");
    other_head.prompt("ship it").edit("t1").tool(
        "t2",
        "Bash",
        json!({"command":"gh run view 9 --json conclusion,headSha,url"}),
        "{\"conclusion\":\"success\",\"headSha\":\"0123456789abcdef0123456789abcdef01234567\",\"url\":\"https://github.com/o/r/actions/runs/9\"}",
    );
    assert_eq!(other_head.stop("Done.")["allowed"], false);

    let mut receipt = Session::new("stop-receipt");
    receipt.prompt("test it").edit("t1").tool(
        "t2",
        "Bash",
        json!({"command":"rustright status req-7"}),
        r#"{"id":"req-7","command":"cargo test -p legion-hook","exitCode":0}"#,
    );
    assert_eq!(receipt.stop("Done.")["allowed"], true);
}

#[test]
fn stop_reopens_a_turn_at_most_three_times() {
    let mut session = Session::new("stop-cap");
    session.prompt("fix the parser").edit("t1");
    for attempt in 1..=3 {
        let result = session.stop("Done.");
        assert_eq!(result["allowed"], false, "attempt {attempt}: {result}");
    }
    let fourth = session.stop("Done.");
    assert_eq!(
        fourth["allowed"], true,
        "the cap must release the turn: {fourth}"
    );
    // The cap resets: the next turn that fails is held again.
    let next = session.stop("Done.");
    assert_eq!(next["allowed"], false, "{next}");
}

#[test]
fn a_transcript_the_gate_cannot_read_never_blocks() {
    let session = Session::new("stop-unreadable");
    fs::write(
        &session.transcript,
        "{\"type\":\"response_item\",\"payload\":{}}\nnot json",
    )
    .unwrap();
    assert_eq!(session.stop("Done.")["allowed"], true);
    let missing = invoke(
        Some(&session.scratch.state()),
        &json!({"hook_event_name":"Stop","session_id":"s","cwd":session.repo,
                "transcript_path":session.scratch.path().join("absent.jsonl"),
                "last_assistant_message":"Done."}),
    );
    assert_eq!(missing["allowed"], true);
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn a_shell_edit_is_caught_by_the_git_status_taken_at_prompt_time() {
    if !git_available() {
        return;
    }
    let scratch = Scratch::new("stop-shell");
    let repo = scratch.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(&repo)
        .status()
        .unwrap()
        .success());
    fs::write(repo.join("a.txt"), "one\n").unwrap();
    for arguments in [
        vec!["add", "a.txt"],
        vec![
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "init",
        ],
    ] {
        assert!(Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(arguments)
            .status()
            .unwrap()
            .success());
    }
    let transcript = scratch.path().join("t.jsonl");
    // The only tool call is a shell command the gate cannot classify.
    let lines = [
        json!({"type":"user","message":{"role":"user","content":"tidy the file"}}),
        json!({"type":"assistant","message":{"role":"assistant","content":[
            {"type":"tool_use","id":"t1","name":"Bash","input":{"command":"python3 tidy.py"}}]}}),
        json!({"type":"user","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"t1","content":"ok","is_error":false}]}}),
    ]
    .map(|line| line.to_string())
    .join("\n");
    fs::write(&transcript, lines).unwrap();
    let state = scratch.state();
    let payload = |event: &str, message: Option<&str>| {
        let mut payload = json!({"hook_event_name":event,"session_id":"shell-session",
            "cwd":repo,"transcript_path":transcript});
        if let Some(message) = message {
            payload["last_assistant_message"] = json!(message);
        }
        payload
    };
    invoke(Some(&state), &payload("UserPromptSubmit", None));

    // Nothing changed yet: a done claim is not held.
    assert_eq!(
        invoke(Some(&state), &payload("Stop", Some("Done.")))["allowed"],
        true
    );

    // The shell command rewrote the file during the turn.
    fs::write(repo.join("a.txt"), "two\n").unwrap();
    let held = invoke(Some(&state), &payload("Stop", Some("Done.")));
    assert_eq!(held["code"], "ARC_COMPLETION_EVIDENCE_MISSING", "{held}");
}

// ---------------------------------------------------------------------------
// SessionStart
// ---------------------------------------------------------------------------

fn python_available() -> bool {
    ["python3", "python"].iter().any(|program| {
        Command::new(program)
            .args(["-c", "pass"])
            .output()
            .is_ok_and(|output| output.status.success())
    })
}

fn session_start(cwd: &Path) -> Value {
    invoke(
        None,
        &json!({"hook_event_name":"SessionStart","source":"startup","cwd":cwd}),
    )
}

#[test]
fn session_start_reports_the_workspace_gate_hook_check() {
    if !python_available() {
        return;
    }
    let scratch = Scratch::new("session-start");
    let workspace = scratch.path().join("workspace");
    fs::create_dir_all(workspace.join("tools")).unwrap();
    fs::create_dir_all(workspace.join("app")).unwrap();
    fs::write(
        workspace.join("tools/setup-workspace.py"),
        "import sys\nif '--check' not in sys.argv:\n    sys.exit(3)\nprint('app: core.hooksPath unset')\nsys.exit(1)\n",
    )
    .unwrap();
    let failing = session_start(&workspace.join("app"));
    let context = failing["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(context.contains("exited 1"), "{context}");
    assert!(context.contains("core.hooksPath unset"), "{context}");
    assert!(context.contains("setup-workspace.py"), "{context}");
    // The check is shown to the operator as well.
    let message = failing["systemMessage"].as_str().unwrap();
    assert!(message.starts_with("LEGION:ACTIVE"), "{message}");
    assert!(message.contains("Workspace gate hook"), "{message}");

    fs::write(
        workspace.join("tools/setup-workspace.py"),
        "import sys\nassert sys.argv[1:] == ['--check']\nprint('hooks ok')\n",
    )
    .unwrap();
    let passing = session_start(&workspace);
    let context = passing["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(context.contains("exited 0"), "{context}");
    assert!(context.contains("hooks ok"), "{context}");
}

#[test]
fn session_start_outside_a_workspace_adds_nothing_and_states_the_gate_contract() {
    let scratch = Scratch::new("session-bare");
    let result = session_start(scratch.path());
    let context = result["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(!context.contains("Workspace gate hook"), "{context}");
    assert!(context.contains("right-release check"), "{context}");
    assert_eq!(result["systemMessage"], "LEGION:ACTIVE");
}

#[test]
fn the_session_contract_and_the_package_rules_state_the_same_gate() {
    let agents = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../AGENTS.md"));
    let mirror = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/agent-rules.md"
    ));
    let scratch = Scratch::new("session-keywords");
    let result = session_start(scratch.path());
    let context = result["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    for keyword in ["right-release check", "CI run URL", "receipt"] {
        assert!(context.contains(keyword), "session context lacks {keyword}");
        assert!(agents.contains(keyword), "AGENTS.md lacks {keyword}");
        assert!(
            mirror.contains(keyword),
            "docs/agent-rules.md lacks {keyword}"
        );
    }
}
