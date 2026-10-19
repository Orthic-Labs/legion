//! Privileged native proof runs only on disposable macOS GitHub runners.
//! Reviewer fixtures are pinned subprocesses; no provider credentials or models run.
#[cfg(target_os = "macos")]
mod macos {
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Output, Stdio},
    };

    fn successful(mut command: Command) -> Output {
        let output = command.output().expect("spawn fixture command");
        assert!(output.status.success(), "{command:?}: {output:?}");
        output
    }

    fn git(root: &Path, args: &[&str]) -> String {
        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .current_dir(root)
            .args(args);
        String::from_utf8(successful(command).stdout).unwrap()
    }

    fn sudo(args: &[&str]) {
        let mut command = Command::new("/usr/bin/sudo");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["-n", "--"])
            .args(args);
        successful(command);
    }

    fn cli(route: &str, request: &Value) -> Output {
        let mut child = Command::new("/usr/bin/sudo")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-n",
                "--",
                env!("CARGO_BIN_EXE_legion"),
                "--json",
                "authority",
                "freeze",
                route,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn native privileged broker");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(request).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn ok(route: &str, request: &Value) -> Value {
        let output = cli(route, request);
        assert!(output.status.success(), "{request}: {output:?}");
        serde_json::from_slice(&output.stdout).expect("native CLI JSON")
    }

    fn denied(route: &str, request: &Value, reason: &str) {
        let output = cli(route, request);
        assert!(
            !output.status.success(),
            "unexpected authority: {request}: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(reason),
            "{output:?}"
        );
    }

    fn commit(root: &Path, contents: &str) -> String {
        fs::write(root.join("frozen.txt"), contents).unwrap();
        git(root, &["add", "frozen.txt"]);
        git(
            root,
            &[
                "-c",
                "user.name=Freeze CI",
                "-c",
                "user.email=freeze@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "fixture",
            ],
        );
        git(root, &["rev-parse", "HEAD"]).trim().into()
    }

    fn install_reviewer(base: &Path, protected: &Path, trace: &Path) -> (PathBuf, String) {
        // All interpolated path characters are fixed literals or verified digits.
        let script = format!(
            r#"#!/bin/sh
set -eu
model=
while [ "$#" -gt 0 ]; do
  case "$1" in --model|-m) model=$2; shift 2;; *) shift;; esac
done
/bin/cat >/dev/null
printf '%s\n' "$model" >> '{}'
case "$model" in
  fixture-sage) decision=necessary;;
  claude-fable-5-1) decision=agree;;
  gpt-6-astra)
    printf '%s\n' 'OpenAI Codex vfixture' '--------' 'model: gpt-6-astra' 'provider: openai' 'sandbox: read-only' 'session id: fixture-astra' '--------' >&2
    printf '%s\n' '{{"decision":"agree","reason":"fixture"}}'
    exit 0;;
  *) exit 7;;
esac
printf '{{"type":"result","is_error":false,"session_id":"session-%s","modelUsage":{{"%s":{{}}}},"structured_output":{{"decision":"%s","reason":"fixture"}}}}\n' "$model" "$model" "$decision"
"#,
            trace.display()
        );
        let source = base.join("reviewer.sh");
        fs::write(&source, script.as_bytes()).unwrap();
        sudo(&["/bin/mkdir", "-p", protected.to_str().unwrap()]);
        sudo(&["/bin/chmod", "755", protected.to_str().unwrap()]);
        let installed = protected.join("reviewer");
        sudo(&[
            "/bin/cp",
            source.to_str().unwrap(),
            installed.to_str().unwrap(),
        ]);
        sudo(&["/bin/chmod", "755", installed.to_str().unwrap()]);
        assert_eq!(installed.canonicalize().unwrap(), installed);
        (
            installed,
            format!("sha256:{}", hex::encode(Sha256::digest(script.as_bytes()))),
        )
    }

    #[test]
    fn protected_broker_binds_reviews_to_exact_git_objects_and_revokes_monotonically() {
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
            eprintln!("NOT RUN native privileged proof: requires disposable macOS GitHub Actions runner; no local sudo invoked");
            return;
        }
        let run = std::env::var("GITHUB_RUN_ID").expect("GitHub run identity");
        assert!(!run.is_empty() && run.len() <= 20 && run.bytes().all(|b| b.is_ascii_digit()));
        let id = format!("freeze-ci-{run}-{}", std::process::id());
        let base = PathBuf::from("/private/tmp").join(format!("legion-{id}"));
        fs::create_dir(&base).unwrap();
        assert_eq!(base.canonicalize().unwrap(), base);
        let root = base.join("repo");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "--initial-branch=main"]);
        let baseline = commit(&root, "threshold=1\n");
        let remote = base.join("remote.git");
        git(&base, &["init", "--bare", remote.to_str().unwrap()]);
        let scratch = base.join("scratch");
        fs::create_dir(&scratch).unwrap();
        let trace = base.join("review-calls");
        fs::write(&trace, "").unwrap();
        let protected = PathBuf::from("/Library/Application Support/Orthic Labs/Legion")
            .join(format!("authority-ci-fixture-{id}"));
        let (executable, digest) = install_reviewer(&base, &protected, &trace);
        let delivery_root = protected.join("delivery");
        let push_hooks = protected.join("hooks");
        for path in [&delivery_root, &push_hooks] {
            sudo(&["/bin/mkdir", path.to_str().unwrap()]);
            sudo(&["/bin/chmod", "755", path.to_str().unwrap()]);
        }
        let hook_trace = base.join("push-hook-calls");
        fs::write(&hook_trace, "").unwrap();
        let hook_source = base.join("pre-push");
        fs::write(
            &hook_source,
            format!(
                "#!/bin/sh\nset -eu\n/bin/cat >/dev/null\nprintf 'hook\\n' >> '{}'\n",
                hook_trace.display()
            ),
        )
        .unwrap();
        let hook = push_hooks.join("pre-push");
        sudo(&[
            "/bin/cp",
            hook_source.to_str().unwrap(),
            hook.to_str().unwrap(),
        ]);
        sudo(&["/bin/chmod", "755", hook.to_str().unwrap()]);
        let mut identity = Command::new("/usr/bin/id");
        identity.arg("-u");
        let uid = String::from_utf8(successful(identity).stdout)
            .unwrap()
            .trim()
            .to_owned();
        assert_ne!(uid, "0", "runner must exercise privilege drop");
        let home = PathBuf::from(std::env::var_os("HOME").expect("runner HOME"))
            .canonicalize()
            .unwrap();
        let reviewer = |provider: &str, model: &str| {
            json!({
                "provider":provider,"executable":executable,"executable_sha256":digest,
                "model":model,"run_as_user":uid,"home":home,"timeout_seconds":15
            })
        };
        let enrollment = json!({"schema":1,"id":id,"repository":"fixture-repository",
            "root":root,"baseline_source":baseline,"selectors":[{"kind":"path","path":"frozen.txt"}],
            "remote_url":remote,"remote_ref":"refs/heads/main","scratch_root":scratch,
            "delivery_root":delivery_root,"push_hooks":push_hooks,
            "allowed_operations":["Push"],"max_review_launches":3,
            "sage":reviewer("claude","fixture-sage"),
            "fable":reviewer("claude","claude-fable-5-1"),"astra":reviewer("codex","gpt-6-astra")});
        assert_eq!(ok("admin-enroll", &enrollment)["status"], "enrolled");
        let status_request = json!({"op":"status","id":id});
        assert_eq!(ok("broker", &status_request)["reservedReviewLaunches"], 0);
        denied(
            "broker",
            &json!({"op":"approve","id":id,"decision":"agree"}),
            "unknown variant",
        );

        fs::write(root.join("frozen.txt"), "threshold=2\n").unwrap();
        let patch = git(&root, &["diff", "--binary", "--", "frozen.txt"]);
        fs::write(root.join("frozen.txt"), "threshold=1\n").unwrap();
        let index = fs::read(root.join(".git/index")).unwrap();
        let prepared = ok(
            "broker",
            &json!({"op":"prepare","id":id,"base_source":baseline,
            "patch":patch,"missed_review_reason":"Fixture threshold needs amendment"}),
        );
        assert_eq!(prepared["status"], "prepared");
        let candidate = prepared["candidate"].as_str().unwrap();
        assert_eq!(
            fs::read_to_string(root.join("frozen.txt")).unwrap(),
            "threshold=1\n"
        );
        assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), baseline);
        assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
        assert!(git(&root, &["status", "--porcelain"]).is_empty());
        assert!(fs::read_to_string(&trace).unwrap().is_empty());

        let approved_source = commit(&root, "threshold=2\n");
        let check = |source: &str, candidate: Option<&str>| {
            json!({"op":"check","id":id,
            "source":source,"candidate":candidate,"operation":"Push"})
        };
        denied(
            "broker",
            &check(&approved_source, Some(candidate)),
            "denied:",
        );
        denied("broker", &check(&approved_source, None), "denied:");
        assert_eq!(
            ok(
                "broker",
                &json!({"op":"review","id":id,"candidate":candidate})
            )["status"],
            "approved"
        );
        let mut calls: Vec<_> = fs::read_to_string(&trace)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        calls.sort();
        assert_eq!(calls, ["claude-fable-5-1", "fixture-sage", "gpt-6-astra"]);
        assert_eq!(
            ok("broker", &check(&approved_source, Some(candidate)))["status"],
            "allowed"
        );
        denied("broker", &check(&approved_source, None), "denied:");
        let unreviewed_source = commit(&root, "threshold=3\n");
        denied(
            "broker",
            &check(&unreviewed_source, Some(candidate)),
            "denied:",
        );

        let decoy = base.join("redirected.git");
        git(&base, &["init", "--bare", decoy.to_str().unwrap()]);
        git(
            &root,
            &[
                "config",
                &format!("url.{}.insteadOf", decoy.display()),
                remote.to_str().unwrap(),
            ],
        );
        git(&root, &["config", "push.followTags", "true"]);
        git(
            &root,
            &[
                "-c",
                "user.name=Freeze CI",
                "-c",
                "user.email=freeze@example.invalid",
                "-c",
                "tag.gpgsign=false",
                "tag",
                "-a",
                "unintended-tag",
                "-m",
                "must not escape",
                &approved_source,
            ],
        );
        git(&root, &["replace", &approved_source, &unreviewed_source]);
        let attacker_hooks = base.join("attacker-hooks");
        fs::create_dir(&attacker_hooks).unwrap();
        fs::write(attacker_hooks.join("pre-push"), "#!/bin/sh\nexit 99\n").unwrap();
        fs::set_permissions(
            attacker_hooks.join("pre-push"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        git(
            &root,
            &["config", "core.hooksPath", attacker_hooks.to_str().unwrap()],
        );
        assert_eq!(
            ok("broker", &check(&approved_source, Some(candidate)))["status"],
            "allowed"
        );

        // HEAD now differs: managed delivery must use approved immutable source.
        let pushed = ok(
            "broker",
            &json!({"op":"push","id":id,"source":approved_source,"candidate":candidate}),
        );
        assert_eq!(pushed["status"], "pushed");
        assert_eq!(pushed["source"], approved_source);
        assert_eq!(
            git(&remote, &["rev-parse", "refs/heads/main"]).trim(),
            approved_source
        );
        assert_eq!(
            git(&remote, &["show", "refs/heads/main:frozen.txt"]),
            "threshold=2\n"
        );
        assert_eq!(
            git(&remote, &["for-each-ref", "--format=%(refname)"]),
            "refs/heads/main\n"
        );
        assert!(git(&decoy, &["for-each-ref"]).is_empty());
        assert_eq!(fs::read_to_string(&hook_trace).unwrap(), "hook\n");
        assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), unreviewed_source);
        let before = ok("broker", &status_request);
        assert_eq!(before["reservedReviewLaunches"], 3);
        assert_eq!(before["pendingPush"], Value::Null);
        assert_eq!(
            ok("broker", &check(&approved_source, None))["status"],
            "allowed"
        );
        assert_eq!(
            ok("broker", &status_request)["reservedReviewLaunches"],
            before["reservedReviewLaunches"]
        );
        assert_eq!(fs::read_to_string(&trace).unwrap().lines().count(), 3);

        let revoked = ok("broker", &json!({"op":"revoke","id":id}));
        assert!(revoked["revision"].as_u64().unwrap() > pushed["revision"].as_u64().unwrap());
        denied(
            "broker",
            &check(&approved_source, Some(candidate)),
            "denied:",
        );
        denied("broker", &check(&approved_source, None), "denied:");
        let revoked_again = ok("broker", &json!({"op":"revoke","id":id}));
        assert!(
            revoked_again["revision"].as_u64().unwrap() > revoked["revision"].as_u64().unwrap()
        );
        denied("admin-enroll", &enrollment, "File exists");
        let final_state = ok("broker", &status_request);
        assert_eq!(final_state["revoked"], true);
        assert_eq!(final_state["revision"], revoked_again["revision"]);
        assert_eq!(final_state["reservedReviewLaunches"], 3);
        assert_eq!(fs::read_to_string(&trace).unwrap().lines().count(), 3);
        eprintln!("native privileged proof completed for {id}");
        // Root authority tombstone remains intact for this ephemeral runner's lifetime.
    }
}
