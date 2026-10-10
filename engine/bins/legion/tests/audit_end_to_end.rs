//! End-to-end `legion audit` -> `legion verify` over a small real repository,
//! driven through the built binary with an isolated home.

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    repo: PathBuf,
    out: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
            "legion-audit-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&base);
        // Run output and home live beside the repository, never inside it, so
        // the audited tree can be asserted unchanged.
        let fixture = Self {
            repo: base.join("repo"),
            out: base.join("run"),
            home: base.join("home"),
        };
        fs::create_dir_all(fixture.repo.join("src")).unwrap();
        fs::create_dir_all(&fixture.home).unwrap();
        fixture.write(
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        fixture.write("src/lib.rs", "pub mod db;\n\npub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n");
        fixture.write(
            "src/db.rs",
            "// TODO: replace this stub with a real connection pool\npub fn save(path: &str, data: &str) {\n    let _ = std::fs::write(path, data);\n}\n",
        );
        fixture.write("web.ts", "export function greet(name: string): string {\n  return `hello ${name}`;\n}\n");
        fixture.write(
            "README.md",
            "# Fixture\n\nSee `docs/missing-guide.md` for details.\n",
        );
        fixture.git_pass(&["init", "-q"]);
        fixture.git_pass(&["config", "user.email", "e2e@example.invalid"]);
        fixture.git_pass(&["config", "user.name", "e2e"]);
        fixture.git_pass(&["config", "commit.gpgsign", "false"]);
        fixture.git_pass(&["add", "-A"]);
        fixture.git_pass(&["commit", "-q", "-m", "fixture"]);
        fixture
    }

    fn write(&self, relative: &str, text: &str) {
        fs::write(self.repo.join(relative), text).unwrap();
    }

    fn base(&self) -> PathBuf {
        self.repo.parent().unwrap().to_path_buf()
    }

    fn legion(&self, args: &[&str]) -> Output {
        // The provider registry is a repository asset; an isolated home has no
        // installed release to supply it.
        let registry = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/registry/providers.json");
        Command::new(env!("CARGO_BIN_EXE_legion"))
            .current_dir(&self.repo)
            .env("GIT_CEILING_DIRECTORIES", self.base())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env("LEGION_PROVIDER_REGISTRY", registry)
            .env_remove("AUDIT_PLAN_SIGNING_KEY")
            .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
            .args(args)
            .output()
            .unwrap()
    }

    fn git(&self, args: &[&str]) -> Output {
        Command::new("git")
            .current_dir(&self.repo)
            .env("GIT_CEILING_DIRECTORIES", self.base())
            .args(args)
            .output()
            .unwrap()
    }

    fn git_pass(&self, args: &[&str]) {
        let output = self.git(args);
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.base());
    }
}

fn json_of(label: &str, output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{label} stdout is not JSON ({error}): stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn audit_then_verify_an_ordinary_run() {
    let fixture = Fixture::new();
    let repo = fixture.repo.to_str().unwrap();
    let run = fixture.out.to_str().unwrap();

    let audit = fixture.legion(&["audit", repo, "--out", run, "--json"]);
    let code = audit.status.code();
    assert!(
        matches!(code, Some(0) | Some(2)),
        "audit exit {code:?}: stderr={}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let _report = json_of("audit", &audit);

    // b) reasoning lens packets were emitted
    let packets = fs::read_dir(fixture.out.join("lens-packets"))
        .map(|entries| entries.flatten().count())
        .unwrap_or(0);
    assert!(packets >= 1, "no lens packets under {}/lens-packets", run);

    // c) no self-invalidation gaps
    let execution: Value =
        serde_json::from_slice(&fs::read(fixture.out.join("execution.json")).unwrap()).unwrap();
    let gaps: Vec<String> = execution["gaps"]
        .as_array()
        .map(|gaps| gaps.iter().filter_map(|g| g.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let offending: Vec<&String> = gaps
        .iter()
        .filter(|gap| {
            gap.starts_with("invalid-provider-result:") || gap.starts_with("lens-packets-unavailable:")
        })
        .collect();
    assert!(offending.is_empty(), "offending gaps: {offending:#?} (all gaps: {gaps:#?})");

    // d) at least one code.* provider produced a non-failed result with coverage
    let results = execution["results"].as_array().expect("execution results");
    let usable = results.iter().any(|entry| {
        entry["provider"].as_str().is_some_and(|id| id.starts_with("code."))
            && entry["result"]["status"].as_str().is_some_and(|status| status != "failed")
            && !entry["result"]["coverage"].is_null()
    });
    let summary: Vec<String> = results
        .iter()
        .map(|entry| {
            format!(
                "{} status={} coverage={}",
                entry["provider"], entry["result"]["status"], !entry["result"]["coverage"].is_null()
            )
        })
        .collect();
    assert!(usable, "no usable code.* provider result: {summary:#?}");

    // e) scratch must not land in the audited tree
    let status = fixture.git(&["status", "--porcelain"]);
    assert!(status.status.success());
    assert_eq!(
        String::from_utf8_lossy(&status.stdout).trim(),
        "",
        "audit modified the audited repository"
    );

    // f) an ordinary, incomplete-but-intact run verifies with no extra environment
    let verify = fixture.legion(&["verify", run, "--json"]);
    let verified = json_of("verify", &verify);
    assert_eq!(
        verified["valid"],
        Value::Bool(true),
        "verify rejected the run: {verified:#}"
    );
    assert_eq!(
        verified["contentErrors"].as_array().map(Vec::len),
        Some(0),
        "verify content errors: {verified:#}"
    );
}
