use std::process::Command;

/// `legion languages <root>` scans the given root, not the process cwd.
#[test]
fn languages_scans_the_path_argument_not_the_cwd() {
    let base = std::env::temp_dir().join(format!(
        "legion-languages-root-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let repo = base.join("repo");
    let elsewhere = base.join("elsewhere");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(repo.join("go.mod"), "module example.com/x\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .arg("languages")
        .arg(&repo)
        .current_dir(&elsewhere)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("language.go"), "stdout: {stdout}");

    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .arg("languages")
        .current_dir(&repo)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("language.go"), "stdout: {stdout}");

    let _ = std::fs::remove_dir_all(&base);
}
