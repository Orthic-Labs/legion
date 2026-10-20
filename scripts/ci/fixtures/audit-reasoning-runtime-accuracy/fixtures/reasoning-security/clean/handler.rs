fn run(name: &str) {
    if name.contains("..") || name.contains('/') { return; }
    let path = format!("/srv/data/{name}");
    std::process::Command::new("cat").arg("--").arg(path).status().unwrap();
}
