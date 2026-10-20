fn run(name: &str) {
    let command = format!("cat /srv/data/{name}");
    std::process::Command::new("sh").arg("-c").arg(command).status().unwrap();
}
