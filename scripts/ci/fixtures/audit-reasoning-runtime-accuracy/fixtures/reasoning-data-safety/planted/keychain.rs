fn save(path: &str, token: &str) { std::fs::write(path, token).unwrap(); }
