fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("geiger-project-execution-marker"), b"LEGION_GEIGER_PROJECT_CODE_EXECUTED").unwrap();
}
