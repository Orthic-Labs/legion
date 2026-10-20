use std::{io, path::PathBuf};
#[cfg(target_os = "windows")]
pub fn data_dir() -> io::Result<PathBuf> { env_dir("LOCALAPPDATA").map(|p| p.join("app")) }
#[cfg(target_os = "macos")]
pub fn data_dir() -> io::Result<PathBuf> { env_dir("HOME").map(|p| p.join("Library/Application Support/app")) }
#[cfg(target_os = "linux")]
pub fn data_dir() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_DATA_HOME").filter(|p| PathBuf::from(p).is_absolute()) { return Ok(PathBuf::from(path).join("app")); }
    env_dir("HOME").map(|p| p.join(".local/share/app"))
}
fn env_dir(name: &str) -> io::Result<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).filter(|p| p.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, name.to_owned()))
}
