use std::path::PathBuf;
#[cfg(target_os = "windows")]
pub fn data_dir() -> PathBuf { PathBuf::from("/home/app/.local/share/app") }
#[cfg(target_os = "macos")]
pub fn data_dir() -> PathBuf { PathBuf::from("/home/app/.local/share/app") }
#[cfg(target_os = "linux")]
pub fn data_dir() -> PathBuf { PathBuf::from("/home/app/.local/share/app") }
