//! Port of `qa.mjs`'s `findBrowser()` and `defaultStartCommand()` (lines 254-298).

/// Abstracts `existsSync` and `process.env` so browser discovery is testable without touching
/// the real filesystem or environment.
pub trait FsProbe {
    fn exists(&self, path: &str) -> bool;
    fn env(&self, name: &str) -> Option<String>;
}

/// `process.platform === "win32"` candidate list vs the POSIX list (qa.mjs lines 266-285).
pub fn candidate_browsers(platform_is_windows: bool, home: &str, program_files: &str, program_files_x86: &str) -> Vec<String> {
    if platform_is_windows {
        vec![
            format!("{program_files}\\Google\\Chrome\\Application\\chrome.exe"),
            format!("{program_files_x86}\\Google\\Chrome\\Application\\chrome.exe"),
            format!("{program_files}\\Microsoft\\Edge\\Application\\msedge.exe"),
            format!("{program_files_x86}\\Microsoft\\Edge\\Application\\msedge.exe"),
        ]
    } else {
        vec![
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string(),
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".to_string(),
            "/Applications/Chromium.app/Contents/MacOS/Chromium".to_string(),
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser".to_string(),
            format!("{home}/.local/chrome-for-testing/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"),
            format!("{home}/.local/chrome-for-testing/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"),
            "/usr/bin/google-chrome".to_string(),
            "/usr/bin/chromium".to_string(),
            "/usr/bin/chromium-browser".to_string(),
            "/usr/bin/microsoft-edge".to_string(),
        ]
    }
}

/// Port of `findBrowser()`. `CHROME_PATH`/`QA_BROWSER` env override wins and must exist or this
/// errors (qa.mjs lines 258-264); otherwise the first existing platform candidate wins.
pub fn find_browser(fs: &dyn FsProbe, platform_is_windows: bool) -> Result<String, String> {
    if let Some(over) = fs.env("CHROME_PATH").or_else(|| fs.env("QA_BROWSER")) {
        if !over.is_empty() {
            if !fs.exists(&over) {
                return Err(format!("CHROME_PATH/QA_BROWSER set but not found: {over}"));
            }
            return Ok(over);
        }
    }
    let home = fs.env("HOME").or_else(|| fs.env("USERPROFILE")).unwrap_or_default();
    let program_files = fs.env("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".to_string());
    let program_files_x86 = fs.env("ProgramFiles(x86)").unwrap_or_else(|| "C:\\Program Files (x86)".to_string());
    let candidates = candidate_browsers(platform_is_windows, &home, &program_files, &program_files_x86);
    candidates
        .into_iter()
        .find(|p| fs.exists(p))
        .ok_or_else(|| "No Chrome/Edge executable found.".to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Launch {
    pub command: String,
    pub args: Vec<String>,
}

/// Port of `defaultStartCommand(port)` (qa.mjs lines 291-298): launches the repo's local Vite
/// via `node_modules/vite/bin/vite.js`, erroring if it is missing.
pub fn default_start_command(node_exec_path: &str, root: &str, port: u32, vite_exists: bool) -> Result<Launch, String> {
    if !vite_exists {
        return Err("No --start command supplied and node_modules/vite/bin/vite.js was not found.".to_string());
    }
    let vite = format!("{root}/node_modules/vite/bin/vite.js");
    Ok(Launch {
        command: node_exec_path.to_string(),
        args: vec![vite, "--host".to_string(), "127.0.0.1".to_string(), "--port".to_string(), port.to_string(), "--strictPort".to_string()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeFs {
        existing: Vec<String>,
        env: HashMap<String, String>,
    }
    impl FsProbe for FakeFs {
        fn exists(&self, path: &str) -> bool {
            self.existing.iter().any(|p| p == path)
        }
        fn env(&self, name: &str) -> Option<String> {
            self.env.get(name).cloned()
        }
    }

    #[test]
    fn override_env_wins_when_present() {
        let fs = FakeFs { existing: vec!["/opt/chrome".into()], env: HashMap::from([("CHROME_PATH".into(), "/opt/chrome".into())]) };
        assert_eq!(find_browser(&fs, false).unwrap(), "/opt/chrome");
    }

    #[test]
    fn override_env_missing_path_errors() {
        let fs = FakeFs { existing: vec![], env: HashMap::from([("QA_BROWSER".into(), "/nope".into())]) };
        let e = find_browser(&fs, false).unwrap_err();
        assert_eq!(e, "CHROME_PATH/QA_BROWSER set but not found: /nope");
    }

    #[test]
    fn first_existing_posix_candidate_wins() {
        let fs = FakeFs {
            existing: vec!["/usr/bin/chromium".into()],
            env: HashMap::new(),
        };
        assert_eq!(find_browser(&fs, false).unwrap(), "/usr/bin/chromium");
    }

    #[test]
    fn none_found_errors() {
        let fs = FakeFs { existing: vec![], env: HashMap::new() };
        assert_eq!(find_browser(&fs, false).unwrap_err(), "No Chrome/Edge executable found.");
    }

    #[test]
    fn windows_candidates_use_program_files_env() {
        let list = candidate_browsers(true, "", "C:\\PF", "C:\\PF86");
        assert!(list.contains(&"C:\\PF\\Google\\Chrome\\Application\\chrome.exe".to_string()));
        assert!(list.contains(&"C:\\PF86\\Microsoft\\Edge\\Application\\msedge.exe".to_string()));
    }

    #[test]
    fn default_start_command_errors_when_vite_missing() {
        let e = default_start_command("/usr/bin/node", "/repo", 1422, false).unwrap_err();
        assert_eq!(e, "No --start command supplied and node_modules/vite/bin/vite.js was not found.");
    }

    #[test]
    fn default_start_command_builds_argv() {
        let l = default_start_command("/usr/bin/node", "/repo", 1422, true).unwrap();
        assert_eq!(l.command, "/usr/bin/node");
        assert_eq!(
            l.args,
            vec!["/repo/node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", "1422", "--strictPort"]
        );
    }
}
