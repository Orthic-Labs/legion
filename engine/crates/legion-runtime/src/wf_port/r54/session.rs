//! Port of `qa.mjs`'s `loadSession`/`saveSession` file I/O halves (lines 125-147): reading/
//! writing the `--load-session`/`--save-session` JSON file. The CDP-side halves (setting cookies,
//! injecting the localStorage bootstrap script, reading cookies/localStorage back) are
//! `session_client::BrowserSession::load_session`/`save_session`.

use super::session_client::SessionData;

/// Abstracts `readFileSync`/`writeFileSync`/`mkdirSync(dirname(...))` for the session file.
pub trait SessionFile {
    fn read(&self, path: &str) -> Result<String, String>;
    fn write(&mut self, path: &str, contents: &str) -> Result<(), String>;
}

/// Port of `loadSession`'s file read (qa.mjs lines 126-128): `JSON.parse(readFileSync(...))`,
/// erroring as `--load-session: cannot read <file>: <message>` on any failure.
pub fn read_session_file(fs: &dyn SessionFile, file: &str) -> Result<SessionData, String> {
    let raw = fs.read(file).map_err(|e| format!("--load-session: cannot read {file}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("--load-session: cannot read {file}: {e}"))
}

/// Port of `saveSession`'s file write (qa.mjs lines 138-146): `JSON.stringify(data, null, 2)`
/// (2-space indent, matching Node's default) to `abs(file)`, after `ensureParent`.
pub fn write_session_file(fs: &mut dyn SessionFile, file: &str, data: &SessionData) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs.write(file, &json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    struct FakeFs {
        files: HashMap<String, String>,
        fail_read: bool,
    }
    impl SessionFile for FakeFs {
        fn read(&self, path: &str) -> Result<String, String> {
            if self.fail_read {
                return Err("ENOENT".to_string());
            }
            self.files.get(path).cloned().ok_or_else(|| "ENOENT".to_string())
        }
        fn write(&mut self, path: &str, contents: &str) -> Result<(), String> {
            self.files.insert(path.to_string(), contents.to_string());
            Ok(())
        }
    }

    #[test]
    fn read_session_file_parses_cookies_and_local_storage() {
        let mut files = HashMap::new();
        files.insert("s.json".to_string(), r#"{"cookies":[{"name":"a"}],"localStorage":{"k":"v"}}"#.to_string());
        let fs = FakeFs { files, fail_read: false };
        let data = read_session_file(&fs, "s.json").unwrap();
        assert_eq!(data.cookies, json!([{"name": "a"}]));
        assert_eq!(data.local_storage, json!({"k": "v"}));
    }

    #[test]
    fn read_session_file_missing_errors_with_js_prefix() {
        let fs = FakeFs { files: HashMap::new(), fail_read: true };
        let e = read_session_file(&fs, "missing.json").unwrap_err();
        assert!(e.starts_with("--load-session: cannot read missing.json:"));
    }

    #[test]
    fn write_session_file_round_trips() {
        let mut fs = FakeFs { files: HashMap::new(), fail_read: false };
        let data = SessionData { cookies: json!([]), local_storage: json!({}) };
        write_session_file(&mut fs, "out.json", &data).unwrap();
        let back = read_session_file(&fs, "out.json").unwrap();
        assert_eq!(back, data);
    }
}
