//! Port of `qa.mjs`'s `loadSession`/`saveSession` file I/O halves (lines 125-147): reading/
//! writing the `--load-session`/`--save-session` JSON file. The CDP-side halves (setting cookies,
//! injecting the localStorage bootstrap script, reading cookies/localStorage back) are
//! `session_client::BrowserSession::load_session`/`save_session`.

use headless_chrome::protocol::cdp::Network::CookieParam;
use serde_json::{Map, Value};

use super::session_client::{BrowserSession, SessionData};

/// Abstracts `readFileSync`/`writeFileSync`/`mkdirSync(dirname(...))` for the session file.
pub trait SessionFile {
    fn read(&self, path: &str) -> Result<String, String>;
    fn write(&mut self, path: &str, contents: &str) -> Result<(), String>;
}

/// Port of `loadSession`'s file read (qa.mjs lines 126-128): `JSON.parse(readFileSync(...))`,
/// erroring as `--load-session: cannot read <file>: <message>` on any failure.
pub fn read_session_file(fs: &dyn SessionFile, file: &str) -> Result<SessionData, String> {
    let raw = fs
        .read(file)
        .map_err(|e| format!("--load-session: cannot read {file}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("--load-session: cannot read {file}: {e}"))
}

/// Port of `saveSession`'s file write (qa.mjs lines 138-146): `JSON.stringify(data, null, 2)`
/// (2-space indent, matching Node's default) to `abs(file)`, after `ensureParent`.
pub fn write_session_file(
    fs: &mut dyn SessionFile,
    file: &str,
    data: &SessionData,
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs.write(file, &json)
}

/// Maps the cookie objects of a session file onto CDP `Network.setCookies` parameters (qa.mjs
/// line 130 sends `data.cookies` as-is). Returns the parameters plus the number of entries that
/// could not be applied: anything that is not an object, or lacks a string `name` or `value`.
/// Unknown keys are ignored, and a missing or unparseable optional field becomes `None`. A
/// negative `expires` (Chrome's session-cookie marker) becomes `None`. A non-array `cookies`
/// value applies nothing and is not counted, as qa.mjs's `Array.isArray` check ignored it.
pub fn cookie_params(cookies: &Value) -> (Vec<CookieParam>, usize) {
    let Some(items) = cookies.as_array() else {
        return (Vec::new(), 0);
    };
    let mut params = Vec::with_capacity(items.len());
    let mut skipped = 0usize;
    for item in items {
        let Some(obj) = item.as_object() else {
            skipped += 1;
            continue;
        };
        let name = obj.get("name").and_then(Value::as_str);
        let value = obj.get("value").and_then(Value::as_str);
        let (Some(name), Some(value)) = (name, value) else {
            skipped += 1;
            continue;
        };
        params.push(CookieParam {
            name: name.to_string(),
            value: value.to_string(),
            url: string_field(obj, "url"),
            domain: string_field(obj, "domain"),
            path: string_field(obj, "path"),
            secure: bool_field(obj, "secure"),
            http_only: bool_field(obj, "httpOnly"),
            same_site: enum_field(obj, "sameSite"),
            expires: obj
                .get("expires")
                .and_then(Value::as_f64)
                .filter(|e| *e >= 0.0),
            priority: enum_field(obj, "priority"),
            same_party: bool_field(obj, "sameParty"),
            source_scheme: enum_field(obj, "sourceScheme"),
            source_port: obj
                .get("sourcePort")
                .and_then(Value::as_u64)
                .and_then(|p| u32::try_from(p).ok()),
            partition_key: enum_field(obj, "partitionKey"),
        });
    }
    (params, skipped)
}

fn string_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(Value::as_str).map(str::to_string)
}

fn bool_field(obj: &Map<String, Value>, key: &str) -> Option<bool> {
    obj.get(key).and_then(Value::as_bool)
}

/// Deserialises a CDP enum field the way the saved `Network.Cookie` JSON spells it. A value that
/// does not match a known variant becomes `None`, so it is treated as absent rather than failing
/// the whole cookie.
fn enum_field<T: serde::de::DeserializeOwned>(obj: &Map<String, Value>, key: &str) -> Option<T> {
    obj.get(key)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// Port of `saveSession`'s capture-and-write (qa.mjs lines 138-146) through the session trait.
/// `ChromeSession::save_session` returns an error when `Network.getCookies` fails, so a file
/// written from a successful call records `"cookiesCaptured": true`.
pub fn save_session_to_file(
    session: &mut dyn BrowserSession,
    fs: &mut dyn SessionFile,
    file: &str,
) -> Result<(), String> {
    let data = session.save_session()?;
    write_session_file_with_capture(fs, file, &data, true)
}

/// Like [`write_session_file`], but also records whether the cookies in `data` were really
/// captured from the browser, as a top-level `"cookiesCaptured"` flag beside `cookies`. A file
/// written without a real capture must say `false`, so an empty `cookies` array is never
/// presented as the truth.
pub fn write_session_file_with_capture(
    fs: &mut dyn SessionFile,
    file: &str,
    data: &SessionData,
    cookies_captured: bool,
) -> Result<(), String> {
    let mut value = serde_json::to_value(data).map_err(|e| e.to_string())?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "cookiesCaptured".to_string(),
            serde_json::Value::Bool(cookies_captured),
        );
    }
    let json = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
    fs.write(file, &json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    #[test]
    fn write_session_file_with_capture_marks_cookies_not_captured() {
        let mut fs = FakeFs {
            files: HashMap::new(),
            fail_read: false,
        };
        let data = SessionData {
            cookies: json!([]),
            local_storage: json!({"theme": "dark"}),
        };
        write_session_file_with_capture(&mut fs, "out.json", &data, false).unwrap();
        let raw = fs.files.get("out.json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed["cookiesCaptured"], json!(false));
        assert_eq!(parsed["cookies"], json!([]));
        // The extra flag does not break reading the file back.
        let back = read_session_file(&fs, "out.json").unwrap();
        assert_eq!(back, data);
    }

    struct FakeFs {
        files: HashMap<String, String>,
        fail_read: bool,
    }
    impl SessionFile for FakeFs {
        fn read(&self, path: &str) -> Result<String, String> {
            if self.fail_read {
                return Err("ENOENT".to_string());
            }
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| "ENOENT".to_string())
        }
        fn write(&mut self, path: &str, contents: &str) -> Result<(), String> {
            self.files.insert(path.to_string(), contents.to_string());
            Ok(())
        }
    }

    #[test]
    fn read_session_file_parses_cookies_and_local_storage() {
        let mut files = HashMap::new();
        files.insert(
            "s.json".to_string(),
            r#"{"cookies":[{"name":"a"}],"localStorage":{"k":"v"}}"#.to_string(),
        );
        let fs = FakeFs {
            files,
            fail_read: false,
        };
        let data = read_session_file(&fs, "s.json").unwrap();
        assert_eq!(data.cookies, json!([{"name": "a"}]));
        assert_eq!(data.local_storage, json!({"k": "v"}));
    }

    #[test]
    fn read_session_file_missing_errors_with_js_prefix() {
        let fs = FakeFs {
            files: HashMap::new(),
            fail_read: true,
        };
        let e = read_session_file(&fs, "missing.json").unwrap_err();
        assert!(e.starts_with("--load-session: cannot read missing.json:"));
    }

    #[test]
    fn write_session_file_round_trips() {
        let mut fs = FakeFs {
            files: HashMap::new(),
            fail_read: false,
        };
        let data = SessionData {
            cookies: json!([]),
            local_storage: json!({}),
        };
        write_session_file(&mut fs, "out.json", &data).unwrap();
        let back = read_session_file(&fs, "out.json").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn cookie_params_maps_a_saved_network_cookie_object() {
        let saved = json!([{
            "name": "sid",
            "value": "abc",
            "domain": ".example.test",
            "path": "/",
            "expires": 1900000000.5,
            "size": 6,
            "httpOnly": true,
            "secure": true,
            "session": false,
            "sameSite": "Lax",
            "priority": "Medium",
            "sameParty": false,
            "sourceScheme": "Secure",
            "sourcePort": 443,
            "partitionKey": null
        }]);
        let (params, skipped) = cookie_params(&saved);
        assert_eq!(skipped, 0);
        assert_eq!(params.len(), 1);
        let p = &params[0];
        assert_eq!(p.name, "sid");
        assert_eq!(p.value, "abc");
        assert_eq!(p.domain.as_deref(), Some(".example.test"));
        assert_eq!(p.path.as_deref(), Some("/"));
        assert_eq!(p.expires, Some(1900000000.5));
        assert_eq!(p.http_only, Some(true));
        assert_eq!(p.secure, Some(true));
        assert_eq!(p.same_party, Some(false));
        assert_eq!(p.source_port, Some(443));
        assert!(p.same_site.is_some());
        assert!(p.priority.is_some());
        assert!(p.source_scheme.is_some());
        assert!(p.partition_key.is_none());
        assert!(p.url.is_none());
    }

    #[test]
    fn cookie_params_skips_and_counts_entries_without_name_or_value() {
        let saved = json!([
            {"name": "ok", "value": "1"},
            {"value": "no-name"},
            {"name": "no-value"},
            {"name": 7, "value": "wrong-type"},
            "not-an-object",
            {"name": "also-ok", "value": ""}
        ]);
        let (params, skipped) = cookie_params(&saved);
        assert_eq!(skipped, 4);
        let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["ok", "also-ok"]);
    }

    #[test]
    fn cookie_params_negative_expires_and_unknown_enum_become_none() {
        let saved = json!([{
            "name": "s",
            "value": "v",
            "expires": -1,
            "sameSite": "NotAVariant",
            "sourcePort": -5
        }]);
        let (params, skipped) = cookie_params(&saved);
        assert_eq!(skipped, 0);
        assert_eq!(params[0].expires, None);
        assert!(params[0].same_site.is_none());
        assert_eq!(params[0].source_port, None);
    }

    #[test]
    fn cookie_params_non_array_applies_nothing_and_counts_nothing() {
        assert_eq!(cookie_params(&json!({"name": "a"})).0.len(), 0);
        assert_eq!(cookie_params(&json!({"name": "a"})).1, 0);
        assert_eq!(cookie_params(&Value::Null).1, 0);
        assert_eq!(cookie_params(&json!([])).1, 0);
    }

    #[test]
    fn save_session_to_file_writes_captured_cookies_and_flag_true() {
        use crate::wf_port::r54::session_client::{Conditions, ElementPoint};

        struct CapturingSession;
        impl BrowserSession for CapturingSession {
            fn wait(&mut self, _ms: u64) {}
            fn wait_for_eval(&mut self, _e: &str, _t: u64) -> Result<Value, String> {
                Ok(json!({"ok": true}))
            }
            fn eval(&mut self, _e: &str) -> Result<Value, String> {
                Ok(json!(null))
            }
            fn element_point(&mut self, _s: &str) -> Result<ElementPoint, String> {
                Err("unused".into())
            }
            fn click(&mut self, _x: f64, _y: f64) -> Result<(), String> {
                Ok(())
            }
            fn mouse_move(&mut self, _x: f64, _y: f64) -> Result<(), String> {
                Ok(())
            }
            fn insert_text(&mut self, _t: &str) -> Result<(), String> {
                Ok(())
            }
            fn press_key(&mut self, _k: &str) -> Result<(), String> {
                Ok(())
            }
            fn mouse_wheel(&mut self, _x: f64, _y: f64, _dx: f64, _dy: f64) -> Result<(), String> {
                Ok(())
            }
            fn capture(&mut self, out: &str) -> Result<String, String> {
                Ok(out.to_string())
            }
            fn apply_conditions(&mut self, _c: &Conditions) -> Result<(), String> {
                Ok(())
            }
            fn navigate(&mut self, _u: &str) -> Result<(), String> {
                Ok(())
            }
            fn set_cookies(
                &mut self,
                _c: &[headless_chrome::protocol::cdp::Network::CookieParam],
            ) -> Result<(), String> {
                Ok(())
            }
            fn load_session(&mut self, _d: &SessionData) -> Result<(), String> {
                Ok(())
            }
            fn save_session(&mut self) -> Result<SessionData, String> {
                Ok(SessionData {
                    cookies: json!([{"name": "sid", "value": "abc"}]),
                    local_storage: json!({"theme": "dark"}),
                })
            }
        }

        let mut fs = FakeFs {
            files: HashMap::new(),
            fail_read: false,
        };
        save_session_to_file(&mut CapturingSession, &mut fs, "out.json").unwrap();
        let parsed: Value = serde_json::from_str(fs.files.get("out.json").unwrap()).unwrap();
        assert_eq!(parsed["cookiesCaptured"], json!(true));
        assert_eq!(parsed["cookies"], json!([{"name": "sid", "value": "abc"}]));
        assert_eq!(parsed["localStorage"], json!({"theme": "dark"}));
    }
}
