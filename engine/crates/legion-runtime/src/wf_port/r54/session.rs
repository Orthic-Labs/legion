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
