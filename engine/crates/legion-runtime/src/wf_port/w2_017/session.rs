//! Port of `live-browser-session.js`'s `createLiveBrowserSessionState`.
//!
//! The JS version is driven by `localStorage` (or an injected `storage`) and
//! runs inside the live page. The read/write/JSON/key-derivation logic has
//! no DOM dependency, so it is ported here in full against a [`KvStore`]
//! trait that mirrors `Storage.getItem/setItem/removeItem` (including "swallow
//! any error, return null/no-op" semantics). An in-memory store is provided
//! for tests; the browser build continues to use real `localStorage` through
//! the JS file.

use serde_json::{Map, Value};

/// Mirrors the subset of the DOM `Storage` interface
/// `createLiveBrowserSessionState` uses: `getItem`, `setItem`, `removeItem`.
/// Every JS call site wraps these in `try { ... } catch { ... }`; callers of
/// this trait are expected to return `Err` only for genuinely storage-level
/// failures (quota exceeded, unavailable storage), which [`LiveBrowserSessionState`]
/// swallows exactly like the JS `safeRead`/`safeWrite`/`safeRemove` helpers.
pub trait KvStore {
    fn get_item(&self, key: &str) -> Result<Option<String>, ()>;
    fn set_item(&mut self, key: &str, value: &str) -> Result<(), ()>;
    fn remove_item(&mut self, key: &str) -> Result<(), ()>;
}

/// In-memory [`KvStore`] used by tests (and available to any caller that
/// wants `localStorage`-like semantics without a browser).
#[derive(Debug, Default, Clone)]
pub struct MemoryKvStore {
    map: std::collections::HashMap<String, String>,
}

impl MemoryKvStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KvStore for MemoryKvStore {
    fn get_item(&self, key: &str) -> Result<Option<String>, ()> {
        Ok(self.map.get(key).cloned())
    }

    fn set_item(&mut self, key: &str, value: &str) -> Result<(), ()> {
        self.map.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn remove_item(&mut self, key: &str) -> Result<(), ()> {
        self.map.remove(key);
        Ok(())
    }
}

/// Port of `createLiveBrowserSessionState({ prefix, storage, idFactory })`.
///
/// `owner` is generated once at construction, matching the JS `const owner =
/// makeId();` line. The default `idFactory` in JS is
/// `Math.random().toString(16).slice(2, 10)`; callers here supply an
/// `id_factory` closure explicitly (there is no faithful Rust equivalent of
/// `Math.random` and the JS default is itself non-deterministic, so nothing
/// is lost by requiring it).
pub struct LiveBrowserSessionState<S: KvStore> {
    store: S,
    session_key: String,
    handled_key: String,
    scroll_key: String,
    checkpoint_revision: i64,
    owner: String,
}

impl<S: KvStore> LiveBrowserSessionState<S> {
    /// `prefix` must be non-empty, matching JS's `if (!prefix) throw new
    /// Error('prefix required')`.
    pub fn new(prefix: &str, store: S, owner: String) -> Result<Self, &'static str> {
        if prefix.is_empty() {
            return Err("prefix required");
        }
        let session_key = format!("{prefix}-session");
        let handled_key = format!("{session_key}-handled");
        let scroll_key = format!("{session_key}-scroll");
        Ok(Self {
            store,
            session_key,
            handled_key,
            scroll_key,
            checkpoint_revision: 0,
            owner,
        })
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn session_key(&self) -> &str {
        &self.session_key
    }

    pub fn handled_key(&self) -> &str {
        &self.handled_key
    }

    pub fn scroll_key(&self) -> &str {
        &self.scroll_key
    }

    fn safe_read(&self, key: &str) -> Option<String> {
        self.store.get_item(key).unwrap_or(None)
    }

    fn safe_write(&mut self, key: &str, value: &str) {
        let _ = self.store.set_item(key, value);
    }

    fn safe_remove(&mut self, key: &str) {
        let _ = self.store.remove_item(key);
    }

    /// Port of `loadSession()`. Returns `None` on missing key or malformed
    /// JSON, exactly like the JS `try { ... } catch { return null; }`.
    /// A `checkpointRevision` integer field in the stored session bumps the
    /// in-memory counter via `Math.max`, matching JS.
    pub fn load_session(&mut self) -> Option<Value> {
        let raw = self.safe_read(&self.session_key.clone())?;
        let parsed: Value = serde_json::from_str(&raw).ok()?;
        if let Some(rev) = parsed.get("checkpointRevision").and_then(Value::as_i64) {
            self.checkpoint_revision = self.checkpoint_revision.max(rev);
        }
        Some(parsed)
    }

    /// Port of `saveSession(session)`. No-op when `session` has no truthy
    /// `id` field, matching `if (!session || !session.id) return;`.
    pub fn save_session(&mut self, session: &Value) {
        let has_id = session
            .get("id")
            .map(|v| match v {
                Value::Null => false,
                Value::Bool(b) => *b,
                Value::String(s) => !s.is_empty(),
                Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
                _ => true,
            })
            .unwrap_or(false);
        if !has_id {
            return;
        }
        let mut payload = match session.as_object() {
            Some(map) => map.clone(),
            None => Map::new(),
        };
        payload.insert(
            "checkpointRevision".to_string(),
            Value::from(self.checkpoint_revision),
        );
        let serialized = Value::Object(payload).to_string();
        self.safe_write(&self.session_key.clone(), &serialized);
    }

    /// Port of `clearSession()`.
    pub fn clear_session(&mut self) {
        self.safe_remove(&self.session_key.clone());
    }

    /// Port of `nextCheckpointRevision()`: bumps the counter, then re-saves
    /// the existing session (if any) so the new revision is persisted.
    pub fn next_checkpoint_revision(&mut self) -> i64 {
        self.checkpoint_revision += 1;
        if let Some(existing) = self.load_session() {
            let has_id = existing
                .get("id")
                .map(|v| !matches!(v, Value::Null))
                .unwrap_or(false);
            if has_id {
                self.save_session(&existing);
            }
        }
        self.checkpoint_revision
    }

    /// Port of `seedCheckpointRevision(value)`.
    pub fn seed_checkpoint_revision(&mut self, value: Option<i64>) -> i64 {
        if let Some(v) = value {
            self.checkpoint_revision = self.checkpoint_revision.max(v);
        }
        self.checkpoint_revision
    }

    /// Port of `currentCheckpointRevision()`.
    pub fn current_checkpoint_revision(&self) -> i64 {
        self.checkpoint_revision
    }

    /// Port of `markHandled(id)`. No-op for an empty id.
    pub fn mark_handled(&mut self, id: &str) {
        if id.is_empty() {
            return;
        }
        self.safe_write(&self.handled_key.clone(), id);
    }

    /// Port of `isHandled(id)`.
    pub fn is_handled(&self, id: &str) -> bool {
        !id.is_empty() && self.safe_read(&self.handled_key).as_deref() == Some(id)
    }

    /// Port of `clearHandled()`.
    pub fn clear_handled(&mut self) {
        self.safe_remove(&self.handled_key.clone());
    }

    /// Port of `writeScrollY(y)`.
    pub fn write_scroll_y(&mut self, y: f64) {
        self.safe_write(&self.scroll_key.clone(), &y.to_string());
    }

    /// Port of `readScrollY()`. Mirrors `parseFloat` + `isFinite`: returns
    /// `None` for a missing key or a value that does not parse to a finite
    /// float (JS `parseFloat` parses a numeric prefix; this uses the same
    /// leading-numeric-prefix behavior).
    pub fn read_scroll_y(&self) -> Option<f64> {
        let raw = self.safe_read(&self.scroll_key)?;
        let n = parse_float_prefix(&raw)?;
        if n.is_finite() {
            Some(n)
        } else {
            None
        }
    }

    /// Port of `clearScrollY()`.
    pub fn clear_scroll_y(&mut self) {
        self.safe_remove(&self.scroll_key.clone());
    }
}

/// Mirrors JS `parseFloat`'s leading-numeric-prefix parsing (e.g. `"12abc"`
/// -> `12.0`), which `Number`/`str::parse` do not do.
fn parse_float_prefix(raw: &str) -> Option<f64> {
    let trimmed = raw.trim_start();
    let mut end = 0;
    let bytes = trimmed.as_bytes();
    let mut seen_digit = false;
    let mut seen_dot = false;
    let mut seen_exp = false;
    let mut i = 0;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        i += 1;
    }
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() {
            seen_digit = true;
            i += 1;
            end = i;
        } else if c == '.' && !seen_dot && !seen_exp {
            seen_dot = true;
            i += 1;
            if seen_digit {
                end = i;
            }
        } else if (c == 'e' || c == 'E') && seen_digit && !seen_exp {
            // tentatively consume exponent; only commit `end` if a valid
            // exponent digit sequence follows.
            let mut j = i + 1;
            if j < bytes.len() && (bytes[j] == b'+' || bytes[j] == b'-') {
                j += 1;
            }
            let exp_start = j;
            while j < bytes.len() && (bytes[j] as char).is_ascii_digit() {
                j += 1;
            }
            if j > exp_start {
                seen_exp = true;
                i = j;
                end = j;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    if !seen_digit {
        return None;
    }
    trimmed[..end].parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn state() -> LiveBrowserSessionState<MemoryKvStore> {
        LiveBrowserSessionState::new("prefix", MemoryKvStore::new(), "owner1".to_string()).unwrap()
    }

    #[test]
    fn empty_prefix_errors() {
        assert!(LiveBrowserSessionState::new("", MemoryKvStore::new(), "o".into()).is_err());
    }

    #[test]
    fn key_derivation_matches_js() {
        let s = state();
        assert_eq!(s.session_key(), "prefix-session");
        assert_eq!(s.handled_key(), "prefix-session-handled");
        assert_eq!(s.scroll_key(), "prefix-session-scroll");
    }

    #[test]
    fn save_load_roundtrip() {
        let mut s = state();
        s.save_session(&json!({"id": "abc", "phase": "open"}));
        let loaded = s.load_session().unwrap();
        assert_eq!(loaded["id"], "abc");
        assert_eq!(loaded["checkpointRevision"], 0);
    }

    #[test]
    fn save_without_id_is_noop() {
        let mut s = state();
        s.save_session(&json!({"phase": "open"}));
        assert!(s.load_session().is_none());
    }

    #[test]
    fn next_checkpoint_revision_persists_and_bumps() {
        let mut s = state();
        s.save_session(&json!({"id": "abc"}));
        let rev = s.next_checkpoint_revision();
        assert_eq!(rev, 1);
        let loaded = s.load_session().unwrap();
        assert_eq!(loaded["checkpointRevision"], 1);
    }

    #[test]
    fn seed_checkpoint_revision_takes_max() {
        let mut s = state();
        assert_eq!(s.seed_checkpoint_revision(Some(5)), 5);
        assert_eq!(s.seed_checkpoint_revision(Some(2)), 5);
        assert_eq!(s.seed_checkpoint_revision(Some(9)), 9);
    }

    #[test]
    fn handled_roundtrip() {
        let mut s = state();
        assert!(!s.is_handled("x"));
        s.mark_handled("x");
        assert!(s.is_handled("x"));
        assert!(!s.is_handled("y"));
        s.clear_handled();
        assert!(!s.is_handled("x"));
    }

    #[test]
    fn scroll_roundtrip_and_parse_prefix() {
        let mut s = state();
        assert_eq!(s.read_scroll_y(), None);
        s.write_scroll_y(123.5);
        assert_eq!(s.read_scroll_y(), Some(123.5));
        s.clear_scroll_y();
        assert_eq!(s.read_scroll_y(), None);
    }

    #[test]
    fn parse_float_prefix_matches_js_semantics() {
        assert_eq!(parse_float_prefix("12abc"), Some(12.0));
        assert_eq!(parse_float_prefix("  -3.5xyz"), Some(-3.5));
        assert_eq!(parse_float_prefix("abc"), None);
        assert_eq!(parse_float_prefix("1e3"), Some(1000.0));
        assert_eq!(parse_float_prefix(""), None);
    }

    #[test]
    fn clear_session_removes_key() {
        let mut s = state();
        s.save_session(&json!({"id": "abc"}));
        s.clear_session();
        assert!(s.load_session().is_none());
    }
}
