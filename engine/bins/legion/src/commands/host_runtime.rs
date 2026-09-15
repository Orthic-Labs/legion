use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const EVENT_FIELDS: &[&str] = &[
    "schemaVersion",
    "kind",
    "eventId",
    "eventSequence",
    "previousDigest",
    "turnCorrelationDigest",
    "stopOrdinal",
    "adapter",
    "eventType",
    "sessionId",
    "runId",
    "taskId",
    "contractId",
    "contractVersion",
    "contractDigest",
    "sourceRevision",
    "observedAuthority",
    "payloadDigest",
    "observedAt",
];
const HEAD_FIELDS: &[&str] = &["kind", "eventSequence", "digest"];

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if argv.first().map(String::as_str) == Some("describe") {
        return run_describe(&argv[1..]);
    }
    let mut values = argv.as_slice();
    if values.first().map(String::as_str) == Some("events") {
        values = &values[1..];
    }
    if values.is_empty() && argv.is_empty() {
        return Err(CommandError::usage(
            "host requires events inspect or describe",
        ));
    }
    if values
        .first()
        .map(String::as_str)
        .is_none_or(|value| value == "--help" || value == "help")
    {
        return Ok(json!({"__raw":"Usage: legion host events inspect [--session <id>]\n"}));
    }
    if values.first().map(String::as_str) != Some("inspect") {
        return Err(CommandError::usage("host events requires inspect"));
    }
    let mut session = None;
    let mut key_dir = None;
    let mut i = 1;
    while i < values.len() {
        match values[i].as_str() {
            "--session" => {
                i += 1;
                let Some(value) = values.get(i) else {
                    return Err(CommandError::usage("host events requires inspect"));
                };
                session = Some(value.clone());
            }
            "--key-dir" => {
                i += 1;
                let Some(value) = values.get(i) else {
                    return Err(CommandError::usage("host events requires inspect"));
                };
                key_dir = Some(value.clone());
            }
            other => {
                return Err(CommandError::usage(format!(
                    "unknown host events option: {other}"
                )))
            }
        }
        i += 1;
    }
    inspect_ledger(session.as_deref(), key_dir.as_deref())
        .map_err(|message| CommandError::internal(format!("ArcaneError: {message}")))
}

fn run_describe(argv: &[String]) -> CommandResult {
    let mut root = PathBuf::from(".");
    let mut descriptor = None;
    let mut json_output = false;
    let mut positional = false;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--descriptor" => {
                i += 1;
                let Some(value) = argv.get(i) else {
                    return Err(CommandError::usage(
                        "host requires events inspect or describe",
                    ));
                };
                descriptor = Some(PathBuf::from(value));
            }
            "--json" => json_output = true,
            "--help" | "help" => {
                return Ok(json!({
                    "__raw": "Usage: legion host describe [<root>] [--descriptor <path>] [--json]\n"
                }));
            }
            value if value.starts_with('-') => {
                return Err(CommandError::usage(format!(
                    "unknown host describe option: {value}"
                )));
            }
            value if !positional => {
                root = PathBuf::from(value);
                positional = true;
            }
            _ => {
                return Err(CommandError::usage(
                    "host requires events inspect or describe",
                ))
            }
        }
        i += 1;
    }
    super::host::run(super::host::HostArgs {
        root,
        descriptor,
        json: json_output,
    })
}

pub fn inspect_ledger(session: Option<&str>, key_dir: Option<&str>) -> Result<Value, String> {
    let key_root = key_dir
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("ARCANE_KEY_DIR").map(PathBuf::from))
        .unwrap_or_else(canonical_key_dir);
    let keys = load_keys(&key_root)?;
    if !keys.values().any(|record| !record.revoked) {
        return Err("no active key available".into());
    }
    let root = Path::new(".audit/arcane/host-events");
    let (allowed, records, code) = verify_ledger(root, &keys);
    let session = session.filter(|value| !value.is_empty());
    let events = if allowed {
        records
            .into_iter()
            .filter(|record| {
                session.is_none() || record.get("sessionId").and_then(Value::as_str) == session
            })
            .map(redact_authentication)
            .collect()
    } else {
        Vec::new()
    };
    Ok(
        json!({"allowed":allowed,"code":if allowed {Value::Null}else{json!(code.unwrap_or("ARC_STORE_CORRUPT"))},"events":events}),
    )
}

fn canonical_key_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".codex")
        .join("arcane-keys")
}

#[derive(Clone)]
struct KeyRecord {
    key: Vec<u8>,
    revoked: bool,
}

fn load_keys(root: &Path) -> Result<BTreeMap<String, KeyRecord>, String> {
    let entries = std::fs::read_dir(root)
        .map_err(|_| format!("host key directory not found: {}", root.display()))?;
    let mut keys = BTreeMap::new();
    for entry in entries {
        let path = entry
            .map_err(|_| "host key directory is unreadable".to_owned())?
            .path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("key") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| "host key id is invalid".to_owned())?
            .to_owned();
        let text = std::fs::read_to_string(&path)
            .map_err(|_| format!("key material unreadable for {id}"))?;
        let bytes =
            decode_hex(text.trim()).ok_or_else(|| format!("key material unreadable for {id}"))?;
        if bytes.is_empty() {
            return Err(format!("key material unreadable for {id}"));
        }
        let mut revoked = false;
        let metadata = root.join(format!("{id}.json"));
        if metadata.is_file() {
            let value: Value = serde_json::from_slice(
                &std::fs::read(&metadata)
                    .map_err(|_| "host key metadata is unreadable".to_owned())?,
            )
            .map_err(|_| "host key metadata is invalid JSON".to_owned())?;
            revoked = value.get("status").and_then(Value::as_str) == Some("revoked");
        }
        keys.insert(
            id,
            KeyRecord {
                key: bytes,
                revoked,
            },
        );
    }
    if keys.is_empty() {
        return Err(format!("no host key material found in {}", root.display()));
    }
    Ok(keys)
}

fn verify_ledger(
    root: &Path,
    keys: &BTreeMap<String, KeyRecord>,
) -> (bool, Vec<Value>, Option<&'static str>) {
    let mut paths = match std::fs::read_dir(root) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| is_event_file(path))
            .collect::<Vec<_>>(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (true, Vec::new(), None)
        }
        Err(_) => return (false, Vec::new(), Some("ARC_STORE_CORRUPT")),
    };
    paths.sort();
    let mut records = Vec::new();
    let mut previous = None;
    for path in paths {
        let value: Value = match serde_json::from_slice(&std::fs::read(&path).unwrap_or_default()) {
            Ok(value) => value,
            Err(_) => return (false, Vec::new(), Some("ARC_STORE_CORRUPT")),
        };
        if verify_record(&value, keys, EVENT_FIELDS).is_err() {
            return (false, Vec::new(), Some("ARC_STORE_CORRUPT"));
        }
        let sequence = value.get("eventSequence").and_then(Value::as_u64);
        let expected_sequence = previous
            .as_ref()
            .and_then(|record: &Value| record.get("eventSequence").and_then(Value::as_u64))
            .unwrap_or(0)
            + 1;
        if sequence != Some(expected_sequence) {
            return (false, Vec::new(), Some("ARC_STORE_CORRUPT"));
        }
        let expected_parent = previous
            .as_ref()
            .map(legion_contracts::canonical_digest)
            .transpose()
            .ok()
            .flatten();
        if value.get("previousDigest").and_then(Value::as_str) != expected_parent.as_deref() {
            return (false, Vec::new(), Some("ARC_STORE_CORRUPT"));
        }
        previous = Some(value.clone());
        records.push(value);
    }
    let head = root.join("head.json");
    if records.is_empty() != !head.is_file() {
        return (false, Vec::new(), Some("ARC_STORE_CORRUPT"));
    }
    if let Some(last) = records.last() {
        let value: Value = match serde_json::from_slice(&std::fs::read(&head).unwrap_or_default()) {
            Ok(value) => value,
            Err(_) => return (false, Vec::new(), Some("ARC_STORE_CORRUPT")),
        };
        if verify_record(&value, keys, HEAD_FIELDS).is_err()
            || value.get("eventSequence") != last.get("eventSequence")
            || value.get("digest").and_then(Value::as_str)
                != legion_contracts::canonical_digest(last).ok().as_deref()
        {
            return (false, Vec::new(), Some("ARC_STORE_CORRUPT"));
        }
    }
    (true, records, None)
}

fn is_event_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.len() == 21
        && name.ends_with(".json")
        && name[..16].bytes().all(|byte| byte.is_ascii_digit())
}

fn verify_record(
    record: &Value,
    keys: &BTreeMap<String, KeyRecord>,
    fields: &[&str],
) -> Result<(), ()> {
    let auth = record
        .get("authentication")
        .and_then(Value::as_object)
        .ok_or(())?;
    if auth.contains_key("signature_or_mac") {
        return Err(());
    }
    if auth.get("alg").and_then(Value::as_str) != Some("HMAC-SHA256") {
        return Err(());
    }
    let key_id = auth.get("keyId").and_then(Value::as_str).ok_or(())?;
    let mac = auth.get("mac").and_then(Value::as_str).ok_or(())?;
    if mac != mac.to_ascii_lowercase() {
        return Err(());
    }
    let bound = auth
        .get("boundFieldsDigest")
        .and_then(Value::as_str)
        .ok_or(())?;
    if bound != legion_contracts::canonical_digest(&fields.to_vec()).map_err(|_| ())? {
        return Err(());
    }
    let key = keys
        .get(key_id)
        .filter(|record| !record.revoked)
        .ok_or(())?;
    let mut subject = Map::new();
    for field in fields {
        subject.insert((*field).into(), record.get(*field).cloned().ok_or(())?);
    }
    let mut message = json!({"alg":"HMAC-SHA256","boundFields":fields,"subject":subject});
    if let Some(domain) = auth.get("macDomain").filter(|value| !value.is_null()) {
        message["macDomain"] = domain.clone();
    }
    let bytes = legion_contracts::canonical_json_bytes(&message).map_err(|_| ())?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(&key.key).map_err(|_| ())?;
    hmac.update(&bytes);
    let presented = decode_hex(mac).ok_or(())?;
    hmac.verify_slice(&presented).map_err(|_| ())?;
    for field in [
        "authority",
        "callerAuthority",
        "assertedAuthority",
        "trust_class",
        "trustClass",
    ] {
        if record.get(field).is_some() {
            return Err(());
        }
    }
    Ok(())
}

fn redact_authentication(mut record: Value) -> Value {
    if let Some(object) = record.as_object_mut() {
        let auth = object.get("authentication").and_then(Value::as_object);
        let mut projected = Map::new();
        if let Some(auth) = auth {
            projected.insert(
                "keyId".into(),
                auth.get("keyId").cloned().unwrap_or(Value::Null),
            );
            projected.insert(
                "alg".into(),
                auth.get("alg").cloned().unwrap_or(Value::Null),
            );
        }
        object.insert("authentication".into(), Value::Object(projected));
    }
    record
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            Some(
                (char::from(pair[0]).to_digit(16)? as u8) << 4
                    | char::from(pair[1]).to_digit(16)? as u8,
            )
        })
        .collect()
}
