//! `legion keys init`: provision the host key ring the Arcane protocol loads.
use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use legion_arcane::key_ring::{resolve_key_dir, KeyDirSource, KeyRing};
use serde_json::json;
use std::path::PathBuf;

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if argv.first().map(String::as_str) != Some("init") {
        return Err(CommandError::usage(format!(
            "keys requires init (got {})",
            argv.first().map(String::as_str).unwrap_or("<none>")
        )));
    }
    let mut key_dir: Option<PathBuf> = None;
    let mut index = 1;
    while index < argv.len() {
        match argv[index].as_str() {
            "--key-dir" => {
                index += 1;
                key_dir = Some(PathBuf::from(argv.get(index).ok_or_else(|| {
                    CommandError::usage("keys init --key-dir requires a path")
                })?));
            }
            other => {
                return Err(CommandError::usage(format!(
                    "keys init does not accept '{other}'"
                )))
            }
        }
        index += 1;
    }
    let (dir, source) = resolve_key_dir(key_dir.as_deref())
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    // Cryptographic randomness: 32 bytes from the OS RNG (getrandom).
    let material = legion_audit::new_plan_key()
        .map_err(|error| CommandError::internal(format!("could not generate key: {error}")))?;
    let ring = KeyRing::init_ring(&dir, &material, &rfc3339_now())
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    Ok(json!({
        "kind": "legion-keys-init",
        "keyDir": ring.dir,
        "keyId": ring.key_id,
        "source": match source {
            KeyDirSource::Explicit => "--key-dir",
            KeyDirSource::Environment => "ARCANE_KEY_DIR",
            KeyDirSource::Canonical => "canonical",
        },
        "created": true,
    }))
}

fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    fn args(parts: &[&str]) -> CommonArgs {
        CommonArgs {
            json: false,
            args: parts.iter().map(OsString::from).collect(),
        }
    }

    #[test]
    fn rfc3339_known_instant_shape() {
        let text = rfc3339_now();
        assert_eq!(text.len(), 20);
        assert!(text.ends_with('Z'));
    }

    #[test]
    fn init_command_creates_then_refuses() {
        let dir = std::env::temp_dir().join(format!("legion-keys-cmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.to_string_lossy().into_owned();
        let out = run(args(&["init", "--key-dir", &path])).unwrap();
        assert_eq!(out["created"], true);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let error = run(args(&["init", "--key-dir", &path])).unwrap_err();
        assert!(error.message.contains("already initialized"));
        assert!(run(args(&["bogus"])).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
