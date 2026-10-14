//! Read-only access to a generic secret held in the OS credential store.
//!
//! macOS: Keychain generic password (service = `service`, account = current user).
//! Windows: Credential Manager generic credential with target `service`.
//! Other platforms: not available (`None`).
//!
//! The secret is returned to the caller and never logged or included in errors here.

/// Returns the non-empty secret stored under `service`, or `None` when it is absent,
/// empty, or the platform has no supported store.
pub fn read_generic_secret(service: &str) -> Option<String> {
    let secret = read_impl(service)?;
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "macos")]
fn read_impl(service: &str) -> Option<String> {
    use std::process::{Command, Stdio};
    let mut command = Command::new("/usr/bin/security");
    command.args(["find-generic-password", "-s", service]);
    let account = std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("LOGNAME").ok())
        .filter(|value| !value.is_empty());
    if let Some(account) = account {
        command.args(["-a", account.as_str()]);
    }
    command.arg("-w");
    let output = command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(windows)]
fn read_impl(service: &str) -> Option<String> {
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };
    let target: Vec<u16> = service.encode_utf16().chain(std::iter::once(0)).collect();
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `target` is a NUL-terminated UTF-16 buffer that outlives the call, and
    // `credential` is a valid out-pointer. On success the returned block is read within
    // its stated blob size and released exactly once with CredFree.
    unsafe {
        if CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) == 0
            || credential.is_null()
        {
            return None;
        }
        let size = (*credential).CredentialBlobSize as usize;
        let blob = (*credential).CredentialBlob;
        let bytes: Vec<u8> = if blob.is_null() || size == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(blob as *const u8, size).to_vec()
        };
        CredFree(credential as *const std::ffi::c_void);
        decode_blob(&bytes)
    }
}

/// Credential Manager blobs are UTF-16LE when written by `cmdkey`/most tools, UTF-8
/// when written by some libraries.
#[cfg(any(windows, test))]
fn decode_blob(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    if bytes.len() % 2 == 0 && bytes.iter().skip(1).step_by(2).all(|b| *b == 0) {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16(&units).ok();
    }
    String::from_utf8(bytes.to_vec()).ok()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn read_impl(_service: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::decode_blob;

    #[test]
    fn decodes_utf16_and_utf8_blobs() {
        let utf16: Vec<u8> = "nvapi-x"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode_blob(&utf16).as_deref(), Some("nvapi-x"));
        assert_eq!(decode_blob(b"nvapi-y").as_deref(), Some("nvapi-y"));
        assert_eq!(decode_blob(b""), None);
    }
}
