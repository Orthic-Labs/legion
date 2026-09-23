//! Minimal base64 (standard alphabet, with padding) encode/decode.
//! Ported from Node's `Buffer.from(value, 'base64')` semantics as used by
//! `src/lib/platform/artifact-sanitize.mjs` (`isCanonicalBase64`) and
//! `src/lib/platform/external/validate.mjs`.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes to standard base64 with `=` padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((n >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard base64. Returns `None` on any malformed input (mirrors
/// treating decode failure as invalid, matching the try/catch in the JS).
pub fn decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut chunks = bytes.chunks(4).peekable();
    while let Some(chunk) = chunks.next() {
        let is_last = chunks.peek().is_none();
        let pad = if is_last {
            chunk.iter().filter(|&&b| b == b'=').count()
        } else {
            0
        };
        if pad > 0 && !is_last {
            return None;
        }
        let mut vals = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                if i < 2 {
                    return None;
                }
                vals[i] = 0;
            } else {
                vals[i] = decode_char(c)?;
            }
        }
        let n = ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6) | (vals[3] as u32);
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

/// Mirrors `isCanonicalBase64`: the value must match the base64 regex AND
/// round-trip (re-encoding the decoded bytes reproduces the same string),
/// which rejects non-canonical padding/alphabet variants.
pub fn is_canonical(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if !value.bytes().all(|b| decode_char(b).is_some() || b == b'=') {
        return false;
    }
    match decode(value) {
        Some(bytes) => encode(&bytes) == value,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let s = encode(b"hello world");
        assert_eq!(decode(&s).unwrap(), b"hello world");
        assert!(is_canonical(&s));
    }

    #[test]
    fn rejects_noncanonical() {
        assert!(!is_canonical("not base64!!"));
        assert!(!is_canonical(""));
    }
}
