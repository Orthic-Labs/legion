//! Port of the pure pieces of `detect-url.mjs` (`serializeDesignSystemForBrowser`)
//! and `detect-url-cdp.mjs` (the CDP WebSocket frame codec, and the
//! Chrome/Edge executable candidate-path list). `detectUrl`/`detectUrlCdp`
//! themselves launch a browser process, open a page, and inject a script —
//! process/network side effects with no return-value contract to assert
//! against without a real browser, so they stay unported.

use std::collections::BTreeMap;

/// Mirror of the JS `designSystem` shape after
/// `serializeDesignSystemForBrowser` strips it down to what
/// `window.__IMPECCABLE_CONFIG__.designSystem` needs in-page. `None` when
/// the input design system is absent/`present !== true`.
#[derive(Debug, Clone, PartialEq)]
pub struct SerializedDesignSystem {
    pub has_fonts: bool,
    pub allowed_fonts: Vec<String>,
    pub has_colors: bool,
    pub allowed_colors: Vec<(f64, f64, f64)>,
    pub has_radii: bool,
    pub allowed_radii: Vec<f64>,
    pub has_pill_radius: bool,
}

/// Minimal stand-in for the JS `designSystem` object
/// `serializeDesignSystemForBrowser` reads from. `allowed_color_keys`
/// mirrors `designSystem.allowedColorKeys` (a `Map`-like: values carry an
/// optional `{r,g,b}` color, some of which may be missing/non-finite and
/// are filtered out, same as the JS `.filter(color => color &&
/// Number.isFinite(...))`).
#[derive(Debug, Clone, Default)]
pub struct DesignSystemInput {
    pub present: bool,
    pub has_fonts: bool,
    pub allowed_fonts: Vec<String>,
    pub has_colors: bool,
    pub allowed_color_values: Vec<Option<(f64, f64, f64)>>,
    pub has_radii: bool,
    pub allowed_radii: Vec<Option<f64>>,
    pub has_pill_radius: bool,
}

/// Port of `serializeDesignSystemForBrowser(designSystem)`.
pub fn serialize_design_system_for_browser(
    ds: &DesignSystemInput,
) -> Option<SerializedDesignSystem> {
    if !ds.present {
        return None;
    }
    let allowed_colors = ds
        .allowed_color_values
        .iter()
        .filter_map(|c| *c)
        .filter(|(r, g, b)| r.is_finite() && g.is_finite() && b.is_finite())
        .collect();
    let allowed_radii = ds
        .allowed_radii
        .iter()
        .filter_map(|px| *px)
        .filter(|px| px.is_finite())
        .collect();
    Some(SerializedDesignSystem {
        has_fonts: ds.has_fonts,
        allowed_fonts: ds.allowed_fonts.clone(),
        has_colors: ds.has_colors,
        allowed_colors,
        has_radii: ds.has_radii,
        allowed_radii,
        has_pill_radius: ds.has_pill_radius,
    })
}

// ---------------------------------------------------------------------------
// Minimal WebSocket frame codec (port of detect-url-cdp.mjs's makeFrame /
// readFrames — the raw hand-rolled CDP client, no masking-key randomness
// asserted, only the frame layout).
// ---------------------------------------------------------------------------

/// Port of `makeFrame(text)`: builds a single masked text (opcode `0x1`)
/// WebSocket client frame for `text`, using the given 4-byte mask (the JS
/// draws this from `randomBytes(4)`; tests pass a fixed mask for
/// determinism and to check the XOR math independent of RNG).
pub fn make_frame(text: &str, mask: [u8; 4]) -> Vec<u8> {
    let payload = text.as_bytes();
    let mut out = Vec::new();
    if payload.len() < 126 {
        out.push(0x81);
        out.push(0x80 | payload.len() as u8);
    } else if payload.len() < 65536 {
        out.push(0x81);
        out.push(0x80 | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(0x81);
        out.push(0x80 | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

/// One decoded WebSocket frame: opcode plus UTF-8 payload text (matches
/// `readFrames`'s `{ opcode, text }`; non-UTF-8 payloads are lossily
/// decoded the way JS `Buffer#toString('utf8')` would replace invalid
/// sequences).
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedFrame {
    pub opcode: u8,
    pub text: String,
}

/// Port of `readFrames(buffer)`: parses as many complete frames as
/// `buffer` holds (7/16/64-bit length forms, optional masking), returning
/// the decoded frames plus the unconsumed remainder — same
/// incomplete-frame-stays-buffered contract as the JS version (used to
/// accumulate partial TCP reads).
pub fn read_frames(buffer: &[u8]) -> (Vec<DecodedFrame>, Vec<u8>) {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while buffer.len() - offset >= 2 {
        let b0 = buffer[offset];
        let b1 = buffer[offset + 1];
        let opcode = b0 & 0x0f;
        let masked = (b1 & 0x80) != 0;
        let mut len = (b1 & 0x7f) as u64;
        let mut pos = offset + 2;
        if len == 126 {
            if buffer.len() - pos < 2 {
                break;
            }
            len = u16::from_be_bytes([buffer[pos], buffer[pos + 1]]) as u64;
            pos += 2;
        } else if len == 127 {
            if buffer.len() - pos < 8 {
                break;
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&buffer[pos..pos + 8]);
            len = u64::from_be_bytes(arr);
            pos += 8;
        }
        let mask = if masked {
            if buffer.len() - pos < 4 {
                break;
            }
            let m = [buffer[pos], buffer[pos + 1], buffer[pos + 2], buffer[pos + 3]];
            pos += 4;
            Some(m)
        } else {
            None
        };
        let len = len as usize;
        if buffer.len() - pos < len {
            break;
        }
        let mut payload = buffer[pos..pos + len].to_vec();
        if let Some(mask) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        frames.push(DecodedFrame {
            opcode,
            text: String::from_utf8_lossy(&payload).into_owned(),
        });
        offset = pos + len;
    }
    (frames, buffer[offset..].to_vec())
}

// ---------------------------------------------------------------------------
// findBrowserExecutable's candidate list (pure path construction; the
// filesystem-existence check and env override are injected by the caller
// so this stays testable without touching the real filesystem).
// ---------------------------------------------------------------------------

/// Port of `findBrowserExecutable`'s per-platform candidate path list
/// (everything after the `CHROME_PATH`/`QA_BROWSER` override check). `home`
/// mirrors `process.env.HOME || process.env.USERPROFILE || ''`.
pub fn browser_executable_candidates(is_windows: bool, program_files: Option<&str>, program_files_x86: Option<&str>, home: &str) -> Vec<String> {
    if is_windows {
        let pf = program_files.unwrap_or("C:\\Program Files");
        let pf86 = program_files_x86.unwrap_or("C:\\Program Files (x86)");
        vec![
            format!("{pf}\\Google\\Chrome\\Application\\chrome.exe"),
            format!("{pf86}\\Google\\Chrome\\Application\\chrome.exe"),
            format!("{pf}\\Microsoft\\Edge\\Application\\msedge.exe"),
            format!("{pf86}\\Microsoft\\Edge\\Application\\msedge.exe"),
        ]
    } else {
        vec![
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string(),
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".to_string(),
            "/Applications/Chromium.app/Contents/MacOS/Chromium".to_string(),
            format!("{home}/.local/chrome-for-testing/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"),
            format!("{home}/.local/chrome-for-testing/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"),
            "/usr/bin/google-chrome".to_string(),
            "/usr/bin/chromium".to_string(),
            "/usr/bin/chromium-browser".to_string(),
            "/usr/bin/microsoft-edge".to_string(),
        ]
    }
}

/// Port of `findBrowserExecutable`'s selection: the env override when set
/// (`Err` when it's set but `exists` says it's missing, matching the JS
/// `throw`), else the first candidate `exists` reports true for, else the
/// "neither was found" error. `exists` stands in for `fs.existsSync`.
pub fn find_browser_executable(
    env_override: Option<&str>,
    candidates: &[String],
    exists: impl Fn(&str) -> bool,
) -> Result<String, String> {
    if let Some(over) = env_override {
        return if exists(over) {
            Ok(over.to_string())
        } else {
            Err(format!("CHROME_PATH/QA_BROWSER set but not found: {over}"))
        };
    }
    for c in candidates {
        if exists(c) {
            return Ok(c.clone());
        }
    }
    Err("URL scanning needs puppeteer or an installed Chrome/Edge. Neither was found.".to_string())
}

/// Port of the mobile-emulation flag `detectUrlCdp` passes to
/// `Emulation.setDeviceMetricsOverride`: `mobile: viewport.width < 600`.
pub fn is_mobile_viewport(width: u32) -> bool {
    width < 600
}

/// Port of `window.__IMPECCABLE_CONFIG__` merge target used by both
/// `detectUrl` (`page.evaluate`) and `detectUrlCdp` (string-built
/// `Runtime.evaluate` expression): `{ ...existing, autoScan: false, ...
/// (designSystem ? { designSystem } : {}) }`, represented as an ordered map
/// of top-level keys to their JSON-ish string values so callers can render
/// it either way without duplicating the merge decision.
pub fn impeccable_config_overrides(has_design_system: bool) -> BTreeMap<&'static str, &'static str> {
    let mut m = BTreeMap::new();
    m.insert("autoScan", "false");
    if has_design_system {
        m.insert("designSystem", "<serialized>");
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_design_system_none_when_absent() {
        assert_eq!(
            serialize_design_system_for_browser(&DesignSystemInput::default()),
            None
        );
    }

    #[test]
    fn serialize_design_system_filters_non_finite_colors_and_radii() {
        let ds = DesignSystemInput {
            present: true,
            has_fonts: true,
            allowed_fonts: vec!["Inter".to_string()],
            has_colors: true,
            allowed_color_values: vec![
                Some((10.0, 20.0, 30.0)),
                None,
                Some((f64::NAN, 0.0, 0.0)),
            ],
            has_radii: true,
            allowed_radii: vec![Some(4.0), None, Some(f64::INFINITY)],
            has_pill_radius: true,
        };
        let out = serialize_design_system_for_browser(&ds).unwrap();
        assert_eq!(out.allowed_colors, vec![(10.0, 20.0, 30.0)]);
        assert_eq!(out.allowed_radii, vec![4.0]);
        assert!(out.has_fonts && out.has_colors && out.has_radii && out.has_pill_radius);
        assert_eq!(out.allowed_fonts, vec!["Inter".to_string()]);
    }

    #[test]
    fn make_frame_then_read_frames_roundtrips() {
        let mask = [0x11, 0x22, 0x33, 0x44];
        let frame = make_frame("hello cdp", mask);
        let (frames, rest) = read_frames(&frame);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].opcode, 1);
        assert_eq!(frames[0].text, "hello cdp");
        assert!(rest.is_empty());
    }

    #[test]
    fn make_frame_uses_16_bit_length_form_at_126_bytes() {
        let mask = [0, 0, 0, 0];
        let text: String = std::iter::repeat('a').take(200).collect();
        let frame = make_frame(&text, mask);
        assert_eq!(frame[1] & 0x7f, 126);
        let (frames, _) = read_frames(&frame);
        assert_eq!(frames[0].text, text);
    }

    #[test]
    fn read_frames_leaves_incomplete_frame_in_rest() {
        let mask = [1, 2, 3, 4];
        let mut frame = make_frame("full message", mask);
        frame.truncate(frame.len() - 3); // chop off the last few payload bytes
        let (frames, rest) = read_frames(&frame);
        assert!(frames.is_empty());
        assert_eq!(rest, frame);
    }

    #[test]
    fn browser_executable_candidates_and_lookup() {
        let candidates = browser_executable_candidates(false, None, None, "/Users/me");
        assert!(candidates.contains(&"/usr/bin/google-chrome".to_string()));
        assert!(candidates[3].starts_with("/Users/me/.local/chrome-for-testing"));

        let found = find_browser_executable(None, &candidates, |p| p == "/usr/bin/chromium");
        assert_eq!(found, Ok("/usr/bin/chromium".to_string()));

        let missing = find_browser_executable(None, &candidates, |_| false);
        assert!(missing.is_err());

        let overridden = find_browser_executable(Some("/opt/chrome"), &candidates, |p| p == "/opt/chrome");
        assert_eq!(overridden, Ok("/opt/chrome".to_string()));

        let bad_override = find_browser_executable(Some("/opt/missing"), &candidates, |_| false);
        assert!(bad_override.unwrap_err().contains("CHROME_PATH/QA_BROWSER"));
    }

    #[test]
    fn mobile_viewport_threshold_matches_js() {
        assert!(is_mobile_viewport(599));
        assert!(!is_mobile_viewport(600));
    }
}
