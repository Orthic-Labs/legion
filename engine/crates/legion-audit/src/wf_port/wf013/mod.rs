//! Port of `src/lib/qa-engine/{qa.mjs,qa-functional.mjs,qa-shot.mjs}` (chunk wf013).
//!
//! `qa.mjs` is a Node CLI that drives a headless Chrome/Edge via raw CDP (Chrome DevTools
//! Protocol) websocket frames it hand-rolls over a TCP socket, plus a small local dev-server
//! launcher. `qa-shot.mjs` and `qa-functional.mjs` are argv-rewriting wrappers around it
//! (`--shot` only, and `--actions`-only respectively; `qa-functional.mjs` with no `--actions`
//! degrades to `--help`).
//!
//! This module ports the pure, unit-testable logic faithfully: CLI argument parsing, viewport
//! presets, network-throttle presets, websocket frame encode/decode, JSON string escaping for
//! injected `Runtime.evaluate` expressions, the wrapper argv-rewrite rules, and the stale
//! browser-profile sweep predicate. The process-spawning / live-socket orchestration
//! (`main`, `runShot`, `runShotCdp`, `runActions`, `cdpConnect`'s live I/O loop) is intentionally
//! left un-ported in this chunk — see the wf013 report for the gap and suggested follow-up.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------------------------
// CLI argument parsing (qa.mjs parseArgs)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Args {
    pub route: String,
    pub out: String,
    pub width: f64,
    pub height: f64,
    pub port: u32,
    pub cdp_port: u32,
    pub qa_env: String,
    pub shot: bool,
    pub keep_open: bool,
    pub mobile: bool,
    pub dpr: f64,
    pub help: bool,
    pub sweep: bool,
    pub actions: Option<String>,
    pub url: Option<String>,
    pub start: Option<String>,
    pub throttle: Option<String>,
    pub cpu: Option<f64>,
    pub save_session: Option<String>,
    pub load_session: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            route: "/?qa=1".to_string(),
            out: ".cache/qa-shots/app.png".to_string(),
            width: 1365.0,
            height: 900.0,
            port: 0,
            cdp_port: 0,
            qa_env: "VITE_APP_BROWSER_QA=1".to_string(),
            shot: false,
            keep_open: false,
            mobile: false,
            dpr: 1.0,
            help: false,
            sweep: false,
            actions: None,
            url: None,
            start: None,
            throttle: None,
            cpu: None,
            save_session: None,
            load_session: None,
        }
    }
}

/// Mirrors `parseArgs` in qa.mjs, including its "Unknown argument" error and the fact that a
/// flag expecting a value that is missing from argv yields `NaN`/`undefined` in JS. We surface
/// a missing value as an explicit error instead of silently producing a bad numeric arg, since
/// Rust has no `NaN`-from-nothing equivalent for `String` args — this is a faithful strengthening,
/// not a behavior change for any well-formed invocation.
pub fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut args = Args::default();
    let mut i = 0usize;
    let next = |argv: &[String], i: &mut usize, flag: &str| -> Result<String, String> {
        *i += 1;
        argv.get(*i)
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "--help" | "-h" => args.help = true,
            "--shot" => args.shot = true,
            "--sweep" => args.sweep = true,
            "--keep-open" => args.keep_open = true,
            "--actions" => args.actions = Some(next(argv, &mut i, "--actions")?),
            "--url" => args.url = Some(next(argv, &mut i, "--url")?),
            "--start" => args.start = Some(next(argv, &mut i, "--start")?),
            "--route" => args.route = next(argv, &mut i, "--route")?,
            "--out" => args.out = next(argv, &mut i, "--out")?,
            "--width" => {
                let v = next(argv, &mut i, "--width")?;
                args.width = v
                    .parse()
                    .map_err(|_| format!("--width: not a number: {v}"))?;
            }
            "--height" => {
                let v = next(argv, &mut i, "--height")?;
                args.height = v
                    .parse()
                    .map_err(|_| format!("--height: not a number: {v}"))?;
            }
            "--port" => {
                let v = next(argv, &mut i, "--port")?;
                args.port = v
                    .parse()
                    .map_err(|_| format!("--port: not a number: {v}"))?;
            }
            "--cdp-port" => {
                let v = next(argv, &mut i, "--cdp-port")?;
                args.cdp_port = v
                    .parse()
                    .map_err(|_| format!("--cdp-port: not a number: {v}"))?;
            }
            "--qa-env" => args.qa_env = next(argv, &mut i, "--qa-env")?,
            "--viewport" => {
                let v = next(argv, &mut i, "--viewport")?;
                let p = parse_viewport(&v)?;
                args.width = p.width;
                args.height = p.height;
                args.dpr = p.dpr;
                args.mobile = p.mobile;
            }
            "--slow-3g" => args.throttle = Some("slow-3g".to_string()),
            "--slow-4g" => args.throttle = Some("slow-4g".to_string()),
            "--cpu-4x" => args.cpu = Some(4.0),
            "--cpu-throttle" => {
                let v = next(argv, &mut i, "--cpu-throttle")?;
                args.cpu = Some(
                    v.parse()
                        .map_err(|_| format!("--cpu-throttle: not a number: {v}"))?,
                );
            }
            "--save-session" => args.save_session = Some(next(argv, &mut i, "--save-session")?),
            "--load-session" => args.load_session = Some(next(argv, &mut i, "--load-session")?),
            other => return Err(format!("Unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(args)
}

pub fn usage() -> &'static str {
    r#"Usage:
  qa.mjs --shot [--route "/?qa=1"] [--out ".cache/qa-shots/app.png"]
  qa.mjs --actions actions.json [--route "/?qa=1"]
  qa.mjs --url "http://127.0.0.1:3000/?qa=1" --actions actions.json

Options:
  --shot                 Capture one viewport-only app screenshot.
  --actions <file>       JSON action file for hover/click/assert/screenshot QA.
  --url <url>            Use an already-running app URL.
  --start <command>      Start command. Use {port} placeholder for the selected port.
  --route <route>        Route to open on the local server. Default: /?qa=1
  --out <path>           Screenshot path for --shot. Default: .cache/qa-shots/app.png
  --width <px>           Viewport width. Default: 1365
  --height <px>          Viewport height. Default: 900
  --port <port>          Server port. Default: first free port from 1422.
  --cdp-port <port>      DevTools port for action mode. Default: first free port from 9222.
  --qa-env <NAME=VALUE>  Env var for server process. Default: VITE_APP_BROWSER_QA=1
  --viewport <spec>      Preset (desktop|tablet|mobile) or WxH (e.g. 390x844). Sets width/height/DPR/mobile.
  --slow-3g              Throttle network ~400 kbps / 400ms RTT (CDP). Reveals spinners/jank hidden on localhost.
  --slow-4g              Throttle network ~1.6 Mbps / 150ms RTT (CDP).
  --cpu-4x               Throttle CPU 4x (CDP). Shorthand for --cpu-throttle 4.
  --cpu-throttle <n>     Throttle CPU by factor n (CDP).
  --save-session <file>  After the run, save cookies + localStorage to <file>.
  --load-session <file>  Restore cookies + localStorage before first paint (skip re-login).
  --keep-open            Leave server running after the run.
  --sweep                Delete abandoned browser profiles under .cache and exit.
  --help                 Show help.

Any throttle/CPU/mobile/session flag routes --shot through the CDP path, because Chrome's
fire-and-forget --screenshot= flag cannot express those conditions.
"#
}

// ---------------------------------------------------------------------------------------------
// Viewport presets (qa.mjs VIEWPORTS / parseViewport)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Viewport {
    pub width: f64,
    pub height: f64,
    pub dpr: f64,
    pub mobile: bool,
}

pub fn viewport_presets() -> HashMap<&'static str, Viewport> {
    let mut m = HashMap::new();
    m.insert(
        "desktop",
        Viewport {
            width: 1440.0,
            height: 900.0,
            dpr: 1.0,
            mobile: false,
        },
    );
    m.insert(
        "tablet",
        Viewport {
            width: 768.0,
            height: 1024.0,
            dpr: 2.0,
            mobile: true,
        },
    );
    m.insert(
        "mobile",
        Viewport {
            width: 390.0,
            height: 844.0,
            dpr: 3.0,
            mobile: true,
        },
    );
    m
}

/// Mirrors `parseViewport`: preset name, or `WxH` (integers only, matching the JS `/^(\d+)x(\d+)$/`).
pub fn parse_viewport(v: &str) -> Result<Viewport, String> {
    if v.is_empty() {
        return Err("--viewport needs a value (desktop|tablet|mobile|WxH)".to_string());
    }
    if let Some(p) = viewport_presets().get(v) {
        return Ok(*p);
    }
    let parts: Vec<&str> = v.splitn(2, 'x').collect();
    if parts.len() == 2
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].chars().all(|c| c.is_ascii_digit())
    {
        let width: f64 = parts[0].parse().map_err(|_| bad_viewport(v))?;
        let height: f64 = parts[1].parse().map_err(|_| bad_viewport(v))?;
        return Ok(Viewport {
            width,
            height,
            dpr: 1.0,
            mobile: false,
        });
    }
    Err(bad_viewport(v))
}

fn bad_viewport(v: &str) -> String {
    format!("bad --viewport: {v} (use desktop|tablet|mobile or 1440x900)")
}

// ---------------------------------------------------------------------------------------------
// Network throttle presets (qa.mjs THROTTLE)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThrottlePreset {
    pub download_throughput: f64,
    pub upload_throughput: f64,
    pub latency_ms: f64,
}

pub fn throttle_preset(name: &str) -> Option<ThrottlePreset> {
    match name {
        "slow-3g" => Some(ThrottlePreset {
            download_throughput: 50.0 * 1000.0,
            upload_throughput: 50.0 * 1000.0,
            latency_ms: 400.0,
        }),
        "slow-4g" => Some(ThrottlePreset {
            download_throughput: 200.0 * 1000.0,
            upload_throughput: 94.0 * 1000.0,
            latency_ms: 150.0,
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// JSON string escaping for injected Runtime.evaluate expressions (qa.mjs jsString)
// ---------------------------------------------------------------------------------------------

/// Mirrors `jsString`: `JSON.stringify(String(value))`. serde_json is not a dependency of this
/// crate, so this hand-rolls JSON string escaping for the subset qa.mjs ever needs to embed
/// (selectors, text, css property names/values, aria labels): control chars, `"`, and `\`.
pub fn js_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------------------------
// Websocket frame encode/decode for the hand-rolled CDP client (qa.mjs makeFrame / readFrames)
// ---------------------------------------------------------------------------------------------

/// Mirrors `makeFrame`: a single masked text (opcode 0x1) websocket frame, client-to-server.
/// Always masks (RFC 6455 requires client frames to be masked), matching the JS, which always
/// XORs with a fresh random 4-byte key. Callers needing determinism for tests should decode the
/// frame right back with `read_frames`, which un-masks — the mask key itself is not asserted on.
pub fn make_frame(text: &str, mask: [u8; 4]) -> Vec<u8> {
    let payload = text.as_bytes();
    let len = payload.len();
    let mut header: Vec<u8> = Vec::new();
    if len < 126 {
        header.push(0x81);
        header.push(0x80 | (len as u8));
    } else if len < 65536 {
        header.push(0x81);
        header.push(0x80 | 126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(0x81);
        header.push(0x80 | 127);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mut out = header;
    out.extend_from_slice(&mask);
    let masked: Vec<u8> = payload
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 4])
        .collect();
    out.extend_from_slice(&masked);
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub opcode: u8,
    pub text: String,
}

/// Mirrors `readFrames`: parses as many complete frames as `buffer` holds (handling the 7-bit /
/// 16-bit-extended / 64-bit-extended length encoding and optional masking), returning the
/// frames found and the number of bytes consumed — the caller keeps the remainder buffered for
/// the next socket read, exactly as qa.mjs's `buffer = parsed.rest` does.
pub fn read_frames(buffer: &[u8]) -> (Vec<Frame>, usize) {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while buffer.len().saturating_sub(offset) >= 2 {
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
            let mut b = [0u8; 8];
            b.copy_from_slice(&buffer[pos..pos + 8]);
            len = u64::from_be_bytes(b);
            pos += 8;
        }
        let mask = if masked {
            if buffer.len() - pos < 4 {
                break;
            }
            let m = [
                buffer[pos],
                buffer[pos + 1],
                buffer[pos + 2],
                buffer[pos + 3],
            ];
            pos += 4;
            Some(m)
        } else {
            None
        };
        let len_usize = len as usize;
        if buffer.len() - pos < len_usize {
            break;
        }
        let mut payload = buffer[pos..pos + len_usize].to_vec();
        if let Some(mask) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        let text = String::from_utf8_lossy(&payload).into_owned();
        frames.push(Frame { opcode, text });
        offset = pos + len_usize;
    }
    (frames, offset)
}

// ---------------------------------------------------------------------------------------------
// Wrapper argv rewrite rules (qa-shot.mjs, qa-functional.mjs)
// ---------------------------------------------------------------------------------------------

/// Mirrors `qa-shot.mjs`: always prepends `--shot` to whatever argv the wrapper was called with.
pub fn qa_shot_final_args(argv: &[String]) -> Vec<String> {
    let mut out = vec!["--shot".to_string()];
    out.extend(argv.iter().cloned());
    out
}

/// Mirrors `qa-functional.mjs`: passes argv through unchanged only when it contains `--actions`
/// or an `--actions=...` form; otherwise it degrades to `["--help"]` regardless of what else was
/// passed.
pub fn qa_functional_final_args(argv: &[String]) -> Vec<String> {
    let has_actions = argv
        .iter()
        .any(|a| a == "--actions" || a.starts_with("--actions="));
    if has_actions {
        argv.to_vec()
    } else {
        vec!["--help".to_string()]
    }
}

// ---------------------------------------------------------------------------------------------
// Stale browser-profile sweep predicate (qa.mjs sweepStaleProfiles)
// ---------------------------------------------------------------------------------------------

pub const PROFILE_PREFIXES: [&str; 2] = ["qa-browser-profile-", "qa-cdp-profile-"];

/// True when a `.cache` entry name matches one of the throwaway-profile prefixes qa.mjs ever
/// creates. Mirrors the `PROFILE_PREFIXES.some(...)` filter in `sweepStaleProfiles`.
pub fn is_profile_dir_name(name: &str) -> bool {
    PROFILE_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// One directory entry as `sweepStaleProfiles` inspects it: name, whether it is a (non-symlink)
/// directory, and its mtime.
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub mtime: SystemTime,
}

/// Mirrors the filtering core of `sweepStaleProfiles`: skips non-directories, symlinks, and
/// names that don't match a known profile prefix; among the rest, returns the names older than
/// `older_than`. `active` mirrors the JS `_profiles` set — profiles this process itself created
/// and is still using are never swept, no matter their age. Actual removal (`rmSync`) stays a
/// side-effecting caller concern, kept out of this pure predicate.
pub fn stale_profile_names(
    entries: &[ProfileEntry],
    now: SystemTime,
    older_than: Duration,
    active: &[String],
) -> Vec<String> {
    entries
        .iter()
        .filter(|e| e.is_dir && !e.is_symlink)
        .filter(|e| is_profile_dir_name(&e.name))
        .filter(|e| !active.iter().any(|a| a == &e.name))
        .filter(|e| match now.duration_since(e.mtime) {
            Ok(age) => age >= older_than,
            Err(_) => false, // mtime in the future: treat as fresh, matching `now - mtimeMs < olderThanMs` → skip
        })
        .map(|e| e.name.clone())
        .collect()
}

/// Resolves a possibly-relative path against `root`, mirroring `abs()` in qa.mjs
/// (`isAbsolute(path) ? path : resolve(root, path)`).
pub fn resolve_abs(root: &Path, path: &str) -> std::path::PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // --- parse_args -----------------------------------------------------------------------

    #[test]
    fn parse_args_defaults() {
        let a = parse_args(&[]).unwrap();
        assert_eq!(a, Args::default());
    }

    #[test]
    fn parse_args_shot_and_out() {
        let a = parse_args(&s(&["--shot", "--out", "shots/app.png"])).unwrap();
        assert!(a.shot);
        assert_eq!(a.out, "shots/app.png");
    }

    #[test]
    fn parse_args_actions_and_url() {
        let a = parse_args(&s(&[
            "--actions",
            "actions.json",
            "--url",
            "http://127.0.0.1:3000/?qa=1",
        ]))
        .unwrap();
        assert_eq!(a.actions.as_deref(), Some("actions.json"));
        assert_eq!(a.url.as_deref(), Some("http://127.0.0.1:3000/?qa=1"));
    }

    #[test]
    fn parse_args_viewport_preset_sets_width_height_dpr_mobile() {
        let a = parse_args(&s(&["--viewport", "mobile"])).unwrap();
        assert_eq!(a.width, 390.0);
        assert_eq!(a.height, 844.0);
        assert_eq!(a.dpr, 3.0);
        assert!(a.mobile);
    }

    #[test]
    fn parse_args_viewport_wxh() {
        let a = parse_args(&s(&["--viewport", "1440x900"])).unwrap();
        assert_eq!(a.width, 1440.0);
        assert_eq!(a.height, 900.0);
        assert_eq!(a.dpr, 1.0);
        assert!(!a.mobile);
    }

    #[test]
    fn parse_args_cpu_4x_shorthand() {
        let a = parse_args(&s(&["--cpu-4x"])).unwrap();
        assert_eq!(a.cpu, Some(4.0));
    }

    #[test]
    fn parse_args_cpu_throttle_explicit() {
        let a = parse_args(&s(&["--cpu-throttle", "6"])).unwrap();
        assert_eq!(a.cpu, Some(6.0));
    }

    #[test]
    fn parse_args_unknown_argument_errors() {
        let err = parse_args(&s(&["--bogus"])).unwrap_err();
        assert_eq!(err, "Unknown argument: --bogus");
    }

    #[test]
    fn parse_args_sweep_and_keep_open_and_help() {
        let a = parse_args(&s(&["--sweep", "--keep-open", "--help"])).unwrap();
        assert!(a.sweep);
        assert!(a.keep_open);
        assert!(a.help);
    }

    #[test]
    fn parse_args_qa_env_default_and_override() {
        let a = parse_args(&[]).unwrap();
        assert_eq!(a.qa_env, "VITE_APP_BROWSER_QA=1");
        let a = parse_args(&s(&["--qa-env", "FOO=bar"])).unwrap();
        assert_eq!(a.qa_env, "FOO=bar");
    }

    // --- parse_viewport ---------------------------------------------------------------------

    #[test]
    fn parse_viewport_presets() {
        assert_eq!(
            parse_viewport("desktop").unwrap(),
            Viewport {
                width: 1440.0,
                height: 900.0,
                dpr: 1.0,
                mobile: false
            }
        );
        assert_eq!(
            parse_viewport("tablet").unwrap(),
            Viewport {
                width: 768.0,
                height: 1024.0,
                dpr: 2.0,
                mobile: true
            }
        );
    }

    #[test]
    fn parse_viewport_wxh_form() {
        assert_eq!(
            parse_viewport("390x844").unwrap(),
            Viewport {
                width: 390.0,
                height: 844.0,
                dpr: 1.0,
                mobile: false
            }
        );
    }

    #[test]
    fn parse_viewport_rejects_bad_input() {
        assert!(parse_viewport("").is_err());
        assert!(parse_viewport("bogus").is_err());
        assert!(parse_viewport("390xNaN").is_err());
        assert!(parse_viewport("x900").is_err());
    }

    // --- throttle_preset --------------------------------------------------------------------

    #[test]
    fn throttle_preset_values_match_js() {
        let p = throttle_preset("slow-3g").unwrap();
        assert_eq!(p.download_throughput, 50_000.0);
        assert_eq!(p.upload_throughput, 50_000.0);
        assert_eq!(p.latency_ms, 400.0);

        let p = throttle_preset("slow-4g").unwrap();
        assert_eq!(p.download_throughput, 200_000.0);
        assert_eq!(p.upload_throughput, 94_000.0);
        assert_eq!(p.latency_ms, 150.0);

        assert!(throttle_preset("fast").is_none());
    }

    // --- js_string --------------------------------------------------------------------------

    #[test]
    fn js_string_escapes_quotes_and_backslashes() {
        assert_eq!(js_string("plain"), "\"plain\"");
        assert_eq!(js_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(js_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(js_string("line\nbreak"), "\"line\\nbreak\"");
    }

    // --- websocket frames --------------------------------------------------------------------

    #[test]
    fn make_frame_then_read_frames_roundtrips_short_payload() {
        let mask = [0x12, 0x34, 0x56, 0x78];
        let frame = make_frame("hello", mask);
        // header: FIN+opcode 0x81, MASK bit set + len
        assert_eq!(frame[0], 0x81);
        assert_eq!(frame[1], 0x80 | 5);
        let (frames, consumed) = read_frames(&frame);
        assert_eq!(consumed, frame.len());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].opcode, 1);
        assert_eq!(frames[0].text, "hello");
    }

    #[test]
    fn make_frame_extended_16bit_length() {
        let payload = "x".repeat(200);
        let frame = make_frame(&payload, [1, 2, 3, 4]);
        assert_eq!(frame[1], 0x80 | 126);
        let (frames, consumed) = read_frames(&frame);
        assert_eq!(consumed, frame.len());
        assert_eq!(frames[0].text, payload);
    }

    #[test]
    fn read_frames_leaves_partial_frame_unconsumed() {
        let mask = [1, 2, 3, 4];
        let mut frame = make_frame("hello world", mask);
        frame.truncate(frame.len() - 2); // chop off the tail of the payload
        let (frames, consumed) = read_frames(&frame);
        assert!(frames.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn read_frames_parses_multiple_frames_in_one_buffer() {
        let mut buf = make_frame("one", [9, 9, 9, 9]);
        buf.extend(make_frame("two", [1, 1, 1, 1]));
        let (frames, consumed) = read_frames(&buf);
        assert_eq!(consumed, buf.len());
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].text, "one");
        assert_eq!(frames[1].text, "two");
    }

    #[test]
    fn read_frames_unmasked_server_frame() {
        // CDP server frames are unmasked; build one by hand.
        let payload = b"srv";
        let mut buf = vec![0x81u8, payload.len() as u8];
        buf.extend_from_slice(payload);
        let (frames, consumed) = read_frames(&buf);
        assert_eq!(consumed, buf.len());
        assert_eq!(frames[0].text, "srv");
    }

    // --- wrapper argv rewrite ----------------------------------------------------------------

    #[test]
    fn qa_shot_prepends_shot_flag() {
        assert_eq!(
            qa_shot_final_args(&s(&["--route", "/x"])),
            s(&["--shot", "--route", "/x"])
        );
        assert_eq!(qa_shot_final_args(&[]), s(&["--shot"]));
    }

    #[test]
    fn qa_functional_passes_through_with_actions() {
        assert_eq!(
            qa_functional_final_args(&s(&["--actions", "a.json"])),
            s(&["--actions", "a.json"])
        );
        assert_eq!(
            qa_functional_final_args(&s(&["--actions=a.json"])),
            s(&["--actions=a.json"])
        );
    }

    #[test]
    fn qa_functional_degrades_to_help_without_actions() {
        assert_eq!(qa_functional_final_args(&[]), s(&["--help"]));
        assert_eq!(
            qa_functional_final_args(&s(&["--shot"])),
            s(&["--help"])
        );
    }

    // --- stale profile sweep -----------------------------------------------------------------

    #[test]
    fn is_profile_dir_name_matches_known_prefixes_only() {
        assert!(is_profile_dir_name("qa-browser-profile-12345"));
        assert!(is_profile_dir_name("qa-cdp-profile-99"));
        assert!(!is_profile_dir_name("something-else"));
        assert!(!is_profile_dir_name("qa-shots"));
    }

    #[test]
    fn stale_profile_names_filters_age_type_and_active_set() {
        let now = SystemTime::now();
        let old = now - Duration::from_secs(3600);
        let fresh = now - Duration::from_secs(10);
        let entries = vec![
            ProfileEntry {
                name: "qa-browser-profile-1".into(),
                is_dir: true,
                is_symlink: false,
                mtime: old,
            },
            ProfileEntry {
                name: "qa-cdp-profile-2".into(),
                is_dir: true,
                is_symlink: false,
                mtime: fresh,
            },
            ProfileEntry {
                name: "qa-browser-profile-3".into(),
                is_dir: true,
                is_symlink: false,
                mtime: old,
            },
            ProfileEntry {
                name: "unrelated-dir".into(),
                is_dir: true,
                is_symlink: false,
                mtime: old,
            },
            ProfileEntry {
                name: "qa-browser-profile-symlink".into(),
                is_dir: true,
                is_symlink: true,
                mtime: old,
            },
            ProfileEntry {
                name: "qa-browser-profile-notdir".into(),
                is_dir: false,
                is_symlink: false,
                mtime: old,
            },
        ];
        let stale = stale_profile_names(
            &entries,
            now,
            Duration::from_secs(60 * 60),
            &["qa-browser-profile-3".to_string()],
        );
        // Only #1 survives: #2 too fresh, #3 in the active set, #4 wrong prefix,
        // symlink and non-dir excluded regardless of prefix/age.
        assert_eq!(stale, vec!["qa-browser-profile-1".to_string()]);
    }

    // --- resolve_abs ------------------------------------------------------------------------

    #[test]
    fn resolve_abs_joins_relative_and_keeps_absolute() {
        let root = Path::new("/work/app");
        assert_eq!(
            resolve_abs(root, "shots/app.png"),
            Path::new("/work/app/shots/app.png")
        );
        assert_eq!(
            resolve_abs(root, "/tmp/x.png"),
            Path::new("/tmp/x.png")
        );
    }

    // --- usage --------------------------------------------------------------------------------

    #[test]
    fn usage_mentions_all_flags() {
        let u = usage();
        for flag in [
            "--shot",
            "--actions",
            "--url",
            "--start",
            "--route",
            "--out",
            "--width",
            "--height",
            "--port",
            "--cdp-port",
            "--qa-env",
            "--viewport",
            "--slow-3g",
            "--slow-4g",
            "--cpu-4x",
            "--cpu-throttle",
            "--save-session",
            "--load-session",
            "--keep-open",
            "--sweep",
            "--help",
        ] {
            assert!(u.contains(flag), "usage() missing {flag}");
        }
    }
}
