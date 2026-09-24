//! Port of `qa.mjs`'s `usage()`, `parseArgs()`, `parseViewport()`, `VIEWPORTS`, and `THROTTLE`
//! (packet r54, `src/lib/qa-engine/qa.mjs` lines 11-121).

use std::collections::HashMap;

/// Mirrors the `args` object built by `parseArgs`. Field names match the JS keys; `route`/`out`/
/// `qaEnv`/`width`/`height`/`dpr` keep the same defaults as the JS initializer.
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewportSpec {
    pub width: f64,
    pub height: f64,
    pub dpr: f64,
    pub mobile: bool,
}

/// `VIEWPORTS` preset table (qa.mjs lines 87-91).
pub fn viewport_presets() -> HashMap<&'static str, ViewportSpec> {
    let mut m = HashMap::new();
    m.insert("desktop", ViewportSpec { width: 1440.0, height: 900.0, dpr: 1.0, mobile: false });
    m.insert("tablet", ViewportSpec { width: 768.0, height: 1024.0, dpr: 2.0, mobile: true });
    m.insert("mobile", ViewportSpec { width: 390.0, height: 844.0, dpr: 3.0, mobile: true });
    m
}

/// Port of `parseViewport` (qa.mjs lines 92-98). `v` is the raw `--viewport` value; `None`
/// mirrors the falsy-check `if (!v)`.
pub fn parse_viewport(v: Option<&str>) -> Result<ViewportSpec, String> {
    let v = v.ok_or_else(|| "--viewport needs a value (desktop|tablet|mobile|WxH)".to_string())?;
    if let Some(spec) = viewport_presets().get(v) {
        return Ok(*spec);
    }
    // `/^(\d+)x(\d+)$/` — ASCII digits only, no whitespace, exact match.
    if let Some((w, h)) = v.split_once('x') {
        if !w.is_empty() && !h.is_empty() && w.bytes().all(|b| b.is_ascii_digit()) && h.bytes().all(|b| b.is_ascii_digit()) {
            let width: f64 = w.parse().map_err(|_| format!("bad --viewport: {v} (use desktop|tablet|mobile or 1440x900)"))?;
            let height: f64 = h.parse().map_err(|_| format!("bad --viewport: {v} (use desktop|tablet|mobile or 1440x900)"))?;
            return Ok(ViewportSpec { width, height, dpr: 1.0, mobile: false });
        }
    }
    Err(format!("bad --viewport: {v} (use desktop|tablet|mobile or 1440x900)"))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThrottleProfile {
    pub download_throughput: f64,
    pub upload_throughput: f64,
    pub latency: f64,
}

/// `THROTTLE` table (qa.mjs lines 101-104): DevTools-style bytes/sec + ms latency presets.
pub fn throttle_profile(name: &str) -> Option<ThrottleProfile> {
    match name {
        "slow-3g" => Some(ThrottleProfile { download_throughput: 50.0 * 1000.0, upload_throughput: 50.0 * 1000.0, latency: 400.0 }),
        "slow-4g" => Some(ThrottleProfile { download_throughput: 200.0 * 1000.0, upload_throughput: 94.0 * 1000.0, latency: 150.0 }),
        _ => None,
    }
}

pub const USAGE: &str = r#"Usage:
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
"#;

pub fn usage() -> &'static str {
    USAGE
}

/// Port of `parseArgs` (qa.mjs lines 45-85). Returns `Err` on `Unknown argument: <a>`, matching
/// the JS `throw`. A flag consuming a following value (`argv[++i]`) that runs off the end yields
/// `None`/`NaN`-equivalent, same as JS `argv[++i]` being `undefined`.
pub fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut args = Args::default();
    let mut i = 0usize;
    let next = |i: &mut usize, argv: &[String]| -> Option<String> {
        *i += 1;
        argv.get(*i).cloned()
    };
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "--help" | "-h" => args.help = true,
            "--shot" => args.shot = true,
            "--sweep" => args.sweep = true,
            "--keep-open" => args.keep_open = true,
            "--actions" => args.actions = next(&mut i, argv),
            "--url" => args.url = next(&mut i, argv),
            "--start" => args.start = next(&mut i, argv),
            "--route" => { if let Some(v) = next(&mut i, argv) { args.route = v; } }
            "--out" => { if let Some(v) = next(&mut i, argv) { args.out = v; } }
            "--width" => { if let Some(v) = next(&mut i, argv) { args.width = v.parse().unwrap_or(f64::NAN); } }
            "--height" => { if let Some(v) = next(&mut i, argv) { args.height = v.parse().unwrap_or(f64::NAN); } }
            "--port" => { if let Some(v) = next(&mut i, argv) { args.port = v.parse().unwrap_or(0); } }
            "--cdp-port" => { if let Some(v) = next(&mut i, argv) { args.cdp_port = v.parse().unwrap_or(0); } }
            "--qa-env" => { if let Some(v) = next(&mut i, argv) { args.qa_env = v; } }
            "--viewport" => {
                let v = next(&mut i, argv);
                let p = parse_viewport(v.as_deref())?;
                args.width = p.width;
                args.height = p.height;
                args.dpr = p.dpr;
                args.mobile = p.mobile;
            }
            "--slow-3g" => args.throttle = Some("slow-3g".to_string()),
            "--slow-4g" => args.throttle = Some("slow-4g".to_string()),
            "--cpu-4x" => args.cpu = Some(4.0),
            "--cpu-throttle" => { if let Some(v) = next(&mut i, argv) { args.cpu = Some(v.parse().unwrap_or(f64::NAN)); } }
            "--save-session" => args.save_session = next(&mut i, argv),
            "--load-session" => args.load_session = next(&mut i, argv),
            other => return Err(format!("Unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(args)
}

/// `--qa-env NAME=VALUE` split used by `startServer` (qa.mjs line 303): first `=` splits name
/// from value; a value with no `=` (or empty value) becomes `"1"`, mirroring
/// `valueParts.length ? valueParts.join("=") : "1"`.
pub fn split_qa_env(qa_env: &str) -> Option<(String, String)> {
    let mut parts = qa_env.splitn(2, '=');
    let name = parts.next().unwrap_or("");
    if name.is_empty() {
        return None;
    }
    let value = parts.next();
    Some((name.to_string(), value.map(|v| v.to_string()).unwrap_or_else(|| "1".to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_js_initializer() {
        let a = Args::default();
        assert_eq!(a.route, "/?qa=1");
        assert_eq!(a.out, ".cache/qa-shots/app.png");
        assert_eq!(a.width, 1365.0);
        assert_eq!(a.height, 900.0);
        assert_eq!(a.qa_env, "VITE_APP_BROWSER_QA=1");
        assert!(!a.shot && !a.keep_open && !a.mobile);
        assert_eq!(a.dpr, 1.0);
    }

    #[test]
    fn shot_and_out_flags_parse() {
        let a = parse_args(&["--shot".into(), "--out".into(), "x.png".into()]).unwrap();
        assert!(a.shot);
        assert_eq!(a.out, "x.png");
    }

    #[test]
    fn unknown_flag_errors_like_js_throw() {
        let e = parse_args(&["--bogus".into()]).unwrap_err();
        assert_eq!(e, "Unknown argument: --bogus");
    }

    #[test]
    fn viewport_preset_sets_all_four_fields() {
        let a = parse_args(&["--viewport".into(), "mobile".into()]).unwrap();
        assert_eq!(a.width, 390.0);
        assert_eq!(a.height, 844.0);
        assert_eq!(a.dpr, 3.0);
        assert!(a.mobile);
    }

    #[test]
    fn viewport_wxh_parses_custom_size() {
        let p = parse_viewport(Some("1024x768")).unwrap();
        assert_eq!(p, ViewportSpec { width: 1024.0, height: 768.0, dpr: 1.0, mobile: false });
    }

    #[test]
    fn viewport_bad_value_errors() {
        let e = parse_viewport(Some("nope")).unwrap_err();
        assert!(e.contains("bad --viewport: nope"));
    }

    #[test]
    fn viewport_missing_value_errors() {
        let e = parse_viewport(None).unwrap_err();
        assert!(e.contains("--viewport needs a value"));
    }

    #[test]
    fn viewport_rejects_non_digit_like_js_regex() {
        assert!(parse_viewport(Some("12x3.5")).is_err());
        assert!(parse_viewport(Some("x400")).is_err());
        assert!(parse_viewport(Some("400x")).is_err());
    }

    #[test]
    fn slow_3g_and_slow_4g_flags_set_throttle_name() {
        let a = parse_args(&["--slow-3g".into()]).unwrap();
        assert_eq!(a.throttle.as_deref(), Some("slow-3g"));
        let b = parse_args(&["--slow-4g".into()]).unwrap();
        assert_eq!(b.throttle.as_deref(), Some("slow-4g"));
    }

    #[test]
    fn cpu_4x_shorthand_sets_cpu_to_4() {
        let a = parse_args(&["--cpu-4x".into()]).unwrap();
        assert_eq!(a.cpu, Some(4.0));
    }

    #[test]
    fn throttle_table_matches_js_constants() {
        let p = throttle_profile("slow-3g").unwrap();
        assert_eq!(p.download_throughput, 50000.0);
        assert_eq!(p.upload_throughput, 50000.0);
        assert_eq!(p.latency, 400.0);
        let p4 = throttle_profile("slow-4g").unwrap();
        assert_eq!(p4.download_throughput, 200000.0);
        assert_eq!(p4.upload_throughput, 94000.0);
        assert_eq!(p4.latency, 150.0);
        assert!(throttle_profile("fast").is_none());
    }

    #[test]
    fn qa_env_split_defaults_value_to_one() {
        assert_eq!(split_qa_env("FOO"), Some(("FOO".to_string(), "1".to_string())));
        assert_eq!(split_qa_env("FOO="), Some(("FOO".to_string(), "1".to_string())));
        assert_eq!(split_qa_env("FOO=bar"), Some(("FOO".to_string(), "bar".to_string())));
        assert_eq!(split_qa_env("FOO=bar=baz"), Some(("FOO".to_string(), "bar=baz".to_string())));
    }
}
