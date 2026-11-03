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
    m.insert(
        "desktop",
        ViewportSpec {
            width: 1440.0,
            height: 900.0,
            dpr: 1.0,
            mobile: false,
        },
    );
    m.insert(
        "tablet",
        ViewportSpec {
            width: 768.0,
            height: 1024.0,
            dpr: 2.0,
            mobile: true,
        },
    );
    m.insert(
        "mobile",
        ViewportSpec {
            width: 390.0,
            height: 844.0,
            dpr: 3.0,
            mobile: true,
        },
    );
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
        if !w.is_empty()
            && !h.is_empty()
            && w.bytes().all(|b| b.is_ascii_digit())
            && h.bytes().all(|b| b.is_ascii_digit())
        {
            let width: f64 = w.parse().map_err(|_| {
                format!("bad --viewport: {v} (use desktop|tablet|mobile or 1440x900)")
            })?;
            let height: f64 = h.parse().map_err(|_| {
                format!("bad --viewport: {v} (use desktop|tablet|mobile or 1440x900)")
            })?;
            return Ok(ViewportSpec {
                width,
                height,
                dpr: 1.0,
                mobile: false,
            });
        }
    }
    Err(format!(
        "bad --viewport: {v} (use desktop|tablet|mobile or 1440x900)"
    ))
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
        "slow-3g" => Some(ThrottleProfile {
            download_throughput: 50.0 * 1000.0,
            upload_throughput: 50.0 * 1000.0,
            latency: 400.0,
        }),
        "slow-4g" => Some(ThrottleProfile {
            download_throughput: 200.0 * 1000.0,
            upload_throughput: 94.0 * 1000.0,
            latency: 150.0,
        }),
        _ => None,
    }
}

pub const USAGE: &str = r#"Usage:
  qa.mjs --shot [--route "/?qa=1"] [--out ".cache/qa-shots/app.png"]
  qa.mjs --actions actions.json [--route "/?qa=1"]
  qa.mjs --url "http://127.0.0.1:3000/?qa=1" --actions actions.json

Options:
  --shot                 Capture one viewport-only app screenshot.
  --actions <file>       JSON action file for hover/click/assert/screenshot/eval QA. An eval action
                         also prints `[qa] N:eval value <json>` on its own line (compact JSON,
                         64 KiB max; larger values print {"truncated":true,"bytes":n}).
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
  --save-session <file>  After the run, save cookies + localStorage to <file> (cookiesCaptured: true).
  --load-session <file>  Restore cookies before the first navigation, then localStorage, then reload.
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
            "--route" => {
                if let Some(v) = next(&mut i, argv) {
                    args.route = v;
                }
            }
            "--out" => {
                if let Some(v) = next(&mut i, argv) {
                    args.out = v;
                }
            }
            "--width" => {
                if let Some(v) = next(&mut i, argv) {
                    args.width = v.parse().unwrap_or(f64::NAN);
                }
            }
            "--height" => {
                if let Some(v) = next(&mut i, argv) {
                    args.height = v.parse().unwrap_or(f64::NAN);
                }
            }
            "--port" => {
                if let Some(v) = next(&mut i, argv) {
                    args.port = v.parse().unwrap_or(0);
                }
            }
            "--cdp-port" => {
                let v = next(&mut i, argv)
                    .ok_or_else(|| "--cdp-port needs a value (1-65535)".to_string())?;
                args.cdp_port = parse_cdp_port(&v)?;
            }
            "--qa-env" => {
                if let Some(v) = next(&mut i, argv) {
                    args.qa_env = v;
                }
            }
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
            "--cpu-throttle" => {
                if let Some(v) = next(&mut i, argv) {
                    args.cpu = Some(v.parse().unwrap_or(f64::NAN));
                }
            }
            "--save-session" => args.save_session = next(&mut i, argv),
            "--load-session" => args.load_session = next(&mut i, argv),
            other => return Err(format!("Unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(args)
}

/// Largest TCP port number, the upper bound for `--cdp-port`.
pub const MAX_TCP_PORT: u32 = 65535;

/// Parses `--cdp-port`: ASCII digits only, at most `MAX_TCP_PORT`. `0` is accepted and, like an
/// omitted flag, means "first free port from 9222" (qa.mjs `args.cdpPort || freePort(9222)`).
/// Anything else is a usage error, never a silent fallback to the default.
pub fn parse_cdp_port(raw: &str) -> Result<u32, String> {
    let bad = || format!("bad --cdp-port: {raw} (use a port from 1 to 65535, or omit the flag)");
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let port: u32 = raw.parse().map_err(|_| bad())?;
    if port > MAX_TCP_PORT {
        return Err(bad());
    }
    Ok(port)
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
    let value = parts.next().filter(|v| !v.is_empty());
    Some((
        name.to_string(),
        value
            .map(|v| v.to_string())
            .unwrap_or_else(|| "1".to_string()),
    ))
}
