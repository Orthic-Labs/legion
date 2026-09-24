//! Port of `qa.mjs`'s `main()` (lines 728-764) plus the small pure helpers it inlines
//! (`abs`, `ensureParent`, `needsCdpShot`, URL assembly). The orchestration below wires the
//! traits from sibling modules to real I/O (`std::process::Command`, `std::net::TcpStream`,
//! `ChromeSession`); the decision logic that JS inlines into `main()` is pulled out as pure,
//! independently tested functions.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::args::{self, Args};
use super::browser::{self, FsProbe};
use super::profiles::{self, DirEntry, ProfileDir};
use super::ports::{self, HttpAttempt, HttpProbe, PortProbe};

/// `abs(path)` (qa.mjs lines 206-208): resolve relative to `root` unless already absolute.
pub fn abs(root: &str, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(root).join(p)
    }
}

/// `needsCdpShot` (qa.mjs line 749): any of throttle/cpu/mobile/session flags force the CDP
/// screenshot path instead of the fast `--screenshot=` flag.
pub fn needs_cdp_shot(args: &Args) -> bool {
    args.throttle.is_some() || args.cpu.is_some() || args.mobile || args.load_session.is_some() || args.save_session.is_some()
}

/// Resolves the URL to open (qa.mjs line 746): `args.url` wins, else
/// `http://127.0.0.1:<serverPort><route>`.
pub fn resolve_url(args: &Args, server_port: Option<u32>) -> Result<String, String> {
    if let Some(u) = &args.url {
        return Ok(u.clone());
    }
    let port = server_port.ok_or("resolve_url: server_port required when --url is absent")?;
    Ok(format!("http://127.0.0.1:{port}{route}", route = args.route))
}

/// What `main()` decides to do for a given parsed `Args`, before touching any I/O. Mirrors the
/// branch structure of qa.mjs lines 730-758 without performing the actions.
#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    Sweep { older_than_ms: f64 },
    Usage,
    Run { needs_server: bool, needs_cdp_shot: bool, do_shot: bool, do_actions: bool },
}

/// Port of the branch structure at the top of `main()` (qa.mjs lines 730-753).
pub fn plan(args: &Args) -> Plan {
    if args.sweep {
        return Plan::Sweep { older_than_ms: profiles::EXPLICIT_SWEEP_OLDER_THAN_MS };
    }
    if args.help || (!args.shot && args.actions.is_none()) {
        return Plan::Usage;
    }
    Plan::Run {
        needs_server: args.url.is_none(),
        needs_cdp_shot: needs_cdp_shot(args),
        do_shot: args.shot,
        do_actions: args.actions.is_some(),
    }
}

// ---- Production I/O adapters -------------------------------------------------------------

struct StdFsProbe;
impl FsProbe for StdFsProbe {
    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

struct TcpPortProbe;
impl PortProbe for TcpPortProbe {
    fn is_taken(&mut self, port: u32) -> bool {
        TcpStream::connect(("127.0.0.1", port as u16)).is_ok()
    }
}

struct ReqwestHttpProbe {
    started: Instant,
}
impl HttpProbe for ReqwestHttpProbe {
    fn attempt(&mut self, url: &str) -> HttpAttempt {
        match reqwest::blocking::get(url) {
            Ok(res) if res.status().is_success() => HttpAttempt::Ok,
            Ok(res) => HttpAttempt::NotOk { status: res.status().as_u16(), status_text: res.status().canonical_reason().unwrap_or("").to_string() },
            Err(e) => HttpAttempt::Error(e.to_string()),
        }
    }
    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
    fn sleep(&mut self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

struct CacheDirProbe {
    cache_dir: PathBuf,
}
impl ProfileDir for CacheDirProbe {
    fn list(&self) -> Result<Vec<DirEntry>, ()> {
        let rd = std::fs::read_dir(&self.cache_dir).map_err(|_| ())?;
        let mut out = Vec::new();
        for entry in rd.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime_ms = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as f64).unwrap_or(0.0);
            out.push(DirEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                is_dir: meta.is_dir(),
                is_symlink: meta.is_symlink(),
                mtime_ms,
            });
        }
        Ok(out)
    }
    fn remove(&mut self, name: &str) {
        let _ = std::fs::remove_dir_all(self.cache_dir.join(name));
    }
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)
}

/// Port of `main()` (qa.mjs lines 728-764): parses argv, dispatches per `plan()`, and returns
/// the process exit code (`0` on success, `1` on any error — mirrors the top-level
/// `main().catch(...); process.exit(1)`).
pub fn run(argv: &[String], repo_root: &str) -> i32 {
    let args = match args::parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[qa] {e}");
            return 1;
        }
    };
    match plan(&args) {
        Plan::Sweep { older_than_ms } => {
            let mut dir = CacheDirProbe { cache_dir: abs(repo_root, ".cache") };
            let removed = profiles::sweep_stale_profiles(&mut dir, older_than_ms, now_ms(), &[]);
            if removed == 0 {
                println!("[qa] no abandoned browser profiles under .cache");
            } else {
                println!("[qa] swept {removed} abandoned browser profile{}", if removed == 1 { "" } else { "s" });
            }
            0
        }
        Plan::Usage => {
            println!("{}", args::usage());
            0
        }
        Plan::Run { needs_server, needs_cdp_shot, do_shot, do_actions } => {
            // Startup sweep (qa.mjs `wireCleanup` -> `sweepStaleProfiles()` with the 1h default).
            let mut dir = CacheDirProbe { cache_dir: abs(repo_root, ".cache") };
            profiles::sweep_stale_profiles(&mut dir, profiles::STARTUP_OLDER_THAN_MS, now_ms(), &[]);

            let fs = StdFsProbe;
            let server_port = if needs_server {
                let mut probe = TcpPortProbe;
                match ports::free_port(&mut probe, if args.port != 0 { args.port } else { 1422 }) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        eprintln!("[qa] {e}");
                        return 1;
                    }
                }
            } else {
                None
            };
            let url = match resolve_url(&args, server_port) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("[qa] {e}");
                    return 1;
                }
            };
            let browser_path = match browser::find_browser(&fs, cfg!(target_os = "windows")) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[qa] {e}");
                    return 1;
                }
            };
            let server = if needs_server {
                match start_server_process(&args, repo_root, server_port.unwrap()) {
                    Ok(child) => Some(child),
                    Err(e) => {
                        eprintln!("[qa] {e}");
                        return 1;
                    }
                }
            } else {
                None
            };
            let mut exit_code = 0;
            if needs_server {
                let mut probe = ReqwestHttpProbe { started: Instant::now() };
                if let Err(e) = ports::wait_for_http(&mut probe, &url, 30000) {
                    eprintln!("[qa] {e}");
                    exit_code = 1;
                }
            }
            if exit_code == 0 {
                if do_shot && !needs_cdp_shot {
                    // `runShot` fast path (qa.mjs lines 602-622): the fire-and-forget
                    // `--screenshot=` flag, no CDP session needed.
                    if let Err(e) = run_shot_fast(&args, &url, &browser_path, repo_root) {
                        eprintln!("[qa] {e}");
                        exit_code = 1;
                    } else {
                        println!("[qa] url {url}");
                        println!("[qa] screenshot {}", abs(repo_root, &args.out).display());
                    }
                } else if do_shot || do_actions {
                    // `runShotCdp`/`runActions` (qa.mjs lines 627-726): needs a real CDP session,
                    // constructed here via `headless_chrome`. See `chrome_session`'s module doc
                    // for the PORTED-PARTIAL gaps in that wiring (network throttling, cookies,
                    // synthetic vs. native input events).
                    match run_cdp_session(&args, &url, &browser_path, repo_root, do_shot, do_actions) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("[qa] {e}");
                            exit_code = 1;
                        }
                    }
                }
            }
            if let Some(mut child) = server {
                if !args.keep_open {
                    let _ = child.kill();
                }
            }
            exit_code
        }
    }
}

fn run_shot_fast(args: &Args, url: &str, browser_path: &str, repo_root: &str) -> Result<(), String> {
    // `runShot` (qa.mjs lines 602-622): headless one-shot screenshot via Chrome's own
    // `--screenshot=` flag, no CDP round-trip.
    let out = abs(repo_root, &args.out);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let profile = abs(repo_root, &format!(".cache/qa-browser-profile-{}", now_ms() as u64));
    std::fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
    let status = Command::new(browser_path)
        .args([
            "--headless=new",
            "--disable-gpu",
            "--no-default-browser-check",
            "--no-first-run",
            "--force-device-scale-factor=1",
        ])
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--window-size={},{}", args.width as i64, args.height as i64))
        .arg(format!("--screenshot={}", out.display()))
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&profile);
    if !status.success() && !out.exists() {
        return Err(format!("Headless screenshot failed with exit code {:?}.", status.code()));
    }
    Ok(())
}

fn run_cdp_session(args: &Args, url: &str, browser_path: &str, repo_root: &str, do_shot: bool, do_actions: bool) -> Result<(), String> {
    use headless_chrome::{Browser, LaunchOptions};
    use std::ffi::OsStr;

    let launch_options = LaunchOptions::default_builder()
        .path(Some(PathBuf::from(browser_path)))
        .headless(true)
        .window_size(Some((args.width as u32, args.height as u32)))
        .args(vec![OsStr::new("--no-default-browser-check"), OsStr::new("--no-first-run")])
        .build()
        .map_err(|e| e.to_string())?;
    let browser = Browser::new(launch_options).map_err(|e| e.to_string())?;
    let tab = browser.new_tab().map_err(|e| e.to_string())?;
    let mut session = super::chrome_session::ChromeSession::new(tab);

    let conditions = super::session_client::Conditions {
        width: args.width,
        height: args.height,
        dpr: args.dpr,
        mobile: args.mobile,
        throttle: args.throttle.as_deref().and_then(args::throttle_profile),
        cpu: args.cpu,
    };
    session.apply_conditions(&conditions)?;
    if let Some(load_path) = &args.load_session {
        let mut fs = FsSessionFile { repo_root: repo_root.to_string() };
        let data = super::session::read_session_file(&fs, load_path)?;
        session.load_session(&data)?;
        let _ = &mut fs;
    }
    session.navigate(url)?;

    if do_shot {
        let out = abs(repo_root, &args.out);
        let file = session.capture(&out.to_string_lossy())?;
        println!("[qa] url {url}");
        println!("[qa] screenshot {file}");
    }
    if do_actions {
        let actions_path = args.actions.as_deref().ok_or("--actions path missing")?;
        let abs_path = abs(repo_root, actions_path);
        let raw = std::fs::read_to_string(&abs_path).map_err(|e| e.to_string())?;
        let parsed = super::actions::parse_actions(&raw)?;
        for (i, action) in parsed.iter().enumerate() {
            let line = super::actions::run_action(&mut session, action, i)?;
            println!("{line}");
        }
        println!("[qa] actions complete {}", abs_path.display());
    }
    if let Some(save_path) = &args.save_session {
        let data = session.save_session()?;
        let mut fs = FsSessionFile { repo_root: repo_root.to_string() };
        super::session::write_session_file(&mut fs, save_path, &data)?;
        println!("[qa] session saved {}", abs(repo_root, save_path).display());
    }
    Ok(())
}

struct FsSessionFile {
    repo_root: String,
}
impl super::session::SessionFile for FsSessionFile {
    fn read(&self, path: &str) -> Result<String, String> {
        std::fs::read_to_string(abs(&self.repo_root, path)).map_err(|e| e.to_string())
    }
    fn write(&mut self, path: &str, contents: &str) -> Result<(), String> {
        let p = abs(&self.repo_root, path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(p, contents).map_err(|e| e.to_string())
    }
}

fn start_server_process(args: &Args, repo_root: &str, port: u32) -> Result<std::process::Child, String> {
    // `startServer` (qa.mjs lines 300-324): `--start` runs as a shell command with `{port}`
    // substituted; otherwise the default Vite launch (argv-only, no shell).
    let mut cmd = if let Some(start) = &args.start {
        let command = start.replace("{port}", &port.to_string());
        let mut c = Command::new(if cfg!(windows) { "cmd" } else { "sh" });
        if cfg!(windows) {
            c.arg("/C").arg(&command);
        } else {
            c.arg("-c").arg(&command);
        }
        c
    } else {
        // `defaultStartCommand` launches Vite via `process.execPath` (the Node binary running
        // qa.mjs itself); this Rust binary has no such notion, so it resolves a `node` on PATH
        // the way any other Vite-launching tool in this repo would.
        let vite_path = Path::new(repo_root).join("node_modules/vite/bin/vite.js");
        let launch = browser::default_start_command("node", repo_root, port, vite_path.exists())?;
        let mut c = Command::new(&launch.command);
        c.args(&launch.args);
        c
    };
    if let Some((name, value)) = args::split_qa_env(&args.qa_env) {
        cmd.env(name, value);
    }
    cmd.current_dir(repo_root).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.spawn().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_leaves_absolute_paths_untouched() {
        assert_eq!(abs("/repo", "/etc/x"), PathBuf::from("/etc/x"));
    }

    #[test]
    fn abs_resolves_relative_against_root() {
        assert_eq!(abs("/repo", ".cache/x.png"), PathBuf::from("/repo/.cache/x.png"));
    }

    #[test]
    fn needs_cdp_shot_true_for_each_condition() {
        let mut a = Args::default();
        assert!(!needs_cdp_shot(&a));
        a.throttle = Some("slow-3g".into());
        assert!(needs_cdp_shot(&a));
        let mut a = Args::default();
        a.cpu = Some(4.0);
        assert!(needs_cdp_shot(&a));
        let mut a = Args::default();
        a.mobile = true;
        assert!(needs_cdp_shot(&a));
        let mut a = Args::default();
        a.load_session = Some("s.json".into());
        assert!(needs_cdp_shot(&a));
        let mut a = Args::default();
        a.save_session = Some("s.json".into());
        assert!(needs_cdp_shot(&a));
    }

    #[test]
    fn resolve_url_prefers_explicit_url() {
        let mut a = Args::default();
        a.url = Some("http://x/y".into());
        assert_eq!(resolve_url(&a, None).unwrap(), "http://x/y");
    }

    #[test]
    fn resolve_url_builds_from_port_and_route() {
        let a = Args::default();
        assert_eq!(resolve_url(&a, Some(1422)).unwrap(), "http://127.0.0.1:1422/?qa=1");
    }

    #[test]
    fn resolve_url_errors_without_port_or_url() {
        let a = Args::default();
        assert!(resolve_url(&a, None).is_err());
    }

    #[test]
    fn plan_sweep_wins_over_everything_else() {
        let mut a = Args::default();
        a.sweep = true;
        a.shot = true;
        assert_eq!(plan(&a), Plan::Sweep { older_than_ms: profiles::EXPLICIT_SWEEP_OLDER_THAN_MS });
    }

    #[test]
    fn plan_usage_when_no_shot_or_actions() {
        assert_eq!(plan(&Args::default()), Plan::Usage);
    }

    #[test]
    fn plan_usage_when_help_even_with_shot() {
        let mut a = Args::default();
        a.help = true;
        a.shot = true;
        assert_eq!(plan(&a), Plan::Usage);
    }

    #[test]
    fn plan_run_reflects_needs_server_and_cdp_shot() {
        let mut a = Args::default();
        a.shot = true;
        a.mobile = true;
        assert_eq!(plan(&a), Plan::Run { needs_server: true, needs_cdp_shot: true, do_shot: true, do_actions: false });
        a.url = Some("http://x".into());
        assert_eq!(plan(&a), Plan::Run { needs_server: false, needs_cdp_shot: true, do_shot: true, do_actions: false });
    }
}
