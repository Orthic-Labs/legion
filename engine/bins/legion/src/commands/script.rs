//! `legion script <skill>/<stem> [args...]` — dispatches to the Rust ports of the
//! legacy `skills/**/scripts/**` (and `skills/designer/engine/**`) Python/JS CLIs,
//! via a static table of already-ported `pub fn run`/`run_cli` entry points under
//! `legion_runtime::wf_port::*`. `legion script --list` prints the table.
//!
//! Each entry wraps a real production I/O adapter (the `Reqwest*`/`Real*` structs
//! the ported modules already define for their own tests' production path), reads
//! stdin/env the same way the legacy script did, and returns that entry's process
//! exit code unchanged.

use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::json;
use std::io::Write;

use legion_runtime::wf_port::{
    r12, r22, r24, r32, w2_016, w2_018, w2_028, w2_029, w2_030, w2_031, w2_032, w2_033, w2_034,
};

/// Reads a file from disk the way Python's `open(path).read()` would,
/// surfacing any I/O error as a `String` for the ported CLI's own error
/// reporting instead of panicking.
struct RealFileReader;

impl w2_031::indexnow::UrlsFileReader for RealFileReader {
    fn read_to_string(&self, path: &str) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    }
}

impl w2_031::indexing_notify::BatchFileReader for RealFileReader {
    fn read_to_string(&self, path: &str) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Args)]
pub struct ScriptArgs {
    /// Print the table of `<skill>/<stem>` scripts with a Rust entry point.
    #[arg(long)]
    pub list: bool,
    /// `<skill>/<stem>` followed by the arguments to pass through to the port.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub rest: Vec<String>,
}

type Entry = fn(&[String]) -> i32;

/// `legion script --list` names, in this order. Keep sorted by skill then stem.
pub const TABLE: &[(&str, Entry)] = &[
    ("designer/hook-admin", designer_hook_admin),
    ("designer/live-accept", designer_live_accept),
    ("designer/live-inject", designer_live_inject),
    ("designer/live-insert", designer_live_insert),
    ("designer/live-poll", designer_live_poll),
    ("designer/live-server", designer_live_server),
    ("seo/bing_webmaster", seo_bing_webmaster),
    ("seo/crux_history", seo_crux_history),
    ("seo/edit", seo_edit),
    ("seo/fetch_page", seo_fetch_page),
    ("seo/ga4_report", seo_ga4_report),
    ("seo/google_auth", seo_google_auth),
    ("seo/gsc_inspect", seo_gsc_inspect),
    ("seo/gsc_query", seo_gsc_query),
    ("seo/gsc_query_v2", seo_gsc_query_v2),
    ("seo/indexing_notify", seo_indexing_notify),
    ("seo/indexnow", seo_indexnow),
    ("seo/keyword_planner", seo_keyword_planner),
    ("seo/nlp_analyze", seo_nlp_analyze),
    ("seo/pagespeed_check", seo_pagespeed_check),
    ("seo/parse_html", seo_parse_html),
    ("seo/seo_closure", seo_seo_closure),
    ("seo/seo_project", seo_seo_project),
    ("seo/site_audit", seo_site_audit),
    ("seo/youtube_search", seo_youtube_search),
];

pub fn run(args: ScriptArgs) -> CommandResult {
    if args.list {
        let names: Vec<&str> = TABLE.iter().map(|(name, _)| *name).collect();
        return Ok(json!({ "__compact": true, "scripts": names }));
    }
    let Some((name, rest)) = args.rest.split_first() else {
        return Err(CommandError::usage(
            "Usage: legion script <skill>/<stem> [args...]\n       legion script --list",
        ));
    };
    match TABLE.iter().find(|(candidate, _)| *candidate == name.as_str()) {
        Some((_, entry)) => {
            let code = entry(rest);
            Ok(json!({ "__exit_code": code }))
        }
        None => Err(CommandError::usage(format!(
            "unknown script: {name} (see `legion script --list`)"
        ))),
    }
}

fn cwd() -> std::path::PathBuf {
    std::env::current_dir().unwrap_or_default()
}

// ---- seo -------------------------------------------------------------

fn seo_seo_closure(args: &[String]) -> i32 {
    w2_033::seo_closure::run(args)
}

fn seo_seo_project(args: &[String]) -> i32 {
    w2_033::seo_project::run(args)
}

fn seo_edit(args: &[String]) -> i32 {
    r32::edit::run(args)
}

fn seo_google_auth(args: &[String]) -> i32 {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    w2_030::google_auth::run(args, &mut stdout, &mut stderr)
}

fn seo_gsc_query(args: &[String]) -> i32 {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    w2_030::gsc_query::run(args, &mut stdout, &mut stderr)
}

fn seo_gsc_query_v2(args: &[String]) -> i32 {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    w2_030::gsc_query_v2::run(args, &mut stdout, &mut stderr)
}

fn seo_gsc_inspect(args: &[String]) -> i32 {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    w2_030::gsc_inspect::run(args, &mut stdout, &mut stderr)
}

fn seo_pagespeed_check(args: &[String]) -> i32 {
    let client = w2_032::pagespeed_check::ReqwestPsiClient;
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    w2_032::pagespeed_check::run(args, &client, &mut stdout, &mut stderr)
}

fn seo_parse_html(args: &[String]) -> i32 {
    let mut file: Option<&str> = None;
    let mut base_url: Option<&str> = None;
    let mut json_output = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--base-url" | "--url" => {
                i += 1;
                base_url = args.get(i).map(String::as_str);
            }
            "--json" | "-j" => json_output = true,
            other => file = Some(other),
        }
        i += 1;
    }
    let (code, out, err) = w2_032::parse_html::run(file, base_url, json_output);
    if !out.is_empty() {
        print!("{out}");
    }
    if !err.is_empty() {
        eprint!("{err}");
    }
    code
}

fn seo_site_audit(args: &[String]) -> i32 {
    let fetcher = w2_034::site_audit::ReqwestFetcher::default();
    w2_034::site_audit::run(&fetcher, args)
}

fn seo_youtube_search(args: &[String]) -> i32 {
    let env_api_key = std::env::var("YOUTUBE_API_KEY").ok();
    let outcome = w2_034::youtube_search::run(args, env_api_key, |key| {
        Box::new(w2_034::youtube_search::ReqwestYouTubeApi::new(key))
    });
    print_cli_outcome(outcome.exit_code, &outcome.stdout, &outcome.stderr)
}

fn seo_crux_history(args: &[String]) -> i32 {
    let client = w2_029::crux_history::ReqwestCruxClient;
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    w2_029::crux_history::run(args, &client, &mut stdout, &mut stderr)
}

fn seo_fetch_page(args: &[String]) -> i32 {
    let fetcher = w2_029::fetch_page::ReqwestFetcher;
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    w2_029::fetch_page::run(args, &fetcher, &mut stdout, &mut stderr)
}

fn seo_ga4_report(args: &[String]) -> i32 {
    let bearer_token = std::env::var("GA4_BEARER_TOKEN").unwrap_or_default();
    let client = w2_029::ga4_report::ReqwestGa4Http::new(bearer_token);
    let config_property = std::env::var("GA4_PROPERTY_ID").ok();
    let outcome = w2_029::ga4_report::run(args, &client, civil_today(), config_property.as_deref());
    print_cli_outcome(outcome.exit_code, &outcome.stdout, &outcome.stderr)
}

fn seo_indexnow(args: &[String]) -> i32 {
    let transport = w2_031::indexnow::ReqwestTransport::new();
    let files = RealFileReader;
    let env_key = std::env::var("INDEXNOW_KEY").ok();
    let outcome = w2_031::indexnow::run(args, &transport, &files, env_key.as_deref());
    if let Some((path, contents)) = &outcome.write_file {
        let _ = std::fs::write(path, contents);
    }
    print_cli_outcome(outcome.exit_code, &outcome.stdout, &outcome.stderr)
}

fn seo_indexing_notify(args: &[String]) -> i32 {
    let bearer_token = std::env::var("GOOGLE_INDEXING_BEARER_TOKEN").unwrap_or_default();
    let client = w2_031::indexing_notify::ReqwestIndexingClient::new(bearer_token);
    let files = RealFileReader;
    let outcome = w2_031::indexing_notify::run(args, &client, &files);
    print_cli_outcome(outcome.exit_code, &outcome.stdout, &outcome.stderr)
}

fn seo_keyword_planner(args: &[String]) -> i32 {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    match w2_031::keyword_planner::build_ads_client() {
        Ok((client, customer_id)) => {
            w2_031::keyword_planner::run(args, &client, &customer_id, &mut stdout, &mut stderr)
        }
        Err(message) => {
            let _ = writeln!(stderr, "{message}");
            1
        }
    }
}

fn seo_nlp_analyze(args: &[String]) -> i32 {
    let transport = w2_031::nlp_analyze::ReqwestNlpTransport;
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    w2_031::nlp_analyze::run(args, &transport, &mut stdout, &mut stderr)
}

fn seo_bing_webmaster(args: &[String]) -> i32 {
    let bwt_args = match parse_bwt_args(args) {
        Ok(a) => a,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let env_key = std::env::var("BING_API_KEY").ok();
    let transport = w2_028::bing_webmaster::ReqwestTransport::default();
    let outcome = w2_028::bing_webmaster::run(&bwt_args, env_key.as_deref(), &transport);
    if let Some(printed) = &outcome.printed {
        println!("{printed}");
    }
    if let Some(usage) = &outcome.usage_error {
        eprintln!("{usage}");
    }
    if let (Some(path), Some(json)) = (bwt_args.out.as_ref(), outcome.written_json.as_ref()) {
        let _ = std::fs::write(path, json);
    }
    outcome.exit_code
}

fn parse_bwt_args(args: &[String]) -> Result<w2_028::bing_webmaster::BwtArgs, String> {
    let mut command = None;
    let mut method = None;
    let mut site = None;
    let mut url = None;
    let mut out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--method" => {
                i += 1;
                method = args.get(i).cloned();
            }
            "--site" => {
                i += 1;
                site = args.get(i).cloned();
            }
            "--url" => {
                i += 1;
                url = args.get(i).cloned();
            }
            "--out" | "--json" => {
                i += 1;
                out = args.get(i).cloned();
            }
            other if command.is_none() => command = Some(other.to_string()),
            other => return Err(format!("unrecognized argument: {other}")),
        }
        i += 1;
    }
    Ok(w2_028::bing_webmaster::BwtArgs {
        command: command.ok_or_else(|| "missing command".to_string())?,
        method,
        site,
        url,
        out,
    })
}

// ---- designer ----------------------------------------------------------

fn designer_live_inject(args: &[String]) -> i32 {
    let cwd = cwd();
    let env_live_config = std::env::var("IMPECCABLE_LIVE_CONFIG").ok();
    w2_018::inject::run(args, &cwd, None, env_live_config.as_deref())
}

fn designer_live_insert(args: &[String]) -> i32 {
    let cwd = cwd();
    let (code, out) = r22::live_insert::run(args, &cwd);
    if !out.is_empty() {
        println!("{out}");
    }
    code
}

fn designer_live_poll(args: &[String]) -> i32 {
    let cwd = cwd();
    r22::live_poll::run(args, &cwd)
}

fn designer_live_accept(args: &[String]) -> i32 {
    let cwd = cwd();
    let (code, out) = w2_016::live_accept::run(args, &cwd);
    if !out.is_empty() {
        println!("{out}");
    }
    code
}

fn designer_live_server(args: &[String]) -> i32 {
    let root = cwd();
    match r24::run(args, &root) {
        r24::RunOutcome::HelpPrinted | r24::RunOutcome::Stopped | r24::RunOutcome::ServerExited => 0,
        r24::RunOutcome::StopFailedNoServer => 1,
        r24::RunOutcome::AlreadyRunning { port, pid } => {
            println!("already running: pid={pid} port={port}");
            0
        }
        r24::RunOutcome::BackgroundStarted { ready, .. } => {
            if ready {
                0
            } else {
                1
            }
        }
    }
}

fn designer_hook_admin(args: &[String]) -> i32 {
    let cwd = cwd();
    let env_kill = std::env::var("IMPECCABLE_HOOK_DISABLED").ok();
    let mut fs = r12::RealFs;
    let outcome = r12::run_cli(&mut fs, &cwd, args, env_kill.as_deref());
    print_cli_outcome(outcome.exit_code, &outcome.stdout, &outcome.stderr)
}

// ---- shared helpers ------------------------------------------------------

fn print_cli_outcome(exit_code: i32, stdout: &str, stderr: &str) -> i32 {
    if !stdout.is_empty() {
        print!("{stdout}");
        let _ = std::io::stdout().flush();
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    exit_code
}

/// `SystemTime::now()` converted to a proleptic-Gregorian civil date, using
/// the inverse of the Howard Hinnant `days_from_civil`/`civil_from_days`
/// algorithm the ported `CivilDate` type itself uses for date arithmetic.
fn civil_today() -> w2_029::ga4_report::CivilDate {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let z = secs.div_euclid(86_400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    w2_029::ga4_report::CivilDate::new(year, m as u32, d as u32)
}
