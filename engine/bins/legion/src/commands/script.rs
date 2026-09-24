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

use legion_handoff::{l1_port, l1b_port};
use legion_provider_sdk::l1b_port::execution as coder_execution;
use legion_runtime::p9_skills;
use legion_runtime::wf_port::{
    r00, r02, r03, r04, r05, r07, r08, r12, r18, r22, r24, r32, r37, r46, w2_005, w2_010, w2_016,
    w2_017, w2_018, w2_019, w2_020, w2_023, w2_028, w2_029, w2_030, w2_031, w2_032, w2_033,
    w2_034, w2_044,
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
    ("alchemist/parse_events", alchemist_parse_events),
    ("alchemist/viewer", alchemist_viewer),
    ("brand-identity/color-check", brand_identity_color_check),
    ("coder/api-worker", coder_api_worker),
    ("covenant/validate-external-review-packet", covenant_validate_external_review_packet),
    ("designer/context", designer_context),
    ("designer/context-signals", designer_context_signals),
    ("designer/critique-storage", designer_critique_storage),
    ("designer/detect", designer_detect),
    ("designer/detect-csp", designer_detect_csp),
    ("designer/export-deck-pptx", designer_export_deck_pptx),
    ("designer/export-deck-stage-pdf", designer_export_deck_stage_pdf),
    ("designer/fetch-images", designer_fetch_images),
    ("designer/gen-deck-thumbs", designer_gen_deck_thumbs),
    ("designer/hook-admin", designer_hook_admin),
    ("designer/live", designer_live),
    ("designer/live-accept", designer_live_accept),
    ("designer/live-commit-manual-edits", designer_live_commit_manual_edits),
    ("designer/live-complete", designer_live_complete),
    ("designer/live-inject", designer_live_inject),
    ("designer/live-insert", designer_live_insert),
    ("designer/live-poll", designer_live_poll),
    ("designer/live-resume", designer_live_resume),
    ("designer/live-server", designer_live_server),
    ("designer/live-status", designer_live_status),
    ("designer/live-target", designer_live_target),
    ("designer/live-wrap", designer_live_wrap),
    ("designer/narrate-pipeline", designer_narrate_pipeline),
    ("designer/palette", designer_palette),
    ("designer/render-video", designer_render_video),
    ("designer/render-video-seek", designer_render_video_seek),
    ("designer/tts-doubao", designer_tts_doubao),
    ("designer/verify", designer_verify),
    ("dispatch/validate-dispatch", dispatch_validate_dispatch),
    ("handoff/transcript-handoff", handoff_transcript_handoff),
    ("handoff/validate-handoff", handoff_validate_handoff),
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
    ("seo/provider_registry", seo_provider_registry),
    ("seo/question_inventory", seo_question_inventory),
    ("seo/query_ownership", seo_query_ownership),
    ("seo/rank_tracker", seo_rank_tracker),
    ("seo/render_gap", seo_render_gap),
    ("seo/search_ops", seo_search_ops),
    ("seo/seo_closure", seo_seo_closure),
    ("seo/seo_project", seo_seo_project),
    ("seo/site_audit", seo_site_audit),
    ("seo/google_report", seo_google_report),
    ("seo/templated_metadata", seo_templated_metadata),
    ("seo/youtube_search", seo_youtube_search),
    ("tasklist/validate-tasklist", tasklist_validate_tasklist),
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

/// Walks up from `cwd()` looking for a `skills/` directory (repo root), so ports of scripts
/// that load a fixed path relative to their own script location (e.g.
/// `skills/seo/config/provider-registry.json`) can find it regardless of the caller's cwd.
/// Falls back to `cwd()` itself if none is found.
fn find_skills_root() -> std::path::PathBuf {
    let mut dir = cwd();
    loop {
        if dir.join("skills").is_dir() {
            return dir;
        }
        if !dir.pop() {
            return cwd();
        }
    }
}

// ---- alchemist ---------------------------------------------------------

fn alchemist_parse_events(args: &[String]) -> i32 {
    let mut stdin_text = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut stdin_text);
    let read_file = |path: &str| -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    };
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    p9_skills::alchemist::run(args, &stdin_text, &read_file, &mut stdout, &mut stderr)
}

fn alchemist_viewer(args: &[String]) -> i32 {
    let home_dir = dirs_home();
    let env_run_dir = std::env::var("ALCHEMIST_RUN_DIR").ok();
    p9_skills::alchemist_viewer::run(args, &home_dir, env_run_dir.as_deref())
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(cwd)
}

// ---- brand-identity ------------------------------------------------------

fn brand_identity_color_check(args: &[String]) -> i32 {
    p9_skills::brand_identity::run(args)
}

// ---- covenant --------------------------------------------------------

fn covenant_validate_external_review_packet(args: &[String]) -> i32 {
    w2_005::run(args)
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

fn seo_provider_registry(args: &[String]) -> i32 {
    let registry_path = find_skills_root().join("skills/seo/config/provider-registry.json");
    let registry_json = match std::fs::read_to_string(&registry_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: could not read {}: {e}", registry_path.display());
            return 2;
        }
    };
    w2_032::provider_registry::run(args, &registry_json)
}

fn seo_question_inventory(args: &[String]) -> i32 {
    w2_032::question_inventory::run(args)
}

fn seo_query_ownership(args: &[String]) -> i32 {
    w2_032::query_ownership::run(args)
}

fn seo_templated_metadata(args: &[String]) -> i32 {
    w2_034::templated_metadata::run(args)
}

fn seo_render_gap(args: &[String]) -> i32 {
    let raw = p9_skills::render_gap::ReqwestRawFetcher;
    let rendered = p9_skills::render_gap::ChromeRenderedFetcher;
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    p9_skills::render_gap::run(args, &raw, &rendered, &mut stdout, &mut stderr)
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

fn seo_rank_tracker(args: &[String]) -> i32 {
    w2_033::rank_tracker::run_argv(args)
}

fn seo_search_ops(args: &[String]) -> i32 {
    w2_033::search_ops::run_argv(args)
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

/// Real [`w2_020::live_cli::ProcessRunner`] for `live.mjs`'s
/// `ensureServerRunning`: runs `live-server.mjs --background` in-process
/// (mirroring the sibling `designer/live-server` entry) and hands back the
/// `server.json` connection record it writes, the same JSON shape the JS's
/// `runScript` would have captured from the child's stdout.
struct RealLiveServerRunner;

impl w2_020::live_cli::ProcessRunner for RealLiveServerRunner {
    fn start_live_server(&self, cwd: &std::path::Path) -> String {
        let _ = r24::run(&["--background".to_string()], cwd);
        w2_016::impeccable_paths::read_live_server_info(cwd)
            .map(|info| info.raw.to_string())
            .unwrap_or_default()
    }
}

fn designer_live(args: &[String]) -> i32 {
    let cwd = cwd();
    let runner = RealLiveServerRunner;
    let (code, out) = w2_020::live_cli::live_cli(&runner, &cwd, args);
    if !out.is_empty() {
        println!("{out}");
    }
    code
}

fn designer_live_complete(args: &[String]) -> i32 {
    let cwd = cwd();
    let poster = w2_017::complete::ReqwestPoster::new();
    let (code, out) = w2_017::complete::completion_cli(&poster, &cwd, args);
    if !out.is_empty() {
        println!("{out}");
    }
    code
}

fn designer_live_resume(args: &[String]) -> i32 {
    let cwd = cwd();
    let (code, out) = w2_019::resume::run(&cwd, args);
    if !out.is_empty() {
        println!("{out}");
    }
    code
}

fn designer_live_status(_args: &[String]) -> i32 {
    let cwd = cwd();
    let env = w2_019::live_status::HttpStatusEnv::new(&cwd);
    let payload = w2_019::live_status::run(&env);
    println!("{payload}");
    0
}

fn designer_live_target(args: &[String]) -> i32 {
    let cwd = cwd();
    match w2_019::live_target::run(&cwd, args) {
        w2_019::live_target::RunOutcome::Resolved(resolution) => {
            let payload = json!({
                "originalCwd": resolution.original_cwd,
                "projectRoot": resolution.project_root,
                "targetPath": resolution.target_path,
                "absoluteTargetPath": resolution.absolute_target_path,
                "targetOptions": resolution.target_options,
            });
            println!("{payload}");
            0
        }
        w2_019::live_target::RunOutcome::ArgError(message) => {
            eprintln!("{message}");
            1
        }
    }
}

fn designer_live_wrap(args: &[String]) -> i32 {
    let cwd = cwd();
    let env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let (code, out) = w2_020::wrap_cli::wrap_cli(args, &cwd, &env);
    if !out.is_empty() {
        println!("{out}");
    }
    code
}

fn designer_live_commit_manual_edits(args: &[String]) -> i32 {
    let cwd = cwd();
    let env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let (code, out) = r18::commit_cli::run_cli(args, cwd, &env);
    if !out.is_empty() {
        println!("{out}");
    }
    code
}

fn designer_hook_admin(args: &[String]) -> i32 {
    let cwd = cwd();
    let env_kill = std::env::var("IMPECCABLE_HOOK_DISABLED").ok();
    let mut fs = r12::RealFs;
    let outcome = r12::run_cli(&mut fs, &cwd, args, env_kill.as_deref());
    print_cli_outcome(outcome.exit_code, &outcome.stdout, &outcome.stderr)
}

/// Port of `context.mjs`'s CLI: argv parse -> target selection -> load
/// context -> directive block. The `computeUpdateDirective` skill
/// self-update network poll is intentionally skipped (`update_directive =
/// None`) — it needs the running skill's own install directory, which this
/// dispatcher (invoked as `legion script designer/context`, not as
/// `node <skill>/scripts/context.mjs`) has no equivalent of; documented as
/// a gap in `r04`'s own finish note (`read_local_skill_version`).
/// Port of `skills/coder/scripts/api-worker.py`'s `main()` (delegates
/// unmodified to `src/lib/coder-api-worker/api-worker.py`, whose `argparse`
/// CLI is already ported as `legion_provider_sdk::l1b_port::execution::run`).
fn coder_api_worker(args: &[String]) -> i32 {
    let runner = coder_execution::RealProcessRunner;
    coder_execution::run(args, &runner)
}

/// `%Y-%m-%d` for today (UTC), matching Python's `datetime.now().strftime(...)`
/// closely enough for the paste-prompt's evidence-path fragment.
fn today_ymd() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64 + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Port of `skills/handoff/scripts/validate-handoff.py`'s `main()`.
fn handoff_validate_handoff(args: &[String]) -> i32 {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = l1b_port::run(args, &mut stdout, &mut stderr);
    print_cli_outcome(code, &String::from_utf8_lossy(&stdout), &String::from_utf8_lossy(&stderr))
}

/// Port of `skills/handoff/scripts/transcript-handoff.py`'s `main()`
/// (`bootstrap`/`continuity` subcommands).
fn handoff_transcript_handoff(args: &[String]) -> i32 {
    let today = today_ymd();
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let runner = l1_port::RealContinuityRunner;
    let env = l1_port::RunEnv {
        home,
        cwd: cwd(),
        today,
        env_membrane_bin: std::env::var("MEMBRANE_BIN").ok(),
        runner: &runner,
    };
    let mut stdout = Vec::new();
    let code = l1_port::run(args, &env, &mut stdout);
    print_cli_outcome(code, &String::from_utf8_lossy(&stdout), "")
}

fn designer_context(args: &[String]) -> i32 {
    let cwd = cwd();
    let out = r04::cli::run_cli(args, &cwd, "context", None);
    print_cli_outcome(out.exit_code, &out.stdout, "")
}

/// Port of `context-signals.mjs`'s `cli()`: gather signals for `cwd` and
/// print them as JSON, matching `JSON.stringify(signals, null, 2)`.
fn designer_context_signals(_args: &[String]) -> i32 {
    let cwd = cwd();
    let s = w2_010::context_signals::gather_signals(&cwd);
    let critique_latest = s.critique_latest.as_ref().map(|c| {
        json!({
            "slug": c.slug,
            "score": c.score,
            "p0": c.p0,
            "p1": c.p1,
            "timestamp": c.timestamp,
            "file": c.file,
        })
    });
    let out = json!({
        "setup": {
            "hasProduct": s.setup.has_product,
            "productPath": s.setup.product_path,
            "hasDesign": s.setup.has_design,
            "designPath": s.setup.design_path,
            "hasCode": s.setup.has_code,
            "register": s.setup.register,
        },
        "critique": { "latest": critique_latest },
        "git": {
            "isRepo": s.git.is_repo,
            "branch": s.git.branch,
            "base": s.git.base,
            "changedFiles": s.git.changed_files,
            "changedCount": s.git.changed_count,
        },
        "devServer": { "running": s.dev_server.running, "ports": s.dev_server.ports },
        "scan": { "targets": s.scan.targets, "via": s.scan.via },
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    0
}

/// Port of `critique-storage.mjs`'s CLI dispatcher (`slug|write|latest|trend`),
/// wired directly to the deterministic core already ported in `w2_010`.
fn designer_critique_storage(args: &[String]) -> i32 {
    let cwd = cwd();
    let options = w2_010::context::TargetOptions::none();
    let mut it = args.iter();
    let cmd = it.next().map(String::as_str);
    match cmd {
        Some("slug") => {
            let input = args.get(1).cloned().unwrap_or_default();
            match w2_010::critique_storage::slug_from_target(&input, &cwd) {
                Some(slug) => {
                    println!("{slug}");
                    0
                }
                None => {
                    eprintln!("no stable slug for input");
                    1
                }
            }
        }
        Some("write") => {
            let (Some(slug), Some(body_file)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: write <slug> <body-file>");
                return 1;
            };
            let raw = match std::fs::read_to_string(body_file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            };
            let mut meta: w2_010::critique_storage::Frontmatter = Vec::new();
            if let Ok(meta_arg) = std::env::var("IMPECCABLE_CRITIQUE_META") {
                if let Ok(serde_json::Value::Object(map)) =
                    serde_json::from_str::<serde_json::Value>(&meta_arg)
                {
                    for (k, v) in map {
                        let value = match v {
                            serde_json::Value::String(s) => s,
                            other => other.to_string(),
                        };
                        meta.push((k, value));
                    }
                }
            }
            let now_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            match w2_010::critique_storage::write_snapshot(&cwd, &options, slug, meta, &raw, now_millis)
            {
                Ok(path) => {
                    println!("{}", path.display());
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        Some("latest") => {
            let slug = args.get(1).cloned().unwrap_or_default();
            match w2_010::critique_storage::read_latest_snapshot(&slug, &cwd, &options) {
                Some(latest) => {
                    print!("{}", latest.body);
                    0
                }
                None => 2,
            }
        }
        Some("trend") => {
            let slug = args.get(1).cloned().unwrap_or_default();
            let limit = args
                .get(2)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(5);
            let rows = w2_010::critique_storage::read_trend(&slug, limit, &cwd, &options);
            let out: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|m| serde_json::to_value(m).unwrap_or_default())
                .collect();
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            0
        }
        _ => {
            let _ = it;
            eprintln!("usage: critique-storage.mjs <slug|write|latest|trend> [args]");
            1
        }
    }
}

/// Port of `detect-csp.mjs`'s CLI mode: scan `cwd` and print the detection
/// as JSON.
fn designer_detect_csp(_args: &[String]) -> i32 {
    let cwd = cwd();
    let result = w2_010::detect_csp::detect_csp(&cwd);
    let out = json!({
        "shape": result.shape.as_ref().map(|s| s.as_str()),
        "signals": result.signals,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    0
}

/// Port of `palette.mjs`'s CLI: `--id <id>` / `--from <key>` /
/// `IMPECCABLE_PALETTE_SEED` env / uniform random, then the full
/// instructional report. `--id "unknown"` exits 2 with a stderr message,
/// matching the source.
fn designer_palette(args: &[String]) -> i32 {
    let mut pick_args = w2_023::PickArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" => {
                i += 1;
                pick_args.id = args.get(i).cloned();
            }
            "--from" => {
                i += 1;
                pick_args.from = args.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }
    if pick_args.from.is_none() {
        pick_args.from = std::env::var("IMPECCABLE_PALETTE_SEED").ok();
    }

    struct OsRandom;
    impl w2_023::UnitRandom for OsRandom {
        fn next_unit(&mut self) -> f64 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            // A simple splitmix64-style scramble of the wall clock, sized
            // for "pick a random seed", not cryptographic use.
            let mut x = nanos as u64 ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15);
            x ^= x >> 30;
            x = x.wrapping_mul(0xBF58476D1CE4E5B9);
            x ^= x >> 27;
            x = x.wrapping_mul(0x94D049BB133111EB);
            x ^= x >> 31;
            ((x >> 11) as f64) / ((1u64 << 53) as f64)
        }
    }
    let mut rng = OsRandom;

    match w2_023::pick_seed(w2_023::SEEDS, &pick_args, &mut rng) {
        Ok(seed) => {
            println!("{}", w2_023::render_seed_report(&seed));
            0
        }
        Err(w2_023::PaletteError::UnknownSeedId(id)) => {
            eprintln!("unknown seed id: {id}");
            2
        }
    }
}

/// Composed [`r05::cli::Detectors`] wired to production I/O: `RealChromeDriver`
/// for URL scans (browser executable auto-discovered via `r07`), `RegistryLookup`
/// for antipattern metadata, `ReqwestFetcher` for `--site` sweeps.
///
/// Gap: `main.mjs`'s `--site`/`--url`/direct-URL scan path calls the
/// browser-injection script `window.impeccableDetect` (`browser_script.js`),
/// which is not present anywhere in this tree (not `detect.mjs`,
/// `detect-antipatterns.mjs`, or any `.js` under `detector/`) and is not
/// ported by any prior packet (`r05`'s and `r07`'s own finish notes record
/// the same gap). It is passed here as an empty string, so a URL/browser
/// scan runs the browser but the injected findings collector returns
/// nothing; file/dir text and HTML scanning (the common path) are fully
/// wired and unaffected.
fn designer_detect(args: &[String]) -> i32 {
    let cwd = cwd();
    let env = r07::browser::ProcessEnv;
    let fs_lookup = r07::browser::RealFs;
    let platform = if cfg!(target_os = "windows") {
        r07::Platform::Windows
    } else {
        r07::Platform::Other
    };
    let executable = match r07::find_browser_executable(platform, &env, &fs_lookup) {
        Ok(p) => Some(p),
        Err(_) => None,
    };
    let registry = r07::RegistryLookup;
    let fetcher = r08::sweep_live::ReqwestFetcher::default();
    let providers: Vec<String> = Vec::new();

    // A driver is only constructed (launching a real browser) if this
    // invocation actually needs one; file/dir/text scans never touch it.
    let mut maybe_driver = executable.and_then(|exe| {
        r07::RealChromeDriver::new(exe, r07::Viewport::default()).ok()
    });

    struct NullDriver;
    impl r07::ChromeDriver for NullDriver {
        fn navigate(&mut self, _url: &str) -> Result<(), String> {
            Err("no browser executable found".to_string())
        }
        fn evaluate(&mut self, _script: &str) -> Result<serde_json::Value, String> {
            Err("no browser executable found".to_string())
        }
    }
    let mut null_driver = NullDriver;

    let outcome = if let Some(driver) = maybe_driver.as_mut() {
        let mut detectors = r05::real_detectors::RealDetectors {
            driver,
            registry: &registry,
            fetcher: &fetcher,
            browser_script: "",
            providers: &providers,
        };
        run_r05(&cwd, args, &mut detectors)
    } else {
        let mut detectors = r05::real_detectors::RealDetectors {
            driver: &mut null_driver,
            registry: &registry,
            fetcher: &fetcher,
            browser_script: "",
            providers: &providers,
        };
        run_r05(&cwd, args, &mut detectors)
    };
    outcome
}

fn run_r05<D: r05::cli::Detectors>(cwd: &std::path::Path, args: &[String], detectors: &mut D) -> i32 {
    struct RealIo {
        cwd: std::path::PathBuf,
    }
    impl r05::cli::Io for RealIo {
        fn stdout(&mut self, s: &str) {
            print!("{s}");
            let _ = std::io::stdout().flush();
        }
        fn stderr(&mut self, s: &str) {
            eprint!("{s}");
        }
        fn stdin_is_tty(&self) -> bool {
            false
        }
        fn read_stdin(&mut self) -> String {
            use std::io::Read;
            let mut buf = String::new();
            let _ = std::io::stdin().read_to_string(&mut buf);
            buf
        }
        fn confirm(&mut self, question: &str) -> bool {
            print!("{question} [Y/n] ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            r05::cli::parse_confirm_answer(&line)
        }
    }
    let mut io = RealIo { cwd: cwd.to_path_buf() };
    let design_system = r05::design_system_loader::load_design_system_for_cwd(&io.cwd);
    r05::cli::run(args, cwd, &mut io, detectors, design_system.as_ref())
}

// ---- designer / huashu deck+video (packet r00, w2_007, r02, r03) --------

/// Real [`r00::export_deck_stage_pdf::FileSystem`]: `std::fs`.
struct RealDeckStageFs;

impl r00::export_deck_stage_pdf::FileSystem for RealDeckStageFs {
    fn exists(&self, path: &std::path::Path) -> bool {
        path.exists()
    }
    fn write(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }
}

/// Real [`r00::gen_deck_thumbs::FileSystem`]: `std::fs`.
struct RealThumbsFs;

impl r00::gen_deck_thumbs::FileSystem for RealThumbsFs {
    fn dir_exists(&self, path: &std::path::Path) -> bool {
        path.is_dir()
    }
    fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }
    fn read_dir_names(&self, path: &std::path::Path) -> std::io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }
    fn write(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }
}

/// `legion script designer/export-deck-pptx --slides <dir> --out <file.pptx>`,
/// port of `export_deck_pptx.mjs`: discovers `.html` slides, converts each
/// via a real headless-Chrome tab (`w2_007::html2pptx`), and writes the
/// merged `.pptx`. See `r00::export_deck_pptx::run_production`.
fn designer_export_deck_pptx(args: &[String]) -> i32 {
    let parsed = match r00::export_deck_pptx::parse_args(args) {
        Ok(a) => a,
        Err(_) => {
            eprintln!("用法: node export_deck_pptx.mjs --slides <dir> --out <file.pptx>");
            return 1;
        }
    };
    match r00::export_deck_pptx::run_production(&parsed) {
        Ok(outcome) => {
            for line in &outcome.log {
                match line {
                    r00::export_deck_pptx::ConvertLogLine::Ok { index, total, file } => {
                        println!("  [{index}/{total}] {file} \u{2713}");
                    }
                    r00::export_deck_pptx::ConvertLogLine::Fail { index, total, file, error } => {
                        eprintln!("  [{index}/{total}] {file} \u{2717} {error}");
                    }
                }
            }
            println!(
                "Wrote {} ({}/{} slides)",
                parsed.out.display(),
                outcome.converted,
                outcome.total
            );
            0
        }
        Err(e) => {
            eprintln!("{e:?}");
            1
        }
    }
}

/// `legion script designer/export-deck-stage-pdf --html <deck.html> --out <file.pdf>`,
/// port of `export_deck_stage_pdf.mjs`.
fn designer_export_deck_stage_pdf(args: &[String]) -> i32 {
    let parsed = match r00::export_deck_stage_pdf::parse_args(args) {
        Ok(a) => a,
        Err(_) => {
            eprintln!(
                "用法: node export_deck_stage_pdf.mjs --html <deck.html> --out <file.pdf> [--width 1920] [--height 1080]"
            );
            return 1;
        }
    };
    let fs = RealDeckStageFs;
    let mut browser = match r00::export_deck_stage_pdf::ChromeDeckStageBrowser::launch(
        parsed.width,
        parsed.height,
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to launch headless chrome: {e}");
            return 1;
        }
    };
    match r00::export_deck_stage_pdf::run(&fs, &mut browser, &parsed) {
        Ok(outcome) => {
            println!(
                "Wrote {} ({} bytes, {} sections)",
                parsed.out.display(),
                outcome.bytes_written,
                outcome.section_count
            );
            0
        }
        Err(e) => {
            eprintln!("{e:?}");
            1
        }
    }
}

/// `legion script designer/gen-deck-thumbs [--slides slides] [--out thumbs] ...`,
/// port of `gen_deck_thumbs.mjs`.
fn designer_gen_deck_thumbs(args: &[String]) -> i32 {
    let parsed = r00::gen_deck_thumbs::parse_args(args);
    let fs = RealThumbsFs;
    let mut browser = match r00::gen_deck_thumbs::ChromeThumbBrowser::launch(
        parsed.canvas_w,
        parsed.canvas_h,
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to launch headless chrome: {e}");
            return 1;
        }
    };
    match r00::gen_deck_thumbs::run(&fs, &mut browser, &parsed) {
        Ok(outcome) => {
            for line in &outcome.log {
                match line {
                    r00::gen_deck_thumbs::ThumbLogLine::Ok(path) => println!("  [ok] {path}"),
                    r00::gen_deck_thumbs::ThumbLogLine::Fail { file, error } => {
                        eprintln!("  [FAIL] {file}: {error}")
                    }
                }
            }
            println!("{}/{} thumbnails written", outcome.ok_count, outcome.total);
            0
        }
        Err(e) => {
            eprintln!("{e:?}");
            1
        }
    }
}

/// `legion script designer/fetch-images --query <q...> --out <dir> [--count 2] [--width 1600]`,
/// port of `fetch_images.py`. `fetch_images::run` is `async` (real HTTP via
/// `reqwest`'s async client); this dispatcher runs on Tokio's
/// multi-threaded runtime (`#[tokio::main]` in `main.rs`), so the async
/// call is bridged with `block_in_place` + `Handle::current().block_on`
/// rather than spinning up a second nested runtime (which would panic).
fn designer_fetch_images(args: &[String]) -> i32 {
    let parsed = match r00::fetch_images::parse_args(args) {
        Ok(a) => a,
        Err(_) => {
            eprintln!("usage: fetch_images.py --query <q...> --out <dir> [--count 2] [--width 1600]");
            return 1;
        }
    };
    let client = match r00::fetch_images::HttpCommonsClient::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let write_file = |path: &std::path::Path, bytes: &[u8]| std::fs::write(path, bytes);
    let ensure_dir = |path: &std::path::Path| std::fs::create_dir_all(path);

    let (got, log, summary, exit_code) = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(r00::fetch_images::run(&client, &write_file, &ensure_dir, &parsed))
    });
    let _ = &got;
    for line in &log {
        println!("{line:?}");
    }
    for line in &summary {
        println!("{line:?}");
    }
    exit_code
}

/// `legion script designer/render-video <html-file> [--duration N] [--width N] [--height N] ...`,
/// port of `render-video.js`.
fn designer_render_video(args: &[String]) -> i32 {
    let cwd = cwd();
    let mut recorder = match r03::render_video::ChromeRecorder::launch() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let ffmpeg = r03::render_video::RealFfmpeg;
    let fs = r03::render_video::RealFileSystem;
    let mut stdout = std::io::stdout();
    // pid-scoped tmp-dir suffix so concurrent invocations never collide,
    // matching the porting brief's "test temp dirs need pid + process-wide
    // AtomicU64" convention.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    match r03::render_video::run(args, &cwd, &suffix, &mut recorder, &ffmpeg, &fs, &mut stdout) {
        Ok(path) => {
            println!("\u{2713} Wrote {}", path.display());
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// `legion script designer/render-video-seek <html-file> [--duration=N] [--fps=N] ...`,
/// port of `render-video-seek.js`.
fn designer_render_video_seek(args: &[String]) -> i32 {
    // `parse_args` mirrors `process.argv[2]` for the positional, so the
    // dispatcher's `rest` (already stripped of `node`/script-path) needs a
    // two-element pad in front to line up with that indexing.
    let mut argv = vec!["legion".to_string(), "render-video-seek".to_string()];
    argv.extend_from_slice(args);
    let parsed = match r02::render_video_seek::parse_args(&argv) {
        Ok(a) => a,
        Err(_) => {
            eprintln!("Usage: node render-video-seek.js <html-file> [--duration=N] [--fps=N] [--width=N] [--height=N] [--concurrency=N]");
            return 1;
        }
    };
    let driver = match r02::render_video_seek::HeadlessChromeDriver::launch() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let encoder = r02::render_video_seek::RealFfmpegEncoder;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let tmp_dir = std::env::temp_dir().join(format!("legion-render-video-seek-{suffix}"));
    match r02::render_video_seek::run(&parsed, &driver, &encoder, &tmp_dir) {
        Ok(outcome) => {
            for line in &outcome.log_lines {
                println!("{line}");
            }
            println!(
                "\u{2713} Wrote {} ({}/{} frames)",
                outcome.mp4_path.display(),
                outcome.frames_captured,
                outcome.total_frames
            );
            0
        }
        Err(e) => {
            eprintln!("{e:?}");
            1
        }
    }
}

/// `legion script designer/narrate-pipeline <script.json> <out-dir>`, port
/// of `narrate-pipeline.mjs`. `tts_script` points at the sibling
/// `tts-doubao.mjs` next to the given script file, matching the original's
/// `path.join(__dirname, 'tts-doubao.mjs')` (this dispatcher has no
/// `__dirname`; the huashu `scripts/` directory convention is that every
/// narration script and `tts-doubao.mjs` live side by side).
fn designer_narrate_pipeline(args: &[String]) -> i32 {
    let tts_script = args
        .first()
        .map(std::path::PathBuf::from)
        .and_then(|p| p.parent().map(|d| d.join("tts-doubao.mjs")))
        .unwrap_or_else(|| std::path::PathBuf::from("tts-doubao.mjs"));
    let runner = r02::narrate_pipeline::RealProcessRunner::new(tts_script);
    let (code, log) = r02::narrate_pipeline::run_cli(args, &runner);
    for line in &log {
        println!("{line}");
    }
    code
}

/// `legion script designer/tts-doubao --text <t> --out <file> [--voice v] [--speed s]`,
/// port of `tts-doubao.mjs`.
fn designer_tts_doubao(args: &[String]) -> i32 {
    struct RealFileIo;
    impl r03::tts_doubao::FileIo for RealFileIo {
        fn read_to_string(&self, path: &std::path::Path) -> std::io::Result<String> {
            std::fs::read_to_string(path)
        }
        fn read_dotenv(&self, skill_root: &std::path::Path) -> Option<String> {
            std::fs::read_to_string(skill_root.join(".env")).ok()
        }
        fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
            std::fs::create_dir_all(path)
        }
        fn write(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
            std::fs::write(path, bytes)
        }
    }
    let skill_root = cwd();
    let process_env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let reqid = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let io = RealFileIo;
    let http = r03::tts_doubao::ReqwestHttpPost;
    let probe = r03::tts_doubao::RealFfprobe;
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    r03::tts_doubao::run(
        args,
        &skill_root,
        &process_env,
        reqid,
        &io,
        &http,
        &probe,
        &mut stdout,
        &mut stderr,
    )
}

/// `legion script designer/verify <html> [--viewports ...] [--slides N] [--output dir] [--wait N]`,
/// port of `verify.py`.
fn designer_verify(args: &[String]) -> i32 {
    let fs = r03::verify::RealFileSystem;
    let mut driver = match r03::verify::ChromeBrowserDriver::launch(true) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    r03::verify::run(args, &fs, &mut driver, &mut stdout, &mut stderr)
}

// ---- dispatch / tasklist --------------------------------------------------

/// A [`r46::cli::MinimizeGate`] backed by the real `legion-minimize` decision
/// verifier, closing the gap `r46::cli`'s module doc names (its own
/// `NoMinimizeGate` always fails).
struct RealMinimizeGate;

impl r46::cli::MinimizeGate for RealMinimizeGate {
    fn verify_decision(
        &self,
        minimize_path: &std::path::Path,
        minimize_receipt: &std::path::Path,
    ) -> Result<(), String> {
        let paths = legion_minimize::resolve_minimize_paths().map_err(|e| e.to_string())?;
        legion_minimize::verify_decision(minimize_path, minimize_receipt, &paths)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

struct DispatchArgs {
    dispatch: std::path::PathBuf,
    packet_type: String,
    template_self_check: bool,
    write_receipt: Option<std::path::PathBuf>,
    verify_receipt: Option<std::path::PathBuf>,
}

fn parse_dispatch_args(argv: &[String]) -> Result<DispatchArgs, String> {
    let mut dispatch = None;
    let mut packet_type = "legacy".to_string();
    let mut template_self_check = false;
    let mut write_receipt = None;
    let mut verify_receipt = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--packet-type" => {
                i += 1;
                let v = argv.get(i).ok_or("argument --packet-type: expected one argument")?;
                if !["authority", "worker", "legacy"].contains(&v.as_str()) {
                    return Err(format!(
                        "argument --packet-type: invalid choice: '{v}' (choose from 'authority', 'worker', 'legacy')"
                    ));
                }
                packet_type = v.clone();
            }
            "--template-self-check" => template_self_check = true,
            "--write-receipt" => {
                i += 1;
                let v = argv.get(i).ok_or("argument --write-receipt: expected one argument")?;
                write_receipt = Some(std::path::PathBuf::from(v));
            }
            "--verify-receipt" => {
                i += 1;
                let v = argv.get(i).ok_or("argument --verify-receipt: expected one argument")?;
                verify_receipt = Some(std::path::PathBuf::from(v));
            }
            other => dispatch = Some(std::path::PathBuf::from(other)),
        }
        i += 1;
    }
    if write_receipt.is_some() && verify_receipt.is_some() {
        return Err("argument --verify-receipt: not allowed with argument --write-receipt".to_string());
    }
    Ok(DispatchArgs {
        dispatch: dispatch.ok_or("the following arguments are required: dispatch")?,
        packet_type,
        template_self_check,
        write_receipt,
        verify_receipt,
    })
}

/// Full port of `validate-dispatch.py`'s `main()`: the `authority`/`worker`
/// packet-type branch (structural checks via
/// `w2_044::authority_packet_errors`, receipt write/verify with the
/// `schema_version: 4` authority receipt shape) and the `legacy` dispatch
/// document branch (`r46::cli::run`, wired to the real Minimize gate).
/// Returns `(exit_code, stdout, stderr)`.
fn run_dispatch_validate(argv: &[String]) -> (i32, String, String) {
    let args = match parse_dispatch_args(argv) {
        Ok(a) => a,
        Err(e) => return (2, String::new(), format!("{e}\n")),
    };
    if !args.dispatch.is_file() {
        return (2, String::new(), format!("FAIL: dispatch file not found: {}\n", args.dispatch.display()));
    }
    if !args.template_self_check && args.write_receipt.is_none() && args.verify_receipt.is_none() {
        return (1, String::new(), "FAIL: exactly one receipt mode is required\n".to_string());
    }
    let raw_bytes = match std::fs::read(&args.dispatch) {
        Ok(b) => b,
        Err(e) => return (2, String::new(), format!("FAIL: dispatch file not found: {e}\n")),
    };

    if args.packet_type == "authority" || args.packet_type == "worker" {
        let packet: serde_json::Value = match serde_json::from_slice(&raw_bytes) {
            Ok(v) => v,
            Err(e) => return (1, format!("FAIL: authority packet is not valid JSON: {e}\n"), String::new()),
        };
        if args.packet_type == "worker" && packet.get("packetType").and_then(|v| v.as_str()) != Some("worker") {
            return (1, "FAIL: worker mode requires worker packet\n".to_string(), String::new());
        }
        let resolved = args.dispatch.canonicalize().unwrap_or_else(|_| args.dispatch.clone());
        let (errors, references) = w2_044::authority_packet::authority_packet_errors(&packet, &resolved);
        if !errors.is_empty() {
            let mut out = format!("FAIL: {} authority dispatch defect(s)\n", errors.len());
            for e in &errors {
                out.push_str(&format!("- {e}\n"));
            }
            return (1, out, String::new());
        }
        let digest = w2_044::digest::sha256_digest(&raw_bytes);
        let references_json: Vec<serde_json::Value> = references
            .iter()
            .map(|r| serde_json::json!({"path": r.path, "sha256": r.sha256}))
            .collect();
        let authority_binding = serde_json::json!({
            "packet_sha256": digest,
            "source_revision": packet.get("sourceRevision").cloned().unwrap_or(serde_json::Value::Null),
            "prompt_digest": packet.get("promptDigest").cloned().unwrap_or(serde_json::Value::Null),
        });
        if let Some(verify_receipt) = &args.verify_receipt {
            let text = match std::fs::read_to_string(verify_receipt) {
                Ok(t) => t,
                Err(e) => return (1, format!("FAIL: invalid receipt: {e}\n"), String::new()),
            };
            let receipt: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => return (1, format!("FAIL: invalid receipt: {e}\n"), String::new()),
            };
            let refs_match = receipt.get("referenced_artifacts").cloned().unwrap_or(serde_json::Value::Null)
                == serde_json::Value::Array(references_json.clone());
            if receipt.get("sha256").and_then(|v| v.as_str()) != Some(digest.as_str())
                || !refs_match
                || receipt.get("authority_binding").cloned().unwrap_or(serde_json::Value::Null) != authority_binding
            {
                return (
                    1,
                    "FAIL: packet, source/prompt binding, or referenced artifacts do not match receipt\n"
                        .to_string(),
                    String::new(),
                );
            }
        }
        if let Some(write_receipt) = &args.write_receipt {
            let receipt = serde_json::json!({
                "schema_version": 4,
                "sha256": digest,
                "referenced_artifacts": references_json,
                "authority_binding": authority_binding,
            });
            let body = format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap_or_default());
            if let Some(parent) = write_receipt.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(write_receipt, body) {
                return (1, format!("FAIL: could not write receipt: {e}\n"), String::new());
            }
        }
        return (
            0,
            format!("PASS: {} packet is structurally complete (sha256={digest})\n", args.packet_type),
            String::new(),
        );
    }

    let opts = r46::cli::RunOptions {
        dispatch: &args.dispatch,
        template_self_check: args.template_self_check,
        write_receipt: args.write_receipt.as_deref(),
        verify_receipt: args.verify_receipt.as_deref(),
    };
    let outcome = r46::cli::run(&opts, &RealMinimizeGate);
    let mut stdout = String::new();
    for line in &outcome.stdout {
        stdout.push_str(line);
        stdout.push('\n');
    }
    (outcome.exit_code, stdout, String::new())
}

fn dispatch_validate_dispatch(args: &[String]) -> i32 {
    let (code, stdout, stderr) = run_dispatch_validate(args);
    print_cli_outcome(code, &stdout, &stderr)
}

/// [`w2_044::tasklist::CommandRunner`] that runs `validate-dispatch` in
/// process (via [`run_dispatch_validate`]) instead of spawning a Python
/// subprocess, since no Python side exists any more.
struct InProcessValidateDispatch;

impl w2_044::tasklist::CommandRunner for InProcessValidateDispatch {
    fn run(
        &self,
        _program: &str,
        args: &[String],
    ) -> std::io::Result<w2_044::tasklist::ProcessOutput> {
        // args[0] is the validator path placeholder (unused in-process); the
        // rest is `<dispatch> --packet-type <type> --<mode>-receipt <path>`,
        // matching `run_cli`'s own child_args construction.
        let (code, stdout, stderr) = run_dispatch_validate(&args[1..]);
        Ok(w2_044::tasklist::ProcessOutput { stdout, stderr, code })
    }
}

fn tasklist_validate_tasklist(args: &[String]) -> i32 {
    let runner = InProcessValidateDispatch;
    let outcome = w2_044::tasklist::run_cli(args, "legion-in-process", std::path::Path::new("validate-dispatch"), &runner);
    print_cli_outcome(outcome.code, &outcome.stdout, &outcome.stderr)
}

// ---- seo/google_report -----------------------------------------------

fn seo_google_report(args: &[String]) -> i32 {
    struct RealDataSource;
    impl r37::cli::DataSource for RealDataSource {
        fn read_file(&self, path: &std::path::Path) -> Result<String, String> {
            std::fs::read_to_string(path).map_err(|e| e.to_string())
        }
        fn read_stdin(&self) -> Option<Result<String, String>> {
            use std::io::{IsTerminal as _, Read as _};
            let stdin = std::io::stdin();
            if stdin.is_terminal() {
                return None;
            }
            let mut buf = String::new();
            Some(std::io::stdin().lock().read_to_string(&mut buf).map(|_| buf).map_err(|e| e.to_string()))
        }
    }
    let parsed = match r37::cli::parse_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {e:?}");
            return 1;
        }
    };
    let data = match r37::cli::load_data(&parsed, &RealDataSource) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let timestamp = now_iso8601_for_report();
    let needs_pdf = matches!(parsed.format, r37::report::OutputFormat::Pdf);
    let mut renderer = if needs_pdf {
        match r37::report::ChromePdfRenderer::launch() {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        }
    } else {
        None
    };
    let (_, stdout_lines) = r37::cli::run_with_data(
        &parsed,
        &data,
        &timestamp,
        renderer.as_mut().map(|r| r as &mut dyn r37::report::PdfRenderer),
    );
    for line in stdout_lines {
        println!("{line}");
    }
    0
}

fn now_iso8601_for_report() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
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
