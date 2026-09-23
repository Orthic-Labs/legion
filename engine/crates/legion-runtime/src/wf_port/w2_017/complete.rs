//! Port of `live-complete.mjs`'s pure logic: CLI argument parsing and the
//! durable completion event it appends.
//!
//! The two effectful branches — posting to the local live server
//! (`fetch(http://localhost:${port}/poll, ...)`) and falling back to
//! `createLiveSessionStore(...).appendEvent(...)` — depend on
//! `live/session-store.mjs` and `lib/impeccable-paths.mjs`, neither of which
//! is in this chunk's owned files. [`CompletionEvent`] models exactly the
//! event payload those calls would build, so a caller that does own a
//! session-store port can drive it from here.

/// Port of the CLI status `parseArgs` derives from `--discarded`/`--discard`,
/// `--error[=MESSAGE]`, or the default.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Complete,
    Discarded,
    AgentError { message: String },
}

/// Port of the object `parseArgs(argv)` returns (`{ status, id, help,
/// message }`, with `status` defaulting to `'complete'`).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedArgs {
    pub status: Status,
    pub id: Option<String>,
    pub help: bool,
}

/// Port of:
/// ```js
/// function parseArgs(argv) {
///   const out = { status: 'complete' };
///   for (let i = 0; i < argv.length; i++) {
///     const arg = argv[i];
///     if (arg === '--id') out.id = argv[++i];
///     else if (arg.startsWith('--id=')) out.id = arg.slice('--id='.length);
///     else if (arg === '--discarded' || arg === '--discard') out.status = 'discarded';
///     else if (arg === '--error') { out.status = 'agent_error'; out.message = argv[++i] || 'unknown error'; }
///     else if (arg.startsWith('--error=')) { out.status = 'agent_error'; out.message = arg.slice('--error='.length); }
///     else if (arg === '--help' || arg === '-h') out.help = true;
///   }
///   return out;
/// }
/// ```
/// `argv` here is already `process.argv.slice(2)` — the script's own
/// arguments, not `["node", "live-complete.mjs", ...]`.
pub fn parse_args(argv: &[String]) -> ParsedArgs {
    let mut status = Status::Complete;
    let mut id: Option<String> = None;
    let mut help = false;
    let mut i = 0usize;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--id" {
            i += 1;
            id = argv.get(i).cloned();
        } else if let Some(rest) = arg.strip_prefix("--id=") {
            id = Some(rest.to_string());
        } else if arg == "--discarded" || arg == "--discard" {
            status = Status::Discarded;
        } else if arg == "--error" {
            i += 1;
            let message = argv
                .get(i)
                .cloned()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown error".to_string());
            status = Status::AgentError { message };
        } else if let Some(rest) = arg.strip_prefix("--error=") {
            status = Status::AgentError {
                message: rest.to_string(),
            };
        } else if arg == "--help" || arg == "-h" {
            help = true;
        }
        i += 1;
    }
    ParsedArgs { status, id, help }
}

/// Port of the usage-gate check:
/// ```js
/// if (args.help || !args.id) {
///   console.log(usage);
///   process.exit(args.help ? 0 : 1);
/// }
/// ```
/// Returns the process exit code the script would use, or `None` if the CLI
/// should proceed.
pub fn usage_exit_code(args: &ParsedArgs) -> Option<i32> {
    if args.help || args.id.is_none() {
        Some(if args.help { 0 } else { 1 })
    } else {
        None
    }
}

/// Port of the event object built from a resolved `ParsedArgs`:
/// ```js
/// const event = args.status === 'discarded'
///   ? { type: 'discarded', id: args.id }
///   : args.status === 'agent_error'
///     ? { type: 'agent_error', id: args.id, message: args.message || 'unknown error' }
///     : { type: 'complete', id: args.id };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum CompletionEvent {
    Complete { id: String },
    Discarded { id: String },
    AgentError { id: String, message: String },
}

/// Builds the durable event for a resolved `id` + `Status`, matching the JS
/// ternary above exactly (only reachable once `usage_exit_code` returns
/// `None`, i.e. `id` is present).
pub fn build_event(id: &str, status: &Status) -> CompletionEvent {
    match status {
        Status::Discarded => CompletionEvent::Discarded { id: id.to_string() },
        Status::AgentError { message } => CompletionEvent::AgentError {
            id: id.to_string(),
            message: if message.is_empty() {
                "unknown error".to_string()
            } else {
                message.clone()
            },
        },
        Status::Complete => CompletionEvent::Complete { id: id.to_string() },
    }
}

/// Port of the `/poll` request body's `type` field derivation in
/// `completeThroughServer`:
/// ```js
/// const type = args.status === 'discarded' ? 'discarded' : args.status === 'agent_error' ? 'error' : 'complete';
/// ```
/// Note this differs from [`CompletionEvent`]'s local-store `type` field
/// (`'agent_error'` vs. the server's `'error'`) — both are ported faithfully
/// as separate strings, matching the JS source exactly.
pub fn server_poll_type(status: &Status) -> &'static str {
    match status {
        Status::Discarded => "discarded",
        Status::AgentError { .. } => "error",
        Status::Complete => "complete",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_defaults_to_complete() {
        let parsed = parse_args(&args(&["--id", "abc"]));
        assert_eq!(parsed.status, Status::Complete);
        assert_eq!(parsed.id.as_deref(), Some("abc"));
        assert!(!parsed.help);
    }

    #[test]
    fn parse_args_id_equals_form() {
        let parsed = parse_args(&args(&["--id=xyz"]));
        assert_eq!(parsed.id.as_deref(), Some("xyz"));
    }

    #[test]
    fn parse_args_discarded_variants() {
        assert_eq!(parse_args(&args(&["--discarded"])).status, Status::Discarded);
        assert_eq!(parse_args(&args(&["--discard"])).status, Status::Discarded);
    }

    #[test]
    fn parse_args_error_with_message() {
        let parsed = parse_args(&args(&["--error", "boom"]));
        assert_eq!(
            parsed.status,
            Status::AgentError { message: "boom".to_string() }
        );
    }

    #[test]
    fn parse_args_error_missing_message_defaults() {
        let parsed = parse_args(&args(&["--error"]));
        assert_eq!(
            parsed.status,
            Status::AgentError { message: "unknown error".to_string() }
        );
    }

    #[test]
    fn parse_args_error_equals_form_empty_message_kept_empty() {
        let parsed = parse_args(&args(&["--error="]));
        assert_eq!(parsed.status, Status::AgentError { message: String::new() });
    }

    #[test]
    fn parse_args_help_flags() {
        assert!(parse_args(&args(&["--help"])).help);
        assert!(parse_args(&args(&["-h"])).help);
    }

    #[test]
    fn usage_exit_code_help_takes_priority() {
        let parsed = ParsedArgs { status: Status::Complete, id: None, help: true };
        assert_eq!(usage_exit_code(&parsed), Some(0));
    }

    #[test]
    fn usage_exit_code_missing_id_is_error() {
        let parsed = ParsedArgs { status: Status::Complete, id: None, help: false };
        assert_eq!(usage_exit_code(&parsed), Some(1));
    }

    #[test]
    fn usage_exit_code_ok_when_id_present() {
        let parsed = ParsedArgs { status: Status::Complete, id: Some("x".into()), help: false };
        assert_eq!(usage_exit_code(&parsed), None);
    }

    #[test]
    fn build_event_variants() {
        assert_eq!(build_event("id1", &Status::Complete), CompletionEvent::Complete { id: "id1".into() });
        assert_eq!(build_event("id1", &Status::Discarded), CompletionEvent::Discarded { id: "id1".into() });
        assert_eq!(
            build_event("id1", &Status::AgentError { message: "oops".into() }),
            CompletionEvent::AgentError { id: "id1".into(), message: "oops".into() }
        );
        // empty message falls back to 'unknown error', matching `args.message || 'unknown error'`
        assert_eq!(
            build_event("id1", &Status::AgentError { message: String::new() }),
            CompletionEvent::AgentError { id: "id1".into(), message: "unknown error".into() }
        );
    }

    #[test]
    fn server_poll_type_matches_js() {
        assert_eq!(server_poll_type(&Status::Complete), "complete");
        assert_eq!(server_poll_type(&Status::Discarded), "discarded");
        assert_eq!(
            server_poll_type(&Status::AgentError { message: "x".into() }),
            "error"
        );
    }
}
