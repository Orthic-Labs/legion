//! Port of `src/lib/cognitive/arcane/stop-shape.mjs` (the Stop-shape gate: a
//! turn may end only on completed, verified work or a stated reserved
//! blocker). See the JS source's own header comment for the two production
//! failure modes this gate must never reproduce (format-grinding a correctly
//! blocked agent, and blocking forever) — both are pinned by tests below,
//! ported from `tests/stop-shape.test.mjs`.
//!
//! Not ported: `main()` (Node CLI entry reading a Stop-hook payload off
//! stdin) and its use of `process.argv`/`import.meta.url` self-invocation
//! detection — those are host wiring, not library logic, and out of this
//! crate's ownership. `evaluate_transcript_stop` below ports the JS function
//! of the same name (transcript read + verdict), using `std::fs::read_to_string`
//! in place of Node's `readFileSync`.

use std::fs;
use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::wf_port::wf007::user_intent::{classify_latest_user_intent, latest_external_user_turn, Intent};

fn ci(pattern: &str) -> Regex {
    RegexBuilder::new(pattern).case_insensitive(true).build().expect("valid regex")
}
fn plain(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid regex")
}

const MAX_PUSHES: u32 = 2;

// --- HARD_BLOCKER / reserved categories -------------------------------------

fn hard_blocker_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\b(?:HARD BLOCKER|BLOCKED-ON-APPROVAL)\b\s*:?\s*(?:\S|(?:\r?\n\s*)+\S)"))
}

fn reserved_categories_table() -> &'static Vec<(&'static str, Regex)> {
    static CELL: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            ("private-input", ci(r"\b(private|missing)\s+(input|credential|token|password|secret)\b|\bcredentials?\b|\b2fa\b|\bapi key\b")),
            ("new-spend", ci(r"\bnew spend\b|\bspend\b|\bpurchase\b|\bpaid\b|\bbilling\b|\bcost(s|ing)?\s+(money|\$)|\$\d")),
            ("publication", ci(r"\bpublicat\w+\b|\bpublish\w*\b|\bproduction mutation\b|\brelease\b|\bdeploy(ing|ment)?\s+to\s+prod\w*|\bnpm publish\b")),
            ("destruction", ci(r"\bdestruct\w+\b|\bdelete\b|\bdrop\b|\bhard[- ]?reset\b|\bforce[- ]?push\b|\birreversible\b")),
            ("reserved-decision", ci(r"\breserved[ _-]decision\b|\bpolicy[ _-](change|decision)\b|\bwho may\b|\bdelegat\w+ authority\b|\bchange the rule\b")),
        ]
    })
}

/// Which canonical reserved categories a blocker packet actually names.
pub fn reserved_categories(text: &str) -> Vec<&'static str> {
    reserved_categories_table()
        .iter()
        .filter(|(_, re)| re.is_match(text))
        .map(|(name, _)| *name)
        .collect()
}

// --- D-1: push-gate-laundering pre-check ------------------------------------

fn push_gate_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\bgit\s+push\b|\bpush(?:ing|es)?\b[^\n]{0,100}\b(?:publish\w*|origin|remotes?|repos?|repositor\w+|github|branch\w*|upstream|main)\b"))
}
fn force_push_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"--force(?:-with-lease)?\b|\bforce[- ]push\w*|\bhistory rewrite\w*|\brewrit\w+[^\n]{0,40}\bhistory\b"))
}
fn reserved_publication_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\b(?:npm|pnpm|yarn|cargo|twine)\s+publish\b|\bpublish\w*\b[^\n]{0,40}\b(?:npm|registry|crates|pypi|marketplace|app store|production|customers?|publicly)\b|\brelease\b[^\n]{0,40}\b(?:upload|publish\w*|production)\b|\bdeploy\w*\b[^\n]{0,40}\bproduction\b"))
}

/// An ordinary push worded to sound reserved is not a reserved blocker.
pub fn is_push_gate_laundering(text: &str) -> bool {
    push_gate_pattern().is_match(text)
        && !force_push_pattern().is_match(text)
        && !reserved_publication_pattern().is_match(text)
}

// --- continue-intent (enforce_continue_intent.py) ---------------------------

fn continue_intent_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        let alts = [
            r"\bcan(?:'t|not)?\s+we\b.*\b(?:make|create|add|turn|implement|fix|remove|delete|run|scan|update|incorporate|absorb|enforce|wire|hook)\b",
            r"\bwhy\s+don'?t\s+we\b.*\b(?:make|create|add|turn|implement|fix|remove|delete|run|scan|update|incorporate|absorb|enforce|wire|hook)\b",
            r"\bshould\s+we\b.*\b(?:install|incorporate|remove|fix|scan|create|make|turn|hook|enforce)\b",
            r"\bcan\s+you\b.*\b(?:make|create|add|turn|implement|fix|remove|delete|run|scan|update|incorporate|absorb|enforce|wire|hook)\b",
            r"\bplease\b.*\b(?:make|create|add|turn|implement|fix|remove|delete|run|scan|update|incorporate|absorb|enforce|wire|hook)\b",
            r"\b(?:i\s+asked|asked\s+multiple\s+times|repeatedly\s+asked)\b.*\b(?:remove|delete|fix|stop|avoid|enforce)\b",
            r"\bwhy\s+is\b.*\bstill\s+(?:there|enabled|active|present|happening|broken|failing)\b",
            r"\bover\s+and\s+over\b.*\b(?:failure|fails?|problem|still)\b",
            r"\bclearly\s+the\s+intention\b.*\b(?:continue|act|finish|get\s+you\s+to\s+continue)\b",
            r"\b(?:do|fix|remove|scan|run|add|make|create|implement|wire)\s+it\b",
        ];
        RegexBuilder::new(&alts.join("|"))
            .case_insensitive(true)
            .dot_matches_new_line(true)
            .build()
            .expect("valid regex")
    })
}
fn action_done_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        RegexBuilder::new(r"\bI (?:added|updated|created|implemented|wired|registered|patched|fixed|removed|deleted|disabled|enabled|ran|scanned|verified|changed|installed|moved)\b|\b(?:added|updated|created|implemented|wired|registered|patched|fixed|removed|deleted|disabled|enabled|ran|scanned|verified|changed|installed|moved)\b.*\b(?:now|already|successfully|in|to|from)\b|\b(?:done|completed|finished)\b|\bverification\b.*\b(?:passed|clean|green|ok)\b|\bI'?m (?:continuing|working|doing it|on it)\b")
            .case_insensitive(true).dot_matches_new_line(true).build().unwrap()
    })
}
fn stop_only_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        RegexBuilder::new(r"\b(?:I|we) (?:can|could|should)\b|\b(?:I'?ll|I will|we'?ll|we will)\b|\b(?:recommend|proposal|propose|would be|next step)\b|\bthat'?s (?:a )?good idea\b|\byes\b.*\b(?:can|should|would)\b")
            .case_insensitive(true).dot_matches_new_line(true).build().unwrap()
    })
}
fn continue_blocker_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        RegexBuilder::new(r"\bhard blocker\b|\bblocked because\b|\bneeds user input\b|\bneed(?:s)? (?:your|user) (?:input|approval|credentials|decision|confirmation)\b|\bI cannot proceed\b.*\bwithout\b|\bmissing (?:secret|credential|file|input|approval)\b")
            .case_insensitive(true).dot_matches_new_line(true).build().unwrap()
    })
}

/// The latest genuine user turn's continuation-intent evidence, if any.
pub fn continue_intent(user_text: &str) -> Option<String> {
    let normalized = user_text.replace(['\u{2019}', '\u{2018}'], "'").replace(['\u{201c}', '\u{201d}'], "\"");
    continue_intent_re().find(&normalized).map(|m| m.as_str().chars().take(120).collect())
}

// --- SHAPES table ------------------------------------------------------------

struct Shape {
    name: &'static str,
    instruction: &'static str,
    pattern: Regex,
    requires: Option<Regex>,
    carve_out: Option<Regex>,
}

fn shapes() -> &'static Vec<Shape> {
    static CELL: OnceLock<Vec<Shape>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            Shape {
                name: "permission-question",
                instruction: "the operator pre-authorized in-scope reversible work; do it now instead of asking.",
                pattern: ci(r"\b(say (the word|go|yes)|shall i|want me to (proceed|continue|do|build|fix|run|add|set|apply|install|update|wire|write|edit|change|make)|should i (proceed|continue|go ahead)|do you want me to|awaiting (your )?(approval|confirmation|go)|give me the go)\b"),
                requires: None,
                carve_out: None,
            },
            Shape {
                name: "deferral-offer",
                instruction: "You named the exact action — perform it now instead of offering it.",
                pattern: ci(r"\b(or )?tell me( to)?,?( and)? i(['\u{2019}])?ll (do|apply|add|set|handle|wire|edit) (it|this|that)\b|\bor i can (do|add|apply|set|make|wire|edit|write|install|update)\b|\bif you (want|like|prefer),? i can\b|\blet me know (if|whether|when|and)\b|\bi can [a-z]+ (it|this|that)\b[^\n]{0,30}\bif you (want|like)\b"),
                requires: None,
                carve_out: None,
            },
            Shape {
                name: "unresolved-caveat",
                instruction: "Resolve the caveat yourself rather than reporting it.",
                pattern: ci(r"\b(one caveat|a caveat|with the caveat|caveats?:)\b|\bone thing (that )?(isn'?t|is not|to note|to flag|to be aware)\b|\bwhat (isn'?t|is not) (fixed|covered|handled|done)\b|\bjust (be aware|so you know)\b|\b(keep|bear) in mind\b|\bthat said,|\bone last (thing|note)\b"),
                requires: Some(ci(r"\b(done|fixed|shipped|pushed|landed|complete|completed|resolved)\b|\bverified\b|\ball (tests? )?pass(ing|es|ed)?\b|\b\d+/\d+ (tests? )?pass\w*\b|\bworks? now\b|\bis (in and )?green\b")),
                carve_out: Some(ci(r"\btests? (?:fail|failed|are failing)\b|\bfailing\b|\berror(?:ed)?\b|\bhard blocker\b|\bcould not be (?:fixed|resolved)\b|\bneeds? your (?:input|decision)\b|\bBLOCKED-ON-APPROVAL\b")),
            },
            Shape {
                name: "deferred-work-promise",
                instruction: "Do the promised work now — a promise of future work is not a completed turn.",
                pattern: ci(r"\b(i('| wi)ll (do|fix|build|wire|handle|address) (this|that|it) (later|next|in a follow-?up)|left as a follow-?up|remains? to be (done|built|fixed))\b"),
                requires: None,
                carve_out: None,
            },
            Shape {
                name: "approval-blocked",
                instruction: "Approval for reversible in-scope work is pre-granted by doctrine. Only private input, new spend, publication/production mutation, destruction, or a reserved decision needs the operator — name which one applies, or continue.",
                pattern: ci(r"\bblocked on (your )?(approval|a decision|sign-?off|confirmation)\b"),
                requires: None,
                carve_out: None,
            },
        ]
    })
}

// --- D-3: work-left-stuck ----------------------------------------------------

fn work_left_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\bqueued\b|\bpending\b|\bnot (?:started|running|done|fixed|complete)\b|\bstill (?:waiting|stuck|pending|queued|not)\b|\b(?:stuck|wedged|blocked)\b|\bwill (?:start|rerun|continue|resume|fix)\b|\b(?:should|need to|needs to) (?:start|restart|fix|rerun|continue|resume|launch)\b|\bI (?:did not|didn't|haven't|have not) (?:touch|start|restart|fix|launch|change|kill)\b|\bI (?:have not|haven't|did not|didn't|could not|couldn't) (?:found|find|locate|identif\w+|trace)\b|\bthat'?s the next thing\b|\bnext (?:thing|step) (?:to|is to) (?:pin|find|trace|figure|determine)\b|\b(?:remaining|left):?\s+\d+\b"))
}
fn work_left_nonstatus() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\b[\w./-]*pending[\w./-]*\.(?:md|json|ya?ml|txt|py|js|mjs|toml)\b|\bpending\s+(?:doc|document|note|plan|adr|spec|queue)s?\b"))
}
fn work_left_done_negation() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\b(?:nothing|none|no(?:t anything)?)\s+(?:is\s+)?(?:still\s+)?(?:left|pending|queued|remaining|outstanding|stuck|blocked|waiting|further)\b|\bno\s+(?:remaining|further|outstanding|pending)\s+(?:work|tasks?|steps?|actions?|items?)\b|\b(?:all|everything)\s+(?:is\s+)?(?:done|complete|completed|finished|verified|passing|green|shipped)\b|\bnothing (?:left|remains|remaining|further|else)\b"))
}
fn work_left_action_taken() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\bI (?:fixed|patched|started|restarted|launched|killed|stopped|resumed|continued)\b|\b(?:fixed|patched|restarted|launched|resumed|continued) (?:it|them|the|all|workers?|jobs?|runs?|processes?)\b|\b(?:workers?|jobs?|runs?|processes?) (?:are|were) (?:fixed|patched|started|restarted|launched|resumed|continued)\b|\bnow running\b|\bverified\b|\bconfirmed\b|\bprogress(?:ing)? again\b|\bno safe corrective action\b|\bleft (?:it|them) untouched because\b"))
}
fn work_left_hard_blocker_mention() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\bhard blocker\b|\bblocked because\b|\bneeds user input\b|\bneed(?:s)? (?:your|user) (?:input|approval|credentials|decision|confirmation)\b"))
}
fn work_left_review_self() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\breview-self\b|\bself-review\b|\breviewed alternatives\b"))
}

/// Unfinished-work language with no corrective action taken and no genuine
/// done/blocked carve-out.
pub fn work_left_stuck(text: &str) -> bool {
    let cleaned = work_left_nonstatus().replace_all(text, " ").into_owned();
    if !work_left_pattern().is_match(&cleaned) {
        return false;
    }
    if work_left_done_negation().is_match(&cleaned) {
        return false;
    }
    if work_left_action_taken().is_match(&cleaned) {
        return false;
    }
    if work_left_hard_blocker_mention().is_match(&cleaned) && work_left_review_self().is_match(&cleaned) {
        return false;
    }
    true
}

// --- D-4: tool-denial ---------------------------------------------------------

fn tool_denial_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\bI don'?t have (?:web ?search|webfetch|web_search|web_fetch)\b|\bI don'?t have access to (?:web ?search|webfetch|the (?:web|internet))\b|\bI can'?t (?:search the web|use web ?search|use webfetch|browse the web|fetch URLs?)\b|\bno (?:web ?search|webfetch) (?:available|access) (?:in this|for this) session\b|\bI (?:cannot|can'?t) access (?:web ?search|webfetch|the (?:internet|web))\b"))
}

/// The specific matched phrase claiming a tool is missing, or `None`.
pub fn tool_denial_match(text: &str) -> Option<String> {
    tool_denial_pattern().find(text).map(|m| m.as_str().to_string())
}

// --- D-5: scope-cut-after-explicit-directive ----------------------------------

fn scope_cut_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\b(?:5|four|five|six) (?:of|out of) (?:8|seven|eight|nine|ten)\b|\bskip(?:ping)? the (?:3|three|four|five) (?:NeMo |models?|options?)|\b(?:defer|punt|table) (?:these|them|the|this|that|it)\b|\bdrop(?:ping)? (?:the |these |\d+ )?(?:models?|options?|features?)\b|\bship (?:5 )?tonight\b|\bthis (?:is a |would be a |feels like a )?(?:tar pit|rabbit hole|deep hole)\b|\bno way forward\b|\b(?:will|would) take \d+(?:-\d+)? hours? to (?:fully )?(?:fix|sort|resolve)\b|\binstead of (?:all |the )?\d+\b|\bnot worth (?:saving|the time)\b|\bdo (?:bake-?off|test|run) with (?:5|fewer|just )\b"))
}

/// The specific matched scope-cut phrase, or `None`.
pub fn scope_cut_match(text: &str) -> Option<String> {
    scope_cut_pattern().find(text).map(|m| m.as_str().to_string())
}

// --- deferred-defect shapes ----------------------------------------------------

fn deferred_defect_markers() -> &'static Vec<(&'static str, Regex)> {
    static CELL: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            ("worth-flagging", ci(r"\bworth\s+(?:flagging|mentioning)\b")),
            ("worth-doing-later", ci(r"\bworth\s+doing\s+(?:at\s+some\s+point|later|some\s*time)\b")),
            ("leave-for-later", ci(r"\bi(?:'|\u{2019})?ll\s+leave\s+(?:that|this|it)\s+for\s+(?:a\s+)?(?:later|follow-?up|another\s+time)\b")),
            ("someone-should", ci(r"\bsomeone\s+should\s+(?:clean|fix|address|look\s+at|handle|sync)\b")),
            ("out-of-scope-for-now", ci(r"\bout\s+of\s+scope\s+for\s+now\b")),
            ("todo-fix-later", ci(r"\bTODO:?\s*(?:fix|address|clean\s*up|sync)\s+(?:this\s+)?later\b")),
            ("separate-cleanup", ci(r"\b(?:a\s+)?separate\s+cleanup\b")),
            ("note-for-later", ci(r"\bnote\s+for\s+later\b")),
        ]
    })
}

fn deferred_defect_carve_outs() -> &'static Vec<Regex> {
    static CELL: OnceLock<Vec<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            ci(r"\b(?:another|a\s+separate|the\s+other)\s+agent\b|\b(?:sage|alchemist|oracle|covenant)\s+(?:is|will\s+be|has|already)\b|\bnot\s+(?:your|my)\s+lane\b"),
            ci(r"\bneeds?\s+(?:your|operator'?s|the\s+user'?s)\s+(?:input|decision|credentials|approval|confirmation|call|access)\b|\bblocked\s+on\s+(?:your|operator'?s|the\s+user'?s)\b|\bOPERATOR[- ]ONLY\b|\breserved\s+(?:to|for)\s+(?:you|operator)\b"),
            ci(r"\bwant\s+me\s+to\s+also\b|\bhappy\s+to\s+also\b"),
            ci(r"\b(?:already|also)\s+(?:fixed|resolved|patched|corrected|addressed|recorded)\b"),
            ci(r"\bspawn_task\b|\bspawned\s+a\s+(?:background\s+)?task\b|\bfiled\s+(?:as|a)\s+(?:background\s+)?task\b"),
        ]
    })
}

fn deferred_ok_tag() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\[deferred-ok(?::[^\]]{0,200})?\]"))
}

/// Which deferred-defect markers fire, after dropping carved-out paragraphs
/// and respecting the override tag. Pure — mirrors the JS `deferredDefectCodes`,
/// the single source of stop-policy content that generated hook copies must
/// reproduce.
pub fn deferred_defect_codes(text: &str) -> Vec<&'static str> {
    if deferred_ok_tag().is_match(text) {
        return Vec::new();
    }
    let mut codes: Vec<&'static str> = Vec::new();
    for paragraph in text.split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
        // JS splits on /\n\s*\n/ (blank line with optional whitespace); a
        // plain "\n\n" split is equivalent for the fixtures this gate reads
        // (transcripts never carry trailing-whitespace-only blank lines) and
        // avoids a manual regex-split reimplementation.
        if deferred_defect_carve_outs().iter().any(|re| re.is_match(paragraph)) {
            continue;
        }
        for (code, pattern) in deferred_defect_markers() {
            if pattern.is_match(paragraph) && !codes.contains(code) {
                codes.push(code);
            }
        }
    }
    codes.sort_unstable();
    codes
}

// --- finding language ----------------------------------------------------------

fn finding_language() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\b(worth (noting|knowing|recording|your attention)|for (the )?(pattern file|future reference|posterity)|note for (the )?(future|next)|lesson (here|learned)|gotcha|trap for|bit(es|) us|cost (me|us) (an hour|hours|time)|next agent (should|will|needs)|remember (this|that) for)\b"))
}

fn record_targets() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"(GOTCHAS?\.md|HANDOFF\.md|crypt\b|\bmemory/[\w-]+\.md)"))
}

const DURABLE_WRITE_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"];
const COMMAND_TOOLS: &[&str] = &["Bash", "PowerShell", "shell", "shell_command"];

fn is_error_output_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r#"Script failed|"isError"\s*:\s*true|Exit code:\s*[1-9]"#))
}
fn crypt_put_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r"\bcrypt\s+put\b"))
}
fn apply_patch_call_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| plain(r"tools\.apply_patch\s*\("))
}

// --- transcript entry model ----------------------------------------------------

/// One JSONL transcript line, parsed leniently (unparsable lines are dropped,
/// matching the JS `try { JSON.parse(line) } catch { continue; }`).
fn transcript_entries(raw: &str) -> Vec<Value> {
    raw.split('\n')
        .filter(|l| !l.is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

#[derive(Debug, Clone)]
struct ContentBlock {
    kind: String,
    id: Option<String>,
    name: Option<String>,
    input: Value,
    text: Option<String>,
    tool_use_id: Option<String>,
    is_error: Option<bool>,
}

fn content_blocks(entry: &Value) -> Vec<ContentBlock> {
    // Claude-style entries: entry.message.content (array) or entry.content.
    let content = entry
        .get("message")
        .and_then(|m| m.get("content"))
        .or_else(|| entry.get("content"));
    if let Some(Value::Array(items)) = content {
        return items
            .iter()
            .map(|block| ContentBlock {
                kind: block.get("type").and_then(Value::as_str).unwrap_or_default().to_string(),
                id: block.get("id").and_then(Value::as_str).map(String::from),
                name: block.get("name").and_then(Value::as_str).map(String::from),
                input: block.get("input").cloned().unwrap_or(Value::Null),
                text: block.get("text").and_then(Value::as_str).map(String::from),
                tool_use_id: block.get("tool_use_id").and_then(Value::as_str).map(String::from),
                is_error: block.get("is_error").and_then(Value::as_bool),
            })
            .collect();
    }
    // Codex-style `response_item` entries.
    if entry.get("type").and_then(Value::as_str) == Some("response_item") {
        if let Some(payload) = entry.get("payload") {
            let payload_type = payload.get("type").and_then(Value::as_str);
            if payload_type == Some("message") {
                if let Some(Value::Array(items)) = payload.get("content") {
                    return items
                        .iter()
                        .filter_map(|block| {
                            let t = block.get("type").and_then(Value::as_str)?;
                            let mapped = if matches!(t, "input_text" | "output_text") { "text" } else { t };
                            Some(ContentBlock {
                                kind: mapped.to_string(),
                                id: None,
                                name: None,
                                input: Value::Null,
                                text: block.get("text").and_then(Value::as_str).map(String::from),
                                tool_use_id: None,
                                is_error: None,
                            })
                        })
                        .collect();
                }
                return Vec::new();
            }
            if matches!(payload_type, Some("custom_tool_call") | Some("function_call")) {
                let call_id = payload
                    .get("call_id")
                    .and_then(Value::as_str)
                    .or_else(|| payload.get("id").and_then(Value::as_str))
                    .map(String::from);
                let name = payload.get("name").and_then(Value::as_str).map(String::from);
                let input = payload
                    .get("input")
                    .or_else(|| payload.get("arguments"))
                    .cloned()
                    .unwrap_or(Value::Null);
                return vec![ContentBlock {
                    kind: "tool_use".to_string(),
                    id: call_id,
                    name,
                    input,
                    text: None,
                    tool_use_id: None,
                    is_error: None,
                }];
            }
            if matches!(payload_type, Some("custom_tool_call_output") | Some("function_call_output")) {
                let output_json = serde_json::to_string(payload.get("output").unwrap_or(&Value::String(String::new())))
                    .unwrap_or_default();
                let tool_use_id = payload.get("call_id").and_then(Value::as_str).map(String::from);
                return vec![ContentBlock {
                    kind: "tool_result".to_string(),
                    id: None,
                    name: None,
                    input: Value::Null,
                    text: None,
                    tool_use_id,
                    is_error: Some(is_error_output_re().is_match(&output_json)),
                }];
            }
        }
    }
    Vec::new()
}

fn entry_role(entry: &Value) -> Option<String> {
    if entry.get("message").is_some() {
        return entry.get("type").and_then(Value::as_str).map(String::from);
    }
    if entry.get("type").and_then(Value::as_str) == Some("response_item") {
        if let Some(payload) = entry.get("payload") {
            if payload.get("type").and_then(Value::as_str) == Some("message") {
                return payload.get("role").and_then(Value::as_str).map(String::from);
            }
        }
    }
    None
}

fn latest_external_user_index(entries: &[Value]) -> Option<usize> {
    for (i, entry) in entries.iter().enumerate().rev() {
        if entry_role(entry).as_deref() != Some("user") {
            continue;
        }
        if content_blocks(entry).iter().any(|b| b.kind == "tool_result") {
            continue;
        }
        return Some(i);
    }
    None
}

fn durable_write_use(block: &ContentBlock) -> bool {
    if block.kind != "tool_use" {
        return false;
    }
    let name = block.name.as_deref().unwrap_or_default();
    if DURABLE_WRITE_TOOLS.contains(&name) {
        let input_json = serde_json::to_string(&block.input).unwrap_or_default();
        return record_targets().is_match(&input_json);
    }
    if name == "exec" {
        if let Value::String(input) = &block.input {
            if apply_patch_call_re().is_match(input) {
                return record_targets().is_match(input);
            }
        }
        return false;
    }
    if !COMMAND_TOOLS.contains(&name) {
        return false;
    }
    let command = match &block.input {
        Value::String(s) => Some(s.as_str()),
        Value::Object(map) => map.get("command").and_then(Value::as_str),
        _ => None,
    };
    command.is_some_and(|c| crypt_put_re().is_match(c))
}

/// Did this turn actually record something durable? Reads the transcript for
/// a tool call that wrote to a recognised destination (GOTCHAS.md,
/// HANDOFF.md, memory/*.md, or a `crypt put`), paired with a successful
/// result.
pub fn recorded_this_turn(transcript_text: &str) -> bool {
    let entries = transcript_entries(transcript_text);
    let last_user = match latest_external_user_index(&entries) {
        Some(i) => i,
        None => return false,
    };
    let mut pending: Vec<String> = Vec::new();
    for entry in &entries[last_user + 1..] {
        for block in content_blocks(entry) {
            if durable_write_use(&block) {
                if let Some(id) = &block.id {
                    pending.push(id.clone());
                }
            }
            if block.kind == "tool_result" {
                if let Some(tool_use_id) = &block.tool_use_id {
                    if pending.iter().any(|p| p == tool_use_id) && block.is_error != Some(true) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Evidence that a reserved decision reached its authority owner before
/// blocking: a real Sage dispatch somewhere in this session's raw transcript
/// (tool-call JSON), never the agent's prose claim of one.
fn escalation_evidence_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| ci(r#""subagent_type"\s*:\s*"(?:legion:)?sage"|(?:^|\s)@sage\b"#))
}

pub fn escalated_this_session(transcript_text: &str) -> bool {
    escalation_evidence_re().is_match(transcript_text)
}

const ESCALATION: [&str; 2] = [
    "Resolve it yourself now; dispatch Sage only if material meaning, ownership, or acceptance remains unresolved.",
    "Make the best bounded decision from settled doctrine and record the reasoning. Re-verify the blocker against CURRENT state before re-asserting it — a blocker observed earlier in a session is often already stale.",
];

/// The last assistant text block in the transcript, newest-first.
pub fn last_assistant_text(raw: &str) -> Option<String> {
    let lines: Vec<&str> = raw.split('\n').filter(|l| !l.is_empty()).collect();
    for line in lines.iter().rev() {
        let entry: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if entry_role(&entry).as_deref() != Some("assistant") {
            continue;
        }
        let text = content_blocks(&entry)
            .iter()
            .filter(|b| b.kind == "text")
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        if !text.is_empty() {
            return Some(text);
        }
    }
    None
}

/// Was any tool used after the last genuine (non-tool-result) user turn?
pub fn tool_use_after_last_user(transcript_text: &str) -> bool {
    let entries = transcript_entries(transcript_text);
    let last_user = match latest_external_user_index(&entries) {
        Some(i) => i,
        None => return false,
    };
    entries[last_user + 1..]
        .iter()
        .any(|entry| content_blocks(entry).iter().any(|b| b.kind == "tool_use"))
}

// --- stripCodeSpans ------------------------------------------------------------

fn fence_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| plain(r"```[\s\S]*?```|~~~[\s\S]*?~~~"))
}
fn inline_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| plain(r"`[^`\n]*`"))
}
fn quoted_span_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| plain("[\"\u{201c}][^\"\u{201c}\u{201d}\n]{0,300}[\"\u{201d}]"))
}

/// A turn that DISCUSSES a trigger phrase must not trip the gate that
/// enforces it.
pub fn strip_code_spans(text: &str) -> String {
    let step1 = fence_re().replace_all(text, " ");
    let step2 = inline_code_re().replace_all(&step1, " ");
    let step3 = quoted_span_re().replace_all(&step2, " ");
    step3.into_owned()
}

// --- evaluateStopShape -----------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopVerdict {
    pub block: bool,
    pub reason: Option<String>,
    pub shape: Option<String>,
    pub instruction: Option<String>,
    pub advisory: Option<String>,
}

impl StopVerdict {
    fn no_block(reason: &str) -> Self {
        StopVerdict { block: false, reason: Some(reason.to_string()), shape: None, instruction: None, advisory: None }
    }
    fn blocked(shape: &str, instruction: String) -> Self {
        StopVerdict { block: true, reason: None, shape: Some(shape.to_string()), instruction: Some(instruction), advisory: None }
    }
}

#[derive(Debug, Clone)]
pub struct StopShapeOptions {
    pub intent: String,
    pub pushes: u32,
    pub reopenings: u32,
    pub recorded: bool,
    pub escalated: bool,
    pub authorized: bool,
    pub authorized_evidence: Option<String>,
    pub explicit_directive_evidence: Vec<String>,
    pub continue_intent_evidence: Option<String>,
    pub continue_tools_used: bool,
}

impl Default for StopShapeOptions {
    fn default() -> Self {
        StopShapeOptions {
            intent: "EXECUTE".to_string(),
            pushes: 0,
            reopenings: 0,
            recorded: false,
            escalated: false,
            authorized: false,
            authorized_evidence: None,
            explicit_directive_evidence: Vec::new(),
            continue_intent_evidence: None,
            continue_tools_used: false,
        }
    }
}

fn truncate_collapsed(text: &str, max_chars: usize) -> String {
    let collapsed: String = {
        let mut out = String::new();
        let mut last_was_space = false;
        for ch in text.chars() {
            if ch.is_whitespace() {
                if !last_was_space {
                    out.push(' ');
                }
                last_was_space = true;
            } else {
                out.push(ch);
                last_was_space = false;
            }
        }
        out
    };
    collapsed.chars().take(max_chars).collect()
}

/// Port of `evaluateStopShape` in `stop-shape.mjs`. See the module doc for
/// what is intentionally out of scope (the Node CLI entry point).
pub fn evaluate_stop_shape(final_text: &str, options: &StopShapeOptions) -> StopVerdict {
    if final_text.is_empty() {
        return StopVerdict::no_block("no-final-text");
    }
    if options.intent != "EXECUTE" && options.intent != "CONTINUE" {
        return StopVerdict::no_block("non-compelling-intent");
    }
    if options.pushes >= MAX_PUSHES || options.reopenings >= MAX_PUSHES {
        let advisory = if !options.recorded && finding_language().is_match(final_text) {
            Some("A durable finding was reported but no successful post-user write to GOTCHAS.md, HANDOFF.md, memory, or crypt was observed.".to_string())
        } else {
            None
        };
        return StopVerdict { block: false, reason: Some("stop-circuit-open".to_string()), shape: None, instruction: None, advisory };
    }

    // Packet parsing stays on the RAW text (see JS comment: structured
    // blockers legitimately carry quoted JSON keys).
    if hard_blocker_re().is_match(final_text) {
        if !options.authorized && is_push_gate_laundering(final_text) {
            return StopVerdict::blocked(
                "unreserved-blocker",
                "Your blocker gate is an ordinary git push, worded as reserved. A normal push of requested work to the operator's own remotes is pre-approved: using the word \"irreversible\" does not make it publication or destruction. Only a --force push or a history rewrite on a shared branch is genuinely reserved. Push it and report the receipt.".to_string(),
            );
        }
        if ci(r"\bHARD BLOCKER\b").is_match(final_text) {
            return StopVerdict::no_block("hard-blocker-stated");
        }
        if options.authorized {
            let evidence_suffix = options
                .authorized_evidence
                .as_deref()
                .map(|ev| format!(" (\"{}\")", truncate_collapsed(ev, 120)))
                .unwrap_or_default();
            return StopVerdict::blocked(
                "already-authorized",
                format!(
                    "the operator already told you to proceed in a recent turn{evidence_suffix}. That IS the approval — asking again is the stop-short. Do the work and report the receipt. If a later instruction held you back, or the effect is genuinely outside what he asked for, say which and name it precisely."
                ),
            );
        }
        if !reserved_categories(final_text).is_empty() {
            if options.escalated {
                return StopVerdict::no_block("reserved-blocker-escalated");
            }
            return StopVerdict::blocked(
                "unescalated-blocker",
                "Your blocker names a real category but shows no authority resolution. Resolve settled work directly. If material meaning, ownership, or acceptance remains unresolved, dispatch Sage now and block only if Sage cannot settle it.".to_string(),
            );
        }
        return StopVerdict::blocked(
            "unreserved-blocker",
            "Your BLOCKED-ON-APPROVAL names no canonical reserved category. Only five exist: missing private input, new spend, unrequested publication or production mutation, destruction, or a reserved decision. A rule found in a doc is not a sixth category — if the work is reversible and in scope, the operator already authorized it. Do it.".to_string(),
        );
    }

    // Prose heuristics run on the stripped view.
    let prose = strip_code_spans(final_text);
    let tail: String = {
        let chars: Vec<char> = prose.chars().collect();
        let start = chars.len().saturating_sub(1200);
        chars[start..].iter().collect()
    };
    for shape in shapes() {
        if shape.pattern.is_match(&tail) {
            if let Some(requires) = &shape.requires {
                if !requires.is_match(&prose) {
                    continue;
                }
            }
            if let Some(carve_out) = &shape.carve_out {
                if carve_out.is_match(&prose) {
                    continue;
                }
            }
            let escalation = ESCALATION[(options.pushes as usize).min(ESCALATION.len() - 1)];
            return StopVerdict::blocked(shape.name, format!("{} {}", shape.instruction, escalation));
        }
    }

    // D-4: tool-denial.
    if let Some(tool_denial) = tool_denial_match(&prose) {
        return StopVerdict::blocked(
            "tool-denial",
            format!(
                "You claimed a tool is missing without verifying it against this session's tools list (detected: \"{tool_denial}\"). Check the available-tools list before claiming absence; if it is genuinely unavailable, say so precisely instead of \"I don't have X\"."
            ),
        );
    }

    // D-5: scope-cut-after-explicit-directive.
    if !options.explicit_directive_evidence.is_empty() {
        if let Some(scope_cut) = scope_cut_match(&prose) {
            let directive = truncate_collapsed(&options.explicit_directive_evidence[0], 80);
            return StopVerdict::blocked(
                "scope-cut",
                format!(
                    "the operator issued an explicit no-deferral directive (\"{directive}\") and this reply proposes a scope cut or deferral (detected: \"{scope_cut}\"). Execute the literal request. If genuinely blocked, report \"tried [X]: [error]. trying [Y].\" and keep moving — do not fork or defer."
                ),
            );
        }
    }

    // Continue-intent.
    if let Some(evidence) = &options.continue_intent_evidence {
        if !evidence.is_empty()
            && !action_done_re().is_match(&prose)
            && !continue_blocker_re().is_match(&prose)
            && (!options.continue_tools_used || stop_only_re().is_match(&prose))
        {
            return StopVerdict::blocked(
                "continue-intent",
                format!(
                    "the operator's latest message (\"{evidence}\") is an instruction, not an invitation to explain and stop. Do the work now, or state a hard blocker with the exact missing input. Do not end on \"we can/should/I will\" when the missing work is safe to do."
                ),
            );
        }
    }

    // D-3: work-left-stuck.
    if work_left_stuck(&prose) {
        return StopVerdict::blocked(
            "work-left-stuck",
            "You reported unfinished work (stuck/queued/pending/no corrective action) without a hard blocker. Do NOT stop to ask whether to continue — keep working now, or state a HARD BLOCKER with the exact missing input.".to_string(),
        );
    }

    // Deferred-defect: checked against the WHOLE message.
    let deferred = deferred_defect_codes(final_text);
    if !deferred.is_empty() {
        return StopVerdict::blocked(
            "deferred-defect",
            format!(
                "You deferred a found issue instead of resolving it (matched: {}). Standing rule: found issues get fixed in the turn that found them. If it is fixable now, fix it and report the fixed state. If it genuinely is not yours, say which agent owns it, what input only the operator can supply, or that you filed it as a background task. If deferring is still correct, tag the reply [deferred-ok: <reason>].",
                deferred.join(", ")
            ),
        );
    }

    // Unrecorded finding: checked against the WHOLE message.
    if !options.recorded && finding_language().is_match(final_text) {
        return StopVerdict::blocked(
            "unrecorded-finding",
            "You reported something a future agent needs, but only in chat — nothing here survives this session. Append it to docs/GOTCHAS.md (symptom, cause, fix), or to the relevant HANDOFF, or save it with crypt.".to_string(),
        );
    }

    StopVerdict::no_block("clean-ending")
}

/// Port of `evaluateTranscriptStop`: reads a transcript file and evaluates
/// the Stop shape. Retry state (`pushes`/`reopenings`) belongs to the
/// authenticated runtime and is not read here, matching the JS source (its
/// own comment: "Evaluate Stop shape only").
pub fn evaluate_transcript_stop(transcript_path: &str) -> StopVerdict {
    let raw = match fs::read_to_string(transcript_path) {
        Ok(r) => r,
        Err(_) => return StopVerdict::no_block("transcript-unreadable"),
    };
    let intent = classify_latest_user_intent(&raw);
    let latest_instruction = latest_external_user_turn(&raw).unwrap_or_default();
    let authorized = matches!(intent.intent, Intent::Execute | Intent::Continue);
    let options = StopShapeOptions {
        intent: match intent.intent {
            Intent::Execute => "EXECUTE".to_string(),
            Intent::Continue => "CONTINUE".to_string(),
            Intent::Revoke => "REVOKE".to_string(),
            Intent::ScopeNarrow => "SCOPE_NARROW".to_string(),
            Intent::Plan => "PLAN".to_string(),
            Intent::Question => "QUESTION".to_string(),
            Intent::Unknown => "UNKNOWN".to_string(),
        },
        pushes: 0,
        reopenings: 0,
        recorded: recorded_this_turn(&raw),
        escalated: escalated_this_session(&raw),
        authorized,
        authorized_evidence: intent.evidence,
        explicit_directive_evidence: Vec::new(),
        continue_intent_evidence: continue_intent(&latest_instruction),
        continue_tools_used: tool_use_after_last_user(&raw),
    };
    let final_text = last_assistant_text(&raw).unwrap_or_default();
    evaluate_stop_shape(&final_text, &options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> StopShapeOptions {
        StopShapeOptions::default()
    }

    fn with_escalated() -> StopShapeOptions {
        StopShapeOptions { escalated: true, ..opts() }
    }

    // --- permission-question / deferral / caveat / deferred-work shapes ---

    #[test]
    fn permission_questions_block() {
        for ending in [
            "Done mostly. Say go and I execute.",
            "Shall I proceed with the fix?",
            "Do you want me to wire it in?",
            "Awaiting your approval to continue.",
        ] {
            assert!(evaluate_stop_shape(ending, &opts()).block, "{ending}");
        }
    }

    #[test]
    fn caveats_and_deferred_promises_block() {
        assert!(evaluate_stop_shape("Fixed. One caveat: the cache is stale.", &opts()).block);
        assert!(evaluate_stop_shape("Tests green. I'll fix that later.", &opts()).block);
        assert!(evaluate_stop_shape("Works, but the retry path remains to be built.", &opts()).block);
    }

    #[test]
    fn completed_work_passes() {
        assert!(!evaluate_stop_shape("Fixed the parser, 12/12 tests, committed abc123.", &opts()).block);
    }

    #[test]
    fn reserved_blocker_is_legal_in_any_format() {
        for ending in [
            "Deploy staged. HARD BLOCKER: the Cloudflare token only the operator can supply.",
            "BLOCKED-ON-APPROVAL: publish @rightkit/ax@0.1.1 (publication/production mutation)",
            "blocked-on-approval: new spend — the Hetzner upgrade needs your card",
            "Work verified.\nBLOCKED-ON-APPROVAL\n  category: destruction\n  action: drop the legacy table",
            "BLOCKED-ON-APPROVAL:\n{\n  \"reserved_category\": \"reserved_decision\"\n}",
        ] {
            assert!(!evaluate_stop_shape(ending, &with_escalated()).block, "{ending}");
        }
    }

    #[test]
    fn caveat_resolved_mid_turn_does_not_block() {
        let padded = "One caveat existed here early on. ".to_string() + &"x ".repeat(650);
        let text = format!("{padded}\nAll of it is now fixed and verified, 44/44.");
        assert!(!evaluate_stop_shape(&text, &opts()).block);
    }

    #[test]
    fn block_instructions_escalate_across_pushes() {
        let first = evaluate_stop_shape("Say go and I execute.", &StopShapeOptions { pushes: 0, ..opts() });
        let second = evaluate_stop_shape("Say go and I execute.", &StopShapeOptions { pushes: 1, ..opts() });
        assert!(first.block);
        assert!(second.block);
        assert_ne!(first.instruction, second.instruction);
        assert!(first.instruction.as_deref().unwrap().contains("Sage"));
        assert!(!second.instruction.as_deref().unwrap().contains("Covenant"));
        assert!(second.instruction.as_deref().unwrap().contains("CURRENT state"));
    }

    #[test]
    fn push_cap_ends_the_loop() {
        assert!(evaluate_stop_shape("Say go and I execute.", &StopShapeOptions { pushes: 1, ..opts() }).block);
        assert!(!evaluate_stop_shape("Say go and I execute.", &StopShapeOptions { pushes: 2, ..opts() }).block);
    }

    #[test]
    fn deferral_offer_is_caught() {
        let escaped = "Next action: add export RIGHT_RELEASE_CACHE_ROOT=/Volumes/D/rightsuite-cache/release to your ~/.zshenv, or tell me to and I'll do it.";
        let verdict = evaluate_stop_shape(escaped, &opts());
        assert!(verdict.block);
        assert_eq!(verdict.shape.as_deref(), Some("deferral-offer"));
        for variant in ["Or I can add it for you.", "If you want, I can wire that in.", "Tell me to and I'll do it."] {
            assert!(evaluate_stop_shape(variant, &opts()).block, "{variant}");
        }
    }

    #[test]
    fn genuine_operator_only_next_action_passes() {
        for ending in [
            "Done and verified. Next action for you: approve the $40/mo Hetzner upgrade in the console.",
            "Complete. You will need to enter the 2FA code on your phone to finish enrollment.",
        ] {
            assert!(!evaluate_stop_shape(ending, &opts()).block, "{ending}");
        }
    }

    #[test]
    fn unrecorded_finding_blocks_and_recorded_passes() {
        let unrecorded = evaluate_stop_shape(
            "Fixed and verified. Worth noting for the pattern file: hooks are additive, so a duplicate registration denies every Write.",
            &StopShapeOptions { recorded: false, ..opts() },
        );
        assert!(unrecorded.block);
        assert_eq!(unrecorded.shape.as_deref(), Some("unrecorded-finding"));
        assert!(unrecorded.instruction.as_deref().unwrap().contains("GOTCHAS.md"));

        let recorded = evaluate_stop_shape(
            "Fixed and verified. Worth noting for the pattern file: hooks are additive.",
            &StopShapeOptions { recorded: true, ..opts() },
        );
        assert!(!recorded.block);
    }

    #[test]
    fn ordinary_work_reports_do_not_trip_finding_check() {
        for ending in [
            "Fixed the parser, 12/12 tests, committed abc123.",
            "Wired both machines and verified: 0 duplicates, exit 0.",
            "Note: the suite takes about 40 seconds.",
        ] {
            assert!(!evaluate_stop_shape(ending, &StopShapeOptions { recorded: false, ..opts() }).block, "{ending}");
        }
    }

    // --- recordedThisTurn / transcript reading -----------------------------

    fn transcript_after_user(blocks: &[serde_json::Value]) -> String {
        let mut lines = vec![serde_json::json!({"type": "user", "message": {"content": [{"type": "text", "text": "record it"}]}}).to_string()];
        lines.extend(blocks.iter().map(|b| b.to_string()));
        lines.join("\n")
    }

    #[test]
    fn recorded_this_turn_requires_paired_successful_write() {
        let write = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "w1", "name": "Write", "input": {"file_path": "D:/workspace/docs/GOTCHAS.md"}}]}});
        let ok = serde_json::json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "w1", "content": "ok"}]}});
        let failed = serde_json::json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "w1", "is_error": true, "content": "failed"}]}});
        assert!(recorded_this_turn(&transcript_after_user(&[write.clone(), ok])));
        assert!(!recorded_this_turn(&transcript_after_user(&[write.clone()])), "an attempted write is not a receipt");
        assert!(!recorded_this_turn(&transcript_after_user(&[write, failed])));

        let read_use = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "r1", "name": "Read", "input": {"file_path": "D:/workspace/docs/GOTCHAS.md"}}]}});
        let read_result = serde_json::json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "r1"}]}});
        assert!(!recorded_this_turn(&transcript_after_user(&[read_use, read_result])));

        let text_only = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "text", "text": "docs/plans/legion/HANDOFF.md"}]}});
        assert!(!recorded_this_turn(&transcript_after_user(&[text_only])));
    }

    #[test]
    fn recorded_this_turn_accepts_apply_patch_and_crypt_only() {
        let patch_use = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "p1", "name": "apply_patch", "input": "*** Update File: docs/GOTCHAS.md"}]}});
        let patch_result = serde_json::json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "p1"}]}});
        assert!(recorded_this_turn(&transcript_after_user(&[patch_use, patch_result])));

        let memory_use = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "m1", "name": "Bash", "input": {"command": "crypt put hook-lesson --scope claude"}}]}});
        let memory_result = serde_json::json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "m1"}]}});
        assert!(recorded_this_turn(&transcript_after_user(&[memory_use, memory_result])));

        let retired_use = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "m2", "name": "Bash", "input": {"command": "memright put hook-lesson --scope claude"}}]}});
        let retired_result = serde_json::json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "m2"}]}});
        assert!(!recorded_this_turn(&transcript_after_user(&[retired_use, retired_result])));
    }

    #[test]
    fn codex_response_item_calls_prove_successful_writes_only() {
        let user = serde_json::json!({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "record it"}]}}).to_string();
        let call = serde_json::json!({"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": "c1", "name": "exec", "input": "text(await tools.apply_patch(\"*** Update File: D:/workspace/docs/GOTCHAS.md\"));"}}).to_string();
        let ok = serde_json::json!({"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c1", "output": [{"type": "input_text", "text": "Script completed\nOutput: {}"}]}}).to_string();
        let failed = serde_json::json!({"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c1", "output": [{"type": "input_text", "text": "Script failed\nExit code: 1"}]}}).to_string();

        assert!(recorded_this_turn(&[user.clone(), call.clone(), ok].join("\n")));
        assert!(!recorded_this_turn(&[user.clone(), call.clone(), failed].join("\n")));
        assert!(tool_use_after_last_user(&[user, call].join("\n")));
    }

    #[test]
    fn recorded_this_turn_ignores_writes_from_an_earlier_user_turn() {
        let earlier_write = serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "w1", "name": "Write", "input": {"file_path": "docs/GOTCHAS.md"}}]}});
        let earlier_result = serde_json::json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "w1"}]}});
        let earlier = transcript_after_user(&[earlier_write, earlier_result]);
        let latest = serde_json::json!({"type": "user", "message": {"content": [{"type": "text", "text": "new question"}]}}).to_string();
        assert!(!recorded_this_turn(&format!("{earlier}\n{latest}")));
    }

    #[test]
    fn open_circuit_makes_missing_durability_advisory_not_blocking() {
        let verdict = evaluate_stop_shape(
            "Fixed it. Worth noting for future reference: rename scans can explode.",
            &StopShapeOptions { pushes: 2, recorded: false, ..opts() },
        );
        assert!(!verdict.block);
        assert_eq!(verdict.reason.as_deref(), Some("stop-circuit-open"));
        assert!(verdict.advisory.as_deref().unwrap().to_lowercase().contains("no successful post-user write"));
    }

    // --- deferred-defect ----------------------------------------------------

    #[test]
    fn deferring_a_found_defect_blocks() {
        for ending in [
            "Worth flagging for later: sampleapp's committed AGENTS.md is still stale doctrine on origin. That's a separate cleanup whenever you want it.",
            "I'll leave that for a follow-up.",
            "Someone should clean this up eventually.",
            "Out of scope for now, but note that the retry logic is flaky.",
            "TODO: fix later.",
            "Note for later: the cache eviction logic looks fragile.",
            "The duplicate config is worth doing at some point.",
        ] {
            let verdict = evaluate_stop_shape(ending, &opts());
            assert!(verdict.block, "{ending}");
            assert_eq!(verdict.shape.as_deref(), Some("deferred-defect"), "{ending}");
        }
    }

    #[test]
    fn legitimate_deferral_passes() {
        for ending in [
            "Worth flagging: the stale AGENTS.md — another agent is already working on that cleanup.",
            "Worth mentioning: the key rotation is overdue, but it needs your credentials to proceed.",
            "Worth mentioning: the broken link — already fixed it while I was in there.",
            "Worth flagging: sampleapp's AGENTS.md is stale — filed as a background task via spawn_task.",
            "Deploying the binary is a separate cleanup, and it is OPERATOR-ONLY per HANDOFF.",
        ] {
            assert!(!evaluate_stop_shape(ending, &opts()).block, "{ending}");
        }
    }

    #[test]
    fn carve_outs_are_paragraph_scoped() {
        let laundered = "Fixed the parser and already fixed the lint config too.\n\nWorth flagging for later: the release lane still double-signs. That's a separate cleanup.";
        assert!(evaluate_stop_shape(laundered, &opts()).block, "an unrelated carve-out must not launder a real deferral");
    }

    #[test]
    fn override_tag_is_honoured() {
        let text = "Worth flagging for later: this is a separate cleanup. [deferred-ok: the operator owns this call]";
        assert!(!evaluate_stop_shape(text, &opts()).block);
    }

    #[test]
    fn reserved_blocker_wins_over_deferral_marker() {
        let text = "Worth flagging for later: the deploy is a separate cleanup.\n\nBLOCKED-ON-APPROVAL: publishing @rightkit/ax@0.1.1 (publication).";
        assert!(!evaluate_stop_shape(text, &with_escalated()).block);
    }

    #[test]
    fn push_cap_releases_a_deferral_block_too() {
        let text = "Worth flagging for later: that's a separate cleanup.";
        assert!(!evaluate_stop_shape(text, &StopShapeOptions { pushes: 2, ..opts() }).block);
    }

    #[test]
    fn invented_reserved_category_does_not_launder() {
        let v = evaluate_stop_shape(
            "BLOCKED-ON-APPROVAL: installing ~/.claude/bin/rhook.exe for the fast-path twin — reserved to the operator per HANDOFF.",
            &opts(),
        );
        assert!(v.block);
        assert_eq!(v.shape.as_deref(), Some("unreserved-blocker"));
        assert!(v.instruction.as_deref().unwrap().to_lowercase().contains("five"));
    }

    #[test]
    fn genuine_reserved_categories_still_pass() {
        for ending in [
            "BLOCKED-ON-APPROVAL: publish @rightkit/ax@0.1.1 (publication)",
            "BLOCKED-ON-APPROVAL: the Hetzner upgrade is new spend on your card",
            "BLOCKED-ON-APPROVAL: destruction — drop the legacy table",
            "BLOCKED-ON-APPROVAL: reserved decision — who may change the enforcement rules",
            "BLOCKED-ON-APPROVAL: needs your 2FA code (private input)",
            "HARD BLOCKER: the Cloudflare token only the operator can supply.",
        ] {
            assert!(!evaluate_stop_shape(ending, &with_escalated()).block, "{ending}");
        }
    }

    #[test]
    fn reserved_categories_identifies_the_canonical_five() {
        assert_eq!(reserved_categories("this needs new spend of $40"), vec!["new-spend"]);
        assert!(reserved_categories("per HANDOFF this is reserved to the operator").is_empty());
    }

    #[test]
    fn blocker_with_real_category_but_no_escalation_blocks() {
        let packet = "BLOCKED-ON-APPROVAL: flipping VCS_PUSH from deny to allow — reserved decision, it changes what the enforcement plane permits globally.";
        let verdict = evaluate_stop_shape(packet, &opts());
        assert!(verdict.block);
        assert_eq!(verdict.shape.as_deref(), Some("unescalated-blocker"));
    }

    #[test]
    fn same_blocker_passes_once_sage_was_dispatched() {
        let packet = "BLOCKED-ON-APPROVAL: flipping VCS_PUSH from deny to allow — reserved decision, it changes what the enforcement plane permits globally.";
        assert!(!evaluate_stop_shape(packet, &with_escalated()).block);
    }

    #[test]
    fn hard_blocker_never_requires_escalation() {
        let packet = "HARD BLOCKER: the Azure signing profile name, which is not in any config I can read.";
        assert!(!evaluate_stop_shape(packet, &opts()).block);
    }

    #[test]
    fn invented_category_still_blocks_with_escalation() {
        let packet = "BLOCKED-ON-APPROVAL: deploying the binary — reserved to the operator per HANDOFF.";
        let verdict = evaluate_stop_shape(packet, &with_escalated());
        assert!(verdict.block);
        assert_eq!(verdict.shape.as_deref(), Some("unreserved-blocker"));
    }

    #[test]
    fn escalation_evidence_comes_from_real_dispatches() {
        assert!(!escalated_this_session("I considered dispatching Sage about this."));
        assert!(escalated_this_session(r#"{"subagent_type":"sage","prompt":"..."}"#));
        assert!(!escalated_this_session(r#"{"subagent_type":"legion:covenant-seat"}"#));
    }

    #[test]
    fn blocker_refused_when_operator_already_said_proceed() {
        let packet = "BLOCKED-ON-APPROVAL: flipping VCS_PUSH to allow — reserved decision.";
        let verdict = evaluate_stop_shape(
            packet,
            &StopShapeOptions { escalated: true, authorized: true, authorized_evidence: Some("Go on, fix it.".to_string()), ..opts() },
        );
        assert!(verdict.block);
        assert_eq!(verdict.shape.as_deref(), Some("already-authorized"));
        assert!(verdict.instruction.as_deref().unwrap().contains("Go on, fix it"));
    }

    #[test]
    fn hard_blocker_outranks_authorization() {
        let packet = "HARD BLOCKER: the Cloudflare token only the operator can supply.";
        assert!(!evaluate_stop_shape(packet, &StopShapeOptions { authorized: true, ..opts() }).block);
    }

    #[test]
    fn without_authorization_ordinary_blocker_rules_still_apply() {
        let packet = "BLOCKED-ON-APPROVAL: destruction — drop the legacy table.";
        assert!(!evaluate_stop_shape(packet, &StopShapeOptions { escalated: true, authorized: false, ..opts() }).block);
    }

    #[test]
    fn recovered_closing_caveat_selftest_cases_block() {
        for ending in [
            "All 9 repos pushed and verified. One thing that isn't in git: the runtime DB, because it is not a repository.",
            "The fix is in and green. That said, the hook is only pattern matching.",
            "Shipped. Keep in mind the Mac picks this up on next pull.",
        ] {
            assert!(evaluate_stop_shape(ending, &opts()).block, "{ending}");
        }
    }

    #[test]
    fn recovered_deferral_offer_selftest_cases_block() {
        for ending in ["Let me know and I'll rebuild it.", "I can trace it if you want."] {
            assert!(evaluate_stop_shape(ending, &opts()).block, "{ending}");
        }
    }

    #[test]
    fn closing_caveat_without_done_claim_does_not_block() {
        let ending = "The tradeoff differs per repo. Keep in mind pnpm resolves peers differently.";
        assert!(!evaluate_stop_shape(ending, &opts()).block);
    }

    #[test]
    fn quoted_or_fenced_trigger_phrases_do_not_block() {
        for ending in [
            "Triggers now include `shall I proceed`, `awaiting your approval`, `say go`.",
            "The hook blocks `say the word and I'll trace it`; verified and synced.",
            "Verified both ways: a plain \"Shall I proceed with the commit?\" still blocks, while the documented form passes.",
            "The guard now catches \"do you want me to continue\" as well; all suites pass.",
        ] {
            assert!(!evaluate_stop_shape(ending, &opts()).block, "{ending}");
        }
    }

    #[test]
    fn same_trigger_phrase_unquoted_still_blocks() {
        assert!(evaluate_stop_shape("Everything is staged. Shall I proceed with the commit?", &opts()).block);
    }

    #[test]
    fn ordinary_git_push_worded_as_reserved_is_not_reserved() {
        let packet = "BLOCKED-ON-APPROVAL:\nGate: git push origin main in membrane (3 commits)\nReserved-reason: pushing publishes to Orthic-Labs/Membrane; outward-facing and irreversible-in-effect\nDone: 4 commits made and verified locally\nRemaining: push both repos\nNo-ungated-work: true";
        let verdict = evaluate_stop_shape(packet, &with_escalated());
        assert!(verdict.block);
        assert_eq!(verdict.shape.as_deref(), Some("unreserved-blocker"));
        assert!(is_push_gate_laundering(packet));
    }

    #[test]
    fn real_publication_not_laundered_by_ordinary_push_exemption() {
        for gate in [
            "Gate: npm publish @rightkit/git 0.2.0, then push the tag to origin",
            "Gate: pushing the release upload to the npm registry",
            "Gate: push to origin and deploy to production",
        ] {
            let packet = format!("BLOCKED-ON-APPROVAL:\n{gate}");
            assert!(!is_push_gate_laundering(&packet), "{gate}");
        }
    }

    #[test]
    fn force_push_history_rewrite_stays_reserved() {
        let packet = "BLOCKED-ON-APPROVAL:\nGate: git push --force to rewrite shared main history\nReserved-reason: destructive history rewrite on a shared branch\nDone: local branch rebased and tested\nRemaining: the force push only\nNo-ungated-work: true";
        assert!(!is_push_gate_laundering(packet));
        assert!(!evaluate_stop_shape(packet, &with_escalated()).block);
    }

    #[test]
    fn authorized_push_gate_laundering_still_clears_via_already_authorized() {
        let packet = "BLOCKED-ON-APPROVAL: git push origin main — irreversible-in-effect publication.";
        let verdict = evaluate_stop_shape(
            packet,
            &StopShapeOptions { authorized: true, authorized_evidence: Some("push it".to_string()), ..opts() },
        );
        assert!(verdict.block);
        assert_eq!(verdict.shape.as_deref(), Some("already-authorized"));
    }

    #[test]
    fn caveat_reporting_real_failure_or_hard_blocker_is_not_a_hedge() {
        for ending in [
            "One caveat: the integration tests are failing on main.",
            "One caveat: I hit an error connecting to the staging DB.",
            "One caveat: this needs your input before I can continue — HARD BLOCKER.",
        ] {
            assert!(!evaluate_stop_shape(ending, &opts()).block, "{ending}");
        }
    }

    #[test]
    fn ordinary_hedge_caveat_still_blocks() {
        let v = evaluate_stop_shape("Fixed. One caveat: the cache is stale.", &opts());
        assert!(v.block);
        assert_eq!(v.shape.as_deref(), Some("unresolved-caveat"));
    }

    #[test]
    fn generic_stuck_queued_pending_work_blocks() {
        for ending in [
            "The render is still queued and not running.",
            "The job is stuck; remaining: 12 items.",
            "I have not found the script that produces the export. That's the next thing to pin down.",
        ] {
            let v = evaluate_stop_shape(ending, &opts());
            assert!(v.block, "{ending}");
            assert_eq!(v.shape.as_deref(), Some("work-left-stuck"), "{ending}");
        }
    }

    #[test]
    fn work_left_stuck_carve_outs_pass() {
        for ending in [
            "All done, nothing pending.",
            "Everything is complete; nothing left to do.",
            "I restarted the workers; verified now running.",
            "Blocked because credentials are missing; ran /review-self.",
        ] {
            assert!(!evaluate_stop_shape(ending, &opts()).block, "{ending}");
        }
    }

    #[test]
    fn work_left_stuck_is_pure() {
        assert!(work_left_stuck("The render is still queued and not running."));
        assert!(!work_left_stuck("gstack is a third-party skill bundle."));
        assert!(!work_left_stuck("All done, nothing pending."));
    }

    #[test]
    fn claiming_missing_tool_without_verifying_blocks() {
        let v = evaluate_stop_shape("I don't have webfetch in this session, so I can't check the URL.", &opts());
        assert!(v.block);
        assert_eq!(v.shape.as_deref(), Some("tool-denial"));
        assert!(tool_denial_match("I don't have web search.").unwrap().to_lowercase().contains("don"));
    }

    #[test]
    fn scope_cut_after_explicit_no_deferral_directive_blocks() {
        let v = evaluate_stop_shape(
            "Given the time, I will drop the legacy models and ship 5 of 8 tonight.",
            &StopShapeOptions { explicit_directive_evidence: vec!["no deferring, do all 8".to_string()], ..opts() },
        );
        assert!(v.block);
        assert_eq!(v.shape.as_deref(), Some("scope-cut"));
        assert!(v.instruction.as_deref().unwrap().contains("no deferring, do all 8"));
    }

    #[test]
    fn scope_cut_language_without_explicit_directive_does_not_trip_d5() {
        let v = evaluate_stop_shape("Given the time, I will drop the legacy models and ship 5 of 8 tonight.", &opts());
        assert_ne!(v.shape.as_deref(), Some("scope-cut"));
    }

    #[test]
    fn scope_cut_match_is_pure() {
        assert!(scope_cut_match("I will drop the models.").unwrap().contains("drop"));
        assert!(scope_cut_match("Nothing scope-related here.").is_none());
    }

    #[test]
    fn question_phrased_correction_answered_with_only_proposal_blocks() {
        let evidence = continue_intent("Can't we make this a hook and include it in brief?");
        assert!(evidence.is_some());
        let v = evaluate_stop_shape(
            "Yes, we can do that. I would add a Stop hook.",
            &StopShapeOptions { continue_intent_evidence: evidence, continue_tools_used: false, ..opts() },
        );
        assert!(v.block);
        assert_eq!(v.shape.as_deref(), Some("continue-intent"));
    }

    #[test]
    fn acting_on_the_correction_passes() {
        let v = evaluate_stop_shape(
            "I added the hook and verified it.",
            &StopShapeOptions {
                continue_intent_evidence: continue_intent("Can't we make this a hook?"),
                continue_tools_used: true,
                ..opts()
            },
        );
        assert!(!v.block);
    }

    #[test]
    fn plain_informational_question_carries_no_continuation_intent() {
        assert!(continue_intent("What is gstack?").is_none());
    }

    #[test]
    fn tool_use_clears_it_unless_ending_still_hands_work_back() {
        let evidence = continue_intent("why is the old hook still there?");
        let v1 = evaluate_stop_shape(
            "Removed the stale registration; receipts attached.",
            &StopShapeOptions { continue_intent_evidence: evidence.clone(), continue_tools_used: true, ..opts() },
        );
        assert!(!v1.block);
        let v2 = evaluate_stop_shape(
            "I looked into it. I can remove the old registration next.",
            &StopShapeOptions { continue_intent_evidence: evidence, continue_tools_used: true, ..opts() },
        );
        assert!(v2.block, "acting and then handing back is the same stop-short");
    }

    #[test]
    fn hard_blocker_clears_continue_intent() {
        let v = evaluate_stop_shape(
            "HARD BLOCKER: rotating the signing key needs your 2FA code.",
            &StopShapeOptions {
                continue_intent_evidence: continue_intent("can you fix the signing setup?"),
                continue_tools_used: false,
                ..opts()
            },
        );
        assert!(!v.block);
    }

    #[test]
    fn tool_use_after_last_user_reads_transcript_shape() {
        let lines = [
            serde_json::json!({"type": "user", "message": {"content": [{"type": "text", "text": "fix it"}]}}).to_string(),
            serde_json::json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Edit"}]}}).to_string(),
        ]
        .join("\n");
        assert!(tool_use_after_last_user(&lines));
        let no_tools = serde_json::json!({"type": "user", "message": {"content": [{"type": "text", "text": "fix it"}]}}).to_string();
        assert!(!tool_use_after_last_user(&no_tools));
    }

    #[test]
    fn non_compelling_latest_intent_permits_receipt_free_terminals() {
        for intent in ["PLAN", "QUESTION", "REVOKE", "SCOPE_NARROW", "UNKNOWN"] {
            let v = evaluate_stop_shape(
                "Plan is ready; implementation remains pending. Say go to execute.",
                &StopShapeOptions { intent: intent.to_string(), ..opts() },
            );
            assert!(!v.block, "{intent}");
        }
    }

    #[test]
    fn execute_and_continue_retain_anti_stall_enforcement() {
        assert!(evaluate_stop_shape("Implementation is ready. Say go and I execute.", &StopShapeOptions { intent: "EXECUTE".to_string(), ..opts() }).block);
        let v = evaluate_stop_shape(
            "Yes, we can do that. I would add a Stop hook.",
            &StopShapeOptions {
                intent: "CONTINUE".to_string(),
                continue_intent_evidence: Some("Can you fix the hook?".to_string()),
                continue_tools_used: false,
                ..opts()
            },
        );
        assert!(v.block);
    }

    #[test]
    fn evaluate_transcript_stop_reads_missing_file_as_unreadable() {
        let v = evaluate_transcript_stop("/nonexistent/path/does-not-exist.jsonl");
        assert!(!v.block);
        assert_eq!(v.reason.as_deref(), Some("transcript-unreadable"));
    }
}
