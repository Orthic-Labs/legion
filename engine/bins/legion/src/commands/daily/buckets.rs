//! The B1-B11 keyword map (`every-failure.md` headings). A failure gets a
//! bucket and a cause slug; `<bucket>/<cause>` is its fingerprint. No model.

#[rustfmt::skip]
pub const NAMES: [&str; 11] = [
    "Authority: acted without Adrian, on a peer, or ignored a stop",
    "Effects: destructive, live or gate-bypassing actions",
    "Builds and CI: avoidable reds, reruns, uncompiled edits",
    "False claims: done, green, causes and facts without evidence",
    "Request fidelity: did something other than asked, lost orders",
    "Idling and looping while work was pending",
    "Questions and work pushed back to Adrian",
    "Reports Adrian could not use",
    "Skills not used",
    "Invented process and broken workspace rules",
    "Harness, tooling and other",
];

pub fn name(bucket: &str) -> &'static str {
    let number: usize = bucket.trim_start_matches('B').parse().unwrap_or(0);
    NAMES
        .get(number.wrapping_sub(1))
        .map_or("Unknown bucket", |name| *name)
}

/// (bucket, cause, keywords). A trailing `*` matches any word ending.
#[rustfmt::skip]
const RULES: &[(&str, &str, &[&str])] = &[
    ("B1", "ignored-stop",
        &["told you to stop", "said stop", "kept building", "keep building", "didn't stop"]),
    ("B1", "acted-without-authority",
        &["authoriz*", "without asking", "without my", "who told you", "approv*", "relay*"]),
    ("B2", "gate-bypass",
        &["no-broker", "cmake", "cold clone", "bypass*", "outside the gate", "broker-exceptions"]),
    ("B2", "destructive-or-live-action",
        &["production", "delete*", "overwr*", "rm -rf", "reset --hard", "force push", "deploy*"]),
    ("B3", "ci-as-compiler",
        &["ci", "gh run", "github actions", "workflow*", "push gate", "rerun*", "re-run*"]),
    ("B3", "build-red-or-uncompiled",
        &["build*", "cargo", "compil*", "rustright", "gate", "broker", "install*", "failed"]),
    ("B4", "claim-without-evidence",
        &["claimed", "lied", "false", "not true", "verified", "evidence", "green", "not done"]),
    ("B5", "request-not-followed",
        &["i asked", "i told you", "i said", "supposed to", "instead of", "not what i", "wrong"]),
    ("B6", "idle-or-looping",
        &["idle", "idling", "loop*", "waiting", "stuck", "hung", "no change", "resend*"]),
    ("B7", "question-pushed-back",
        &["stop asking", "asking me", "decide it", "your call", "manual step*", "do it yourself"]),
    ("B8", "unusable-report",
        &["jargon", "wall of text", "too long", "plain english", "can't read", "summary"]),
    ("B9", "skill-not-used",
        &["skill", "/debugger", "/writing", "/designer", "/commit", "debugger"]),
    ("B10", "invented-process",
        &["worktree*", "decisions.md", "watchdog", "process.md", "invented", "specialist"]),
    ("B11", "harness-or-tooling",
        &["pulse", "browser", "harness", "sign-in", "signed in", "mcp", "plugin", "codex"]),
];

/// Whether lowercase `text` contains `keyword` on word edges.
pub fn has(text: &str, keyword: &str) -> bool {
    let (word, open_end) = (keyword.trim_end_matches('*'), keyword.ends_with('*'));
    let edge = |c: Option<char>| c.is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
    text.match_indices(word).any(|(start, found)| {
        let after = text[start + found.len()..].chars().next();
        edge(text[..start].chars().next_back()) && (open_end || edge(after))
    })
}

/// The best-scoring (bucket, cause); the earliest rule wins a tie; `None` with no match.
pub fn classify(text: &str) -> Option<(&'static str, &'static str)> {
    let low = text.to_lowercase();
    let mut best = (0, None);
    for (bucket, cause, keywords) in RULES {
        let score = keywords.iter().filter(|k| has(&low, k)).count();
        if score > best.0 {
            best = (score, Some((*bucket, *cause)));
        }
    }
    best.1
}

/// The bucket a commit targets: an explicit `B<n>` word, else the keyword map.
pub fn of_commit(text: &str) -> Option<String> {
    let tagged = text.split(|c: char| !c.is_alphanumeric()).find_map(|word| {
        let number = word.strip_prefix('B')?.parse::<usize>().ok()?;
        (1..=NAMES.len()).contains(&number).then(|| word.to_owned())
    });
    tagged.or_else(|| classify(text).map(|(bucket, _)| bucket.to_owned()))
}
