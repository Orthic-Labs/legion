//! The deterministic B1-B11 keyword map (fix-plan buckets, `every-failure.md`).
//! A failure gets a bucket and a stable cause slug; the pair is the issue
//! fingerprint `<bucket>/<cause>`. No model is involved: the first pass is a
//! keyword score, and a later classifier call may refine it.
use super::text::{phrase_match, slugify};

pub struct Bucket {
    pub id: &'static str,
    pub name: &'static str,
}

pub const BUCKETS: [Bucket; 11] = [
    Bucket {
        id: "B1",
        name: "Authority: acted without Adrian, on a peer, or ignored a stop",
    },
    Bucket {
        id: "B2",
        name: "Effects: destructive, live or gate-bypassing actions",
    },
    Bucket {
        id: "B3",
        name: "Builds and CI: avoidable reds, reruns, uncompiled edits",
    },
    Bucket {
        id: "B4",
        name: "False claims: done, green, causes and facts without evidence",
    },
    Bucket {
        id: "B5",
        name: "Request fidelity: did something other than asked, lost standing orders",
    },
    Bucket {
        id: "B6",
        name: "Idling and looping while work was pending",
    },
    Bucket {
        id: "B7",
        name: "Questions and work pushed back to Adrian",
    },
    Bucket {
        id: "B8",
        name: "Reports Adrian could not use",
    },
    Bucket {
        id: "B9",
        name: "Skills not used",
    },
    Bucket {
        id: "B10",
        name: "Invented process and broken workspace rules",
    },
    Bucket {
        id: "B11",
        name: "Harness, tooling and other",
    },
];

pub fn bucket_name(id: &str) -> &'static str {
    BUCKETS
        .iter()
        .find(|bucket| bucket.id == id)
        .map_or("Unknown bucket", |bucket| bucket.name)
}

/// The bucket and cause a failure was placed in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    pub bucket: &'static str,
    pub cause: String,
    /// A broad cause needs more occurrences before it may open an issue.
    pub catch_all: bool,
}

struct Rule {
    bucket: &'static str,
    cause: &'static str,
    label: &'static str,
    broad: bool,
    keys: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        bucket: "B1",
        cause: "acted-without-authority",
        label: "acted without Adrian's authority",
        broad: false,
        keys: &[
            "who authorized",
            "authoriz*",
            "without asking",
            "without my",
            "who told you",
            "nobody told you",
            "no one told you",
            "never approved",
            "not approved",
            "didn't approve",
            "approver",
            "no go",
            "unauthorized",
        ],
    },
    Rule {
        bucket: "B1",
        cause: "ignored-stop",
        label: "kept working after a stop",
        broad: false,
        keys: &[
            "told you to stop",
            "said stop",
            "i said no",
            "kept building",
            "keep building",
            "still building",
            "didn't stop",
            "did not stop",
            "stop all",
        ],
    },
    Rule {
        bucket: "B1",
        cause: "peer-relay-as-authority",
        label: "treated a peer relay as Adrian's word",
        broad: false,
        keys: &[
            "relay*",
            "peer",
            "other chat",
            "that chat",
            "chat said",
            "pulse message",
        ],
    },
    Rule {
        bucket: "B2",
        cause: "destructive-or-live-action",
        label: "destructive or live action",
        broad: false,
        keys: &[
            "production",
            "prod",
            "deleted",
            "delete*",
            "wiped",
            "overwr*",
            "rm -rf",
            "reset --hard",
            "force push",
            "force-push",
            "dropped",
            "destroy*",
            "killed",
            "password",
            "live payment",
            "test card",
            "sweep",
        ],
    },
    Rule {
        bucket: "B2",
        cause: "gate-bypass",
        label: "bypassed the gate",
        broad: false,
        keys: &[
            "--no-broker",
            "no-broker",
            "cmake",
            "cold clone",
            "cold-clone",
            "bypass*",
            "one door",
            "outside the gate",
            "around the gate",
            "broker-exceptions",
        ],
    },
    Rule {
        bucket: "B3",
        cause: "ci-as-compiler",
        label: "used CI as the compiler or reran CI",
        broad: false,
        keys: &[
            "ci",
            "gh run",
            "github actions",
            "workflow*",
            "push gate",
            "push-gate",
            "rerun*",
            "re-run*",
            "preflight",
        ],
    },
    Rule {
        bucket: "B3",
        cause: "build-red-or-uncompiled",
        label: "avoidable red build or uncompiled edit",
        broad: true,
        keys: &[
            "cargo",
            "compile*",
            "build*",
            "clippy",
            "rustfmt",
            "test failed",
            "tests failed",
            "broker",
            "gate",
            "cold build",
            "mid-run",
            "install failed",
        ],
    },
    Rule {
        bucket: "B4",
        cause: "false-done-claim",
        label: "claimed done, green or installed without evidence",
        broad: false,
        keys: &[
            "claimed",
            "you said it was",
            "are we done",
            "not done",
            "isn't done",
            "wasn't done",
            "didn't actually",
            "never installed",
            "not installed",
            "isn't there",
            "lied",
            "lying",
            "not true",
            "overstat*",
            "green",
        ],
    },
    Rule {
        bucket: "B4",
        cause: "ungrounded-cause",
        label: "stated a cause or fact without checking",
        broad: false,
        keys: &[
            "guess*",
            "made up",
            "invented",
            "hypothes*",
            "stale",
            "assum*",
            "without checking",
            "didn't check",
            "never checked",
            "did you check",
            "verif*",
            "evidence",
        ],
    },
    Rule {
        bucket: "B5",
        cause: "ignored-request",
        label: "did something other than asked",
        broad: true,
        keys: &[
            "i asked",
            "i told you",
            "i said",
            "not what i",
            "again",
            "instead of",
            "supposed to",
            "forgot",
            "ignor*",
            "my first requirement",
            "explicitly",
            "misunderstand*",
            "wrong thing",
            "what i asked",
            "as i said",
        ],
    },
    Rule {
        bucket: "B5",
        cause: "lost-standing-order",
        label: "lost a standing order",
        broad: false,
        keys: &[
            "standing",
            "keep telling",
            "told you before",
            "already told",
            "multiple times",
            "every time",
            "over and over",
            "how many times",
        ],
    },
    Rule {
        bucket: "B6",
        cause: "stopped-with-work-pending",
        label: "stopped or idled while work was pending",
        broad: true,
        keys: &[
            "why are you stopped",
            "why did you stop",
            "why have you stopped",
            "you stopped",
            "idle",
            "nothing ran",
            "nothing is happening",
            "no progress",
            "still stopped",
            "stuck",
            "hung",
            "still waiting",
            "waiting",
        ],
    },
    Rule {
        bucket: "B6",
        cause: "loop-or-poll",
        label: "looped, polled or resent",
        broad: false,
        keys: &[
            "loop*",
            "poll*",
            "cron",
            "every minute",
            "sleep*",
            "spin*",
            "empty turn*",
            "resend*",
            "retry*",
            "retrying",
        ],
    },
    Rule {
        bucket: "B7",
        cause: "question-it-could-decide",
        label: "asked Adrian a question the agent could decide",
        broad: false,
        keys: &[
            "why are you asking",
            "what are you asking",
            "you decide",
            "decide it",
            "your call",
            "my call",
            "figure it out",
            "you're the owner",
            "your job",
            "not your job",
            "do it yourself",
            "confused",
            "hedging",
        ],
    },
    Rule {
        bucket: "B7",
        cause: "work-handed-to-adrian",
        label: "handed Adrian work the agent should do",
        broad: false,
        keys: &[
            "not pasting",
            "why am i running",
            "paste",
            "run these",
            "you do it",
            "manual*",
            "by hand",
            "i have to",
        ],
    },
    Rule {
        bucket: "B8",
        cause: "report-unusable",
        label: "report Adrian could not use",
        broad: true,
        keys: &[
            "don't understand",
            "do not understand",
            "what does that mean",
            "what do you mean",
            "plain english",
            "english",
            "jargon",
            "too long",
            "wall of",
            "tl;dr",
            "tldr",
            "don't complicate",
            "simply",
            "shorter",
            "explain",
        ],
    },
    Rule {
        bucket: "B8",
        cause: "over-reporting",
        label: "narrated or reported too often",
        broad: false,
        keys: &[
            "updates",
            "every second",
            "narrat*",
            "don't want updates",
            "no updates",
            "report every",
            "quiet",
        ],
    },
    Rule {
        bucket: "B9",
        cause: "skill-not-used",
        label: "did not use a named skill",
        broad: false,
        keys: &[
            "skill*",
            "debugger",
            "designer",
            "egm",
            "should have used",
            "didn't use the",
            "did not use",
            "/debugger",
            "/commit",
            "/designer",
        ],
    },
    Rule {
        bucket: "B10",
        cause: "invented-process",
        label: "invented process or paperwork",
        broad: false,
        keys: &[
            "worktree*",
            "decisions.md",
            "process.md",
            "watchdog",
            "nag",
            "schedul*",
            "expir*",
            "amendment",
            "artifact*",
            "who asked you to",
            "didn't ask you to",
            "never asked for",
            "scope creep",
            "unnecessary",
            "paperwork",
            "ceremony",
            "bureaucra*",
        ],
    },
    Rule {
        bucket: "B10",
        cause: "workspace-rule-broken",
        label: "broke a workspace rule",
        broad: false,
        keys: &[
            "workspace rule",
            "rule says",
            "rules say",
            "scratch",
            "/volumes/e",
            "run output",
            "sonnet",
            "haiku",
            "opus",
            "hook error",
            "destructive command",
            "not permitted",
            "symlink*",
        ],
    },
    Rule {
        bucket: "B11",
        cause: "harness-or-tooling",
        label: "harness or tooling fault",
        broad: true,
        keys: &[
            "pulse",
            "browser",
            "sign in",
            "signed in",
            "sign-in",
            "logged out",
            "login",
            "path",
            "youtube",
            "disk",
            "council",
            "crash",
            "regression",
            "migration",
        ],
    },
];

fn best_rule(lower: &str) -> Option<&'static Rule> {
    let mut best: Option<&'static Rule> = None;
    let mut best_score = 0usize;
    for rule in RULES {
        let score = rule
            .keys
            .iter()
            .filter(|key| phrase_match(lower, key))
            .count();
        if score > best_score {
            best_score = score;
            best = Some(rule);
        }
    }
    best
}

fn class_of(rule: &Rule, catch_all: bool) -> Class {
    Class {
        bucket: rule.bucket,
        cause: rule.cause.to_owned(),
        catch_all: catch_all || rule.broad,
    }
}

/// Bucket a corrected agent turn: the user's words decide; the agent turn
/// before is a weaker second pass; nothing matching falls to B5.
pub fn classify_correction(user: &str, agent: &str) -> Class {
    if let Some(rule) = best_rule(&user.to_lowercase()) {
        return class_of(rule, false);
    }
    if let Some(rule) = best_rule(&agent.to_lowercase()) {
        return class_of(rule, true);
    }
    Class {
        bucket: "B5",
        cause: "unclassified".to_owned(),
        catch_all: true,
    }
}

/// An `UNRESOLVED:` line from the M3 judge, bucketed by its words.
pub fn classify_unresolved(text: &str) -> Class {
    match best_rule(&text.to_lowercase()) {
        Some(rule) => class_of(rule, false),
        None => Class {
            bucket: "B5",
            cause: "unresolved".to_owned(),
            catch_all: true,
        },
    }
}

fn denial_bucket(code: &str) -> &'static str {
    match code {
        "ARC_APPROVAL_REQUIRED" => "B1",
        "ARC_EFFECT_CLASS_UNAUTHORIZED" => "B2",
        "ARC_SKILL_FIRST" | "ARC_SKILL_EVENT" => "B9",
        "ARC_SLEEP_WAIT" | "ARC_POLL_LIMIT" | "ARC_AGENT_CAP" => "B6",
        "ARC_SELF_SCHEDULE" | "ARC_ISSUE_SEARCH_FIRST" => "B10",
        "ARC_EVIDENCE_REQUIRED" => "B4",
        "ARC_FILE_OWNED" => "B5",
        "ARC_CHECKOUT_BUSY" => "B3",
        _ => "B11",
    }
}

/// A hook denial: `code` is `ARC_X`, or `hook:<name>` for a `[HOOK:name:block]`.
pub fn classify_denial(code: &str) -> Class {
    if let Some(name) = code.strip_prefix("hook:") {
        let bucket = match name {
            "one-door" | "rightkit-door" => "B3",
            "desktop-intrusion" => "B2",
            _ => "B10",
        };
        return Class {
            bucket,
            cause: format!("hook-{}", slugify(name, 40)),
            catch_all: false,
        };
    }
    Class {
        bucket: denial_bucket(code),
        cause: format!("hook-{}", slugify(code, 48)),
        catch_all: false,
    }
}

/// A red build, CI run or install: always B3, split by what failed.
pub fn classify_build(kind: &str) -> Class {
    Class {
        bucket: "B3",
        cause: format!("{}-red", slugify(kind, 24)),
        catch_all: true,
    }
}

/// The issue-title label for a fingerprint's cause.
pub fn cause_label(cause: &str) -> String {
    if let Some(rule) = RULES.iter().find(|rule| rule.cause == cause) {
        return rule.label.to_owned();
    }
    if let Some(rest) = cause.strip_prefix("hook-") {
        return format!("hook denial {rest}");
    }
    if let Some(kind) = cause.strip_suffix("-red") {
        return format!("red {kind} run");
    }
    cause.replace('-', " ")
}

/// Bucket for a change from its words (commit subject and body), if any rule
/// scores; used to attribute a merged change to the bucket it targets.
pub fn bucket_of_text(text: &str) -> Option<&'static str> {
    best_rule(&text.to_lowercase()).map(|rule| rule.bucket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrections_follow_the_user_words() {
        let class = classify_correction("who authorized you to push that", "");
        assert_eq!(class.bucket, "B1");
        assert_eq!(class.cause, "acted-without-authority");
        assert!(!class.catch_all);

        let class = classify_correction("I said stop all work", "");
        assert_eq!(class.bucket, "B1");
        assert_eq!(class.cause, "ignored-stop");

        let class = classify_correction("why are you asking me, you decide", "");
        assert_eq!(class.bucket, "B7");
        assert_eq!(class.cause, "question-it-could-decide");

        let class = classify_correction("use the debugger skill first", "");
        assert_eq!(class.bucket, "B9");
    }

    #[test]
    fn unmatched_text_falls_back_to_b5_and_is_catch_all() {
        let class = classify_correction("hmm", "");
        assert_eq!(class.bucket, "B5");
        assert_eq!(class.cause, "unclassified");
        assert!(class.catch_all);
    }

    #[test]
    fn agent_turn_is_a_weaker_second_pass() {
        let class = classify_correction("hmm", "I used cmake for a cold clone");
        assert_eq!(class.bucket, "B2");
        assert_eq!(class.cause, "gate-bypass");
        assert!(class.catch_all);
    }

    #[test]
    fn denials_map_codes_to_buckets() {
        let class = classify_denial("ARC_SELF_SCHEDULE");
        assert_eq!(class.bucket, "B10");
        assert_eq!(class.cause, "hook-arc-self-schedule");
        let class = classify_denial("ARC_SOMETHING_NEW");
        assert_eq!(class.bucket, "B11");
        let class = classify_denial("hook:one-door");
        assert_eq!(class.bucket, "B3");
        assert_eq!(class.cause, "hook-one-door");
    }

    #[test]
    fn builds_and_labels() {
        let class = classify_build("cargo");
        assert_eq!(class.bucket, "B3");
        assert_eq!(class.cause, "cargo-red");
        assert!(class.catch_all);
        assert_eq!(cause_label("cargo-red"), "red cargo run");
        assert_eq!(cause_label("ignored-stop"), "kept working after a stop");
        assert_eq!(cause_label("hook-one-door"), "hook denial one-door");
        assert_eq!(bucket_name("B4"), BUCKETS[3].name);
    }

    #[test]
    fn every_rule_names_a_known_bucket_once_per_cause() {
        let mut causes: Vec<&str> = Vec::new();
        for rule in RULES {
            assert!(BUCKETS.iter().any(|bucket| bucket.id == rule.bucket));
            assert!(
                !causes.contains(&rule.cause),
                "duplicate cause {}",
                rule.cause
            );
            causes.push(rule.cause);
        }
    }
}
