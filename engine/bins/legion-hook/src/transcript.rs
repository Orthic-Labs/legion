//! Claude Code transcript (JSONL) reading: tail, genuine user turns, skill loads.

use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

use serde_json::Value;

const TAIL_BYTES: u64 = 2 * 1024 * 1024;
const SCAN_BYTES: u64 = 256 * 1024 * 1024;
/// Text that starts a user record a person did not type.
const NOT_HUMAN: [&str; 4] = [
    "[Pulse Chat",
    "<task-notification>",
    "<system-reminder>",
    "<side-sessions-event>",
];

/// The last `max` bytes of a file, from the start of a whole line.
pub fn tail(path: &str, max: u64) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    let cut = length > max;
    if cut {
        file.seek(SeekFrom::Start(length - max)).ok()?;
    }
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    if !cut {
        return Some(text);
    }
    // The cut tail starts mid-line: drop that partial line.
    let rest = text.split_once('\n');
    Some(rest.map_or(String::new(), |(_, rest)| rest.to_owned()))
}

/// JSON records of the last 2 MiB, oldest first.
fn records(path: &str) -> Vec<Value> {
    let text = tail(path, TAIL_BYTES).unwrap_or_default();
    let parse = |line: &str| serde_json::from_str(line).ok();
    text.lines().filter_map(parse).collect()
}

/// Whether text was typed by a person, not sent by the host, a relay or a notice.
pub fn human(text: &str) -> bool {
    let text = text.trim_start();
    !text.is_empty() && !NOT_HUMAN.iter().any(|prefix| text.starts_with(prefix))
}

/// The text of a record's message; `None` when it carries a tool result.
fn text_of(record: &Value) -> Option<String> {
    match record.pointer("/message/content")? {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            if items.iter().any(|item| item["type"] == "tool_result") {
                return None;
            }
            let texts: Vec<&str> = items
                .iter()
                .filter_map(|item| item["text"].as_str())
                .filter(|text| human(text))
                .collect();
            Some(texts.join("\n"))
        }
        _ => None,
    }
}

/// The text of a user record a person typed, not a tool result, meta or summary record.
fn genuine(record: &Value) -> Option<String> {
    if record["type"] != "user" || record["isMeta"] == true || record["isCompactSummary"] == true {
        return None;
    }
    text_of(record).filter(|text| human(text))
}

/// Texts of the genuine user turns in the last 2 MiB, oldest first.
pub fn genuine_user_turns(path: &str) -> Vec<String> {
    records(path).iter().filter_map(genuine).collect()
}

/// The text of the last assistant record that has any.
pub fn last_assistant_text(path: &str) -> Option<String> {
    let all = records(path);
    let assistant = |record: &&Value| record["type"] == "assistant";
    let filled = |record: &Value| text_of(record).filter(|text| !text.trim().is_empty());
    all.iter().rev().filter(assistant).find_map(filled)
}

/// Did a command run by a tool call contain `needle` in the last 2 MiB?
pub fn has_tool_command(path: &str, needle: &str) -> bool {
    let runs = |item: &Value| {
        let command = item["input"]["command"].as_str().unwrap_or("");
        item["type"] == "tool_use" && command.contains(needle)
    };
    let items = |record: &Value| record["message"]["content"].as_array().cloned();
    let calls = records(path)
        .iter()
        .filter_map(items)
        .flatten()
        .collect::<Vec<_>>();
    calls.iter().any(runs)
}

/// Does this record load `skill`: a `Skill` call, or a typed `/skill` command?
fn loads(record: &Value, skill: &str) -> bool {
    let named = |arg: &str| {
        let arg = arg.trim().trim_start_matches('/');
        !arg.is_empty() && (arg == skill || skill.ends_with(&format!(":{arg}")))
    };
    let Some(items) = record["message"]["content"].as_array() else {
        let text = record["message"]["content"].as_str().unwrap_or("");
        return record["type"] == "user" && typed(text, &named);
    };
    items.iter().any(|item| {
        let arg = item["input"]["skill"].as_str().unwrap_or("");
        let called = item["name"] == "Skill" && named(arg);
        let text = item["text"].as_str().unwrap_or("");
        called || (record["type"] == "user" && typed(text, &named))
    })
}

fn typed(text: &str, named: &dyn Fn(&str) -> bool) -> bool {
    let mut tags = text.split("<command-name>").skip(1);
    let close = |rest: &str| rest.split("</command-name>").next().map(named);
    tags.any(|rest| close(rest) == Some(true))
}

/// Is `skill` loaded since the last compaction? `None` when the file cannot be read or is huge.
pub fn skill_loaded_since_compaction(path: &str, skill: &str) -> Option<bool> {
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > SCAN_BYTES {
        return None;
    }
    let mut loaded = false;
    for line in BufReader::new(file).lines() {
        let line = line.ok()?;
        let marks = [
            "compact_boundary",
            "isCompactSummary",
            "\"Skill\"",
            "<command-name>",
        ];
        if !marks.iter().any(|mark| line.contains(mark)) {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if record["subtype"] == "compact_boundary" || record["isCompactSummary"] == true {
            loaded = false;
        } else if loads(&record, skill) {
            loaded = true;
        }
    }
    Some(loaded)
}
