use regex::Regex;
use std::sync::OnceLock;

const MARKER_START: &str = "<!-- legion:bind:start v1 -->";
const MARKER_END: &str = "<!-- legion:bind:end -->";

fn marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"<!-- legion:bind:start v1 -->[\s\S]*?<!-- legion:bind:end -->")
            .expect("valid marker regex")
    })
}

pub fn marker_block(content: &str) -> String {
    format!(
        "{MARKER_START}\n{}\n{MARKER_END}",
        content.trim()
    )
}

pub fn upsert_marker_block(existing: &str, content: &str) -> String {
    let block = marker_block(content);
    if marker_re().is_match(existing) {
        return marker_re().replace(existing, block.as_str()).to_string();
    }
    if existing.is_empty() {
        return format!("{block}\n");
    }
    let sep = if existing.ends_with('\n') { "\n" } else { "\n\n" };
    format!("{existing}{sep}{block}\n")
}

pub fn strip_marker_block(existing: &str) -> String {
    if !marker_re().is_match(existing) {
        return existing.to_string();
    }
    let stripped = marker_re().replace_all(existing, "").to_string();
    let collapsed = Regex::new(r"\n{3,}")
        .expect("valid regex")
        .replace_all(&stripped, "\n\n")
        .to_string();
    collapsed
        .trim_start_matches('\n')
        .trim_end_matches('\n')
        .to_string()
        + "\n"
}
