//! Claude Code transcript helpers: what counts as text a person typed.

/// Text that starts a user record a person did not type.
const NOT_HUMAN: [&str; 4] = [
    "[Pulse Chat",
    "<task-notification>",
    "<system-reminder>",
    "<side-sessions-event>",
];

/// Whether text was typed by a person, not sent by the host, a relay or a notice.
pub fn human(text: &str) -> bool {
    let text = text.trim_start();
    !text.is_empty() && !NOT_HUMAN.iter().any(|prefix| text.starts_with(prefix))
}
