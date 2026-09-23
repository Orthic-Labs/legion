//! Port of `skills/designer/engine/scripts/live/vocabulary.mjs`.
//!
//! Pure data: the canonical design-command vocabulary for Live Mode. Each
//! command carries its value, human label, and SVG icon markup. Faithful
//! 1:1 port of the JS array; icon markup strings are copied verbatim.

/// One entry of `LIVE_COMMANDS` in vocabulary.mjs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCommand {
    pub value: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
}

const ICON_ATTRS: &str = r#"width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block""#;

fn svg(inner: &str) -> String {
    format!("<svg {} >{}</svg>", ICON_ATTRS, inner)
}

/// `LIVE_COMMANDS` in vocabulary.mjs, in palette order.
pub fn live_commands() -> Vec<LiveCommand> {
    vec![
        LiveCommand {
            value: "impeccable",
            label: "Freeform",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><path d="M4 20l4-1L18 9l-3-3L5 16z"/><path d="M14 7l3 3"/></svg>"#,
        },
        LiveCommand {
            value: "bolder",
            label: "Bolder",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><rect x="6" y="12" width="4" height="7" rx="0.5"/><rect x="14" y="5" width="4" height="14" rx="0.5"/></svg>"#,
        },
        LiveCommand {
            value: "quieter",
            label: "Quieter",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><rect x="6" y="5" width="4" height="14" rx="0.5"/><rect x="14" y="12" width="4" height="7" rx="0.5"/></svg>"#,
        },
        LiveCommand {
            value: "distill",
            label: "Distill",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><path d="M4 5h16l-6 8v7l-4-2v-5z"/></svg>"#,
        },
        LiveCommand {
            value: "polish",
            label: "Polish",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><path d="M15 3l1 3 3 1-3 1-1 3-1-3-3-1 3-1z"/><path d="M7 13l0.6 1.8 1.8 0.6-1.8 0.6-0.6 1.8-0.6-1.8-1.8-0.6 1.8-0.6z"/></svg>"#,
        },
        LiveCommand {
            value: "typeset",
            label: "Typeset",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><path d="M5 6h14" stroke-width="2.6"/><path d="M5 12h9" stroke-width="1.9"/><path d="M5 18h5" stroke-width="1.3"/></svg>"#,
        },
        LiveCommand {
            value: "colorize",
            label: "Colorize",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><circle cx="9" cy="10" r="5"/><circle cx="15" cy="10" r="5"/><circle cx="12" cy="15" r="5"/></svg>"#,
        },
        LiveCommand {
            value: "layout",
            label: "Layout",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><rect x="3" y="4" width="8" height="16" rx="0.5"/><rect x="13" y="4" width="8" height="7" rx="0.5"/><rect x="13" y="13" width="8" height="7" rx="0.5"/></svg>"#,
        },
        LiveCommand {
            value: "morph",
            label: "Morph",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><rect x="2.5" y="5" width="12" height="11" rx="1"/><line x1="2.5" y1="19" x2="14.5" y2="19"/><rect x="16.5" y="8" width="5" height="11" rx="1"/></svg>"#,
        },
        LiveCommand {
            value: "animate",
            label: "Animate",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><path d="M3 18c4-4 6-10 10-10"/><path d="M13 8c3 0 5 5 8 10"/><circle cx="13" cy="8" r="1.6" fill="currentColor" stroke="none"/></svg>"#,
        },
        LiveCommand {
            value: "delight",
            label: "Delight",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><path d="M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2z"/></svg>"#,
        },
        LiveCommand {
            value: "overdrive",
            label: "Overdrive",
            icon: r#"<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:block"><path d="M13 3L5 13h5l-1 8 9-12h-6z"/></svg>"#,
        },
    ]
}

/// `VISUAL_ACTIONS` in vocabulary.mjs: action values in palette order.
pub fn visual_actions() -> Vec<&'static str> {
    live_commands().into_iter().map(|c| c.value).collect()
}

// Silence the unused-helper warning when the verbose `svg()` builder is not
// used directly (icons above are written out in full to stay byte-faithful
// to the JS source, which the tests assert against).
#[allow(dead_code)]
fn _unused_svg_helper_reference() -> String {
    svg("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twelve_commands_in_order() {
        let cmds = live_commands();
        assert_eq!(cmds.len(), 12);
        let values: Vec<&str> = cmds.iter().map(|c| c.value).collect();
        assert_eq!(
            values,
            vec![
                "impeccable", "bolder", "quieter", "distill", "polish", "typeset", "colorize",
                "layout", "morph", "animate", "delight", "overdrive",
            ]
        );
    }

    #[test]
    fn visual_actions_matches_command_values() {
        assert_eq!(visual_actions(), live_commands().iter().map(|c| c.value).collect::<Vec<_>>());
    }

    #[test]
    fn labels_are_human_readable() {
        let cmds = live_commands();
        assert_eq!(cmds[0].label, "Freeform");
        assert_eq!(cmds[11].label, "Overdrive");
    }

    #[test]
    fn every_icon_is_well_formed_svg_with_shared_attrs() {
        for cmd in live_commands() {
            assert!(cmd.icon.starts_with("<svg "));
            assert!(cmd.icon.ends_with("</svg>"));
            assert!(cmd.icon.contains(r#"viewBox="0 0 24 24""#));
            assert!(cmd.icon.contains("stroke=\"currentColor\""));
        }
    }
}
