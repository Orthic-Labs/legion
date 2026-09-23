//! Port of `skills/designer/engine/scripts/live/ui-core.mjs`.
//!
//! `ui-core.mjs` is the framework-neutral Impeccable live chrome contract:
//! mostly DOM-facing (`document`, `globalThis`, live-mounted elements), which
//! has no meaningful Rust equivalent. This port keeps only the
//! source-of-truth *data* (mount contract, UI surface inventory, derived
//! component-id set) and the one pure string helper (`escapeCssIdent`),
//! matching the JS constants byte-for-byte.
//!
//! NOT ported (DOM-only, no server-side behaviour to port):
//! `resolveLiveUiRoot`, `getLiveUiElementById`, `appendToLiveUiRoot`,
//! `appendStyleToLiveUiRoot`, `activeElementDeep` — all operate on a live
//! `document`/`window` and have no meaning outside a browser.

/// `LIVE_CHROME_MOUNT_CONTRACT` in ui-core.mjs.
pub const LIVE_CHROME_MOUNT_CONTRACT: [&str; 4] = ["root", "transport", "state", "actions"];

/// One entry of `LIVE_UI_SURFACES` in ui-core.mjs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveUiSurface {
    pub key: &'static str,
    pub ids: &'static [&'static str],
    pub states: &'static [&'static str],
}

/// `LIVE_UI_SURFACES` in ui-core.mjs, in source order.
pub const LIVE_UI_SURFACES: &[LiveUiSurface] = &[
    LiveUiSurface {
        key: "global-bottom-bar",
        ids: &[
            "impeccable-live-global-bar",
            "impeccable-live-global-bar-brand",
            "impeccable-live-pick-toggle",
            "impeccable-live-insert-toggle",
            "impeccable-live-detect-toggle",
            "impeccable-live-detect-badge",
            "impeccable-live-design-toggle",
            "impeccable-live-page-chat",
            "impeccable-live-page-chat-input",
            "impeccable-live-page-chat-voice",
        ],
        states: &["rest", "hover", "focus-visible", "pressed", "active", "tooltip"],
    },
    LiveUiSurface {
        key: "pending-copy-edit-dock",
        ids: &["impeccable-live-pending-dock"],
        states: &["closed", "open", "hover", "pressed", "loading", "rollback", "keep-fixing"],
    },
    LiveUiSurface {
        key: "element-selection-chrome",
        ids: &[
            "impeccable-live-highlight",
            "impeccable-live-tooltip",
            "impeccable-live-bar",
            "impeccable-live-selection-pill",
            "impeccable-live-input",
            "impeccable-live-configure-voice",
            "impeccable-live-configure-bar-tooltip",
        ],
        states: &["rest", "hover", "focus-visible", "pressed", "disabled"],
    },
    LiveUiSurface {
        key: "action-picker",
        ids: &["impeccable-live-picker"],
        states: &["closed", "open", "option-hover", "option-focus"],
    },
    LiveUiSurface {
        key: "edit-chrome",
        ids: &["impeccable-live-edit-badge"],
        states: &["enabled", "disabled", "editing", "cancel", "save", "edited-content"],
    },
    LiveUiSurface {
        key: "generating-row",
        ids: &["impeccable-live-bar", "impeccable-live-shader"],
        states: &["action-label", "animated-dots", "generating", "done"],
    },
    LiveUiSurface {
        key: "variant-cycling-row",
        ids: &["impeccable-live-bar", "impeccable-live-params-panel"],
        states: &[
            "variant-1",
            "variant-2",
            "variant-3",
            "left-disabled",
            "right-disabled",
            "dot-click",
            "accept",
            "discard",
        ],
    },
    LiveUiSurface {
        key: "variant-params-panel",
        ids: &["impeccable-live-params-panel"],
        states: &["closed", "open-above", "open-below", "range", "steps", "toggle"],
    },
    LiveUiSurface {
        key: "saving-confirmed-rows",
        ids: &["impeccable-live-bar"],
        states: &["saving", "applying-variant", "confirmed"],
    },
    LiveUiSurface {
        key: "insert-mode-chrome",
        ids: &[
            "impeccable-live-insert-line",
            "impeccable-live-insert-placeholder",
            "impeccable-live-placeholder-resize",
            "impeccable-live-insert-input",
            "impeccable-live-insert-voice",
            "impeccable-live-insert-create",
            "impeccable-live-insert-create-tooltip",
        ],
        states: &["toggle-active", "line", "placeholder", "resize", "enabled", "disabled", "tooltip"],
    },
    LiveUiSurface {
        key: "annotation-chrome",
        ids: &[
            "impeccable-live-annot",
            "impeccable-live-annot-svg",
            "impeccable-live-annot-pins",
            "impeccable-live-annot-clear",
        ],
        states: &["overlay", "drawing", "pin", "pin-edit", "clear"],
    },
    LiveUiSurface {
        key: "design-system-panel",
        ids: &["impeccable-live-design-host"],
        states: &["closed", "open", "tabs", "token-tiles", "copy"],
    },
    LiveUiSurface {
        key: "toasts-and-errors",
        ids: &["impeccable-live-toast"],
        states: &["normal", "error", "no-variants-mounted"],
    },
    LiveUiSurface {
        key: "css-isolation-boundary",
        ids: &["impeccable-live-root"],
        states: &["shadow-root", "style-tags", "hostile-css"],
    },
];

/// `LIVE_UI_COMPONENT_IDS` in ui-core.mjs: the deduped union of every
/// surface's `ids`, in first-seen order (JS `new Set(...flatMap...)`
/// preserves insertion order).
pub fn live_ui_component_ids() -> Vec<&'static str> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for surface in LIVE_UI_SURFACES {
        for id in surface.ids {
            if seen.insert(*id) {
                out.push(*id);
            }
        }
    }
    out
}

/// Port of `escapeCssIdent` in ui-core.mjs: the manual `CSS.escape`
/// fallback used when the runtime has no native implementation. Escapes
/// each character in the punctuation set with a backslash.
pub fn escape_css_ident(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(
            ch,
            ' ' | '!' | '"' | '#' | '$' | '%' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | '.'
                | '/' | ':' | ';' | '<' | '=' | '>' | '?' | '@' | '[' | '\\' | ']' | '^' | '`'
                | '{' | '|' | '}' | '~'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_contract_matches_js_order() {
        assert_eq!(LIVE_CHROME_MOUNT_CONTRACT, ["root", "transport", "state", "actions"]);
    }

    #[test]
    fn fourteen_surfaces_present() {
        assert_eq!(LIVE_UI_SURFACES.len(), 14);
        assert_eq!(LIVE_UI_SURFACES[0].key, "global-bottom-bar");
        assert_eq!(LIVE_UI_SURFACES.last().unwrap().key, "css-isolation-boundary");
    }

    #[test]
    fn component_ids_are_deduped_in_first_seen_order() {
        let ids = live_ui_component_ids();
        // "impeccable-live-bar" appears in three surfaces; it must show up
        // exactly once, at its first-seen position.
        let bar_count = ids.iter().filter(|id| **id == "impeccable-live-bar").count();
        assert_eq!(bar_count, 1);
        let bar_pos = ids.iter().position(|id| *id == "impeccable-live-bar").unwrap();
        // First seen inside "element-selection-chrome" (before
        // "generating-row"/"variant-cycling-row"/"saving-confirmed-rows").
        assert!(ids[..bar_pos].contains(&"impeccable-live-tooltip"));
    }

    #[test]
    fn escape_css_ident_matches_css_escape_semantics() {
        assert_eq!(escape_css_ident("foo bar"), "foo\\ bar");
        assert_eq!(escape_css_ident("a.b#c"), "a\\.b\\#c");
        assert_eq!(escape_css_ident("plain"), "plain");
        assert_eq!(escape_css_ident("id[data-x]"), "id\\[data-x\\]");
    }
}
