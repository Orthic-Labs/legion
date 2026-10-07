//! Portable Citadel viewer and tray status helpers.

/// Alchemist run viewer URL.
pub const CITADEL_URL: &str = "http://127.0.0.1:8790";

/// Port of viewer idempotency rule: start only when no viewer is listening.
pub fn should_start(already_listening: bool) -> bool {
    !already_listening
}

/// Port of `start-stack.vbs`'s tray-idempotency rule: the tray is launched
/// only when no `powershell.exe` process already has `tray.ps1` on its
/// command line (`If Not running Then shell.Run ...`).
pub fn should_start_tray(tray_already_running: bool) -> bool {
    !tray_already_running
}

/// Port of `tray.ps1`'s Citadel-only status text.
pub fn status_menu_text(citadel_up: bool) -> String {
    format!("Citadel: {}", up_down(citadel_up))
}

/// Port of `tray.ps1`'s Citadel-only tooltip text.
pub fn tray_tooltip_text(citadel_up: bool) -> String {
    format!("Alchemist - Citadel {}", up_down(citadel_up))
}

fn up_down(is_up: bool) -> &'static str {
    if is_up {
        "up"
    } else {
        "down"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_start_only_when_not_already_listening() {
        assert!(should_start(false));
        assert!(!should_start(true));
    }

    #[test]
    fn should_start_tray_only_when_not_already_running() {
        assert!(should_start_tray(false));
        assert!(!should_start_tray(true));
    }

    #[test]
    fn status_menu_text_matches_tray_ps1_format() {
        assert_eq!(status_menu_text(true), "Citadel: up");
        assert_eq!(status_menu_text(false), "Citadel: down");
    }

    #[test]
    fn tray_tooltip_text_matches_tray_ps1_format() {
        assert_eq!(tray_tooltip_text(false), "Alchemist - Citadel down");
    }

    #[test]
    fn citadel_url_is_stable() {
        assert_eq!(CITADEL_URL, "http://127.0.0.1:8790");
    }
}
