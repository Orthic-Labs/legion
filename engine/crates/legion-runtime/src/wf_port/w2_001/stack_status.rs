//! Portable logic from `skills/alchemist/scripts/start-stack.vbs` (Windows
//! Startup-folder launcher for the OmniRoute gateway + Alchemist viewer +
//! tray) and `tray.ps1` (the NotifyIcon tray). See the module-level doc
//! comment in `super` for why the WSH/`Win32_Process`/NotifyIcon halves of
//! those two scripts are not ported.

/// OmniRoute gateway health-check URL both scripts probe before deciding to
/// start it (`start-stack.vbs`'s `Listening(...)`, `tray.ps1`'s
/// `Test-Up "$GATEWAY/healthz"`).
pub const GATEWAY_HEALTHZ_URL: &str = "http://127.0.0.1:20128/healthz";

/// Gateway dashboard URL (`tray.ps1`'s `$GATEWAY`, opened by "Open OmniRoute
/// dashboard").
pub const GATEWAY_DASHBOARD_URL: &str = "http://localhost:20128";

/// Alchemist run viewer URL both scripts probe/open
/// (`start-stack.vbs`: `http://127.0.0.1:8790/`; `tray.ps1`'s `$CITADEL`).
pub const CITADEL_URL: &str = "http://127.0.0.1:8790";

/// Port of `start-stack.vbs`'s idempotency rule: each service is only
/// started when nothing already answers on its probe URL
/// (`If Not Listening(url) Then ... shell.Run ...`). This captures the
/// decision, not the probe or the launch.
pub fn should_start(already_listening: bool) -> bool {
    !already_listening
}

/// Port of `start-stack.vbs`'s tray-idempotency rule: the tray is launched
/// only when no `powershell.exe` process already has `tray.ps1` on its
/// command line (`If Not running Then shell.Run ...`).
pub fn should_start_tray(tray_already_running: bool) -> bool {
    !tray_already_running
}

/// Port of `tray.ps1`'s status-menu text:
/// `"OmniRoute: $g   Citadel: $c"` where `$g`/`$c` are `"up"`/`"down"`.
pub fn status_menu_text(gateway_up: bool, citadel_up: bool) -> String {
    format!(
        "OmniRoute: {}   Citadel: {}",
        up_down(gateway_up),
        up_down(citadel_up)
    )
}

/// Port of `tray.ps1`'s tooltip text:
/// `"Alchemist - OmniRoute $g, Citadel $c"`.
pub fn tray_tooltip_text(gateway_up: bool, citadel_up: bool) -> String {
    format!(
        "Alchemist - OmniRoute {}, Citadel {}",
        up_down(gateway_up),
        up_down(citadel_up)
    )
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
        assert_eq!(status_menu_text(true, true), "OmniRoute: up   Citadel: up");
        assert_eq!(
            status_menu_text(false, true),
            "OmniRoute: down   Citadel: up"
        );
        assert_eq!(
            status_menu_text(true, false),
            "OmniRoute: up   Citadel: down"
        );
    }

    #[test]
    fn tray_tooltip_text_matches_tray_ps1_format() {
        assert_eq!(
            tray_tooltip_text(true, false),
            "Alchemist - OmniRoute up, Citadel down"
        );
    }

    #[test]
    fn urls_match_source_scripts() {
        assert_eq!(GATEWAY_HEALTHZ_URL, "http://127.0.0.1:20128/healthz");
        assert_eq!(GATEWAY_DASHBOARD_URL, "http://localhost:20128");
        assert_eq!(CITADEL_URL, "http://127.0.0.1:8790");
    }
}
