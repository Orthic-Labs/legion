//! Host surface declarations consumed by the projection generator.
//! Native role configuration is materialized by legion's commands/bind.rs;
//! supported configuration does not prove a host loaded or launched a role.

pub struct Surface {
    pub fidelity: &'static str,
    pub mechanism_kind: &'static str,
}

pub struct Adapter {
    pub id: &'static str,
    pub install_owner: &'static str,
    /// (instructions, skills, agents, mcp, hooks) — `Object.entries(adapter.surfaces)`
    /// iteration order in the JS source.
    pub surfaces: [(&'static str, Surface); 5],
}

macro_rules! surfaces {
    ($ii:expr, $im:expr, $si:expr, $sm:expr, $ai:expr, $am:expr, $mi:expr, $mm:expr, $hi:expr, $hm:expr) => {
        [
            (
                "instructions",
                Surface {
                    fidelity: $ii,
                    mechanism_kind: $im,
                },
            ),
            (
                "skills",
                Surface {
                    fidelity: $si,
                    mechanism_kind: $sm,
                },
            ),
            (
                "agents",
                Surface {
                    fidelity: $ai,
                    mechanism_kind: $am,
                },
            ),
            (
                "mcp",
                Surface {
                    fidelity: $mi,
                    mechanism_kind: $mm,
                },
            ),
            (
                "hooks",
                Surface {
                    fidelity: $hi,
                    mechanism_kind: $hm,
                },
            ),
        ]
    };
}

pub fn host_adapters() -> Vec<Adapter> {
    vec![
        Adapter {
            id: "claude-code",
            install_owner: "plugin",
            surfaces: surfaces!(
                "strong",
                "plugin",
                "strong",
                "plugin",
                "strong",
                "plugin",
                "strong",
                "plugin",
                "strong",
                "blocking-hook"
            ),
        },
        Adapter {
            id: "codex",
            install_owner: "adapter",
            surfaces: surfaces!(
                "strong",
                "agents-md",
                "strong",
                "skills-dir",
                "strong",
                "agent-config",
                "strong",
                "toml",
                "unsupported",
                "none"
            ),
        },
        Adapter {
            id: "cline",
            install_owner: "adapter",
            surfaces: surfaces!(
                "strong",
                "native-file",
                "degraded",
                "skills-dir",
                "unsupported",
                "none",
                "unsupported",
                "none",
                "unsupported",
                "none"
            ),
        },
        Adapter {
            id: "command-code",
            install_owner: "adapter",
            surfaces: surfaces!(
                "strong",
                "agents-md",
                "degraded",
                "skills-dir",
                "unsupported",
                "none",
                "unsupported",
                "none",
                "unsupported",
                "none"
            ),
        },
        Adapter {
            id: "pi",
            install_owner: "adapter",
            surfaces: surfaces!(
                "strong",
                "agents-md",
                "degraded",
                "skills-dir",
                "unsupported",
                "none",
                "unsupported",
                "none",
                "unsupported",
                "none"
            ),
        },
        Adapter {
            id: "generic",
            install_owner: "adapter",
            surfaces: surfaces!(
                "strong",
                "agents-md",
                "degraded",
                "skills-dir",
                "unsupported",
                "none",
                "unsupported",
                "none",
                "unsupported",
                "none"
            ),
        },
    ]
}
