use crate::descriptor::Mechanism;

pub const SURFACES: [&str; 5] = ["instructions", "skills", "agents", "mcp", "hooks"];

pub fn enforcement_fidelity(mechanism: &Mechanism) -> String {
    if mechanism.kind == "none" {
        return "unsupported".into();
    }
    if mechanism.kind == "blocking-hook" {
        return "strong".into();
    }
    "degraded".into()
}
