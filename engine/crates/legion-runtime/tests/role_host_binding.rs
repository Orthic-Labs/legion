use legion_runtime::p7_host::host_adapters::codex_descriptor;

#[test]
fn codex_roles_have_native_configuration_without_claiming_hook_enforcement() {
    let descriptor = codex_descriptor();
    assert_eq!(descriptor["surfaces"]["agents"]["fidelity"], "strong");
    assert_eq!(
        descriptor["surfaces"]["agents"]["mechanism"]["kind"],
        "agent-config"
    );
    assert_eq!(descriptor["surfaces"]["hooks"]["fidelity"], "unsupported");
}
