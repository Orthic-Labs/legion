use legion_runtime::p7_host::host_adapters::codex_descriptor;

#[test]
fn codex_roles_and_plugin_surfaces_have_native_configuration() {
    let descriptor = codex_descriptor();
    assert_eq!(descriptor["surfaces"]["agents"]["fidelity"], "strong");
    assert_eq!(
        descriptor["surfaces"]["agents"]["mechanism"]["kind"],
        "agent-config"
    );
    assert_eq!(descriptor["installOwner"], "plugin");
    assert_eq!(
        descriptor["surfaces"]["skills"]["mechanism"]["kind"],
        "plugin"
    );
    assert_eq!(descriptor["surfaces"]["mcp"]["mechanism"]["kind"], "plugin");
    assert_eq!(descriptor["surfaces"]["hooks"]["fidelity"], "degraded");
    assert!(descriptor["surfaces"]["hooks"]["note"]
        .as_str()
        .unwrap()
        .contains("no pre-tool effect-enforcement hook is projected"));
}
