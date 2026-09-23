//! Port of `src/providers/runtime/web/runner/index.mjs`
//! (`runWebControl`) — chunk wf050.
//!
//! `runWebControl` dispatches to three collaborators outside this chunk's
//! owned paths: `inspectWebBackend` (`../backend/index.mjs`, ported under
//! `wf_port::wf048::backend`), `verifyServiceApi`
//! (`../../service/api/index.mjs`, not yet ported at authoring time), and
//! this chunk's own `runWebScenario`/`executeWebProtocol`. The two
//! external dispatch targets are taken as injected closures so the
//! dispatch logic itself (`family` matching, the `api` receipt
//! re-wrapping) stays exact without this module reaching into another
//! chunk's files. See the wf050 report for this dependency.

use serde_json::{json, Value};

use super::shared::finalize;

/// Port of `runWebControl({ binding, family, input })`.
///
/// `backend_inspect` stands in for `inspectWebBackend({ binding, ...input
/// })`; `service_api_verify` stands in for `verifyServiceApi({ binding,
/// ...input })`, called via the `family === 'api'` branch's destructure-
/// and-relabel (`digest`/`kind`/`schemaVersion` dropped, `provider` set to
/// `'runtime.web'`, the original provider kept as `delegatedProvider`).
pub fn run_web_control(
    binding: &Value,
    family: Option<&str>,
    input: &Value,
    protocol_execute: &dyn Fn(&Value) -> Value,
    backend_inspect: &dyn Fn(&Value) -> Value,
    scenario_run: &dyn Fn(&Value) -> Value,
    service_api_verify: &dyn Fn(&Value) -> Value,
) -> Value {
    let mut merged = input.clone();
    if let Value::Object(map) = &mut merged {
        map.insert("binding".to_string(), binding.clone());
    }

    match family {
        Some("protocol") => protocol_execute(&merged),
        Some("backend") => backend_inspect(&merged),
        Some("scenario") => scenario_run(&merged),
        Some("api") => {
            let receipt = service_api_verify(&merged);
            let mut rest = receipt.as_object().cloned().unwrap_or_default();
            rest.remove("digest");
            rest.remove("kind");
            rest.remove("schemaVersion");
            let delegated_provider =
                rest.remove("provider").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "runtime.service.api".to_string());
            let mut out = Value::Object(rest);
            if let Value::Object(map) = &mut out {
                map.insert("provider".to_string(), Value::String("runtime.web".to_string()));
                map.insert("delegatedProvider".to_string(), Value::String(delegated_provider));
            }
            finalize("legion-web-api-provider", out)
        }
        _ => finalize(
            "legion-web-control-receipt",
            json!({
                "status": "blocked",
                "terminal": true,
                "binding": binding,
                "family": family,
                "coverageGaps": ["web-control-family-unsupported"],
            }),
        ),
    }
}
