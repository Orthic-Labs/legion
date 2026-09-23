//! Port of `src/providers/runtime/web/actors/index.mjs`
//! (`buildActorFixtures`, `switchActor`).

use super::shared::{denominator, digest, exact_binding, finalize, same_binding, sort_by_id};
use serde_json::{Map, Value};

const REQUIRED_KEYS: &[&str] = &["role", "tier", "tenantId", "accountState"];
const ACCOUNT_STATES: &[&str] = &["active", "disabled", "expired", "locked", "revoked"];
const REFERENCE_TYPES: &[&str] = &["vault", "env", "secret-manager", "keychain"];

fn reference_id_re() -> regex::Regex {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$").unwrap()
}
fn reference_string_re() -> regex::Regex {
    regex::Regex::new(r"^([a-z-]+)://([A-Za-z0-9][A-Za-z0-9._:/-]*)$").unwrap()
}
fn safe_identifier_re() -> regex::Regex {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$").unwrap()
}

/// Port of `reference(value)`.
fn reference(value: &Value) -> Option<Value> {
    if let Some(obj) = value.as_object() {
        let type_ = obj.get("type").and_then(Value::as_str)?;
        let id = obj.get("id").and_then(Value::as_str).unwrap_or("");
        if REFERENCE_TYPES.contains(&type_) && reference_id_re().is_match(id) {
            return Some(serde_json::json!({ "type": type_, "id": id }));
        }
        return None;
    }
    let s = value.as_str()?;
    let caps = reference_string_re().captures(s)?;
    let type_ = caps.get(1)?.as_str();
    let id = caps.get(2)?.as_str();
    if REFERENCE_TYPES.contains(&type_) {
        Some(serde_json::json!({ "type": type_, "id": id }))
    } else {
        None
    }
}

/// Port of `utcMillis(value)`.
fn utc_millis(value: &Value) -> Option<i64> {
    let s = value.as_str()?;
    let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$").unwrap();
    if !re.is_match(s) {
        return None;
    }
    chrono_parse_millis(s)
}

/// Minimal RFC3339-ish millisecond parser matching JS `Date.parse` for the
/// exact pattern `utcMillis` already validated via regex (no external date
/// crate is in `engine/Cargo.lock` for this crate, so this hand-rolled
/// parser only needs to handle the pre-validated shape above).
fn chrono_parse_millis(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;
    let millis: i64 = if bytes.len() > 19 && bytes[19] == b'.' {
        s.get(20..23)?.parse().ok()?
    } else {
        0
    };
    // Days since epoch via a civil-calendar algorithm (Howard Hinnant's
    // days_from_civil), then combine with time-of-day.
    let days = days_from_civil(year, month, day);
    Some(days * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1000 + millis)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Port of `hostileIdentifier(value)`. Rust's `serde_json::Value` has no
/// symbol/bigint/function variants, so those JS branches (always hostile)
/// are unreachable for JSON-representable input.
fn hostile_identifier(value: &Value) -> bool {
    match value {
        Value::String(s) => !s.is_empty() && !safe_identifier_re().is_match(s),
        _ => false,
    }
}

fn str_or_empty(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").to_string()
}

fn required_key(item: &Value) -> String {
    REQUIRED_KEYS.iter().map(|k| str_or_empty(item.get(*k))).collect::<Vec<_>>().join(":")
}

/// Port of `buildActorFixtures(input)`.
pub fn build_actor_fixtures(
    binding: &Value,
    actors: &Value,
    required: &Value,
    now: Option<&str>,
    identity_capability: &Value,
    environment_capability: &Value,
) -> Value {
    let binding_out = if binding.is_object() { binding.clone() } else { Value::Object(Map::new()) };
    let actors_valid = actors.is_array()
        && actors.as_array().unwrap().iter().all(|item| {
            item.is_object()
                && item
                    .get("transitionCapabilities")
                    .map(|t| !t.is_array() || t.as_array().unwrap().iter().all(|tr| tr.is_object()))
                    .unwrap_or(true)
        });
    let required_valid = required.is_array() && required.as_array().unwrap().iter().all(Value::is_object);

    if !actors_valid || !required_valid {
        return finalize(
            "legion-web-actor-fixtures",
            serde_json::json!({
                "status": "error", "complete": false, "proof": false, "terminal": true,
                "binding": binding_out, "actors": [], "denominator": denominator(&[], &[], &[]).to_value(),
                "coverageGaps": ["actor-collections-invalid"],
            }),
        );
    }

    let actors_arr = actors.as_array().unwrap();
    let required_arr = required.as_array().unwrap();

    let identifiers_hostile = actors_arr.iter().any(|actor| {
        hostile_identifier(actor.get("id").unwrap_or(&Value::Null))
            || ["identityId", "credentialPolicyId", "sessionPolicyId", "role", "tier", "tenantId"]
                .iter()
                .any(|key| hostile_identifier(actor.get(*key).unwrap_or(&Value::Null)))
            || actor.get("serverAuthorizations").and_then(Value::as_array).is_some_and(|arr| arr.iter().any(hostile_identifier))
            || actor.get("uiVisibility").and_then(Value::as_array).is_some_and(|arr| arr.iter().any(hostile_identifier))
            || actor.get("transitionCapabilities").and_then(Value::as_array).is_some_and(|arr| {
                arr.iter().any(|item| {
                    ["id", "toActorId", "fromTenantId", "toTenantId", "authorizationId"]
                        .iter()
                        .any(|key| hostile_identifier(item.get(*key).unwrap_or(&Value::Null)))
                })
            })
    }) || required_arr.iter().any(|item| REQUIRED_KEYS.iter().any(|key| hostile_identifier(item.get(*key).unwrap_or(&Value::Null))));

    if identifiers_hostile {
        return finalize(
            "legion-web-actor-fixtures",
            serde_json::json!({
                "status": "error", "complete": false, "proof": false, "terminal": true,
                "binding": binding_out, "actors": [], "denominator": denominator(&[], &[], &[]).to_value(),
                "coverageGaps": ["actor-identifiers-invalid"],
            }),
        );
    }

    let mut blocked: Vec<String> = Vec::new();
    let identity_status = identity_capability.get("status").and_then(Value::as_str);
    if identity_status != Some("available") {
        blocked.push(format!("identity-capability-{}", identity_status.unwrap_or("missing")));
    }
    let env_status = environment_capability.get("status").and_then(Value::as_str);
    if env_status != Some("available") {
        blocked.push(format!("environment-capability-{}", env_status.unwrap_or("missing")));
    }
    if !blocked.is_empty() {
        let expected: Vec<String> = required_arr.iter().map(required_key).collect();
        blocked.sort();
        return finalize(
            "legion-web-actor-fixtures",
            serde_json::json!({
                "status": "blocked", "complete": false, "proof": false, "terminal": true,
                "binding": binding_out, "actors": [],
                "denominator": denominator(&expected, &[], &[]).to_value(),
                "coverageGaps": blocked,
            }),
        );
    }

    let sorted_actors = sort_by_id(actors_arr);
    let normalized: Vec<Value> = sorted_actors
        .iter()
        .map(|actor| {
            let concurrency_key = actor
                .get("concurrencyKey")
                .cloned()
                .unwrap_or_else(|| Value::String(format!("{}:{}", str_or_empty(actor.get("tenantId")), str_or_empty(actor.get("id")))));
            let server_authorizations: Vec<Value> = actor
                .get("serverAuthorizations")
                .and_then(Value::as_array)
                .map(|arr| {
                    let mut v = arr.clone();
                    v.sort_by(|a, b| js_string_val(a).cmp(&js_string_val(b)));
                    v
                })
                .unwrap_or_default();
            let ui_visibility: Vec<Value> = actor
                .get("uiVisibility")
                .and_then(Value::as_array)
                .map(|arr| {
                    let mut v = arr.clone();
                    v.sort_by(|a, b| js_string_val(a).cmp(&js_string_val(b)));
                    v
                })
                .unwrap_or_default();
            let transition_capabilities: Vec<Value> = actor
                .get("transitionCapabilities")
                .and_then(Value::as_array)
                .map(|arr| {
                    sort_by_id(arr)
                        .into_iter()
                        .map(|item| {
                            serde_json::json!({
                                "id": item.get("id").cloned().unwrap_or(Value::Null),
                                "toActorId": item.get("toActorId").cloned().unwrap_or(Value::Null),
                                "fromTenantId": item.get("fromTenantId").cloned().unwrap_or(Value::Null),
                                "toTenantId": item.get("toTenantId").cloned().unwrap_or(Value::Null),
                                "authorizationId": item.get("authorizationId").cloned().unwrap_or(Value::Null),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            serde_json::json!({
                "id": actor.get("id").cloned().unwrap_or(Value::Null),
                "identityId": actor.get("identityId").cloned().unwrap_or(Value::Null),
                "credentialPolicyId": actor.get("credentialPolicyId").cloned().unwrap_or(Value::Null),
                "sessionPolicyId": actor.get("sessionPolicyId").cloned().unwrap_or(Value::Null),
                "role": actor.get("role").cloned().unwrap_or(Value::Null),
                "tier": actor.get("tier").cloned().unwrap_or(Value::Null),
                "tenantId": actor.get("tenantId").cloned().unwrap_or(Value::Null),
                "accountState": actor.get("accountState").cloned().unwrap_or(Value::Null),
                "credential": reference(actor.get("secretRef").unwrap_or(&Value::Null)).unwrap_or(Value::Null),
                "issuedAt": actor.get("issuedAt").cloned().unwrap_or(Value::Null),
                "expiresAt": actor.get("expiresAt").cloned().unwrap_or(Value::Null),
                "revokedAt": actor.get("revokedAt").cloned().unwrap_or(Value::Null),
                "serverAuthorizations": server_authorizations,
                "uiVisibility": ui_visibility,
                "transitionCapabilities": transition_capabilities,
                "concurrencyKey": concurrency_key,
            })
        })
        .collect();

    let expected: Vec<String> = required_arr.iter().map(required_key).collect();
    let actual: Vec<String> = normalized.iter().map(required_key).collect();
    let receipt_ids: Vec<String> = actual.iter().filter(|id| expected.contains(id)).cloned().collect();

    let mut gaps: Vec<String> = exact_binding(&binding_out).gaps.iter().map(|k| format!("binding-missing:{k}")).collect();
    if now.is_none() {
        gaps.push("actor-clock-unbound".to_string());
    }
    if required_arr.is_empty() {
        gaps.push("required-actor-denominator-empty".to_string());
    }

    let actor_ids: Vec<String> = normalized.iter().map(|a| str_or_empty(a.get("id"))).collect();
    for id in actor_ids.iter().collect::<std::collections::BTreeSet<_>>() {
        if actor_ids.iter().filter(|v| *v == id).count() > 1 {
            gaps.push(format!("actor-id-duplicate:{id}"));
        }
    }
    let transition_ids: Vec<String> = normalized
        .iter()
        .flat_map(|a| a.get("transitionCapabilities").and_then(Value::as_array).cloned().unwrap_or_default())
        .map(|t| str_or_empty(t.get("id")))
        .collect();
    for id in transition_ids.iter().collect::<std::collections::BTreeSet<_>>() {
        if transition_ids.iter().filter(|v| *v == id).count() > 1 {
            gaps.push(format!("actor-transition-id-duplicate:{id}"));
        }
    }

    for (actor_index, actor) in normalized.iter().enumerate() {
        let source_actor = &sorted_actors[actor_index];
        let actor_id = str_or_empty(actor.get("id"));
        for key in ["id", "role", "tier", "tenantId", "identityId", "credentialPolicyId", "sessionPolicyId"] {
            if !actor.get(key).and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
                gaps.push(format!("actor-{key}-invalid:{actor_id}"));
            }
        }
        let account_state = actor.get("accountState").and_then(Value::as_str).unwrap_or("");
        if !ACCOUNT_STATES.contains(&account_state) {
            gaps.push(format!("actor-accountState-invalid:{actor_id}"));
        }
        for key in ["serverAuthorizations", "uiVisibility", "transitionCapabilities"] {
            if !source_actor.get(key).is_some_and(Value::is_array) {
                gaps.push(format!("actor-{key}-invalid:{actor_id}"));
            }
        }
        let server_auths = actor.get("serverAuthorizations").and_then(Value::as_array).cloned().unwrap_or_default();
        if server_auths.iter().any(|item| !item.as_str().is_some_and(|s| !s.is_empty())) {
            gaps.push(format!("actor-serverAuthorizations-entry-invalid:{actor_id}"));
        }
        let ui_vis = actor.get("uiVisibility").and_then(Value::as_array).cloned().unwrap_or_default();
        if ui_vis.iter().any(|item| !item.as_str().is_some_and(|s| !s.is_empty())) {
            gaps.push(format!("actor-uiVisibility-entry-invalid:{actor_id}"));
        }
        if actor.get("credential") == Some(&Value::Null) || actor.get("credential").is_none() {
            gaps.push(format!("credential-reference-invalid:{actor_id}"));
        }

        let current = now.map(|n| Value::String(n.to_string())).and_then(|v| utc_millis(&v));
        let issued_raw = actor.get("issuedAt").cloned().unwrap_or(Value::Null);
        let expires_raw = actor.get("expiresAt").cloned().unwrap_or(Value::Null);
        let revoked_raw = actor.get("revokedAt").cloned().unwrap_or(Value::Null);
        let issued = if issued_raw.is_null() { None } else { utc_millis(&issued_raw) };
        let expires = if expires_raw.is_null() { None } else { utc_millis(&expires_raw) };
        let revoked = if revoked_raw.is_null() { None } else { utc_millis(&revoked_raw) };

        if now.is_some() && current.is_none() {
            gaps.push(format!("credential-now-timestamp-invalid:{actor_id}"));
        }
        for (key, raw, parsed) in [
            ("issuedAt", &issued_raw, issued),
            ("expiresAt", &expires_raw, expires),
            ("revokedAt", &revoked_raw, revoked),
        ] {
            if !raw.is_null() && parsed.is_none() {
                gaps.push(format!("credential-{key}-timestamp-invalid:{actor_id}"));
            }
        }
        if account_state == "active" && expires_raw.is_null() {
            gaps.push(format!("credential-expiry-unbound:{actor_id}"));
        }
        if account_state == "active" {
            if let (Some(e), Some(c)) = (expires, current) {
                if e <= c {
                    gaps.push(format!("credential-expired:{actor_id}"));
                }
            }
        }
        if account_state == "revoked" && revoked_raw.is_null() {
            gaps.push(format!("revocation-unbound:{actor_id}"));
        }
        if let (Some(i), Some(c)) = (issued, current) {
            if i > c {
                gaps.push(format!("credential-issued-in-future:{actor_id}"));
            }
        }
        if let (Some(r), Some(c)) = (revoked, current) {
            if r > c {
                gaps.push(format!("credential-revoked-in-future:{actor_id}"));
            }
        }
        if let (Some(i), Some(e)) = (issued, expires) {
            if i > e {
                gaps.push(format!("credential-issued-after-expiry:{actor_id}"));
            }
        }
        if let (Some(i), Some(r)) = (issued, revoked) {
            if i > r {
                gaps.push(format!("credential-issued-after-revocation:{actor_id}"));
            }
        }
        if let (Some(e), Some(r)) = (expires, revoked) {
            if e < r {
                gaps.push(format!("credential-revoked-after-expiry:{actor_id}"));
            }
        }

        for transition in actor.get("transitionCapabilities").and_then(Value::as_array).cloned().unwrap_or_default() {
            let to_actor_id = transition.get("toActorId").and_then(Value::as_str).unwrap_or("");
            let target = normalized.iter().find(|c| c.get("id").and_then(Value::as_str) == Some(to_actor_id));
            let transition_id = transition.get("id").and_then(Value::as_str).unwrap_or("missing");
            let from_tenant_ok = transition.get("fromTenantId") == actor.get("tenantId");
            let auth_id_ok = transition.get("authorizationId").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
            let id_ok = transition.get("id").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
            let to_tenant_ok = target.map(|t| transition.get("toTenantId") == t.get("tenantId")).unwrap_or(false);
            if !id_ok || !from_tenant_ok || target.is_none() || !to_tenant_ok || !auth_id_ok {
                gaps.push(format!("actor-transition-invalid:{actor_id}:{transition_id}"));
            }
            let actor_identity = actor.get("identityId").and_then(Value::as_str).filter(|s| !s.is_empty());
            let target_identity = target.and_then(|t| t.get("identityId")).and_then(Value::as_str).filter(|s| !s.is_empty());
            let actor_cred_policy = actor.get("credentialPolicyId").and_then(Value::as_str).filter(|s| !s.is_empty());
            let target_cred_policy = target.and_then(|t| t.get("credentialPolicyId")).and_then(Value::as_str);
            let actor_session_policy = actor.get("sessionPolicyId").and_then(Value::as_str).filter(|s| !s.is_empty());
            let target_session_policy = target.and_then(|t| t.get("sessionPolicyId")).and_then(Value::as_str);
            if actor_identity.is_none()
                || target_identity.is_none()
                || actor_cred_policy.is_none()
                || actor_cred_policy != target_cred_policy
                || actor_session_policy.is_none()
                || actor_session_policy != target_session_policy
            {
                gaps.push(format!("actor-transition-policy-mismatch:{actor_id}:{transition_id}"));
            }
            let authorization_id = transition.get("authorizationId").and_then(Value::as_str).unwrap_or("");
            let actor_has_auth = server_auths.iter().any(|a| a.as_str() == Some(authorization_id));
            let target_has_auth = target
                .and_then(|t| t.get("serverAuthorizations"))
                .and_then(Value::as_array)
                .is_some_and(|arr| arr.iter().any(|a| a.as_str() == Some(authorization_id)));
            if !actor_has_auth || !target_has_auth {
                gaps.push(format!("actor-transition-authorization-ungranted:{actor_id}:{transition_id}"));
            }
        }
    }

    let counts = denominator(&expected, &receipt_ids, &[]);
    gaps.extend(counts.missing.iter().map(|id| format!("actor-fixture-missing:{id}")));

    let mut sorted_gaps = gaps;
    sorted_gaps.sort();
    sorted_gaps.dedup();
    let status = if sorted_gaps.is_empty() { "pass" } else { "unproven" };

    finalize(
        "legion-web-actor-fixtures",
        serde_json::json!({
            "status": status,
            "complete": status == "pass",
            "proof": status == "pass",
            "terminal": true,
            "binding": binding_out,
            "actors": normalized,
            "denominator": counts.to_value(),
            "coverageGaps": sorted_gaps,
        }),
    )
}

fn js_string_val(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Port of `switchActor(input)`. Returns `{status, ...}`; on success
/// `status: 'pass'` plus `from`/`to`/`tenantId`/`concurrencyKey`/
/// `sessionBinding`; on failure `status: 'blocked'` plus `reason`.
#[allow(clippy::too_many_arguments)]
pub fn switch_actor(
    receipt: &Value,
    from: &str,
    to: &str,
    current_actor_id: &str,
    session_binding: &Value,
    concurrent_actor_ids: &[String],
    transition_capability_id: Option<&str>,
    server_authorization: &Value,
) -> Value {
    let blocked = |reason: &str| serde_json::json!({ "status": "blocked", "reason": reason });

    let receipt_obj = receipt.as_object().cloned().unwrap_or_default();
    let receipt_digest = receipt_obj.get("digest").and_then(Value::as_str);
    let mut receipt_body = receipt_obj.clone();
    receipt_body.remove("digest");
    let computed_digest = digest(&Value::Object(receipt_body));
    if receipt_digest.is_none() || receipt_digest != Some(computed_digest.as_str()) {
        return blocked("actor-fixture-digest-mismatch");
    }
    let status_ok = receipt.get("status").and_then(Value::as_str) == Some("pass")
        && receipt.get("terminal") == Some(&Value::Bool(true))
        && receipt.get("complete") == Some(&Value::Bool(true))
        && receipt.get("proof") == Some(&Value::Bool(true))
        && exact_binding(receipt.get("binding").unwrap_or(&Value::Null)).gaps.is_empty();
    if !status_ok {
        return blocked("actor-fixture-proof-unproven");
    }

    let actors = receipt.get("actors").and_then(Value::as_array).cloned().unwrap_or_default();
    let source = actors.iter().find(|a| a.get("id").and_then(Value::as_str) == Some(from)).cloned();
    let target = actors.iter().find(|a| a.get("id").and_then(Value::as_str) == Some(to)).cloned();
    let Some(source) = source else { return blocked("source-actor-missing") };
    let Some(target) = target else { return blocked("target-actor-missing") };
    if current_actor_id != from {
        return blocked("current-actor-mismatch");
    }
    let receipt_binding = receipt.get("binding").cloned().unwrap_or(Value::Null);
    if !same_binding(&receipt_binding, session_binding)
        || session_binding.get("actorId").and_then(Value::as_str) != Some(from)
        || session_binding.get("tenantId") != source.get("tenantId")
    {
        return blocked("session-binding-mismatch");
    }
    if source.get("accountState").and_then(Value::as_str) != Some("active") {
        return blocked("source-actor-not-active");
    }

    let cross_tenant = target.get("tenantId") != source.get("tenantId");
    let authorization_required = source.get("identityId") != target.get("identityId")
        || cross_tenant
        || source.get("role") != target.get("role")
        || source.get("accountState") != target.get("accountState");

    if authorization_required {
        let transition = source
            .get("transitionCapabilities")
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter().find(|item| {
                    item.get("id").and_then(Value::as_str) == transition_capability_id
                        && item.get("toActorId").and_then(Value::as_str) == Some(to)
                        && item.get("fromTenantId") == source.get("tenantId")
                        && item.get("toTenantId") == target.get("tenantId")
                })
            })
            .cloned();
        let Some(transition) = transition else {
            return blocked(if cross_tenant { "cross-tenant-transition-capability-missing" } else { "actor-transition-capability-missing" });
        };
        let policy_ok = source.get("identityId").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && target.get("identityId").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && source.get("credentialPolicyId").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && source.get("credentialPolicyId") == target.get("credentialPolicyId")
            && source.get("sessionPolicyId").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && source.get("sessionPolicyId") == target.get("sessionPolicyId");
        if !policy_ok {
            return blocked(if cross_tenant { "cross-tenant-transition-policy-mismatch" } else { "actor-transition-policy-mismatch" });
        }
        let transition_id = transition.get("id").cloned().unwrap_or(Value::Null);
        let authorization_bound = server_authorization.get("kind").and_then(Value::as_str) == Some("server-authorization-evidence")
            && server_authorization.get("transitionId") == Some(&transition_id)
            && server_authorization.get("controlId") == Some(&transition_id)
            && server_authorization.get("authorizationId") == transition.get("authorizationId")
            && server_authorization.get("fromActorId").and_then(Value::as_str) == Some(from)
            && server_authorization.get("toActorId").and_then(Value::as_str) == Some(to)
            && server_authorization.get("actorId").and_then(Value::as_str) == Some(from)
            && server_authorization.get("fromTenantId") == source.get("tenantId")
            && server_authorization.get("toTenantId") == target.get("tenantId")
            && server_authorization.get("tenantId") == source.get("tenantId")
            && server_authorization.get("fromAccountState") == source.get("accountState")
            && server_authorization.get("toAccountState") == target.get("accountState")
            && server_authorization.get("sessionPolicyId") == source.get("sessionPolicyId")
            && same_binding(session_binding, server_authorization.get("sessionBinding").unwrap_or(&Value::Null));
        let auth_ok = authorization_bound
            && server_authorization.get("status").and_then(Value::as_str) == Some("pass")
            && server_authorization.get("terminal") == Some(&Value::Bool(true))
            && same_binding(&receipt_binding, server_authorization.get("binding").unwrap_or(&Value::Null))
            && source
                .get("serverAuthorizations")
                .and_then(Value::as_array)
                .is_some_and(|arr| arr.iter().any(|a| Some(a) == transition.get("authorizationId")))
            && target
                .get("serverAuthorizations")
                .and_then(Value::as_array)
                .is_some_and(|arr| arr.iter().any(|a| Some(a) == transition.get("authorizationId")));
        if !auth_ok {
            return blocked(if cross_tenant { "cross-tenant-server-authorization-unproven" } else { "actor-server-authorization-unproven" });
        }
    }

    if concurrent_actor_ids.iter().any(|id| id == from) {
        return blocked("source-actor-concurrent-session-active");
    }
    if target.get("accountState").and_then(Value::as_str) != Some("active") {
        return blocked("target-actor-not-active");
    }

    let mut new_session_binding = session_binding.as_object().cloned().unwrap_or_default();
    new_session_binding.insert("actorId".to_string(), Value::String(to.to_string()));
    new_session_binding.insert("tenantId".to_string(), target.get("tenantId").cloned().unwrap_or(Value::Null));

    serde_json::json!({
        "status": "pass",
        "from": from,
        "to": to,
        "tenantId": target.get("tenantId").cloned().unwrap_or(Value::Null),
        "concurrencyKey": target.get("concurrencyKey").cloned().unwrap_or(Value::Null),
        "sessionBinding": new_session_binding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_collections_are_error() {
        let out = build_actor_fixtures(
            &Value::Null,
            &Value::String("x".to_string()),
            &Value::Array(vec![]),
            None,
            &Value::Null,
            &Value::Null,
        );
        assert_eq!(out["status"], "error");
        assert_eq!(out["coverageGaps"][0], "actor-collections-invalid");
    }

    #[test]
    fn hostile_identifier_is_rejected() {
        let actors = serde_json::json!([{ "id": "bad id with spaces" }]);
        let out = build_actor_fixtures(
            &Value::Null,
            &actors,
            &Value::Array(vec![]),
            None,
            &Value::Null,
            &Value::Null,
        );
        assert_eq!(out["status"], "error");
        assert_eq!(out["coverageGaps"][0], "actor-identifiers-invalid");
    }

    #[test]
    fn blocked_when_capability_unavailable() {
        let out = build_actor_fixtures(
            &Value::Null,
            &Value::Array(vec![]),
            &Value::Array(vec![]),
            None,
            &serde_json::json!({"status": "unavailable"}),
            &serde_json::json!({"status": "available"}),
        );
        assert_eq!(out["status"], "blocked");
        let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(gaps.contains(&"identity-capability-unavailable"));
    }

    #[test]
    fn switch_actor_rejects_digest_mismatch() {
        let receipt = serde_json::json!({ "digest": "sha256:deadbeef", "status": "pass" });
        let out = switch_actor(&receipt, "a", "b", "a", &Value::Null, &[], None, &Value::Null);
        assert_eq!(out["status"], "blocked");
        assert_eq!(out["reason"], "actor-fixture-digest-mismatch");
    }
}
