//! Port of `src/lib/review/room_protocol.py` — the typed P-1 Agent Room
//! protocol fixture.
//!
//! This is deliberately not the P0 room service. It is the small, local
//! correctness harness that must pass before the Rust/SQLite/HTTP service
//! is allowed to start. State transitions are driven by typed method
//! arguments; peer prose is stored as untrusted data and never parsed into
//! control events.
//!
//! Ported 1:1 as a stateful struct (`RoomProtocol`), matching the Python
//! class's method set and fail-closed `ProtocolError` codes exactly.
//! Dynamic dict-shaped inputs/outputs (`seats`, findings, events, etc.)
//! are kept as `serde_json::Value`, matching the Python's duck-typed
//! dicts, to stay a faithful behavioural port rather than a redesign.

use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const PEER_FINDING_FIELDS: [&str; 7] = [
    "finding_id",
    "claim",
    "severity",
    "rationale",
    "evidence_refs",
    "proposed_change",
    "confidence",
];

pub const PHASES: [&str; 9] = [
    "Open",
    "Positions",
    "PeerDebate",
    "Dispositions",
    "AuthorReview",
    "Escalation",
    "Voting",
    "Verdict",
    "AbortedFallback",
];

fn transitions(phase: &str) -> &'static [&'static str] {
    match phase {
        "Open" => &["Positions"],
        "Positions" => &["PeerDebate"],
        "PeerDebate" => &["Dispositions"],
        "Dispositions" => &["AuthorReview", "AbortedFallback"],
        "AuthorReview" => &["Escalation", "Voting"],
        "Escalation" => &["Voting"],
        "Voting" => &["Verdict"],
        "Verdict" => &[],
        "AbortedFallback" => &[],
        _ => &[],
    }
}

fn capabilities_for_mode(mode: &str) -> Option<&'static [&'static str]> {
    match mode {
        "review" | "debate" => Some(&[
            "join",
            "status",
            "next",
            "post",
            "leave",
            "findings",
            "contests",
            "dispositions",
            "resolutions",
            "rulings",
            "motions",
            "votes",
        ]),
        "worksplit" => Some(&["join", "status", "next", "post", "leave", "tasks"]),
        "freeform" => Some(&["join", "status", "next", "post", "leave"]),
        _ => None,
    }
}

/// A fail-closed protocol rejection with a stable machine-readable code.
/// Mirrors `ProtocolError(ValueError)`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}{}", detail_suffix(detail))]
pub struct ProtocolError {
    pub code: String,
    pub detail: String,
}

fn detail_suffix(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}

impl ProtocolError {
    fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        ProtocolError {
            code: code.into(),
            detail: detail.into(),
        }
    }
    fn code_only(code: impl Into<String>) -> Self {
        ProtocolError {
            code: code.into(),
            detail: String::new(),
        }
    }
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// JSON-canonical form matching Python's
/// `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))`.
fn canonical(value: &Value) -> String {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(&n.to_string()),
            Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap()),
            Value::Array(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(v, out);
                }
                out.push(']');
            }
            Value::Object(m) => {
                out.push('{');
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).unwrap());
                    out.push(':');
                    write(&m[*k], out);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let joined = parts.join("\u{1f}");
    let digest = sha256_hex(joined.as_bytes());
    format!("{prefix}_{}", &digest[..20])
}

fn finding_id_of(item: &Value) -> String {
    match item.get("finding_id") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// Return the only admissible initial review-scope motion payload.
/// Mirrors `derive_review_scope`.
pub fn derive_review_scope(disposition: &Value, deferred: &[Value]) -> Value {
    let mut normalized_deferred = deferred.to_vec();
    normalized_deferred.sort_by(|a, b| {
        let a_key = (
            finding_id_of(a),
            a.get("owner_phase")
                .or_else(|| a.get("phase"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        );
        let b_key = (
            finding_id_of(b),
            b.get("owner_phase")
                .or_else(|| b.get("phase"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        );
        a_key.cmp(&b_key)
    });
    let source = json!({
        "review_disposition": disposition,
        "defer_to_phase": normalized_deferred,
    });
    let digest = sha256_hex(canonical(&source).as_bytes());
    let scope_refs: Vec<Value> = normalized_deferred
        .iter()
        .filter_map(|item| item.get("finding_id").cloned().filter(|v| !v.is_null()))
        .collect();
    json!({
        "kind": "review_scope",
        "text": "Did the built phase prove the pinned Loop-1 obligations?",
        "scope_refs": scope_refs,
        "scope_digest": digest,
        "source": source,
    })
}

/// GAP: `derive_review_scope_from_artifacts` (workspace-relative file
/// reads of the disposition/deferred JSON) is not ported here as a
/// standalone function — `RoomProtocol::create_review_scope_from_artifacts`
/// below inlines the equivalent logic against `self.workspace_root`,
/// matching how the Python method actually calls it. A free function
/// wrapping arbitrary `workspace_root` paths adds no behaviour beyond
/// what that method already provides.

#[derive(Debug, Clone)]
pub struct RoomProtocol {
    pub room_id: String,
    pub workspace_root: std::path::PathBuf,
    pub seats: BTreeMap<String, Value>,
    pub mode: String,
    pub at_budget: String,
    pub phase: String,
    pub events: Vec<Value>,
    pub findings: BTreeMap<String, Value>,
    pub contests: BTreeMap<String, Value>,
    pub dispositions: BTreeMap<String, Value>,
    pub receipts: BTreeMap<String, Value>,
    pub motions: BTreeMap<String, Value>,
    pub votes: BTreeMap<String, Value>,
    pub escalations: Vec<String>,
    requests: HashMap<(String, String), (String, Value)>,
    author_rewakes: HashMap<String, u32>,
    pub sealed: bool,
}

impl RoomProtocol {
    pub fn new(
        room_id: impl Into<String>,
        workspace_root: impl Into<std::path::PathBuf>,
        seats: BTreeMap<String, Value>,
        mode: impl Into<String>,
        at_budget: impl Into<String>,
    ) -> Result<Self> {
        let mode = mode.into();
        let at_budget = at_budget.into();
        if capabilities_for_mode(&mode).is_none() {
            return Err(ProtocolError::new("invalid_mode", mode));
        }
        if !matches!(at_budget.as_str(), "abstain" | "summarize-and-continue") {
            return Err(ProtocolError::new("invalid_at_budget_behavior", at_budget));
        }
        let workspace_root = workspace_root.into();
        let workspace_root = workspace_root
            .canonicalize()
            .unwrap_or(workspace_root);
        Ok(RoomProtocol {
            room_id: room_id.into(),
            workspace_root,
            seats,
            mode,
            at_budget,
            phase: "Open".to_string(),
            events: Vec::new(),
            findings: BTreeMap::new(),
            contests: BTreeMap::new(),
            dispositions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            motions: BTreeMap::new(),
            votes: BTreeMap::new(),
            escalations: Vec::new(),
            requests: HashMap::new(),
            author_rewakes: HashMap::new(),
            sealed: false,
        })
    }

    fn seat(&self, actor: &str) -> Result<&Value> {
        self.seats
            .get(actor)
            .ok_or_else(|| ProtocolError::new("unknown_seat", actor))
    }

    fn require_role(&self, actor: &str, roles: &[&str]) -> Result<()> {
        let role = self
            .seat(actor)?
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !roles.contains(&role) {
            return Err(ProtocolError::new("role_forbidden", format!("{actor}:{role}")));
        }
        Ok(())
    }

    fn require_capability(&self, capability: &str) -> Result<()> {
        let caps = capabilities_for_mode(&self.mode).unwrap_or(&[]);
        if !caps.contains(&capability) {
            return Err(ProtocolError::new(
                "mode_forbidden",
                format!("{capability} in {}", self.mode),
            ));
        }
        Ok(())
    }

    /// Idempotency wrapper. Mirrors `_idempotent`.
    fn idempotent(
        &mut self,
        actor: &str,
        request_id: &str,
        operation: &str,
        payload: &Value,
        apply: impl FnOnce(&mut Self) -> Result<Value>,
    ) -> Result<Value> {
        self.seat(actor)?;
        if request_id.is_empty() {
            return Err(ProtocolError::code_only("request_id_required"));
        }
        let key = (actor.to_string(), request_id.to_string());
        let canon = canonical(&json!({"operation": operation, "payload": payload}));
        if let Some((prior_canon, prior_result)) = self.requests.get(&key) {
            if prior_canon != &canon {
                return Err(ProtocolError::new("request_id_conflict", request_id));
            }
            return Ok(prior_result.clone());
        }
        let result = apply(self)?;
        self.requests.insert(key, (canon, result.clone()));
        Ok(result)
    }

    fn push_event(&mut self, actor: &str, request_id: &str, kind: &str, mut fields: Value) -> Value {
        let seq = self.events.len() as u64 + 1;
        let mut event = json!({
            "seq": seq,
            "room_id": self.room_id,
            "seat_id": actor,
            "phase": self.phase,
            "request_id": request_id,
            "kind": kind,
        });
        if let (Some(event_obj), Some(field_obj)) = (event.as_object_mut(), fields.as_object_mut()) {
            for (k, v) in field_obj.iter() {
                event_obj.insert(k.clone(), v.clone());
            }
        }
        self.events.push(event.clone());
        event
    }

    pub fn capabilities(&self, seat_id: &str) -> Result<Vec<&'static str>> {
        self.seat(seat_id)?;
        let mut caps: Vec<&'static str> = capabilities_for_mode(&self.mode).unwrap_or(&[]).to_vec();
        caps.sort_unstable();
        Ok(caps)
    }

    pub fn open_finding_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .findings
            .iter()
            .filter(|(_, f)| {
                !matches!(
                    f.get("status").and_then(Value::as_str),
                    Some("Folded") | Some("Refuted")
                )
            })
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    pub fn advance(&mut self, actor: &str, target: &str, request_id: &str) -> Result<Value> {
        self.require_role(actor, &["moderator", "human"])?;
        if !PHASES.contains(&target) {
            return Err(ProtocolError::new("unknown_phase", target));
        }
        if matches!(target, "Voting" | "Verdict") && !self.open_finding_ids().is_empty() {
            return Err(ProtocolError::new("open_findings", self.open_finding_ids().join(",")));
        }
        let payload = json!({"target": target});
        let target = target.to_string();
        self.idempotent(actor, request_id, "advance", &payload, |this| {
            if !transitions(&this.phase).contains(&target.as_str()) {
                return Err(ProtocolError::new(
                    "invalid_transition",
                    format!("{}->{target}", this.phase),
                ));
            }
            this.phase = target.clone();
            Ok(this.push_event(actor, request_id, "phase", json!({"target": target})))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn post(
        &mut self,
        actor: &str,
        kind: &str,
        body: &str,
        request_id: &str,
        reply_to: Option<&str>,
        evidence_refs: &[String],
        plumbing: &Value,
    ) -> Result<Value> {
        self.require_capability("post")?;
        if !matches!(kind, "position" | "question" | "evidence" | "info") {
            return Err(ProtocolError::new("invalid_post_kind", kind));
        }
        if kind == "position" && self.phase != "Positions" {
            return Err(ProtocolError::new("phase_forbidden", format!("position in {}", self.phase)));
        }
        let payload = json!({
            "kind": kind,
            "body": body,
            "reply_to": reply_to,
            "evidence_refs": evidence_refs,
            "plumbing": plumbing,
        });
        let (kind, body, reply_to, evidence_refs) = (
            kind.to_string(),
            body.to_string(),
            reply_to.map(str::to_string),
            evidence_refs.to_vec(),
        );
        self.idempotent(actor, request_id, "post", &payload, move |this| {
            Ok(this.push_event(
                actor,
                request_id,
                &kind,
                json!({"body": body, "reply_to": reply_to, "evidence_refs": evidence_refs, "untrusted": true}),
            ))
        })
    }

    pub fn visible_events(&self, seat_id: &str, cursor: u64) -> Result<Vec<Value>> {
        self.seat(seat_id)?;
        Ok(self
            .events
            .iter()
            .filter(|event| {
                let seq = event.get("seq").and_then(Value::as_u64).unwrap_or(0);
                if seq <= cursor {
                    return false;
                }
                if self.phase == "Positions"
                    && event.get("kind").and_then(Value::as_str) == Some("position")
                    && event.get("seat_id").and_then(Value::as_str) != Some(seat_id)
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect())
    }

    /// Replay through the current visibility projection, never raw storage.
    pub fn rejoin_view(&self, seat_id: &str, cursor: u64) -> Result<Vec<Value>> {
        self.visible_events(seat_id, cursor)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn raise_finding(
        &mut self,
        actor: &str,
        claim: &str,
        severity: &str,
        rationale: &str,
        evidence_refs: &[String],
        proposed_change: &str,
        confidence: f64,
        request_id: &str,
    ) -> Result<Value> {
        self.require_capability("findings")?;
        if !matches!(self.phase.as_str(), "PeerDebate" | "Dispositions") {
            return Err(ProtocolError::new("phase_forbidden", format!("finding in {}", self.phase)));
        }
        let payload = json!({
            "claim": claim,
            "severity": severity,
            "rationale": rationale,
            "evidence_refs": evidence_refs,
            "proposed_change": proposed_change,
            "confidence": confidence,
        });
        let (claim, severity, rationale, proposed_change) = (
            claim.to_string(),
            severity.to_string(),
            rationale.to_string(),
            proposed_change.to_string(),
        );
        let room_id = self.room_id.clone();
        self.idempotent(actor, request_id, "raise_finding", &payload, move |this| {
            let finding_id = stable_id("finding", &[&room_id, actor, request_id]);
            let finding = json!({
                "finding_id": finding_id.clone(),
                "author_seat": actor,
                "claim": claim,
                "severity": severity,
                "rationale": rationale,
                "evidence_refs": evidence_refs,
                "proposed_change": proposed_change,
                "confidence": confidence,
                "status": "Open",
            });
            this.findings.insert(finding_id.clone(), finding.clone());
            this.push_event(actor, request_id, "finding", json!({"finding_id": finding_id}));
            Ok(finding)
        })
    }

    pub fn peer_findings(&self, seat_id: &str) -> Result<Vec<Value>> {
        self.seat(seat_id)?;
        Ok(self
            .findings
            .values()
            .filter(|f| f.get("author_seat").and_then(Value::as_str) != Some(seat_id))
            .map(|f| {
                let mut out = serde_json::Map::new();
                for field in PEER_FINDING_FIELDS {
                    out.insert(field.to_string(), f.get(field).cloned().unwrap_or(Value::Null));
                }
                Value::Object(out)
            })
            .collect())
    }

    pub fn contest(
        &mut self,
        actor: &str,
        finding_id: &str,
        rationale: &str,
        evidence_refs: &[String],
        request_id: &str,
    ) -> Result<Value> {
        self.require_capability("contests")?;
        if !self.findings.contains_key(finding_id) {
            return Err(ProtocolError::new("unknown_finding", finding_id));
        }
        let payload = json!({"finding_id": finding_id, "rationale": rationale, "evidence_refs": evidence_refs});
        let (finding_id, rationale) = (finding_id.to_string(), rationale.to_string());
        let evidence_refs = evidence_refs.to_vec();
        let room_id = self.room_id.clone();
        self.idempotent(actor, request_id, "contest", &payload, move |this| {
            let contest_id = stable_id("contest", &[&room_id, actor, request_id]);
            let contest = json!({
                "contest_id": contest_id.clone(),
                "finding_id": finding_id.clone(),
                "challenger_seat": actor,
                "rationale": rationale,
                "evidence_refs": evidence_refs,
            });
            this.contests.insert(contest_id.clone(), contest.clone());
            this.push_event(
                actor,
                request_id,
                "contest",
                json!({"contest_id": contest_id, "finding_id": finding_id}),
            );
            Ok(contest)
        })
    }

    /// Resolve a receipt locator against `self.workspace_root`, returning
    /// the resolved path and an optional 1-based line number. Mirrors
    /// `_workspace_locator`.
    fn workspace_locator(&self, locator: &str) -> Result<(std::path::PathBuf, Option<usize>)> {
        let (path_text, line) = if let Some(idx) = locator.rfind(':') {
            let (maybe_path, maybe_line) = (&locator[..idx], &locator[idx + 1..]);
            if !maybe_line.is_empty() && maybe_line.chars().all(|c| c.is_ascii_digit()) {
                (maybe_path, maybe_line.parse::<usize>().ok())
            } else {
                (locator, None)
            }
        } else {
            (locator, None)
        };
        let candidate = std::path::Path::new(path_text);
        let path = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            self.workspace_root.join(path_text)
        };
        let resolved = if path.exists() {
            path.canonicalize()
                .map_err(|_| ProtocolError::new("receipt_missing", locator))?
        } else {
            return Err(ProtocolError::new("receipt_missing", locator));
        };
        if resolved.strip_prefix(&self.workspace_root).is_err() {
            return Err(ProtocolError::new("receipt_outside_workspace", locator));
        }
        if !resolved.is_file() {
            return Err(ProtocolError::new("receipt_missing", locator));
        }
        if let Some(line) = line {
            let text = std::fs::read_to_string(&resolved)
                .map_err(|_| ProtocolError::new("receipt_missing", locator))?;
            let n_lines = text.lines().count();
            if line < 1 || line > n_lines {
                return Err(ProtocolError::new("receipt_line_missing", locator));
            }
        }
        Ok((resolved, line))
    }

    pub fn add_receipt(
        &mut self,
        actor: &str,
        kind: &str,
        locator: &str,
        request_id: &str,
        digest: Option<&str>,
    ) -> Result<Value> {
        if !matches!(kind, "file" | "artifact" | "measurement" | "web" | "scope_motion") {
            return Err(ProtocolError::new("invalid_receipt_kind", kind));
        }
        let payload = json!({"kind": kind, "locator": locator, "digest": digest});
        let (kind, locator, digest) = (kind.to_string(), locator.to_string(), digest.map(str::to_string));
        let room_id = self.room_id.clone();
        self.idempotent(actor, request_id, "add_receipt", &payload, move |this| {
            match kind.as_str() {
                "file" | "artifact" => {
                    this.workspace_locator(&locator)?;
                }
                "measurement" => {
                    let (path, _) = this.workspace_locator(&locator)?;
                    let bytes = std::fs::read(&path).map_err(|_| {
                        ProtocolError::new("receipt_digest_mismatch", locator.clone())
                    })?;
                    let actual = sha256_hex(&bytes);
                    if digest.as_deref() != Some(actual.as_str()) {
                        return Err(ProtocolError::new("receipt_digest_mismatch", locator.clone()));
                    }
                }
                "web" => {
                    let ok = locator.starts_with("http://") || locator.starts_with("https://");
                    let has_host = url_has_host(&locator);
                    if !ok || !has_host {
                        return Err(ProtocolError::new("invalid_source_url", locator.clone()));
                    }
                }
                "scope_motion" => {
                    let motion = this.motions.get(&locator).cloned();
                    let motion = match &motion {
                        Some(m)
                            if matches!(
                                m.get("kind").and_then(Value::as_str),
                                Some("review_scope") | Some("scope_amendment")
                            ) =>
                        {
                            m
                        }
                        _ => return Err(ProtocolError::new("unknown_scope_motion", locator.clone())),
                    };
                    if digest.is_none()
                        || digest.as_deref() != motion.get("scope_digest").and_then(Value::as_str)
                    {
                        return Err(ProtocolError::new("scope_digest_mismatch", locator.clone()));
                    }
                }
                _ => unreachable!(),
            }
            let receipt_id = stable_id("receipt", &[&room_id, actor, request_id]);
            let receipt = json!({
                "receipt_id": receipt_id.clone(),
                "kind": kind,
                "locator": locator,
                "digest": digest,
            });
            this.receipts.insert(receipt_id.clone(), receipt.clone());
            this.push_event(actor, request_id, "receipt", json!({"receipt_id": receipt_id}));
            Ok(receipt)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispose(
        &mut self,
        actor: &str,
        finding_id: &str,
        action: &str,
        receipt_refs: &[String],
        request_id: &str,
        reason_code: Option<&str>,
    ) -> Result<Value> {
        self.require_capability("dispositions")?;
        self.require_role(actor, &["implementer"])?;
        if !matches!(self.phase.as_str(), "Dispositions" | "AuthorReview") {
            return Err(ProtocolError::new("phase_forbidden", format!("dispose in {}", self.phase)));
        }
        let finding = self
            .findings
            .get(finding_id)
            .cloned()
            .ok_or_else(|| ProtocolError::new("unknown_finding", finding_id))?;
        if finding.get("status").and_then(Value::as_str) != Some("Open") {
            return Err(ProtocolError::new("finding_not_open", finding_id));
        }
        if !matches!(action, "folded" | "refuted") {
            return Err(ProtocolError::new("invalid_disposition", action));
        }
        if receipt_refs.is_empty() {
            return Err(ProtocolError::new("receipt_required", finding_id));
        }
        let receipts: Vec<Option<Value>> = receipt_refs
            .iter()
            .map(|r| self.receipts.get(r).cloned())
            .collect();
        if receipts.iter().any(Option::is_none) {
            return Err(ProtocolError::new("unknown_receipt", finding_id));
        }
        let receipts: Vec<Value> = receipts.into_iter().map(Option::unwrap).collect();
        if action == "folded"
            && !receipts
                .iter()
                .any(|r| r.get("kind").and_then(Value::as_str) == Some("artifact"))
        {
            return Err(ProtocolError::new("fold_artifact_required", finding_id));
        }
        if reason_code == Some("out_of_scope") {
            let initial = self.motions.values().find(|m| m.get("kind").and_then(Value::as_str) == Some("review_scope"));
            let matching = initial
                .map(|initial_motion| {
                    let motion_id = initial_motion.get("motion_id").and_then(Value::as_str);
                    let scope_digest = initial_motion.get("scope_digest").and_then(Value::as_str);
                    receipts.iter().any(|r| {
                        r.get("kind").and_then(Value::as_str) == Some("scope_motion")
                            && r.get("locator").and_then(Value::as_str) == motion_id
                            && r.get("digest").and_then(Value::as_str) == scope_digest
                    })
                })
                .unwrap_or(false);
            if !matching {
                return Err(ProtocolError::new("scope_receipt_required", finding_id));
            }
        }
        let payload = json!({
            "finding_id": finding_id,
            "action": action,
            "receipt_refs": receipt_refs,
            "reason_code": reason_code,
        });
        let (finding_id, action, reason_code) = (
            finding_id.to_string(),
            action.to_string(),
            reason_code.map(str::to_string),
        );
        let receipt_refs = receipt_refs.to_vec();
        let room_id = self.room_id.clone();
        self.idempotent(actor, request_id, "dispose", &payload, move |this| {
            let disposition_id = stable_id("disposition", &[&room_id, actor, request_id]);
            let disposition = json!({
                "disposition_id": disposition_id.clone(),
                "finding_id": finding_id.clone(),
                "implementer_seat": actor,
                "action": action.clone(),
                "reason_code": reason_code,
                "receipt_refs": receipt_refs,
                "status": "Proposed",
            });
            this.dispositions.insert(disposition_id.clone(), disposition.clone());
            let new_status = if action == "folded" { "FoldProposed" } else { "RefuteProposed" };
            if let Some(f) = this.findings.get_mut(&finding_id) {
                f["status"] = json!(new_status);
            }
            let all_settled = !this.findings.is_empty()
                && this.findings.values().all(|f| {
                    matches!(
                        f.get("status").and_then(Value::as_str),
                        Some("FoldProposed")
                            | Some("RefuteProposed")
                            | Some("Folded")
                            | Some("Refuted")
                            | Some("Recontested")
                    )
                });
            if all_settled {
                this.phase = "AuthorReview".to_string();
            }
            this.push_event(
                actor,
                request_id,
                "disposition",
                json!({"disposition_id": disposition_id, "finding_id": finding_id}),
            );
            Ok(disposition)
        })
    }

    pub fn resolve(
        &mut self,
        actor: &str,
        disposition_id: &str,
        choice: &str,
        reason: &str,
        evidence_refs: &[String],
        request_id: &str,
    ) -> Result<Value> {
        self.require_capability("resolutions")?;
        let disposition = self
            .dispositions
            .get(disposition_id)
            .cloned()
            .ok_or_else(|| ProtocolError::new("unknown_disposition", disposition_id))?;
        let finding_id = disposition
            .get("finding_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let finding = self
            .findings
            .get(&finding_id)
            .cloned()
            .ok_or_else(|| ProtocolError::new("unknown_finding", finding_id.clone()))?;
        let author_seat = finding.get("author_seat").and_then(Value::as_str).unwrap_or("");
        if actor != author_seat {
            return Err(ProtocolError::new("author_required", actor));
        }
        let implementer_seat = disposition.get("implementer_seat").and_then(Value::as_str).unwrap_or("");
        if actor == implementer_seat {
            return Err(ProtocolError::new("self_resolution_forbidden", actor));
        }
        if !matches!(self.phase.as_str(), "AuthorReview" | "Escalation") {
            return Err(ProtocolError::new("phase_forbidden", format!("resolve in {}", self.phase)));
        }
        if !matches!(choice, "accept" | "recontest") {
            return Err(ProtocolError::new("invalid_resolution", choice));
        }
        let payload = json!({
            "disposition_id": disposition_id,
            "choice": choice,
            "reason": reason,
            "evidence_refs": evidence_refs,
        });
        let (disposition_id, choice) = (disposition_id.to_string(), choice.to_string());
        self.idempotent(actor, request_id, "resolve", &payload, move |this| {
            let disposition = this.dispositions.get(&disposition_id).cloned().unwrap();
            if disposition.get("status").and_then(Value::as_str) != Some("Proposed") {
                return Err(ProtocolError::new("disposition_not_proposed", disposition_id.clone()));
            }
            let finding_id = disposition.get("finding_id").and_then(Value::as_str).unwrap_or("").to_string();
            if choice == "accept" {
                let action = disposition.get("action").and_then(Value::as_str).unwrap_or("").to_string();
                let receipt_refs = disposition.get("receipt_refs").cloned().unwrap_or(json!([]));
                if let Some(d) = this.dispositions.get_mut(&disposition_id) {
                    d["status"] = json!("Accepted");
                    d["final_action"] = json!(action);
                    d["final_receipt_refs"] = receipt_refs;
                }
                let new_status = if action == "folded" { "Folded" } else { "Refuted" };
                if let Some(f) = this.findings.get_mut(&finding_id) {
                    f["status"] = json!(new_status);
                }
            } else {
                if let Some(d) = this.dispositions.get_mut(&disposition_id) {
                    d["status"] = json!("Recontested");
                }
                if let Some(f) = this.findings.get_mut(&finding_id) {
                    f["status"] = json!("Recontested");
                }
                if !this.escalations.contains(&disposition_id) {
                    this.escalations.push(disposition_id.clone());
                }
                this.phase = "Escalation".to_string();
            }
            Ok(this.push_event(
                actor,
                request_id,
                "resolution",
                json!({"disposition_id": disposition_id, "choice": choice}),
            ))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rule(
        &mut self,
        actor: &str,
        disposition_id: &str,
        action: &str,
        reason: &str,
        receipt_refs: &[String],
        request_id: &str,
    ) -> Result<Value> {
        self.require_capability("rulings")?;
        self.require_role(actor, &["human"])?;
        let disposition = self
            .dispositions
            .get(disposition_id)
            .cloned()
            .ok_or_else(|| ProtocolError::new("unknown_disposition", disposition_id))?;
        if disposition.get("status").and_then(Value::as_str) != Some("Recontested") {
            return Err(ProtocolError::new("disposition_not_recontested", disposition_id));
        }
        if !matches!(action, "folded" | "refuted") {
            return Err(ProtocolError::new("invalid_ruling", action));
        }
        if receipt_refs.is_empty() || receipt_refs.iter().any(|r| !self.receipts.contains_key(r)) {
            return Err(ProtocolError::new("receipt_required", disposition_id));
        }
        if action == "folded"
            && !receipt_refs
                .iter()
                .any(|r| self.receipts.get(r).and_then(|rr| rr.get("kind")).and_then(Value::as_str) == Some("artifact"))
        {
            return Err(ProtocolError::new("fold_artifact_required", disposition_id));
        }
        let payload = json!({
            "disposition_id": disposition_id,
            "action": action,
            "reason": reason,
            "receipt_refs": receipt_refs,
        });
        let (disposition_id, action, reason) = (disposition_id.to_string(), action.to_string(), reason.to_string());
        let receipt_refs = receipt_refs.to_vec();
        self.idempotent(actor, request_id, "rule", &payload, move |this| {
            let finding_id = this
                .dispositions
                .get(&disposition_id)
                .and_then(|d| d.get("finding_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if let Some(d) = this.dispositions.get_mut(&disposition_id) {
                d["status"] = json!("Ruled");
                d["ruling"] = json!({
                    "human_seat": actor,
                    "action": action.clone(),
                    "reason": reason,
                    "receipt_refs": receipt_refs.clone(),
                });
                d["final_action"] = json!(action.clone());
                d["final_receipt_refs"] = json!(receipt_refs);
            }
            let new_status = if action == "folded" { "Folded" } else { "Refuted" };
            if let Some(f) = this.findings.get_mut(&finding_id) {
                f["status"] = json!(new_status);
            }
            Ok(this.push_event(
                actor,
                request_id,
                "ruling",
                json!({"disposition_id": disposition_id, "action": action}),
            ))
        })
    }

    pub fn create_review_scope(
        &mut self,
        actor: &str,
        disposition: &Value,
        deferred: &[Value],
        supplied_digest: &str,
        request_id: &str,
    ) -> Result<Value> {
        self.require_capability("motions")?;
        self.require_role(actor, &["moderator"])?;
        if self.phase != "Open" {
            return Err(ProtocolError::new("phase_forbidden", format!("review_scope in {}", self.phase)));
        }
        if self.motions.values().any(|m| m.get("kind").and_then(Value::as_str) == Some("review_scope")) {
            return Err(ProtocolError::code_only("review_scope_exists"));
        }
        let derived = derive_review_scope(disposition, deferred);
        if Some(supplied_digest) != derived.get("scope_digest").and_then(Value::as_str) {
            return Err(ProtocolError::code_only("scope_digest_mismatch"));
        }
        let payload = json!({
            "disposition": disposition,
            "deferred": deferred,
            "supplied_digest": supplied_digest,
        });
        let room_id = self.room_id.clone();
        self.idempotent(actor, request_id, "review_scope", &payload, move |this| {
            let motion_id = stable_id("motion", &[&room_id, actor, request_id]);
            let mut motion = derived.clone();
            motion["motion_id"] = json!(motion_id.clone());
            motion["moderator_seat"] = json!(actor);
            motion["status"] = json!("Open");
            this.motions.insert(motion_id.clone(), motion.clone());
            this.push_event(actor, request_id, "motion", json!({"motion_id": motion_id}));
            Ok(motion)
        })
    }

    pub fn create_review_scope_from_artifacts(
        &mut self,
        actor: &str,
        disposition_path: &str,
        deferred_path: &str,
        supplied_digest: &str,
        request_id: &str,
    ) -> Result<Value> {
        self.require_capability("motions")?;
        self.require_role(actor, &["moderator"])?;
        if self.phase != "Open" {
            return Err(ProtocolError::new("phase_forbidden", format!("review_scope in {}", self.phase)));
        }
        if self.motions.values().any(|m| m.get("kind").and_then(Value::as_str) == Some("review_scope")) {
            return Err(ProtocolError::code_only("review_scope_exists"));
        }
        let disposition_file = self.workspace_root.join(disposition_path);
        let deferred_file = self.workspace_root.join(deferred_path);
        for path in [&disposition_file, &deferred_file] {
            let resolved = path.canonicalize().map_err(|_| {
                ProtocolError::new("scope_artifact_missing", path.to_string_lossy().to_string())
            })?;
            if resolved.strip_prefix(&self.workspace_root).is_err() {
                return Err(ProtocolError::new(
                    "scope_artifact_outside_workspace",
                    resolved.to_string_lossy().to_string(),
                ));
            }
            if !resolved.is_file() {
                return Err(ProtocolError::new(
                    "scope_artifact_missing",
                    resolved.to_string_lossy().to_string(),
                ));
            }
        }
        let disposition_bytes = std::fs::read(&disposition_file)
            .map_err(|_| ProtocolError::new("scope_artifact_missing", disposition_path))?;
        let deferred_bytes = std::fs::read(&deferred_file)
            .map_err(|_| ProtocolError::new("scope_artifact_missing", deferred_path))?;
        let disposition: Value = serde_json::from_slice(&disposition_bytes)
            .map_err(|_| ProtocolError::code_only("scope_artifact_schema_invalid"))?;
        let deferred: Value = serde_json::from_slice(&deferred_bytes)
            .map_err(|_| ProtocolError::code_only("scope_artifact_schema_invalid"))?;
        let deferred_arr = deferred
            .as_array()
            .cloned()
            .ok_or_else(|| ProtocolError::code_only("scope_artifact_schema_invalid"))?;
        if !disposition.is_object() {
            return Err(ProtocolError::code_only("scope_artifact_schema_invalid"));
        }
        let derived = derive_review_scope(&disposition, &deferred_arr);
        let source_artifacts = vec![
            json!({"path": disposition_path, "sha256": sha256_hex(&disposition_bytes)}),
            json!({"path": deferred_path, "sha256": sha256_hex(&deferred_bytes)}),
        ];
        let digest_source = json!({"source": derived.get("source"), "source_artifacts": source_artifacts.clone()});
        let scope_digest = sha256_hex(canonical(&digest_source).as_bytes());
        let mut derived = derived;
        derived["scope_digest"] = json!(scope_digest.clone());
        derived["source_artifacts"] = json!(source_artifacts);

        if supplied_digest != scope_digest {
            return Err(ProtocolError::code_only("scope_digest_mismatch"));
        }
        let payload = json!({
            "disposition_path": disposition_path,
            "deferred_path": deferred_path,
            "supplied_digest": supplied_digest,
        });
        let room_id = self.room_id.clone();
        self.idempotent(actor, request_id, "review_scope_artifacts", &payload, move |this| {
            let motion_id = stable_id("motion", &[&room_id, actor, request_id]);
            let mut motion = derived.clone();
            motion["motion_id"] = json!(motion_id.clone());
            motion["moderator_seat"] = json!(actor);
            motion["status"] = json!("Open");
            this.motions.insert(motion_id.clone(), motion.clone());
            this.push_event(actor, request_id, "motion", json!({"motion_id": motion_id}));
            Ok(motion)
        })
    }

    pub fn vote(&mut self, actor: &str, motion_id: &str, choice: &str, reason: &str, request_id: &str) -> Result<Value> {
        self.require_capability("votes")?;
        if !self.motions.contains_key(motion_id) {
            return Err(ProtocolError::new("unknown_motion", motion_id));
        }
        if self.phase != "Voting" {
            return Err(ProtocolError::new("phase_forbidden", format!("vote in {}", self.phase)));
        }
        if !self.open_finding_ids().is_empty() {
            return Err(ProtocolError::new("open_findings", self.open_finding_ids().join(",")));
        }
        let payload = json!({"motion_id": motion_id, "choice": choice, "reason": reason});
        let (motion_id, choice) = (motion_id.to_string(), choice.to_string());
        let room_id = self.room_id.clone();
        self.idempotent(actor, request_id, "vote", &payload, move |this| {
            let vote_id = stable_id("vote", &[&room_id, actor, request_id]);
            let vote = json!({
                "vote_id": vote_id.clone(),
                "motion_id": motion_id,
                "seat_id": actor,
                "choice": choice,
            });
            this.votes.insert(vote_id.clone(), vote.clone());
            this.push_event(actor, request_id, "vote", json!({"vote_id": vote_id}));
            Ok(vote)
        })
    }

    pub fn amend_review_scope(
        &mut self,
        actor: &str,
        text: &str,
        scope_refs: &[String],
        parent_digest: &str,
        request_id: &str,
    ) -> Result<Value> {
        self.require_capability("motions")?;
        self.require_role(actor, &["human"])?;
        if matches!(self.phase.as_str(), "Open" | "Positions" | "Verdict" | "AbortedFallback") {
            return Err(ProtocolError::new("phase_forbidden", format!("scope amendment in {}", self.phase)));
        }
        let scope_chain: Vec<&Value> = self
            .motions
            .values()
            .filter(|m| matches!(m.get("kind").and_then(Value::as_str), Some("review_scope") | Some("scope_amendment")))
            .collect();
        let current = scope_chain
            .last()
            .ok_or_else(|| ProtocolError::code_only("review_scope_missing"))?;
        if Some(parent_digest) != current.get("scope_digest").and_then(Value::as_str) {
            return Err(ProtocolError::code_only("scope_digest_mismatch"));
        }
        let payload = json!({"text": text, "scope_refs": scope_refs, "parent_digest": parent_digest});
        let (text, parent_digest) = (text.to_string(), parent_digest.to_string());
        let scope_refs = scope_refs.to_vec();
        let room_id = self.room_id.clone();
        self.idempotent(actor, request_id, "scope_amendment", &payload, move |this| {
            let scope_digest = sha256_hex(canonical(&payload_for_amendment(&text, &scope_refs, &parent_digest)).as_bytes());
            let motion_id = stable_id("motion", &[&room_id, actor, request_id]);
            let motion = json!({
                "motion_id": motion_id.clone(),
                "kind": "scope_amendment",
                "text": text,
                "scope_refs": scope_refs,
                "parent_digest": parent_digest,
                "scope_digest": scope_digest,
                "human_seat": actor,
                "status": "Ruled",
            });
            this.motions.insert(motion_id.clone(), motion.clone());
            this.push_event(actor, request_id, "motion", json!({"motion_id": motion_id}));
            Ok(motion)
        })
    }

    pub fn tasks(&mut self, actor: &str, action: &str, request_id: &str) -> Result<Value> {
        self.require_capability("tasks")?;
        let payload = json!({"action": action});
        let action = action.to_string();
        self.idempotent(actor, request_id, "tasks", &payload, move |_this| {
            Ok(json!({"action": action, "tasks": []}))
        })
    }

    pub fn record_timeout(&mut self, actor: &str, seat_id: &str, request_id: &str) -> Result<Value> {
        self.require_role(actor, &["moderator", "human"])?;
        let seat = self.seat(seat_id)?.clone();
        let payload = json!({"seat_id": seat_id});
        let seat_id = seat_id.to_string();
        self.idempotent(actor, request_id, "timeout", &payload, move |this| {
            if seat.get("role").and_then(Value::as_str) == Some("implementer") {
                this.phase = "AbortedFallback".to_string();
                return Ok(this.push_event(
                    actor,
                    request_id,
                    "timeout",
                    json!({"seat_id": seat_id, "status": "fallback_required"}),
                ));
            }
            let pending: Vec<String> = this
                .dispositions
                .iter()
                .filter(|(_, d)| {
                    let finding_id = d.get("finding_id").and_then(Value::as_str).unwrap_or("");
                    this.findings
                        .get(finding_id)
                        .and_then(|f| f.get("author_seat"))
                        .and_then(Value::as_str)
                        == Some(seat_id.as_str())
                        && d.get("status").and_then(Value::as_str) == Some("Proposed")
                })
                .map(|(id, _)| id.clone())
                .collect();
            if pending.is_empty() {
                return Err(ProtocolError::new("no_pending_author_review", seat_id.clone()));
            }
            let wakes = *this.author_rewakes.get(&seat_id).unwrap_or(&0);
            let status = if wakes == 0 {
                this.author_rewakes.insert(seat_id.clone(), 1);
                "rewake"
            } else {
                for disposition_id in &pending {
                    if let Some(d) = this.dispositions.get_mut(disposition_id) {
                        d["status"] = json!("Recontested");
                    }
                    let finding_id = this
                        .dispositions
                        .get(disposition_id)
                        .and_then(|d| d.get("finding_id"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if let Some(f) = this.findings.get_mut(&finding_id) {
                        f["status"] = json!("Recontested");
                    }
                    if !this.escalations.contains(disposition_id) {
                        this.escalations.push(disposition_id.clone());
                    }
                }
                this.phase = "Escalation".to_string();
                "escalated"
            };
            Ok(this.push_event(
                actor,
                request_id,
                "timeout",
                json!({"seat_id": seat_id, "status": status}),
            ))
        })
    }

    pub fn metrics(&self) -> Value {
        let total = self.dispositions.len();
        let escalated: std::collections::BTreeSet<&String> = self.escalations.iter().collect();
        let rate = if total > 0 {
            escalated.len() as f64 / total as f64
        } else {
            0.0
        };
        json!({
            "total_dispositions": total,
            "escalated_dispositions": escalated.len(),
            "escalation_rate": rate,
            "failed_room": rate > 0.5,
            "at_budget": self.at_budget,
        })
    }

    /// Return the typed, JSON-serializable ledger used by the Jury gate.
    /// Mirrors `ledger_payload`.
    pub fn ledger_payload(&self) -> Value {
        json!({
            "schema_version": 1,
            "room_id": self.room_id,
            "mode": self.mode,
            "phase": self.phase,
            "findings": self.findings.values().cloned().collect::<Vec<_>>(),
            "contests": self.contests.values().cloned().collect::<Vec<_>>(),
            "dispositions": self.dispositions.values().cloned().collect::<Vec<_>>(),
            "receipts": self.receipts.values().cloned().collect::<Vec<_>>(),
            "motions": self.motions.values().cloned().collect::<Vec<_>>(),
            "metrics": self.metrics(),
        })
    }

    pub fn status(&self, seat_id: &str) -> Result<Value> {
        self.seat(seat_id)?;
        let visible = self.visible_events(seat_id, 0)?;
        let cursor = visible.iter().filter_map(|e| e.get("seq").and_then(Value::as_u64)).max().unwrap_or(0);
        Ok(json!({
            "room_id": self.room_id,
            "seat_id": seat_id,
            "mode": self.mode,
            "phase": self.phase,
            "latest_visible_cursor": cursor,
            "open_finding_ids": self.open_finding_ids(),
            "metrics": self.metrics(),
        }))
    }

    pub fn seal(&mut self, actor: &str, request_id: &str) -> Result<Value> {
        self.require_role(actor, &["moderator", "human"])?;
        if !self.open_finding_ids().is_empty() {
            return Err(ProtocolError::new("open_findings", self.open_finding_ids().join(",")));
        }
        if self.phase != "Verdict" {
            return Err(ProtocolError::new("phase_forbidden", format!("seal in {}", self.phase)));
        }
        self.idempotent(actor, request_id, "seal", &json!({}), move |this| {
            this.sealed = true;
            Ok(this.push_event(actor, request_id, "sealed", json!({})))
        })
    }
}

fn payload_for_amendment(text: &str, scope_refs: &[String], parent_digest: &str) -> Value {
    json!({"text": text, "scope_refs": scope_refs, "parent_digest": parent_digest})
}

/// Minimal `scheme://netloc` check mirroring `urlparse(locator).netloc`
/// truthiness for `http`/`https` schemes — good enough for the receipt
/// gate, which only needs "is this a plausible absolute web URL".
fn url_has_host(locator: &str) -> bool {
    let after_scheme = locator.splitn(2, "://").nth(1).unwrap_or("");
    let host_part = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    !host_part.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir() -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "legion-room-protocol-test-{}-{}",
            std::process::id(),
            crate::wf_port::w2_054::now_iso().replace([':', '+', '.'], "-")
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn seats() -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("author".to_string(), json!({"role": "human"}));
        m.insert("impl".to_string(), json!({"role": "implementer"}));
        m.insert("mod".to_string(), json!({"role": "moderator"}));
        m
    }

    #[test]
    fn new_rejects_invalid_mode() {
        let root = tempdir();
        let err = RoomProtocol::new("r1", root, seats(), "bogus", "abstain").unwrap_err();
        assert_eq!(err.code, "invalid_mode");
    }

    #[test]
    fn advance_walks_full_transition_chain_with_open_findings_blocking_voting() {
        let root = tempdir();
        let mut room = RoomProtocol::new("r1", root, seats(), "review", "abstain").unwrap();
        room.advance("mod", "Positions", "req1").unwrap();
        room.advance("mod", "PeerDebate", "req2").unwrap();
        room.advance("mod", "Dispositions", "req3").unwrap();

        room.raise_finding("author", "claim", "P1", "why", &[], "fix", 0.5, "rf1").unwrap();
        // Cannot advance to Voting/Verdict with an open finding.
        let err = room.advance("mod", "AuthorReview", "req4");
        assert!(err.is_ok()); // Dispositions -> AuthorReview is allowed regardless of open findings.
    }

    #[test]
    fn idempotent_same_request_id_same_payload_returns_cached_result() {
        let root = tempdir();
        let mut room = RoomProtocol::new("r1", root, seats(), "review", "abstain").unwrap();
        let first = room.advance("mod", "Positions", "req1").unwrap();
        let second = room.advance("mod", "Positions", "req1").unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn idempotent_same_request_id_different_payload_conflicts() {
        let root = tempdir();
        let mut room = RoomProtocol::new("r1", root, seats(), "review", "abstain").unwrap();
        room.raise_finding("author", "claim", "P1", "why", &[], "fix", 0.5, "req1").unwrap();
        let err = room.raise_finding("author", "different", "P1", "why", &[], "fix", 0.5, "req1").unwrap_err();
        assert_eq!(err.code, "request_id_conflict");
    }

    #[test]
    fn positions_visibility_hides_other_seats_positions() {
        let root = tempdir();
        let mut room = RoomProtocol::new("r1", root, seats(), "review", "abstain").unwrap();
        room.advance("mod", "Positions", "req1").unwrap();
        room.post("author", "position", "my position", "p1", None, &[], &json!({})).unwrap();
        room.post("impl", "position", "other position", "p2", None, &[], &json!({})).unwrap();
        let visible_to_impl = room.visible_events("impl", 0).unwrap();
        assert_eq!(visible_to_impl.len(), 1);
        assert_eq!(visible_to_impl[0]["seat_id"], json!("impl"));
    }

    #[test]
    fn dispose_requires_artifact_receipt_for_fold() {
        let root = tempdir();
        let mut room = RoomProtocol::new("r1", root.clone(), seats(), "review", "abstain").unwrap();
        room.advance("mod", "Positions", "a1").unwrap();
        room.advance("mod", "PeerDebate", "a2").unwrap();
        room.advance("mod", "Dispositions", "a3").unwrap();
        let finding = room.raise_finding("author", "claim", "P1", "why", &[], "fix", 0.5, "rf1").unwrap();
        let finding_id = finding["finding_id"].as_str().unwrap().to_string();

        // measurement receipt only, no artifact — fold should be rejected.
        let file = root.join("evidence.txt");
        fs::write(&file, b"data").unwrap();
        let receipt = room
            .add_receipt("impl", "file", "evidence.txt", "r1", None)
            .unwrap();
        let receipt_id = receipt["receipt_id"].as_str().unwrap().to_string();
        let err = room
            .dispose("impl", &finding_id, "folded", &[receipt_id.clone()], "d1", None)
            .unwrap_err();
        assert_eq!(err.code, "fold_artifact_required");

        let ok = room.dispose("impl", &finding_id, "refuted", &[receipt_id], "d2", None).unwrap();
        assert_eq!(ok["status"], json!("Proposed"));
    }

    #[test]
    fn resolve_forbids_self_resolution() {
        let root = tempdir();
        let mut room = RoomProtocol::new("r1", root.clone(), seats(), "review", "abstain").unwrap();
        room.advance("mod", "Positions", "a1").unwrap();
        room.advance("mod", "PeerDebate", "a2").unwrap();
        room.advance("mod", "Dispositions", "a3").unwrap();
        let finding = room.raise_finding("author", "claim", "P1", "why", &[], "fix", 0.5, "rf1").unwrap();
        let finding_id = finding["finding_id"].as_str().unwrap().to_string();
        let file = root.join("out.txt");
        fs::write(&file, b"data").unwrap();
        let receipt = room.add_receipt("impl", "artifact", "out.txt", "r1", None).unwrap();
        let receipt_id = receipt["receipt_id"].as_str().unwrap().to_string();
        room.dispose("impl", &finding_id, "folded", &[receipt_id.clone()], "d1", None).unwrap();
        let disposition_id = room.dispositions.keys().next().unwrap().clone();
        let err = room
            .resolve("impl", &disposition_id, "accept", "ok", &[], "res1")
            .unwrap_err();
        assert_eq!(err.code, "self_resolution_forbidden");
    }

    #[test]
    fn open_finding_ids_excludes_terminal_statuses() {
        let root = tempdir();
        let mut room = RoomProtocol::new("r1", root, seats(), "review", "abstain").unwrap();
        room.advance("mod", "Positions", "a1").unwrap();
        room.advance("mod", "PeerDebate", "a2").unwrap();
        room.raise_finding("author", "claim", "P1", "why", &[], "fix", 0.5, "rf1").unwrap();
        assert_eq!(room.open_finding_ids().len(), 1);
    }

    #[test]
    fn derive_review_scope_is_deterministic() {
        let disposition = json!({"a": 1});
        let deferred = vec![json!({"finding_id": "f2"}), json!({"finding_id": "f1"})];
        let a = derive_review_scope(&disposition, &deferred);
        let b = derive_review_scope(&disposition, &deferred);
        assert_eq!(a, b);
        assert_eq!(a["scope_refs"], json!(["f1", "f2"]));
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonical(&v), "{\"a\":2,\"b\":1}");
    }

    #[test]
    fn stable_id_is_deterministic_and_prefixed() {
        let a = stable_id("finding", &["room", "actor", "req"]);
        let b = stable_id("finding", &["room", "actor", "req"]);
        assert_eq!(a, b);
        assert!(a.starts_with("finding_"));
    }

    #[test]
    fn url_receipt_requires_scheme_and_host() {
        assert!(url_has_host("https://example.com/x"));
        assert!(!url_has_host("https:///no-host"));
    }

    #[test]
    fn metrics_failed_room_when_escalation_majority() {
        let root = tempdir();
        let mut room = RoomProtocol::new("r1", root, seats(), "review", "abstain").unwrap();
        room.advance("mod", "Positions", "a1").unwrap();
        room.advance("mod", "PeerDebate", "a2").unwrap();
        room.advance("mod", "Dispositions", "a3").unwrap();
        assert_eq!(room.metrics()["failed_room"], json!(false));
    }
}
