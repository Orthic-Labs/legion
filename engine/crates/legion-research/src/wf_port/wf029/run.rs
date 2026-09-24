//! Full port of `src/lib/research-core/run.py`: both the pure decision
//! logic (`_default_search_provider`, `_resolve_acquire_provider`,
//! `_check_effects`, the `init_run` scale-to-budget mapping) and the
//! stateful CLI orchestrator (`init_run`, `grant`, `worker` metering,
//! `acquire`, `record_evidence`, `record_claim`, `render_draft`,
//! `issue_patch_receipt`, `apply_draft_patch`, `verify`, `finalize`, and
//! the `argparse` `main`).
//!
//! Packet r56 closes the gap this module's doc comment used to describe:
//! every dependency (`manifest.py`, `ledger.py`, `citecheck.py`,
//! `contradictions.py`, `gap_critic.py`, `domain_verify.py`,
//! `retraction.py`, `patcher.py`, `draft_integrity.py`, `effect_audit.py`,
//! `meter.py`, `patch_guard.py`, and `providers/search_open_find.py`) now
//! has a canonical Rust port elsewhere in this crate (`wf023`-`wf028`, and
//! `research_port::query` for `query.py`), so this module wires them
//! together exactly as `run.py` does. `retraction.py`'s live OpenAlex/
//! Crossref calls are backed by [`ReqwestRetractionTransport`] below (the
//! `retraction.rs` port only defines the `RetractionTransport` trait and a
//! fixture path; the real transport belongs with the first caller that
//! needs live network access, which is this orchestrator).
//!
//! Every stateful function below takes `root: Option<&Path>` exactly as
//! the underlying `manifest.rs` functions do (`None` = `manifest::
//! default_run_root()`), rather than re-deriving a `WORKSPACE` constant
//! from `file!()`, since this port is a library, not a script.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::wf_port::wf023::{citecheck, contradictions};
use crate::wf_port::wf024::{domain_verify, draft_integrity, effect_audit};
use crate::wf_port::wf025::{gap_critic, ledger, manifest};
use crate::wf_port::wf026::{meter, patch_guard, patcher};
use crate::wf_port::wf027::types::Provider;
use crate::wf_port::wf028::retraction::{self, RetractionTransport, TransportError};
use crate::wf_port::wf028::search_open_find;
use crate::wf_port::wf029::route_resolve::{self, Context};
use crate::research_port::query as query_contract;

fn field_str<'a>(route: &'a Value, key: &str) -> &'a str {
    route.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `run._default_search_provider`.
pub fn default_search_provider(route: &Value) -> String {
    let provider = field_str(route, "provider");
    if provider == "domain-default" {
        let domain = field_str(route, "domain");
        if matches!(domain, "medical" | "scientific") {
            return "scholarly".to_string();
        }
        if domain == "legal" {
            return "legal-authority".to_string();
        }
        return "browser".to_string();
    }
    provider.to_string()
}

/// `run._resolve_acquire_provider`. `requested` mirrors `str | None`.
pub fn resolve_acquire_provider(route: &Value, requested: Option<&str>) -> Result<String, String> {
    let route_provider = field_str(route, "provider").to_string();
    let mut selected = requested.map(str::to_string).unwrap_or_else(|| route_provider.clone());
    let default = default_search_provider(route);
    let mut allowed: Vec<String> = vec![route_provider.clone(), default.clone()];
    if route_provider == "domain-default" {
        allowed.push("domain-default".to_string());
    }
    if selected == "domain-default" {
        selected = default;
    }
    if !allowed.contains(&selected) {
        return Err(format!(
            "provider {selected:?} is not authorized by frozen route provider {route_provider:?}"
        ));
    }
    if selected == "notebooklm" {
        return Err(
            "NotebookLM does not expose search/open/find; answers remain leads until \
             their underlying sources are opened through an authorized provider"
                .to_string(),
        );
    }
    Ok(selected)
}

/// `run._check_effects`: raises (here, errs) listing every effect in
/// `effects` that the route's `allowed_effects` does not grant, preserving
/// the requested order (matches the Python list comprehension order, not
/// `allowed_effects`' order).
pub fn check_effects(route: &Value, effects: &[&str]) -> Result<(), String> {
    let allowed: Vec<&str> = route
        .get("allowed_effects")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let missing: Vec<&str> = effects.iter().copied().filter(|e| !allowed.contains(e)).collect();
    if !missing.is_empty() {
        return Err(format!("frozen route does not grant effects: {missing:?}"));
    }
    Ok(())
}

/// `run.init_run`'s `scale_budgets` mapping plus the `dossier` validation
/// branch. `context_budget` mirrors `context.get('budget')`: `None`/absent
/// keys behave like Python's falsy `dict.get`.
pub fn scale_budget(scale: &str, context_budget: Option<&Value>) -> Result<Value, String> {
    match scale {
        "focused" => Ok(json!({"external_requests": 12, "workers": 1})),
        "broad" => Ok(json!({"external_requests": 30, "workers": 4})),
        "dossier" => {
            let budget = context_budget.cloned().unwrap_or_else(|| json!({}));
            let external_requests = budget.get("external_requests");
            let workers = budget.get("workers");
            let requests_missing = matches!(external_requests, None | Some(Value::Null))
                || matches!(external_requests, Some(Value::Number(n)) if n.as_i64() == Some(0));
            let workers_missing = matches!(workers, None | Some(Value::Null));
            if requests_missing || workers_missing {
                return Err(
                    "dossier routes require context.budget.external_requests and context.budget.workers"
                        .to_string(),
                );
            }
            Ok(budget)
        }
        other => Err(format!("unknown scale: {other}")),
    }
}


// ---------------------------------------------------------------------
// Stateful orchestrator (packet r56): `run.py`'s `init_run` directory
// write, `grant`, `worker`, `acquire`, `record_evidence`, `record_claim`,
// `render_draft`, `issue_patch_receipt`, `apply_draft_patch`, `verify`,
// `finalize`, and the `argparse` `main`. Every function below takes
// `root: Option<&Path>` in place of the Python module's implicit
// `manifest.default_run_root()`, threaded straight through to the
// `wf025::manifest` calls it wraps.
// ---------------------------------------------------------------------

fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    let tmp = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("json"),
        std::process::id()
    ));
    fs::write(&tmp, text.as_bytes()).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

/// Faithful port of `manifest.py`'s `parse_jsonl`/`common.py` JSONL reading:
/// one JSON value per non-blank line.
fn parse_jsonl(path: &Path) -> Result<Vec<Value>, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|e| e.to_string()))
        .collect()
}

/// Port of `common.append_jsonl`: append one compact, key-sorted JSON line.
fn append_jsonl(path: &Path, value: &Value) -> Result<(), String> {
    use std::io::Write as _;
    let line = serde_json::to_string(value).map_err(|e| e.to_string())?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    writeln!(file, "{line}").map_err(|e| e.to_string())
}

/// Writes each row as its own key-sorted, non-ASCII-preserving JSON line
/// (matches `ledger_result`'s post-normalize rewrite of `evidence.jsonl`/
/// `claims.jsonl` in `verify()`). `serde_json::Value`'s `Map` is a
/// `BTreeMap` (this crate does not enable `preserve_order`), so
/// `serde_json::to_string` already sorts object keys like
/// `json.dumps(..., sort_keys=True)`.
fn write_jsonl_sorted(path: &Path, rows: &[Value]) -> Result<(), String> {
    let mut out = String::new();
    for row in rows {
        out.push_str(&serde_json::to_string(row).map_err(|e| e.to_string())?);
        out.push('\n');
    }
    fs::write(path, out.as_bytes()).map_err(|e| e.to_string())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

// -- contradictions.py / gap_critic.py output shaping (no `Serialize` on
// their result structs; these mirror the exact dict shapes those Python
// modules return, checked against `src/lib/research-core/contradictions.py`
// directly) -------------------------------------------------------------

fn scope_to_json(scope: &contradictions::Scope) -> Value {
    let mut obj = Map::new();
    for (k, v) in scope {
        obj.insert(k.clone(), json!(v));
    }
    Value::Object(obj)
}

fn contradiction_to_json(c: &contradictions::Contradiction) -> Value {
    let mut positions = Map::new();
    for (k, v) in &c.positions {
        positions.insert(k.clone(), json!(v));
    }
    json!({
        "target": c.target,
        "scope": scope_to_json(&c.scope),
        "claim_ids": c.claim_ids,
        "kind": c.kind,
        "positions": Value::Object(positions),
        "numeric_values": c.numeric_values,
        "resolution_status": c.resolution_status,
        "decision_relevance": c.decision_relevance,
    })
}

fn consensus_to_json(c: &contradictions::Consensus) -> Value {
    json!({
        "target": c.target,
        "scope": scope_to_json(&c.scope),
        "claim_ids": c.claim_ids,
        "independent_voices": c.independent_voices,
        "status": c.status,
    })
}

fn derive_to_json(r: &contradictions::DeriveResult) -> Value {
    json!({
        "contradictions": r.contradictions.iter().map(contradiction_to_json).collect::<Vec<_>>(),
        "consensus": r.consensus.iter().map(consensus_to_json).collect::<Vec<_>>(),
    })
}

// -- citecheck.py output shaping ----------------------------------------

fn sentence_row_to_json(r: &citecheck::SentenceRow) -> Value {
    json!({"index": r.index, "text": r.text})
}

fn cite_pair_to_json(p: &citecheck::CitePair) -> Value {
    let mut obj = Map::new();
    obj.insert("index".into(), json!(p.index));
    obj.insert("text".into(), json!(p.text));
    obj.insert("evidence_id".into(), json!(p.evidence_id));
    obj.insert("verdict".into(), json!(p.verdict));
    if let Some(reason) = &p.reason {
        obj.insert("reason".into(), json!(reason));
    }
    Value::Object(obj)
}

fn citecheck_to_json(r: &citecheck::CiteCheckResult) -> Value {
    json!({
        "ok": r.ok,
        "summary": {
            "pairs": r.pairs_count,
            "unbound": r.unbound_count,
            "dangling": r.dangling_count,
            "unsupported_or_partial": r.unsupported_or_partial_count,
        },
        "pairs": r.pairs.iter().map(cite_pair_to_json).collect::<Vec<_>>(),
        "unbound": r.unbound.iter().map(sentence_row_to_json).collect::<Vec<_>>(),
        "dangling": r.dangling.iter().map(cite_pair_to_json).collect::<Vec<_>>(),
        "unsupported": r.unsupported.iter().map(cite_pair_to_json).collect::<Vec<_>>(),
    })
}

// -- ledger.py `check()` output shaping ----------------------------------

fn claim_verdict_to_json(v: &ledger::ClaimVerdict) -> Value {
    match v.kind {
        "block" => json!({"id": v.id, "verdict": "block", "reasons": v.reasons}),
        "downgrade" => json!({
            "id": v.id, "verdict": "downgrade", "reason": v.reason, "from": v.from, "to": v.to,
        }),
        _ => json!({
            "id": v.id, "verdict": "ok", "confidence": v.confidence,
            "independent_clusters": v.independent_clusters,
        }),
    }
}

fn cluster_row_to_json(c: &crate::wf_port::wf025::independence::ClusterRow) -> Value {
    json!({"cluster_id": c.cluster_id, "members": c.members, "reasons": c.reasons})
}

fn ledger_check_to_json(r: &ledger::LedgerCheck) -> Value {
    json!({
        "overall_ok": r.overall_ok,
        "evidence": r.evidence,
        "claims": r.claims,
        "clusters": r.clusters.iter().map(cluster_row_to_json).collect::<Vec<_>>(),
        "evidence_verdicts": r.evidence_verdicts.iter().map(|v| json!({
            "id": v.id,
            "verdict": if v.blocked { "block" } else { "ok" },
            "reasons": v.reasons,
        })).collect::<Vec<_>>(),
        "verdicts": r.verdicts.iter().map(claim_verdict_to_json).collect::<Vec<_>>(),
    })
}

// -- retraction.py's live OpenAlex/Crossref transport --------------------

/// Percent-encodes like Python's `urllib.parse.quote(value, safe=safe)`:
/// unreserved characters (`A-Za-z0-9_.-~`) plus everything in `safe` pass
/// through untouched; everything else becomes `%XX` (byte-wise, so
/// multi-byte UTF-8 sequences encode correctly).
fn percent_encode(value: &str, safe: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || "_.-~".contains(ch) || (byte < 128 && safe.contains(ch)) {
            out.push(ch);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// Real transport for `retraction.py`'s `_openalex`/`_crossref`, backed by
/// `reqwest`'s blocking client (already a dependency of this crate via
/// `wf027::http_browser::ReqwestTransport`). `retraction.rs` (wf028) ports
/// only the `RetractionTransport` trait and the pure `sweep`/`check_doi`
/// logic against it; this is the first caller that needs live network
/// access, so the real transport is wired here.
pub struct ReqwestRetractionTransport {
    client: reqwest::blocking::Client,
    user_agent: String,
}

impl Default for ReqwestRetractionTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestRetractionTransport {
    pub fn new() -> Self {
        let contact = std::env::var("RESEARCH_CONTACT_EMAIL").ok().filter(|s| !s.is_empty());
        let user_agent = match contact {
            Some(email) => format!("ResearchCore/2.0 (mailto:{email})"),
            None => "ResearchCore/2.0".to_string(),
        };
        Self { client: reqwest::blocking::Client::new(), user_agent }
    }

    fn fetch_json(&self, url: &str) -> Result<Value, TransportError> {
        let resp = self
            .client
            .get(url)
            .timeout(std::time::Duration::from_secs(25))
            .header("User-Agent", self.user_agent.as_str())
            .header("Accept", "application/json")
            .send()
            .map_err(|e| TransportError(e.to_string()))?;
        let text = resp.text().map_err(|e| TransportError(e.to_string()))?;
        serde_json::from_str(&text).map_err(|e| TransportError(e.to_string()))
    }
}

impl RetractionTransport for ReqwestRetractionTransport {
    fn openalex(&self, doi: &str) -> Result<Value, TransportError> {
        let encoded = percent_encode(&format!("https://doi.org/{doi}"), ":/");
        self.fetch_json(&format!("https://api.openalex.org/works/{encoded}"))
    }

    fn crossref(&self, doi: &str) -> Result<Value, TransportError> {
        let encoded = percent_encode(doi, "");
        self.fetch_json(&format!("https://api.crossref.org/works/{encoded}"))
    }
}

/// Port of `retraction.py`'s `RESEARCH_RETRACTION_FIXTURE` env-var escape
/// hatch, read here (a library has no business reading `os.environ`
/// implicitly, but this preserves the CLI-visible behaviour in [`run`]).
fn load_retraction_fixture() -> Option<Map<String, Value>> {
    let path = std::env::var("RESEARCH_RETRACTION_FIXTURE").ok()?;
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&text).ok()?.as_object().cloned()
}

// -- orchestrator functions ----------------------------------------------

fn require_granted(run_id: &str, effects: &[&str], root: Option<&Path>) -> Result<Value, String> {
    let run = manifest::load_run(run_id, root).map_err(|e| e.to_string())?;
    let route = run.get("route").cloned().unwrap_or_else(|| json!({}));
    let granted = route
        .get("allowed_effects")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if !granted {
        return Err("route effects have not been granted".to_string());
    }
    check_effects(&route, effects)?;
    Ok(run)
}

/// `run.init_run`: resolves the route, computes the budget, creates the
/// run directory, persists the query/wrapper-contract and `route.json`.
pub fn init_run(intent: &str, context: &Context, root: Option<&Path>) -> Result<Value, String> {
    let route = route_resolve::resolve(intent, context)?;
    let scale = route.get("scale").and_then(Value::as_str).unwrap_or("");
    let budget = scale_budget(scale, context.get("budget"))?;
    let run = manifest::create_run(intent, &route, &budget, root).map_err(|e| e.to_string())?;
    let run_id = run.get("run_id").and_then(Value::as_str).unwrap_or("").to_string();
    let directory = manifest::run_dir(&run_id, root).map_err(|e| e.to_string())?;
    let wrapper_contract = context.get("wrapper_contract").and_then(Value::as_str);
    query_contract::persist(&directory, intent, wrapper_contract).map_err(|e| e.to_string())?;
    write_json(&directory.join("route.json"), &route)?;
    let verdicts = route_resolve::gate_verdicts(&route, None);
    Ok(json!({"run": run, "route": route, "gate_verdicts": verdicts}))
}

/// `run.grant`.
pub fn grant(run_id: &str, root: Option<&Path>) -> Result<Value, String> {
    let run = manifest::load_run(run_id, root).map_err(|e| e.to_string())?;
    let route = run.get("route").cloned().unwrap_or_else(|| json!({}));
    let approvals = run.get("approvals").and_then(Value::as_object);
    let (granted, verdicts) = route_resolve::grant_effects(&route, approvals)?;
    let allowed_empty = granted
        .get("allowed_effects")
        .and_then(Value::as_array)
        .map(|a| a.is_empty())
        .unwrap_or(true);
    if allowed_empty {
        let pending: Vec<String> = verdicts
            .iter()
            .filter(|v| v.get("verdict").and_then(Value::as_str) != Some("ok"))
            .filter_map(|v| v.get("gate").and_then(Value::as_str).map(String::from))
            .collect();
        let detail = if pending.is_empty() { "route-gate".to_string() } else { pending.join(",") };
        manifest::set_stage(run_id, "route", "blocked", Some(&detail), root).map_err(|e| e.to_string())?;
        return Ok(json!({"ready": false, "route": granted, "gate_verdicts": verdicts, "pending": pending}));
    }
    let route_sha = manifest::sha256_text(&serde_json::to_string(&granted).map_err(|e| e.to_string())?);
    let granted_for_mutate = granted.clone();
    manifest::mutate_run(run_id, root, move |m| {
        m["route"] = granted_for_mutate;
        m["route_sha256"] = json!(route_sha);
        m["stages"]["route"]["status"] = json!("done");
        m["blocked_on"] = json!([]);
        m["status"] = json!("running");
    })
    .map_err(|e| e.to_string())?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    write_json(&directory.join("route.json"), &granted)?;
    manifest::record_event(
        run_id,
        "route.effects-granted",
        Some(&json!({"effects": granted.get("allowed_effects").cloned().unwrap_or(json!([]))})),
        root,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({"ready": true, "route": granted, "gate_verdicts": verdicts}))
}

/// `run.meter_worker`.
pub fn meter_worker(run_id: &str, event: &str, units: i64, root: Option<&Path>) -> Result<Value, String> {
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    meter::consume(&directory, "worker", units, Some(event)).map_err(|e| e.to_string())
}

/// `run.acquire`.
pub fn acquire(
    run_id: &str,
    query: &str,
    provider_name: Option<&str>,
    corpus: Option<&str>,
    pattern: Option<&str>,
    limit: usize,
    root: Option<&Path>,
) -> Result<Value, String> {
    let run = require_granted(run_id, &["search", "extract"], root)?;
    let route = run.get("route").cloned().unwrap_or_else(|| json!({}));
    let name = resolve_acquire_provider(&route, provider_name)?;
    let provider_impl = search_open_find::provider(&name, corpus).map_err(|e| e.to_string())?;
    let parsed = search_open_find::ProviderName::parse(&name);
    if name == "local-corpus" {
        check_effects(&route, &["read-local"])?;
    }
    let search_metered = parsed.map(|p| search_open_find::is_metered_op(p, "search")).unwrap_or(false);
    let open_metered = parsed.map(|p| search_open_find::is_metered_op(p, "open")).unwrap_or(false);
    let find_metered = parsed.map(|p| search_open_find::is_metered_op(p, "find")).unwrap_or(false);
    if open_metered {
        check_effects(&route, &["fetch"])?;
    }
    manifest::set_stage(run_id, "acquire", "running", None, root).map_err(|e| e.to_string())?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    if search_metered {
        search_open_find::meter_effect(Some(&directory), "external_request").map_err(|e| e.to_string())?;
    }
    let seed_chain: Vec<String> = Vec::new();
    let hits = provider_impl.search(query, limit, &seed_chain).map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    for hit in &hits {
        if open_metered {
            search_open_find::meter_effect(Some(&directory), "external_request").map_err(|e| e.to_string())?;
        }
        let opened = provider_impl.open(&hit.url).map_err(|e| e.to_string())?;
        if find_metered {
            search_open_find::meter_effect(Some(&directory), "external_request").map_err(|e| e.to_string())?;
        }
        let find_pattern = match pattern {
            Some(p) if !p.is_empty() => p,
            _ => query,
        };
        let located = provider_impl.find(&opened, find_pattern).map_err(|e| e.to_string())?;
        rows.push(json!({
            "hit": hit.to_dict(),
            "opened": opened.to_dict(),
            "located": located.map(|l| l.to_dict()),
        }));
    }
    write_json(&directory.join("acquisition.json"), &Value::Array(rows.clone()))?;
    manifest::attach_artifact(
        run_id,
        "acquisition",
        directory.join("acquisition.json").to_string_lossy().as_ref(),
        None,
        root,
    )
    .map_err(|e| e.to_string())?;
    manifest::set_stage(run_id, "acquire", "done", None, root).map_err(|e| e.to_string())?;
    Ok(json!({"provider": name, "results": rows}))
}

/// `run.record_evidence`.
pub fn record_evidence(run_id: &str, row: Value, root: Option<&Path>) -> Result<Value, String> {
    require_granted(run_id, &["extract"], root)?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    let path = directory.join("evidence.jsonl");
    let existing = if path.exists() { parse_jsonl(&path)? } else { Vec::new() };
    let row_id = row.get("id").map(value_to_string).unwrap_or_default();
    if existing.iter().any(|item| item.get("id").map(value_to_string).unwrap_or_default() == row_id) {
        return Err(format!("duplicate evidence id: {row_id:?}"));
    }
    let verdict = &ledger::validate_evidence(std::slice::from_ref(&row))[0];
    if verdict.blocked {
        return Err(format!("evidence record blocked: {:?}", verdict.reasons));
    }
    append_jsonl(&path, &row)?;
    let sha = sha256_file(&path)?;
    manifest::attach_artifact(run_id, "evidence-ledger", path.to_string_lossy().as_ref(), Some(&sha), root)
        .map_err(|e| e.to_string())?;
    Ok(row)
}

/// `run.record_claim`.
pub fn record_claim(run_id: &str, row: Value, root: Option<&Path>) -> Result<Value, String> {
    require_granted(run_id, &["synthesize"], root)?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    let path = directory.join("claims.jsonl");
    let existing = if path.exists() { parse_jsonl(&path)? } else { Vec::new() };
    let row_id = row.get("id").map(value_to_string).unwrap_or_default();
    if existing.iter().any(|item| item.get("id").map(value_to_string).unwrap_or_default() == row_id) {
        return Err(format!("duplicate claim id: {row_id:?}"));
    }
    let evidence_path = directory.join("evidence.jsonl");
    let evidence = if evidence_path.exists() { parse_jsonl(&evidence_path)? } else { Vec::new() };
    let mut claims_input = existing;
    claims_input.push(row.clone());
    let result = ledger::check(&evidence, &claims_input);
    let blocked: Vec<&ledger::ClaimVerdict> =
        result.verdicts.iter().filter(|v| v.id == row_id && v.kind == "block").collect();
    if !blocked.is_empty() {
        let reasons: Vec<&Vec<String>> = blocked.iter().map(|v| &v.reasons).collect();
        return Err(format!("claim record blocked: {reasons:?}"));
    }
    let normalized = result
        .claims
        .iter()
        .find(|item| item.get("id").map(value_to_string).unwrap_or_default() == row_id)
        .cloned()
        .ok_or_else(|| "normalized claim missing from ledger.check output".to_string())?;
    append_jsonl(&path, &normalized)?;
    let sha = sha256_file(&path)?;
    manifest::attach_artifact(run_id, "claim-ledger", path.to_string_lossy().as_ref(), Some(&sha), root)
        .map_err(|e| e.to_string())?;
    Ok(normalized)
}

/// `run.render_draft`.
pub fn render_draft(run_id: &str, title: &str, root: Option<&Path>) -> Result<Value, String> {
    require_granted(run_id, &["synthesize", "write-output"], root)?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    let evidence_path = directory.join("evidence.jsonl");
    let claims_path = directory.join("claims.jsonl");
    let evidence = if evidence_path.exists() { parse_jsonl(&evidence_path)? } else { Vec::new() };
    let claims = if claims_path.exists() { parse_jsonl(&claims_path)? } else { Vec::new() };
    let draft = ledger::render(&evidence, &claims, title)?;
    let path = directory.join("draft.md");
    fs::write(&path, draft.as_bytes()).map_err(|e| e.to_string())?;
    manifest::set_stage(run_id, "synthesize", "done", None, root).map_err(|e| e.to_string())?;
    let sha = sha256_file(&path)?;
    manifest::attach_artifact(run_id, "sourced-draft", path.to_string_lossy().as_ref(), Some(&sha), root)
        .map_err(|e| e.to_string())?;
    Ok(json!({"path": path.to_string_lossy(), "sha256": sha}))
}

/// `run.issue_patch_receipt`.
pub fn issue_patch_receipt(run_id: &str, key_file: Option<&str>, root: Option<&Path>) -> Result<Value, String> {
    require_granted(run_id, &["patch-sourced-draft"], root)?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    let draft = directory.join("draft.md");
    if !draft.exists() {
        return Err("draft.md does not exist".to_string());
    }
    let key_path = key_file.map(Path::new);
    let receipt = patch_guard::issue_receipt(&draft, run_id, key_path).map_err(|e| e.to_string())?;
    let path = directory.join("patch-receipt.json");
    write_json(&path, &receipt)?;
    let sha = sha256_file(&path)?;
    manifest::attach_artifact(run_id, "patch-receipt", path.to_string_lossy().as_ref(), Some(&sha), root)
        .map_err(|e| e.to_string())?;
    Ok(receipt)
}

/// `run.apply_draft_patch`.
pub fn apply_draft_patch(
    run_id: &str,
    diff_path: &str,
    key_file: Option<&str>,
    root: Option<&Path>,
) -> Result<Value, String> {
    require_granted(run_id, &["patch-sourced-draft"], root)?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    let source_path = directory.join("draft.md");
    let receipt_path = directory.join("patch-receipt.json");
    let receipt = read_json(&receipt_path)?;
    let source_bytes = fs::read(&source_path).map_err(|e| e.to_string())?;
    let key_path = key_file.map(Path::new);
    let (ok, reason) = patcher::validate_correction_receipt(&receipt, Some(&source_bytes), key_path);
    if !ok {
        return Err(reason);
    }
    let diff = fs::read_to_string(diff_path).map_err(|e| e.to_string())?;
    let source_text = String::from_utf8(source_bytes).map_err(|e| e.to_string())?;
    let max_hunks = receipt.get("max_hunks").and_then(Value::as_u64).unwrap_or(patcher::DEFAULT_MAX_HUNKS as u64) as u32;
    let max_hunk_bytes = receipt
        .get("max_hunk_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(patcher::DEFAULT_MAX_HUNK_BYTES as u64) as u32;
    let result = patcher::apply_patch(&source_text, &diff, max_hunks, max_hunk_bytes);
    if !result.ok {
        manifest::set_stage(run_id, "patch", "failed", result.reason.as_deref(), root).map_err(|e| e.to_string())?;
        return Ok(result.to_json(true));
    }
    let output = result.output.clone().unwrap_or_default();
    fs::write(&source_path, output.as_bytes()).map_err(|e| e.to_string())?;
    let saved_diff = directory.join("applied.patch");
    fs::write(&saved_diff, diff.as_bytes()).map_err(|e| e.to_string())?;
    manifest::set_stage(run_id, "patch", "done", None, root).map_err(|e| e.to_string())?;
    let diff_sha = sha256_file(&saved_diff)?;
    manifest::attach_artifact(run_id, "patch-diff", saved_diff.to_string_lossy().as_ref(), Some(&diff_sha), root)
        .map_err(|e| e.to_string())?;
    let src_sha = sha256_file(&source_path)?;
    manifest::attach_artifact(run_id, "patched-draft", source_path.to_string_lossy().as_ref(), Some(&src_sha), root)
        .map_err(|e| e.to_string())?;
    Ok(result.to_json(false))
}

/// `run.verify`.
pub fn verify(run_id: &str, allow_unknown_retractions: bool, root: Option<&Path>) -> Result<Value, String> {
    let run = require_granted(run_id, &[], root)?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    let route = run.get("route").cloned().unwrap_or_else(|| json!({}));
    let evidence_path = directory.join("evidence.jsonl");
    let claims_path = directory.join("claims.jsonl");
    let draft_path = directory.join("draft.md");
    for (path, name) in [
        (&evidence_path, "evidence.jsonl"),
        (&claims_path, "claims.jsonl"),
        (&draft_path, "draft.md"),
    ] {
        if !path.exists() {
            return Err(format!("missing required run artifact: {name}"));
        }
    }
    let mut evidence = parse_jsonl(&evidence_path)?;
    let mut claims = parse_jsonl(&claims_path)?;

    manifest::set_stage(run_id, "normalize", "running", None, root).map_err(|e| e.to_string())?;
    let ledger_result = ledger::check(&evidence, &claims);
    let ledger_json = ledger_check_to_json(&ledger_result);
    write_json(&directory.join("ledger-check.json"), &ledger_json)?;
    if !ledger_result.overall_ok {
        manifest::set_stage(run_id, "normalize", "failed", Some("ledger-block"), root).map_err(|e| e.to_string())?;
        return Ok(json!({"ok": false, "stage": "ledger", "ledger": ledger_json}));
    }
    evidence = ledger_result.evidence.clone();
    claims = ledger_result.claims.clone();
    write_jsonl_sorted(&evidence_path, &evidence)?;
    write_jsonl_sorted(&claims_path, &claims)?;
    manifest::set_stage(run_id, "normalize", "done", None, root).map_err(|e| e.to_string())?;

    manifest::set_stage(run_id, "challenge", "running", None, root).map_err(|e| e.to_string())?;
    let views = contradictions::derive(&claims, &evidence);
    let views_json = derive_to_json(&views);
    write_json(&directory.join("contradictions.json"), &views_json)?;
    let assurance = route.get("assurance").and_then(Value::as_str).unwrap_or("");
    let gap = if assurance == "verified" {
        gap_critic::review_to_json(&claims, &evidence, Some(&views_json))
    } else {
        json!({"complete": true, "findings": [], "targeted_queries": []})
    };
    write_json(&directory.join("gap-review.json"), &gap)?;
    let gap_complete = gap.get("complete").and_then(Value::as_bool).unwrap_or(false);
    manifest::set_stage(
        run_id,
        "challenge",
        if gap_complete { "done" } else { "blocked" },
        if gap_complete { None } else { Some("gap-fetch-required") },
        root,
    )
    .map_err(|e| e.to_string())?;

    let domain = domain_verify::verify(&route, &evidence, &claims);
    write_json(&directory.join("domain-verification.json"), &domain)?;

    let citations = if matches!(assurance, "standard" | "verified") {
        check_effects(&route, &["citecheck"])?;
        manifest::set_stage(run_id, "citecheck", "running", None, root).map_err(|e| e.to_string())?;
        let draft_text = fs::read_to_string(&draft_path).map_err(|e| e.to_string())?;
        let cc = citecheck::check(&draft_text, &evidence);
        let cc_json = citecheck_to_json(&cc);
        write_json(&directory.join("citation-binding.json"), &cc_json)?;
        manifest::set_stage(
            run_id,
            "citecheck",
            if cc.ok { "done" } else { "failed" },
            if cc.ok { None } else { Some("citation-binding") },
            root,
        )
        .map_err(|e| e.to_string())?;
        cc_json
    } else {
        let cc_json = json!({
            "ok": true,
            "skipped": true,
            "reason": "citecheck not granted for quick assurance",
            "summary": {"pairs": 0, "unbound": 0, "dangling": 0, "unsupported_or_partial": 0},
            "pairs": [], "unbound": [], "dangling": [], "unsupported": [],
        });
        write_json(&directory.join("citation-binding.json"), &cc_json)?;
        manifest::set_stage(run_id, "citecheck", "skipped", Some("quick-assurance"), root)
            .map_err(|e| e.to_string())?;
        cc_json
    };

    let mut retract = json!({"dois_checked": 0, "results": [], "block_brief": false, "unknown_count": 0});
    if assurance == "verified" {
        check_effects(&route, &["retraction-check", "patch-sourced-draft"])?;
        manifest::set_stage(run_id, "retraction", "running", None, root).map_err(|e| e.to_string())?;
        let dois: Vec<String> =
            evidence.iter().filter_map(|e| e.get("doi").and_then(Value::as_str).map(String::from)).collect();
        if !dois.is_empty() {
            let disclosed: Vec<String> = evidence
                .iter()
                .filter(|e| e.get("doi").is_some() && e.get("retraction_disclosed").map(is_truthy).unwrap_or(false))
                .filter_map(|e| e.get("doi").and_then(Value::as_str).map(String::from))
                .collect();
            let transport = ReqwestRetractionTransport::new();
            let fixture = load_retraction_fixture();
            retract = retraction::sweep(&transport, &dois, &disclosed, !allow_unknown_retractions, fixture.as_ref());
        }
        write_json(&directory.join("retraction.json"), &retract)?;
        let block_brief = retract.get("block_brief").and_then(Value::as_bool).unwrap_or(false);
        manifest::set_stage(
            run_id,
            "retraction",
            if !block_brief { "done" } else { "failed" },
            if !block_brief { None } else { Some("retraction") },
            root,
        )
        .map_err(|e| e.to_string())?;
    } else {
        manifest::set_stage(run_id, "retraction", "skipped", None, root).map_err(|e| e.to_string())?;
    }

    if assurance != "verified" {
        manifest::set_stage(run_id, "patch", "skipped", None, root).map_err(|e| e.to_string())?;
    } else if directory.join("applied.patch").exists() {
        manifest::set_stage(run_id, "patch", "done", None, root).map_err(|e| e.to_string())?;
    } else {
        manifest::set_stage(run_id, "patch", "skipped", Some("no correction requested"), root)
            .map_err(|e| e.to_string())?;
    }

    let manifest_now = manifest::load_run(run_id, root).map_err(|e| e.to_string())?;
    let integrity = draft_integrity::check(&directory, &manifest_now);
    let events = effect_audit::read_events(&directory.join("events.jsonl")).map_err(|e| e.to_string())?;
    let effects = effect_audit::audit(&manifest_now, &events);
    write_json(&directory.join("draft-integrity.json"), &integrity)?;
    write_json(&directory.join("effect-audit.json"), &effects)?;

    let checks = json!({
        "ledger": ledger_result.overall_ok,
        "domain": domain.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "citations": citations.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "retraction": !retract.get("block_brief").and_then(Value::as_bool).unwrap_or(false),
        "gaps_complete": gap_complete,
        "draft_integrity": integrity.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "effect_accounting": effects.get("ok").and_then(Value::as_bool).unwrap_or(false),
    });
    let ok = checks.as_object().unwrap().values().all(|v| v.as_bool().unwrap_or(false));
    write_json(&directory.join("ship-checks.json"), &checks)?;
    for name in [
        "ledger-check", "contradictions", "gap-review", "domain-verification", "citation-binding",
        "retraction", "draft-integrity", "effect-audit", "ship-checks",
    ] {
        let p = directory.join(format!("{name}.json"));
        if p.exists() {
            let sha = sha256_file(&p)?;
            manifest::attach_artifact(run_id, name, p.to_string_lossy().as_ref(), Some(&sha), root)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(json!({
        "ok": ok,
        "checks": checks,
        "ledger": ledger_json,
        "domain": domain,
        "citations": citations,
        "retraction": retract,
        "gap": gap,
        "draft_integrity": integrity,
        "effect_audit": effects,
    }))
}

/// `run.finalize`.
pub fn finalize(run_id: &str, root: Option<&Path>) -> Result<Value, String> {
    require_granted(run_id, &["write-output"], root)?;
    let directory = manifest::run_dir(run_id, root).map_err(|e| e.to_string())?;
    let mut checks = read_json(&directory.join("ship-checks.json"))?;
    let manifest_now = manifest::load_run(run_id, root).map_err(|e| e.to_string())?;
    let integrity = draft_integrity::check(&directory, &manifest_now);
    let events = effect_audit::read_events(&directory.join("events.jsonl")).map_err(|e| e.to_string())?;
    let effects = effect_audit::audit(&manifest_now, &events);
    write_json(&directory.join("draft-integrity.json"), &integrity)?;
    write_json(&directory.join("effect-audit.json"), &effects)?;
    checks["draft_integrity"] = json!(integrity.get("ok").and_then(Value::as_bool).unwrap_or(false));
    checks["effect_accounting"] = json!(effects.get("ok").and_then(Value::as_bool).unwrap_or(false));
    write_json(&directory.join("ship-checks.json"), &checks)?;
    let ok = checks.as_object().unwrap().values().all(|v| v.as_bool().unwrap_or(false));
    let verdict = if ok { "ship" } else { "block" };
    manifest::set_stage(run_id, "ship", if ok { "done" } else { "blocked" }, if ok { None } else { Some("ship-gate") }, root)
        .map_err(|e| e.to_string())?;
    manifest::finalize(run_id, verdict, &checks, root).map_err(|e| e.to_string())
}


// -- CLI entrypoint (`run.py`'s `argparse` `main`) ------------------------

fn cli_err(msg: impl std::fmt::Display) -> String {
    format!("error: {msg}")
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Port of `run.py`'s `main(argv)`: parses the same subcommands
/// (`init`/`approve`/`grant`/`worker`/`acquire`/`record-evidence`/
/// `record-claim`/`render`/`issue-patch`/`apply-patch`/`verify`/
/// `finalize`), dispatches to the functions above, and prints the result
/// as pretty JSON — matching `json.dumps(result, indent=2, sort_keys=True)`
/// and the same exit-code rule (`0` on `ok`/`ready` truthy or
/// `verdict == 'ship'`, else `2`, and `1` on any raised error, mirrored
/// here as a `Result::Err` before printing).
pub fn run(argv: &[String]) -> i32 {
    if argv.is_empty() {
        eprintln!("error: a subcommand is required");
        return 2;
    }
    let cmd = argv[0].as_str();
    let rest = &argv[1..];
    let root: Option<&Path> = None;

    let outcome: Result<Value, String> = (|| match cmd {
        "init" => {
            let intent = flag(rest, "--intent").ok_or_else(|| cli_err("--intent is required"))?;
            let context: Context = match flag(rest, "--context") {
                Some(path) => read_json(Path::new(path))?.as_object().cloned().unwrap_or_default(),
                None => Context::new(),
            };
            init_run(intent, &context, root)
        }
        "approve" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            let gate = flag(rest, "--gate").ok_or_else(|| cli_err("--gate is required"))?;
            let text = flag(rest, "--text").ok_or_else(|| cli_err("--text is required"))?;
            manifest::approve(run_id, gate, text, "user", root).map_err(|e| e.to_string())
        }
        "grant" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            grant(run_id, root)
        }
        "worker" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            let event = flag(rest, "--event").ok_or_else(|| cli_err("--event is required"))?;
            let units: i64 = flag(rest, "--units").and_then(|s| s.parse().ok()).unwrap_or(1);
            meter_worker(run_id, event, units, root)
        }
        "acquire" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            let query = flag(rest, "--query").ok_or_else(|| cli_err("--query is required"))?;
            let limit: usize = flag(rest, "--limit").and_then(|s| s.parse().ok()).unwrap_or(5);
            acquire(run_id, query, flag(rest, "--provider"), flag(rest, "--corpus"), flag(rest, "--pattern"), limit, root)
        }
        "record-evidence" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            let record = flag(rest, "--record").ok_or_else(|| cli_err("--record is required"))?;
            record_evidence(run_id, read_json(Path::new(record))?, root)
        }
        "record-claim" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            let record = flag(rest, "--record").ok_or_else(|| cli_err("--record is required"))?;
            record_claim(run_id, read_json(Path::new(record))?, root)
        }
        "render" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            let title = flag(rest, "--title").unwrap_or("Research brief");
            render_draft(run_id, title, root)
        }
        "issue-patch" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            issue_patch_receipt(run_id, flag(rest, "--key-file"), root)
        }
        "apply-patch" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            let diff = flag(rest, "--diff").ok_or_else(|| cli_err("--diff is required"))?;
            apply_draft_patch(run_id, diff, flag(rest, "--key-file"), root)
        }
        "verify" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            verify(run_id, has_flag(rest, "--allow-unknown-retractions"), root)
        }
        "finalize" => {
            let run_id = flag(rest, "--run-id").ok_or_else(|| cli_err("--run-id is required"))?;
            finalize(run_id, root)
        }
        other => Err(cli_err(format!("unknown subcommand: {other}"))),
    })();

    match outcome {
        Ok(result) => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
            // Port of `return 0 if result.get('ok', True) or result.get('verdict')
            // == 'ship' else 2`: a missing `ok` key defaults truthy (matching the
            // Python `dict.get(..., True)` default), including for results like
            // `grant`'s `{'ready': False, ...}` that carry no `ok` key at all.
            let ok = result.get("ok").map(is_truthy).unwrap_or(true);
            let ship = result.get("verdict").and_then(Value::as_str) == Some("ship");
            if ok || ship { 0 } else { 2 }
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(provider: &str, domain: &str) -> Value {
        json!({"provider": provider, "domain": domain, "allowed_effects": ["search", "extract"]})
    }

    #[test]
    fn default_search_provider_maps_domain_default_by_domain() {
        assert_eq!(default_search_provider(&route("domain-default", "medical")), "scholarly");
        assert_eq!(default_search_provider(&route("domain-default", "scientific")), "scholarly");
        assert_eq!(default_search_provider(&route("domain-default", "legal")), "legal-authority");
        assert_eq!(default_search_provider(&route("domain-default", "general")), "browser");
        assert_eq!(default_search_provider(&route("browser", "general")), "browser");
    }

    #[test]
    fn resolve_acquire_provider_rejects_unauthorized_and_notebooklm() {
        let r = route("browser", "general");
        assert_eq!(resolve_acquire_provider(&r, None).unwrap(), "browser");
        assert!(resolve_acquire_provider(&r, Some("local-corpus")).is_err());

        let notebooklm_route = route("notebooklm", "general");
        let err = resolve_acquire_provider(&notebooklm_route, None).unwrap_err();
        assert!(err.contains("NotebookLM does not expose"));
    }

    #[test]
    fn resolve_acquire_provider_domain_default_resolves_to_concrete_provider() {
        let r = route("domain-default", "legal");
        assert_eq!(resolve_acquire_provider(&r, None).unwrap(), "legal-authority");
        assert_eq!(resolve_acquire_provider(&r, Some("domain-default")).unwrap(), "legal-authority");
    }

    #[test]
    fn check_effects_lists_missing_in_requested_order() {
        let r = route("browser", "general");
        let err = check_effects(&r, &["fetch", "search", "citecheck"]).unwrap_err();
        assert!(err.contains(r#"["fetch", "citecheck"]"#), "{err}");
        assert!(check_effects(&r, &["search", "extract"]).is_ok());
    }

    #[test]
    fn scale_budget_dossier_requires_explicit_budget() {
        assert_eq!(scale_budget("focused", None).unwrap(), json!({"external_requests": 12, "workers": 1}));
        assert_eq!(scale_budget("broad", None).unwrap(), json!({"external_requests": 30, "workers": 4}));
        assert!(scale_budget("dossier", None).is_err());
        let budget = json!({"external_requests": 50, "workers": 2});
        assert_eq!(scale_budget("dossier", Some(&budget)).unwrap(), budget);
        let zero_requests = json!({"external_requests": 0, "workers": 2});
        assert!(scale_budget("dossier", Some(&zero_requests)).is_err());
    }
}
