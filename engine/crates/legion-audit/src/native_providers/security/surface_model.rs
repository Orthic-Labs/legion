//! `security.surface-model`: a deterministic, revision-bound security surface
//! model (`security-model.json`) derived from frozen inventory bytes and an
//! optional graph context.
//!
//! The model gives later security providers one shared vocabulary of
//! entrypoints, assets/crown jewels, actors/principals/identities, trust
//! boundaries, controls and typed relations. Design rules:
//!
//! * **Detector proposes, never establishes.** Nothing here is ever
//!   `verified`; strength is `possible` or `strong-inference` only, and every
//!   entity carries an `observed` / `inferred` / `assumed` assertion label.
//! * **Evidence or nothing.** Every observed entity and relation cites path,
//!   line range, source digest and the inventory digest. Entities that exist
//!   only because another entity exists (actors, trust boundaries) are labelled
//!   `assumed` and cite the entrypoint evidence that implies them.
//! * **Fail closed.** Unsupported frameworks, missing/mismatched bytes,
//!   absent or unbound graph context, truncation and unbound plans become
//!   explicit gaps. A domain is `applicable` only with cited evidence (SEC
//!   section 6.7); otherwise it is `not-evidenced`, never silently clean.
//! * **No secrets stored.** Secret-bearing locations are recorded by name and
//!   path only; line content is never copied into the model.
//! * No model calls, no execution, no network, no filesystem access: inputs are
//!   the frozen bytes the caller supplies.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::graph_context::{scoped_bytes_digest, GraphContext};
use crate::inventory::InventoryEnvelope;
use crate::source_cache::bytes_digest;

pub const PROVIDER_ID: &str = "security.surface-model";
pub const MODEL_KIND: &str = "legion-security-model";
pub const SCHEMA_VERSION: &str = "1.0.0";

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_LINE_CHARS: usize = 2000;
const MAX_ENTITIES: usize = 4000;
const MAX_RELATIONS: usize = 8000;
const MAX_GRAPH_DEPTH: usize = 4;
const MAX_GAP_PATHS: usize = 50;
const GUARD_WINDOW: usize = 3;

/// Strength labels (registry `evidenceStrength`). `verified` is never produced.
const POSSIBLE: &str = "possible";
const STRONG: &str = "strong-inference";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRef {
    pub id: String,
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
    pub source_digest: String,
    pub inventory_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelEntity {
    pub id: String,
    /// Registry `entityKind`.
    pub kind: String,
    /// Detector-local refinement, e.g. `http-route`, `secret`, `tauri-command`.
    pub subkind: String,
    pub name: String,
    /// `observed` | `inferred` | `assumed`.
    pub assertion: String,
    /// Registry `evidenceStrength` (`possible` | `strong-inference`).
    pub evidence_strength: String,
    pub evidence_refs: Vec<String>,
    pub provider: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRelation {
    pub id: String,
    /// Registry `relationKind`.
    pub kind: String,
    pub from: String,
    pub to: String,
    pub assertion: String,
    pub evidence_strength: String,
    pub evidence_refs: Vec<String>,
    pub provider: String,
    /// `inventory-bytes` | `graph-context`.
    pub origin: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Denominator {
    pub kind: String,
    pub count: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainApplicability {
    pub domain_id: String,
    /// `applicable` only with cited evidence; otherwise `not-evidenced`.
    pub status: String,
    pub selected_because: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub denominator: Denominator,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelGap {
    pub id: String,
    pub kind: String,
    pub reason: String,
    /// A blocking gap means the model cannot support a clean/complete claim.
    pub blocking: bool,
    pub path_count: u64,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphBinding {
    pub contract_version: String,
    pub scoped_bytes_digest: String,
    pub coverage_floor: String,
    pub freshness: String,
    pub truncated: bool,
    /// Whether edges were admitted into the model.
    pub used: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelBinding {
    pub repository_id: String,
    pub repository_revision: String,
    pub inventory_digest: String,
    pub inventory_generation: String,
    pub inventory_schema_version: u32,
    pub scoped_bytes_digest: String,
    pub plan_digest: Option<String>,
    pub cortex_generation_id: Option<String>,
    pub plan_bound: bool,
    pub graph: Option<GraphBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelCoverage {
    pub inventory_entries: u64,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub truncated: bool,
    /// True only when no blocking gap exists. Never a claim of "no attack surface".
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityModel {
    pub schema_version: String,
    pub kind: String,
    pub provider: String,
    pub binding: ModelBinding,
    pub entities: Vec<ModelEntity>,
    pub relations: Vec<ModelRelation>,
    pub evidence: Vec<EvidenceRef>,
    pub applicability: Vec<DomainApplicability>,
    pub gaps: Vec<ModelGap>,
    pub coverage: ModelCoverage,
    pub digest: String,
}

impl SecurityModel {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("security model serialization is infallible")
    }

    pub fn entities_of(&self, kind: &str, subkind: &str) -> Vec<&ModelEntity> {
        self.entities
            .iter()
            .filter(|e| e.kind == kind && e.subkind == subkind)
            .collect()
    }

    pub fn has_blocking_gap(&self) -> bool {
        self.gaps.iter().any(|g| g.blocking)
    }
}

/// Inputs. `files` are the frozen bytes keyed by repository-relative path; any
/// inventory entry without bytes (or whose digest disagrees) becomes a gap.
pub struct SurfaceModelInput<'a> {
    pub inventory: &'a InventoryEnvelope,
    pub files: &'a BTreeMap<String, Vec<u8>>,
    pub graph: Option<&'a GraphContext>,
    pub repository_revision: &'a str,
    pub plan_digest: Option<&'a str>,
    pub cortex_generation_id: Option<&'a str>,
}

/// Build the model. Pure and deterministic.
pub fn build_security_model(input: &SurfaceModelInput<'_>) -> SecurityModel {
    let mut b = Builder::new(input);
    b.run(input);
    b.finish(input)
}

// ---------------------------------------------------------------------------
// Patterns

struct Patterns {
    js_route: Regex,
    py_decorator_route: Regex,
    py_django_path: Regex,
    rs_axum_route: Regex,
    rs_attr_route: Regex,
    go_route: Regex,
    guard: Regex,
    cli_rs: Regex,
    cli_py: Regex,
    cli_js: Regex,
    cli_go: Regex,
    package_bin: Regex,
    tauri_command: Regex,
    fn_name: Regex,
    electron_ipc: Regex,
    electron_bridge: Regex,
    queue_js: Regex,
    queue_js_topic: Regex,
    queue_py: Regex,
    queue_rs: Regex,
    mcp_js: Regex,
    mcp_py: Regex,
    py_def: Regex,
    mcp_rs: Regex,
    cron_expr: Regex,
    ci_trigger: Regex,
    sched_js: Regex,
    sched_py: Regex,
    sched_other: Regex,
    k8s_cronjob: Regex,
    env_ref: Regex,
    secret_name: Regex,
    credential_lib: Regex,
    pii_field: Regex,
    money_dep: Regex,
    import_line: Regex,
    identity_lib: Regex,
    secret_file: Regex,
    template_suffix: Regex,
    hint_js: Regex,
    hint_py: Regex,
    hint_rs: Regex,
    hint_go: Regex,
    hint_queue_js: Regex,
    hint_mcp: Regex,
    hint_queue_py: Regex,
    tauri_hint: Regex,
    unsupported: Vec<(&'static str, Regex)>,
}

fn rx(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("surface-model pattern {pattern:?}: {e}"))
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        js_route: rx(
            r#"\b(?:app|router|server|api|fastify|route|routes)\.(get|post|put|patch|delete|all|options|head)\(\s*['"`]([^'"`]*)['"`]"#,
        ),
        py_decorator_route: rx(
            r#"@\w+\.(route|get|post|put|patch|delete)\(\s*['"]([^'"]*)['"]"#,
        ),
        py_django_path: rx(r#"\b(?:re_)?path\(\s*r?['"]([^'"]*)['"]"#),
        rs_axum_route: rx(r#"\.route\(\s*"([^"]*)""#),
        rs_attr_route: rx(r#"#\[(get|post|put|patch|delete)\(\s*"([^"]*)""#),
        go_route: rx(r#"\.(GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc)\(\s*"([^"]*)""#),
        guard: rx(
            r"(?i)\b(authenticate|authenticated|requireauth|require_auth|login_required|jwt|bearer|passport|permission_required|permissions?|guard|protected|requires?_?role|requires?_?admin|isadmin|current_user|get_current_user)\b",
        ),
        cli_rs: rx(r"#\[derive\([^)]*\b(?:Parser|Subcommand)\b|\bclap::"),
        cli_py: rx(r"argparse\.ArgumentParser\(|@click\.(?:command|group)|typer\.Typer\(|\bsys\.argv\b"),
        cli_js: rx(r#"\bprocess\.argv\b|require\(\s*['"](?:commander|yargs)['"]\)|from\s+['"](?:commander|yargs)['"]"#),
        cli_go: rx(r"\bflag\.Parse\(|cobra\.Command"),
        package_bin: rx(r#""bin"\s*:"#),
        tauri_command: rx(r"#\[(?:tauri::)?command\b"),
        fn_name: rx(r"\bfn\s+(\w+)"),
        electron_ipc: rx(r#"\bipcMain\.(?:handle|handleOnce|on|once)\(\s*['"]([^'"]+)['"]"#),
        electron_bridge: rx(r"\bcontextBridge\.exposeInMainWorld\("),
        queue_js: rx(r#"\bnew\s+Worker\(\s*['"]([^'"]+)['"]|\.consume\(\s*['"]([^'"]+)['"]"#),
        queue_js_topic: rx(r#"\.subscribe\(\s*\{\s*topic:\s*['"]([^'"]+)['"]"#),
        queue_py: rx(r"@(?:\w+\.)?(?:shared_task|task)\b|\bbasic_consume\("),
        queue_rs: rx(r"\.basic_consume\(|\.receive_message\("),
        mcp_js: rx(r#"\.(?:tool|registerTool)\(\s*['"]([^'"]+)['"]|\bCallToolRequestSchema\b"#),
        mcp_py: rx(r"@\w+\.tool\("),
        py_def: rx(r"\bdef\s+(\w+)"),
        mcp_rs: rx(r"#\[tool\b|#\[tool_router\b"),
        cron_expr: rx(r##"^\s*-?\s*cron:\s*['"]?([^'"#\r\n]+)"##),
        ci_trigger: rx(
            r"\b(pull_request_target|issue_comment|workflow_run|repository_dispatch|workflow_dispatch|pull_request_review_comment)\b",
        ),
        sched_js: rx(r#"\bcron\.schedule\(\s*['"]([^'"]+)['"]|\bnew\s+CronJob\("#),
        sched_py: rx(r"@(?:\w+\.)?(?:scheduled_job|periodic_task)\b|\bschedule\.every\(|\bBackgroundScheduler\("),
        sched_other: rx(r#"@Scheduled\(|tokio_cron_scheduler|\bJob::new(?:_async)?\(\s*"([^"]+)""#),
        k8s_cronjob: rx(r"^\s*kind:\s*CronJob\b"),
        env_ref: rx(
            r#"(?:process\.env\.|process\.env\[\s*['"]|env::var\(\s*"|os\.environ(?:\.get)?[\[\(]\s*['"]|os\.getenv\(\s*['"]|os\.Getenv\(\s*")([A-Z][A-Z0-9_]*)"#,
        ),
        secret_name: rx(
            r"(?i)(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL|SIGNING_?KEY|ACCESS_?KEY)",
        ),
        credential_lib: rx(
            r"\b(bcrypt|argon2|scrypt|pbkdf2|password_hash|hash_password|keyring|SecItemAdd|SecItemCopyMatching|keytar)\b",
        ),
        pii_field: rx(
            r"(?i)\b(ssn|social_security(?:_number)?|date_of_birth|dob|passport(?:_number)?|phone(?:_number)?|national_id|credit_card|card_number|iban)\b",
        ),
        money_dep: rx(r"(?i)\b(stripe|braintree|paypal|plaid|adyen)\b"),
        import_line: rx(r"^\s*(?:import|from|use|require|const\s+\w+\s*=\s*require|extern\s+crate)\b"),
        identity_lib: rx(
            r"\b(jsonwebtoken|passport|express-session|next-auth|authlib|oauthlib|flask_login|flask_jwt_extended|oauth2|openidconnect|django\.contrib\.auth)\b",
        ),
        secret_file: rx(
            r"(?:^|/)(?:\.env(?:\.[^/]*)?|[^/]+\.(?:pem|key|p12|pfx|jks|keystore)|id_rsa|id_ed25519)$",
        ),
        template_suffix: rx(r"(?i)\.(?:example|sample|template|dist)$"),
        hint_js: rx(r"\b(express|fastify|koa|hono|restify)\b|@hapi/"),
        hint_py: rx(r"\b(flask|fastapi|django|starlette|aiohttp|sanic|bottle)\b"),
        hint_rs: rx(r"\b(axum|actix_web|actix-web|rocket|warp|tide)\b"),
        hint_go: rx(r"net/http|gin-gonic|go-chi|gorilla/mux|labstack/echo|gofiber"),
        hint_queue_js: rx(r"\b(bullmq|bull|amqplib|kafkajs|sqs)\b"),
        hint_mcp: rx(r"(?i)modelcontextprotocol|\bMcpServer\b|\bfastmcp\b|\brmcp\b|\bmcp\b"),
        hint_queue_py: rx(r"\b(celery|pika|kombu)\b"),
        tauri_hint: rx(r"\btauri\b"),
        unsupported: vec![
            ("nestjs", rx(r"@nestjs/common|@Controller\(")),
            ("spring", rx(r"@RestController|@GetMapping|@PostMapping|@RequestMapping")),
            ("laravel", rx(r"\bRoute::(?:get|post|put|patch|delete)\(")),
            ("aspnet", rx(r"\[Http(?:Get|Post|Put|Delete|Patch)\b|\.Map(?:Get|Post|Put|Delete)\(")),
            ("ktor", rx(r"\brouting\s*\{")),
        ],
    })
}

// ---------------------------------------------------------------------------
// Builder

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Lang {
    Js,
    Py,
    Rs,
    Go,
    Other,
}

fn lang_of(path: &str) -> Lang {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Lang::Js,
        "py" => Lang::Py,
        "rs" => Lang::Rs,
        "go" => Lang::Go,
        _ => Lang::Other,
    }
}

fn strength_rank(s: &str) -> u8 {
    if s == STRONG {
        1
    } else {
        0
    }
}

fn norm_hex(digest: &str) -> Option<&str> {
    digest.strip_prefix("sha256:")
}

fn sorted_refs(refs: impl IntoIterator<Item = String>) -> Vec<String> {
    refs.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

struct Builder {
    inventory_digest: String,
    entities: BTreeMap<String, ModelEntity>,
    relations: BTreeMap<String, ModelRelation>,
    evidence: BTreeMap<String, EvidenceRef>,
    gaps: BTreeMap<String, ModelGap>,
    truncated: bool,
    graph_used: bool,
    files_scanned: u64,
    files_skipped: u64,
    /// entrypoint id -> file path
    entrypoints: BTreeMap<String, String>,
    /// file path -> asset entity ids
    asset_files: BTreeMap<String, BTreeSet<String>>,
    /// subkind -> entrypoint ids, for actor/boundary synthesis
    entrypoint_subkinds: BTreeMap<String, BTreeSet<String>>,
    applic_evidence: BTreeMap<&'static str, BTreeSet<String>>,
    applic_reason: BTreeMap<&'static str, BTreeSet<String>>,
}

impl Builder {
    fn new(input: &SurfaceModelInput<'_>) -> Self {
        Self {
            inventory_digest: input.inventory.digest.clone(),
            entities: BTreeMap::new(),
            relations: BTreeMap::new(),
            evidence: BTreeMap::new(),
            gaps: BTreeMap::new(),
            truncated: false,
            graph_used: false,
            files_scanned: 0,
            files_skipped: 0,
            entrypoints: BTreeMap::new(),
            asset_files: BTreeMap::new(),
            entrypoint_subkinds: BTreeMap::new(),
            applic_evidence: BTreeMap::new(),
            applic_reason: BTreeMap::new(),
        }
    }

    fn gap(&mut self, kind: &str, reason: &str, blocking: bool, paths: &[String]) {
        let id = format!("gap:{kind}");
        let entry = self.gaps.entry(id.clone()).or_insert_with(|| ModelGap {
            id,
            kind: kind.into(),
            reason: reason.into(),
            blocking,
            path_count: 0,
            paths: Vec::new(),
        });
        entry.blocking |= blocking;
        let mut set: BTreeSet<String> = entry.paths.iter().cloned().collect();
        for p in paths {
            if set.insert(p.clone()) {
                entry.path_count += 1;
            }
        }
        entry.paths = set.into_iter().take(MAX_GAP_PATHS).collect();
    }

    fn evidence(&mut self, path: &str, start: usize, end: usize, source_digest: &str) -> String {
        let key = format!("{path}\0{start}\0{end}\0{source_digest}");
        let id = format!("ev:{}", &bytes_digest(key.as_bytes())[..20]);
        self.evidence
            .entry(id.clone())
            .or_insert_with(|| EvidenceRef {
                id: id.clone(),
                path: path.into(),
                start_line: start as u64,
                end_line: end as u64,
                source_digest: source_digest.into(),
                inventory_digest: self.inventory_digest.clone(),
            });
        id
    }

    #[allow(clippy::too_many_arguments)]
    fn entity(
        &mut self,
        kind: &str,
        subkind: &str,
        name: &str,
        scope: &str,
        assertion: &str,
        strength: &str,
        refs: &[String],
        attrs: &[(&str, String)],
    ) -> Option<String> {
        let id = format!(
            "ent:{}",
            &bytes_digest(format!("{kind}\0{subkind}\0{name}\0{scope}").as_bytes())[..20]
        );
        if let Some(existing) = self.entities.get_mut(&id) {
            let merged = sorted_refs(
                existing
                    .evidence_refs
                    .iter()
                    .cloned()
                    .chain(refs.iter().cloned()),
            );
            existing.evidence_refs = merged;
            if strength_rank(strength) > strength_rank(&existing.evidence_strength) {
                existing.evidence_strength = strength.into();
            }
            return Some(id);
        }
        if self.entities.len() >= MAX_ENTITIES {
            self.truncated = true;
            self.gap(
                "model-truncated",
                "entity cap reached; surface enumeration is incomplete",
                true,
                &[],
            );
            return None;
        }
        let mut attributes = BTreeMap::new();
        for (k, v) in attrs {
            attributes.insert((*k).to_string(), v.clone());
        }
        self.entities.insert(
            id.clone(),
            ModelEntity {
                id: id.clone(),
                kind: kind.into(),
                subkind: subkind.into(),
                name: name.into(),
                assertion: assertion.into(),
                evidence_strength: strength.into(),
                evidence_refs: sorted_refs(refs.iter().cloned()),
                provider: PROVIDER_ID.into(),
                attributes,
            },
        );
        Some(id)
    }

    #[allow(clippy::too_many_arguments)]
    fn relation(
        &mut self,
        kind: &str,
        from: &str,
        to: &str,
        assertion: &str,
        strength: &str,
        refs: &[String],
        origin: &str,
    ) {
        let id = format!(
            "rel:{}",
            &bytes_digest(format!("{kind}\0{from}\0{to}\0{origin}").as_bytes())[..20]
        );
        if let Some(existing) = self.relations.get_mut(&id) {
            existing.evidence_refs = sorted_refs(
                existing
                    .evidence_refs
                    .iter()
                    .cloned()
                    .chain(refs.iter().cloned()),
            );
            if strength_rank(strength) > strength_rank(&existing.evidence_strength) {
                existing.evidence_strength = strength.into();
            }
            return;
        }
        if self.relations.len() >= MAX_RELATIONS {
            self.truncated = true;
            self.gap(
                "model-truncated",
                "relation cap reached; relation enumeration is incomplete",
                true,
                &[],
            );
            return;
        }
        self.relations.insert(
            id.clone(),
            ModelRelation {
                id,
                kind: kind.into(),
                from: from.into(),
                to: to.into(),
                assertion: assertion.into(),
                evidence_strength: strength.into(),
                evidence_refs: sorted_refs(refs.iter().cloned()),
                provider: PROVIDER_ID.into(),
                origin: origin.into(),
            },
        );
    }

    fn note_domain(&mut self, domain: &'static str, reason: &str, refs: &[String]) {
        self.applic_reason
            .entry(domain)
            .or_default()
            .insert(reason.into());
        self.applic_evidence
            .entry(domain)
            .or_default()
            .extend(refs.iter().cloned());
    }

    fn artifact(&mut self, path: &str, source_digest: &str, line_count: usize) -> Option<String> {
        let ev = self.evidence(path, 1, line_count.max(1), source_digest);
        self.entity(
            "repository-artifact",
            "file",
            path,
            path,
            "observed",
            STRONG,
            &[ev],
            &[("path", path.to_string())],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_entrypoint(
        &mut self,
        subkind: &str,
        name: &str,
        path: &str,
        refs: &[String],
        strength: &str,
        attrs: &[(&str, String)],
        artifact: Option<&str>,
    ) -> Option<String> {
        let id = self.entity(
            "entrypoint",
            subkind,
            name,
            path,
            "observed",
            strength,
            refs,
            attrs,
        )?;
        self.entrypoints.insert(id.clone(), path.to_string());
        self.entrypoint_subkinds
            .entry(subkind.to_string())
            .or_default()
            .insert(id.clone());
        if let Some(a) = artifact {
            self.relation(
                "contains",
                a,
                &id,
                "observed",
                strength,
                refs,
                "inventory-bytes",
            );
        }
        Some(id)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_asset(
        &mut self,
        kind: &str,
        subkind: &str,
        name: &str,
        path: &str,
        refs: &[String],
        strength: &str,
        attrs: &[(&str, String)],
    ) -> Option<String> {
        let id = self.entity(kind, subkind, name, path, "observed", strength, refs, attrs)?;
        self.asset_files
            .entry(path.to_string())
            .or_default()
            .insert(id.clone());
        Some(id)
    }

    // -----------------------------------------------------------------------

    fn run(&mut self, input: &SurfaceModelInput<'_>) {
        let inv = input.inventory;
        if inv.digest.trim().is_empty() {
            self.gap(
                "inventory-digest-missing",
                "inventory envelope carries no digest; model cannot be revision-bound",
                true,
                &[],
            );
        }
        if input.repository_revision.trim().is_empty() {
            self.gap(
                "repository-revision-missing",
                "no repository revision supplied; model is not revision-bound",
                true,
                &[],
            );
        }
        if input.plan_digest.map(str::trim).unwrap_or("").is_empty() {
            self.gap(
                "plan-digest-unbound",
                "no frozen plan digest supplied; model is not bound to a plan",
                false,
                &[],
            );
        }

        let mut unavailable = Vec::new();
        let mut mismatch = Vec::new();
        let mut oversize = Vec::new();
        let mut long_lines = Vec::new();
        let mut unsupported: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        let mut path_applic: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();

        for entry in &inv.entries {
            let path = entry.path.as_str();
            let Some(bytes) = input.files.get(path) else {
                self.files_skipped += 1;
                unavailable.push(path.to_string());
                continue;
            };
            let actual = bytes_digest(bytes);
            match entry.digest.as_deref() {
                Some(d) if norm_hex(d).is_some_and(|hex| hex.eq_ignore_ascii_case(&actual)) => {}
                Some(_) | None => {
                    self.files_skipped += 1;
                    mismatch.push(path.to_string());
                    continue;
                }
            }
            if bytes.len() > MAX_FILE_BYTES {
                self.files_skipped += 1;
                oversize.push(path.to_string());
                continue;
            }
            if bytes.iter().take(8192).any(|b| *b == 0) {
                // Binary content: not a text surface; not an error.
                self.files_skipped += 1;
                continue;
            }
            self.files_scanned += 1;
            self.path_domains(path, &actual, &mut path_applic);
            let text = String::from_utf8_lossy(bytes);
            let lines: Vec<&str> = text.lines().collect();
            if lines.iter().any(|l| l.len() > MAX_LINE_CHARS) {
                long_lines.push(path.to_string());
            }
            self.scan_file(path, &actual, &lines, &mut unsupported);
        }

        if !unavailable.is_empty() {
            self.gap(
                "source-bytes-unavailable",
                "inventory entries without frozen bytes were not modelled",
                true,
                &unavailable,
            );
        }
        if !mismatch.is_empty() {
            self.gap(
                "source-digest-unverified",
                "frozen bytes missing a matching sha256 inventory digest were not modelled",
                true,
                &mismatch,
            );
        }
        if !oversize.is_empty() {
            self.gap(
                "file-too-large",
                "files over the per-file byte cap were not modelled",
                true,
                &oversize,
            );
        }
        if !long_lines.is_empty() {
            self.gap(
                "long-lines-skipped",
                "lines over the length cap (minified/generated) were not pattern-matched",
                false,
                &long_lines,
            );
        }
        for (name, paths) in unsupported {
            let reason = format!(
                "{name} routing is not enumerated by this provider; its entrypoints are unmodelled"
            );
            self.gap(
                &format!("unsupported-framework:{name}"),
                &reason,
                true,
                &paths,
            );
        }

        self.synthesize_actors_and_boundaries();
        self.relate_reachability(input);

        // Applicability: path-derived domains.
        for (domain, paths) in path_applic {
            let refs: Vec<String> = paths
                .iter()
                .filter_map(|p| {
                    let d = bytes_digest(input.files.get(p)?);
                    Some(self.evidence(p, 1, 1, &d))
                })
                .collect();
            self.note_domain(
                domain,
                &format!("{} matching artifact(s) found", paths.len()),
                &refs,
            );
        }

        if self.entrypoints.is_empty() {
            self.gap(
                "no-entrypoints-evidenced",
                "no entrypoint was detected in modelled files; this is not evidence that no attack surface exists",
                inv.entries.iter().any(|e| e.source_file),
                &[],
            );
        }
    }

    fn path_domains(
        &mut self,
        path: &str,
        _digest: &str,
        out: &mut BTreeMap<&'static str, BTreeSet<String>>,
    ) {
        let lower = path.to_ascii_lowercase();
        let base = lower.rsplit('/').next().unwrap_or("");
        let mut hit = |d: &'static str| {
            out.entry(d).or_default().insert(path.to_string());
        };
        if base == "androidmanifest.xml" || base == "info.plist" {
            hit("mobile");
        }
        if lower.ends_with(".sol") || lower.ends_with(".vy") {
            hit("smart-contract");
        }
        if lower.ends_with(".tf") || lower.ends_with(".tfvars") || base.starts_with("dockerfile") {
            hit("cloud-iac");
        }
        if lower.starts_with(".github/workflows/")
            && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
        {
            hit("ci-cd");
        }
    }

    fn scan_file(
        &mut self,
        path: &str,
        digest: &str,
        lines: &[&str],
        unsupported: &mut BTreeMap<&'static str, Vec<String>>,
    ) {
        let p = patterns();
        let lang = lang_of(path);
        let lower = path.to_ascii_lowercase();
        let base = lower.rsplit('/').next().unwrap_or("").to_string();
        let joined_hint = |re: &Regex| {
            lines
                .iter()
                .take(400)
                .any(|l| l.len() <= MAX_LINE_CHARS && re.is_match(l))
        };
        let artifact_id: std::cell::OnceCell<Option<String>> = std::cell::OnceCell::new();
        // Lazily create the file artifact only when something is found.
        macro_rules! art {
            ($self:ident) => {
                artifact_id
                    .get_or_init(|| $self.artifact(path, digest, lines.len()))
                    .clone()
            };
        }

        // Unsupported framework detection (entrypoints not enumerated).
        if matches!(lang, Lang::Js | Lang::Other)
            && !lower.ends_with(".md")
            && !lower.ends_with(".json")
        {
            for (name, re) in &p.unsupported {
                if lines
                    .iter()
                    .any(|l| l.len() <= MAX_LINE_CHARS && re.is_match(l))
                {
                    unsupported.entry(*name).or_default().push(path.to_string());
                }
            }
        }
        if lower.ends_with("config/routes.rb") {
            unsupported
                .entry("rails")
                .or_default()
                .push(path.to_string());
        }
        if lower.ends_with("/router.ex") || base == "router.ex" {
            unsupported
                .entry("phoenix")
                .or_default()
                .push(path.to_string());
        }

        // Path-derived entrypoints (Next.js route handlers).
        if let Some(route) = nextjs_route(&lower) {
            let ev = self.evidence(path, 1, lines.len().max(1), digest);
            let a = art!(self);
            if let Some(id) = self.add_entrypoint(
                "http-route",
                &format!("ANY {route}"),
                path,
                &[ev.clone()],
                POSSIBLE,
                &[
                    ("method", "ANY".into()),
                    ("route", route.clone()),
                    ("derivation", "file-path-convention".into()),
                    ("authObservation", "none-observed".into()),
                ],
                a.as_deref(),
            ) {
                self.admin_check(&id, &route, path, &ev);
            }
            self.note_domain("http-service", "file-convention route handler", &[ev]);
        }

        // Secret-bearing files, by name/path only. Content is never read.
        if p.secret_file.is_match(&lower) && !p.template_suffix.is_match(&lower) {
            let ev = self.evidence(path, 1, 1, digest);
            self.add_asset(
                "crown-jewel",
                "secret-file",
                path,
                path,
                &[ev],
                POSSIBLE,
                &[
                    ("valueRecorded", "false".into()),
                    ("derivation", "file-name".into()),
                ],
            );
        }

        // Structured config files.
        if base == "tauri.conf.json" || base == "tauri.conf.json5" {
            let ev = self.evidence(path, 1, lines.len().max(1), digest);
            let a = art!(self);
            let dc = self.entity(
                "deployment-context",
                "tauri-app",
                path,
                path,
                "observed",
                STRONG,
                &[ev.clone()],
                &[],
            );
            if let (Some(a), Some(dc)) = (a, dc) {
                self.relation(
                    "contains",
                    &a,
                    &dc,
                    "observed",
                    STRONG,
                    &[ev.clone()],
                    "inventory-bytes",
                );
            }
            self.note_domain("native-desktop", "tauri.conf.json present", &[ev]);
        }
        if lower.contains("capabilities/")
            && lower.ends_with(".json")
            && lower.contains("src-tauri")
        {
            let a = art!(self);
            self.tauri_capabilities(path, digest, lines, a);
        }
        if base == ".mcp.json" || base == "mcp.json" {
            let a = art!(self);
            self.mcp_config(path, digest, lines, a);
        }
        if base == "package.json" {
            for (i, l) in lines.iter().enumerate() {
                if p.package_bin.is_match(l) {
                    let ev = self.evidence(path, i + 1, i + 1, digest);
                    let a = art!(self);
                    self.add_entrypoint(
                        "cli",
                        path,
                        path,
                        &[ev.clone()],
                        POSSIBLE,
                        &[("derivation", "package-bin-field".into())],
                        a.as_deref(),
                    );
                    self.note_domain("cli", "package.json bin entry", &[ev]);
                    break;
                }
            }
        }
        let is_manifest = matches!(
            base.as_str(),
            "package.json"
                | "cargo.toml"
                | "pyproject.toml"
                | "go.mod"
                | "gemfile"
                | "pom.xml"
                | "build.gradle"
        ) || (base.starts_with("requirements") && base.ends_with(".txt"));
        let is_workflow = lower.starts_with(".github/workflows/")
            && (lower.ends_with(".yml") || lower.ends_with(".yaml"));
        let is_model_file = lower.ends_with(".sql")
            || lower.ends_with(".prisma")
            || ["models", "migrations", "schema", "entities"]
                .iter()
                .any(|seg| lower.split('/').any(|s| s.starts_with(seg)));

        // Per-file gating on framework hints.
        let hint_route = match lang {
            Lang::Js => joined_hint(&p.hint_js),
            Lang::Py => joined_hint(&p.hint_py),
            Lang::Rs => joined_hint(&p.hint_rs),
            Lang::Go => joined_hint(&p.hint_go),
            Lang::Other => false,
        };
        let has_queue_js = lang == Lang::Js && joined_hint(&p.hint_queue_js);
        let has_queue_py = lang == Lang::Py && joined_hint(&p.hint_queue_py);
        let has_mcp = joined_hint(&p.hint_mcp);
        let has_tauri = lang == Lang::Rs && joined_hint(&p.tauri_hint);
        let is_django_urls = base == "urls.py";
        let mut cli_seen = false;
        let mut bridge_seen = false;
        let mut cred_seen: BTreeSet<String> = BTreeSet::new();
        let mut pii_fields: BTreeSet<String> = BTreeSet::new();
        let mut pii_first: Option<usize> = None;
        let mut ident_seen: BTreeSet<String> = BTreeSet::new();
        let mut money_seen: BTreeSet<String> = BTreeSet::new();
        let mut ci_seen: BTreeSet<String> = BTreeSet::new();

        for (idx, line) in lines.iter().enumerate() {
            if line.len() > MAX_LINE_CHARS {
                continue;
            }
            let ln = idx + 1;

            // HTTP routes / webhooks.
            let mut route_hit: Option<(String, String)> = None;
            match lang {
                Lang::Js => {
                    if let Some(c) = p.js_route.captures(line) {
                        let r = c[2].to_string();
                        if r.starts_with('/') || r.starts_with('*') {
                            route_hit = Some((c[1].to_ascii_uppercase(), r));
                        }
                    }
                }
                Lang::Py => {
                    if let Some(c) = p.py_decorator_route.captures(line) {
                        let m = if &c[1] == "route" {
                            "ANY".to_string()
                        } else {
                            c[1].to_ascii_uppercase()
                        };
                        if c[2].starts_with('/') {
                            route_hit = Some((m, c[2].to_string()));
                        }
                    } else if is_django_urls {
                        if let Some(c) = p.py_django_path.captures(line) {
                            route_hit =
                                Some(("ANY".into(), format!("/{}", c[1].trim_start_matches('/'))));
                        }
                    }
                }
                Lang::Rs => {
                    if let Some(c) = p.rs_attr_route.captures(line) {
                        if c[2].starts_with('/') {
                            route_hit = Some((c[1].to_ascii_uppercase(), c[2].to_string()));
                        }
                    } else if let Some(c) = p.rs_axum_route.captures(line) {
                        if c[1].starts_with('/') {
                            route_hit = Some(("ANY".into(), c[1].to_string()));
                        }
                    }
                }
                Lang::Go => {
                    if let Some(c) = p.go_route.captures(line) {
                        if c[2].starts_with('/') {
                            let m = match &c[1] {
                                "Handle" | "HandleFunc" => "ANY".to_string(),
                                other => other.to_string(),
                            };
                            route_hit = Some((m, c[2].to_string()));
                        }
                    }
                }
                Lang::Other => {}
            }
            if let Some((method, route)) = route_hit {
                let strength = if hint_route || is_django_urls {
                    STRONG
                } else {
                    POSSIBLE
                };
                let rl = route.to_ascii_lowercase();
                let subkind = if rl.contains("webhook") || rl.contains("/hooks") {
                    "webhook"
                } else {
                    "http-route"
                };
                let ev = self.evidence(path, ln, ln, digest);
                let a = art!(self);
                let guard = guard_token(lines, idx);
                let obs = if guard.is_some() {
                    "guard-token-near-declaration"
                } else {
                    "none-observed"
                };
                if let Some(id) = self.add_entrypoint(
                    subkind,
                    &format!("{method} {route}"),
                    path,
                    &[ev.clone()],
                    strength,
                    &[
                        ("method", method.clone()),
                        ("route", route.clone()),
                        ("authObservation", obs.into()),
                    ],
                    a.as_deref(),
                ) {
                    if let Some(tok) = guard {
                        // The guard token is a *name* seen near the route; whether it
                        // enforces anything is unknown, never asserted.
                        let gev =
                            self.evidence(path, ln.saturating_sub(GUARD_WINDOW).max(1), ln, digest);
                        if let Some(c) = self.entity(
                            "control",
                            "auth-guard-token",
                            &tok,
                            path,
                            "inferred",
                            POSSIBLE,
                            &[gev.clone()],
                            &[("controlState", "unknown".into())],
                        ) {
                            self.relation(
                                "protects",
                                &c,
                                &id,
                                "inferred",
                                POSSIBLE,
                                &[gev],
                                "inventory-bytes",
                            );
                        }
                    }
                    self.admin_check(&id, &route, path, &ev);
                }
                self.note_domain(
                    if subkind == "webhook" {
                        "webhooks"
                    } else {
                        "http-service"
                    },
                    "route declaration found",
                    &[ev],
                );
            }

            // CLI.
            if !cli_seen {
                let (hit, strength) = match lang {
                    Lang::Rs => (p.cli_rs.is_match(line), STRONG),
                    Lang::Py => (p.cli_py.is_match(line), STRONG),
                    Lang::Js => (p.cli_js.is_match(line), POSSIBLE),
                    Lang::Go => (p.cli_go.is_match(line), STRONG),
                    Lang::Other => (false, POSSIBLE),
                };
                if hit {
                    cli_seen = true;
                    let ev = self.evidence(path, ln, ln, digest);
                    let a = art!(self);
                    self.add_entrypoint(
                        "cli",
                        path,
                        path,
                        &[ev.clone()],
                        strength,
                        &[("derivation", "argument-parser".into())],
                        a.as_deref(),
                    );
                    self.note_domain("cli", "argument parsing found", &[ev]);
                }
            }

            // IPC / Tauri / Electron.
            if has_tauri && p.tauri_command.is_match(line) {
                let name = lines
                    .iter()
                    .skip(idx)
                    .take(6)
                    .find_map(|l| p.fn_name.captures(l).map(|c| c[1].to_string()));
                if let Some(name) = name {
                    let ev = self.evidence(path, ln, ln, digest);
                    let a = art!(self);
                    self.add_entrypoint(
                        "ipc-command",
                        &name,
                        path,
                        &[ev.clone()],
                        STRONG,
                        &[("framework", "tauri".into())],
                        a.as_deref(),
                    );
                    self.note_domain("native-desktop", "tauri command found", &[ev]);
                }
            }
            if lang == Lang::Js {
                if let Some(c) = p.electron_ipc.captures(line) {
                    let ev = self.evidence(path, ln, ln, digest);
                    let a = art!(self);
                    self.add_entrypoint(
                        "ipc-command",
                        &c[1],
                        path,
                        &[ev.clone()],
                        STRONG,
                        &[("framework", "electron".into())],
                        a.as_deref(),
                    );
                    self.note_domain("native-desktop", "electron ipc handler found", &[ev]);
                }
                if !bridge_seen && p.electron_bridge.is_match(line) {
                    bridge_seen = true;
                    let ev = self.evidence(path, ln, ln, digest);
                    let a = art!(self);
                    self.add_entrypoint(
                        "ipc-command",
                        &format!("preload-bridge:{path}"),
                        path,
                        &[ev.clone()],
                        STRONG,
                        &[("framework", "electron-preload-bridge".into())],
                        a.as_deref(),
                    );
                    self.note_domain("native-desktop", "electron preload bridge found", &[ev]);
                }
            }

            // Queue consumers.
            let queue_hit: Option<String> = if has_queue_js {
                p.queue_js
                    .captures(line)
                    .map(|c| {
                        c.get(1)
                            .or_else(|| c.get(2))
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_default()
                    })
                    .or_else(|| p.queue_js_topic.captures(line).map(|c| c[1].to_string()))
            } else if has_queue_py && p.queue_py.is_match(line) {
                Some(String::new())
            } else if lang == Lang::Rs && p.queue_rs.is_match(line) {
                Some(String::new())
            } else {
                None
            };
            if let Some(q) = queue_hit {
                let ev = self.evidence(path, ln, ln, digest);
                let a = art!(self);
                let name = if q.is_empty() {
                    format!("consumer:{path}:{ln}")
                } else {
                    q
                };
                self.add_entrypoint(
                    "queue-consumer",
                    &name,
                    path,
                    &[ev.clone()],
                    if lang == Lang::Rs { POSSIBLE } else { STRONG },
                    &[],
                    a.as_deref(),
                );
                self.note_domain("queue-processing", "queue consumer found", &[ev]);
            }

            // MCP tools.
            if has_mcp {
                let mcp = match lang {
                    Lang::Js => p.mcp_js.captures(line).map(|c| {
                        c.get(1)
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_else(|| format!("call-tool-handler:{ln}"))
                    }),
                    Lang::Py => p.mcp_py.is_match(line).then(|| {
                        lines
                            .iter()
                            .skip(idx)
                            .take(4)
                            .find_map(|l| p.py_def.captures(l).map(|c| c[1].to_string()))
                            .unwrap_or_else(|| format!("tool:{ln}"))
                    }),
                    Lang::Rs => p.mcp_rs.is_match(line).then(|| {
                        lines
                            .iter()
                            .skip(idx)
                            .take(6)
                            .find_map(|l| p.fn_name.captures(l).map(|c| c[1].to_string()))
                            .unwrap_or_else(|| format!("tool:{ln}"))
                    }),
                    _ => None,
                };
                if let Some(name) = mcp {
                    let ev = self.evidence(path, ln, ln, digest);
                    let a = art!(self);
                    self.add_entrypoint(
                        "mcp-tool",
                        &name,
                        path,
                        &[ev.clone()],
                        STRONG,
                        &[],
                        a.as_deref(),
                    );
                    self.note_domain("mcp-agent", "mcp tool registration found", &[ev]);
                }
            }

            // Scheduled jobs and CI triggers.
            let sched: Option<String> = if is_workflow {
                p.cron_expr
                    .captures(line)
                    .map(|c| format!("cron {}", c[1].trim()))
            } else if k8s_like(&lower) && p.k8s_cronjob.is_match(line) {
                Some(format!("k8s-cronjob:{path}"))
            } else {
                match lang {
                    Lang::Js => p.sched_js.captures(line).map(|c| {
                        c.get(1)
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_else(|| format!("cronjob:{path}:{ln}"))
                    }),
                    Lang::Py => p
                        .sched_py
                        .is_match(line)
                        .then(|| format!("scheduled:{path}:{ln}")),
                    Lang::Rs | Lang::Go | Lang::Other => p.sched_other.captures(line).map(|c| {
                        c.get(1)
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_else(|| format!("scheduled:{path}:{ln}"))
                    }),
                }
            };
            if let Some(name) = sched {
                let ev = self.evidence(path, ln, ln, digest);
                let a = art!(self);
                self.add_entrypoint(
                    "scheduled-job",
                    &name,
                    path,
                    &[ev.clone()],
                    if is_workflow { STRONG } else { POSSIBLE },
                    &[],
                    a.as_deref(),
                );
                self.note_domain("scheduled-automation", "scheduled job found", &[ev]);
            }
            if is_workflow {
                for c in p.ci_trigger.captures_iter(line) {
                    let trig = c[1].to_string();
                    if ci_seen.insert(trig.clone()) {
                        let ev = self.evidence(path, ln, ln, digest);
                        let a = art!(self);
                        self.add_entrypoint(
                            "ci-trigger",
                            &trig,
                            path,
                            &[ev.clone()],
                            STRONG,
                            &[],
                            a.as_deref(),
                        );
                        self.note_domain("ci-cd", "ci trigger found", &[ev]);
                    }
                }
            }

            // Assets: env-referenced secrets.
            if matches!(lang, Lang::Js | Lang::Py | Lang::Rs | Lang::Go) {
                for c in p.env_ref.captures_iter(line) {
                    let name = c[1].to_string();
                    if p.secret_name.is_match(&name) {
                        let ev = self.evidence(path, ln, ln, digest);
                        let a = art!(self);
                        if let Some(id) = self.entity(
                            "crown-jewel",
                            "secret",
                            &name,
                            "env",
                            "observed",
                            POSSIBLE,
                            &[ev.clone()],
                            &[
                                ("valueRecorded", "false".into()),
                                ("derivation", "env-var-name".into()),
                            ],
                        ) {
                            // Env secrets are not file-scoped: file reachability keys on the reader.
                            self.asset_files
                                .entry(path.to_string())
                                .or_default()
                                .insert(id.clone());
                            if let Some(a) = a {
                                self.relation(
                                    "reads",
                                    &a,
                                    &id,
                                    "observed",
                                    POSSIBLE,
                                    &[ev],
                                    "inventory-bytes",
                                );
                            }
                        }
                    }
                }
                if let Some(c) = p.credential_lib.captures(line) {
                    let tok = c[1].to_string();
                    if cred_seen.insert(tok.clone()) {
                        let ev = self.evidence(path, ln, ln, digest);
                        let a = art!(self);
                        if let Some(id) = self.add_asset(
                            "asset",
                            "credential-store",
                            &tok,
                            path,
                            &[ev.clone()],
                            POSSIBLE,
                            &[("derivation", "library-token".into())],
                        ) {
                            if let Some(a) = a {
                                self.relation(
                                    "stores",
                                    &a,
                                    &id,
                                    "inferred",
                                    POSSIBLE,
                                    &[ev],
                                    "inventory-bytes",
                                );
                            }
                        }
                    }
                }
                if let Some(c) = p.identity_lib.captures(line) {
                    let lib = c[1].to_string();
                    if ident_seen.insert(lib.clone()) {
                        let ev = self.evidence(path, ln, ln, digest);
                        let a = art!(self);
                        if let Some(id) = self.entity(
                            "identity",
                            "auth-library",
                            &lib,
                            "repository",
                            "observed",
                            POSSIBLE,
                            &[ev.clone()],
                            &[],
                        ) {
                            if let Some(a) = a {
                                self.relation(
                                    "authenticates-as",
                                    &a,
                                    &id,
                                    "inferred",
                                    POSSIBLE,
                                    &[ev],
                                    "inventory-bytes",
                                );
                            }
                        }
                    }
                }
            }

            // Assets: PII fields in schema/model files.
            if is_model_file {
                if let Some(c) = p.pii_field.captures(line) {
                    pii_fields.insert(c[1].to_ascii_lowercase());
                    pii_first.get_or_insert(ln);
                }
            }

            // Assets: payment providers (manifests and import lines).
            if is_manifest || p.import_line.is_match(line) {
                if let Some(c) = p.money_dep.captures(line) {
                    let prov = c[1].to_ascii_lowercase();
                    if money_seen.insert(prov.clone()) {
                        let ev = self.evidence(path, ln, ln, digest);
                        let a = art!(self);
                        if let Some(id) = self.add_asset(
                            "crown-jewel",
                            "money",
                            &format!("payment-provider:{prov}"),
                            path,
                            &[ev.clone()],
                            POSSIBLE,
                            &[("derivation", "payment-dependency".into())],
                        ) {
                            if let Some(a) = a {
                                self.relation(
                                    "reads",
                                    &a,
                                    &id,
                                    "inferred",
                                    POSSIBLE,
                                    &[ev],
                                    "inventory-bytes",
                                );
                            }
                        }
                    }
                }
            }
        }

        if let Some(first) = pii_first {
            let ev = self.evidence(path, first, first, digest);
            let a = art!(self);
            let fields = pii_fields.iter().cloned().collect::<Vec<_>>().join(",");
            if let Some(id) = self.add_asset(
                "crown-jewel",
                "pii-store",
                path,
                path,
                &[ev.clone()],
                POSSIBLE,
                &[
                    ("fieldNames", fields),
                    ("derivation", "schema-field-names".into()),
                ],
            ) {
                if let Some(a) = a {
                    self.relation(
                        "stores",
                        &a,
                        &id,
                        "inferred",
                        POSSIBLE,
                        &[ev],
                        "inventory-bytes",
                    );
                }
            }
        }
    }

    fn admin_check(&mut self, entrypoint: &str, route: &str, path: &str, ev: &str) {
        let admin = route.to_ascii_lowercase().split('/').any(|s| {
            matches!(
                s,
                "admin" | "internal" | "manage" | "management" | "superuser"
            )
        });
        if !admin {
            return;
        }
        if let Some(id) = self.add_asset(
            "crown-jewel",
            "admin-capability",
            route,
            path,
            &[ev.to_string()],
            POSSIBLE,
            &[("derivation", "route-segment".into())],
        ) {
            self.relation(
                "exposes",
                entrypoint,
                &id,
                "inferred",
                POSSIBLE,
                &[ev.to_string()],
                "inventory-bytes",
            );
        }
    }

    fn tauri_capabilities(
        &mut self,
        path: &str,
        digest: &str,
        lines: &[&str],
        artifact: Option<String>,
    ) {
        let text = lines.join("\n");
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            self.gap(
                "config-unparsed",
                "a capability/config file was not valid JSON and was not modelled",
                true,
                &[path.to_string()],
            );
            return;
        };
        let perms = value
            .get("permissions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for perm in perms {
            let id = perm.as_str().map(str::to_string).or_else(|| {
                perm.get("identifier")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
            let Some(id) = id else { continue };
            let line = lines
                .iter()
                .position(|l| l.contains(&format!("\"{id}\"")))
                .map(|i| i + 1)
                .unwrap_or(1);
            let ev = self.evidence(path, line, line, digest);
            if let Some(scope) = self.entity(
                "permission-scope",
                "tauri-permission",
                &id,
                path,
                "observed",
                STRONG,
                &[ev.clone()],
                &[],
            ) {
                if let Some(a) = &artifact {
                    self.relation(
                        "grants",
                        a,
                        &scope,
                        "observed",
                        STRONG,
                        &[ev.clone()],
                        "inventory-bytes",
                    );
                }
                self.note_domain("native-desktop", "tauri capability permission found", &[ev]);
            }
        }
    }

    fn mcp_config(&mut self, path: &str, digest: &str, lines: &[&str], artifact: Option<String>) {
        let text = lines.join("\n");
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            self.gap(
                "config-unparsed",
                "a capability/config file was not valid JSON and was not modelled",
                true,
                &[path.to_string()],
            );
            return;
        };
        let servers = value
            .get("mcpServers")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for (name, def) in servers {
            let line = lines
                .iter()
                .position(|l| l.contains(&format!("\"{name}\"")))
                .map(|i| i + 1)
                .unwrap_or(1);
            let ev = self.evidence(path, line, line, digest);
            let command = def
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let transport = if def.get("url").is_some() {
                "remote"
            } else {
                "stdio"
            };
            // Arguments and environment values are intentionally not copied.
            if let Some(id) = self.entity(
                "tool-capability",
                "mcp-server-config",
                &name,
                path,
                "observed",
                STRONG,
                &[ev.clone()],
                &[("command", command), ("transport", transport.into())],
            ) {
                if let Some(a) = &artifact {
                    self.relation(
                        "loads",
                        a,
                        &id,
                        "observed",
                        STRONG,
                        &[ev.clone()],
                        "inventory-bytes",
                    );
                }
                self.entrypoint_subkinds
                    .entry("mcp-config".into())
                    .or_default()
                    .insert(id);
                self.note_domain("mcp-agent", "mcp server configuration found", &[ev]);
            }
        }
    }

    /// Actors and trust boundaries exist only because entrypoints of that kind
    /// exist; they are `assumed`, cite the implying entrypoint evidence, and make
    /// no claim about authentication or enforcement.
    fn synthesize_actors_and_boundaries(&mut self) {
        let table: [(&str, &str, &str); 9] = [
            (
                "http-route",
                "untrusted-network-client",
                "network-to-service",
            ),
            ("webhook", "third-party-sender", "third-party-to-service"),
            ("cli", "local-user-or-script", "user-to-process"),
            (
                "ipc-command",
                "webview-or-renderer-content",
                "renderer-to-privileged-core",
            ),
            (
                "mcp-tool",
                "agent-model-and-prompt-content",
                "agent-to-tool-host",
            ),
            ("queue-consumer", "message-producer", "broker-to-consumer"),
            ("scheduled-job", "scheduler", "scheduler-to-job"),
            ("ci-trigger", "repository-event-actor", "event-to-ci-runner"),
            (
                "mcp-config",
                "workspace-content-author",
                "workspace-config-to-host",
            ),
        ];
        let subkinds = self.entrypoint_subkinds.clone();
        for (sub, actor, boundary) in table {
            let Some(ids) = subkinds.get(sub) else {
                continue;
            };
            let refs: Vec<String> = ids
                .iter()
                .filter_map(|id| self.entities.get(id))
                .flat_map(|e| e.evidence_refs.clone())
                .collect();
            let Some(a) = self.entity(
                "actor",
                sub,
                actor,
                "repository",
                "assumed",
                POSSIBLE,
                &refs,
                &[("impliedBy", format!("{sub} entrypoints"))],
            ) else {
                continue;
            };
            let Some(tb) = self.entity(
                "trust-boundary",
                sub,
                boundary,
                "repository",
                "assumed",
                POSSIBLE,
                &refs,
                &[("impliedBy", format!("{sub} entrypoints"))],
            ) else {
                continue;
            };
            for id in ids.clone() {
                let ev = self
                    .entities
                    .get(&id)
                    .map(|e| e.evidence_refs.clone())
                    .unwrap_or_default();
                self.relation(
                    "reaches",
                    &a,
                    &id,
                    "assumed",
                    POSSIBLE,
                    &ev,
                    "inventory-bytes",
                );
                self.relation(
                    "crosses",
                    &id,
                    &tb,
                    "assumed",
                    POSSIBLE,
                    &ev,
                    "inventory-bytes",
                );
            }
        }
    }

    fn relate_reachability(&mut self, input: &SurfaceModelInput<'_>) {
        let mut adjacency: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
        let mut graph_used = false;
        match input.graph {
            None => self.gap(
                "graph-context-absent",
                "no graph context supplied; cross-file reachability from entrypoints to assets is not modelled",
                false,
                &[],
            ),
            Some(g) => {
                let bound_digest = scoped_bytes_digest(input.files);
                if g.freshness != "bound-to-frozen-covered-bytes" || g.scoped_bytes_digest != bound_digest {
                    self.gap(
                        "graph-context-unbound",
                        "graph context is not bound to the frozen bytes; its edges were ignored",
                        false,
                        &[],
                    );
                } else {
                    graph_used = true;
                    if g.truncated {
                        self.gap(
                            "graph-truncated",
                            "graph context is truncated; cross-file reachability is incomplete",
                            true,
                            &[],
                        );
                    }
                    if !g.unknowns.is_empty() {
                        let paths: Vec<String> =
                            g.unknowns.iter().filter_map(|u| u.path.clone()).collect();
                        self.gap(
                            "graph-unknowns",
                            "graph context reported unresolved edges; reachability may be incomplete",
                            false,
                            &paths,
                        );
                    }
                    let mut edges: Vec<_> = g
                        .edges
                        .iter()
                        .filter(|e| matches!(e.kind.as_str(), "imports" | "calls" | "implements"))
                        .collect();
                    edges.sort_by(|a, b| (&a.from, &a.to, &a.kind).cmp(&(&b.from, &b.to, &b.kind)));
                    for e in edges {
                        let certain = e.confidence == "certain" && e.source == "blueprint";
                        let ev = self.evidence(
                            &e.evidence.path,
                            e.evidence.start_line as usize,
                            e.evidence.end_line.max(e.evidence.start_line) as usize,
                            &e.evidence.source_digest,
                        );
                        adjacency
                            .entry(e.from.clone())
                            .or_default()
                            .push((e.to.clone(), ev, certain));
                    }
                }
            }
        }

        let entrypoints = self.entrypoints.clone();
        for (ep_id, ep_path) in entrypoints {
            let ep_refs = self
                .entities
                .get(&ep_id)
                .map(|e| e.evidence_refs.clone())
                .unwrap_or_default();
            // BFS over files; each queue item carries the edge-evidence chain and weakest strength.
            let mut seen: BTreeSet<String> = BTreeSet::new();
            let mut queue: VecDeque<(String, Vec<String>, bool, usize)> = VecDeque::new();
            seen.insert(ep_path.clone());
            queue.push_back((ep_path.clone(), Vec::new(), true, 0));
            while let Some((file, chain, all_certain, depth)) = queue.pop_front() {
                if let Some(assets) = self.asset_files.get(&file).cloned() {
                    for asset in assets {
                        let asset_refs = self
                            .entities
                            .get(&asset)
                            .map(|e| e.evidence_refs.clone())
                            .unwrap_or_default();
                        let mut refs = ep_refs.clone();
                        refs.extend(asset_refs);
                        refs.extend(chain.iter().cloned());
                        if depth == 0 {
                            // Same file only: co-location, not proof the handler touches the asset.
                            self.relation(
                                "reaches",
                                &ep_id,
                                &asset,
                                "inferred",
                                POSSIBLE,
                                &refs,
                                "inventory-bytes",
                            );
                        } else {
                            let s = if all_certain { STRONG } else { POSSIBLE };
                            self.relation(
                                "reaches",
                                &ep_id,
                                &asset,
                                "inferred",
                                s,
                                &refs,
                                "graph-context",
                            );
                        }
                    }
                }
                if depth >= MAX_GRAPH_DEPTH {
                    if adjacency
                        .get(&file)
                        .is_some_and(|v| v.iter().any(|(t, _, _)| !seen.contains(t)))
                    {
                        self.gap(
                            "graph-depth-limit",
                            "reachability search stopped at the hop limit; deeper paths are not modelled",
                            false,
                            &[ep_path.clone()],
                        );
                    }
                    continue;
                }
                if let Some(next) = adjacency.get(&file) {
                    for (to, ev, certain) in next.clone() {
                        if seen.insert(to.clone()) {
                            let mut c = chain.clone();
                            c.push(ev);
                            queue.push_back((to, c, all_certain && certain, depth + 1));
                        }
                    }
                }
            }
        }
        self.graph_used = graph_used;
    }

    fn finish(mut self, input: &SurfaceModelInput<'_>) -> SecurityModel {
        let graph_used = self.graph_used;

        const DOMAINS: &[(&str, &str)] = &[
            ("http-service", "http-routes"),
            ("webhooks", "webhook-routes"),
            ("native-desktop", "native-ipc-surfaces"),
            ("cli", "cli-entrypoints"),
            ("mcp-agent", "mcp-surfaces"),
            ("queue-processing", "queue-consumers"),
            ("scheduled-automation", "scheduled-jobs"),
            ("ci-cd", "ci-workflow-evidence"),
            ("mobile", "mobile-manifests"),
            ("smart-contract", "contract-sources"),
            ("cloud-iac", "iac-and-container-files"),
        ];
        let mut applicability = Vec::new();
        for (domain, denom_kind) in DOMAINS {
            let refs: Vec<String> = self
                .applic_evidence
                .get(domain)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            let reasons: Vec<String> = self
                .applic_reason
                .get(domain)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            let applicable = !refs.is_empty();
            applicability.push(DomainApplicability {
                domain_id: (*domain).into(),
                status: if applicable {
                    "applicable"
                } else {
                    "not-evidenced"
                }
                .into(),
                selected_because: reasons,
                denominator: Denominator {
                    kind: (*denom_kind).into(),
                    count: refs.len() as u64,
                    digest: bytes_digest(refs.join("\n").as_bytes()),
                },
                evidence_refs: refs,
            });
        }

        // Drop evidence not referenced by any entity, relation or applicability row.
        let mut used: BTreeSet<&str> = BTreeSet::new();
        for e in self.entities.values() {
            used.extend(e.evidence_refs.iter().map(String::as_str));
        }
        for r in self.relations.values() {
            used.extend(r.evidence_refs.iter().map(String::as_str));
        }
        for a in &applicability {
            used.extend(a.evidence_refs.iter().map(String::as_str));
        }
        let evidence: Vec<EvidenceRef> = self
            .evidence
            .values()
            .filter(|e| used.contains(e.id.as_str()))
            .cloned()
            .collect();

        let scoped = scoped_bytes_digest(input.files);
        let plan_bound = input
            .plan_digest
            .map(str::trim)
            .is_some_and(|d| !d.is_empty());
        let gaps: Vec<ModelGap> = self.gaps.values().cloned().collect();
        let complete = !gaps.iter().any(|g| g.blocking) && !self.truncated;
        let mut model = SecurityModel {
            schema_version: SCHEMA_VERSION.into(),
            kind: MODEL_KIND.into(),
            provider: PROVIDER_ID.into(),
            binding: ModelBinding {
                repository_id: input.inventory.repository_id.clone(),
                repository_revision: input.repository_revision.into(),
                inventory_digest: input.inventory.digest.clone(),
                inventory_generation: input.inventory.generation.clone(),
                inventory_schema_version: input.inventory.schema_version,
                scoped_bytes_digest: scoped,
                plan_digest: input.plan_digest.map(str::to_string),
                cortex_generation_id: input.cortex_generation_id.map(str::to_string),
                plan_bound,
                graph: input.graph.map(|g| GraphBinding {
                    contract_version: g.contract_version.clone(),
                    scoped_bytes_digest: g.scoped_bytes_digest.clone(),
                    coverage_floor: g.coverage_floor.clone(),
                    freshness: g.freshness.clone(),
                    truncated: g.truncated,
                    used: graph_used,
                }),
            },
            entities: self.entities.into_values().collect(),
            relations: self.relations.into_values().collect(),
            evidence,
            applicability,
            gaps,
            coverage: ModelCoverage {
                inventory_entries: input.inventory.entries.len() as u64,
                files_scanned: self.files_scanned,
                files_skipped: self.files_skipped,
                truncated: self.truncated,
                complete,
            },
            digest: String::new(),
        };
        let bytes = serde_json::to_vec(&model).expect("security model serialization is infallible");
        model.digest = bytes_digest(&bytes);
        model
    }
}

// ---------------------------------------------------------------------------
// Helpers

fn is_route_line(line: &str) -> bool {
    let p = patterns();
    p.js_route.is_match(line)
        || p.py_decorator_route.is_match(line)
        || p.rs_attr_route.is_match(line)
        || p.rs_axum_route.is_match(line)
        || p.go_route.is_match(line)
}

/// A guard-like token on the declaration line, or on up to `GUARD_WINDOW`
/// preceding lines (decorators/attributes) that belong to the same
/// declaration: the walk stops at a blank line or another route declaration.
fn guard_token(lines: &[&str], idx: usize) -> Option<String> {
    let p = patterns();
    let find = |l: &str| -> Option<String> {
        (l.len() <= MAX_LINE_CHARS)
            .then(|| p.guard.captures(l).map(|c| c[1].to_ascii_lowercase()))
            .flatten()
    };
    if let Some(t) = find(lines[idx]) {
        return Some(t);
    }
    let start = idx.saturating_sub(GUARD_WINDOW);
    for l in lines[start..idx].iter().rev() {
        if l.trim().is_empty() || is_route_line(l) {
            break;
        }
        if let Some(t) = find(l) {
            return Some(t);
        }
    }
    None
}

fn k8s_like(lower_path: &str) -> bool {
    lower_path.ends_with(".yaml") || lower_path.ends_with(".yml")
}

/// Next.js file-convention routes: `pages/api/**` and `app/**/route.{ts,js,tsx}`.
fn nextjs_route(lower_path: &str) -> Option<String> {
    let strip_ext = |s: &str| -> Option<String> {
        for ext in [".ts", ".tsx", ".js", ".jsx", ".mjs"] {
            if let Some(stem) = s.strip_suffix(ext) {
                return Some(stem.to_string());
            }
        }
        None
    };
    let segments: Vec<&str> = lower_path.split('/').collect();
    if let Some(pos) = segments
        .windows(2)
        .position(|w| w[0] == "pages" && w[1] == "api")
    {
        let rest = segments[pos + 1..].join("/");
        let stem = strip_ext(&rest)?;
        let stem = stem.strip_suffix("/index").unwrap_or(&stem).to_string();
        return Some(format!("/{stem}"));
    }
    let last = segments.last()?;
    if strip_ext(last).as_deref() == Some("route") {
        let pos = segments.iter().position(|s| *s == "app")?;
        let mid = &segments[pos + 1..segments.len() - 1];
        let mid: Vec<&str> = mid
            .iter()
            .copied()
            .filter(|s| !(s.starts_with('(') && s.ends_with(')')))
            .collect();
        return Some(format!("/{}", mid.join("/")));
    }
    None
}
