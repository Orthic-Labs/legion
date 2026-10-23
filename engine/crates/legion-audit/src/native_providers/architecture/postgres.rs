//! A10: PostgreSQL migration-safety facts and isolated-workload evidence.
//!
//! Source half: [`analyze_postgres`] classifies migration SQL using the
//! declared/derived server version, migration order, transaction scope and
//! the phase (expand/contract) the caller declares. It is a lexical parser,
//! not a planner: production cardinality, runtime plans, dynamic SQL, unknown
//! `search_path` and unavailable schema are *gaps*, never clean.
//!
//! Evidence half: [`assess_evidence`] judges authenticated A03 imports
//! (isolated migration, EXPLAIN/workload, contention, backup-restore,
//! client compatibility). This module never opens a connection, never reads
//! a discovered `DATABASE_URL`, and keeps only one-way host fingerprints of
//! URLs it sees ([`discovered_database_fingerprints`]) so evidence aimed at a
//! repository-referenced database is refused.
//!
//! Root integration: `pub mod postgres;` in `architecture/mod.rs`; call
//! [`analyze_postgres`] from the `framework.data` producer path and attach
//! [`PostgresAnalysis::into_analysis`] gaps/facts.

use super::common::{gap, Analysis};
use crate::{
    artifact_evidence::{EvidenceOutcome, ImportKind, ImportVerdict},
    assurance::ObligationStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const CONCERN_ISOLATED_MIGRATION: &str = "postgres.isolated-migration";
pub const CONCERN_EXPLAIN_PLAN: &str = "postgres.explain-plan";
pub const CONCERN_WORKLOAD_MEASURED: &str = "postgres.workload-measured";
pub const CONCERN_CONTENTION: &str = "postgres.contention";
pub const CONCERN_BACKUP_RESTORE: &str = "postgres.backup-restore";
pub const CONCERN_CLIENT_COMPAT: &str = "postgres.client-compat";

pub const DEFAULT_MAX_STATEMENT_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_MAX_LOCK_TIMEOUT_MS: u64 = 5_000;
/// Tables measured below this row count are not flagged for lock-duration
/// findings; unmeasured tables stay a cardinality gap.
pub const SMALL_TABLE_ROWS: u64 = 10_000;

// ---------------------------------------------------------------- inputs

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresSourceFile {
    pub path: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationPhase {
    Expand,
    Contract,
}

#[derive(Clone, Debug, Default)]
pub struct PostgresContext {
    /// Declared/measured server major version. `None` keeps version-dependent
    /// rules as gaps. Falls back to a single version derived from source.
    pub server_major: Option<u32>,
    /// Session/role search_path when known.
    pub search_path: Option<Vec<String>>,
    /// Tables guaranteed to exist before the first migration.
    pub baseline_tables: BTreeSet<String>,
    /// Declared phase per migration path (A10 never guesses intent).
    pub phases: BTreeMap<String, MigrationPhase>,
    /// Contract migrations whose old/new compatibility has authenticated
    /// evidence (see [`assess_evidence`] with [`CONCERN_CLIENT_COMPAT`]).
    pub contract_compat_verified: BTreeSet<String>,
    /// Framework fact: migration path -> runner wraps it in one transaction.
    pub transaction_wrapped: BTreeMap<String, bool>,
    /// Runner/role sets lock_timeout for migrations.
    pub lock_timeout_declared: bool,
    /// Measured row counts from authenticated workload evidence.
    pub table_rows: BTreeMap<String, u64>,
}

// --------------------------------------------------------------- outputs

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostgresFinding {
    pub rule: String,
    pub severity: String,
    /// `definite` or `conditional` (depends on unmeasured cardinality/runtime).
    pub confidence: String,
    pub path: String,
    pub line: usize,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct PostgresAnalysis {
    pub applicable: bool,
    pub findings: Vec<PostgresFinding>,
    pub gaps: BTreeSet<String>,
    pub facts: Value,
    pub migrations_expected: usize,
    pub migrations_parsed: usize,
}

impl PostgresAnalysis {
    /// Convert to the shared provider shape. A not-applicable result is still
    /// `unproven`: applicability is the producer's typed absence, not ours.
    pub fn into_analysis(self) -> Analysis {
        let complete = self.applicable && self.gaps.is_empty();
        let mut analysis = Analysis::new(
            if complete { "pass" } else { "unproven" },
            complete,
            json!({"kind":"postgres-migrations","expected":self.migrations_expected,
                   "examined":self.migrations_parsed}),
        );
        analysis.findings = self
            .findings
            .iter()
            .map(|f| {
                json!({"id": format!("postgres:{}:{}:{}", f.rule, f.path, f.line),
                       "rule": f.rule, "severity": f.severity, "confidence": f.confidence,
                       "path": f.path, "line": f.line, "message": f.message})
            })
            .collect();
        analysis.coverage_gaps = self.gaps.iter().map(|kind| gap(kind)).collect();
        if !self.applicable {
            analysis.coverage_gaps.push(gap("postgres-not-detected"));
            analysis.complete = false;
            analysis.status = "unproven".into();
        }
        analysis.extras.insert("postgres".into(), self.facts);
        analysis
    }
}

// ------------------------------------------------------------- tokenizer

#[derive(Debug)]
struct Stmt {
    line: usize,
    tokens: Vec<String>,
    bodies: Vec<String>,
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn finish(
    norm: &mut String,
    bodies: &mut Vec<String>,
    start: &mut usize,
    out: &mut Vec<Stmt>,
) {
    let tokens: Vec<String> = norm.split_whitespace().map(str::to_owned).collect();
    if !tokens.is_empty() {
        out.push(Stmt {
            line: (*start).max(1),
            tokens,
            bodies: std::mem::take(bodies),
        });
    }
    norm.clear();
    bodies.clear();
    *start = 0;
}

fn split_statements(sql: &str) -> Vec<Stmt> {
    let c: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut norm = String::new();
    let mut bodies: Vec<String> = Vec::new();
    let (mut i, mut line, mut start) = (0usize, 1usize, 0usize);
    while i < c.len() {
        let ch = c[i];
        if ch == '\n' {
            line += 1;
            norm.push(' ');
            i += 1;
            continue;
        }
        if ch == '-' && c.get(i + 1) == Some(&'-') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && c.get(i + 1) == Some(&'*') {
            let mut depth = 1;
            i += 2;
            while i < c.len() && depth > 0 {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if c[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            norm.push(' ');
            continue;
        }
        if start == 0 && !ch.is_whitespace() && ch != ';' {
            start = line;
        }
        match ch {
            '\\' if norm.trim().is_empty() => {
                // psql meta-command: never executed or classified here.
                let mut word = String::new();
                while i < c.len() && c[i] != '\n' {
                    word.push(c[i]);
                    i += 1;
                }
                norm.push_str("\\meta ");
                norm.push_str(&word.to_lowercase());
                finish(&mut norm, &mut bodies, &mut start, &mut out);
            }
            ';' => {
                finish(&mut norm, &mut bodies, &mut start, &mut out);
                i += 1;
            }
            '\'' => {
                let escapes = i > 0
                    && matches!(c[i - 1], 'e' | 'E')
                    && (i < 2 || !is_ident(c[i - 2]));
                i += 1;
                while i < c.len() {
                    if escapes && c[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if c[i] == '\n' {
                        line += 1;
                    }
                    if c[i] == '\'' {
                        if c.get(i + 1) == Some(&'\'') {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                norm.push_str(" '' ");
            }
            '"' => {
                i += 1;
                let mut ident = String::new();
                while i < c.len() && c[i] != '"' {
                    ident.push(if c[i].is_whitespace() { '_' } else { c[i] });
                    i += 1;
                }
                i += 1;
                norm.push(' ');
                norm.push_str(&ident.to_lowercase());
                norm.push(' ');
            }
            '$' if !(i > 0 && is_ident(c[i - 1])) => {
                let mut j = i + 1;
                while j < c.len() && is_ident(c[j]) {
                    j += 1;
                }
                let tag_ok = c.get(j) == Some(&'$')
                    && !c.get(i + 1).is_some_and(|d| d.is_ascii_digit());
                if !tag_ok {
                    norm.push(' ');
                    norm.push('$');
                    i += 1;
                    continue;
                }
                let tag: Vec<char> = c[i..=j].to_vec();
                let body_start = j + 1;
                let mut k = body_start;
                let mut end = c.len();
                while k + tag.len() <= c.len() {
                    if c[k..k + tag.len()] == tag[..] {
                        end = k;
                        break;
                    }
                    k += 1;
                }
                let body: String = c[body_start..end.min(c.len())].iter().collect();
                line += body.matches('\n').count();
                bodies.push(body);
                norm.push_str(" $$ ");
                i = (end + tag.len()).min(c.len());
            }
            '(' | ')' | ',' | '=' | '<' | '>' => {
                norm.push(' ');
                norm.push(ch);
                norm.push(' ');
                i += 1;
            }
            _ => {
                for lower in ch.to_lowercase() {
                    norm.push(lower);
                }
                i += 1;
            }
        }
    }
    finish(&mut norm, &mut bodies, &mut start, &mut out);
    out
}

fn seq(t: &[String], pat: &[&str]) -> Option<usize> {
    if pat.is_empty() || t.len() < pat.len() {
        return None;
    }
    (0..=t.len() - pat.len()).find(|&i| pat.iter().enumerate().all(|(k, p)| t[i + k] == *p))
}

fn has(t: &[String], pat: &[&str]) -> bool {
    seq(t, pat).is_some()
}

fn has_word(t: &[String], word: &str) -> bool {
    t.iter().any(|x| x == word)
}

fn canon_rel(s: &str) -> String {
    s.strip_prefix("public.").unwrap_or(s).to_owned()
}

fn rel_at(t: &[String], mut i: usize) -> Option<(String, usize)> {
    while i < t.len()
        && matches!(
            t[i].as_str(),
            "if" | "exists" | "not" | "only" | "concurrently" | "unique" | "table"
        )
    {
        i += 1;
    }
    t.get(i)
        .filter(|s| s.as_str() != "(" && s.as_str() != "$$")
        .map(|s| (canon_rel(s), i))
}

fn clauses(t: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut depth = 0i32;
    for token in t {
        match token.as_str() {
            "(" => depth += 1,
            ")" => depth -= 1,
            _ => {}
        }
        if token == "," && depth == 0 {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(token.clone());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn builtin_relation(name: &str) -> bool {
    name.starts_with("pg_")
        || name.starts_with("information_schema.")
        || name.starts_with("pg_catalog.")
        || name.starts_with("auth.")
        || name.starts_with("storage.")
        || name.starts_with("extensions.")
}

// ---------------------------------------------------- migration identity

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OrderKey(Vec<u128>);

fn order_key_for(path: &str) -> Option<OrderKey> {
    let mut parts: Vec<&str> = path.split('/').collect();
    let file = parts.pop()?;
    let stem = file.split('.').next().unwrap_or(file);
    let name = if matches!(stem, "migration" | "up" | "down" | "up_sql") {
        parts.pop().unwrap_or(stem)
    } else {
        stem
    };
    let name = name.strip_prefix(['V', 'v']).unwrap_or(name);
    let mut digits = String::new();
    let chars: Vec<char> = name.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch.is_ascii_digit() || ch == '.' {
            digits.push(ch);
        } else if ch == '_' {
            if chars.get(i + 1) == Some(&'_') || !chars.get(i + 1).is_some_and(|n| n.is_ascii_digit())
            {
                break;
            }
            digits.push('.');
        } else {
            break;
        }
        i += 1;
    }
    let nums: Vec<u128> = digits
        .split('.')
        .filter(|part| !part.is_empty() && part.len() <= 30)
        .filter_map(|part| part.parse().ok())
        .collect();
    (!nums.is_empty()).then_some(OrderKey(nums))
}

fn is_down_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".down.sql")
        || lower.ends_with("/down.sql")
        || lower.contains("/down/")
        || lower.ends_with("_down.sql")
}

fn is_migration_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.ends_with(".sql") {
        return false;
    }
    lower.split('/').any(|part| {
        part.starts_with("migrat") || part == "flyway" || part == "sqitch"
    }) || lower
        .rsplit('/')
        .next()
        .is_some_and(|f| f.starts_with('v') && f.contains("__"))
}

fn framework_of(path: &str, text: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("prisma/migrations") {
        Some("prisma")
    } else if lower.contains("supabase/migrations") {
        Some("supabase")
    } else if text.contains("-- +goose") {
        Some("goose")
    } else if text.contains("-- migrate:") {
        Some("dbmate")
    } else if lower.ends_with(".up.sql") || lower.ends_with(".down.sql") {
        Some("golang-migrate")
    } else if lower
        .rsplit('/')
        .next()
        .is_some_and(|f| f.starts_with(['V', 'v']) && f.contains("__"))
    {
        Some("flyway")
    } else if lower.contains("drizzle") {
        Some("drizzle")
    } else {
        None
    }
}

fn nonsql_framework(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let segs: Vec<&str> = lower.split('/').collect();
    let file = segs.last().copied().unwrap_or("");
    if lower.contains("db/migrate/") && file.ends_with(".rb") {
        Some("rails")
    } else if lower.contains("alembic/versions/") && file.ends_with(".py") {
        Some("alembic")
    } else if (lower.contains("/migrations/") || lower.starts_with("migrations/"))
        && (file.ends_with(".js") || file.ends_with(".ts") || file.ends_with(".cjs") || file.ends_with(".mjs"))
        && file.chars().next().is_some_and(|c| c.is_ascii_digit())
    {
        Some("js-migration")
    } else if file.starts_with('0') && lower.contains("/migrations/") && file.ends_with(".py") {
        Some("django")
    } else {
        None
    }
}

fn up_section(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let (up, down) = if lower.contains("-- +goose") {
        ("-- +goose up", "-- +goose down")
    } else if lower.contains("-- migrate:") {
        ("-- migrate:up", "-- migrate:down")
    } else {
        return text.to_owned();
    };
    let start = lower.find(up).map(|p| p + up.len()).unwrap_or(0);
    let end = lower[start..].find(down).map(|p| p + start).unwrap_or(text.len());
    text[start..end].to_owned()
}

fn versions_in(text: &str) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let lower = text.to_ascii_lowercase();
    for marker in [
        "postgres:", "postgresql:", "postgis/postgis:", "postgresql@", "postgresql-",
        "postgres_version=", "postgres_version:", "pg_version=",
    ] {
        let mut rest = lower.as_str();
        while let Some(pos) = rest.find(marker) {
            let after = &rest[pos + marker.len()..];
            let digits: String = after
                .trim_start_matches(['"', '\'', ' '])
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(v) = digits.parse::<u32>() {
                if (9..=30).contains(&v) {
                    out.insert(v);
                }
            }
            rest = after;
        }
    }
    for line in lower.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("major_version") {
            let digits: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
            if let Ok(v) = digits.parse::<u32>() {
                if (9..=30).contains(&v) {
                    out.insert(v);
                }
            }
        }
    }
    out
}

fn pg_hint(path: &str, text: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let t = text.to_ascii_lowercase();
    lower.ends_with(".sql")
        && (t.contains("create extension")
            || t.contains("plpgsql")
            || t.contains("row level security")
            || t.contains("security definer")
            || t.contains("create policy")
            || t.contains("concurrently")
            || t.contains("timestamptz")
            || t.contains("jsonb")
            || t.contains("serial")
            || t.contains("gen_random_uuid"))
        || t.contains("postgres://")
        || t.contains("postgresql://")
        || t.contains("image: postgres")
        || t.contains("from postgres:")
        || t.contains("\"pg\"")
        || t.contains("psycopg")
        || t.contains("sqlx")
}

// -------------------------------------------------------------- analyzer

struct Analyzer<'a> {
    ctx: &'a PostgresContext,
    version: Option<u32>,
    findings: Vec<PostgresFinding>,
    gaps: BTreeSet<String>,
    created: BTreeMap<String, usize>,
    unknown_origin: BTreeSet<String>,
    rls_enabled: BTreeSet<String>,
    policies: BTreeSet<String>,
    definer_fns: BTreeSet<String>,
    staged: BTreeMap<(String, String), (bool, bool)>,
    pgcrypto: bool,
}

impl<'a> Analyzer<'a> {
    fn push(&mut self, rule: &str, sev: &str, conf: &str, path: &str, line: usize, msg: String) {
        self.findings.push(PostgresFinding {
            rule: rule.into(),
            severity: sev.into(),
            confidence: conf.into(),
            path: path.into(),
            line,
            message: msg,
        });
    }

    /// `Some(true/false)` when the version is known, else a gap.
    fn at_least(&mut self, min: u32, why: &str) -> Option<bool> {
        match self.version {
            Some(v) => Some(v >= min),
            None => {
                self.gaps.insert(format!("postgres-version-unknown:{why}"));
                None
            }
        }
    }

    fn small(&self, table: &str) -> bool {
        self.ctx
            .table_rows
            .get(table)
            .is_some_and(|rows| *rows < SMALL_TABLE_ROWS)
    }

    fn cardinality(&mut self, table: &str) {
        if !self.ctx.table_rows.contains_key(table) {
            self.gaps.insert(format!("table-cardinality-unknown:{table}"));
        }
    }

    fn destructive(&mut self, kind: &str, path: &str, line: usize, what: &str) {
        let ctx = self.ctx;
        match ctx.phases.get(path) {
            Some(MigrationPhase::Contract) => {
                if !ctx.contract_compat_verified.contains(path) {
                    self.push(
                        "contract-step-without-compat-evidence",
                        "warning",
                        "definite",
                        path,
                        line,
                        format!("{kind} ({what}) in a contract migration has no authenticated old/new client compatibility evidence"),
                    );
                }
            }
            Some(MigrationPhase::Expand) => self.push(
                "destructive-in-expand-phase",
                "error",
                "definite",
                path,
                line,
                format!("{kind} ({what}) is destructive but the migration is declared expand-only"),
            ),
            None => self.push(
                "destructive-change-unclassified",
                "warning",
                "conditional",
                path,
                line,
                format!("{kind} ({what}) destroys data or schema; migration phase is not declared"),
            ),
        }
    }

    fn breaking_shape(&mut self, kind: &str, path: &str, line: usize, what: &str) {
        let ctx = self.ctx;
        match ctx.phases.get(path) {
            Some(MigrationPhase::Contract) if ctx.contract_compat_verified.contains(path) => {}
            _ => self.push(
                "old-client-incompatible-change",
                "warning",
                "conditional",
                path,
                line,
                format!("{kind} ({what}) breaks readers/writers of the previous schema unless a compatibility layer and contract phase evidence exist"),
            ),
        }
    }
}

const VOLATILE_DEFAULTS: &[&str] = &[
    "random", "clock_timestamp", "timeofday", "nextval", "gen_random_uuid", "uuid_generate_v4",
    "uuid_generate_v1", "gen_random_bytes", "txid_current", "setseed",
];

fn default_is_volatile(clause: &[String]) -> bool {
    let Some(d) = clause.iter().position(|x| x == "default") else {
        return false;
    };
    clause[d + 1..]
        .iter()
        .any(|tok| VOLATILE_DEFAULTS.iter().any(|v| tok == v || tok.starts_with(&format!("{v}("))))
        || clause.iter().any(|x| x == "serial" || x == "bigserial" || x == "smallserial")
}

/// Derive facts and findings from migration/config sources. Never executes
/// SQL. `files` should be the frozen-denominator text of the repository.
pub fn analyze_postgres(files: &[PostgresSourceFile], ctx: &PostgresContext) -> PostgresAnalysis {
    let mut gaps: BTreeSet<String> = BTreeSet::new();
    let applicable = files.iter().any(|f| pg_hint(&f.path, &f.text));

    let mut versions = BTreeSet::new();
    for f in files {
        let lower = f.path.to_ascii_lowercase();
        if lower.ends_with(".yml")
            || lower.ends_with(".yaml")
            || lower.ends_with(".toml")
            || lower.ends_with("dockerfile")
            || lower.contains("tool-versions")
            || lower.ends_with(".env.example")
            || lower.contains("docker-compose")
        {
            versions.extend(versions_in(&f.text));
        }
    }
    let version = ctx.server_major.or_else(|| {
        if versions.len() == 1 {
            versions.iter().next().copied()
        } else {
            None
        }
    });
    if ctx.server_major.is_none() && versions.len() > 1 {
        gaps.insert("postgres-version-conflict".into());
    }

    let mut frameworks = BTreeSet::new();
    let mut migrations: Vec<(OrderKey, String, String)> = Vec::new();
    let mut total = 0usize;
    for f in files {
        if let Some(name) = nonsql_framework(&f.path) {
            frameworks.insert(name.to_owned());
            total += 1;
            gaps.insert(format!("migration-framework-nonsql:{name}"));
            continue;
        }
        if !is_migration_path(&f.path) || is_down_path(&f.path) {
            continue;
        }
        total += 1;
        if let Some(name) = framework_of(&f.path, &f.text) {
            frameworks.insert(name.to_owned());
        }
        match order_key_for(&f.path) {
            Some(key) => migrations.push((key, f.path.clone(), up_section(&f.text))),
            None => {
                gaps.insert(format!("migration-order-unknown:{}", f.path));
            }
        }
    }
    migrations.sort();
    let mut duplicate_versions = Vec::new();

    let mut an = Analyzer {
        ctx,
        version,
        findings: Vec::new(),
        gaps,
        created: BTreeMap::new(),
        unknown_origin: BTreeSet::new(),
        rls_enabled: BTreeSet::new(),
        policies: BTreeSet::new(),
        definer_fns: BTreeSet::new(),
        staged: BTreeMap::new(),
        pgcrypto: false,
    };
    for pair in migrations.windows(2) {
        if pair[0].0 == pair[1].0 {
            duplicate_versions.push(pair[1].1.clone());
            an.push(
                "duplicate-migration-version",
                "error",
                "definite",
                &pair[1].1,
                1,
                format!("same version as {}; apply order is ambiguous", pair[0].1),
            );
        }
    }

    // Pass 1: object creation order.
    let parsed: Vec<Vec<Stmt>> = migrations.iter().map(|m| split_statements(&m.2)).collect();
    for (idx, stmts) in parsed.iter().enumerate() {
        for s in stmts {
            let t = &s.tokens;
            if t.len() > 2 && t[0] == "create" && !has(t, &["temp"]) && !has(t, &["temporary"]) {
                if let Some(p) = seq(t, &["table"]) {
                    if let Some((name, _)) = rel_at(t, p + 1) {
                        an.created.entry(name).or_insert(idx);
                    }
                }
            }
            if has(t, &["create", "extension"]) && t.iter().any(|x| x == "pgcrypto") {
                an.pgcrypto = true;
            }
        }
    }

    // Pass 2.
    let mut parsed_ok = 0usize;
    let mut tables_created = BTreeSet::new();
    for (idx, stmts) in parsed.iter().enumerate() {
        let path = migrations[idx].1.clone();
        parsed_ok += 1;
        check_migration(&mut an, idx, &path, stmts, &mut tables_created);
    }

    for table in &an.rls_enabled.clone() {
        if !an.policies.contains(table) {
            an.gaps.insert(format!("rls-enabled-without-policy-in-set:{table}"));
        }
    }
    if !an.unknown_origin.is_empty() {
        an.gaps.insert(format!("object-origin-unknown:{}", an.unknown_origin.len()));
    }
    if versions.is_empty() && ctx.server_major.is_none() {
        an.gaps.insert("postgres-version-unknown".into());
    }

    let facts = json!({
        "applicable": applicable,
        "serverMajor": version,
        "declaredVersions": versions,
        "frameworks": frameworks,
        "migrationOrder": migrations.iter().map(|m| m.1.clone()).collect::<Vec<_>>(),
        "duplicateVersions": duplicate_versions,
        "tablesCreated": tables_created,
        "rlsEnabledTables": an.rls_enabled,
        "policyTables": an.policies,
        "definerFunctions": an.definer_fns,
        "contractVerified": ctx.contract_compat_verified,
        "bound": "lexical-source-only: no production cardinality, runtime plan, or schema state",
    });
    PostgresAnalysis {
        applicable,
        findings: an.findings,
        gaps: an.gaps,
        facts,
        migrations_expected: total,
        migrations_parsed: parsed_ok.min(total),
    }
}

fn check_migration(
    an: &mut Analyzer<'_>,
    idx: usize,
    path: &str,
    stmts: &[Stmt],
    tables_created: &mut BTreeSet<String>,
) {
    let ctx = an.ctx;
    let wrapped = ctx.transaction_wrapped.get(path).copied();
    let mut in_txn = false;
    let mut here: BTreeSet<String> = BTreeSet::new();
    let mut search_path_pinned = false;
    let mut lock_timeout = ctx.lock_timeout_declared;
    let mut unqualified_ddl = false;
    let mut lock_gap_reported = false;

    for s in stmts {
        let t = &s.tokens;
        let line = s.line;
        let first = t[0].as_str();
        let others = stmts.len() > 1;

        if first == "\\meta" {
            an.gaps.insert(format!("psql-meta-command:{path}"));
            continue;
        }
        if t.iter().any(|x| x.contains("{{") || x.contains("${") || x.contains("<%")) {
            an.gaps.insert(format!("templated-sql:{path}"));
        }
        if matches!(first, "begin" | "start") {
            in_txn = true;
            continue;
        }
        if matches!(first, "commit" | "end" | "rollback" | "abort") {
            in_txn = false;
            continue;
        }
        if first == "set" || has(t, &["set_config"]) {
            if has(t, &["search_path"]) {
                search_path_pinned = true;
            }
            if has(t, &["lock_timeout"]) {
                lock_timeout = true;
            }
            continue;
        }

        // Dynamic / opaque SQL.
        let bodies_dynamic = s.bodies.iter().any(|b| {
            b.to_ascii_lowercase()
                .split(|c: char| !is_ident(c))
                .any(|w| w == "execute")
        });
        if bodies_dynamic {
            an.gaps.insert(format!("dynamic-sql:{path}:{line}"));
        }
        if first == "do" {
            let opaque = s.bodies.iter().any(|b| {
                let l = b.to_ascii_lowercase();
                ["alter ", "drop ", "create ", "truncate ", "grant ", "revoke "]
                    .iter()
                    .any(|k| l.contains(k))
            });
            if opaque && !bodies_dynamic {
                an.gaps.insert(format!("opaque-procedural-ddl:{path}:{line}"));
            }
        }
        if first == "execute" || first == "prepare" {
            an.gaps.insert(format!("dynamic-sql:{path}:{line}"));
        }

        // Version-gated syntax.
        let joined = t.join(" ");
        let need = |min: u32, why: &str, an: &mut Analyzer<'_>| {
            if an.at_least(min, why) == Some(false) {
                let v = an.version.unwrap_or(0);
                an.push(
                    "syntax-unsupported-by-target-version",
                    "error",
                    "definite",
                    path,
                    line,
                    format!("{why} requires PostgreSQL {min}+, target is {v}"),
                );
            }
        };
        if joined.contains(") include (") && has(t, &["index"]) {
            need(11, "INCLUDE columns", an);
        }
        if joined.contains("nulls not distinct") {
            need(15, "NULLS NOT DISTINCT", an);
        }
        if first == "merge" {
            need(15, "MERGE", an);
        }
        if has(t, &["generated", "always", "as"]) && has_word(t, "stored") {
            need(12, "generated stored columns", an);
        }
        if has(t, &["detach", "partition"]) && has_word(t, "concurrently") {
            need(14, "DETACH PARTITION CONCURRENTLY", an);
        }
        if joined.contains("uuidv7") {
            need(18, "uuidv7()", an);
        }
        if first == "create" && has(t, &["procedure"]) || first == "call" {
            need(11, "procedures/CALL", an);
        }
        if joined.contains("gen_random_uuid") && !an.pgcrypto {
            if let Some(false) = an.at_least(13, "gen_random_uuid") {
                an.push(
                    "syntax-unsupported-by-target-version",
                    "error",
                    "definite",
                    path,
                    line,
                    "gen_random_uuid() is core only in 13+; create extension pgcrypto earlier in the set".into(),
                );
            }
        }

        // Non-transactional statements.
        let concurrent = has_word(t, "concurrently");
        let non_txn = (first == "create" && has_word(t, "index") && concurrent)
            || (first == "drop" && has_word(t, "index") && concurrent)
            || (first == "reindex" && concurrent)
            || first == "vacuum"
            || (has(t, &["create", "database"]) || has(t, &["drop", "database"]))
            || has(t, &["alter", "system"])
            || (has(t, &["alter", "type"]) && has(t, &["add", "value"]))
            || (has(t, &["detach", "partition"]) && concurrent);
        if non_txn {
            let alter_enum = has(t, &["alter", "type"]);
            let block_cannot = if alter_enum {
                an.version.map(|v| v < 12)
            } else {
                Some(true)
            };
            if in_txn && block_cannot == Some(true) {
                an.push(
                    "non-transactional-statement-in-transaction",
                    "error",
                    "definite",
                    path,
                    line,
                    "statement cannot run inside a transaction block but the migration opened one".into(),
                );
            } else if alter_enum && block_cannot.is_none() && in_txn {
                an.gaps.insert("postgres-version-unknown:alter-type-add-value".into());
            } else if !in_txn && block_cannot == Some(true) {
                match wrapped {
                    Some(true) => an.push(
                        "non-transactional-statement-in-transaction",
                        "error",
                        "definite",
                        path,
                        line,
                        "migration runner wraps this file in one transaction; the statement needs a non-transactional migration".into(),
                    ),
                    Some(false) => {}
                    None => {
                        an.gaps.insert(format!("transaction-wrapper-unknown:{path}"));
                    }
                }
                if others && wrapped != Some(false) {
                    an.gaps.insert(format!("multi-statement-submission-unknown:{path}"));
                }
            }
        }

        // Relation ordering references.
        let mut refs: Vec<String> = Vec::new();
        if first == "alter" && has(t, &["table"]) {
            if let Some(p) = seq(t, &["table"]) {
                if let Some((r, _)) = rel_at(t, p + 1) {
                    refs.push(r);
                }
            }
        }
        if first == "create" && has_word(t, "index") {
            if let Some(p) = t.iter().position(|x| x == "on") {
                if let Some((r, _)) = rel_at(t, p + 1) {
                    refs.push(r);
                }
            }
        }
        if first == "create" && has_word(t, "policy") {
            if let Some(p) = t.iter().position(|x| x == "on") {
                if let Some((r, _)) = rel_at(t, p + 1) {
                    refs.push(r);
                }
            }
        }
        for (p, x) in t.iter().enumerate() {
            if x == "references" {
                if let Some((r, _)) = rel_at(t, p + 1) {
                    refs.push(r);
                }
            }
        }
        for r in refs {
            if ctx.baseline_tables.contains(&r) || builtin_relation(&r) {
                continue;
            }
            match an.created.get(&r).copied() {
                Some(ci) if ci > idx || (ci == idx && !here.contains(&r)) => an.push(
                    "migration-later-object-order",
                    "error",
                    "definite",
                    path,
                    line,
                    format!("{r} is created by a later migration/statement than this reference"),
                ),
                Some(_) => {}
                None => {
                    an.unknown_origin.insert(r);
                }
            }
        }
        if let Some(p) = seq(t, &["table"]) {
            if let Some((r, _)) = rel_at(t, p + 1) {
                if !r.contains('.') && !builtin_relation(&r) {
                    unqualified_ddl = true;
                }
            }
        }

        // CREATE TABLE
        if first == "create" && has_word(t, "table") && !has_word(t, "temp") && !has_word(t, "temporary") {
            if let Some(p) = seq(t, &["table"]) {
                if let Some((r, _)) = rel_at(t, p + 1) {
                    here.insert(r.clone());
                    tables_created.insert(r);
                }
            }
        }

        // CREATE INDEX
        if first == "create" && has_word(t, "index") {
            if let Some(p) = t.iter().position(|x| x == "on") {
                if let Some((table, _)) = rel_at(t, p + 1) {
                    if !concurrent && !here.contains(&table) && !an.small(&table) {
                        an.cardinality(&table);
                        an.push(
                            "index-build-blocks-writes",
                            "warning",
                            "conditional",
                            path,
                            line,
                            format!("CREATE INDEX on existing {table} without CONCURRENTLY blocks writes for the build; harmless only for small/new tables"),
                        );
                    }
                }
            }
        }

        // DROP / TRUNCATE / DELETE / UPDATE
        if first == "drop" && has_word(t, "table") && !has_word(t, "temp") {
            if let Some(p) = seq(t, &["table"]) {
                if let Some((r, _)) = rel_at(t, p + 1) {
                    if !here.contains(&r) {
                        an.destructive("DROP TABLE", path, line, &r);
                    }
                }
            }
        }
        if first == "drop" && has_word(t, "schema") {
            an.destructive("DROP SCHEMA", path, line, "schema");
        }
        if first == "truncate" {
            an.destructive("TRUNCATE", path, line, "table data");
        }
        if first == "delete" && has_word(t, "from") && !has_word(t, "where") {
            an.destructive("DELETE without WHERE", path, line, "all rows");
        }
        if first == "update" && !has_word(t, "where") {
            let table = rel_at(t, 1).map(|x| x.0).unwrap_or_default();
            if !here.contains(&table) && !an.small(&table) {
                an.cardinality(&table);
                an.push(
                    "unbounded-update",
                    "warning",
                    "conditional",
                    path,
                    line,
                    format!("UPDATE without WHERE on {table} holds row locks for the whole statement; batch large backfills"),
                );
            }
        }

        // ALTER TABLE
        if first == "alter" && has_word(t, "table") && !has(t, &["alter", "table", "all"]) {
            if let Some(p) = seq(t, &["table"]) {
                if let Some((table, ti)) = rel_at(t, p + 1) {
                    let new_here = here.contains(&table);
                    if !new_here && !table.contains('.') {
                        unqualified_ddl = true;
                    }
                    if !new_here && !lock_timeout && !lock_gap_reported {
                        an.gaps.insert(format!("lock-timeout-unset:{path}"));
                        lock_gap_reported = true;
                    }
                    for clause in clauses(&t[ti + 1..]) {
                        check_alter_clause(an, path, line, &table, new_here, &clause);
                    }
                }
            }
        }
        if first == "alter" && (has_word(t, "view") || has_word(t, "function") || has_word(t, "index"))
            && has(t, &["rename", "to"])
        {
            an.breaking_shape("RENAME", path, line, "object");
        }

        // Security
        if first == "create" && has_word(t, "function") && has(t, &["security", "definer"]) {
            let name = seq(t, &["function"]).and_then(|p| rel_at(t, p + 1)).map(|x| x.0).unwrap_or_default();
            an.definer_fns.insert(name.clone());
            let pinned = has(t, &["set", "search_path"]);
            if !pinned {
                an.push(
                    "definer-searchpath-unpinned",
                    "error",
                    "definite",
                    path,
                    line,
                    format!("SECURITY DEFINER function {name} has no SET search_path; callers can shadow referenced objects"),
                );
            }
            an.gaps.insert(format!("execute-acl-unproven:{name}"));
        }
        if first == "grant" && has_word(t, "execute") {
            if let Some(f) = seq(t, &["function"]).and_then(|p| rel_at(t, p + 1)).map(|x| x.0) {
                if an.definer_fns.contains(&f) && (has_word(t, "public") || has_word(t, "anon")) {
                    an.push(
                        "definer-execute-granted-to-public",
                        "warning",
                        "conditional",
                        path,
                        line,
                        format!("SECURITY DEFINER {f} is executable by an untrusted role; confirm intended audience"),
                    );
                }
            }
        }
        if first == "grant"
            && !has_word(t, "execute")
            && has_word(t, "on")
            && (has(t, &["to", "public"]) || has(t, &["to", "anon"]))
        {
            an.push(
                "public-object-grant",
                "warning",
                "conditional",
                path,
                line,
                "privilege granted to PUBLIC/anon; confirm RLS or intended exposure".into(),
            );
        }
        if first == "create" && has_word(t, "policy") {
            if let Some(p) = t.iter().position(|x| x == "on") {
                if let Some((table, _)) = rel_at(t, p + 1) {
                    an.policies.insert(table.clone());
                    let permissive_true = has(t, &["using", "(", "true", ")"])
                        || has(t, &["check", "(", "true", ")"]);
                    let broad_role = !has_word(t, "to")
                        || has(t, &["to", "public"])
                        || has(t, &["to", "anon"])
                        || has(t, &["to", "authenticated"]);
                    if permissive_true && broad_role {
                        an.push(
                            "permissive-rls-policy",
                            "error",
                            "definite",
                            path,
                            line,
                            format!("policy on {table} allows every row to a broad role (TRUE predicate)"),
                        );
                    }
                    // Enable may appear later in the same set (checked at the end).
                    if !an.rls_enabled.contains(&table)
                        && !an.created.contains_key(&table)
                        && !here.contains(&table)
                    {
                        an.gaps.insert(format!("rls-enable-state-unknown:{table}"));
                    }
                }
            }
        }
        if first == "alter" && has(t, &["row", "level", "security"]) {
            if let Some(p) = seq(t, &["table"]) {
                if let Some((table, _)) = rel_at(t, p + 1) {
                    if has_word(t, "disable") {
                        an.rls_enabled.remove(&table);
                        an.push(
                            "rls-disabled",
                            "warning",
                            "definite",
                            path,
                            line,
                            format!("row level security disabled on {table}"),
                        );
                    } else if has_word(t, "enable") {
                        an.rls_enabled.insert(table);
                    }
                }
            }
        }
    }

    // Policies on tables never enabled within the set (inert unless enabled elsewhere).
    let inert: Vec<String> = an
        .policies
        .iter()
        .filter(|t| !an.rls_enabled.contains(*t) && an.created.contains_key(*t))
        .cloned()
        .collect();
    for table in inert {
        an.gaps.insert(format!("policy-without-rls-enable:{table}"));
    }
    if unqualified_ddl && !search_path_pinned && ctx.search_path.is_none() {
        an.gaps.insert(format!("search-path-unknown:{path}"));
    }
}

fn check_alter_clause(
    an: &mut Analyzer<'_>,
    path: &str,
    line: usize,
    table: &str,
    new_here: bool,
    c: &[String],
) {
    if c.is_empty() {
        return;
    }
    let small = an.small(table);
    match c[0].as_str() {
        "add" => {
            let second = c.get(1).map(String::as_str).unwrap_or("");
            let is_constraint = matches!(
                second,
                "constraint" | "check" | "unique" | "primary" | "foreign" | "exclude"
            );
            if is_constraint {
                let not_valid = has(c, &["not", "valid"]);
                let name = if second == "constraint" { c.get(2).cloned().unwrap_or_default() } else { String::new() };
                let is_nn_check = has(c, &["is", "not", "null"]);
                if !name.is_empty() {
                    an.staged.insert((table.to_owned(), name), (is_nn_check, false));
                }
                let kind_fk_check = has_word(c, "foreign") || has_word(c, "check");
                let kind_idx = has_word(c, "unique") || has_word(c, "primary") || has_word(c, "exclude");
                if !new_here && !small {
                    if kind_fk_check && !not_valid {
                        an.cardinality(table);
                        an.push(
                            "constraint-validates-under-lock",
                            "warning",
                            "conditional",
                            path,
                            line,
                            format!("ADD CONSTRAINT on existing {table} validates every row while holding a strong lock; stage with NOT VALID then VALIDATE CONSTRAINT"),
                        );
                    }
                    if kind_idx && !has(c, &["using", "index"]) {
                        an.cardinality(table);
                        an.push(
                            "constraint-index-build-blocks-writes",
                            "warning",
                            "conditional",
                            path,
                            line,
                            format!("unique/primary key on existing {table} builds its index under lock; build CONCURRENTLY first then ADD ... USING INDEX"),
                        );
                    }
                }
                return;
            }
            // ADD COLUMN
            let mut i = 1;
            if c.get(i).map(String::as_str) == Some("column") {
                i += 1;
            }
            if has(c.get(i..).unwrap_or(&[]), &["if", "not", "exists"]) {
                i += 3;
            }
            let col = c.get(i).cloned().unwrap_or_default();
            let ty = c.get(i + 1).cloned().unwrap_or_default();
            let notnull = has(c, &["not", "null"]);
            let has_default = has_word(c, "default");
            let always_stored = has(c, &["generated", "always", "as"]) && has_word(c, "stored");
            let identity = has_word(c, "identity");
            let volatile = default_is_volatile(c);
            if !new_here && !small {
                if volatile || always_stored || identity {
                    an.cardinality(table);
                    an.push(
                        "add-column-table-rewrite",
                        "warning",
                        "conditional",
                        path,
                        line,
                        format!("ADD COLUMN {col} on existing {table} uses a volatile/generated/identity default and rewrites the table under ACCESS EXCLUSIVE"),
                    );
                } else if has_default {
                    match an.at_least(11, "add-column-default") {
                        Some(false) => {
                            an.cardinality(table);
                            an.push(
                                "add-column-table-rewrite",
                                "warning",
                                "conditional",
                                path,
                                line,
                                format!("ADD COLUMN {col} DEFAULT on PostgreSQL <11 rewrites {table}"),
                            );
                        }
                        _ => {}
                    }
                }
            }
            if notnull && !has_default && !new_here && !identity && !ty.starts_with("serial") && !ty.starts_with("bigserial") {
                an.push(
                    "add-not-null-column-without-default",
                    "warning",
                    "conditional",
                    path,
                    line,
                    format!("NOT NULL column {col} without default on existing {table} fails if rows exist and breaks old writers that do not set it"),
                );
            }
            if (has_word(c, "unique") || has(c, &["primary", "key"])) && !new_here && !small {
                an.cardinality(table);
                an.push(
                    "constraint-index-build-blocks-writes",
                    "warning",
                    "conditional",
                    path,
                    line,
                    format!("inline unique/primary key on added column builds an index under lock on {table}"),
                );
            }
            if has_word(c, "references") && !new_here && !small && !has(c, &["not", "valid"]) {
                an.push(
                    "constraint-validates-under-lock",
                    "warning",
                    "conditional",
                    path,
                    line,
                    format!("inline REFERENCES on existing {table} takes a lock to add the foreign key"),
                );
            }
        }
        "drop" => {
            let second = c.get(1).map(String::as_str).unwrap_or("");
            if second == "column" || (second != "constraint" && second != "not") {
                let col = c
                    .iter()
                    .skip(1)
                    .find(|x| !matches!(x.as_str(), "if" | "exists" | "column"))
                    .cloned()
                    .unwrap_or_default();
                an.destructive("DROP COLUMN", path, line, &format!("{table}.{col}"));
            }
        }
        "rename" => {
            an.breaking_shape("RENAME", path, line, table);
        }
        "validate" => {
            if let Some(name) = c.get(2) {
                if let Some(entry) = an.staged.get_mut(&(table.to_owned(), name.clone())) {
                    entry.1 = true;
                }
            }
        }
        "alter" => {
            // ALTER [COLUMN] c ...
            let mut i = 1;
            if c.get(i).map(String::as_str) == Some("column") {
                i += 1;
            }
            let col = c.get(i).cloned().unwrap_or_default();
            let rest = &c[(i + 1).min(c.len())..];
            if has(rest, &["set", "not", "null"]) {
                if new_here || small {
                    return;
                }
                let validated = an
                    .staged
                    .iter()
                    .any(|((t, _), (nn, ok))| t == table && *nn && *ok);
                match an.at_least(12, "set-not-null") {
                    Some(true) if validated => {}
                    Some(_) => {
                        an.cardinality(table);
                        an.push(
                            "set-not-null-full-scan",
                            "warning",
                            "conditional",
                            path,
                            line,
                            format!("SET NOT NULL on {table}.{col} scans the table under ACCESS EXCLUSIVE; on 12+ stage a validated CHECK ({col} IS NOT NULL) first"),
                        );
                    }
                    None => {}
                }
            } else if has(rest, &["type"]) {
                let pos = rest.iter().position(|x| x == "type").unwrap_or(0);
                let to = rest.get(pos + 1).cloned().unwrap_or_default();
                let to_full = if rest.get(pos + 2).map(String::as_str) == Some("(") {
                    format!("{to}({})", rest.get(pos + 3).cloned().unwrap_or_default())
                } else {
                    to.clone()
                };
                // The previous type is unknowable lexically, so a rewrite or
                // narrowing can never be ruled out from source alone.
                if !new_here && !small {
                    an.cardinality(table);
                    an.push(
                        "alter-column-type-rewrite-or-narrowing",
                        "warning",
                        "conditional",
                        path,
                        line,
                        format!("ALTER COLUMN TYPE {table}.{col} -> {to_full}: source cannot show the previous type; may rewrite the table or lose data"),
                    );
                    an.destructive("ALTER COLUMN TYPE", path, line, &format!("{table}.{col}"));
                }
            }
        }
        _ => {}
    }
}

// ------------------------------------------------- URL fingerprints only

/// One-way fingerprints (`sha256:` of `host:port/db`) of every PostgreSQL URL
/// in `text`. The URL, credentials and parameters are never retained, and
/// nothing is connected to. Evidence whose target fingerprint is in this set
/// is refused ([`assess_evidence`]).
pub fn discovered_database_fingerprints(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let lower = text.to_ascii_lowercase();
    for scheme in ["postgres://", "postgresql://"] {
        let mut rest = lower.as_str();
        while let Some(pos) = rest.find(scheme) {
            let after = &rest[pos + scheme.len()..];
            let end = after
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ')' | '<' | '>'))
                .unwrap_or(after.len());
            let url = &after[..end];
            let authority_end = url.find(['/', '?']).unwrap_or(url.len());
            let authority = &url[..authority_end];
            let host = authority.rsplit('@').next().unwrap_or(authority);
            let db = url[authority_end..]
                .trim_start_matches('/')
                .split(['?', '#'])
                .next()
                .unwrap_or("");
            if !host.is_empty() {
                out.insert(host_fingerprint(host, db));
            }
            rest = &after[end..];
        }
    }
    out
}

/// Fingerprint used by evidence producers and this scanner alike.
pub fn host_fingerprint(host_port: &str, database: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            format!("{}/{}", host_port.to_ascii_lowercase(), database.to_ascii_lowercase()).as_bytes()
        ))
    )
}

// ------------------------------------------------------ evidence (A03)

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvidenceTarget {
    /// `scratch` | `approved-worker`; anything else is refused.
    pub kind: String,
    pub isolation_attested: bool,
    pub host_fingerprint: String,
    pub role_superuser: Option<bool>,
    pub role_restricted: bool,
    pub statement_timeout_ms: Option<u64>,
    pub lock_timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvidenceQuery {
    pub id: String,
    pub params_digest: String,
    pub executions: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvidenceWorkload {
    pub read_ops: u64,
    pub write_ops: u64,
    pub duration_ms: u64,
    pub data_distribution_digest: String,
    pub row_counts: BTreeMap<String, u64>,
    pub queries: Vec<EvidenceQuery>,
    /// The producer attests the query list is the complete workload.
    pub denominator_attested: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvidencePlan {
    pub explain: bool,
    /// EXPLAIN ANALYZE (actually executed). Plain EXPLAIN is `false`.
    pub analyze: bool,
    pub query_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvidenceContention {
    pub measured: bool,
    pub concurrent_sessions: u64,
    pub lock_wait_ms_max: Option<u64>,
    pub deadlocks: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvidenceRestore {
    pub restored: bool,
    pub backup_digest: String,
    pub verified_invariants: Vec<String>,
    pub row_counts_match: Option<bool>,
    pub representative_sample_digest: String,
    pub row_counts: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvidenceMigration {
    pub applied: Vec<String>,
    pub failed_statements: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvidenceCompat {
    pub old_client_versions: Vec<String>,
    pub new_client_versions: Vec<String>,
    pub old_passed: bool,
    pub new_passed: bool,
}

/// Structured payload carried inside the retained primary artifact.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PostgresEvidenceFacts {
    pub schema_version: u32,
    pub concern: String,
    pub target: EvidenceTarget,
    pub postgres_version_major: Option<u32>,
    pub postgres_version_full: String,
    pub schema_digest: String,
    pub index_set_digest: String,
    pub migration_head: String,
    pub migration: EvidenceMigration,
    pub plan: EvidencePlan,
    pub workload: EvidenceWorkload,
    pub contention: EvidenceContention,
    pub restore: EvidenceRestore,
    pub compat: EvidenceCompat,
}

#[derive(Clone, Debug, Default)]
pub struct PostgresExpectation {
    pub postgres_major: Option<u32>,
    pub schema_digest: Option<String>,
    pub index_set_digest: Option<String>,
    pub migration_head: Option<String>,
    /// Source-detected query ids: a lower bound, never a complete workload.
    pub required_query_ids: BTreeSet<String>,
    pub required_invariants: BTreeSet<String>,
    pub required_old_clients: BTreeSet<String>,
    pub required_new_clients: BTreeSet<String>,
    pub min_concurrent_sessions: u64,
    /// Fingerprints from [`discovered_database_fingerprints`].
    pub forbidden_host_fingerprints: BTreeSet<String>,
    pub max_statement_timeout_ms: Option<u64>,
    pub max_lock_timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObligationAssessment {
    pub concern: String,
    pub status: String,
    pub reasons: Vec<String>,
    /// True only when workload/contention/restore was actually executed.
    pub measured_execution: bool,
    pub evidence_id: Option<String>,
}

impl ObligationAssessment {
    pub fn obligation_status(&self) -> ObligationStatus {
        match self.status.as_str() {
            "satisfied" => ObligationStatus::Satisfied,
            "findings" => ObligationStatus::Findings,
            _ => ObligationStatus::Unmet,
        }
    }
}

fn required_kind(concern: &str) -> Option<ImportKind> {
    match concern {
        CONCERN_ISOLATED_MIGRATION | CONCERN_BACKUP_RESTORE => Some(ImportKind::Runtime),
        CONCERN_EXPLAIN_PLAN | CONCERN_WORKLOAD_MEASURED | CONCERN_CONTENTION => {
            Some(ImportKind::Performance)
        }
        CONCERN_CLIENT_COMPAT => Some(ImportKind::Test),
        _ => None,
    }
}

fn unmet(concern: &str, reasons: Vec<String>, id: Option<String>) -> ObligationAssessment {
    ObligationAssessment {
        concern: concern.into(),
        status: "unmet".into(),
        reasons,
        measured_execution: false,
        evidence_id: id,
    }
}

/// Judge one authenticated import against `expect`. Anything missing,
/// replayed, unauthenticated, wrong-version, wrong-schema or aimed at a
/// repository-referenced database leaves the obligation `unmet`.
pub fn assess_evidence(
    concern: &str,
    verdict: &ImportVerdict,
    artifact_bytes: &[u8],
    expect: &PostgresExpectation,
) -> ObligationAssessment {
    let Some(kind) = required_kind(concern) else {
        return unmet(concern, vec!["unknown-concern".into()], None);
    };
    let Some(record) = verdict.record.as_ref() else {
        let mut reasons = vec!["evidence-missing".to_owned()];
        reasons.extend(verdict.reasons.clone());
        return unmet(concern, reasons, None);
    };
    let id = Some(record.evidence_id.clone());
    let mut reasons: Vec<String> = Vec::new();
    if !(verdict.authenticated && verdict.satisfies_obligation && record.authenticated) {
        reasons.push("evidence-not-authenticated-or-incomplete".into());
        reasons.extend(verdict.reasons.clone());
        return unmet(concern, reasons, id);
    }
    if record.kind != kind {
        reasons.push("kind-mismatch".into());
    }
    if !record.newly_executed || record.replay_of.is_some() {
        reasons.push("replayed-evidence-is-not-fresh-execution".into());
    }
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(artifact_bytes)));
    if digest != record.artifact_digest {
        reasons.push("artifact-digest-mismatch".into());
    }
    let facts: PostgresEvidenceFacts = match serde_json::from_slice(artifact_bytes) {
        Ok(facts) => facts,
        Err(_) => {
            reasons.push("artifact-unparseable".into());
            return unmet(concern, reasons, id);
        }
    };
    if facts.schema_version != 1 {
        reasons.push("unsupported-facts-schema".into());
    }
    if facts.concern != concern {
        reasons.push("concern-mismatch".into());
    }

    // Target safety: declared isolated scratch/worker only.
    let tg = &facts.target;
    if !matches!(tg.kind.as_str(), "scratch" | "approved-worker") {
        reasons.push("target-not-declared-isolated".into());
    }
    if !tg.isolation_attested {
        reasons.push("target-isolation-unattested".into());
    }
    if tg.host_fingerprint.is_empty() {
        reasons.push("target-fingerprint-missing".into());
    } else if expect.forbidden_host_fingerprints.contains(&tg.host_fingerprint) {
        reasons.push("target-is-repository-referenced-database".into());
    }
    if tg.role_superuser != Some(false) || !tg.role_restricted {
        reasons.push("target-role-not-restricted".into());
    }
    let max_stmt = expect.max_statement_timeout_ms.unwrap_or(DEFAULT_MAX_STATEMENT_TIMEOUT_MS);
    let max_lock = expect.max_lock_timeout_ms.unwrap_or(DEFAULT_MAX_LOCK_TIMEOUT_MS);
    match tg.statement_timeout_ms {
        Some(ms) if ms > 0 && ms <= max_stmt => {}
        _ => reasons.push("statement-timeout-unbounded".into()),
    }
    match tg.lock_timeout_ms {
        Some(ms) if ms > 0 && ms <= max_lock => {}
        _ => reasons.push("lock-timeout-unbounded".into()),
    }

    // Version / schema binding.
    match (expect.postgres_major, facts.postgres_version_major) {
        (Some(want), Some(got)) if want == got => {}
        (None, _) => reasons.push("expected-postgres-version-unavailable".into()),
        _ => reasons.push("postgres-version-mismatch".into()),
    }
    match &expect.schema_digest {
        Some(want) if *want == facts.schema_digest && !want.is_empty() => {}
        Some(_) => reasons.push("schema-digest-mismatch".into()),
        None => reasons.push("expected-schema-digest-unavailable".into()),
    }
    if let Some(want) = &expect.index_set_digest {
        if *want != facts.index_set_digest {
            reasons.push("index-set-digest-mismatch".into());
        }
    }
    if let Some(want) = &expect.migration_head {
        if *want != facts.migration_head {
            reasons.push("migration-head-mismatch".into());
        }
    }

    let mut measured = false;
    match concern {
        CONCERN_ISOLATED_MIGRATION => {
            if facts.migration.applied.is_empty() {
                reasons.push("no-migrations-applied".into());
            }
            if facts.migration.failed_statements != Some(0) {
                reasons.push("migration-failures-unproven-absent".into());
            }
            measured = !facts.migration.applied.is_empty();
        }
        CONCERN_EXPLAIN_PLAN => {
            if !facts.plan.explain {
                reasons.push("no-explain-output".into());
            }
            let covered: BTreeSet<&String> = facts.plan.query_ids.iter().collect();
            if expect.required_query_ids.iter().any(|q| !covered.contains(q)) {
                reasons.push("detected-queries-without-plan".into());
            }
            // A plan alone is never measured execution.
            measured = facts.plan.analyze;
        }
        CONCERN_WORKLOAD_MEASURED => {
            let w = &facts.workload;
            if w.read_ops + w.write_ops == 0 || w.duration_ms == 0 {
                reasons.push("no-measured-operations".into());
            }
            if w.data_distribution_digest.is_empty() {
                reasons.push("data-distribution-unrecorded".into());
            }
            if w.row_counts.is_empty() {
                reasons.push("row-counts-unrecorded".into());
            }
            if w.queries.is_empty() || w.queries.iter().any(|q| q.executions == 0 || q.params_digest.is_empty()) {
                reasons.push("query-executions-or-parameters-unrecorded".into());
            }
            let covered: BTreeSet<&String> = w.queries.iter().map(|q| &q.id).collect();
            if expect.required_query_ids.iter().any(|q| !covered.contains(q)) {
                reasons.push("detected-queries-not-in-workload".into());
            }
            if !w.denominator_attested {
                // Source detection is only a lower bound of real workload.
                reasons.push("workload-denominator-unattested".into());
            }
            if facts.plan.explain && !facts.plan.analyze && w.read_ops + w.write_ops == 0 {
                reasons.push("plan-only-is-not-measured-execution".into());
            }
            measured = w.read_ops + w.write_ops > 0;
        }
        CONCERN_CONTENTION => {
            let c = &facts.contention;
            if !c.measured {
                reasons.push("contention-not-measured".into());
            }
            if c.concurrent_sessions < expect.min_concurrent_sessions.max(2) {
                reasons.push("insufficient-concurrent-sessions".into());
            }
            if c.lock_wait_ms_max.is_none() || c.deadlocks.is_none() {
                reasons.push("lock-waits-or-deadlocks-unrecorded".into());
            }
            measured = c.measured;
        }
        CONCERN_BACKUP_RESTORE => {
            let r = &facts.restore;
            if !r.restored {
                // Backup existence is insufficient.
                reasons.push("restore-not-performed".into());
            }
            if r.backup_digest.is_empty() {
                reasons.push("backup-identity-missing".into());
            }
            if r.representative_sample_digest.is_empty() || r.row_counts.is_empty() {
                reasons.push("restored-data-not-representative".into());
            }
            if r.row_counts_match != Some(true) {
                reasons.push("restored-row-counts-unproven".into());
            }
            let got: BTreeSet<&String> = r.verified_invariants.iter().collect();
            if r.verified_invariants.is_empty() || expect.required_invariants.iter().any(|i| !got.contains(i)) {
                reasons.push("restore-invariants-unverified".into());
            }
            measured = r.restored;
        }
        CONCERN_CLIENT_COMPAT => {
            let c = &facts.compat;
            let old: BTreeSet<&String> = c.old_client_versions.iter().collect();
            let new: BTreeSet<&String> = c.new_client_versions.iter().collect();
            if old.is_empty()
                || new.is_empty()
                || expect.required_old_clients.iter().any(|v| !old.contains(v))
                || expect.required_new_clients.iter().any(|v| !new.contains(v))
            {
                reasons.push("client-versions-not-covered".into());
            }
            if !(c.old_passed && c.new_passed) {
                reasons.push("client-compat-not-proven".into());
            }
            measured = true;
        }
        _ => {}
    }

    if !reasons.is_empty() {
        return unmet(concern, reasons, id);
    }
    let status = match record.outcome {
        EvidenceOutcome::Passed => "satisfied",
        EvidenceOutcome::Failed | EvidenceOutcome::Findings => "findings",
        EvidenceOutcome::Error => {
            return unmet(concern, vec!["evidence-outcome-error".into()], id);
        }
    };
    ObligationAssessment {
        concern: concern.into(),
        status: status.into(),
        reasons: Vec::new(),
        measured_execution: measured,
        evidence_id: id,
    }
}
