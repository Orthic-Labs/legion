//! Bounded semantic pattern cards selected by the existing audit lenses.
//!
//! Cards sharpen correctness, schema, data-safety, security, and performance
//! review. They do not add lenses or replace the runtime's existing provider
//! triggers. Each card requires a source trace, names a falsifier, and keeps
//! an unresolved trace explicitly unknown.

use serde_json::{json, Value};

/// Source-language restrictions a card declares. They describe fit by file
/// extension only and never claim parser equivalence: unknown or unrecognized
/// source keeps a card as `unknown`, never `excluded`. Framework, version, and
/// trigger fit still require review; they cannot exclude a card.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanguageApplicability {
    JavaScriptOrTypeScript,
    Swift,
    Kotlin,
    Rust,
    Sql,
    /// Tauri applications: Rust commands, the web front end, and JSON/TOML configuration.
    TauriSurface,
}

impl LanguageApplicability {
    /// Language labels emitted into the packet.
    pub fn languages(self) -> &'static [&'static str] {
        match self {
            Self::JavaScriptOrTypeScript => &["javascript", "typescript"],
            Self::Swift => &["swift"],
            Self::Kotlin => &["kotlin"],
            Self::Rust => &["rust"],
            Self::Sql => &["sql"],
            Self::TauriSurface => &["rust", "typescript", "javascript", "json", "toml"],
        }
    }

    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::JavaScriptOrTypeScript => &[".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"],
            Self::Swift => &[".swift"],
            Self::Kotlin => &[".kt", ".kts"],
            Self::Rust => &[".rs"],
            Self::Sql => &[".sql"],
            Self::TauriSurface => &[
                ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".toml",
            ],
        }
    }

    fn reasons(self) -> (&'static str, &'static str) {
        match self {
            Self::JavaScriptOrTypeScript => (
                "selected-source-includes-javascript-typescript",
                "selected-source-languages-exclude-javascript-typescript",
            ),
            Self::Swift => (
                "selected-source-includes-swift",
                "selected-source-languages-exclude-swift",
            ),
            Self::Kotlin => (
                "selected-source-includes-kotlin",
                "selected-source-languages-exclude-kotlin",
            ),
            Self::Rust => (
                "selected-source-includes-rust",
                "selected-source-languages-exclude-rust",
            ),
            Self::Sql => (
                "selected-source-includes-sql",
                "selected-source-languages-exclude-sql",
            ),
            Self::TauriSurface => (
                "selected-source-includes-tauri-surface",
                "selected-source-languages-exclude-tauri-surface",
            ),
        }
    }
}

/// Extensions recognized well enough to exclude a card whose language does
/// not match. Everything else (SQL, configuration, extensionless files)
/// leaves a language-restricted card `unknown`.
const RECOGNIZED_SOURCE_EXTENSIONS: &[&str] = &[
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".rs", ".swift", ".py", ".kt", ".kts", ".java",
];

/// Evidence tier of a domain-grouped card. Groups select cards from path-level
/// inventory evidence (file kinds, manifests, directory and file names); they
/// never claim framework or dependency equivalence. Path evidence can only
/// raise a group to `retained`; it can never prove a domain absent for a
/// common group, so unproven applicability stays `unknown`, never `excluded`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainTier {
    /// Common web/native/AI surfaces. Weak or absent path evidence keeps the
    /// card `unknown` and in the packet.
    Common,
    /// Specialist domains (smart contracts, embedded, ICS/OT). Apply only on
    /// strong path evidence; excluded only when every selected path is a
    /// recognized source kind and none carries domain evidence.
    Specialist,
}

/// Evidence-selected security card groups. The always-on core (secrets,
/// injection, authorization, unsafe code, Tauri, serialization) carries no
/// group; every card with a group is selected from path evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainEvidence {
    Ssrf,
    HttpProxyCache,
    AuthSession,
    WorkspaceTrust,
    AiMemory,
    AdminWorkflow,
    SmartContract,
    Embedded,
    Ics,
}

struct DomainSignals {
    /// File extensions (lowercase, with dot).
    extensions: &'static [&'static str],
    /// File-name prefixes (lowercase) such as `foundry.toml`.
    basenames: &'static [&'static str],
    /// Whole path tokens (split on non-alphanumerics).
    tokens: &'static [&'static str],
    /// Path-token prefixes of at least five characters.
    token_prefixes: &'static [&'static str],
}

impl DomainEvidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ssrf => "ssrf-egress",
            Self::HttpProxyCache => "http-proxy-cache",
            Self::AuthSession => "auth-session",
            Self::WorkspaceTrust => "workspace-trust",
            Self::AiMemory => "ai-memory-rag",
            Self::AdminWorkflow => "admin-workflow",
            Self::SmartContract => "smart-contract",
            Self::Embedded => "embedded-iot",
            Self::Ics => "ics-ot",
        }
    }

    pub fn tier(self) -> DomainTier {
        match self {
            Self::SmartContract | Self::Embedded | Self::Ics => DomainTier::Specialist,
            _ => DomainTier::Common,
        }
    }

    fn signals(self) -> DomainSignals {
        match self {
            Self::Ssrf => DomainSignals {
                extensions: &[],
                basenames: &[],
                tokens: &[
                    "fetch", "webhook", "webhooks", "egress", "unfurl", "oembed", "crawler",
                    "scraper", "callback", "download", "preview", "proxy",
                ],
                token_prefixes: &[
                    "httpclient",
                    "http_client",
                    "webhook",
                    "import_url",
                    "remote_url",
                ],
            },
            Self::HttpProxyCache => DomainSignals {
                extensions: &[".vcl"],
                basenames: &[
                    "nginx",
                    "haproxy",
                    "envoy",
                    "caddyfile",
                    "varnish",
                    "traefik",
                    "httpd.conf",
                    "apache",
                ],
                tokens: &[
                    "proxy",
                    "gateway",
                    "cdn",
                    "cache",
                    "ingress",
                    "nginx",
                    "haproxy",
                    "envoy",
                    "caddy",
                    "varnish",
                    "traefik",
                    "cloudfront",
                    "rewrite",
                ],
                token_prefixes: &["reverse_proxy"],
            },
            Self::AuthSession => DomainSignals {
                extensions: &[],
                basenames: &[],
                tokens: &[
                    "auth",
                    "login",
                    "logout",
                    "signin",
                    "signup",
                    "session",
                    "sessions",
                    "mfa",
                    "totp",
                    "otp",
                    "oauth",
                    "oidc",
                    "saml",
                    "password",
                    "passwords",
                    "recovery",
                    "reset",
                    "jwt",
                    "passkey",
                    "webauthn",
                    "credential",
                    "credentials",
                ],
                token_prefixes: &["authn", "authent", "refresh_token", "magic_link"],
            },
            Self::WorkspaceTrust => DomainSignals {
                extensions: &[],
                basenames: &[
                    ".env",
                    ".envrc",
                    ".mcp.json",
                    "mcp.json",
                    "tauri.conf",
                    "lefthook",
                    "pre-commit",
                    "tasks.json",
                    "devcontainer",
                ],
                tokens: &[
                    "hooks",
                    "husky",
                    "githooks",
                    "mcp",
                    "devcontainer",
                    "direnv",
                    "workspace",
                    "plugin",
                    "plugins",
                    "extension",
                    "extensions",
                    "vscode",
                    "claude",
                    "cursor",
                ],
                token_prefixes: &["project_config", "workspace_trust"],
            },
            Self::AiMemory => DomainSignals {
                extensions: &[],
                basenames: &[],
                tokens: &[
                    "rag",
                    "embedding",
                    "embeddings",
                    "vector",
                    "vectors",
                    "vectorstore",
                    "memory",
                    "retriever",
                    "retrieval",
                    "chroma",
                    "pinecone",
                    "qdrant",
                    "weaviate",
                    "pgvector",
                    "faiss",
                    "langchain",
                    "llamaindex",
                    "corpus",
                    "llm",
                ],
                token_prefixes: &["retriev", "embedd", "vector_store", "knowledge_base"],
            },
            Self::AdminWorkflow => DomainSignals {
                extensions: &[],
                basenames: &[],
                tokens: &[
                    "admin",
                    "admins",
                    "impersonate",
                    "impersonation",
                    "backoffice",
                    "support",
                    "staff",
                    "moderation",
                    "moderator",
                    "bulk",
                    "refund",
                    "refunds",
                    "operator",
                ],
                token_prefixes: &[
                    "impersonat",
                    "back_office",
                    "customer_support",
                    "bulk_action",
                ],
            },
            Self::SmartContract => DomainSignals {
                extensions: &[".sol", ".vy", ".cairo", ".fe"],
                basenames: &[
                    "foundry.toml",
                    "hardhat.config",
                    "truffle-config",
                    "anchor.toml",
                    "move.toml",
                    "brownie-config",
                    "slither.config",
                ],
                tokens: &[],
                token_prefixes: &[],
            },
            Self::Embedded => DomainSignals {
                extensions: &[".ino", ".dts", ".dtsi", ".ld", ".s19", ".ioc"],
                basenames: &[
                    "platformio.ini",
                    "sdkconfig",
                    "prj.conf",
                    "west.yml",
                    "kconfig",
                    "partitions.csv",
                    "openocd",
                    "cubemx",
                ],
                tokens: &[
                    "firmware",
                    "bootloader",
                    "mcuboot",
                    "freertos",
                    "zephyr",
                    "esp32",
                    "stm32",
                    "nrf52",
                    "uboot",
                    "jtag",
                    "swd",
                    "fota",
                ],
                token_prefixes: &["ota_update", "ota-update", "esp_idf", "esp-idf"],
            },
            Self::Ics => DomainSignals {
                extensions: &[".scl", ".l5x", ".l5k", ".plcproj", ".fbd"],
                basenames: &[],
                tokens: &[
                    "modbus",
                    "opcua",
                    "dnp3",
                    "iec61850",
                    "iec104",
                    "profinet",
                    "scada",
                    "plc",
                    "hmi",
                    "interlock",
                    "interlocks",
                    "ladder",
                ],
                token_prefixes: &[
                    "opc_ua",
                    "opc-ua",
                    "iec_61850",
                    "iec-61131",
                    "iec61131",
                    "ethernet_ip",
                ],
            },
        }
    }

    /// True when the path carries evidence for this group.
    pub fn path_matches(self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        let signals = self.signals();
        if signals.extensions.iter().any(|ext| lower.ends_with(ext)) {
            return true;
        }
        let basename = lower.rsplit('/').next().unwrap_or(&lower);
        if signals
            .basenames
            .iter()
            .any(|name| basename.starts_with(name))
        {
            return true;
        }
        lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|token| !token.is_empty())
            .any(|token| {
                signals.tokens.contains(&token)
                    || signals
                        .token_prefixes
                        .iter()
                        .any(|prefix| token.starts_with(prefix))
            })
            || signals
                .token_prefixes
                .iter()
                .any(|prefix| prefix.contains(['-', '_']) && lower.contains(prefix))
    }

    fn fit(self, paths: &[&str]) -> (&'static str, &'static str) {
        if paths.is_empty() {
            return ("unknown", "selected-source-paths-empty");
        }
        if paths.iter().any(|path| self.path_matches(path)) {
            return ("retained", "domain-path-evidence-present");
        }
        match self.tier() {
            DomainTier::Common => ("unknown", "domain-evidence-not-established-by-paths"),
            DomainTier::Specialist => {
                let all_recognized = paths.iter().all(|path| {
                    let lower = path.to_ascii_lowercase();
                    RECOGNIZED_SOURCE_EXTENSIONS
                        .iter()
                        .any(|extension| lower.ends_with(extension))
                });
                if all_recognized {
                    ("excluded", "specialist-domain-evidence-absent")
                } else {
                    ("unknown", "selected-source-language-unknown")
                }
            }
        }
    }
}

/// Rule maturity. Authored cards start as `Draft`. Only a root-owned,
/// independently measured qualification record may move a card; routing,
/// packet binding, and fixture tests never promote a card.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleMaturity {
    Draft,
    Shadow,
    Qualified,
}

impl RuleMaturity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Shadow => "shadow",
            Self::Qualified => "qualified",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PatternCard {
    pub version: &'static str,
    pub id: &'static str,
    pub owner_lens: &'static str,
    pub applicability: &'static str,
    pub language_applicability: Option<LanguageApplicability>,
    /// Framework/toolchain version fit. Prose guide only; absent version
    /// evidence yields `unknown`, never a finding or a clean result.
    pub version_applicability: Option<&'static str>,
    /// Configuration evidence the card reads, when it needs any.
    pub config_applicability: Option<&'static str>,
    /// Inventory-evidence group that selects this card. `None` keeps the card
    /// in the always-on core of its owner lens.
    pub domain_evidence: Option<DomainEvidence>,
    pub trigger_evidence: &'static str,
    pub required_source_trace: &'static str,
    pub falsifier: &'static str,
    pub no_evidence: &'static str,
    pub positive_case: &'static str,
    pub negative_case: &'static str,
    pub maturity: RuleMaturity,
}

impl PatternCard {
    /// Defaults for fields most cards leave unset.
    pub const BASE: PatternCard = PatternCard {
        version: "1",
        id: "",
        owner_lens: "",
        applicability: "",
        language_applicability: None,
        version_applicability: None,
        config_applicability: None,
        domain_evidence: None,
        trigger_evidence: "",
        required_source_trace: "",
        falsifier: "",
        no_evidence: "",
        positive_case: "",
        negative_case: "",
        maturity: RuleMaturity::Draft,
    };

    fn to_packet_value(self) -> Value {
        let mut value = json!({
            "version": self.version,
            "id": self.id,
            "ownerLens": self.owner_lens,
            "applicability": self.applicability,
            "ruleMaturity": self.maturity.as_str(),
            "triggerEvidence": self.trigger_evidence,
            "requiredSourceTrace": self.required_source_trace,
            "falsifier": self.falsifier,
            "noEvidence": self.no_evidence,
            "pairedCases": {
                "positive": self.positive_case,
                "negative": self.negative_case,
            },
        });
        if let Some(language) = self.language_applicability {
            value["languageApplicability"] = json!({"languages": language.languages()});
        }
        if let Some(version) = self.version_applicability {
            value["versionApplicability"] = json!(version);
        }
        if let Some(config) = self.config_applicability {
            value["configApplicability"] = json!(config);
        }
        if let Some(domain) = self.domain_evidence {
            value["domainApplicability"] = json!({
                "group": domain.label(),
                "tier": match domain.tier() {
                    DomainTier::Common => "evidence-selected",
                    DomainTier::Specialist => "specialist-strong-evidence-only",
                },
            });
        }
        value
    }
}

/// Versioned patterns attached only to their existing owning lens.
/// Applicability describes language/framework fit; deterministic provider
/// trigger evaluation remains owned by the frozen plan.
pub const PATTERN_CARDS: &[PatternCard] = &[
    PatternCard {
        version: "1",
        id: "return-key-consumer-migration",
        owner_lens: "correctness",
        applicability: "Serialized key/column changes: object/RPC/endpoint/SQL view/function/table; any producer/consumer language.",
        language_applicability: None,
        trigger_evidence: "Diff removes/renames emitted field/column.",
        required_source_trace: "Compare old/new shape; trace old-key readers via repo callers/RPCs/routes; log every reader & untraced boundary.",
        falsifier: "All consumers migrated/removed together; new payload; or never serialized.",
        no_evidence: "Untraced caller migration -> unknown contract impact; trace each before claiming breakage.",
        positive_case: "An endpoint renames `accountId` to `ownerId` while an in-repository client still reads `accountId`.",
        negative_case: "The same change updates every traced reader, or removes all consumers along with the field.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "interactive-state-derived-output",
        owner_lens: "correctness",
        applicability: "React/Vue/Svelte/equivalent interactive state/store UI.",
        language_applicability: None,
        trigger_evidence: "User action changes/adds state; nearby rendered/computed output seems linked.",
        required_source_trace: "Trace handler state write -> every dependent rendered value/filter/summary/alert/submit payload.",
        falsifier: "Intentionally control-independent output; or documented seed/default correctly merges live state.",
        no_evidence: "Unclear state/output link -> unknown; names alone don't establish intent.",
        positive_case: "A selected-category control updates state but the alert list continues reading a separate static default list.",
        negative_case: "A star toggle changes only its own presentation and no other output is meant to track it.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "upsert-replay-workflow-state",
        owner_lens: "data-safety",
        applicability: "Database upsert/on-conflict/merge writes in application code or SQL, across supported repository languages.",
        language_applicability: None,
        trigger_evidence: "A replayable insert/upsert supplies a literal to a workflow-bearing field such as status, stage, state, phase, tier, or role.",
        required_source_trace: "Trace the conflict/update column list and guards, then inspect relevant helper, trigger, or generated-column behavior before concluding the state is overwritten.",
        falsifier: "Conflict handling ignores duplicates, omits the state column, or constrains updates to an explicitly safe current state.",
        no_evidence: "If a wrapper, trigger, or database policy may provide a guard and its behavior is unavailable, report unknown.",
        positive_case: "A webhook replay updates a matching order and writes `status = 'pending'` after the order advanced.",
        negative_case: "`DO UPDATE` changes only profile fields and omits the workflow status column.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "migration-later-object-order",
        owner_lens: "data-safety",
        applicability: "Timestamp-ordered SQL migrations, including migrations that include or execute external SQL files.",
        language_applicability: None,
        trigger_evidence: "A migration references a table, column, type, function, policy, or view whose declaration is not visible in the same migration.",
        required_source_trace: "Resolve each referenced object to its creation/alteration source and compare migration timestamps, including transitive includes and documented baseline objects.",
        falsifier: "The object exists in an earlier or same-order migration, a guaranteed baseline, or a known built-in/extension.",
        no_evidence: "If object origin or migration order cannot be established, report fresh-apply behavior as unknown.",
        positive_case: "Migration 020 adds a policy that uses a column first added in migration 030.",
        negative_case: "The referenced column is created in migration 010 or in a guaranteed baseline applied first.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "postgres-definer-searchpath-and-public-execute",
        owner_lens: "security",
        applicability: "PostgreSQL functions, including Supabase migrations and RPCs.",
        language_applicability: None,
        trigger_evidence: "A created or altered function uses SECURITY DEFINER, especially when search_path or EXECUTE grants change or are inherited from defaults.",
        required_source_trace: "Read the complete function body and fixed SET search_path; trace effective EXECUTE grants/revokes, untrusted caller reachability, and documented/API-policy intended roles.",
        falsifier: "Name resolution is pinned away from caller-controlled schemas and effective access matches an evidenced intended audience; PUBLIC execution alone is not a defect without a conflicting access policy.",
        no_evidence: "If function body, search-path resolution, effective ACL, caller reachability, or intended audience cannot be established, report that property as unknown.",
        positive_case: "An untrusted role can call a definer function with caller-influenced name resolution, or PUBLIC retains EXECUTE contrary to an evidenced private access policy.",
        negative_case: "A definer function pins a safe search_path and verified grants match its documented caller audience.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "supabase-single-missing-row-response",
        owner_lens: "correctness",
        applicability: "Supabase/PostgREST JS/TS `.single()` by request-derived ID.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        trigger_evidence: "Possible zero rows; request/unproven-lookup key.",
        required_source_trace: "Trace ID origin, cardinality/guards, `{data,error}` handling & response mapping; separate returned PostgREST errors from throws.",
        falsifier: "Proven row before query; intentional `.maybeSingle()` absence mapping; or PGRST116 -> expected not-found.",
        no_evidence: "Untraced cardinality/prior existence/response mapping -> unknown; returned error isn't thrown.",
        positive_case: "An edge handler calls `.single()` by request ID and returns 500 for a returned PGRST116 result.",
        negative_case: "The handler uses `.maybeSingle()` and maps `data === null` to 404, or handles PGRST116 in its returned error path.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "qualified-function-create-unqualified-comment",
        owner_lens: "data-safety",
        applicability: "PostgreSQL/Supabase SQL migrations containing CREATE FUNCTION and COMMENT ON FUNCTION.",
        language_applicability: None,
        trigger_evidence: "A function is created schema-qualified and later commented by name in the same migration or included SQL.",
        required_source_trace: "Compare the exact schema and argument signature in CREATE and COMMENT statements, then inspect migration-level SET search_path applying to COMMENT.",
        falsifier: "COMMENT is schema-qualified consistently, CREATE is intentionally unqualified under the same convention, or statement scope pins the matching schema.",
        no_evidence: "If included definitions or session search_path are unavailable, report resolution as unknown; a function body's SET search_path does not establish migration-session scope.",
        positive_case: "`CREATE FUNCTION public.refresh()` is followed by `COMMENT ON FUNCTION refresh()` with no migration-level search_path guarantee.",
        negative_case: "`COMMENT ON FUNCTION public.refresh()` matches the qualified CREATE.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "environment-read-before-config-loader",
        owner_lens: "correctness",
        applicability: "Node.js JS/TS: process.env & dotenv/process.loadEnvFile/manual setup.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        trigger_evidence: "Export/config/client reads process.env at module evaluation.",
        required_source_trace: "Trace entry loader/consumer import/evaluation order & export read/use timing.",
        falsifier: "Lazy read after load; dynamic import after config; or documented build-time constant.",
        no_evidence: "Top-level env read alone is not a bug; untraced initialization order -> unknown.",
        positive_case: "An entry imports a client module before calling loadEnvFile, while that module captures process.env.API_URL at top level.",
        negative_case: "The entry loads environment first and dynamically imports the client, or the client reads process.env inside a later-called function.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "react-render-state-and-eager-initializer-effects",
        owner_lens: "correctness",
        applicability: "React function components in JSX/TSX.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        trigger_evidence: "Render-scope setter or nontrivial eager useState argument.",
        required_source_trace: "Trace setter scope/guard; per-render useState(expr) cost/effects; lazy initializer purity/behavior.",
        falsifier: "Event/effect/callback setter or proven guarded derive-state; cheap/pure initializer or lazy expensive work.",
        no_evidence: "Unclear scope/guard/cost/effect -> unknown; setter/useState alone is not a defect.",
        positive_case: "Render unconditionally calls setOpen, or `useState(parseLargePayload())` repeats parsing on every render.",
        negative_case: "A conditional setter compares incoming props with prior state, or `useState(() => parseLargePayload())` lazily computes a pure value.",
        ..PatternCard::BASE
    },
    PatternCard {
        version: "1",
        id: "promise-all-independent-partial-effects",
        owner_lens: "performance",
        applicability: "JavaScript/TypeScript Promise.all over independent writes, sends, publishes, or other side effects.",
        language_applicability: None,
        trigger_evidence: "Promise.all groups independent side effects whose partial completion affects retry or recovery.",
        required_source_trace: "Identify each operation's side effect and caller's failure handling, then trace whether per-item completion/results are persisted or inspected.",
        falsifier: "All entries are reads, use Promise.allSettled, or individually convert rejection into a per-item result before aggregation.",
        no_evidence: "If operations are not established as independent side effects or recovery semantics are unavailable, report partial completion as unknown.",
        positive_case: "Promise.all sends three webhooks; one rejection hides which other deliveries succeeded before retry.",
        negative_case: "Promise.all gathers independent reads, or Promise.allSettled records every write outcome.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "qwik-server-client-serialization",
        owner_lens: "security",
        applicability: "Qwik/Qwik City components, routeLoader$/routeAction$/server$ and useStore/useSignal state.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        version_applicability: Some("Qwik/Qwik City major version read from the installed lockfile; serialization rules differ across versions."),
        config_applicability: Some("Production output (serialized state/HTML) when available."),
        trigger_evidence: "A credential, token, or private record is read in server scope near state, a $() closure capture, or a loader return value that Qwik serializes to the client.",
        required_source_trace: "Trace the value from its server-side origin to every serialized sink (loader return, store/signal, QRL capture); inspect actual production output when available. Source proximity or a variable name alone does not establish serialization.",
        falsifier: "The server consumes the value internally and only a derived safe result is returned or captured; or production output shows the value absent from client-delivered state.",
        no_evidence: "If production output, framework version, or the serialization boundary is unavailable, report client exposure as unknown.",
        positive_case: "A routeLoader$ returns the full user row including an API token and the component renders only the name.",
        negative_case: "The loader maps the row to {name} before returning, and production output contains no token.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "qwik-resumability-closure-capture",
        owner_lens: "correctness",
        applicability: "Qwik $()/component$/useTask$/useVisibleTask$ closures and useStore/useSignal contents.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        version_applicability: Some("Qwik major version; serializable-value rules are version-bound."),
        config_applicability: None,
        trigger_evidence: "A $() closure or store captures a class instance, function, DOM node, Promise, or other value Qwik cannot serialize for resumption.",
        required_source_trace: "Trace each captured variable to its declaration and type, then check whether it is serializable, wrapped with noSerialize, or created only inside the closure.",
        falsifier: "The captured value is plain serializable data, wrapped with noSerialize and re-created on resume, or never crosses a resumability boundary.",
        no_evidence: "If the captured value's type or origin cannot be established, report resumability impact as unknown; the use of a closure alone is not a defect.",
        positive_case: "A component$ captures a WebSocket instance created outside the closure and uses it in an onClick$ handler.",
        negative_case: "The socket is held with noSerialize and re-opened in useVisibleTask$, or the handler captures only an id.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "qwik-loader-action-validation",
        owner_lens: "security",
        applicability: "Qwik City routeAction$/routeLoader$/server$ handlers or endpoints that read request-derived input.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        version_applicability: Some("Qwik City major version; validator$/zod$ APIs differ by version."),
        config_applicability: Some("Route middleware and global validation configuration when present."),
        trigger_evidence: "A handler uses request input in an authorization decision, query, file path, or write without schema validation on the server.",
        required_source_trace: "Trace each request-derived field from handler arguments to its sensitive use, then look for validator$/zod$, middleware, or manual validation on that path. Client-side validation does not count.",
        falsifier: "Server-side validation or typed parsing covers the field before use; or the field is not used in a sensitive operation.",
        no_evidence: "If middleware, validator composition, or the sensitive sink is not visible, report validation coverage as unknown.",
        positive_case: "routeAction$ passes formData.get('id') straight into a SQL query with no validator$.",
        negative_case: "routeAction$ declares zod$({id: z.string().uuid()}) before the query.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "react-state-effect-ownership",
        owner_lens: "correctness",
        applicability: "React function components with useEffect/useLayoutEffect that set state, subscribe, or fetch.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        version_applicability: Some("React major version and StrictMode setting change effect timing; read them before concluding."),
        config_applicability: None,
        trigger_evidence: "An effect copies props or other state into state, or starts a subscription/fetch with no cleanup, so two owners hold one fact or stale async results can land.",
        required_source_trace: "Trace the effect's dependencies, what it writes, the state's other writers, the cleanup return, and whether the effect synchronizes with an external system.",
        falsifier: "The effect syncs with an external system, cleanup or an ignore flag handles stale results, or state is owned once and derived at render.",
        no_evidence: "If the effect body, dependency source, or state owner is unavailable, report ownership or race as unknown; the presence of an effect is not a defect.",
        positive_case: "useEffect(() => setFiltered(items.filter(f)), [items]) duplicates derivable data, and a fetch effect has no cancellation so an older response overwrites a newer one.",
        negative_case: "The filtered list is computed during render, and the fetch effect ignores results after cleanup.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "secret-serialization-through-logs-and-telemetry",
        owner_lens: "security",
        applicability: "Any language: values of credential-bearing type or name reach a logger, debug formatter, serializer, error report, or telemetry event.",
        language_applicability: None,
        version_applicability: None,
        config_applicability: Some("Logging, tracing, telemetry, and crash-reporting configuration; release versus debug behavior."),
        trigger_evidence: "A credential, token, key, or session secret is included in a log call, derived Debug/toString, JSON.stringify/serde of a whole config or request, or telemetry payload.",
        required_source_trace: "Trace the secret from origin to the sink, including derived formatters and whole-object serialization; check redaction, safe projection, and whether the sink is active in release configuration.",
        falsifier: "Redaction or an explicit safe projection removes the secret before the sink; the value is a public identifier; or the sink is excluded from release configuration.",
        no_evidence: "If the sink configuration, formatter implementation, or the value's sensitivity cannot be established, report exposure as unknown.",
        positive_case: "A request handler logs the whole headers object including Authorization, or a config struct with an api_key derives Debug and is logged.",
        negative_case: "The logger redacts Authorization, or the struct implements Debug with the key masked.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "commerce-money-and-inventory-invariants",
        owner_lens: "data-safety",
        applicability: "Price, discount, tax, refund, balance, or stock values are changed by read-modify-write code.",
        language_applicability: None,
        version_applicability: None,
        config_applicability: Some("Domain contract (A12) for units, currency scale, reservation, and refund policy when present."),
        trigger_evidence: "Concurrent or repeated requests can read a balance or stock value, decide, and write without an atomic guard, or amounts cross layers without a stated unit.",
        required_source_trace: "Trace the value's unit and scale across layers, then the read, the decision, and the write; inspect transaction, lock, conditional update, and reservation mechanisms. Use the domain contract when present.",
        falsifier: "An atomic conditional update, transaction, or reservation protects the invariant, or the contract states the units and the layers agree.",
        no_evidence: "If no domain contract or policy states the invariant, report policy-dependent behavior as unknown; never invent refund or stock policy.",
        positive_case: "Two refund requests each check refundable balance before either writes, and the total exceeds the captured amount.",
        negative_case: "The refund runs as one conditional UPDATE ... WHERE refundable >= amount inside a transaction.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "webhook-idempotency-and-verification-order",
        owner_lens: "data-safety",
        applicability: "A webhook or queue consumer performs externally visible effects such as fulfillment, ledger entries, or email.",
        language_applicability: None,
        version_applicability: None,
        config_applicability: Some("Provider retry and delivery guarantees when documented in the repository."),
        trigger_evidence: "A handler performs its effects before verifying the signature, or without deduplicating by event id, so provider retries repeat effects.",
        required_source_trace: "Trace signature verification order, the event identifier, the dedupe store or unique constraint, and each effect's own idempotency.",
        falsifier: "Verification precedes effects and a unique key or idempotent effect makes a replay a no-op.",
        no_evidence: "If the dedupe mechanism or provider retry behavior is outside the selected source, report replay safety as unknown.",
        positive_case: "A payment webhook inserts a ledger row and sends a receipt on every delivery with no event-id check.",
        negative_case: "The handler inserts the event id under a unique constraint first and returns early on conflict.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "tenant-authorization-scope",
        owner_lens: "security",
        applicability: "A handler reads or mutates a record by identifier supplied in the request.",
        language_applicability: None,
        version_applicability: None,
        config_applicability: Some("Row-level security policies, middleware, and ORM scoping configuration when present."),
        trigger_evidence: "The lookup or write uses a record id without an owner or tenant predicate, or authorization is enforced only in client code.",
        required_source_trace: "Trace the identifier's origin, the query predicate, and any server-side policy, middleware, or row-level security that scopes the caller.",
        falsifier: "A server-side policy or query predicate binds the record to the authenticated tenant or owner.",
        no_evidence: "If policy, middleware, or query construction is not visible, report cross-tenant access as unknown.",
        positive_case: "GET /orders/:id loads the order by id alone and returns it to any authenticated user.",
        negative_case: "The query adds AND tenant_id = $caller, or a row-level policy enforces the same.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "swift-actor-reentrancy-stale-state",
        owner_lens: "correctness",
        applicability: "Swift actors or isolated types with an await between a state check and the state commit.",
        language_applicability: Some(LanguageApplicability::Swift),
        version_applicability: Some("Swift 5.5+ concurrency; strict-concurrency mode from the package or project settings."),
        config_applicability: Some("Package.swift or Xcode project settings for strict concurrency."),
        trigger_evidence: "An actor method checks mutable state, suspends at an await, then commits using the earlier result after another task may have changed state.",
        required_source_trace: "Trace the read, each suspension point, and the write; determine whether state is revalidated after the await or reserved before it.",
        falsifier: "State is revalidated after suspension, reserved before it, or no await lies between check and commit.",
        no_evidence: "If the awaited call or isolation context is unavailable, report reentrancy exposure as unknown; actor isolation alone does not prove a multi-step invariant.",
        positive_case: "An actor checks balance >= amount, awaits a remote authorization, then subtracts amount.",
        negative_case: "The actor reserves the amount before the await and releases it on failure.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "swift-task-cancellation-ignored",
        owner_lens: "resilience",
        applicability: "Swift Task or async functions performing long loops, retries, or multi-step effects.",
        language_applicability: Some(LanguageApplicability::Swift),
        version_applicability: Some("Swift 5.5+ structured concurrency."),
        config_applicability: None,
        trigger_evidence: "Cancellation is swallowed or never checked, so canceled work continues into a side effect, retry loop, or persisted write.",
        required_source_trace: "Trace the Task creation, the cancellation checks (Task.checkCancellation, isCancelled, throwing awaits), catch blocks that swallow CancellationError, and the effects that follow.",
        falsifier: "Cancellation propagates, is checked before each effect, or terminal cleanup runs without resuming canceled work.",
        no_evidence: "If the callee's cancellation behavior is unavailable, report continuation after cancellation as unknown; a broad catch alone is not a defect.",
        positive_case: "A retry loop catches every error including CancellationError and keeps posting after the view is dismissed.",
        negative_case: "The loop calls try Task.checkCancellation() each pass and rethrows CancellationError.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "swift-closure-retain-cycle",
        owner_lens: "resilience",
        applicability: "Swift escaping closures, Combine sinks, timers, or Tasks stored on the object that they capture.",
        language_applicability: Some(LanguageApplicability::Swift),
        version_applicability: Some("Swift version; ARC semantics apply to all supported versions."),
        config_applicability: None,
        trigger_evidence: "A class stores a closure, subscription, timer, or Task that strongly captures self, with no cancel or weak capture on the lifetime path.",
        required_source_trace: "Trace who owns the closure, whether it captures self strongly, and where it is canceled or released.",
        falsifier: "The capture is weak or unowned with a safe lifetime, the owner cancels it on deinit or disappearance, or the closure is not stored.",
        no_evidence: "If the storage owner or cancellation path is unavailable, report leak as unknown; a strong self capture in a non-stored closure is not a cycle.",
        positive_case: "A view model stores a Combine sink that captures self strongly and never cancels it.",
        negative_case: "The sink uses [weak self] and is stored in a cancellable set cleared on deinit.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "kotlin-cancellation-swallowed",
        owner_lens: "correctness",
        applicability: "Kotlin suspend functions or coroutine builders with a broad catch around a suspension point.",
        language_applicability: Some(LanguageApplicability::Kotlin),
        version_applicability: Some("kotlinx.coroutines version from the Gradle file."),
        config_applicability: None,
        trigger_evidence: "A catch of Exception or Throwable around a suspending call swallows CancellationException and execution continues into a forbidden effect or retry.",
        required_source_trace: "Trace the suspension point, the catch type, whether CancellationException is rethrown, and the code that runs after the catch.",
        falsifier: "Cancellation is rethrown, or documented terminal cleanup completes without resuming canceled work.",
        no_evidence: "If the callee is not a suspension point or the continuation cannot be traced, report the swallow as unknown; do not flag every broad catch.",
        positive_case: "A retry loop catches Exception around delay() and api.send() and keeps sending after the scope is canceled.",
        negative_case: "The catch rethrows CancellationException before handling other failures.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "android-lifecycle-scope-and-context-leak",
        owner_lens: "resilience",
        applicability: "Android components that launch coroutines, collect flows, or hold Context or View references.",
        language_applicability: Some(LanguageApplicability::Kotlin),
        version_applicability: Some("AndroidX lifecycle library version for repeatOnLifecycle availability."),
        config_applicability: Some("AndroidManifest and Gradle settings are read only for scope facts."),
        trigger_evidence: "Work is launched in GlobalScope or collected from lifecycleScope without repeatOnLifecycle while the UI is stopped, or a long-lived object holds an Activity or View.",
        required_source_trace: "Trace the launching scope, the collection lifecycle state, and the owner's lifetime against the held Context.",
        falsifier: "The scope matches the owner's lifetime, collection is lifecycle-aware, or the holder uses the application context.",
        no_evidence: "If the owner lifetime or scope source is unavailable, report the leak or wasted work as unknown.",
        positive_case: "A fragment collects a location Flow in lifecycleScope.launch and keeps collecting while stopped, and a singleton stores the Activity.",
        negative_case: "Collection uses repeatOnLifecycle(STARTED) and the singleton stores applicationContext.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "compose-state-ownership-and-side-effects",
        owner_lens: "correctness",
        applicability: "Jetpack Compose composables that hold state, mutate collections, or perform side effects.",
        language_applicability: Some(LanguageApplicability::Kotlin),
        version_applicability: Some("Compose runtime version from the Gradle file."),
        config_applicability: None,
        trigger_evidence: "A composable mutates a non-observable collection, keeps remember state without the key that should reset it, or runs a side effect directly in composition.",
        required_source_trace: "Trace the state holder, whether mutations go through snapshot state, the remember keys, and where effects run (LaunchedEffect, DisposableEffect, event callbacks).",
        falsifier: "State is observable and owned once, keys cover its inputs, and effects run in effect handlers or callbacks.",
        no_evidence: "If the state's type or the effect's host is unavailable, report the violation as unknown.",
        positive_case: "A composable adds to a mutableListOf in an onClick and expects recomposition, and calls a network request in the composition body.",
        negative_case: "The list is a mutableStateListOf and the request runs in LaunchedEffect(userId).",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "rust-async-blocking-call",
        owner_lens: "performance",
        applicability: "Rust async functions or tasks running on a shared executor.",
        language_applicability: Some(LanguageApplicability::Rust),
        version_applicability: Some("Tokio or async-std version and runtime flavor from the manifest and main."),
        config_applicability: Some("Runtime configuration when present."),
        trigger_evidence: "An async function performs blocking IO, thread::sleep, a long CPU loop, or holds a synchronous mutex guard across an await.",
        required_source_trace: "Trace the call to its blocking behavior, the executor it runs on, and any spawn_blocking or async replacement.",
        falsifier: "The work is offloaded with spawn_blocking, uses an async API, is brief and bounded, or the runtime is a dedicated blocking-tolerant one.",
        no_evidence: "If the callee or runtime flavor cannot be established, report executor starvation as unknown.",
        positive_case: "An async handler calls std::fs::read_to_string for a large file on the multi-thread runtime.",
        negative_case: "The handler uses tokio::fs or wraps the read in spawn_blocking.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "rust-async-cancellation-safety",
        owner_lens: "resilience",
        applicability: "Rust select!, timeout, or dropped futures around operations that consume partial state.",
        language_applicability: Some(LanguageApplicability::Rust),
        version_applicability: Some("Tokio version; cancel-safety is documented per API."),
        config_applicability: None,
        trigger_evidence: "A future that is not cancel-safe is raced in select! or timeout inside a loop, so partial progress is lost, or a guard drop leaves state half-updated.",
        required_source_trace: "Trace the raced futures, their documented cancel-safety, the loop, and the state mutated before the await point.",
        falsifier: "The future is documented cancel-safe, progress is stored outside the future, or the operation is retried idempotently.",
        no_evidence: "If cancel-safety of the awaited API is not established, report data loss as unknown.",
        positive_case: "A loop uses select! on read_exact and a timer, so a timer win discards partially read bytes.",
        negative_case: "The loop reads into a buffer owned outside the future and resumes with it.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "rust-unsafe-invariant-evidence",
        owner_lens: "security",
        applicability: "Rust unsafe blocks, unsafe fn, FFI calls, or unchecked operations.",
        language_applicability: Some(LanguageApplicability::Rust),
        version_applicability: Some("Rust edition and any forbid/deny(unsafe_code) lint from the manifest or crate root."),
        config_applicability: Some("Miri or sanitizer results count as evidence only when supplied."),
        trigger_evidence: "An unsafe operation depends on an invariant that attacker-influenced or unchecked input can violate and no check or encapsulation establishes it.",
        required_source_trace: "Trace the operation's required invariant to its establishment: bounds checks, validated construction, or documented caller contract.",
        falsifier: "The invariant is established locally, the safe wrapper enforces it, or the input is trusted and fixed.",
        no_evidence: "If the invariant source or input origin is unavailable, report soundness as unknown; unsafe alone is not a defect.",
        positive_case: "get_unchecked(idx) uses an index parsed from a network packet without a bounds check.",
        negative_case: "The wrapper asserts idx < len before the unchecked access and is the only caller.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "tauri-ipc-command-boundary",
        owner_lens: "security",
        applicability: "Tauri commands (#[tauri::command]) and invoke calls that carry paths, URLs, or shell arguments.",
        language_applicability: Some(LanguageApplicability::TauriSurface),
        version_applicability: Some("Tauri major version; v1 allowlist and v2 capability models differ."),
        config_applicability: Some("tauri.conf.json and capability files."),
        trigger_evidence: "A command uses a webview-supplied path, URL, or argument for filesystem, network, or process access without validation or scope restriction.",
        required_source_trace: "Trace the argument from invoke through the Rust command to its sink, then the validation, canonicalization, and capability scope.",
        falsifier: "The command canonicalizes and confines the value to an allowed root, or capability scope already restricts it.",
        no_evidence: "If the Tauri version or capability configuration is unavailable, report reachability as unknown.",
        positive_case: "A read_file command joins an invoke-supplied path to the home directory and reads it without a containment check.",
        negative_case: "The command canonicalizes the path and rejects any outside the app data directory.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "tauri-capability-scope-breadth",
        owner_lens: "security",
        applicability: "Tauri capability, permission, or CSP configuration granting filesystem, shell, http, or remote-origin access.",
        language_applicability: Some(LanguageApplicability::TauriSurface),
        version_applicability: Some("Tauri v2 capabilities or v1 allowlist, per major version."),
        config_applicability: Some("capabilities/*.json, tauri.conf.json security section, and window definitions."),
        trigger_evidence: "A capability grants broad filesystem/shell/http scope or applies to remote-content windows beyond what the app's documented features need.",
        required_source_trace: "Compare each granted permission and scope to the commands and features that use it, and to the windows and origins it applies to.",
        falsifier: "Scope is limited to the used paths/commands and local windows, or the broader scope is justified by a documented feature.",
        no_evidence: "If the used features or window origins cannot be established, report over-grant as unknown.",
        positive_case: "A capability grants fs:scope for $HOME/** to a window that loads a remote URL, and only $APPDATA is used.",
        negative_case: "The capability scopes fs to $APPDATA/** for the local main window only.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "tauri-deeplink-and-update-trust",
        owner_lens: "security",
        applicability: "Tauri deep-link handlers, updater endpoints, and update signature settings.",
        language_applicability: Some(LanguageApplicability::TauriSurface),
        version_applicability: Some("Tauri major version; updater and deep-link plugin versions."),
        config_applicability: Some("tauri.conf.json updater section and signing key configuration."),
        trigger_evidence: "A deep-link handler acts on URL parameters without validation, or updater configuration permits unsigned update acceptance.",
        required_source_trace: "Trace the URL parameter to its action and the updater's endpoint, signature verification, and key configuration.",
        falsifier: "Parameters are validated against an allow-list, the action is non-destructive, and updates require a verified signature.",
        no_evidence: "If the updater or handler configuration is unavailable, report trust as unknown; do not infer certificate pinning requirements.",
        positive_case: "A deep link app://open?path=... opens the supplied path, and the updater has no public key configured.",
        negative_case: "The handler maps the link to an allow-listed route, and the updater requires a signature checked against a configured key.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "rust-gui-per-frame-work",
        owner_lens: "performance",
        applicability: "Rust GUI update, view, or draw functions that run every frame or event.",
        language_applicability: Some(LanguageApplicability::Rust),
        version_applicability: Some("egui/iced/slint/bevy version from the manifest."),
        config_applicability: None,
        trigger_evidence: "The per-frame path performs file or network IO, large allocation, repeated parsing, or unbounded layout work whose cost grows with data size.",
        required_source_trace: "Trace the function to its frame cadence, the data size, and whether the result is cached or recomputed only on change.",
        falsifier: "Work is cached or invalidated on change, input size is small and bounded, or measured cost is within the frame budget.",
        no_evidence: "If frame cadence or data size cannot be established, report the cost as unknown; allocation in a frame alone is not a defect.",
        positive_case: "An egui update function re-reads and re-parses a config file every frame.",
        negative_case: "The file is parsed once and re-parsed only when its modification time changes.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "migration-expand-contract-rollout",
        owner_lens: "data-safety",
        applicability: "A SQL migration drops or renames a column, adds NOT NULL without a default, or rewrites a table while earlier application code may still run.",
        language_applicability: Some(LanguageApplicability::Sql),
        version_applicability: Some("Database engine and version from migration tooling or container configuration."),
        config_applicability: Some("Deployment ordering and rollout documentation when present."),
        trigger_evidence: "A single migration breaks the schema contract used by application code that may be deployed before or after it.",
        required_source_trace: "Trace the changed object to its readers and writers in application code and to the deployment order; check for expand/contract staging, defaults, and backfill.",
        falsifier: "The change is staged (expand then contract), the object is unused or newly created, or deploy ordering is documented as atomic.",
        no_evidence: "If application readers or rollout ordering are unavailable, report compatibility as unknown. Down-migration presence is not a requirement.",
        positive_case: "A migration drops a column that the currently deployed service still selects.",
        negative_case: "The migration adds the new column first and a later release drops the old one after readers moved.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "version-gated-api-without-minimum-guard",
        owner_lens: "release-readiness",
        applicability: "Code uses a platform or library API introduced after the declared minimum.",
        language_applicability: None,
        version_applicability: Some("Declared minimum: iOS/macOS deployment target, Android minSdk, Rust rust-version, Node engines."),
        config_applicability: Some("The manifest or project setting declaring the minimum version."),
        trigger_evidence: "An API is used on a path reachable at the declared minimum with no availability check or fallback.",
        required_source_trace: "Compare the API's introduction version to the declared minimum, then trace the call for #available, SDK_INT, cfg, or feature guards.",
        falsifier: "The call is guarded, a fallback exists, or the declared minimum is at least the introduction version.",
        no_evidence: "If the minimum or the API's introduction version is unavailable, report compatibility as unknown.",
        positive_case: "Code calls an API added in Android API 33 with minSdk 26 and no SDK_INT check.",
        negative_case: "The call sits behind Build.VERSION.SDK_INT >= 33 with a fallback.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "config-key-drift-between-code-and-environments",
        owner_lens: "release-readiness",
        applicability: "Code reads a configuration key or environment variable that deployment configuration may not define.",
        language_applicability: None,
        version_applicability: None,
        config_applicability: Some("Environment, deployment, and server configuration files (including Nginx and CI) when present."),
        trigger_evidence: "A required key is read by code but absent from, or inconsistently defined in, the declared deployment configuration.",
        required_source_trace: "Trace each read to its default, its required status, and the definitions in the declared environments.",
        falsifier: "The key has a safe default, is optional by design, or is defined in every declared environment.",
        no_evidence: "If environment definitions are external or not provided, report drift as unknown; absent files never establish agreement.",
        positive_case: "Code requires STRIPE_WEBHOOK_SECRET and the production deployment file does not define it.",
        negative_case: "The key is defined in every environment file or has a documented safe default.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "a11y-interactive-name-role-keyboard",
        owner_lens: "a11y",
        applicability: "Custom interactive elements: click handlers on non-semantic elements, icon-only buttons, custom gestures.",
        language_applicability: None,
        version_applicability: Some("Framework a11y APIs by platform: HTML/ARIA, SwiftUI accessibility modifiers, Compose semantics."),
        config_applicability: None,
        trigger_evidence: "An interactive element has no accessible name, role, or keyboard/assistive activation path.",
        required_source_trace: "Trace the element's role, name source, focus behavior, and activation path through the platform's accessibility API.",
        falsifier: "A native semantic control, label, or semantics is provided; or the element is decorative and hidden from assistive technology.",
        no_evidence: "If the rendered semantics cannot be established from source, report accessibility as unknown rather than failing it.",
        positive_case: "A div with onClick is the only close control and has no role, label, or key handler.",
        negative_case: "The control is a button with an aria-label, or Compose clickable has a contentDescription.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "privacy-collection-consent-and-disclosure",
        owner_lens: "data-safety",
        applicability: "Code collects, stores, or transmits personal identifiers, location, contacts, or device identifiers.",
        language_applicability: None,
        version_applicability: Some("Platform privacy declarations: Apple privacy manifest, Android data safety, consent library versions."),
        config_applicability: Some("Privacy manifest, data-safety form, and consent configuration when present."),
        trigger_evidence: "Personal data is collected or sent before a consent gate or without a matching disclosure in the declared privacy artifacts.",
        required_source_trace: "Trace the collection to its trigger, the consent gate ordering, and the declared disclosures.",
        falsifier: "Collection waits for consent where required, the data is not personal, or disclosures match the use.",
        no_evidence: "If the disclosure or consent policy source is unavailable, report compliance as unknown; legal sufficiency is not decided.",
        positive_case: "An analytics SDK sends the advertising id at launch and the privacy manifest declares no collection.",
        negative_case: "The SDK is initialized after consent and the manifest declares the collected type.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "outbound-call-timeout-and-retry-bound",
        owner_lens: "resilience",
        applicability: "Network, IPC, or subprocess calls on a request or UI path.",
        language_applicability: None,
        version_applicability: Some("HTTP/RPC client library defaults by version."),
        config_applicability: Some("Client, proxy, and Nginx timeout configuration when present."),
        trigger_evidence: "A call has no timeout and no cancellation, or retries without bound, backoff, or idempotency.",
        required_source_trace: "Trace the client's effective timeout (explicit or library default), retry policy, and the call's idempotency.",
        falsifier: "A timeout and bounded retry exist or are the documented client default, and retried operations are idempotent.",
        no_evidence: "If the client default or wrapper behavior is unavailable, report the hang or retry storm as unknown.",
        positive_case: "A request handler awaits an upstream fetch with no timeout and retries forever on error.",
        negative_case: "The call uses a 5s timeout, three retries with backoff, and an idempotency key.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "release-debug-surface-shipped",
        owner_lens: "release-readiness",
        applicability: "Debug, test, or development controls appear in code or configuration that a release artifact includes.",
        language_applicability: None,
        version_applicability: Some("Release profile and configuration by platform."),
        config_applicability: Some("Release configuration, Tauri devtools setting, Android debuggable, Nginx autoindex, and similar flags."),
        trigger_evidence: "Debug endpoints, devtools, test hooks, or verbose server listing are reachable in the release configuration rather than compiled or configured out.",
        required_source_trace: "Trace the control to its gating (compile-time exclusion or release configuration) and to the release artifact configuration.",
        falsifier: "The control is excluded at compile time from release output, or it is present only in a non-release configuration.",
        no_evidence: "If the release configuration or artifact is unavailable, report shipping as unknown; a runtime flag is evidence of presence, not of exclusion.",
        positive_case: "A debug route is registered unconditionally, behind only a runtime flag defaulting to on.",
        negative_case: "The route is under a compile-time feature excluded from the release profile.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "component-decomposition-recommendation-contract",
        owner_lens: "architecture",
        applicability: "A large component, class, or module is proposed for decomposition.",
        language_applicability: None,
        version_applicability: None,
        config_applicability: None,
        trigger_evidence: "A decomposition recommendation is made from size alone or without naming responsibilities, state, and callers.",
        required_source_trace: "A valid recommendation names each separable responsibility, the state each owns, the callers affected, and the behavior to be preserved.",
        falsifier: "The recommendation names responsibilities, state ownership, callers, and preserved behavior, or size is not the stated reason.",
        no_evidence: "If callers or state ownership cannot be traced, report the recommendation as unknown and do not propose a split.",
        positive_case: "A 1200-line component is flagged as too large with no named responsibilities or callers.",
        negative_case: "The finding names three responsibilities, the state each owns, the callers, and the invariant to preserve.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "ssrf-egress-url-fetch",
        owner_lens: "security",
        applicability: "Server-side code that fetches, proxies, unfurls, imports, or posts to a URL, host, or address derived from request, stored, or model-supplied data.",
        domain_evidence: Some(DomainEvidence::Ssrf),
        config_applicability: Some("Egress policy, network policy, cloud metadata settings, and HTTP client configuration when present."),
        trigger_evidence: "An outbound client call takes a user-influenced URL or host and no allow-list, resolved-address check, or egress restriction precedes it.",
        required_source_trace: "Trace the URL from its entry through parsing, redirect handling, and DNS resolution to the client call, then the allow-list or address-class check and any egress control.",
        falsifier: "The destination is fixed or chosen from a server-side allow-list, the resolved address is checked after redirects, or egress is restricted outside the code.",
        no_evidence: "If the client wrapper, redirect policy, or network egress controls are outside the supplied source, report reachability of internal addresses as unknown.",
        positive_case: "A link-preview endpoint calls the HTTP client on a request-supplied URL and follows redirects with no address check.",
        negative_case: "The endpoint accepts only hosts from a configured allow-list and re-checks the resolved address on every redirect.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "http-proxy-cache-smuggling",
        owner_lens: "security",
        applicability: "Reverse-proxy, gateway, CDN, and cache configuration or code that forwards, rewrites, keys, or caches HTTP requests and responses.",
        domain_evidence: Some(DomainEvidence::HttpProxyCache),
        config_applicability: Some("Proxy, ingress, CDN, and cache-key configuration files and the origin server's framing behavior."),
        trigger_evidence: "A forwarding layer passes hop-by-hop or length headers through, trusts client-set forwarding headers, or caches a response whose key omits a request attribute that changes the body.",
        required_source_trace: "Trace each header from the client through the proxy rules to the origin, the framing headers both tiers honor, and the cache key against what varies the response.",
        falsifier: "The proxy normalizes framing headers, strips or overwrites forwarding headers, and the cache key or Vary covers every attribute that changes the response.",
        no_evidence: "If only one tier of the proxy and origin pair is supplied, report framing disagreement and cache-key coverage as unknown.",
        positive_case: "A proxy forwards client X-Forwarded-Host to an origin that builds absolute links from it, and the response is cached without that header in the key.",
        negative_case: "The proxy overwrites X-Forwarded-Host with its own value and the cache key includes the host.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "auth-session-state-machine",
        owner_lens: "security",
        applicability: "Login, MFA, account recovery, logout, and session or token rotation flows.",
        domain_evidence: Some(DomainEvidence::AuthSession),
        config_applicability: Some("Session store, cookie, token lifetime, and identity-provider configuration when present."),
        trigger_evidence: "A flow step can be reached or replayed out of order, a recovery or MFA path grants a weaker session than the main login, or a session or token survives logout, password change, or privilege change.",
        required_source_trace: "Enumerate states and transitions for login, second factor, recovery, and logout, then trace session or token issuance, binding, rotation, and invalidation at each transition.",
        falsifier: "Each transition checks the prior state, recovery and MFA yield the same assurance as login, and credentials change or logout invalidates and rotates the session.",
        no_evidence: "If the session store or identity-provider behavior is not in the supplied source, report session invalidation and rotation as unknown.",
        positive_case: "A password-reset confirmation signs the user in with a session that skips the MFA step and the old session stays valid.",
        negative_case: "Reset requires the second factor, issues a new session identifier, and revokes all earlier sessions.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "native-workspace-trust-auto-exec",
        owner_lens: "security",
        applicability: "Desktop apps, CLIs, editors, and agents that load .env files, git hooks, project configuration, tasks, plugins, or MCP servers from a repository or workspace they open.",
        domain_evidence: Some(DomainEvidence::WorkspaceTrust),
        config_applicability: Some("Workspace trust settings, project configuration precedence, hook directories, and MCP or plugin discovery paths."),
        trigger_evidence: "Opening an untrusted directory causes configuration to execute a process, change environment or PATH, register a tool server, or run a hook before a trust decision.",
        required_source_trace: "Trace startup from path selection through configuration discovery and precedence to process spawn or environment injection, and locate the trust prompt, its default, and where it is persisted.",
        falsifier: "Execution-capable configuration loads only after an explicit per-workspace trust decision that defaults to untrusted, or is read only from the user's own configuration.",
        no_evidence: "If the trust prompt or discovery path is outside the supplied source, report pre-trust execution as unknown.",
        positive_case: "The app reads .mcp.json from the opened folder and launches the listed command at startup with no trust prompt.",
        negative_case: "Project configuration is parsed as data until the user trusts the folder, and trust defaults to off.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "ai-memory-rag-poisoning-grounding",
        owner_lens: "security",
        applicability: "Agent memory, retrieval-augmented generation, vector stores, and knowledge bases whose contents feed model context.",
        domain_evidence: Some(DomainEvidence::AiMemory),
        config_applicability: Some("Vector store collections, namespaces, access policy, and ingestion pipeline configuration when present."),
        trigger_evidence: "Content from an untrusted or lower-trust writer is stored and later retrieved as trusted context, memory is shared across users or tenants, or retrieved text can issue instructions or override grounding sources.",
        required_source_trace: "Trace each ingestion source to the store with its writer identity and trust label, then retrieval to prompt assembly, checking tenant filters and whether provenance reaches the model.",
        falsifier: "Writes carry provenance and are scoped per tenant, retrieval enforces that scope, and retrieved content is delimited as data with grounding sources kept separate from instructions.",
        no_evidence: "If ingestion writers or retrieval filters are outside the supplied source, report poisoning and cross-tenant retrieval as unknown.",
        positive_case: "Support tickets from any customer are embedded into one shared collection that every agent run retrieves from as trusted context.",
        negative_case: "Each tenant has its own namespace, ingested text is labeled untrusted data, and retrieval filters on the caller's tenant.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "admin-workflow-impersonation-bulk-abuse",
        owner_lens: "security",
        applicability: "Admin consoles, support tooling, impersonation, refunds, and bulk or batch actions operated by staff.",
        domain_evidence: Some(DomainEvidence::AdminWorkflow),
        config_applicability: Some("Staff role definitions, impersonation settings, and audit log configuration when present."),
        trigger_evidence: "A staff action acts as or on another account, or applies to many records, without a distinct role check, scope limit, confirmation, or audit record.",
        required_source_trace: "Trace the action from the admin route through role and scope checks to the effect, noting impersonation session labeling, bulk size limits, and the audit write.",
        falsifier: "The action requires a specific staff role, labels impersonated sessions, bounds and confirms bulk scope, and records actor and target.",
        no_evidence: "If staff role definitions or audit sinks are outside the supplied source, report privilege and traceability of the action as unknown.",
        positive_case: "Any support user can impersonate any account with full permissions and no audit entry, and a bulk refund endpoint accepts an unbounded id list.",
        negative_case: "Impersonation needs an elevated role, is read-only by default, is audited with actor and target, and bulk actions cap size and require confirmation.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "smart-contract-reentrancy-access-oracle",
        owner_lens: "security",
        applicability: "Smart contracts (Solidity, Vyper, and similar) that hold value, gate roles, or read external price or data feeds.",
        domain_evidence: Some(DomainEvidence::SmartContract),
        version_applicability: Some("Compiler version and chain semantics; checked-arithmetic defaults differ by Solidity version."),
        config_applicability: Some("foundry.toml, hardhat configuration, and deployment scripts for proxy and initializer use."),
        trigger_evidence: "A function makes an external call before updating state it depends on, a privileged function lacks an access modifier, or a price or rate comes from a single manipulable on-chain source.",
        required_source_trace: "Trace external calls against state writes in each value-moving function, then each privileged entry point to its role check, then each price input to its source and staleness or manipulation bounds.",
        falsifier: "State is updated before the external call or a reentrancy guard applies, privileged functions enforce roles including initializers, and prices use bounded or time-weighted sources.",
        no_evidence: "If called contracts, proxies, or oracle implementations are not supplied, report reentrancy reach and oracle trust as unknown.",
        positive_case: "withdraw() sends funds with call{value} and zeroes the balance afterward, and setOwner() has no access modifier.",
        negative_case: "withdraw() zeroes the balance first under a reentrancy guard, and setOwner() is restricted to the owner role.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "embedded-firmware-update-debug-keys",
        owner_lens: "security",
        applicability: "Embedded, IoT, and edge-device firmware, bootloaders, and provisioning code.",
        domain_evidence: Some(DomainEvidence::Embedded),
        version_applicability: Some("Bootloader and SDK version; secure-boot and flash-encryption options differ by vendor release."),
        config_applicability: Some("Board configuration, partition tables, fuse or option-byte settings, and debug-port configuration."),
        trigger_evidence: "A firmware image is accepted without signature and version verification, a debug interface stays enabled in the release configuration, or a device holds a hardcoded shared key or credential.",
        required_source_trace: "Trace update download to verification and flash write, the release build configuration for debug ports and logging, and each key or credential from its definition to its use and provisioning source.",
        falsifier: "Updates are verified against a device-held public key with rollback protection, debug access is disabled or locked in release, and keys are per-device and provisioned, not embedded.",
        no_evidence: "If bootloader, fuse, or release-profile configuration is not supplied, report update authentication and debug exposure as unknown.",
        positive_case: "The OTA handler writes any downloaded image to flash after a CRC check, and a shared AES key is a constant in the source.",
        negative_case: "The bootloader verifies an image signature and a monotonic version, and keys are unique per device and read from secure storage.",
        ..PatternCard::BASE
    },
    PatternCard {
        id: "ics-ot-unauthenticated-control-safety",
        owner_lens: "security",
        applicability: "ICS/OT repositories and configuration: PLC projects, Modbus, OPC UA, DNP3, and IEC 61850 integrations, HMI and SCADA code. Repository and configuration review only; no live probing.",
        domain_evidence: Some(DomainEvidence::Ics),
        config_applicability: Some("Protocol security modes, endpoint and security-policy settings, and interlock or simulation-mode flags."),
        trigger_evidence: "A control-capable protocol endpoint is configured without authentication or with a security mode of none, a write command path bypasses an interlock or operator confirmation, or simulation or maintenance mode is the default.",
        required_source_trace: "Trace each write or command path from its network entry through authentication and authorization to the actuator output, the interlock or permissive checks on it, and default-mode configuration.",
        falsifier: "Control endpoints require authenticated, authorized sessions, write paths enforce interlocks and fail safe, and unsafe modes are off by default and gated.",
        no_evidence: "If protocol security settings or interlock logic are outside the supplied source, report control authorization and safety enforcement as unknown.",
        positive_case: "An OPC UA server is configured with security mode None and exposes writable setpoint nodes that no interlock check guards.",
        negative_case: "The server requires signed and encrypted sessions with role-based write access, and setpoint writes pass interlock validation.",
        ..PatternCard::BASE
    },
];

/// Returns only cards owned by the lens already selected for this seat.
pub fn cards_for_lens(lens: &str) -> impl Iterator<Item = &'static PatternCard> + '_ {
    PATTERN_CARDS
        .iter()
        .filter(move |card| card.owner_lens == lens)
}

/// Serializes selected cards for the existing reasoning packet.
pub fn packet_cards_for_lens(lens: &str) -> Vec<Value> {
    cards_for_lens(lens)
        .copied()
        .map(PatternCard::to_packet_value)
        .collect()
}

/// Bytes a bound lens plan spends on pattern cards: card bodies plus the
/// per-card applicability rows (the shared path list is excluded because it
/// is identical for every lens of a part).
pub fn bound_card_bytes(lens_plan: &Value) -> u64 {
    let cards = lens_plan
        .get("patternCards")
        .map_or(0, |cards| cards.to_string().len());
    let rows = lens_plan
        .pointer("/patternCardApplicability/cards")
        .map_or(0, |rows| rows.to_string().len());
    (cards + rows) as u64
}

/// Share of the seat's model-input byte target one packet may spend on pattern
/// cards (bodies plus every applicability row). The remainder stays for the
/// base packet, raw excerpts and review context. Cards beyond the share become
/// compact `deferred-card-budget` rows rather than evicting source excerpts.
pub const CARD_BUDGET_PERCENT: u64 = 35;

/// State recorded for an applicable card whose body was left out of the packet
/// to fit the card budget. It is an unknown, never a clean claim.
pub const DEFERRED_CARD_STATE: &str = "deferred-card-budget";

/// Longest trigger text copied into a compact deferred row.
const DEFERRED_TRIGGER_CHARS: usize = 64;

/// Card byte budget for a seat whose model-input byte target is `seat_input_bytes`.
pub fn packet_card_budget_bytes(seat_input_bytes: u64) -> u64 {
    seat_input_bytes.saturating_mul(CARD_BUDGET_PERCENT) / 100
}

fn deferred_row(card: &PatternCard, prior_state: &str) -> Value {
    let trigger = card
        .trigger_evidence
        .chars()
        .take(DEFERRED_TRIGGER_CHARS)
        .collect::<String>();
    json!({
        "id": card.id,
        "state": DEFERRED_CARD_STATE,
        "reason": "card-body-omitted-for-packet-budget-unknown-never-clean",
        "priorState": prior_state,
        "trigger": trigger,
    })
}

/// Upper bound of `bound_card_bytes` for any lens. Uncapped (`None`): every
/// owned card retained plus a generous per-card accounting row. Capped: the
/// card budget, or the unavoidable compact rows when those alone exceed it.
/// Used to normalize packet sizing so lenses of one bundle keep deriving the
/// same excerpt parts (and keep sharing seats) however many cards each lens owns.
pub fn max_card_bytes_bound(card_budget: Option<u64>) -> u64 {
    let mut lenses = PATTERN_CARDS
        .iter()
        .map(|card| card.owner_lens)
        .collect::<Vec<_>>();
    lenses.sort_unstable();
    lenses.dedup();
    lenses
        .into_iter()
        .map(|lens| {
            let uncapped = cards_for_lens(lens)
                .map(|card| card.to_packet_value().to_string().len() + card.id.len() + 120)
                .sum::<usize>() as u64;
            match card_budget {
                None => uncapped,
                Some(budget) => {
                    let rows = cards_for_lens(lens)
                        .map(|card| deferred_row(card, "unknown").to_string().len() + 1)
                        .sum::<usize>() as u64
                        + 4;
                    uncapped.min(budget.max(rows))
                }
            }
        })
        .max()
        .unwrap_or(0)
}

/// Bind cards after source selection/partitioning, never from repository-wide
/// language guesses. Unknown language, framework, or trigger fit retains work.
pub fn bind_packet_cards_to_paths(lens_plan: &mut Value, selected_paths: &[String]) {
    bind_packet_cards_to_paths_budgeted(lens_plan, selected_paths, None);
}

/// As `bind_packet_cards_to_paths`, with an optional per-packet card byte
/// budget covering card bodies plus all applicability rows. Full bodies go
/// first to positively evidenced cards, then to always-on core cards, then to
/// cards whose fit is only unknown (including unrecognized source extensions),
/// each in catalogue order, while they fit. Every other applicable card keeps a
/// compact `deferred-card-budget` row: unknown, never clean. Excluded cards are
/// unaffected. Rows that cannot be omitted may exceed the budget.
pub fn bind_packet_cards_to_paths_budgeted(
    lens_plan: &mut Value,
    selected_paths: &[String],
    card_budget: Option<u64>,
) {
    let Some(lens) = lens_plan.get("lens").and_then(Value::as_str) else {
        return;
    };
    let mut source_paths = selected_paths
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    source_paths.sort_unstable();
    source_paths.dedup();
    let fits = cards_for_lens(lens)
        .map(|card| {
            let (state, reason) = match (card.domain_evidence, card.language_applicability) {
                (Some(domain), _) => domain.fit(&source_paths),
                (None, None) => ("retained", "no-language-restriction"),
                (None, Some(language)) => language_fit(language, &source_paths),
            };
            (card, state, reason)
        })
        .collect::<Vec<_>>();
    let row = |card: &PatternCard, state: &str, reason: &str| json!({"id": card.id, "state": state, "reason": reason});
    let mut keep = fits
        .iter()
        .map(|(_, state, _)| *state != "excluded")
        .collect::<Vec<_>>();
    let mut deferred_any = false;
    if let Some(budget) = card_budget {
        // Start with every applicable card deferred, then spend the remaining
        // budget on full bodies in priority order.
        // Brackets of the body array and the row array.
        let mut spent = 4usize;
        for (card, state, reason) in &fits {
            spent += if *state == "excluded" {
                row(card, state, reason)
            } else {
                deferred_row(card, state)
            }
            .to_string()
            .len()
                + 1;
        }
        let tier = |state: &str, reason: &str| match (state, reason) {
            ("retained", "no-language-restriction") => 1,
            ("retained", _) => 0,
            _ => 2,
        };
        let mut order = (0..fits.len())
            .filter(|&index| keep[index])
            .collect::<Vec<_>>();
        order.sort_by_key(|&index| (tier(fits[index].1, fits[index].2), index));
        keep.iter_mut().for_each(|kept| *kept = false);
        for index in order {
            let (card, state, reason) = fits[index];
            let delta = (card.to_packet_value().to_string().len()
                + 1
                + row(card, state, reason).to_string().len())
            .saturating_sub(deferred_row(card, state).to_string().len());
            if (spent + delta) as u64 <= budget {
                spent += delta;
                keep[index] = true;
            } else {
                deferred_any = true;
            }
        }
    }
    let mut retained = Vec::new();
    let mut accounting = Vec::new();
    for (index, (card, state, reason)) in fits.iter().enumerate() {
        if *state == "excluded" {
            accounting.push(row(card, state, reason));
        } else if keep[index] {
            retained.push(card.to_packet_value());
            accounting.push(row(card, state, reason));
        } else {
            accounting.push(deferred_row(card, state));
        }
    }
    lens_plan["patternCards"] = json!(retained);
    // One shared exact path identity binds every candidate's decision without
    // repeating paths or card bodies in each accounting row.
    lens_plan["patternCardApplicability"] = json!({
        "sourcePaths": source_paths,
        "cards": accounting,
    });
    if deferred_any {
        lens_plan["patternCardApplicability"]["deferredCardPolicy"] = json!(
            "cards in state deferred-card-budget were not applied to this packet's source; their families are unknown, never clean"
        );
    }
}

/// Attach the A12 domain-contract evaluation to one lens packet. Missing
/// contract evidence is recorded as `absent`; it never reads as clean, and
/// policy-dependent cards must then report `unknown`. The contract is
/// evidence only and never execution authority.
pub fn bind_domain_contract(
    lens_plan: &mut Value,
    evaluation: Option<&Value>,
    domain_contract_digest: Option<&str>,
) {
    lens_plan["domainContract"] = match (evaluation, domain_contract_digest) {
        (Some(evaluation), Some(digest)) if !evaluation.is_null() && !digest.is_empty() => json!({
            "status": "bound",
            "domainContractDigest": digest,
            "executionAuthority": false,
            "evaluation": evaluation,
        }),
        _ => json!({
            "status": "absent",
            "executionAuthority": false,
            "guidance": "No domain contract is bound; policy-dependent behavior is unknown, never confirmed or clean.",
        }),
    };
}

/// Bind the repository's frozen domain-contract set to one lens packet.
/// `None` (no contract files declared and none required) is an explicit
/// `absent`. A set with unresolved boundaries, or a required set with no terms,
/// is bound as `gap` and lists every unresolved kind; it is never clean.
pub fn bind_domain_contract_set(
    lens_plan: &mut Value,
    set: Option<&crate::domain_contract::DomainContractSet>,
) {
    let Some(set) = set else {
        bind_domain_contract(lens_plan, None, None);
        return;
    };
    let evaluation = set.evaluate().to_value();
    bind_domain_contract(lens_plan, Some(&evaluation), Some(&set.set_digest));
    if !set.is_fully_resolved() {
        let kinds = set
            .unresolved
            .iter()
            .map(|boundary| serde_json::to_value(boundary.kind).unwrap_or(Value::Null))
            .collect::<Vec<_>>();
        lens_plan["domainContract"]["status"] = json!("gap");
        lens_plan["domainContract"]["gaps"] = json!(kinds);
        lens_plan["domainContract"]["required"] = json!(set.required);
    }
}

fn language_fit(language: LanguageApplicability, paths: &[&str]) -> (&'static str, &'static str) {
    let (includes, excludes) = language.reasons();
    if paths.is_empty() {
        return ("unknown", "selected-source-paths-empty");
    }
    let mut unknown = false;
    for path in paths {
        let lower = path.to_ascii_lowercase();
        if language
            .extensions()
            .iter()
            .any(|extension| lower.ends_with(*extension))
        {
            return ("retained", includes);
        }
        if !RECOGNIZED_SOURCE_EXTENSIONS
            .iter()
            .any(|extension| lower.ends_with(*extension))
        {
            unknown = true;
        }
    }
    if unknown {
        ("unknown", "selected-source-language-unknown")
    } else {
        ("excluded", excludes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn bound_for(lens: &str, paths: &[&str]) -> Value {
        let mut packet = json!({"lens": lens});
        bind_packet_cards_to_paths(
            &mut packet,
            &paths
                .iter()
                .map(|path| (*path).to_owned())
                .collect::<Vec<_>>(),
        );
        packet
    }

    fn bound_cards(paths: &[&str]) -> Value {
        bound_for("correctness", paths)
    }

    fn card_ids(packet: &Value) -> BTreeSet<&str> {
        packet["patternCards"]
            .as_array()
            .unwrap()
            .iter()
            .map(|card| card["id"].as_str().unwrap())
            .collect()
    }

    fn rows_in_state<'a>(packet: &'a Value, state: &str) -> BTreeSet<&'a str> {
        packet["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["state"] == state)
            .map(|row| row["id"].as_str().unwrap())
            .collect()
    }

    const UNRESTRICTED_CORRECTNESS: [&str; 2] = [
        "return-key-consumer-migration",
        "interactive-state-derived-output",
    ];

    #[test]
    fn rust_source_excludes_only_cards_restricted_to_other_recognized_languages() {
        for paths in [
            vec!["src/lib.rs"],
            vec!["src/react_supabase_process.env.rs"],
            vec!["src/lib.rs", "src/app.py"],
        ] {
            let bound = bound_cards(&paths);
            assert_eq!(
                card_ids(&bound),
                UNRESTRICTED_CORRECTNESS
                    .into_iter()
                    .collect::<BTreeSet<_>>()
            );
            let excluded = rows_in_state(&bound, "excluded");
            let restricted = cards_for_lens("correctness")
                .filter(|card| card.language_applicability.is_some())
                .map(|card| card.id)
                .collect::<BTreeSet<_>>();
            assert_eq!(excluded, restricted);
            assert!(excluded.contains("swift-actor-reentrancy-stale-state"));
            assert!(excluded.contains("kotlin-cancellation-swallowed"));
            assert!(excluded.contains("qwik-resumability-closure-capture"));
        }
    }

    #[test]
    fn each_language_retains_its_cards_and_excludes_the_rest() {
        let swift = bound_cards(&["App/Model.swift"]);
        assert!(card_ids(&swift).contains("swift-actor-reentrancy-stale-state"));
        assert!(!card_ids(&swift).contains("kotlin-cancellation-swallowed"));
        assert!(!card_ids(&swift).contains("react-render-state-and-eager-initializer-effects"));
        let kotlin = bound_cards(&["app/src/Main.kt", "app/build.gradle.kts"]);
        assert!(card_ids(&kotlin).contains("kotlin-cancellation-swallowed"));
        assert!(card_ids(&kotlin).contains("compose-state-ownership-and-side-effects"));
        assert!(!card_ids(&kotlin).contains("swift-actor-reentrancy-stale-state"));
        let tsx = bound_cards(&["src/routes/index.tsx"]);
        assert!(card_ids(&tsx).contains("qwik-resumability-closure-capture"));
        assert!(card_ids(&tsx).contains("react-state-effect-ownership"));
        assert!(!card_ids(&tsx).contains("swift-actor-reentrancy-stale-state"));
        // Tauri cards retain Rust, front-end, and configuration sources.
        for path in [
            "src-tauri/src/main.rs",
            "src/ui.ts",
            "src-tauri/tauri.conf.json",
        ] {
            let security = bound_for("security", &[path]);
            assert!(
                card_ids(&security).contains("tauri-ipc-command-boundary"),
                "{path}"
            );
        }
        let swift_security = bound_for("security", &["App/Model.swift"]);
        assert!(!card_ids(&swift_security).contains("tauri-ipc-command-boundary"));
        assert!(!card_ids(&swift_security).contains("rust-unsafe-invariant-evidence"));
        assert!(card_ids(&swift_security).contains("tenant-authorization-scope"));
    }

    #[test]
    fn unknown_or_unrecognized_source_never_removes_restricted_cards() {
        let all = cards_for_lens("correctness")
            .map(|card| card.id)
            .collect::<BTreeSet<_>>();
        for paths in [
            vec![],
            vec!["src/unknown.sql"],
            vec!["src/extensionless"],
            vec!["Package.swift.lock", "config/app.yaml"],
            vec!["src/lib.rs", "src/unknown.sql"],
        ] {
            let bound = bound_cards(&paths);
            assert_eq!(card_ids(&bound), all, "{paths:?}");
            assert!(rows_in_state(&bound, "excluded").is_empty());
            let restricted = cards_for_lens("correctness")
                .filter(|card| card.language_applicability.is_some())
                .map(|card| card.id)
                .collect::<BTreeSet<_>>();
            assert_eq!(rows_in_state(&bound, "unknown"), restricted);
        }
        for extension in ["js", "jsx", "mjs", "cjs", "ts", "tsx", "TSX"] {
            let path = format!("src/plain.{extension}");
            let bound = bound_cards(&[&path]);
            // Plain JS/TS establishes language only, never framework or trigger fit.
            for id in [
                "supabase-single-missing-row-response",
                "environment-read-before-config-loader",
                "react-render-state-and-eager-initializer-effects",
                "qwik-resumability-closure-capture",
                "react-state-effect-ownership",
            ] {
                assert!(card_ids(&bound).contains(id), "{path} {id}");
            }
        }
    }

    #[test]
    fn accounting_has_one_state_per_candidate_and_stable_source_identity() {
        let bound = bound_cards(&["src/z.rs", "src/a.py", "src/z.rs"]);
        let reordered = bound_cards(&["src/a.py", "src/z.rs"]);
        assert_eq!(bound, reordered);
        assert_eq!(
            bound["patternCardApplicability"]["sourcePaths"],
            json!(["src/a.py", "src/z.rs"])
        );
        let rows = bound["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap();
        let accounted = rows
            .iter()
            .map(|row| {
                assert!(matches!(
                    row["state"].as_str(),
                    Some("retained" | "excluded" | "unknown")
                ));
                assert!(row["reason"].is_string());
                assert_eq!(row.as_object().unwrap().len(), 3);
                row["id"].as_str().unwrap()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(accounted.len(), rows.len());
        assert_eq!(
            accounted,
            cards_for_lens("correctness")
                .map(|card| card.id)
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn language_restrictions_are_exactly_the_declared_set() {
        let restricted = PATTERN_CARDS
            .iter()
            .filter(|card| card.language_applicability.is_some())
            .map(|card| (card.id, card.language_applicability.unwrap()))
            .collect::<Vec<_>>();
        let expect = |language: LanguageApplicability| {
            restricted
                .iter()
                .filter(|(_, candidate)| *candidate == language)
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            expect(LanguageApplicability::JavaScriptOrTypeScript),
            BTreeSet::from([
                "supabase-single-missing-row-response",
                "environment-read-before-config-loader",
                "react-render-state-and-eager-initializer-effects",
                "qwik-server-client-serialization",
                "qwik-resumability-closure-capture",
                "qwik-loader-action-validation",
                "react-state-effect-ownership",
            ])
        );
        assert_eq!(
            expect(LanguageApplicability::Swift),
            BTreeSet::from([
                "swift-actor-reentrancy-stale-state",
                "swift-task-cancellation-ignored",
                "swift-closure-retain-cycle",
            ])
        );
        assert_eq!(
            expect(LanguageApplicability::Kotlin),
            BTreeSet::from([
                "kotlin-cancellation-swallowed",
                "android-lifecycle-scope-and-context-leak",
                "compose-state-ownership-and-side-effects",
            ])
        );
        assert_eq!(
            expect(LanguageApplicability::Rust),
            BTreeSet::from([
                "rust-async-blocking-call",
                "rust-async-cancellation-safety",
                "rust-unsafe-invariant-evidence",
                "rust-gui-per-frame-work",
            ])
        );
        assert_eq!(
            expect(LanguageApplicability::Sql),
            BTreeSet::from(["migration-expand-contract-rollout"])
        );
        assert_eq!(
            expect(LanguageApplicability::TauriSurface),
            BTreeSet::from([
                "tauri-ipc-command-boundary",
                "tauri-capability-scope-breadth",
                "tauri-deeplink-and-update-trust",
            ])
        );
        for lens in ["data-safety", "security", "performance"] {
            let mut bound = json!({"lens": lens});
            bind_packet_cards_to_paths(&mut bound, &["src/unknown.cfg".into()]);
            assert_eq!(
                bound["patternCards"].as_array().unwrap().len(),
                cards_for_lens(lens).count()
            );
        }
    }

    #[test]
    fn every_card_has_required_versioned_trace_falsifier_and_paired_cases() {
        let mut ids = BTreeSet::new();
        for card in PATTERN_CARDS {
            assert_eq!(card.version, "1");
            assert!(ids.insert(card.id), "duplicate card id {}", card.id);
            assert!(!card.id.is_empty());
            assert!(!card.owner_lens.is_empty());
            assert!(!card.applicability.is_empty());
            assert!(!card.trigger_evidence.is_empty());
            assert!(!card.required_source_trace.is_empty());
            assert!(!card.falsifier.is_empty());
            assert!(!card.positive_case.is_empty());
            assert!(!card.negative_case.is_empty());
            assert_ne!(card.positive_case, card.negative_case, "{}", card.id);
            assert!(
                card.no_evidence.to_ascii_lowercase().contains("unknown"),
                "{} must keep the unknown outcome",
                card.id
            );
            for text in [
                card.applicability,
                card.trigger_evidence,
                card.required_source_trace,
                card.falsifier,
                card.no_evidence,
            ] {
                assert!(!text.to_ascii_lowercase().contains("at least one finding"));
            }
        }
    }

    #[test]
    fn authored_cards_stay_draft_and_routing_never_promotes_maturity() {
        assert!(PATTERN_CARDS
            .iter()
            .all(|card| card.maturity == RuleMaturity::Draft));
        for lens in [
            "correctness",
            "security",
            "data-safety",
            "performance",
            "resilience",
            "release-readiness",
            "a11y",
            "architecture",
        ] {
            for card in packet_cards_for_lens(lens) {
                assert_eq!(card["ruleMaturity"], "draft");
            }
            let bound = bound_for(lens, &["src/lib.rs"]);
            for card in bound["patternCards"].as_array().unwrap() {
                assert_eq!(card["ruleMaturity"], "draft");
                // Routing carries no measured benchmark field.
                for field in ["benchmark", "recall", "precision", "qualification"] {
                    assert!(card.get(field).is_none(), "{field}");
                }
            }
        }
        assert_eq!(RuleMaturity::Shadow.as_str(), "shadow");
        assert_eq!(RuleMaturity::Qualified.as_str(), "qualified");
    }

    #[test]
    fn version_and_config_applicability_are_emitted_only_when_declared() {
        let security = packet_cards_for_lens("security");
        let tauri = security
            .iter()
            .find(|card| card["id"] == "tauri-ipc-command-boundary")
            .unwrap();
        assert!(tauri["versionApplicability"].is_string());
        assert!(tauri["configApplicability"].is_string());
        let definer = security
            .iter()
            .find(|card| card["id"] == "postgres-definer-searchpath-and-public-execute")
            .unwrap();
        assert!(definer.get("versionApplicability").is_none());
        assert!(definer.get("configApplicability").is_none());
    }

    #[test]
    fn excluded_rule_families_are_not_present() {
        for card in PATTERN_CARDS {
            for forbidden in [
                "pinning",
                "down-migration",
                "di-seam",
                "dependency-injection",
            ] {
                assert!(!card.id.contains(forbidden), "{}", card.id);
            }
        }
    }

    #[test]
    fn platform_cards_are_owned_by_existing_lenses() {
        for (id, lens) in [
            ("qwik-server-client-serialization", "security"),
            ("qwik-resumability-closure-capture", "correctness"),
            ("qwik-loader-action-validation", "security"),
            ("react-state-effect-ownership", "correctness"),
            (
                "secret-serialization-through-logs-and-telemetry",
                "security",
            ),
            ("commerce-money-and-inventory-invariants", "data-safety"),
            ("webhook-idempotency-and-verification-order", "data-safety"),
            ("tenant-authorization-scope", "security"),
            ("swift-actor-reentrancy-stale-state", "correctness"),
            ("swift-task-cancellation-ignored", "resilience"),
            ("swift-closure-retain-cycle", "resilience"),
            ("kotlin-cancellation-swallowed", "correctness"),
            ("android-lifecycle-scope-and-context-leak", "resilience"),
            ("compose-state-ownership-and-side-effects", "correctness"),
            ("rust-async-blocking-call", "performance"),
            ("rust-async-cancellation-safety", "resilience"),
            ("rust-unsafe-invariant-evidence", "security"),
            ("tauri-ipc-command-boundary", "security"),
            ("tauri-capability-scope-breadth", "security"),
            ("tauri-deeplink-and-update-trust", "security"),
            ("rust-gui-per-frame-work", "performance"),
            ("migration-expand-contract-rollout", "data-safety"),
            (
                "version-gated-api-without-minimum-guard",
                "release-readiness",
            ),
            (
                "config-key-drift-between-code-and-environments",
                "release-readiness",
            ),
            ("a11y-interactive-name-role-keyboard", "a11y"),
            ("privacy-collection-consent-and-disclosure", "data-safety"),
            ("outbound-call-timeout-and-retry-bound", "resilience"),
            ("release-debug-surface-shipped", "release-readiness"),
            (
                "component-decomposition-recommendation-contract",
                "architecture",
            ),
        ] {
            let card = PATTERN_CARDS.iter().find(|card| card.id == id).expect(id);
            assert_eq!(card.owner_lens, lens, "{id}");
            assert!(cards_for_lens(lens).any(|selected| selected.id == id));
        }
        assert!(cards_for_lens("unknown").next().is_none());
        assert!(cards_for_lens("naming").next().is_none());
    }

    #[test]
    fn domain_contract_binding_never_reads_absence_as_clean() {
        let mut plan = json!({"lens": "data-safety"});
        bind_domain_contract(&mut plan, None, None);
        assert_eq!(plan["domainContract"]["status"], "absent");
        assert_eq!(plan["domainContract"]["executionAuthority"], false);
        bind_domain_contract(&mut plan, Some(&json!({"candidates": []})), Some(""));
        assert_eq!(plan["domainContract"]["status"], "absent");
        bind_domain_contract(
            &mut plan,
            Some(&json!({"candidates": [{"rule": "unit-mismatch"}]})),
            Some("sha256:abc"),
        );
        assert_eq!(plan["domainContract"]["status"], "bound");
        assert_eq!(plan["domainContract"]["domainContractDigest"], "sha256:abc");
        assert_eq!(plan["domainContract"]["executionAuthority"], false);
        assert_eq!(
            plan["domainContract"]["evaluation"]["candidates"][0]["rule"],
            "unit-mismatch"
        );
    }

    #[test]
    fn packet_cards_preserve_required_fields_and_unknown_policy() {
        let cards = packet_cards_for_lens("correctness");
        assert!(!cards.is_empty());
        for card in cards {
            for field in [
                "version",
                "id",
                "ownerLens",
                "applicability",
                "ruleMaturity",
                "triggerEvidence",
                "requiredSourceTrace",
                "falsifier",
                "noEvidence",
            ] {
                assert!(card.get(field).is_some(), "missing {field}");
            }
            assert!(card["pairedCases"]["positive"].is_string());
            assert!(card["pairedCases"]["negative"].is_string());
        }
    }

    const SPECIALIST_CARDS: [&str; 3] = [
        "smart-contract-reentrancy-access-oracle",
        "embedded-firmware-update-debug-keys",
        "ics-ot-unauthenticated-control-safety",
    ];
    const COMMON_GROUP_CARDS: [&str; 6] = [
        "ssrf-egress-url-fetch",
        "http-proxy-cache-smuggling",
        "auth-session-state-machine",
        "native-workspace-trust-auto-exec",
        "ai-memory-rag-poisoning-grounding",
        "admin-workflow-impersonation-bulk-abuse",
    ];

    fn state_of<'a>(packet: &'a Value, id: &str) -> (&'a str, &'a str) {
        let row = packet["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap_or_else(|| panic!("no accounting row for {id}"));
        (
            row["state"].as_str().unwrap(),
            row["reason"].as_str().unwrap(),
        )
    }

    #[test]
    fn security_card_groups_are_exactly_the_declared_evidence_set() {
        let grouped = cards_for_lens("security")
            .filter(|card| card.domain_evidence.is_some())
            .map(|card| card.id)
            .collect::<BTreeSet<_>>();
        let expected = COMMON_GROUP_CARDS
            .iter()
            .chain(SPECIALIST_CARDS.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(grouped, expected);
        for id in SPECIALIST_CARDS {
            let card = PATTERN_CARDS.iter().find(|card| card.id == id).unwrap();
            assert_eq!(card.domain_evidence.unwrap().tier(), DomainTier::Specialist);
            assert_eq!(card.owner_lens, "security");
        }
        for id in COMMON_GROUP_CARDS {
            let card = PATTERN_CARDS.iter().find(|card| card.id == id).unwrap();
            assert_eq!(card.domain_evidence.unwrap().tier(), DomainTier::Common);
        }
        // The always-on core keeps no group, so it never depends on path evidence.
        for id in [
            "secret-serialization-through-logs-and-telemetry",
            "tenant-authorization-scope",
            "postgres-definer-searchpath-and-public-execute",
            "rust-unsafe-invariant-evidence",
            "qwik-loader-action-validation",
        ] {
            let card = PATTERN_CARDS.iter().find(|card| card.id == id).unwrap();
            assert!(card.domain_evidence.is_none(), "{id}");
        }
    }

    #[test]
    fn specialist_cards_apply_only_on_strong_path_evidence() {
        let plain = bound_for("security", &["src/lib.rs", "src/app.ts"]);
        for id in SPECIALIST_CARDS {
            assert_eq!(
                state_of(&plain, id),
                ("excluded", "specialist-domain-evidence-absent"),
                "{id}"
            );
            assert!(!card_ids(&plain).contains(id), "{id}");
        }
        for (path, id) in [
            (
                "contracts/Vault.sol",
                "smart-contract-reentrancy-access-oracle",
            ),
            ("foundry.toml", "smart-contract-reentrancy-access-oracle"),
            (
                "firmware/src/main.rs",
                "embedded-firmware-update-debug-keys",
            ),
            ("platformio.ini", "embedded-firmware-update-debug-keys"),
            ("plc/pump.scl", "ics-ot-unauthenticated-control-safety"),
            (
                "src/modbus_client.rs",
                "ics-ot-unauthenticated-control-safety",
            ),
            (
                "src/opc-ua/server.rs",
                "ics-ot-unauthenticated-control-safety",
            ),
        ] {
            let bound = bound_for("security", &[path, "src/lib.rs"]);
            assert_eq!(
                state_of(&bound, id),
                ("retained", "domain-path-evidence-present"),
                "{path}"
            );
            assert!(card_ids(&bound).contains(id), "{path}");
        }
        // Weak lookalikes are not strong evidence.
        for path in ["src/quota.rs", "src/storage/garage.rs", "docs/plcement.rs"] {
            let bound = bound_for("security", &[path]);
            for id in SPECIALIST_CARDS {
                assert_eq!(state_of(&bound, id).0, "excluded", "{path} {id}");
            }
        }
    }

    #[test]
    fn unknown_applicability_stays_unknown_and_retained_never_excluded() {
        for paths in [
            vec![],
            vec!["config/app.yaml"],
            vec!["Cargo.toml", "src/lib.rs"],
            vec!["src/driver.c", "src/lib.rs"],
        ] {
            let bound = bound_for("security", &paths);
            for id in SPECIALIST_CARDS {
                assert_eq!(state_of(&bound, id).0, "unknown", "{paths:?} {id}");
                assert!(card_ids(&bound).contains(id), "{paths:?} {id}");
            }
            for id in COMMON_GROUP_CARDS {
                assert!(card_ids(&bound).contains(id), "{paths:?} {id}");
                assert_ne!(state_of(&bound, id).0, "excluded", "{paths:?} {id}");
            }
        }
    }

    #[test]
    fn common_groups_are_never_excluded_and_report_evidence_state() {
        let none = bound_for("security", &["src/lib.rs"]);
        for id in COMMON_GROUP_CARDS {
            assert_eq!(
                state_of(&none, id),
                ("unknown", "domain-evidence-not-established-by-paths"),
                "{id}"
            );
        }
        for (path, id) in [
            ("src/ssrf/fetch_url.rs", "ssrf-egress-url-fetch"),
            ("deploy/nginx.conf", "http-proxy-cache-smuggling"),
            ("src/auth/login.ts", "auth-session-state-machine"),
            ("repo/.mcp.json", "native-workspace-trust-auto-exec"),
            (".githooks/pre-commit", "native-workspace-trust-auto-exec"),
            ("src/rag/retriever.py", "ai-memory-rag-poisoning-grounding"),
            (
                "src/admin/impersonate.ts",
                "admin-workflow-impersonation-bulk-abuse",
            ),
        ] {
            let bound = bound_for("security", &[path]);
            assert_eq!(
                state_of(&bound, id),
                ("retained", "domain-path-evidence-present"),
                "{path}"
            );
        }
        // Group tokens match whole path tokens, not substrings.
        assert!(!DomainEvidence::AiMemory.path_matches("src/storage/fragment.rs"));
        assert!(!DomainEvidence::AuthSession.path_matches("src/author/list.ts"));
    }

    #[test]
    fn domain_cards_emit_applicability_group_and_keep_core_unchanged() {
        let security = packet_cards_for_lens("security");
        let ics = security
            .iter()
            .find(|card| card["id"] == "ics-ot-unauthenticated-control-safety")
            .unwrap();
        assert_eq!(ics["domainApplicability"]["group"], "ics-ot");
        assert_eq!(
            ics["domainApplicability"]["tier"],
            "specialist-strong-evidence-only"
        );
        let ssrf = security
            .iter()
            .find(|card| card["id"] == "ssrf-egress-url-fetch")
            .unwrap();
        assert_eq!(ssrf["domainApplicability"]["tier"], "evidence-selected");
        let core = security
            .iter()
            .find(|card| card["id"] == "tenant-authorization-scope")
            .unwrap();
        assert!(core.get("domainApplicability").is_none());
    }

    fn budgeted_security(paths: &[&str], budget: u64) -> Value {
        let mut packet = json!({"lens": "security"});
        bind_packet_cards_to_paths_budgeted(
            &mut packet,
            &paths
                .iter()
                .map(|path| path.to_string())
                .collect::<Vec<_>>(),
            Some(budget),
        );
        packet
    }

    #[test]
    fn card_budget_defers_unknown_cards_to_compact_rows_within_the_cap() {
        let budget = packet_card_budget_bytes(15_000);
        assert_eq!(budget, 15_000 * CARD_BUDGET_PERCENT / 100);
        // Unrecognized extensions leave every language-gated and common-domain
        // card unknown; none of them may force a full body.
        let packet = budgeted_security(
            &["scripts/run.sh", "docs/README.md", "db/schema.sql"],
            budget,
        );
        let bodies = packet["patternCards"].as_array().unwrap();
        let rows = packet["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap();
        assert_eq!(rows.len(), 18);
        let deferred = rows
            .iter()
            .filter(|row| row["state"] == DEFERRED_CARD_STATE)
            .collect::<Vec<_>>();
        assert!(!deferred.is_empty());
        assert!(bodies.len() < 18);
        assert!(bound_card_bytes(&packet) <= max_card_bytes_bound(Some(budget)));
        assert!(max_card_bytes_bound(Some(budget)) < max_card_bytes_bound(None));
        let body_ids = bodies
            .iter()
            .map(|card| card["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        for row in &deferred {
            // Unknown, never clean: no body, no clean state, trigger kept, and
            // the packet states the policy.
            assert!(!body_ids.contains(&row["id"].as_str().unwrap()));
            assert_ne!(row["priorState"], "excluded");
            assert!(row["reason"]
                .as_str()
                .unwrap()
                .contains("unknown-never-clean"));
            assert!(!row["trigger"].as_str().unwrap().is_empty());
            assert!(row["trigger"].as_str().unwrap().chars().count() <= 64);
        }
        assert!(packet["patternCardApplicability"]["deferredCardPolicy"]
            .as_str()
            .unwrap()
            .contains("never clean"));
        // Every body in the packet has a non-deferred row.
        for id in body_ids {
            let row = rows.iter().find(|row| row["id"] == id).unwrap();
            assert_ne!(row["state"], DEFERRED_CARD_STATE);
        }
    }

    #[test]
    fn card_budget_prefers_positively_evidenced_then_core_cards() {
        // A Rust path positively evidences the Rust-gated card; with a budget
        // that fits few bodies, evidenced cards precede always-on core, which
        // precede merely unknown ones.
        let mut packet = json!({"lens": "correctness"});
        bind_packet_cards_to_paths_budgeted(
            &mut packet,
            &["src/lib.rs".to_string(), "tool.sh".to_string()],
            Some(packet_card_budget_bytes(15_000)),
        );
        let rows = packet["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap();
        let first_unknown_kept = rows.iter().any(|row| {
            row["state"] == "unknown"
                && packet["patternCards"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|card| card["id"] == row["id"])
        });
        let evidenced_deferred = rows
            .iter()
            .any(|row| row["state"] == DEFERRED_CARD_STATE && row["priorState"] == "retained");
        // An unknown card never holds a body while an evidenced/core card is deferred.
        assert!(!(first_unknown_kept && evidenced_deferred));
    }

    #[test]
    fn card_budget_none_keeps_every_applicable_card() {
        let mut unbudgeted = json!({"lens": "security"});
        bind_packet_cards_to_paths(&mut unbudgeted, &["tool.sh".to_string()]);
        assert_eq!(unbudgeted["patternCards"].as_array().unwrap().len(), 18);
        assert!(unbudgeted["patternCardApplicability"]
            .get("deferredCardPolicy")
            .is_none());
    }
}
