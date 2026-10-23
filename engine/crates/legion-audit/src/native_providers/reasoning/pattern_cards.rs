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

/// Upper bound of `bound_card_bytes` for any lens: every owned card retained
/// plus a generous per-card accounting row. Used to normalize packet sizing so
/// lenses of one bundle keep deriving the same excerpt parts (and keep sharing
/// seats) however many cards each lens owns.
pub fn max_card_bytes_bound() -> u64 {
    let mut lenses = PATTERN_CARDS
        .iter()
        .map(|card| card.owner_lens)
        .collect::<Vec<_>>();
    lenses.sort_unstable();
    lenses.dedup();
    lenses
        .into_iter()
        .map(|lens| {
            cards_for_lens(lens)
                .map(|card| card.to_packet_value().to_string().len() + card.id.len() + 120)
                .sum::<usize>() as u64
        })
        .max()
        .unwrap_or(0)
}

/// Bind cards after source selection/partitioning, never from repository-wide
/// language guesses. Unknown language, framework, or trigger fit retains work.
pub fn bind_packet_cards_to_paths(lens_plan: &mut Value, selected_paths: &[String]) {
    let Some(lens) = lens_plan.get("lens").and_then(Value::as_str) else {
        return;
    };
    let mut source_paths = selected_paths
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    source_paths.sort_unstable();
    source_paths.dedup();
    let mut retained = Vec::new();
    let mut accounting = Vec::new();
    for card in cards_for_lens(lens) {
        let (state, reason) = match card.language_applicability {
            None => ("retained", "no-language-restriction"),
            Some(language) => language_fit(language, &source_paths),
        };
        if state != "excluded" {
            retained.push(card.to_packet_value());
        }
        accounting.push(json!({"id": card.id, "state": state, "reason": reason}));
    }
    lens_plan["patternCards"] = json!(retained);
    // One shared exact path identity binds every candidate's decision without
    // repeating paths or card bodies in each accounting row.
    lens_plan["patternCardApplicability"] = json!({
        "sourcePaths": source_paths,
        "cards": accounting,
    });
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
}
