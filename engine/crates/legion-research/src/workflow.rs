use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use crate::{
    budget::{BudgetAccount, BudgetLimits, BudgetSnapshot},
    error::ResearchError,
    evidence::{Claim, EvidenceKind, EvidenceLedger, EvidenceRecord},
    report::{ReportBuilder, ResearchReport},
    source::InjectedSource,
};

const ROUTE_DOMAINS: &[&str] = &[
    "general",
    "market",
    "technical",
    "scientific",
    "medical",
    "legal",
];
const ROUTE_OPERATIONS: &[&str] = &[
    "discover",
    "compare",
    "verify",
    "analyze",
    "advise",
    "review",
    "draft",
    "procedure",
    "manage-corpus",
    "generate-artifact",
];
const ROUTE_METHODS: &[&str] = &[
    "web",
    "competitor",
    "reddit",
    "audience",
    "trends",
    "scholarly",
    "document",
    "authority",
];
const ROUTE_PROVIDERS: &[&str] = &["browser", "local-corpus", "notebooklm", "domain-default"];
const ROUTE_ASSURANCE: &[&str] = &["quick", "standard", "verified"];
const ROUTE_SCALE: &[&str] = &["focused", "broad", "dossier"];
const ROUTE_EFFECTS: &[&str] = &[
    "read-local",
    "read-sensitive",
    "load-medical-history",
    "search",
    "fetch",
    "extract",
    "synthesize",
    "citecheck",
    "retraction-check",
    "upload-notebooklm",
    "create-artifact",
    "write-output",
    "patch-sourced-draft",
    "spawn-worker",
];
const ROUTE_GATES: &[&str] = &[
    "confirm-personal-medical-route",
    "approve-notebooklm-upload",
    "approve-notebooklm-publish",
    "confirm-jurisdiction",
    "confirm-legal-area",
    "confirm-legal-issue",
    "confirm-consumer-filing-facts",
    "confirm-anonymous-vs-identified",
    "approve-send-sign-file",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResearchNumber {
    Signed(i64),
    Unsigned(u64),
    Float(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResearchValue {
    Null,
    Bool(bool),
    Number(ResearchNumber),
    String(String),
    Array(Vec<ResearchValue>),
    Object(BTreeMap<String, ResearchValue>),
}

impl Serialize for ResearchValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(ResearchNumber::Signed(value)) => serializer.serialize_i64(*value),
            Self::Number(ResearchNumber::Unsigned(value)) => serializer.serialize_u64(*value),
            Self::Number(ResearchNumber::Float(bits)) => {
                serializer.serialize_f64(f64::from_bits(*bits))
            }
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => values.serialize(serializer),
            Self::Object(values) => values.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ResearchValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResearchValueVisitor;

        impl<'de> Visitor<'de> for ResearchValueVisitor {
            type Value = ResearchValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON-shaped research value")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ResearchValue::Null)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ResearchValue::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ResearchValue::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ResearchValue::Number(ResearchNumber::Signed(value)))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ResearchValue::Number(ResearchNumber::Unsigned(value)))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.is_finite() {
                    Ok(ResearchValue::Number(ResearchNumber::Float(
                        value.to_bits(),
                    )))
                } else {
                    Err(E::custom("research JSON number must be finite"))
                }
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ResearchValue::String(value.into()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ResearchValue::String(value))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(ResearchValue::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry()? {
                    values.insert(key, value);
                }
                Ok(ResearchValue::Object(values))
            }
        }

        deserializer.deserialize_any(ResearchValueVisitor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NullableString {
    Null,
    Value(String),
}

impl Serialize for NullableString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_none(),
            Self::Value(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for NullableString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NullableStringVisitor;

        impl<'de> Visitor<'de> for NullableStringVisitor {
            type Value = NullableString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a string or null")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NullableString::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NullableString::Null)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer).map(NullableString::Value)
            }
        }

        deserializer.deserialize_option(NullableStringVisitor)
    }
}

fn deserialize_nullable_field<'de, D>(deserializer: D) -> Result<Option<NullableString>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptionalNullableStringVisitor;

    impl<'de> Visitor<'de> for OptionalNullableStringVisitor {
        type Value = Option<NullableString>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(NullableString::Null))
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(NullableString::Null))
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            NullableString::deserialize(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(OptionalNullableStringVisitor)
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResearchPatient {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_available: Option<bool>,
    #[serde(
        deserialize_with = "deserialize_nullable_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub history_source: Option<NullableString>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, ResearchValue>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResearchSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(
        deserialize_with = "deserialize_nullable_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub country: Option<NullableString>,
    #[serde(
        deserialize_with = "deserialize_nullable_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub area: Option<NullableString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patient: Option<ResearchPatient>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, ResearchValue>,
}

impl ResearchSubject {
    fn for_query(query: &str) -> Self {
        Self {
            query: Some(query.into()),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchRoute {
    pub route_version: u32,
    pub domain: String,
    pub operation: String,
    pub methods: Vec<String>,
    pub provider: String,
    pub assurance: String,
    pub scale: String,
    pub subject: ResearchSubject,
    pub sensitivity: String,
    pub decision: String,
    pub output: String,
    pub allowed_effects: Vec<String>,
    pub human_gates: Vec<String>,
    pub forbidden_resources: Vec<String>,
}

impl ResearchRoute {
    /// Explicit route used by public host-injected source-record integration.
    /// It is not a classifier and carries no pending human gate.
    pub fn host_injected(query: &str) -> Self {
        Self {
            route_version: 2,
            domain: "general".into(),
            operation: "discover".into(),
            methods: vec!["document".into()],
            provider: "local-corpus".into(),
            assurance: "standard".into(),
            scale: "focused".into(),
            subject: ResearchSubject::for_query(query),
            sensitivity: "public".into(),
            decision: query.into(),
            output: "route-scoped evidence report".into(),
            allowed_effects: vec![
                "read-local".into(),
                "search".into(),
                "extract".into(),
                "synthesize".into(),
                "citecheck".into(),
                "write-output".into(),
            ],
            human_gates: Vec::new(),
            forbidden_resources: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.route_version != 2 {
            return Err(ResearchError::invalid(
                "research route must use schema version 2",
            ));
        }
        require_route_value("domain", &self.domain, ROUTE_DOMAINS)?;
        require_route_value("operation", &self.operation, ROUTE_OPERATIONS)?;
        require_route_value("provider", &self.provider, ROUTE_PROVIDERS)?;
        require_route_value("assurance", &self.assurance, ROUTE_ASSURANCE)?;
        require_route_value("scale", &self.scale, ROUTE_SCALE)?;
        require_route_value(
            "sensitivity",
            &self.sensitivity,
            &["public", "private", "highly-sensitive"],
        )?;
        if self.methods.is_empty() {
            return Err(ResearchError::invalid(
                "research route requires at least one method",
            ));
        }
        validate_unique_values("methods", &self.methods, ROUTE_METHODS)?;
        validate_unique_values("allowed_effects", &self.allowed_effects, ROUTE_EFFECTS)?;
        validate_unique_values("human_gates", &self.human_gates, ROUTE_GATES)?;
        let mut forbidden = std::collections::BTreeSet::new();
        if self
            .forbidden_resources
            .iter()
            .any(|resource| !forbidden.insert(resource))
        {
            return Err(ResearchError::invalid(
                "forbidden_resources must not contain duplicates",
            ));
        }
        if self.decision.trim().is_empty() || self.output.trim().is_empty() {
            return Err(ResearchError::invalid(
                "research route decision and output must be non-empty",
            ));
        }
        match self.domain.as_str() {
            "medical" => {
                let patient = self.subject.patient.as_ref().ok_or_else(|| {
                    ResearchError::invalid("medical route requires subject.patient")
                })?;
                let kind = patient.kind.as_str();
                if kind.trim().is_empty() {
                    return Err(ResearchError::invalid(
                        "medical route patient.kind is required",
                    ));
                }
                require_route_value(
                    "subject.patient.kind",
                    kind,
                    &["anonymous", "self", "other-identified"],
                )?;
                require_subject_string(self.subject.issue.as_deref(), "issue")?;
            }
            "legal" => {
                let country = self
                    .subject
                    .country
                    .as_ref()
                    .ok_or_else(|| ResearchError::invalid("legal route country is required"))?;
                if let NullableString::Value(country) = country {
                    if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase())
                    {
                        return Err(ResearchError::invalid(
                            "legal route country must be ISO uppercase alpha-2",
                        ));
                    }
                }
                let area = self
                    .subject
                    .area
                    .as_ref()
                    .ok_or_else(|| ResearchError::invalid("legal route area is required"))?;
                if let NullableString::Value(area) = area {
                    require_route_value(
                        "subject.area",
                        area,
                        &[
                            "consumer",
                            "criminal",
                            "civil",
                            "contract",
                            "employment",
                            "corporate",
                            "tax",
                            "ip",
                            "privacy",
                            "family",
                            "immigration",
                            "regulatory",
                            "other",
                        ],
                    )?;
                }
                require_subject_string(self.subject.issue.as_deref(), "issue")?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ResearchError> {
        self.validate()?;
        legion_contracts::canonical_digest(self)
            .map_err(|error| ResearchError::Report(error.to_string()))
    }

    pub(crate) fn validate_effects(values: &[String]) -> Result<(), ResearchError> {
        validate_unique_values("allowed_effects", values, ROUTE_EFFECTS)
    }

    pub(crate) fn validate_effect_grant(values: &[String]) -> Result<(), ResearchError> {
        validate_unique_values("effect_grant", values, ROUTE_EFFECTS)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchAuthorization {
    pub approval_receipt_ids: Vec<String>,
    pub effect_grant: Vec<String>,
}

impl ResearchAuthorization {
    pub fn full(route: &ResearchRoute) -> Result<Self, ResearchError> {
        route.validate()?;
        Ok(Self {
            approval_receipt_ids: Vec::new(),
            effect_grant: route.allowed_effects.clone(),
        })
    }

    pub fn validate(&self, route: &ResearchRoute) -> Result<(), ResearchError> {
        route.validate()?;
        validate_unique_values("effect_grant", &self.effect_grant, ROUTE_EFFECTS)?;
        if self.effect_grant.iter().any(|effect| {
            !route
                .allowed_effects
                .iter()
                .any(|allowed| allowed == effect)
        }) {
            return Err(ResearchError::invalid(
                "effect grant contains effect outside frozen route allowance",
            ));
        }
        if self
            .approval_receipt_ids
            .iter()
            .any(|receipt| receipt.trim().is_empty())
        {
            return Err(ResearchError::invalid(
                "approval receipt identities must be non-empty",
            ));
        }
        let mut identities = self.approval_receipt_ids.clone();
        identities.sort();
        identities.dedup();
        if identities.len() != self.approval_receipt_ids.len() {
            return Err(ResearchError::invalid(
                "approval receipt identities must be unique",
            ));
        }
        if self.approval_receipt_ids.len() > route.human_gates.len() {
            return Err(ResearchError::invalid(
                "approval receipt identities exceed frozen human gates",
            ));
        }
        Ok(())
    }

    fn grants_effects(&self, route: &ResearchRoute) -> bool {
        !route.allowed_effects.is_empty() && !self.effect_grant.is_empty()
    }

    fn medical_effects_satisfied(&self, route: &ResearchRoute) -> bool {
        !personal_medical_route(route)
            || (self.effect_granted(route, "read-sensitive")
                && self.effect_granted(route, "load-medical-history"))
    }

    fn gates_satisfied(&self, route: &ResearchRoute) -> bool {
        if self.approval_receipt_ids.len() != route.human_gates.len() {
            return false;
        }
        if route.domain == "legal" && !legal_context_complete(route) {
            return false;
        }
        if route.domain == "medical"
            && personal_medical_route(route)
            && (!route
                .human_gates
                .iter()
                .any(|gate| gate == "confirm-personal-medical-route")
                || !medical_history_available(route))
        {
            return false;
        }
        if route.domain == "medical"
            && route.subject.patient.as_ref().is_some_and(|patient| {
                patient.kind == "anonymous"
                    && self
                        .effect_grant
                        .iter()
                        .any(|effect| effect == "load-medical-history")
            })
        {
            return false;
        }
        true
    }

    fn effect_granted(&self, route: &ResearchRoute, effect: &str) -> bool {
        route
            .allowed_effects
            .iter()
            .any(|allowed| allowed == effect)
            && self.effect_grant.iter().any(|grant| grant == effect)
    }
}

fn medical_history_available(route: &ResearchRoute) -> bool {
    let Some(patient) = route.subject.patient.as_ref() else {
        return false;
    };
    patient.history_available.unwrap_or(false)
        && patient.history_source.as_ref().is_some_and(
            |source| matches!(source, NullableString::Value(value) if !value.trim().is_empty()),
        )
}

fn legal_context_complete(route: &ResearchRoute) -> bool {
    let country_complete = route
        .subject
        .country
        .as_ref()
        .is_some_and(|country| matches!(country, NullableString::Value(value) if value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase())));
    let area_complete = route.subject.area.as_ref().is_some_and(
        |area| matches!(area, NullableString::Value(value) if !value.trim().is_empty()),
    );
    let issue_complete = route
        .subject
        .issue
        .as_deref()
        .is_some_and(|issue| !issue.trim().is_empty());
    country_complete && area_complete && issue_complete
}

fn personal_medical_route(route: &ResearchRoute) -> bool {
    route.domain == "medical"
        && route
            .subject
            .patient
            .as_ref()
            .is_some_and(|patient| matches!(patient.kind.as_str(), "self" | "other-identified"))
}

fn normalize_resource(value: &str) -> String {
    let mut normalized = value.trim().replace('\\', "/");
    while normalized.ends_with('/') && !normalized.ends_with("://") {
        normalized.pop();
    }
    normalized
}

fn forbidden_resource_match(route: &ResearchRoute, uri: &str) -> Option<String> {
    let normalized_uri = normalize_resource(uri);
    route
        .forbidden_resources
        .iter()
        .find(|pattern| {
            let normalized_pattern = normalize_resource(pattern);
            if let Some(prefix) = normalized_pattern.strip_suffix("/**") {
                !prefix.is_empty()
                    && (normalized_uri == prefix
                        || normalized_uri.starts_with(&format!("{prefix}/")))
            } else {
                normalized_uri == normalized_pattern
            }
        })
        .cloned()
}

fn require_route_value(field: &str, value: &str, allowed: &[&str]) -> Result<(), ResearchError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(ResearchError::invalid(format!(
            "{field} uses unsupported route value {value}"
        )))
    }
}

fn validate_unique_values(
    field: &str,
    values: &[String],
    allowed: &[&str],
) -> Result<(), ResearchError> {
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        require_route_value(field, value, allowed)?;
        if !unique.insert(value) {
            return Err(ResearchError::invalid(format!(
                "{field} must not contain duplicates"
            )));
        }
    }
    Ok(())
}

fn require_subject_string(value: Option<&str>, field: &str) -> Result<(), ResearchError> {
    if value.is_some_and(|value| !value.trim().is_empty()) {
        Ok(())
    } else {
        Err(ResearchError::invalid(format!(
            "route subject.{field} is required"
        )))
    }
}

type CancellationProbe = Arc<dyn Fn() -> bool + Send + Sync>;

#[derive(Clone, Default)]
pub struct Cancellation {
    local: Arc<AtomicBool>,
    external: Arc<Mutex<Vec<CancellationProbe>>>,
}

impl Cancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_probe<F>(probe: F) -> Self
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        let cancellation = Self::new();
        cancellation.connect_probe(probe);
        cancellation
    }

    /// Link a caller-owned cancellation source through a bounded synchronous probe.
    pub fn connect_probe<F>(&self, probe: F)
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        if let Ok(mut external) = self.external.lock() {
            external.push(Arc::new(probe));
        }
    }

    pub fn cancel(&self) {
        self.local.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.local.load(Ordering::Acquire)
            || self
                .external
                .lock()
                .map(|probes| probes.iter().any(|probe| probe()))
                .unwrap_or(true)
    }
}

impl std::fmt::Debug for Cancellation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStage {
    Created,
    Discovering,
    Reading,
    Recording,
    Reporting,
    Complete,
    Cancelled,
    Unproven,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    Ok,
    Partial,
    Failed,
    Cancelled,
    Unproven,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRequest {
    pub schema_version: u32,
    pub query: String,
    pub source_providers: Vec<String>,
    pub max_hits_per_provider: u32,
    pub max_source_bytes: u64,
}

impl WorkflowRequest {
    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.schema_version != 1 {
            return Err(ResearchError::invalid(
                "unsupported workflow request schema version",
            ));
        }
        if self.query.trim().is_empty() {
            return Err(ResearchError::invalid("query must be non-empty"));
        }
        if self.source_providers.is_empty() {
            return Err(ResearchError::invalid(
                "at least one source provider is required",
            ));
        }
        if self
            .source_providers
            .iter()
            .any(|provider| provider.trim().is_empty())
        {
            return Err(ResearchError::invalid(
                "source provider names must be non-empty",
            ));
        }
        if self.max_hits_per_provider == 0 || self.max_source_bytes == 0 {
            return Err(ResearchError::invalid(
                "hit and byte bounds must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFailure {
    pub provider: String,
    pub stage: WorkflowStage,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageRecord {
    pub stage: WorkflowStage,
    pub completed: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WorkflowOutcome {
    pub status: WorkflowStatus,
    pub stage: WorkflowStage,
    pub ledger: EvidenceLedger,
    pub report: ResearchReport,
    pub failures: Vec<SourceFailure>,
    pub budget: BudgetSnapshot,
    pub stages: Vec<StageRecord>,
    pub route: ResearchRoute,
    pub route_digest: String,
    pub allowed_effects: Vec<String>,
    pub effect_grant: Vec<String>,
    pub approval_receipt_ids: Vec<String>,
    pub selected_provider_denominator: u64,
}

pub struct ResearchWorkflow {
    clients: BTreeMap<String, InjectedSource>,
    budget: BudgetAccount,
    cancellation: Cancellation,
}

impl ResearchWorkflow {
    pub fn new(limits: BudgetLimits, deadline: Instant, cancellation: Cancellation) -> Self {
        Self {
            clients: BTreeMap::new(),
            budget: BudgetAccount::new(limits, deadline),
            cancellation,
        }
    }

    pub fn register(&mut self, client: InjectedSource) -> Result<(), ResearchError> {
        let provider = client.provider().trim().to_owned();
        if provider.is_empty() {
            return Err(ResearchError::invalid(
                "injected source provider must be non-empty",
            ));
        }
        if self.clients.insert(provider, client).is_some() {
            return Err(ResearchError::invalid("duplicate injected source provider"));
        }
        Ok(())
    }

    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
    pub fn budget(&self) -> BudgetSnapshot {
        self.budget.snapshot()
    }

    pub fn run(self, request: WorkflowRequest) -> Result<WorkflowOutcome, ResearchError> {
        let route = ResearchRoute::host_injected(&request.query);
        let authorization = ResearchAuthorization::full(&route)?;
        self.run_with_route(request, route, authorization)
    }

    pub fn run_with_route(
        mut self,
        request: WorkflowRequest,
        route: ResearchRoute,
        authorization: ResearchAuthorization,
    ) -> Result<WorkflowOutcome, ResearchError> {
        request.validate()?;
        route.validate()?;
        authorization.validate(&route)?;
        let mut frozen_request = request.clone();
        frozen_request.source_providers.sort();
        frozen_request.source_providers.dedup();
        let route_digest = route.digest()?;
        let providers = frozen_request
            .source_providers
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let selected_provider_denominator = providers.len() as u64;
        let mut allowed_effects = route.allowed_effects.clone();
        allowed_effects.sort();
        let mut effect_grant = authorization.effect_grant.clone();
        effect_grant.sort();
        let mut approval_receipt_ids = authorization.approval_receipt_ids.clone();
        approval_receipt_ids.sort();
        let approval_detail = if route.human_gates.is_empty() {
            "not-required".into()
        } else if approval_receipt_ids.is_empty() {
            "missing".into()
        } else {
            approval_receipt_ids.join(",")
        };
        let mut stage = WorkflowStage::Created;
        let mut stages = vec![StageRecord {
            stage,
            completed: true,
            detail: Some(format!(
                "route_frozen:{route_digest};allowed_effects:{};effect_grant:{};approval_receipts:{approval_detail};selected_provider_denominator:{selected_provider_denominator}",
                allowed_effects.join(","),
                effect_grant.join(",")
            )),
        }];
        let mut failures = Vec::new();
        let mut ledger = EvidenceLedger::new();

        let gates_satisfied = authorization.gates_satisfied(&route);
        let effects_granted = authorization.grants_effects(&route);
        let medical_effects_satisfied = authorization.medical_effects_satisfied(&route);
        if !gates_satisfied || !effects_granted || !medical_effects_satisfied {
            let reason = if !gates_satisfied {
                "route_gate_denied:approval_receipt_identity_missing"
            } else if !medical_effects_satisfied {
                "effect_denied:personal_medical_requires_read-sensitive_and_load-medical-history"
            } else {
                "effect_grant_missing_for_frozen_route"
            };
            failures.push(SourceFailure {
                provider: "route-authorization".into(),
                stage: WorkflowStage::Created,
                reason: reason.into(),
            });
            let report = ReportBuilder::from_ledger(
                &request.query,
                WorkflowStatus::Unproven,
                &ledger,
                &failures,
            )?;
            stages.push(StageRecord {
                stage: WorkflowStage::Unproven,
                completed: true,
                detail: Some("effects_denied;terminal_unproven".into()),
            });
            return Ok(WorkflowOutcome {
                status: WorkflowStatus::Unproven,
                stage: WorkflowStage::Unproven,
                ledger,
                report,
                failures,
                budget: self.budget.snapshot(),
                stages,
                route,
                route_digest,
                allowed_effects,
                effect_grant,
                approval_receipt_ids,
                selected_provider_denominator,
            });
        }

        stage = WorkflowStage::Discovering;
        stages.push(StageRecord {
            stage,
            completed: false,
            detail: Some("provider_selection_frozen;effects_bounded".into()),
        });
        for provider_name in providers.iter().cloned() {
            if self.cancellation.is_cancelled() {
                stage = WorkflowStage::Cancelled;
                break;
            }
            if !authorization.effect_granted(&route, "search") {
                failures.push(SourceFailure {
                    provider: provider_name,
                    stage,
                    reason: "effect_denied:search_not_route_allowed_or_granted".into(),
                });
                stage = WorkflowStage::Unproven;
                break;
            }
            let Some(client) = self.clients.get(&provider_name).cloned() else {
                failures.push(SourceFailure {
                    provider: provider_name,
                    stage,
                    reason: "provider_unavailable: no injected source client".into(),
                });
                continue;
            };
            if let Err(error) = self.budget.reserve_call(&self.cancellation) {
                failures.push(SourceFailure {
                    provider: provider_name,
                    stage,
                    reason: error.to_string(),
                });
                if self.cancellation.is_cancelled() {
                    stage = WorkflowStage::Cancelled;
                    break;
                }
                continue;
            }
            if let Err(error) = self
                .budget
                .reserve_cost(client.estimated_call_cost_micros(), &self.cancellation)
            {
                failures.push(SourceFailure {
                    provider: provider_name,
                    stage,
                    reason: error.to_string(),
                });
                continue;
            }
            let result = client.search(
                &request.query,
                request.max_hits_per_provider,
                self.budget.deadline(),
                &self.cancellation,
            );
            let mut hits = match result {
                Ok(hits) => hits,
                Err(error) => {
                    failures.push(SourceFailure {
                        provider: provider_name,
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            if let Err(error) = self.budget.ensure_available(&self.cancellation) {
                failures.push(SourceFailure {
                    provider: provider_name,
                    stage,
                    reason: error.to_string(),
                });
                stage = if self.cancellation.is_cancelled() {
                    WorkflowStage::Cancelled
                } else {
                    WorkflowStage::Unproven
                };
                break;
            }
            if hits.len() > request.max_hits_per_provider as usize {
                failures.push(SourceFailure {
                    provider: provider_name.clone(),
                    stage,
                    reason: format!(
                        "provider returned more than hit bound {}; excess leads omitted",
                        request.max_hits_per_provider
                    ),
                });
                hits.truncate(request.max_hits_per_provider as usize);
            }
            if hits.is_empty() {
                failures.push(SourceFailure {
                    provider: provider_name.clone(),
                    stage,
                    reason: "provider returned no opened source records".into(),
                });
            }
            stage = WorkflowStage::Reading;
            for hit in hits {
                if self.cancellation.is_cancelled() {
                    stage = WorkflowStage::Cancelled;
                    break;
                }
                if let Err(error) = hit.validate() {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                if hit.provider != provider_name.as_str() {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: "source hit provider does not match selected provider".into(),
                    });
                    continue;
                }
                if let Some(pattern) = forbidden_resource_match(&route, &hit.uri) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: format!("forbidden_resource:{pattern}"),
                    });
                    stage = WorkflowStage::Unproven;
                    break;
                }
                if !authorization.medical_effects_satisfied(&route) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: "effect_denied:personal_medical_requires_read-sensitive_and-load-medical-history".into(),
                    });
                    stage = WorkflowStage::Unproven;
                    break;
                }
                let open_effect = if route.provider == "local-corpus" {
                    "read-local"
                } else {
                    "fetch"
                };
                if !authorization.effect_granted(&route, open_effect) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: format!("effect_denied:{open_effect}_not_route_allowed_or_granted"),
                    });
                    stage = WorkflowStage::Unproven;
                    break;
                }
                if let Err(error) = self.budget.reserve_call(&self.cancellation) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    if self.cancellation.is_cancelled() {
                        stage = WorkflowStage::Cancelled;
                        break;
                    }
                    continue;
                }
                if let Err(error) = self
                    .budget
                    .reserve_cost(client.estimated_call_cost_micros(), &self.cancellation)
                {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                if let Err(error) = self.budget.reserve_source(&self.cancellation) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                let reserved_bytes = client.estimated_bytes(&hit).max(1);
                if reserved_bytes > request.max_source_bytes {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: "source estimate exceeds per-source byte bound".into(),
                    });
                    continue;
                }
                if let Err(error) = self
                    .budget
                    .reserve_bytes(reserved_bytes, &self.cancellation)
                {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                let mut source = match client.open(&hit, self.budget.deadline(), &self.cancellation)
                {
                    Ok(source) => source,
                    Err(error) => {
                        failures.push(SourceFailure {
                            provider: provider_name.clone(),
                            stage,
                            reason: error.to_string(),
                        });
                        continue;
                    }
                };
                if let Err(error) = self.budget.ensure_available(&self.cancellation) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    stage = if self.cancellation.is_cancelled() {
                        WorkflowStage::Cancelled
                    } else {
                        WorkflowStage::Unproven
                    };
                    break;
                }
                if source.byte_length > request.max_source_bytes {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: format!(
                            "source exceeds per-source byte bound: {}",
                            source.byte_length
                        ),
                    });
                    continue;
                }
                if source.byte_length > reserved_bytes {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: "source exceeded declared byte estimate".into(),
                    });
                    continue;
                }
                if !source.metadata.contains_key("locator") {
                    source.metadata.insert("locator".into(), hit.uri.clone());
                }
                if let Err(error) = source.validate() {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                if let Err(error) = self.budget.ensure_available(&self.cancellation) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    stage = if self.cancellation.is_cancelled() {
                        WorkflowStage::Cancelled
                    } else {
                        WorkflowStage::Unproven
                    };
                    break;
                }
                if !authorization.effect_granted(&route, "extract") {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: "effect_denied:extract_not_route_allowed_or_granted".into(),
                    });
                    stage = WorkflowStage::Unproven;
                    break;
                }
                let evidence_id = format!("{}:source:{}", provider_name, ledger.records().count());
                let evidence = EvidenceRecord::from_source(
                    &source,
                    evidence_id,
                    source.evidence_locator(),
                    EvidenceKind::SourceAssertion,
                )?;
                ledger.add(evidence)?;
            }
            if stage == WorkflowStage::Cancelled || stage == WorkflowStage::Unproven {
                break;
            }
            stage = WorkflowStage::Discovering;
        }

        if self.cancellation.is_cancelled() {
            stage = WorkflowStage::Cancelled;
        } else if let Err(error) = self.budget.ensure_available(&self.cancellation) {
            failures.push(SourceFailure {
                provider: "workflow".into(),
                stage,
                reason: error.to_string(),
            });
            stage = WorkflowStage::Unproven;
        }
        stages.iter_mut().for_each(|record| record.completed = true);
        if ledger.records().next().is_some() {
            stages.push(StageRecord {
                stage: WorkflowStage::Reading,
                completed: true,
                detail: Some("opened_source_records_validated".into()),
            });
        }
        if stage != WorkflowStage::Cancelled
            && stage != WorkflowStage::Unproven
            && !authorization.effect_granted(&route, "synthesize")
        {
            failures.push(SourceFailure {
                provider: "route-authorization".into(),
                stage,
                reason: "effect_denied:synthesize_not_route_allowed_or_granted".into(),
            });
            stage = WorkflowStage::Unproven;
        }
        if stage != WorkflowStage::Cancelled && stage != WorkflowStage::Unproven {
            stage = WorkflowStage::Recording;
            stages.push(StageRecord {
                stage,
                completed: true,
                detail: Some("atomic_claim_proof_binding".into()),
            });
            let ids: Vec<_> = ledger
                .records()
                .map(|record| record.evidence_id.clone())
                .collect();
            for (index, evidence_id) in ids.iter().enumerate() {
                if self.cancellation.is_cancelled() {
                    stage = WorkflowStage::Cancelled;
                    break;
                }
                let Some(record) = ledger.record(evidence_id) else {
                    continue;
                };
                let mut provenance = record.provenance.clone();
                let uncertainty = provenance.get("uncertainty").cloned();
                let claim = Claim {
                    schema_version: 1,
                    claim_id: format!("claim-{index}"),
                    text: record.text.clone(),
                    kind: EvidenceKind::SourceAssertion,
                    evidence_ids: vec![evidence_id.clone()],
                    uncertainty,
                    provenance: {
                        provenance.insert("claim_scope".into(), request.query.clone());
                        if let Some(locator) = &record.locator {
                            provenance.insert("locator".into(), locator.clone());
                        }
                        provenance.insert("evidence_id".into(), evidence_id.clone());
                        provenance
                    },
                };
                ledger.add_claim(claim)?;
            }
            if stage != WorkflowStage::Cancelled {
                for (group, evidence_ids) in ledger.contradiction_groups() {
                    if self.cancellation.is_cancelled() {
                        stage = WorkflowStage::Cancelled;
                        break;
                    }
                    let claim = Claim {
                        schema_version: 1,
                        claim_id: format!("uncertainty-{group}"),
                        text: format!(
                            "Opened sources contain unresolved contradiction group {group}"
                        ),
                        kind: EvidenceKind::Uncertainty,
                        evidence_ids,
                        uncertainty: Some(
                            "contradictory opened-source evidence requires adjudication".into(),
                        ),
                        provenance: BTreeMap::from([
                            ("contradiction_group".into(), group),
                            ("claim_scope".into(), request.query.clone()),
                            ("confidence_ceiling".into(), "low".into()),
                        ]),
                    };
                    ledger.add_claim(claim)?;
                }
            }
            if stage != WorkflowStage::Cancelled {
                stage = WorkflowStage::Reporting;
            }
        }
        let status = if stage == WorkflowStage::Cancelled {
            WorkflowStatus::Cancelled
        } else if stage == WorkflowStage::Unproven {
            WorkflowStatus::Unproven
        } else if ledger.records().next().is_some() && !failures.is_empty() {
            WorkflowStatus::Partial
        } else if ledger.records().next().is_some() {
            WorkflowStatus::Ok
        } else {
            WorkflowStatus::Unproven
        };
        let report = ReportBuilder::from_ledger(&request.query, status, &ledger, &failures)?;
        stages.push(StageRecord {
            stage: WorkflowStage::Reporting,
            completed: true,
            detail: Some("deterministic_report_digest_bound".into()),
        });
        stage = match status {
            WorkflowStatus::Cancelled => WorkflowStage::Cancelled,
            WorkflowStatus::Unproven => WorkflowStage::Unproven,
            WorkflowStatus::Ok | WorkflowStatus::Partial => WorkflowStage::Complete,
            WorkflowStatus::Failed => WorkflowStage::Unproven,
        };
        stages.push(StageRecord {
            stage,
            completed: true,
            detail: Some(match status {
                WorkflowStatus::Ok => "research_complete".into(),
                WorkflowStatus::Partial => "research_partial_with_omissions".into(),
                WorkflowStatus::Cancelled => "caller_cancellation_observed".into(),
                WorkflowStatus::Unproven => "required_evidence_unavailable".into(),
                WorkflowStatus::Failed => "research_failed_without_proof".into(),
            }),
        });
        Ok(WorkflowOutcome {
            status,
            stage,
            ledger,
            report,
            failures,
            budget: self.budget.snapshot(),
            stages,
            route,
            route_digest,
            allowed_effects,
            effect_grant,
            approval_receipt_ids,
            selected_provider_denominator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::ResearchReceipt;
    use std::time::Duration;

    #[test]
    fn linked_caller_cancellation_produces_terminal_receipt() {
        let caller = Arc::new(AtomicBool::new(true));
        let caller_probe = Arc::clone(&caller);
        let workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            std::time::Instant::now() + Duration::from_secs(1),
            Cancellation::from_probe(move || caller_probe.load(Ordering::Acquire)),
        );
        let outcome = workflow
            .run(WorkflowRequest {
                schema_version: 1,
                query: "cancelled query".into(),
                source_providers: vec!["host".into()],
                max_hits_per_provider: 1,
                max_source_bytes: 1024,
            })
            .expect("cancellation is a receipted workflow outcome");
        assert_eq!(outcome.status, WorkflowStatus::Cancelled);
        assert_eq!(outcome.stage, WorkflowStage::Cancelled);
        assert_eq!(outcome.budget.usage.calls, 0);
        assert_eq!(outcome.ledger.claims().count(), 0);
        let receipt = ResearchReceipt::from_outcome(&outcome).expect("terminal receipt validates");
        assert_eq!(receipt.status, WorkflowStatus::Cancelled);
        assert_eq!(receipt.selected_provider_denominator, 1);
        assert!(receipt.stages[0]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("selected_provider_denominator:1")));
    }

    #[test]
    fn pending_route_gate_denies_effects_without_receipt() {
        let mut route = ResearchRoute::host_injected("gated query");
        route.human_gates = vec!["confirm-jurisdiction".into()];
        let authorization = ResearchAuthorization {
            approval_receipt_ids: Vec::new(),
            effect_grant: route.allowed_effects.clone(),
        };
        let workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            Instant::now() + Duration::from_secs(1),
            Cancellation::new(),
        );
        let outcome = workflow
            .run_with_route(
                WorkflowRequest {
                    schema_version: 1,
                    query: "gated query".into(),
                    source_providers: vec!["unavailable".into()],
                    max_hits_per_provider: 1,
                    max_source_bytes: 1024,
                },
                route,
                authorization,
            )
            .expect("missing gate receipt is a typed terminal outcome");
        assert_eq!(outcome.status, WorkflowStatus::Unproven);
        assert_eq!(outcome.budget.usage.calls, 0);
        assert!(outcome
            .failures
            .iter()
            .any(|failure| failure.reason.contains("approval_receipt_identity_missing")));
        let receipt = ResearchReceipt::from_outcome(&outcome).expect("receipt binds denied route");
        assert_eq!(receipt.selected_provider_denominator, 1);
        assert_eq!(receipt.approval_receipt_ids, Vec::<String>::new());
    }

    #[test]
    fn unavailable_provider_consumes_no_call_budget() {
        let workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            Instant::now() + Duration::from_secs(1),
            Cancellation::new(),
        );
        let outcome = workflow
            .run(WorkflowRequest {
                schema_version: 1,
                query: "unavailable provider".into(),
                source_providers: vec!["missing".into()],
                max_hits_per_provider: 1,
                max_source_bytes: 1024,
            })
            .expect("unavailable provider is a typed omission");
        assert_eq!(outcome.budget.usage.calls, 0);
        assert_eq!(outcome.status, WorkflowStatus::Unproven);
        let receipt = ResearchReceipt::from_outcome(&outcome).expect("receipt validates");
        assert_eq!(receipt.external_requests, 0);
    }

    #[test]
    fn legal_stage_one_null_context_is_accepted_but_effects_are_denied() {
        let mut route = ResearchRoute::host_injected("legal query");
        route.domain = "legal".into();
        route.provider = "domain-default".into();
        route.methods = vec!["authority".into()];
        route.subject = ResearchSubject {
            country: Some(NullableString::Null),
            area: Some(NullableString::Null),
            issue: Some("legal issue".into()),
            ..ResearchSubject::default()
        };
        route
            .validate()
            .expect("route schema permits null country and area");
        let authorization = ResearchAuthorization::full(&route).unwrap();
        let workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            Instant::now() + Duration::from_secs(1),
            Cancellation::new(),
        );
        let outcome = workflow
            .run_with_route(
                WorkflowRequest {
                    schema_version: 1,
                    query: "legal query".into(),
                    source_providers: vec!["authority".into()],
                    max_hits_per_provider: 1,
                    max_source_bytes: 1024,
                },
                route,
                authorization,
            )
            .unwrap();
        assert_eq!(outcome.status, WorkflowStatus::Unproven);
        assert_eq!(outcome.budget.usage.calls, 0);
        assert!(outcome
            .failures
            .iter()
            .any(|failure| failure.reason.contains("approval_receipt_identity_missing")));
    }

    #[test]
    fn missing_search_effect_stops_before_provider_call() {
        let mut route = ResearchRoute::host_injected("effect query");
        route
            .allowed_effects
            .retain(|effect| effect.as_str() != "search");
        let authorization = ResearchAuthorization::full(&route).unwrap();
        let workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            Instant::now() + Duration::from_secs(1),
            Cancellation::new(),
        );
        let outcome = workflow
            .run_with_route(
                WorkflowRequest {
                    schema_version: 1,
                    query: "effect query".into(),
                    source_providers: vec!["missing".into()],
                    max_hits_per_provider: 1,
                    max_source_bytes: 1024,
                },
                route,
                authorization,
            )
            .unwrap();
        assert_eq!(outcome.status, WorkflowStatus::Unproven);
        assert_eq!(outcome.budget.usage.calls, 0);
        assert!(outcome
            .failures
            .iter()
            .any(|failure| failure.reason.contains("effect_denied:search")));
    }

    #[test]
    fn personal_medical_route_requires_confirmation_and_sensitive_history_effects() {
        let mut route = ResearchRoute::host_injected("medical query");
        route.domain = "medical".into();
        route.provider = "domain-default".into();
        route.methods = vec!["authority".into()];
        route.subject = ResearchSubject {
            issue: Some("medical issue".into()),
            patient: Some(ResearchPatient {
                kind: "self".into(),
                history_available: Some(true),
                history_source: Some(NullableString::Value("clinic-record".into())),
                ..ResearchPatient::default()
            }),
            ..ResearchSubject::default()
        };
        route.human_gates = vec!["confirm-personal-medical-route".into()];
        route
            .allowed_effects
            .extend(["read-sensitive".into(), "load-medical-history".into()]);
        route.validate().expect("personal medical route is valid");

        let mut authorization = ResearchAuthorization::full(&route).unwrap();
        let workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            Instant::now() + Duration::from_secs(1),
            Cancellation::new(),
        );
        let missing_confirmation = workflow
            .run_with_route(
                WorkflowRequest {
                    schema_version: 1,
                    query: "medical query".into(),
                    source_providers: vec!["missing".into()],
                    max_hits_per_provider: 1,
                    max_source_bytes: 1024,
                },
                route.clone(),
                authorization.clone(),
            )
            .unwrap();
        assert_eq!(missing_confirmation.status, WorkflowStatus::Unproven);
        assert_eq!(missing_confirmation.budget.usage.calls, 0);
        assert!(missing_confirmation
            .failures
            .iter()
            .any(|failure| failure.reason.contains("route_gate_denied")));

        authorization.approval_receipt_ids = vec!["approval-medical-1".into()];
        authorization
            .effect_grant
            .retain(|effect| effect.as_str() != "load-medical-history");
        let workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            Instant::now() + Duration::from_secs(1),
            Cancellation::new(),
        );
        let missing_history_effect = workflow
            .run_with_route(
                WorkflowRequest {
                    schema_version: 1,
                    query: "medical query".into(),
                    source_providers: vec!["missing".into()],
                    max_hits_per_provider: 1,
                    max_source_bytes: 1024,
                },
                route,
                authorization,
            )
            .unwrap();
        assert_eq!(missing_history_effect.status, WorkflowStatus::Unproven);
        assert_eq!(missing_history_effect.budget.usage.calls, 0);
        assert!(missing_history_effect.failures.iter().any(|failure| failure
            .reason
            .contains("requires_read-sensitive_and_load-medical-history")));
    }

    #[test]
    fn subject_extensions_are_preserved_in_wire_digest() {
        let mut route = ResearchRoute::host_injected("extension query");
        let mut nested = BTreeMap::new();
        nested.insert("enabled".into(), ResearchValue::Bool(true));
        nested.insert(
            "items".into(),
            ResearchValue::Array(vec![
                ResearchValue::Null,
                ResearchValue::Number(ResearchNumber::Unsigned(7)),
                ResearchValue::String("nested".into()),
            ]),
        );
        route
            .subject
            .extensions
            .insert("subject_extension".into(), ResearchValue::Object(nested));
        route.subject.patient = Some(ResearchPatient {
            kind: "anonymous".into(),
            extensions: BTreeMap::from([(
                "patient_extension".into(),
                ResearchValue::Object(BTreeMap::from([
                    ("enabled".into(), ResearchValue::Bool(false)),
                    (
                        "threshold".into(),
                        ResearchValue::Number(ResearchNumber::Float(1.25f64.to_bits())),
                    ),
                ])),
            )]),
            ..ResearchPatient::default()
        });
        let bytes = legion_contracts::canonical_json_bytes(&route).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert!(wire.contains("subject_extension"));
        assert!(wire.contains("patient_extension"));
        let digest = route.digest().unwrap();
        let mut changed = route.clone();
        if let Some(ResearchValue::Object(values)) =
            changed.subject.extensions.get_mut("subject_extension")
        {
            values.insert("enabled".into(), ResearchValue::Bool(false));
        }
        assert_ne!(digest, changed.digest().unwrap());
    }

    #[test]
    fn forbidden_resource_prefix_rejects_before_open() {
        use crate::source::{SourceClient, SourceHit, SourceRecord};

        struct ForbiddenResourceClient;

        impl SourceClient for ForbiddenResourceClient {
            fn provider(&self) -> &str {
                "forbidden-provider"
            }

            fn search(
                &self,
                _: &str,
                _: u32,
                _: Instant,
                _: &Cancellation,
            ) -> Result<Vec<SourceHit>, ResearchError> {
                Ok(vec![SourceHit {
                    source_id: "forbidden-source".into(),
                    uri: "https://blocked.test/private/".into(),
                    title: Some("blocked".into()),
                    provider: "forbidden-provider".into(),
                    relevance: None,
                }])
            }

            fn open(
                &self,
                _: &SourceHit,
                _: Instant,
                _: &Cancellation,
            ) -> Result<SourceRecord, ResearchError> {
                panic!("forbidden resource must be rejected before open")
            }
        }

        let mut route = ResearchRoute::host_injected("forbidden query");
        route.forbidden_resources = vec!["https://blocked.test/**".into()];
        route.validate().expect("forbidden resource route is valid");
        assert_eq!(
            forbidden_resource_match(&route, "https://blocked.test/private/"),
            Some("https://blocked.test/**".into())
        );
        route.forbidden_resources = vec!["https://blocked.test/private".into()];
        assert_eq!(
            forbidden_resource_match(&route, "https://blocked.test/private/"),
            Some("https://blocked.test/private".into())
        );
        route.forbidden_resources = vec!["https://blocked.test/**".into()];
        let authorization = ResearchAuthorization::full(&route).unwrap();
        let mut workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            Instant::now() + Duration::from_secs(1),
            Cancellation::new(),
        );
        workflow
            .register(Arc::new(ForbiddenResourceClient))
            .unwrap();
        let outcome = workflow
            .run_with_route(
                WorkflowRequest {
                    schema_version: 1,
                    query: "forbidden query".into(),
                    source_providers: vec!["forbidden-provider".into()],
                    max_hits_per_provider: 1,
                    max_source_bytes: 1024,
                },
                route,
                authorization,
            )
            .unwrap();
        assert_eq!(outcome.status, WorkflowStatus::Unproven);
        assert_eq!(outcome.budget.usage.calls, 1);
        assert_eq!(outcome.ledger.records().count(), 0);
        assert!(outcome
            .failures
            .iter()
            .any(|failure| failure.reason.contains("forbidden_resource:")));
    }

    #[test]
    fn caller_cancellation_after_search_skips_open_and_claims() {
        use crate::source::{SourceClient, SourceHit, SourceRecord};

        struct CancelAfterSearch {
            cancellation: Cancellation,
        }

        impl SourceClient for CancelAfterSearch {
            fn provider(&self) -> &str {
                "cancel-after-search"
            }

            fn search(
                &self,
                _: &str,
                _: u32,
                _: Instant,
                _: &Cancellation,
            ) -> Result<Vec<SourceHit>, ResearchError> {
                self.cancellation.cancel();
                Ok(vec![SourceHit {
                    source_id: "source-1".into(),
                    uri: "https://example.test/source".into(),
                    title: Some("source".into()),
                    provider: "cancel-after-search".into(),
                    relevance: None,
                }])
            }

            fn open(
                &self,
                _: &SourceHit,
                _: Instant,
                _: &Cancellation,
            ) -> Result<SourceRecord, ResearchError> {
                panic!("cancellation must prevent open effect")
            }
        }

        let caller = Cancellation::new();
        let mut workflow = ResearchWorkflow::new(
            BudgetLimits::default(),
            Instant::now() + Duration::from_secs(1),
            caller.clone(),
        );
        workflow
            .register(Arc::new(CancelAfterSearch {
                cancellation: caller,
            }))
            .unwrap();
        let outcome = workflow
            .run(WorkflowRequest {
                schema_version: 1,
                query: "cancel after search".into(),
                source_providers: vec!["cancel-after-search".into()],
                max_hits_per_provider: 1,
                max_source_bytes: 1024,
            })
            .unwrap();
        assert_eq!(outcome.status, WorkflowStatus::Cancelled);
        assert_eq!(outcome.stage, WorkflowStage::Cancelled);
        assert_eq!(outcome.budget.usage.calls, 1);
        assert_eq!(outcome.ledger.records().count(), 0);
        assert_eq!(outcome.ledger.claims().count(), 0);
    }
}
