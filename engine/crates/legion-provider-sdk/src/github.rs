//! Bounded, one-shot, read-only GitHub observations. Nothing here grants merge authority.
//!
//! REST collections use locally constructed page URLs, never server-provided links. Raw
//! observations deliberately retain duplicate checks: consumers must not hide a failure
//! behind another run with the same name. Commit statuses remain newest-first, as returned
//! by GitHub; only the first status for each context is current.

use std::{
    collections::BTreeSet,
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::auth::{
    authorize_credential_access, AuthError, BearerAuth, CredentialAccessGrant,
    CredentialAuthorizer, CredentialReceipt, SecretProvider,
};

const API: &str = "https://api.github.com";
const PAGE_SIZE: usize = 100;

#[derive(Clone, Copy, Debug)]
pub struct GitHubObserverLimits {
    pub max_pages: usize,
    pub max_checks: usize,
    pub max_response_bytes: usize,
    pub request_timeout: Duration,
    pub total_timeout: Duration,
}

impl Default for GitHubObserverLimits {
    fn default() -> Self {
        Self {
            max_pages: 5,
            max_checks: 512,
            max_response_bytes: 2 * 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(300),
        }
    }
}

impl GitHubObserverLimits {
    fn validate(self) -> Result<Self, GitHubObserverError> {
        if self.max_pages == 0
            || self.max_pages > 20
            || self.max_checks == 0
            || self.max_checks > 512
            || self.max_response_bytes == 0
            || self.max_response_bytes > 2 * 1024 * 1024
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(30)
            || self.total_timeout.is_zero()
            || self.total_timeout > Duration::from_secs(300)
        {
            return Err(GitHubObserverError::new("invalid observer limits"));
        }
        Ok(self)
    }
}

/// Fixed-origin request data. No credentials are exposed to injected fixture transports.
#[derive(Clone, Debug)]
pub struct GitHubRequest {
    pub path: String,
    pub graphql_body: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct GitHubResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub request_id: Option<String>,
}

/// Injection seam for deterministic fixtures; implementations must perform no mutations.
/// The observer independently enforces time, response size, and HTTP success boundaries.
#[async_trait]
pub trait GitHubTransport: Send + Sync {
    async fn send(
        &self,
        request: GitHubRequest,
        max_bytes: usize,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<GitHubResponse, GitHubObserverError>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitHubRequestReceipt {
    pub path: String,
    pub status: u16,
    pub body_sha256: String,
    pub request_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitHubObservationCompleteness {
    pub metadata: bool,
    pub checks: bool,
    pub reviews: bool,
    pub threads: bool,
    pub policy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubObservation {
    pub repository: String,
    pub pull_request: u64,
    /// Conservative timestamp for the oldest contributing observation: collection start.
    /// Finishing a slow collection never makes earlier check/review facts fresh again.
    pub observed_at_unix_seconds: u64,
    /// GraphQL PullRequest objects, including head/base OIDs and baseRefName.
    /// `_legion_repository` binds each object to the returned nameWithOwner.
    pub metadata_before: Value,
    pub metadata_after: Value,
    /// REST branch protection objects. Absence means unavailable, never unprotected.
    pub classic_policy_before: Option<Value>,
    pub classic_policy_after: Option<Value>,
    pub rules_before: Vec<Value>,
    pub rules_after: Vec<Value>,
    pub check_runs: Vec<Value>,
    /// Ordered newest-first; each item has `_legion_head` binding the requested commit.
    pub statuses: Vec<Value>,
    /// Latest opinionated review per user, collected independently of reviewDecision.
    /// A later comment must not hide an outstanding request for changes.
    pub reviews: Vec<Value>,
    pub review_threads: Vec<Value>,
    pub completeness: GitHubObservationCompleteness,
    pub gaps: Vec<String>,
    pub receipts: Vec<GitHubRequestReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitHubObserverError {
    pub message: String,
}
impl GitHubObserverError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
impl fmt::Display for GitHubObserverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for GitHubObserverError {}
impl From<AuthError> for GitHubObserverError {
    fn from(_: AuthError) -> Self {
        Self::new("GitHub credential access unavailable or denied")
    }
}

struct HttpTransport {
    client: reqwest::Client,
    auth: BearerAuth,
    _grant: CredentialAccessGrant,
}

#[async_trait]
impl GitHubTransport for HttpTransport {
    async fn send(
        &self,
        request: GitHubRequest,
        max_bytes: usize,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<GitHubResponse, GitHubObserverError> {
        validate_path(&request.path)?;
        let url = format!("{API}{}", request.path);
        let mut builder = if let Some(body) = request.graphql_body {
            self.client.post(url).json(&body)
        } else {
            self.client.get(url)
        };
        builder = builder
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2026-03-10")
            .header("User-Agent", "legion-native-read-only-observer");
        let deadline = Instant::now() + timeout;
        let response = tokio::select! {
            _ = cancellation.cancelled() => return Err(GitHubObserverError::new("observation cancelled")),
            result = tokio::time::timeout(timeout, self.auth.apply(builder).send()) =>
                result.map_err(|_| GitHubObserverError::new("GitHub request deadline exceeded"))?
                    .map_err(|_| GitHubObserverError::new("GitHub HTTP transport failed"))?,
        };
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-github-request-id")
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.len() <= 256)
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|len| len > max_bytes as u64)
        {
            return Err(GitHubObserverError::new(
                "GitHub response byte limit exceeded",
            ));
        }
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let chunk = tokio::select! {
                _ = cancellation.cancelled() => return Err(GitHubObserverError::new("observation cancelled")),
                result = tokio::time::timeout(remaining, stream.next()) =>
                    result.map_err(|_| GitHubObserverError::new("GitHub response deadline exceeded"))?,
            };
            let Some(chunk) = chunk else { break };
            let chunk =
                chunk.map_err(|_| GitHubObserverError::new("GitHub response body failed"))?;
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(GitHubObserverError::new(
                    "GitHub response byte limit exceeded",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(GitHubResponse {
            status,
            body,
            request_id,
        })
    }
}

pub struct GitHubObserver {
    transport: Arc<dyn GitHubTransport>,
    limits: GitHubObserverLimits,
}

impl GitHubObserver {
    pub fn authorized(
        secrets: &dyn SecretProvider,
        authorizer: &dyn CredentialAuthorizer,
        limits: GitHubObserverLimits,
    ) -> Result<(Self, CredentialReceipt), GitHubObserverError> {
        let limits = limits.validate()?;
        let grant = authorize_credential_access("github", authorizer)?;
        let auth = BearerAuth::from_provider(secrets, &grant)?;
        let receipt = CredentialReceipt {
            provider_id: "github".into(),
            auth: auth.redacted(),
            effect: "CREDENTIAL_ACCESS",
        };
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map_err(|_| GitHubObserverError::new("GitHub HTTP client initialization failed"))?;
        Ok((
            Self {
                transport: Arc::new(HttpTransport {
                    client,
                    auth,
                    _grant: grant,
                }),
                limits,
            },
            receipt,
        ))
    }

    /// Supplies a fixture/custom read-only transport; it never reads process credentials.
    pub fn with_transport(
        transport: Arc<dyn GitHubTransport>,
        limits: GitHubObserverLimits,
    ) -> Result<Self, GitHubObserverError> {
        Ok(Self {
            transport,
            limits: limits.validate()?,
        })
    }

    pub async fn observe(
        &self,
        repository: &str,
        pull_request: u64,
        cancellation: CancellationToken,
    ) -> Result<GitHubObservation, GitHubObserverError> {
        let (owner, name) = validate_repository(repository)?;
        if pull_request == 0 || pull_request > i32::MAX as u64 {
            return Err(GitHubObserverError::new(
                "pull request number must be 1..=2147483647",
            ));
        }
        let observed_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut collection = Collection {
            observer: self,
            cancellation,
            deadline: Instant::now() + self.limits.total_timeout,
            receipts: Vec::new(),
            gaps: Vec::new(),
        };
        // Initial identity is mandatory; without it there is no commit to observe.
        let before = collection.metadata(owner, name, pull_request).await?;
        let head = text(&before, "headRefOid")?.to_owned();
        let base = text(&before, "baseRefName")?.to_owned();
        let prefix = format!("/repos/{owner}/{name}");
        let (classic_before, classic_before_ok) =
            collection.classic_policy(&prefix, &base, &before).await;
        let (rules_before, rules_before_ok) = collection
            .pages(
                &format!("{prefix}/rules/branches/{}", segment(&base)),
                None,
                512,
            )
            .await;
        let (check_runs, runs_ok) = collection
            .pages(
                &format!("{prefix}/commits/{head}/check-runs?filter=latest"),
                Some("check_runs"),
                self.limits.max_checks,
            )
            .await;
        let remaining = self.limits.max_checks.saturating_sub(check_runs.len());
        let (mut statuses, statuses_ok) = collection
            .pages(
                &format!("{prefix}/commits/{head}/statuses"),
                None,
                remaining,
            )
            .await;
        for status in &mut statuses {
            if let Some(object) = status.as_object_mut() {
                object.insert("_legion_head".into(), Value::String(head.clone()));
            }
        }
        let revisions_ok = check_runs
            .iter()
            .all(|run| run.get("head_sha").and_then(Value::as_str) == Some(head.as_str()));
        if !revisions_ok {
            collection
                .gaps
                .push("check runs contain a missing or unexpected head revision".into());
        }
        let statuses_shape_ok = statuses.iter().all(|status| {
            status
                .get("context")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        });
        if !statuses_shape_ok {
            collection.gaps.push("commit status context missing".into());
        }
        let (threads, threads_ok) = collection.threads(owner, name, pull_request, &before).await;
        let (reviews, reviews_ok) = collection.reviews(owner, name, pull_request, &before).await;
        // Policy is read again, so concurrent policy changes cannot silently certify readiness.
        let (classic_after, classic_after_ok) =
            collection.classic_policy(&prefix, &base, &before).await;
        let (rules_after, rules_after_ok) = collection
            .pages(
                &format!("{prefix}/rules/branches/{}", segment(&base)),
                None,
                512,
            )
            .await;
        let after = match collection.metadata(owner, name, pull_request).await {
            Ok(value) => value,
            Err(error) => {
                collection.gaps.push(format!("final metadata: {error}"));
                Value::Null
            }
        };
        let metadata_ok = !after.is_null() && same_revision(&before, &after);
        if !metadata_ok {
            collection.gaps.push(
                "head, base revision, or base branch changed or final metadata unavailable".into(),
            );
        }
        let policy_equal = classic_before == classic_after
            && canonical_rules(&rules_before) == canonical_rules(&rules_after)
            && before.pointer("/baseRef/branchProtectionRule")
                == after.pointer("/baseRef/branchProtectionRule");
        if !policy_equal {
            collection
                .gaps
                .push("branch policy changed during collection".into());
        }
        Ok(GitHubObservation {
            repository: text(&before, "_legion_repository")?.to_owned(),
            pull_request,
            observed_at_unix_seconds,
            metadata_before: before,
            metadata_after: after,
            classic_policy_before: classic_before,
            classic_policy_after: classic_after,
            rules_before,
            rules_after,
            check_runs,
            statuses,
            reviews,
            review_threads: threads,
            completeness: GitHubObservationCompleteness {
                metadata: metadata_ok,
                checks: runs_ok && statuses_ok && revisions_ok && statuses_shape_ok,
                reviews: reviews_ok && metadata_ok,
                threads: threads_ok && metadata_ok,
                policy: classic_before_ok
                    && classic_after_ok
                    && rules_before_ok
                    && rules_after_ok
                    && policy_equal
                    && metadata_ok,
            },
            gaps: collection.gaps,
            receipts: collection.receipts,
        })
    }
}

struct Collection<'a> {
    observer: &'a GitHubObserver,
    cancellation: CancellationToken,
    deadline: Instant,
    receipts: Vec<GitHubRequestReceipt>,
    gaps: Vec<String>,
}

impl Collection<'_> {
    async fn request(&mut self, request: GitHubRequest) -> Result<Value, GitHubObserverError> {
        validate_path(&request.path)?;
        if self.cancellation.is_cancelled() {
            return Err(GitHubObserverError::new("observation cancelled"));
        }
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(GitHubObserverError::new("observation deadline exceeded"));
        }
        let timeout = remaining.min(self.observer.limits.request_timeout);
        let path = request.path.clone();
        let response = tokio::select! {
            _ = self.cancellation.cancelled() => return Err(GitHubObserverError::new("observation cancelled")),
            result = tokio::time::timeout(timeout, self.observer.transport.send(request,
                self.observer.limits.max_response_bytes, timeout, self.cancellation.clone())) =>
                result.map_err(|_| GitHubObserverError::new("GitHub request deadline exceeded"))??,
        };
        if response.body.len() > self.observer.limits.max_response_bytes {
            return Err(GitHubObserverError::new(
                "GitHub response byte limit exceeded",
            ));
        }
        self.receipts.push(GitHubRequestReceipt {
            path,
            status: response.status,
            body_sha256: hex::encode(Sha256::digest(&response.body)),
            request_id: response.request_id.filter(|id| id.len() <= 256),
        });
        if !(200..300).contains(&response.status) {
            return Err(GitHubObserverError::new(format!(
                "GitHub returned HTTP {}",
                response.status
            )));
        }
        serde_json::from_slice(&response.body)
            .map_err(|_| GitHubObserverError::new("GitHub response is not valid JSON"))
    }

    async fn graphql(
        &mut self,
        query: &str,
        variables: Value,
    ) -> Result<Value, GitHubObserverError> {
        let value = self
            .request(GitHubRequest {
                path: "/graphql".into(),
                graphql_body: Some(json!({ "query": query, "variables": variables })),
            })
            .await?;
        // Partial GraphQL responses are incomplete even if some requested data survived.
        if value
            .get("errors")
            .is_some_and(|e| !e.as_array().is_some_and(Vec::is_empty))
        {
            return Err(GitHubObserverError::new(
                "GitHub GraphQL returned errors or partial data",
            ));
        }
        value
            .get("data")
            .filter(|v| v.is_object())
            .cloned()
            .ok_or_else(|| GitHubObserverError::new("GitHub GraphQL data missing"))
    }

    async fn metadata(
        &mut self,
        owner: &str,
        name: &str,
        number: u64,
    ) -> Result<Value, GitHubObserverError> {
        let data = self
            .graphql(
                METADATA_QUERY,
                json!({"owner":owner,"name":name,"number":number}),
            )
            .await?;
        validate_identity(&data, owner, name, number)?;
        let mut pr = data
            .pointer("/repository/pullRequest")
            .cloned()
            .ok_or_else(|| GitHubObserverError::new("pull request missing"))?;
        for key in ["headRefOid", "baseRefOid"] {
            if !valid_oid(text(&pr, key)?) {
                return Err(GitHubObserverError::new("invalid pull request revision"));
            }
        }
        for key in ["baseRefName", "state", "mergeable", "mergeStateStatus"] {
            text(&pr, key)?;
        }
        for key in ["isDraft", "isInMergeQueue"] {
            if !pr.get(key).is_some_and(Value::is_boolean) {
                return Err(GitHubObserverError::new("pull request boolean missing"));
            }
        }
        if !pr
            .get("reviewDecision")
            .is_some_and(|v| v.is_null() || v.is_string())
            || !pr
                .get("autoMergeRequest")
                .is_some_and(|v| v.is_null() || v.is_object())
            || !pr
                .get("mergeCommit")
                .is_some_and(|v| v.is_null() || v.is_object())
        {
            return Err(GitHubObserverError::new(
                "pull request review or merge metadata missing",
            ));
        }
        let observed_repository = data
            .pointer("/repository/nameWithOwner")
            .cloned()
            .ok_or_else(|| GitHubObserverError::new("repository identity missing"))?;
        pr.as_object_mut()
            .ok_or_else(|| GitHubObserverError::new("pull request object missing"))?
            .insert("_legion_repository".into(), observed_repository);
        Ok(pr)
    }

    async fn classic_policy(
        &mut self,
        prefix: &str,
        base: &str,
        metadata: &Value,
    ) -> (Option<Value>, bool) {
        // An explicit, error-free GraphQL null establishes absence. REST 404 by
        // itself could mean insufficient visibility and must never establish it.
        if metadata
            .pointer("/baseRef/branchProtectionRule")
            .is_some_and(Value::is_null)
        {
            return (None, true);
        }
        let request = GitHubRequest {
            path: format!("{prefix}/branches/{}/protection", segment(base)),
            graphql_body: None,
        };
        match self.request(request).await {
            Ok(value) if value.is_object() => (Some(value), true),
            Ok(_) => {
                self.gaps
                    .push("classic branch policy has invalid shape".into());
                (None, false)
            }
            Err(error) => {
                self.gaps
                    .push(format!("classic branch policy unavailable: {error}"));
                (None, false)
            }
        }
    }

    async fn pages(
        &mut self,
        path: &str,
        field: Option<&str>,
        max_items: usize,
    ) -> (Vec<Value>, bool) {
        let mut items = Vec::new();
        let mut previous_ids = BTreeSet::new();
        let mut expected_total = None;
        for page in 1..=self.observer.limits.max_pages {
            let separator = if path.contains('?') { '&' } else { '?' };
            let request = GitHubRequest {
                path: format!("{path}{separator}per_page={PAGE_SIZE}&page={page}"),
                graphql_body: None,
            };
            let value = match self.request(request).await {
                Ok(value) => value,
                Err(error) => {
                    self.gaps.push(format!("{path} page {page}: {error}"));
                    return (items, false);
                }
            };
            if field.is_some() {
                let total = value.get("total_count").and_then(Value::as_u64);
                if total.is_none() || expected_total.is_some_and(|old| Some(old) != total) {
                    self.gaps
                        .push(format!("{path}: missing or changing total_count"));
                    return (items, false);
                }
                expected_total = total;
            }
            let array = match field
                .map_or(Some(&value), |key| value.get(key))
                .and_then(Value::as_array)
            {
                Some(array) if array.len() <= PAGE_SIZE => array,
                _ => {
                    self.gaps.push(format!("{path}: invalid collection page"));
                    return (items, false);
                }
            };
            // Repeated records imply unstable pagination. Rules have no record ID, so
            // their complete value acts as identity; normal check/status IDs are stable.
            for item in array {
                if !item.is_object() {
                    self.gaps.push(format!("{path}: malformed collection item"));
                    return (items, false);
                }
                let id = item
                    .get("id")
                    .map_or_else(|| item.to_string(), Value::to_string);
                if !previous_ids.insert(id) {
                    self.gaps
                        .push(format!("{path}: duplicate record across pages"));
                    return (items, false);
                }
                if items.len() == max_items {
                    self.gaps.push(format!("{path}: item limit exceeded"));
                    return (items, false);
                }
                items.push(item.clone());
            }
            if let Some(total) = expected_total {
                if items.len() as u64 > total {
                    self.gaps.push(format!("{path}: inconsistent total_count"));
                    return (items, false);
                }
                if items.len() as u64 == total {
                    return (items, true);
                }
            }
            if array.len() < PAGE_SIZE {
                if expected_total.is_some_and(|total| items.len() as u64 != total) {
                    self.gaps.push(format!("{path}: truncated collection"));
                    return (items, false);
                }
                return (items, true);
            }
        }
        self.gaps.push(format!("{path}: page limit reached"));
        (items, false)
    }

    async fn threads(
        &mut self,
        owner: &str,
        name: &str,
        number: u64,
        before: &Value,
    ) -> (Vec<Value>, bool) {
        self.connection(owner, name, number, before, "reviewThreads", THREADS_QUERY)
            .await
    }

    async fn reviews(
        &mut self,
        owner: &str,
        name: &str,
        number: u64,
        before: &Value,
    ) -> (Vec<Value>, bool) {
        self.connection(
            owner,
            name,
            number,
            before,
            "latestOpinionatedReviews",
            REVIEWS_QUERY,
        )
        .await
    }

    async fn connection(
        &mut self,
        owner: &str,
        name: &str,
        number: u64,
        before: &Value,
        field: &str,
        query: &str,
    ) -> (Vec<Value>, bool) {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        let mut cursors = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for _ in 0..self.observer.limits.max_pages {
            let result = self
                .graphql(
                    query,
                    json!({"owner":owner,"name":name,"number":number,"cursor":cursor}),
                )
                .await;
            let parsed = result.and_then(|data| {
                validate_identity(&data, owner, name, number)?;
                let pr = data
                    .pointer("/repository/pullRequest")
                    .ok_or_else(|| GitHubObserverError::new("thread pull request missing"))?;
                if !same_revision(before, pr) {
                    return Err(GitHubObserverError::new("revision changed on thread page"));
                }
                let connection = pr
                    .get(field)
                    .ok_or_else(|| GitHubObserverError::new("review connection missing"))?;
                let nodes = connection
                    .get("nodes")
                    .and_then(Value::as_array)
                    .filter(|v| v.len() <= PAGE_SIZE)
                    .ok_or_else(|| GitHubObserverError::new("invalid review thread nodes"))?;
                let has_next = connection
                    .pointer("/pageInfo/hasNextPage")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| GitHubObserverError::new("review thread pageInfo missing"))?;
                let end = connection
                    .pointer("/pageInfo/endCursor")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                Ok((nodes.clone(), has_next, end))
            });
            let (nodes, has_next, end) = match parsed {
                Ok(parts) => parts,
                Err(error) => {
                    self.gaps.push(format!("{field}: {error}"));
                    return (items, false);
                }
            };
            for node in nodes {
                let Some(id) = node
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                else {
                    self.gaps.push("review thread identity missing".into());
                    return (items, false);
                };
                let valid = if field == "reviewThreads" {
                    node.get("isResolved").is_some_and(Value::is_boolean)
                } else {
                    node.get("state")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.is_empty())
                        && node
                            .pointer("/author/login")
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty())
                        && node
                            .pointer("/commit/oid")
                            .and_then(Value::as_str)
                            .is_some_and(valid_oid)
                };
                if !valid || !ids.insert(id.to_owned()) || items.len() == 512 {
                    self.gaps
                        .push(format!("{field}: invalid, repeated, or item limit reached"));
                    return (items, false);
                }
                items.push(node);
            }
            if !has_next {
                return (items, true);
            }
            let Some(end) = end.filter(|s| !s.is_empty() && s.len() <= 2048) else {
                self.gaps.push(format!("{field}: next cursor missing"));
                return (items, false);
            };
            if !cursors.insert(end.clone()) {
                self.gaps.push(format!("{field}: cursor repeated"));
                return (items, false);
            }
            cursor = Some(end);
        }
        self.gaps.push(format!("{field}: page limit reached"));
        (items, false)
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, GitHubObserverError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 2048)
        .ok_or_else(|| GitHubObserverError::new(format!("required GitHub field missing: {key}")))
}
fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn same_revision(a: &Value, b: &Value) -> bool {
    ["headRefOid", "baseRefOid", "baseRefName"]
        .iter()
        .all(|key| {
            a.get(key)
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty() && Some(v) == b.get(key).and_then(Value::as_str))
        })
}
fn validate_identity(
    data: &Value,
    owner: &str,
    name: &str,
    number: u64,
) -> Result<(), GitHubObserverError> {
    if !data
        .pointer("/repository/nameWithOwner")
        .and_then(Value::as_str)
        .is_some_and(|actual| actual.eq_ignore_ascii_case(&format!("{owner}/{name}")))
        || data
            .pointer("/repository/pullRequest/number")
            .and_then(Value::as_u64)
            != Some(number)
    {
        return Err(GitHubObserverError::new(
            "GitHub returned a different or missing repository/pull request",
        ));
    }
    Ok(())
}
fn validate_repository(repository: &str) -> Result<(&str, &str), GitHubObserverError> {
    let parts: Vec<_> = repository.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 100
                || *part == "."
                || *part == ".."
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    {
        return Err(GitHubObserverError::new(
            "repository must be an owner/name pair",
        ));
    }
    Ok((parts[0], parts[1]))
}
fn validate_path(path: &str) -> Result<(), GitHubObserverError> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('#')
        || path.contains('\\')
        || path.bytes().any(|b| b.is_ascii_control())
    {
        return Err(GitHubObserverError::new("invalid GitHub API path"));
    }
    Ok(())
}
fn segment(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}
fn canonical_rules(rules: &[Value]) -> Vec<String> {
    let mut values: Vec<_> = rules.iter().map(Value::to_string).collect();
    values.sort();
    values
}

const METADATA_QUERY: &str = r#"query LegionPullRequestObservation($owner:String!,$name:String!,$number:Int!){
 repository(owner:$owner,name:$name){nameWithOwner pullRequest(number:$number){
 number headRefOid baseRefOid baseRefName isDraft state mergeable mergeStateStatus reviewDecision
 baseRef{branchProtectionRule{id}}
 autoMergeRequest{enabledAt} isInMergeQueue mergeCommit{oid}
 }}}"#;
const THREADS_QUERY: &str = r#"query LegionPullRequestThreads($owner:String!,$name:String!,$number:Int!,$cursor:String){
 repository(owner:$owner,name:$name){nameWithOwner pullRequest(number:$number){
 number headRefOid baseRefOid baseRefName reviewThreads(first:100,after:$cursor){
 nodes{id isResolved} pageInfo{hasNextPage endCursor}
 }}}}"#;
const REVIEWS_QUERY: &str = r#"query LegionPullRequestReviews($owner:String!,$name:String!,$number:Int!,$cursor:String){
 repository(owner:$owner,name:$name){nameWithOwner pullRequest(number:$number){
 number headRefOid baseRefOid baseRefName latestOpinionatedReviews(first:100,after:$cursor){
 nodes{id state author{login} commit{oid} submittedAt} pageInfo{hasNextPage endCursor}
 }}}}"#;
