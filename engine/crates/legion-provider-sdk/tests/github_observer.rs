//! Fixture-driven observer contracts. No test contacts GitHub or reads credentials.
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use legion_provider_sdk::{
    auth::{AuthError, CredentialEffectDecision, SecretProvider},
    github::{
        GitHubObserver, GitHubObserverError, GitHubObserverLimits, GitHubRequest, GitHubResponse,
        GitHubTransport,
    },
    CredentialAuthorizer,
};
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BASE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OTHER: &str = "cccccccccccccccccccccccccccccccccccccccc";

struct Step {
    path: String,
    operation: Option<&'static str>,
    status: u16,
    body: Value,
}
fn rest(path: &str, body: Value) -> Step {
    Step {
        path: path.into(),
        operation: None,
        status: 200,
        body,
    }
}
fn graphql(operation: &'static str, body: Value) -> Step {
    Step {
        path: "/graphql".into(),
        operation: Some(operation),
        status: 200,
        body,
    }
}
#[derive(Default)]
struct Fixture {
    steps: Mutex<VecDeque<Step>>,
    requests: Mutex<Vec<GitHubRequest>>,
}
impl Fixture {
    fn new(steps: Vec<Step>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into()),
            requests: Mutex::new(Vec::new()),
        })
    }
    fn drained(&self) {
        assert!(
            self.steps.lock().unwrap().is_empty(),
            "unused fixture responses"
        );
    }
}
#[async_trait]
impl GitHubTransport for Fixture {
    async fn send(
        &self,
        request: GitHubRequest,
        _: usize,
        _: Duration,
        _: CancellationToken,
    ) -> Result<GitHubResponse, GitHubObserverError> {
        let step = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected API request");
        assert_eq!(request.path, step.path);
        if let Some(operation) = step.operation {
            assert!(request.graphql_body.as_ref().unwrap()["query"]
                .as_str()
                .unwrap()
                .contains(operation));
        } else {
            assert!(request.graphql_body.is_none());
        }
        self.requests.lock().unwrap().push(request);
        Ok(GitHubResponse {
            status: step.status,
            body: serde_json::to_vec(&step.body).unwrap(),
            request_id: Some("fixture-request".into()),
        })
    }
}
fn pr() -> Value {
    json!({"number":7,"headRefOid":HEAD,"baseRefOid":BASE,"baseRefName":"main",
        "isDraft":false,"state":"OPEN","mergeable":"MERGEABLE","mergeStateStatus":"CLEAN",
        "reviewDecision":null,"autoMergeRequest":null,"isInMergeQueue":false,"mergeCommit":null,
        "baseRef":{"branchProtectionRule":null}})
}
fn envelope(pr: Value) -> Value {
    json!({"data":{"repository":{"nameWithOwner":"owner/repo","pullRequest":pr}}})
}
fn connection(
    field: &str,
    nodes: Vec<Value>,
    next: bool,
    cursor: Option<&str>,
    head: &str,
) -> Value {
    let mut value = pr();
    value["headRefOid"] = json!(head);
    value[field] = json!({"nodes":nodes,"pageInfo":{"hasNextPage":next,"endCursor":cursor}});
    envelope(value)
}
fn run(id: u64, name: &str, conclusion: &str) -> Value {
    json!({"id":id,"name":name,"head_sha":HEAD,"status":"completed","conclusion":conclusion,"app":{"id":22}})
}
fn review() -> Value {
    json!({"id":"review-1","state":"CHANGES_REQUESTED","author":{"login":"person"},"commit":{"oid":HEAD}})
}
fn steps() -> Vec<Step> {
    vec![
        graphql("LegionPullRequestObservation", envelope(pr())),
        rest(
            "/repos/owner/repo/rules/branches/main?per_page=100&page=1",
            json!([]),
        ),
        rest(
            &format!(
                "/repos/owner/repo/commits/{HEAD}/check-runs?filter=latest&per_page=100&page=1"
            ),
            json!({"total_count":2,"check_runs":[run(1,"build","failure"),run(2,"build","success")]}),
        ),
        rest(
            &format!("/repos/owner/repo/commits/{HEAD}/statuses?per_page=100&page=1"),
            json!([
            {"id":10,"context":"legacy","state":"pending"}, {"id":9,"context":"legacy","state":"success"}]),
        ),
        graphql(
            "LegionPullRequestThreads",
            connection(
                "reviewThreads",
                vec![json!({"id":"thread-1","isResolved":false})],
                false,
                None,
                HEAD,
            ),
        ),
        graphql(
            "LegionPullRequestReviews",
            connection(
                "latestOpinionatedReviews",
                vec![review()],
                false,
                None,
                HEAD,
            ),
        ),
        rest(
            "/repos/owner/repo/rules/branches/main?per_page=100&page=1",
            json!([]),
        ),
        graphql("LegionPullRequestObservation", envelope(pr())),
    ]
}
async fn observe(fixture: Arc<Fixture>) -> legion_provider_sdk::github::GitHubObservation {
    let observer =
        GitHubObserver::with_transport(fixture, GitHubObserverLimits::default()).unwrap();
    observer
        .observe("owner/repo", 7, CancellationToken::new())
        .await
        .unwrap()
}

struct SlowReviewCollection {
    fixture: Arc<Fixture>,
    first_request_at: AtomicU64,
}
#[async_trait]
impl GitHubTransport for SlowReviewCollection {
    async fn send(
        &self,
        request: GitHubRequest,
        max_bytes: usize,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<GitHubResponse, GitHubObserverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = self
            .first_request_at
            .compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst);
        if request.graphql_body.as_ref().is_some_and(|body| {
            body["query"]
                .as_str()
                .is_some_and(|query| query.contains("LegionPullRequestThreads"))
        }) {
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        self.fixture
            .send(request, max_bytes, timeout, cancellation)
            .await
    }
}

#[tokio::test]
async fn slow_collection_does_not_restamp_earlier_facts_as_fresh() {
    let fixture = Fixture::new(steps());
    let transport = Arc::new(SlowReviewCollection {
        fixture: fixture.clone(),
        first_request_at: AtomicU64::new(0),
    });
    let observer =
        GitHubObserver::with_transport(transport.clone(), GitHubObserverLimits::default()).unwrap();
    let value = observer
        .observe("owner/repo", 7, CancellationToken::new())
        .await
        .unwrap();
    let first_request = transport.first_request_at.load(Ordering::SeqCst);
    let completed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fixture.drained();
    assert!(completed > first_request);
    assert!(value.observed_at_unix_seconds <= first_request);
}

#[tokio::test]
async fn retains_failed_duplicate_runs_historic_status_order_and_changes_requested() {
    let fixture = Fixture::new(steps());
    let value = observe(fixture.clone()).await;
    fixture.drained();
    assert!(
        value.completeness.checks
            && value.completeness.threads
            && value.completeness.reviews
            && value.completeness.policy
    );
    assert!(value.gaps.is_empty());
    assert_eq!(value.check_runs[0]["conclusion"], "failure");
    assert_eq!(value.check_runs[1]["conclusion"], "success");
    assert_eq!(value.statuses[0]["state"], "pending");
    assert_eq!(value.statuses[0]["_legion_head"], HEAD);
    assert_eq!(value.reviews[0]["state"], "CHANGES_REQUESTED");
    assert!(fixture.requests.lock().unwrap()[5]
        .graphql_body
        .as_ref()
        .unwrap()["query"]
        .as_str()
        .unwrap()
        .contains("latestOpinionatedReviews"));
    assert_eq!(value.review_threads[0]["isResolved"], false);
    assert_eq!(value.receipts.len(), 8);
    assert!(value
        .receipts
        .iter()
        .all(|receipt| receipt.body_sha256.len() == 64));
    assert!(value.classic_policy_before.is_none());
}

#[tokio::test]
async fn collects_multiple_rest_and_cursor_pages_without_following_server_urls() {
    let mut script = steps();
    let page: Vec<_> = (1..=100).map(|id| run(id, "build", "success")).collect();
    script[2].body = json!({"total_count":101,"check_runs":page});
    script.insert(
        3,
        rest(
            &format!(
                "/repos/owner/repo/commits/{HEAD}/check-runs?filter=latest&per_page=100&page=2"
            ),
            json!({"total_count":101,"check_runs":[run(101,"build","failure")]}),
        ),
    );
    script[5].body = connection(
        "reviewThreads",
        vec![json!({"id":"thread-1","isResolved":true})],
        true,
        Some("cursor-1"),
        HEAD,
    );
    script.insert(
        6,
        graphql(
            "LegionPullRequestThreads",
            connection(
                "reviewThreads",
                vec![json!({"id":"thread-2","isResolved":false})],
                false,
                None,
                HEAD,
            ),
        ),
    );
    let fixture = Fixture::new(script);
    let value = observe(fixture.clone()).await;
    fixture.drained();
    assert!(value.completeness.checks && value.completeness.threads);
    assert_eq!(value.check_runs.len(), 101);
    assert_eq!(value.review_threads.len(), 2);
    assert_eq!(
        fixture.requests.lock().unwrap()[6]
            .graphql_body
            .as_ref()
            .unwrap()["variables"]["cursor"],
        "cursor-1"
    );
}

#[tokio::test]
async fn failed_page_and_partial_graphql_never_look_complete() {
    let mut script = steps();
    script[2].status = 403;
    script[4].body["errors"] = json!([{"message":"fixture private details"}]);
    let fixture = Fixture::new(script);
    let value = observe(fixture.clone()).await;
    fixture.drained();
    assert!(!value.completeness.checks && !value.completeness.threads);
    assert!(value.check_runs.is_empty() && value.review_threads.is_empty());
    assert!(!value.gaps.join(" ").contains("fixture private details"));
}

struct RawResponse(Vec<u8>);
#[async_trait]
impl GitHubTransport for RawResponse {
    async fn send(
        &self,
        _: GitHubRequest,
        _: usize,
        _: Duration,
        _: CancellationToken,
    ) -> Result<GitHubResponse, GitHubObserverError> {
        Ok(GitHubResponse {
            status: 200,
            body: self.0.clone(),
            request_id: None,
        })
    }
}
#[tokio::test]
async fn malformed_json_and_null_graphql_data_fail_before_collection() {
    for body in [b"{invalid-json".to_vec(), br#"{"data":null}"#.to_vec()] {
        let observer = GitHubObserver::with_transport(
            Arc::new(RawResponse(body)),
            GitHubObserverLimits::default(),
        )
        .unwrap();
        assert!(observer
            .observe("owner/repo", 7, CancellationToken::new())
            .await
            .is_err());
    }
}

#[tokio::test]
async fn wrong_check_revision_and_changed_base_invalidate_snapshot() {
    let mut script = steps();
    script[2].body["check_runs"][0]["head_sha"] = json!(OTHER);
    script[7].body["data"]["repository"]["pullRequest"]["baseRefOid"] = json!(OTHER);
    let value = observe(Fixture::new(script)).await;
    assert!(
        !value.completeness.metadata && !value.completeness.checks && !value.completeness.policy
    );
    assert!(!value.completeness.reviews && !value.completeness.threads);
}

#[tokio::test]
async fn repeated_thread_cursor_is_an_explicit_gap() {
    let mut script = steps();
    script[4].body = connection(
        "reviewThreads",
        vec![json!({"id":"thread-1","isResolved":true})],
        true,
        Some("cursor-1"),
        HEAD,
    );
    script.insert(
        5,
        graphql(
            "LegionPullRequestThreads",
            connection(
                "reviewThreads",
                vec![json!({"id":"thread-2","isResolved":true})],
                true,
                Some("cursor-1"),
                HEAD,
            ),
        ),
    );
    let fixture = Fixture::new(script);
    let value = observe(fixture.clone()).await;
    fixture.drained();
    assert!(!value.completeness.threads);
    assert!(value.gaps.iter().any(|gap| gap.contains("cursor repeated")));
}

#[tokio::test]
async fn truncated_check_count_and_null_review_author_are_incomplete() {
    let mut script = steps();
    script[2].body["total_count"] = json!(3);
    script[5].body["data"]["repository"]["pullRequest"]["latestOpinionatedReviews"]["nodes"][0]
        ["author"] = Value::Null;
    let value = observe(Fixture::new(script)).await;
    assert!(!value.completeness.checks && !value.completeness.reviews);
    assert!(value
        .gaps
        .iter()
        .any(|gap| gap.contains("truncated collection")));
}

#[tokio::test]
async fn policy_changes_and_new_classic_protection_are_incomplete() {
    let mut script = steps();
    script[6].body = json!([{"type":"required_signatures"}]);
    script[7].body["data"]["repository"]["pullRequest"]["baseRef"]["branchProtectionRule"] =
        json!({"id":"new-rule"});
    let value = observe(Fixture::new(script)).await;
    assert!(!value.completeness.policy);
    assert!(value.gaps.iter().any(|gap| gap.contains("policy changed")));
}

#[tokio::test]
async fn private_classic_policy_404_does_not_establish_absence() {
    let mut script = steps();
    for index in [0, 7] {
        script[index].body["data"]["repository"]["pullRequest"]["baseRef"]
            ["branchProtectionRule"] = json!({"id":"rule"});
    }
    let mut missing_before = rest(
        "/repos/owner/repo/branches/main/protection",
        json!({"message":"not found"}),
    );
    missing_before.status = 404;
    let mut missing_after = rest(
        "/repos/owner/repo/branches/main/protection",
        json!({"message":"not found"}),
    );
    missing_after.status = 404;
    script.insert(1, missing_before);
    script.insert(7, missing_after);
    let fixture = Fixture::new(script);
    let value = observe(fixture.clone()).await;
    fixture.drained();
    assert!(!value.completeness.policy);
    assert!(value.classic_policy_before.is_none());
}

#[tokio::test]
async fn shared_check_bound_page_bound_and_redirect_are_enforced() {
    let mut script = steps();
    script[2].body =
        json!({"total_count":2,"check_runs":[run(1,"build","success"),run(2,"build","success")]});
    let fixture = Fixture::new(script);
    let limits = GitHubObserverLimits {
        max_checks: 2,
        ..Default::default()
    };
    let value = GitHubObserver::with_transport(fixture.clone(), limits)
        .unwrap()
        .observe("owner/repo", 7, CancellationToken::new())
        .await
        .unwrap();
    fixture.drained();
    assert!(!value.completeness.checks);
    assert!(value.statuses.is_empty());
    assert!(value.gaps.iter().any(|gap| gap.contains("item limit")));

    let mut script = steps();
    let page: Vec<_> = (1..=100).map(|id| run(id, "build", "success")).collect();
    script[2].body = json!({"total_count":101,"check_runs":page});
    let fixture = Fixture::new(script);
    let limits = GitHubObserverLimits {
        max_pages: 1,
        ..Default::default()
    };
    let value = GitHubObserver::with_transport(fixture.clone(), limits)
        .unwrap()
        .observe("owner/repo", 7, CancellationToken::new())
        .await
        .unwrap();
    fixture.drained();
    assert!(!value.completeness.checks);
    assert_eq!(value.check_runs.len(), 100);
    assert!(value.gaps.iter().any(|gap| gap.contains("page limit")));

    let mut script = steps();
    script[0].status = 302;
    let fixture = Fixture::new(script.into_iter().take(1).collect());
    let result = GitHubObserver::with_transport(fixture.clone(), GitHubObserverLimits::default())
        .unwrap()
        .observe("owner/repo", 7, CancellationToken::new())
        .await;
    fixture.drained();
    assert!(result.unwrap_err().message.contains("HTTP 302"));
}

struct Delayed;
#[async_trait]
impl GitHubTransport for Delayed {
    async fn send(
        &self,
        _: GitHubRequest,
        _: usize,
        _: Duration,
        _: CancellationToken,
    ) -> Result<GitHubResponse, GitHubObserverError> {
        tokio::time::sleep(Duration::from_secs(30)).await;
        unreachable!("observer must enforce its own deadline")
    }
}
#[tokio::test]
async fn observer_enforces_deadline_even_if_custom_transport_ignores_it() {
    let limits = GitHubObserverLimits {
        total_timeout: Duration::from_millis(1),
        ..Default::default()
    };
    let observer = GitHubObserver::with_transport(Arc::new(Delayed), limits).unwrap();
    let error = observer
        .observe("owner/repo", 7, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(error.message.contains("deadline"));
}

#[tokio::test]
async fn cancelled_invalid_identity_and_oversized_responses_fail_closed() {
    let fixture = Fixture::new(Vec::new());
    let observer =
        GitHubObserver::with_transport(fixture.clone(), GitHubObserverLimits::default()).unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(observer
        .observe("owner/repo", 7, cancellation)
        .await
        .is_err());
    assert!(observer
        .observe("owner/repo/../../other", 7, CancellationToken::new())
        .await
        .is_err());
    assert!(observer
        .observe("owner/repo", 0, CancellationToken::new())
        .await
        .is_err());
    fixture.drained();

    let mut first = steps().remove(0);
    first.body["data"]["repository"]["nameWithOwner"] = json!("other/repo");
    let fixture = Fixture::new(vec![first]);
    assert!(
        GitHubObserver::with_transport(fixture.clone(), GitHubObserverLimits::default())
            .unwrap()
            .observe("owner/repo", 7, CancellationToken::new())
            .await
            .is_err()
    );
    fixture.drained();

    let fixture = Fixture::new(vec![steps().remove(0)]);
    let limits = GitHubObserverLimits {
        max_response_bytes: 16,
        ..Default::default()
    };
    assert!(GitHubObserver::with_transport(fixture.clone(), limits)
        .unwrap()
        .observe("owner/repo", 7, CancellationToken::new())
        .await
        .unwrap_err()
        .message
        .contains("byte limit"));
    fixture.drained();
}

struct Secrets {
    calls: AtomicUsize,
    missing: bool,
}
impl SecretProvider for Secrets {
    fn bearer_token(&self) -> Result<SecretString, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.missing {
            Err(AuthError::invalid(
                "secret failure details never leave auth boundary",
            ))
        } else {
            Ok(SecretString::from("fixture-never-display-token".to_owned()))
        }
    }
}
struct Authorizer {
    allowed: bool,
}
impl CredentialAuthorizer for Authorizer {
    fn authorize_credential_access(
        &self,
        provider_id: &str,
    ) -> Result<CredentialEffectDecision, AuthError> {
        assert_eq!(provider_id, "github");
        Ok(if self.allowed {
            CredentialEffectDecision::Allowed
        } else {
            CredentialEffectDecision::Denied
        })
    }
}
#[test]
fn credentials_require_exact_scope_and_diagnostics_are_redacted() {
    let secrets = Secrets {
        calls: AtomicUsize::new(0),
        missing: false,
    };
    assert!(GitHubObserver::authorized(
        &secrets,
        &Authorizer { allowed: false },
        GitHubObserverLimits::default()
    )
    .is_err());
    assert_eq!(secrets.calls.load(Ordering::SeqCst), 0);
    let (_, receipt) = GitHubObserver::authorized(
        &secrets,
        &Authorizer { allowed: true },
        GitHubObserverLimits::default(),
    )
    .unwrap();
    assert_eq!(receipt.provider_id, "github");
    assert!(!format!("{receipt:?}").contains("fixture-never-display-token"));
    let missing = Secrets {
        calls: AtomicUsize::new(0),
        missing: true,
    };
    let error = match GitHubObserver::authorized(
        &missing,
        &Authorizer { allowed: true },
        GitHubObserverLimits::default(),
    ) {
        Err(error) => error,
        Ok(_) => panic!("missing token unexpectedly accepted"),
    };
    assert!(!error.message.contains("secret failure details"));
}
