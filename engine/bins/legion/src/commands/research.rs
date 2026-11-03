use super::{CommandError, CommandResult};
use clap::Args;
use rightkit_research::command::{self as research, ResearchOptions};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct ResearchArgs {
    /// Route query for the host-injected search. Not required with `--step`.
    #[arg(long, required_unless_present = "step")]
    pub query: Option<String>,
    /// Complete ResearchRoute v2 JSON file; its subject.query must equal --query.
    #[arg(long = "route-json")]
    pub route_json: Option<PathBuf>,
    /// Run one Research step instead of a search: `ledger-check`,
    /// `ledger-render`, `citecheck`, `meter`, `retraction`, `issue-patch`, or `apply-patch`.
    #[arg(long)]
    pub step: Option<String>,
    /// Evidence ledger rows (JSONL) for `ledger-check` and `ledger-render`,
    /// and for `citecheck`.
    #[arg(long)]
    pub evidence: Option<PathBuf>,
    /// Claim ledger rows (JSONL) for `ledger-check` and `ledger-render`.
    #[arg(long)]
    pub claims: Option<PathBuf>,
    /// Markdown draft to bind citations for `citecheck`.
    #[arg(long)]
    pub draft: Option<PathBuf>,
    /// Run identifier bound into an issue-patch/apply-patch receipt.
    #[arg(long)]
    pub run_id: Option<String>,
    /// Existing raw HMAC key file (at least 32 bytes) for patch receipts.
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    /// Authenticated patch receipt JSON for `apply-patch`.
    #[arg(long)]
    pub receipt: Option<PathBuf>,
    /// Single-file unified diff for `apply-patch`.
    #[arg(long)]
    pub diff: Option<PathBuf>,
    /// Output path for `ledger-render`.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Brief title for `ledger-render`.
    #[arg(long, default_value = "Research brief")]
    pub title: String,
    /// DOI list (one per line) for `retraction`.
    #[arg(long)]
    pub dois: Option<PathBuf>,
    /// DOIs already disclosed as retracted in the draft, one per line.
    #[arg(long)]
    pub disclosed: Option<PathBuf>,
    /// Let unknown retraction status pass instead of blocking.
    #[arg(long = "allow-unknown")]
    pub allow_unknown: bool,
    /// JSON map of DOI to pre-fetched retraction metadata; selecting this keeps the step offline.
    #[arg(long = "retraction-fixture")]
    pub retraction_fixture: Option<PathBuf>,
    /// Do not use public metadata endpoints for missing retraction fixtures.
    #[arg(long)]
    pub offline: bool,
    /// JSON budget/usage state for `meter`. The updated state is reported, not written.
    #[arg(long = "meter-state")]
    pub meter_state: Option<PathBuf>,
    /// Metered effect for `meter`: `external_request` or `worker`.
    #[arg(long)]
    pub effect: Option<String>,
    /// Units consumed by one `meter` step.
    #[arg(long, default_value_t = 1)]
    pub units: u64,
    /// Worker lifecycle for `meter --effect worker`: `start` or `finish`.
    #[arg(long = "worker-event")]
    pub worker_event: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub provider: Vec<String>,
    #[arg(long, default_value_t = 5)]
    pub max_hits: u32,
    #[arg(long = "source-record")]
    pub source_records: Vec<PathBuf>,
    #[arg(long, default_value_t = 2)]
    pub min_independent_providers: usize,
    /// Let records without a usable URL count toward `--min-independent-providers` using their
    /// self-declared `provider` label. Off by default: independence otherwise rests on source
    /// identity (registrable domain), never on a label the host controls.
    #[arg(long)]
    pub allow_self_declared_independence: bool,
    /// Convenience route domain (default: general); conflicts with --route-json are refused.
    #[arg(long)]
    pub domain: Option<String>,
    /// Convenience route sensitivity (default: public); conflicts with --route-json are refused.
    #[arg(long)]
    pub sensitivity: Option<String>,
}

impl From<ResearchArgs> for ResearchOptions {
    fn from(args: ResearchArgs) -> Self {
        Self {
            query: args.query,
            route_json: args.route_json,
            step: args.step,
            evidence: args.evidence,
            claims: args.claims,
            draft: args.draft,
            run_id: args.run_id,
            key_file: args.key_file,
            receipt: args.receipt,
            diff: args.diff,
            out: args.out,
            title: args.title,
            dois: args.dois,
            disclosed: args.disclosed,
            allow_unknown: args.allow_unknown,
            retraction_fixture: args.retraction_fixture,
            offline: args.offline,
            meter_state: args.meter_state,
            effect: args.effect,
            units: args.units,
            worker_event: args.worker_event,
            provider: args.provider,
            max_hits: args.max_hits,
            source_records: args.source_records,
            min_independent_providers: args.min_independent_providers,
            allow_self_declared_independence: args.allow_self_declared_independence,
            domain: args.domain,
            sensitivity: args.sensitivity,
            kind: "legion-research".into(),
        }
    }
}

pub fn run(args: ResearchArgs, cancellation: CancellationToken) -> CommandResult {
    let cancel = rightkit_research::Cancellation::from_probe(move || cancellation.is_cancelled());
    research::run(args.into(), cancel).map_err(|error| CommandError {
        code: error.code,
        message: error.message,
    })
}
