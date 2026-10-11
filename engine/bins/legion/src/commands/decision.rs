use super::{display_path, io_error, CommandError, CommandResult};
use clap::{Args, Subcommand};
use legion_decisions::{
    l1b_port::{produce_candidate_set, CandidateSpec},
    DecisionError, DecisionRecord, DecisionStatus, DecisionStore, InsertDisposition,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const STORE_DIRECTORY: &str = ".legion";
const STORE_FILE: &str = "decisions.sqlite";

#[derive(Debug, Args)]
pub struct DecisionArgs {
    #[command(subcommand)]
    pub command: DecisionCommand,
}

#[derive(Debug, Subcommand)]
pub enum DecisionCommand {
    /// Draft a decision record; persist it only with --write.
    Propose(ProposeArgs),
    /// List the current decision records, optionally filtered.
    List(ListArgs),
    /// Show the current state of one decision record.
    Show(ShowArgs),
    /// Set the lifecycle status of one decision record.
    SetStatus(SetStatusArgs),
}

#[derive(Debug, Args)]
pub struct StoreOption {
    /// Decision store file (default: .legion/decisions.sqlite under the current directory).
    #[arg(long)]
    pub store: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ProposeArgs {
    #[arg(long, default_value = "repository")]
    pub repository: String,
    #[arg(long, default_value = "workspace")]
    pub scope: String,
    #[arg(long)]
    pub task: String,
    #[arg(long)]
    pub rationale: String,
    /// Persist the draft to the decision store (read back before reporting persisted).
    #[arg(long)]
    pub write: bool,
    #[command(flatten)]
    pub store_option: StoreOption,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Only decisions for this repository identifier.
    #[arg(long)]
    pub repository: Option<String>,
    /// Only decisions whose current status is one of proposed, accepted, implemented, superseded.
    #[arg(long)]
    pub status: Option<String>,
    #[command(flatten)]
    pub store_option: StoreOption,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Stable decision id (for example architect:decision:<digest>).
    pub id: String,
    #[command(flatten)]
    pub store_option: StoreOption,
}

#[derive(Debug, Args)]
pub struct SetStatusArgs {
    /// Stable decision id.
    pub id: String,
    /// New status: proposed, accepted, implemented or superseded.
    pub status: String,
    #[command(flatten)]
    pub store_option: StoreOption,
}

pub fn run(args: DecisionArgs) -> CommandResult {
    match args.command {
        DecisionCommand::Propose(args) => propose(args),
        DecisionCommand::List(args) => list(args),
        DecisionCommand::Show(args) => show(args),
        DecisionCommand::SetStatus(args) => set_status(args),
    }
}

fn propose(args: ProposeArgs) -> CommandResult {
    let draft = DecisionRecord::new(
        args.repository,
        args.scope,
        args.task,
        args.rationale,
        DecisionStatus::Proposed,
    );
    if !args.write {
        // Drafted in memory only: nothing is written and the store is not touched.
        return Ok(json!({
            "schemaVersion": 1,
            "kind": "legion-decision",
            "persisted": false,
            "record": draft,
        }));
    }
    let path = store_path(&args.store_option)?;
    let draft_hash = draft.compute_source_hash().map_err(decision_error)?;
    let mut store = open_for_write(&path)?;
    if let Some(existing) = store.get(&draft.id).map_err(decision_error)? {
        if existing.source_hash != draft_hash {
            return Err(CommandError::usage(format!(
                "decision {} is already recorded as {}; use set-status to change it",
                draft.id,
                status_name(existing.current_status)
            )));
        }
    }
    let disposition = store.insert(&draft).map_err(decision_error)?;
    let stored = store
        .get(&draft.id)
        .map_err(decision_error)?
        .filter(|record| record.source_hash == draft_hash)
        .ok_or_else(|| {
            CommandError::internal(format!(
                "decision {} was not readable after write",
                draft.id
            ))
        })?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-decision",
        "persisted": true,
        "disposition": disposition_name(disposition),
        "store": display_path(&path),
        "record": stored,
    }))
}

fn list(args: ListArgs) -> CommandResult {
    let path = store_path(&args.store_option)?;
    let status_filter = args.status.as_deref().map(parse_status).transpose()?;
    let latest = match open_existing(&path)? {
        Some(store) => latest_per_id(store.all().map_err(decision_error)?),
        None => Vec::new(),
    };
    let projection = match &args.repository {
        Some(repository) => {
            let spec = CandidateSpec {
                task: "decision list".to_string(),
                repository_id: repository.clone(),
                ..CandidateSpec::default()
            };
            let set = produce_candidate_set(&spec, &latest, "list").map_err(|error| {
                CommandError::incomplete(format!("decision projection refused: {error}"))
            })?;
            Some(set.as_json())
        }
        None => None,
    };
    let decisions: Vec<DecisionRecord> = latest
        .into_iter()
        .filter(|record| {
            args.repository
                .as_ref()
                .map_or(true, |repository| &record.repository_id == repository)
        })
        .filter(|record| status_filter.map_or(true, |status| record.current_status == status))
        .collect();
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-decision-list",
        "store": display_path(&path),
        "count": decisions.len(),
        "decisions": decisions,
        "projection": projection,
    }))
}

fn show(args: ShowArgs) -> CommandResult {
    let path = store_path(&args.store_option)?;
    let record = match open_existing(&path)? {
        Some(store) => store.get(&args.id).map_err(decision_error)?,
        None => None,
    };
    let record = record.ok_or_else(|| not_found(&args.id, &path))?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-decision-show",
        "store": display_path(&path),
        "decision": record,
    }))
}

fn set_status(args: SetStatusArgs) -> CommandResult {
    let status = parse_status(&args.status)?;
    let path = store_path(&args.store_option)?;
    let Some(mut store) = open_existing(&path)? else {
        return Err(not_found(&args.id, &path));
    };
    let previous = store
        .get(&args.id)
        .map_err(decision_error)?
        .ok_or_else(|| not_found(&args.id, &path))?;
    let updated = store
        .set_status(&args.id, status)
        .map_err(decision_error)?
        .filter(|record| record.current_status == status)
        .ok_or_else(|| {
            CommandError::internal(format!(
                "decision {} status was not readable after write",
                args.id
            ))
        })?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-decision-status",
        "persisted": true,
        "store": display_path(&path),
        "previousStatus": status_name(previous.current_status),
        "decision": updated,
    }))
}

fn store_path(option: &StoreOption) -> Result<PathBuf, CommandError> {
    match &option.store {
        Some(path) => Ok(path.clone()),
        None => Ok(std::env::current_dir()
            .map_err(io_error)?
            .join(STORE_DIRECTORY)
            .join(STORE_FILE)),
    }
}

fn open_for_write(path: &Path) -> Result<DecisionStore, CommandError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    DecisionStore::open(path).map_err(decision_error)
}

/// Opens an existing store for reading or transition; a missing file is `None`,
/// so read commands never create a store as a side effect.
fn open_existing(path: &Path) -> Result<Option<DecisionStore>, CommandError> {
    if !path.is_file() {
        return Ok(None);
    }
    DecisionStore::open(path).map(Some).map_err(decision_error)
}

/// The store is append-only; a stable id can have several rows. Rows are
/// read in retention order, so the last row per id is its current state.
fn latest_per_id(records: Vec<DecisionRecord>) -> Vec<DecisionRecord> {
    let mut latest: BTreeMap<String, DecisionRecord> = BTreeMap::new();
    for record in records {
        latest.insert(record.id.clone(), record);
    }
    latest.into_values().collect()
}

fn not_found(id: &str, path: &Path) -> CommandError {
    CommandError::usage(format!(
        "decision {id} not found in {}",
        display_path(path).display()
    ))
}

fn parse_status(value: &str) -> Result<DecisionStatus, CommandError> {
    match value {
        "proposed" => Ok(DecisionStatus::Proposed),
        "accepted" => Ok(DecisionStatus::Accepted),
        "implemented" => Ok(DecisionStatus::Implemented),
        "superseded" => Ok(DecisionStatus::Superseded),
        other => Err(CommandError::usage(format!(
            "unknown decision status {other}; expected proposed, accepted, implemented or superseded"
        ))),
    }
}

fn status_name(status: DecisionStatus) -> &'static str {
    match status {
        DecisionStatus::Proposed => "proposed",
        DecisionStatus::Accepted => "accepted",
        DecisionStatus::Implemented => "implemented",
        DecisionStatus::Superseded => "superseded",
    }
}

fn disposition_name(disposition: InsertDisposition) -> &'static str {
    match disposition {
        InsertDisposition::Inserted => "inserted",
        InsertDisposition::AlreadyPresent => "alreadyPresent",
    }
}

fn decision_error(error: DecisionError) -> CommandError {
    let message = error.to_string();
    match error {
        DecisionError::Invalid { .. } | DecisionError::UnsupportedVersion(_) => {
            CommandError::usage(message)
        }
        _ => CommandError::internal(message),
    }
}
