use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use sha2::{Digest, Sha256};

use crate::{
    error::{Result, SourceError, SourceErrorCode},
    model::{HandoffEntry, HandoffPacket, HandoffSection, Omission},
    source::{EventCursor, HandoffQuery, Record, RecordCategory, SourceSet},
    token::{TokenAccounting, TokenBudget, Tokenizer},
};

pub struct HandoffBuilder<T> {
    pub query: HandoffQuery,
    pub sources: SourceSet,
    pub tokenizer: Arc<T>,
    pub budget: TokenBudget,
}

impl<T: Tokenizer + 'static> HandoffBuilder<T> {
    pub fn new(
        query: HandoffQuery,
        sources: SourceSet,
        tokenizer: Arc<T>,
        budget: TokenBudget,
    ) -> Self {
        Self {
            query,
            sources,
            tokenizer,
            budget,
        }
    }

    pub async fn build(&self) -> Result<HandoffPacket> {
        let mut records = Vec::new();
        let mut omissions = Vec::new();
        let mut cursor = None;
        self.load_required(&mut records, &mut omissions).await?;
        self.load_optional(&mut records, &mut omissions).await?;
        if let Some(reader) = &self.sources.events {
            match reader.events(&self.query, None).await {
                Ok(page) => {
                    records.extend(page.records);
                    cursor = Some(page.cursor);
                }
                Err(error) => self.record_unavailability(&mut omissions, "event_cursor", error),
            }
        } else {
            omissions.push(Omission {
                id: "event-cursor".into(),
                category: RecordCategory::Event,
                reason: "source_unavailable".into(),
                recoverable: true,
                source_ref: "session-events".into(),
            });
        }
        let records = deduplicate(records);
        let mut accounting = TokenAccounting {
            budget: self.budget.max_tokens,
            ..TokenAccounting::default()
        };
        let (sections, mut budget_omissions) = self.select(records, &mut accounting);
        omissions.append(&mut budget_omissions);
        let mut provenance = sections
            .iter()
            .flat_map(|section| {
                section
                    .entries
                    .iter()
                    .map(|entry| format!("{}:{}", entry.source_ref, entry.source_hash))
            })
            .chain(omissions.iter().map(|omission| omission.source_ref.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        provenance.sort();
        let handoff_id = stable_id(&self.query, &sections, &cursor, &omissions);
        let partial = !omissions.is_empty();
        let blocked = omissions
            .iter()
            .any(|omission| omission.category.protected());
        let receipt_digest =
            stable_receipt_digest(&handoff_id, &sections, &omissions, &accounting, &cursor);
        Ok(HandoffPacket {
            schema_version: 1,
            handoff_id,
            session_id: self.query.session_id.clone(),
            repository_id: self.query.repository_id.clone(),
            source_generation: self.query.source_generation.clone(),
            sections,
            cursor,
            source_provenance: provenance,
            omissions,
            accounting,
            partial,
            blocked,
            receipt_digest,
        })
    }

    async fn load_required(
        &self,
        records: &mut Vec<Record>,
        omissions: &mut Vec<Omission>,
    ) -> Result<()> {
        let Some(source) = &self.sources.records else {
            omissions.push(Omission {
                id: "records".into(),
                category: RecordCategory::ProtectedObligation,
                reason: "source_unavailable".into(),
                recoverable: true,
                source_ref: "records".into(),
            });
            return Ok(());
        };
        match source.records(&self.query).await {
            Ok(mut values) => records.append(&mut values),
            Err(error) => self.record_unavailability(omissions, "records", error),
        }
        if !records
            .iter()
            .any(|record| record.category == RecordCategory::ProtectedObligation)
        {
            omissions.push(Omission {
                id: "protected-obligations".into(),
                category: RecordCategory::ProtectedObligation,
                reason: "no_records_returned".into(),
                recoverable: false,
                source_ref: "records".into(),
            });
        }
        if !records
            .iter()
            .any(|record| record.category == RecordCategory::ActiveTask)
        {
            omissions.push(Omission {
                id: "active-task".into(),
                category: RecordCategory::ActiveTask,
                reason: "no_records_returned".into(),
                recoverable: false,
                source_ref: "records".into(),
            });
        }
        Ok(())
    }

    async fn load_optional(
        &self,
        records: &mut Vec<Record>,
        omissions: &mut Vec<Omission>,
    ) -> Result<()> {
        if let Some(source) = &self.sources.memory {
            match source.search(&self.query).await {
                Ok(mut values) => records.append(&mut values),
                Err(error) => self.record_unavailability(omissions, "memory", error),
            }
        } else {
            omissions.push(Omission {
                id: "memory".into(),
                category: RecordCategory::Memory,
                reason: "source_unavailable".into(),
                recoverable: true,
                source_ref: "memory".into(),
            });
        }
        if let Some(source) = &self.sources.artifacts {
            match source.artifacts(&self.query).await {
                Ok(mut values) => records.append(&mut values),
                Err(error) => self.record_unavailability(omissions, "artifacts", error),
            }
        } else {
            omissions.push(Omission {
                id: "artifacts".into(),
                category: RecordCategory::Artifact,
                reason: "source_unavailable".into(),
                recoverable: true,
                source_ref: "artifacts".into(),
            });
        }
        Ok(())
    }

    fn record_unavailability(&self, omissions: &mut Vec<Omission>, id: &str, error: SourceError) {
        omissions.push(Omission {
            id: id.into(),
            category: if id == "memory" {
                RecordCategory::Memory
            } else if id == "artifacts" {
                RecordCategory::Artifact
            } else {
                RecordCategory::Event
            },
            reason: error.code.to_string(),
            recoverable: matches!(
                error.code,
                SourceErrorCode::Unavailable | SourceErrorCode::Stale
            ),
            source_ref: error.source,
        });
    }

    fn select(
        &self,
        records: Vec<Record>,
        accounting: &mut TokenAccounting,
    ) -> (Vec<HandoffSection>, Vec<Omission>) {
        let mut grouped: BTreeMap<RecordCategory, Vec<Record>> = BTreeMap::new();
        for record in records {
            grouped
                .entry(record.category.clone())
                .or_default()
                .push(record);
        }
        let mut omissions = Vec::new();
        let mut sections = Vec::new();
        for category in [
            RecordCategory::ProtectedObligation,
            RecordCategory::ActiveTask,
            RecordCategory::Decision,
            RecordCategory::Artifact,
            RecordCategory::UnresolvedRisk,
            RecordCategory::Memory,
            RecordCategory::Event,
        ] {
            let Some(mut rows) = grouped.remove(&category) else {
                continue;
            };
            rows.sort_by(|left, right| {
                left.sequence
                    .cmp(&right.sequence)
                    .then_with(|| left.occurred_at_ms.cmp(&right.occurred_at_ms))
                    .then_with(|| left.id.cmp(&right.id))
            });
            let mut entries = Vec::new();
            for record in rows {
                let full_tokens = self.tokenizer.count(&record.text);
                if accounting.add(full_tokens) {
                    entries.push(HandoffEntry::from_record(&record));
                    continue;
                }
                if record.recoverable {
                    if let Some(reference) = &record.external_ref {
                        let mut entry = HandoffEntry::from_record(&record);
                        entry.text = format!("[externalized:{}]", reference);
                        entry.externalized = true;
                        let compact_tokens = self.tokenizer.count(&entry.text);
                        if accounting.add(compact_tokens) {
                            accounting.externalize(full_tokens.saturating_sub(compact_tokens));
                            entries.push(entry);
                            continue;
                        }
                    }
                }
                accounting.omit(full_tokens);
                let protected = record.protected();
                omissions.push(Omission {
                    id: record.id,
                    category: record.category.clone(),
                    reason: if protected {
                        "protected_budget_exceeded"
                    } else {
                        "budget_exceeded"
                    }
                    .into(),
                    recoverable: record.recoverable,
                    source_ref: record.source_ref,
                });
            }
            if !entries.is_empty() {
                sections.push(HandoffSection { category, entries });
            }
        }
        (sections, omissions)
    }
}

fn deduplicate(records: Vec<Record>) -> Vec<Record> {
    let mut by_id = BTreeMap::new();
    for record in records {
        by_id.entry(record.id.clone()).or_insert(record);
    }
    by_id.into_values().collect()
}

fn stable_id(
    query: &HandoffQuery,
    sections: &[HandoffSection],
    cursor: &Option<EventCursor>,
    omissions: &[Omission],
) -> String {
    let payload = serde_json::json!({ "query": query, "sections": sections, "cursor": cursor, "omissions": omissions });
    format!(
        "handoff-{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(&payload).unwrap_or_default()
        ))
    )
}

fn stable_receipt_digest(
    handoff_id: &str,
    sections: &[HandoffSection],
    omissions: &[Omission],
    accounting: &TokenAccounting,
    cursor: &Option<EventCursor>,
) -> String {
    let payload = serde_json::json!({ "handoffId": handoff_id, "sections": sections, "omissions": omissions, "accounting": accounting, "cursor": cursor });
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(&payload).unwrap_or_default()
        ))
    )
}
