use crate::{
    error::DecisionError,
    model::{DecisionQuery, DecisionRecord},
    store::DecisionStore,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RankedDecision {
    pub record: DecisionRecord,
    pub exact_repository_scope: bool,
    pub active: bool,
    pub linked_generation: bool,
}

impl DecisionStore {
    /// Return every retained row in deterministic relevance order.
    ///
    /// Matching is deliberately a ranking operation, not an overwrite: rows
    /// with the same stable ID but different source hashes remain visible.
    /// Exact repository+scope+active rows sort first, followed by linked
    /// generation, decision time (newest first), stable ID, and source hash.
    pub fn query(&self, query: &DecisionQuery) -> Result<Vec<DecisionRecord>, DecisionError> {
        let mut ranked = self
            .all()?
            .into_iter()
            .map(|record| {
                let exact_repository_scope = record.repository_id == query.repository_id
                    && record.scope_id == query.scope_id;
                let active = record.current_status.is_active();
                let linked_generation = query
                    .linked_graph_generation
                    .as_ref()
                    .map(|generation| generation == &record.linked_graph_generation)
                    .unwrap_or(false);
                RankedDecision {
                    record,
                    exact_repository_scope,
                    active,
                    linked_generation,
                }
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            let left_exact = left.exact_repository_scope && left.active;
            let right_exact = right.exact_repository_scope && right.active;
            right_exact
                .cmp(&left_exact)
                .then_with(|| right.linked_generation.cmp(&left.linked_generation))
                .then_with(|| right.active.cmp(&left.active))
                .then_with(|| {
                    right
                        .exact_repository_scope
                        .cmp(&left.exact_repository_scope)
                })
                .then_with(|| right.record.created_at.cmp(&left.record.created_at))
                .then_with(|| left.record.id.cmp(&right.record.id))
                .then_with(|| left.record.source_hash.cmp(&right.record.source_hash))
        });
        Ok(ranked.into_iter().map(|item| item.record).collect())
    }

    pub fn query_active(
        &self,
        query: &DecisionQuery,
    ) -> Result<Vec<DecisionRecord>, DecisionError> {
        Ok(self
            .query(query)?
            .into_iter()
            .filter(|record| record.current_status.is_active())
            .collect())
    }

    pub fn matching(&self, query: &DecisionQuery) -> Result<Vec<DecisionRecord>, DecisionError> {
        Ok(self
            .query(query)?
            .into_iter()
            .filter(|record| {
                record.repository_id == query.repository_id && record.scope_id == query.scope_id
            })
            .collect())
    }
}
