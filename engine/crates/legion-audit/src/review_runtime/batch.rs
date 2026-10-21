//! Compatible lenses share exact source bytes once; receipts distinguish logical
//! reconstruction from physical transport. Verification always stays separate.
use super::{action, action_schema, digest, invalid, native, Controller, Observation};
use crate::{
    error::AuditError,
    native_providers::reasoning::{self, ingest, PendingLensWork},
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct BatchReview {
    pub items: Vec<(PendingLensWork, Value)>,
    pub author: Observation,
    pub gaps: Vec<String>,
}
pub(super) fn compatible(works: &[PendingLensWork]) -> bool {
    initial_prompt(works).is_ok_and(|prompt| prompt.is_some())
}
pub(super) fn initial_prompt(works: &[PendingLensWork]) -> Result<Option<Value>, AuditError> {
    initial_prompt_with_sizer(works, &mut super::InitialRequestSizer::default())
}
pub(super) fn initial_prompt_with_sizer(
    works: &[PendingLensWork],
    sizer: &mut super::InitialRequestSizer,
) -> Result<Option<Value>, AuditError> {
    let mut projected = works.to_vec();
    for work in &mut projected {
        work.request.packet = super::projection::packet(&work.request)?.0;
    }
    let Some(mut prompt) = ingest::shared_seat_payload(&projected)? else {
        return Ok(None);
    };
    for (row, work) in prompt["lenses"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(works)
    {
        row["packetDigest"] = json!(digest(&work.request.packet)?);
        row["logicalReference"] =
            super::projection::invocation(&work.request)?["logicalReference"].clone();
    }
    prompt["task"] = json!("Review every compatible lens independently against shared exact excerpts. A top-level packet field {$sharedContext:fieldName} resolves only to sharedContext[fieldName]. logicalReference binds omitted run accounting & illustrative examples in the frozen invocation artifact; referenced material is not model-delivered, reviewed source or evidence of exhaustive coverage. Missing graph relationships remain unknown. Return finalResult:{results:[{requestId,finalResult:{complete:true,findings:[],withdrawn:[],details:{...required signed semanticReview/changeRisk}}}]}; exactly one result per requested requestId, no unknown or duplicate IDs. No claim of independent author contexts across lenses. Each finding includes id,title,anchor plus schema fields.");
    prompt["contextTools"] = super::tools::specs();
    prompt["conversation"] = json!([]);
    let mut common = works[0].request.clone();
    common.denominator_paths.retain(|path| {
        works
            .iter()
            .all(|work| work.request.denominator_paths.contains(path))
    });
    sizer.attach_context(&mut prompt, &common)?;
    // Both planning & transport must choose the same physical split before
    // authorization. No shared-byte credit applies to fallback singles.
    if native::rendered_input(&prompt)?.len() > super::MAX_REQUEST_BYTES / 2 {
        return Ok(None);
    }
    if super::planning_author_sizes(&prompt, works)?.host_envelope_bytes
        > super::MAX_REQUEST_BYTES as u64
    {
        return Ok(None);
    }
    Ok(Some(prompt))
}
impl Controller<'_> {
    pub(super) fn review_batch(
        &mut self,
        seat: &Value,
        works: &[PendingLensWork],
        initial: Option<String>,
    ) -> Result<BatchReview, AuditError> {
        let mut prompt = initial_prompt(works)?
            .ok_or_else(|| AuditError::BoundExceeded("shared-seat-split-required".into()))?;
        let shared = prompt["sharedContext"].clone();
        let shared_digest = prompt["sharedContextDigest"].clone();
        let mut logical = BTreeMap::new();
        for work in works {
            if logical
                .insert(work.request.request_id.clone(), work.clone())
                .is_some()
            {
                return Err(invalid("duplicate request IDs in shared seat"));
            }
        }
        let single_call = self.options.strict_no_retry || self.options.max_calls_per_packet <= 1;
        let schema = if single_call {
            super::final_only_action_schema()
        } else {
            action_schema()
        };
        if single_call {
            // One physical call: no host context request can be answered.
            prompt["contextTools"] = json!([]);
            prompt["singleCall"] = json!("This packet allows exactly one response: no toolRequest is available; review the supplied shared excerpts and emit finalResult.");
            let requests = works.iter().map(|work| &work.request).collect::<Vec<_>>();
            if let Some(note) = super::full_coverage_note(&requests) {
                prompt["coverage"] = json!(note);
            }
        }
        let mut initial = initial;
        let execution = super::model::author(
            works.iter().map(|work| work.provider_id.as_str()),
            self.options,
        )?;
        if seat["gatherPolicy"] != "deterministic"
            && works
                .iter()
                .any(|work| work.provider_id != "reasoning.dead-file")
        {
            let requests = works.iter().map(|work| &work.request).collect::<Vec<_>>();
            self.gather_for_author(
                seat,
                &requests,
                &mut prompt,
                &schema,
                &execution,
                initial.take(),
            )?;
        }
        for _ in 0..self.options.max_calls_per_packet {
            let author = self.call(
                seat,
                prompt.clone(),
                super::author_system(&execution),
                &schema,
                initial.take(),
                &execution,
            )?;
            if let Some(error) = &author.error {
                return Err(invalid(format!("incomplete:shared-seat-host:{error}")));
            }
            let reply = author
                .reply
                .clone()
                .ok_or_else(|| invalid("shared-seat reply missing"))?;
            let parsed = action(reply.clone())?;
            if let Some(request) = parsed.tool_request {
                super::require_context_continuation(self.options)?;
                let response = self.tools.call(request);
                prompt["conversation"]
                    .as_array_mut()
                    .ok_or_else(|| invalid("shared conversation missing"))?
                    .push(json!({"modelAction":reply,"hostToolReply":response}));
                continue;
            }
            let result = parsed
                .final_result
                .ok_or_else(|| invalid("shared-seat final result missing"))?;
            let returned = result["results"]
                .as_array()
                .ok_or_else(|| invalid("shared-seat final must partition results by requestId"))?;
            super::persist(
                &self.run.join("runtime-shared-results"),
                &format!(
                    "{}.json",
                    super::digest_bytes(author.context_id.as_bytes()).trim_start_matches("sha256:")
                ),
                &result,
            )?;
            let mut partitions = BTreeMap::new();
            let mut duplicates = BTreeSet::new();
            let mut gaps = Vec::new();
            for row in returned {
                let Some(id) = row["requestId"].as_str() else {
                    gaps.push("shared-result-request-id-missing".into());
                    continue;
                };
                if !logical.contains_key(id) {
                    gaps.push(format!("shared-result-unknown:{id}"));
                    continue;
                }
                let Some(value) = row.get("finalResult").filter(|value| value.is_object()) else {
                    gaps.push(format!("shared-result-malformed:{id}"));
                    continue;
                };
                if partitions.insert(id.to_owned(), value.clone()).is_some() {
                    duplicates.insert(id.to_owned());
                    gaps.push(format!("shared-result-duplicate:{id}"));
                }
            }
            let mut items = Vec::new();
            for (id, work) in logical {
                if duplicates.contains(&id) {
                    continue;
                }
                let Some(value) = partitions.remove(&id) else {
                    gaps.push(format!("shared-result-missing:{id}"));
                    continue;
                };
                let projected = super::projection::packet(&work.request)?.0;
                let compact = ingest::compact_shared_packet(&projected, &shared)?;
                super::partial::preserve_author(self.run, &work, &value, &author)?;
                let proof = json!({"schemaVersion":1,"kind":"legion-evidence-delivery","source":"host-transport","receiptId":format!("delivery:{}:{id}",author.context_id),"requestId":id,"packetDigest":digest(&work.request.packet)?,"transportEncoding":"shared-audit-packet-reference-v1","projection":super::projection::evidence(&work.request)?,"reconstructedPacketBytes":legion_contracts::canonical_json_bytes(&projected).map_err(|error|invalid(error.to_string()))?.len(),"physicalRequestDigest":author.request_digest,"physicalRequestBytes":author.request_bytes,"sharedContextDigest":shared_digest,"reconstruction":{"sharedContext":shared,"compactPacket":compact},"complete":true,"truncated":false,"chunks":reasoning::delivery_chunk_manifest(&work.request).map_err(invalid)?,"host":native::observation_value(&author)});
                ingest::mint_runtime_delivery(self.run, &work.request, &proof)?;
                items.push((work, value));
            }
            return Ok(BatchReview {
                items,
                author,
                gaps,
            });
        }
        Err(AuditError::BoundExceeded(
            "incomplete:shared-context-call-limit".into(),
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_refs_are_exact_top_level_fields() {
        let original =
            json!({"excerpts":[{"path":"a","content":"one"}],"lensPlan":{"lens":"correctness"}});
        let shared = json!({"excerpts":original["excerpts"]});
        let mut compact = original.clone();
        compact["excerpts"] = json!({"$sharedContext":"excerpts"});
        compact["excerpts"] = shared["excerpts"].clone();
        assert_eq!(compact, original);
    }
}
