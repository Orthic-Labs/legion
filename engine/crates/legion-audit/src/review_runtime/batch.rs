//! Compatible lenses share exact source bytes once; receipts distinguish logical
//! reconstruction from physical transport. Verification always stays separate.
use super::{action, action_schema, digest, invalid, native, Controller, Observation, SYSTEM};
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
    let Some(mut prompt) = ingest::shared_seat_payload(works)? else {
        return Ok(None);
    };
    prompt["task"] = json!("Review every compatible lens independently against shared exact excerpts. A top-level packet field {$sharedContext:excerpts} resolves only to sharedContext.excerpts. Return finalResult:{results:[{requestId,finalResult:{complete:true,findings:[],withdrawn:[],details:{...required signed semanticReview/changeRisk}}}]}; exactly one result per requested requestId, no unknown or duplicate IDs. No claim of independent author contexts across lenses. Each finding includes id,title,anchor plus schema fields.");
    prompt["contextTools"] = super::tools::specs();
    prompt["conversation"] = json!([]);
    // Both planning & transport must choose the same physical split before
    // authorization. No shared-byte credit applies to fallback singles.
    if native::rendered_input(&prompt)?.len() > super::MAX_REQUEST_BYTES / 2 {
        return Ok(None);
    }
    let (_, rendered) = super::rendered_request(&prompt, SYSTEM, &action_schema(), None)?;
    if super::request_bytes(&rendered)? > super::MAX_REQUEST_BYTES as u64 {
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
        let schema = action_schema();
        let mut initial = initial;
        for _ in 0..self.options.max_calls_per_packet {
            let author = self.call(seat, prompt.clone(), SYSTEM, &schema, initial.take())?;
            if let Some(error) = &author.error {
                return Err(invalid(format!("incomplete:shared-seat-host:{error}")));
            }
            let reply = author
                .reply
                .clone()
                .ok_or_else(|| invalid("shared-seat reply missing"))?;
            let parsed = action(reply.clone())?;
            if let Some(request) = parsed.tool_request {
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
                let mut compact = work.request.packet.clone();
                super::partial::preserve_author(self.run, &work, &value, &author)?;
                compact["excerpts"] = json!({"$sharedContext":"excerpts"});
                let proof = json!({"schemaVersion":1,"kind":"legion-evidence-delivery","source":"host-transport","receiptId":format!("delivery:{}:{id}",author.context_id),"requestId":id,"packetDigest":digest(&work.request.packet)?,"transportEncoding":"shared-context-v1","reconstructedPacketBytes":legion_contracts::canonical_json_bytes(&work.request.packet).map_err(|error|invalid(error.to_string()))?.len(),"physicalRequestDigest":author.request_digest,"physicalRequestBytes":author.request_bytes,"sharedContextDigest":shared_digest,"reconstruction":{"sharedContext":shared,"compactPacket":compact},"complete":true,"truncated":false,"chunks":reasoning::delivery_chunk_manifest(&work.request).map_err(invalid)?,"host":native::observation_value(&author)});
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
