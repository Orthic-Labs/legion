use crate::precedence::EvaluationStage;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceEntry {
    pub stage: EvaluationStage,
    pub code: String,
    pub rule_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Explanation {
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_digest: String,
    pub matched_rule_ids: Vec<String>,
    pub rejected_alternatives: Vec<String>,
    pub trace: Vec<TraceEntry>,
    pub reason_code: String,
}

impl Explanation {
    pub(crate) fn new(policy_id: String, policy_version: u32, policy_digest: String) -> Self {
        Self {
            policy_id,
            policy_version,
            policy_digest,
            matched_rule_ids: Vec::new(),
            rejected_alternatives: Vec::new(),
            trace: Vec::new(),
            reason_code: "evaluator_error".into(),
        }
    }

    pub(crate) fn record(&mut self, stage: EvaluationStage, code: &str, rule_ids: Vec<String>) {
        self.trace.push(TraceEntry {
            stage,
            code: code.into(),
            rule_ids,
        });
    }
}
