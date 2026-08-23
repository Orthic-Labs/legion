use legion_contracts::{canonical_digest, canonical_json_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::DecisionError;

pub const SCHEMA_VERSION: u32 = 1;
pub const DECISION_ID_PREFIX: &str = "architect:decision";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionStatus {
    Proposed,
    Accepted,
    Implemented,
    Superseded,
}

impl DecisionStatus {
    pub fn is_active(self) -> bool {
        self != Self::Superseded
    }
    pub fn rank(self) -> u8 {
        match self {
            Self::Implemented => 3,
            Self::Accepted => 2,
            Self::Proposed => 1,
            Self::Superseded => 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionRecord {
    pub schema_version: u32,
    pub id: String,
    pub repository_id: String,
    pub scope_id: String,
    pub task_id: String,
    #[serde(default)]
    pub linked_graph_generation: String,
    pub rationale: String,
    #[serde(default)]
    pub alternatives: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub implementation_refs: Vec<String>,
    #[serde(default)]
    pub supersedes: Vec<String>,
    #[serde(default)]
    pub superseded_by: Option<String>,
    pub current_status: DecisionStatus,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub source_hash: String,
    #[serde(default)]
    pub source_path: Option<String>,
    #[serde(default)]
    pub provenance: BTreeMap<String, String>,
}

impl DecisionRecord {
    pub fn validate(&self) -> Result<(), DecisionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DecisionError::UnsupportedVersion(self.schema_version));
        }
        for (path, value) in [
            ("id", &self.id),
            ("repositoryId", &self.repository_id),
            ("scopeId", &self.scope_id),
            ("taskId", &self.task_id),
            ("rationale", &self.rationale),
        ] {
            if value.trim().is_empty() {
                return Err(DecisionError::invalid(path, "must be non-empty"));
            }
            if value.chars().any(char::is_control) {
                return Err(DecisionError::invalid(
                    path,
                    "must not contain control characters",
                ));
            }
        }
        if self.current_status == DecisionStatus::Implemented && self.implementation_refs.is_empty()
        {
            // The legacy provider emits a warning for this state rather than dropping it.
        }
        Ok(())
    }

    pub fn new(
        repository_id: impl Into<String>,
        scope_id: impl Into<String>,
        task_id: impl Into<String>,
        rationale: impl Into<String>,
        status: DecisionStatus,
    ) -> Self {
        let repository_id = repository_id.into();
        let task_id = task_id.into();
        let rationale = rationale.into();
        let id = derive_decision_id(&repository_id, &task_id, "", &rationale);
        Self {
            schema_version: SCHEMA_VERSION,
            id,
            repository_id,
            scope_id: scope_id.into(),
            task_id,
            linked_graph_generation: String::new(),
            rationale,
            alternatives: Vec::new(),
            evidence: Vec::new(),
            implementation_refs: Vec::new(),
            supersedes: Vec::new(),
            superseded_by: None,
            current_status: status,
            created_at: String::new(),
            source_hash: String::new(),
            source_path: None,
            provenance: BTreeMap::new(),
        }
    }

    pub fn with_source_hash(mut self) -> Result<Self, DecisionError> {
        self.source_hash = self.compute_source_hash()?;
        Ok(self)
    }

    pub fn compute_source_hash(&self) -> Result<String, DecisionError> {
        // Match the legacy provider's stable projection: timestamps and
        // machine-local provenance are metadata, never decision identity.
        let value = serde_json::json!({
            "id": self.id,
            "repositoryId": self.repository_id,
            "scopeId": self.scope_id,
            "taskId": self.task_id,
            "linkedGraphGeneration": self.linked_graph_generation,
            "rationale": self.rationale,
            "alternatives": self.alternatives,
            "evidence": self.evidence,
            "implementationRefs": self.implementation_refs,
            "supersedes": self.supersedes,
            "supersededBy": self.superseded_by,
            "currentStatus": self.current_status,
        });
        Ok(canonical_digest(&value)?)
    }

    pub fn ensure_source_hash(&mut self) -> Result<(), DecisionError> {
        if self.source_hash.trim().is_empty() {
            self.source_hash = self.compute_source_hash()?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DecisionError> {
        Ok(canonical_json_bytes(self)?)
    }
}

pub fn derive_decision_id(
    repository_id: &str,
    task_id: &str,
    linked_graph_generation: &str,
    rationale: &str,
) -> String {
    let canonical = [repository_id, task_id, linked_graph_generation, rationale]
        .iter()
        .map(|value| value.trim().to_lowercase())
        .collect::<Vec<_>>()
        .join("|");
    let digest = sha256_hex(canonical.as_bytes());
    format!("{}:{}", DECISION_ID_PREFIX, &digest[..24])
}

// Kept local so this compatibility crate does not add a second crypto
// dependency: LEG-010 already defines SHA-256 as the canonical digest.
fn sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut data = input.to_vec();
    let bit_len = (data.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionQuery {
    pub repository_id: String,
    pub scope_id: String,
    pub linked_graph_generation: Option<String>,
}

impl DecisionQuery {
    pub fn new(repository_id: impl Into<String>, scope_id: impl Into<String>) -> Self {
        Self {
            repository_id: repository_id.into(),
            scope_id: scope_id.into(),
            linked_graph_generation: None,
        }
    }
    pub fn generation(mut self, value: impl Into<String>) -> Self {
        self.linked_graph_generation = Some(value.into());
        self
    }
}
