use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    model::{HandoffPacket, Omission},
    source::EventCursor,
    token::TokenAccounting,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffReceipt {
    pub schema_version: u32,
    pub handoff_id: String,
    pub included_ids: Vec<String>,
    pub omissions: Vec<Omission>,
    pub cursor: Option<EventCursor>,
    pub source_provenance: Vec<String>,
    pub accounting: TokenAccounting,
    pub packet_digest: String,
}

impl HandoffReceipt {
    pub fn for_packet(packet: &HandoffPacket) -> Self {
        let mut included_ids = packet
            .sections
            .iter()
            .flat_map(|section| section.entries.iter().map(|entry| entry.id.clone()))
            .collect::<Vec<_>>();
        included_ids.sort();
        Self {
            schema_version: 1,
            handoff_id: packet.handoff_id.clone(),
            included_ids,
            omissions: packet.omissions.clone(),
            cursor: packet.cursor.clone(),
            source_provenance: packet.source_provenance.clone(),
            accounting: packet.accounting.clone(),
            packet_digest: packet.receipt_digest.clone(),
        }
    }

    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }
}
