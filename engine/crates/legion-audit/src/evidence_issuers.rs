//! Host-owned issuer enrollment and Ed25519 provenance verification for
//! imported artifact evidence.
//!
//! `<LEGION state root>/audit-evidence-issuers.json` (0600, owner-only parent,
//! outside every audited root, same hardening as `host_owner`) binds an issuer
//! id to an Ed25519 public key and the repositories, workflows and subjects it
//! may attest. Repository files, requests and the environment can never enroll
//! an issuer. The attestation blob is the lowercase-hex Ed25519 signature over
//! [`evidence_attestation_message`] of the envelope's canonical claims digest.
//!
//! File: `{"schemaVersion":1,"issuers":[{"issuerId","publicKey":"<hex32>",
//! "allowedRepositories":[..],"allowedWorkflows":[..],"allowedSubjects":[..],
//! "notAfter":"<utc second>" (optional)}]}`. An empty allow list permits nothing.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::artifact_evidence::{
    ArtifactEvidenceEnvelope, ProvenanceVerifier, TrustEnrollment, TrustedIssuer, VerifiedIssuer,
    ARTIFACT_EVIDENCE_SCHEMA_VERSION,
};

pub const ISSUERS_FILE: &str = "audit-evidence-issuers.json";
pub const VERIFIER_ID: &str = "host-ed25519-evidence-issuers/1";
pub const TRUST_ROOT_ID: &str = "host-evidence-issuers";
pub const ATTESTATION_FORMAT: &str = "host-ci-provenance";

/// Domain-separated message an issuer signs.
pub fn evidence_attestation_message(claims_digest: &str) -> Vec<u8> {
    format!("legion-audit-evidence-attestation/1\n{claims_digest}").into_bytes()
}

/// Shared strict Ed25519 verification over lowercase-hex key and signature.
pub fn verify_ed25519_hex(
    public_key_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> Result<(), &'static str> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let public: [u8; 32] = decode_hex(public_key_hex).ok_or("key-malformed")?;
    let signature: [u8; 64] = decode_hex(signature_hex).ok_or("signature-malformed")?;
    let key = VerifyingKey::from_bytes(&public).map_err(|_| "key-malformed")?;
    key.verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| "signature-invalid")
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}

/// `sha256` of the raw public key bytes, lowercase hex: the enrolled key id.
pub fn key_id_for(public_key_hex: &str) -> Option<String> {
    let public: [u8; 32] = decode_hex(public_key_hex)?;
    Some(hex::encode(Sha256::digest(public)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IssuersFile {
    schema_version: u32,
    issuers: Vec<IssuerEntry>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IssuerEntry {
    issuer_id: String,
    public_key: String,
    #[serde(default)]
    allowed_repositories: Vec<String>,
    #[serde(default)]
    allowed_workflows: Vec<String>,
    #[serde(default)]
    allowed_subjects: Vec<String>,
    #[serde(default)]
    not_after: Option<String>,
}

/// `<LEGION state root>/audit-evidence-issuers.json` (same resolution as
/// `host_owner::default_policy_path`).
pub fn default_issuers_path() -> Option<PathBuf> {
    crate::host_owner::default_policy_path().map(|p| p.with_file_name(ISSUERS_FILE))
}

/// Host-state file enrolling qualification attestor keys (same state root and
/// hardening as the evidence issuers file).
pub const QUALIFICATION_ATTESTORS_FILE: &str = "audit-qualification-attestors.json";

/// `<LEGION state root>/audit-qualification-attestors.json`.
pub fn default_qualification_attestors_path() -> Option<PathBuf> {
    crate::host_owner::default_policy_path().map(|p| p.with_file_name(QUALIFICATION_ATTESTORS_FILE))
}

/// Read a host-state enrollment file with the issuer-file hardening: canonical
/// non-symlink path, outside every audited root, owner-only 0600 regular file
/// in a non-group/world-writable owner-controlled directory. `Ok(None)`: no
/// file. `Err`: present but untrustworthy (including repository-located).
pub fn read_host_enrollment(
    path: &Path,
    audited_roots: &[PathBuf],
) -> Result<Option<Vec<u8>>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
        Ok(_) => {}
    }
    let roots = audited_roots
        .iter()
        .map(|r| std::fs::canonicalize(r).map_err(|e| format!("{}: {e}", r.display())))
        .collect::<Result<Vec<_>, _>>()?;
    read_trusted(path, &roots).map(Some)
}

/// Host-enrolled Ed25519 verifier. Holds the in-run replay seen-set.
pub struct HostEvidenceVerifier {
    issuers: BTreeMap<String, IssuerEntry>,
    seen: Mutex<BTreeSet<String>>,
}

impl HostEvidenceVerifier {
    /// `Ok(None)`: no file (unchanged: imports stay unmet). `Err`: file exists
    /// but is untrustworthy or malformed (callers treat as no enrollment and
    /// report the reason). Returns the verifier and the matching trust set.
    pub fn load(
        path: &Path,
        audited_roots: &[PathBuf],
    ) -> Result<Option<(Self, TrustEnrollment)>, String> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
            Ok(_) => {}
        }
        let roots = audited_roots
            .iter()
            .map(|r| std::fs::canonicalize(r).map_err(|e| format!("{}: {e}", r.display())))
            .collect::<Result<Vec<_>, _>>()?;
        let bytes = read_trusted(path, &roots)?;
        Self::from_bytes(&bytes).map(Some)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, TrustEnrollment), String> {
        let file: IssuersFile =
            serde_json::from_slice(bytes).map_err(|e| format!("issuer enrollment: {e}"))?;
        if file.schema_version != ARTIFACT_EVIDENCE_SCHEMA_VERSION || file.issuers.is_empty() {
            return Err("issuer enrollment: unsupported schema or no issuers".into());
        }
        let mut issuers = BTreeMap::new();
        let mut trusted = Vec::new();
        for entry in file.issuers {
            let key_id = key_id_for(&entry.public_key)
                .ok_or_else(|| "issuer enrollment: malformed publicKey".to_string())?;
            if entry.issuer_id.trim().is_empty()
                || issuers
                    .insert(entry.issuer_id.clone(), entry.clone())
                    .is_some()
            {
                return Err("issuer enrollment: empty or duplicate issuerId".into());
            }
            trusted.push(TrustedIssuer {
                issuer_id: entry.issuer_id,
                trust_root_id: TRUST_ROOT_ID.into(),
                key_id,
                attestation_format: ATTESTATION_FORMAT.into(),
                verifier_id: VERIFIER_ID.into(),
            });
        }
        let trust = TrustEnrollment {
            schema_version: ARTIFACT_EVIDENCE_SCHEMA_VERSION,
            issuers: trusted,
        };
        trust.validate().map_err(|e| e.to_string())?;
        Ok((
            Self {
                issuers,
                seen: Mutex::new(BTreeSet::new()),
            },
            trust,
        ))
    }
}

impl ProvenanceVerifier for HostEvidenceVerifier {
    fn verifier_id(&self) -> &str {
        VERIFIER_ID
    }

    fn verify(
        &self,
        envelope: &ArtifactEvidenceEnvelope,
        claims_digest: &str,
        attestation: &[u8],
    ) -> Result<VerifiedIssuer, String> {
        let issuer = self
            .issuers
            .get(&envelope.issuer.issuer_id)
            .ok_or("issuer-not-enrolled")?;
        let key_id = key_id_for(&issuer.public_key).ok_or("key-malformed")?;
        if key_id != envelope.issuer.key_id {
            return Err("issuer-key-mismatch".into());
        }
        if let Some(not_after) = &issuer.not_after {
            if envelope.issued_at.as_str() > not_after.as_str() {
                return Err("issuer-key-expired-for-issue-time".into());
            }
        }
        // Authorization scope: every claimed repository, the workflow adapter
        // and the target must be explicitly allowed for this issuer.
        if envelope.subject.repositories.is_empty()
            || envelope
                .subject
                .repositories
                .iter()
                .any(|r| !issuer.allowed_repositories.contains(&r.repository_id))
        {
            return Err("repository-not-allowed-for-issuer".into());
        }
        if !issuer
            .allowed_workflows
            .contains(&envelope.subject.command.adapter_id)
        {
            return Err("workflow-not-allowed-for-issuer".into());
        }
        if !issuer.allowed_subjects.contains(&envelope.subject.target) {
            return Err("subject-not-allowed-for-issuer".into());
        }
        let signature = std::str::from_utf8(attestation)
            .map_err(|_| "attestation-malformed".to_string())?
            .trim();
        verify_ed25519_hex(
            &issuer.public_key,
            signature,
            &evidence_attestation_message(claims_digest),
        )
        .map_err(|e| e.to_string())?;
        // Replay seen-set: only evidence that authenticated is remembered.
        let mut seen = self.seen.lock().map_err(|_| "replay-set-poisoned")?;
        if seen.contains(&format!("id:{}", envelope.evidence_id))
            || seen.contains(&format!("claims:{claims_digest}"))
        {
            return Err("replayed-evidence".into());
        }
        seen.insert(format!("id:{}", envelope.evidence_id));
        seen.insert(format!("claims:{claims_digest}"));
        Ok(VerifiedIssuer {
            issuer_id: envelope.issuer.issuer_id.clone(),
            key_id,
            claims_digest: claims_digest.to_string(),
        })
    }
}

#[cfg(unix)]
fn read_trusted(path: &Path, audited: &[PathBuf]) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let uid = legion_effects::sandbox_runtime::effective_uid();
    let canonical = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
    if canonical != path {
        return Err("issuer enrollment path must be canonical (no symlinks)".into());
    }
    if audited.iter().any(|root| canonical.starts_with(root)) {
        return Err("issuer enrollment lies inside an audited root".into());
    }
    let parent = canonical
        .parent()
        .ok_or("issuer enrollment has no parent")?;
    let parent_meta = std::fs::metadata(parent).map_err(|e| e.to_string())?;
    if parent_meta.mode() & 0o022 != 0 || (parent_meta.uid() != uid && parent_meta.uid() != 0) {
        return Err(
            "enrollment directory must not be group/world writable or foreign-owned".into(),
        );
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(legion_effects::sandbox_runtime::o_nofollow())
        .open(&canonical)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(
            "issuer enrollment must be a regular file owned by this user with mode 0600".into(),
        );
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&mut file, 1 << 20), &mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_trusted(_path: &Path, _audited: &[PathBuf]) -> Result<Vec<u8>, String> {
    Err("issuer enrollment permissions cannot be verified on this platform".into())
}
