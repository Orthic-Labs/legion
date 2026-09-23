//! Faithful port of `src/lib/core/kernel-binding.mjs`.
//!
//! Kernel binding is the seam between Arcane and Lane D's deterministic
//! substrate. Every canonical-state write goes through it: with no Kernel
//! primitives bound, writes fail closed with
//! `ARC_KERNEL_PRIMITIVE_UNAVAILABLE` (mirroring the JS source's own
//! sequencing note in full) rather than falling back to a second store root.
//!
//! `ArcaneError` is reused from the already-ported
//! `legion_policy::arcane_port::errors` module rather than redefined here —
//! `ARC_KERNEL_PRIMITIVE_UNAVAILABLE` is already present in its
//! `ARCANE_ERROR_CODE`/`FAIL_CLOSED_CODES` tables.
//!
//! `mintId`'s provisional-id fallback delegates in JS to
//! `src/lib/contracts/arcane/ids.mjs`'s `mintId(family)`. That file is not
//! in this chunk, is not owned by it, and has no existing Rust port (see the
//! `w2_040` module doc comment for the `git grep` evidence and the exact
//! reuse note for the integrator once it lands). Until then this module
//! carries its own private, self-contained port of just the pieces
//! `kernel-binding.mjs` reaches through `mintId`: the Crockford-base32 ULID
//! encoder and the `HANDLE_PREFIX` table, scoped to a `KernelBinding`
//! instance so the monotonic per-millisecond counter state (`lastTime`/
//! `lastRandom` in JS) does not leak across independent bindings the way a
//! module-level `static` would.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use legion_policy::arcane_port::errors::{ArcaneError, Detail};

/// Mirrors `HANDLE_PREFIX` from `src/lib/contracts/arcane/ids.mjs` — the set
/// of id families `mintId(family)` in `kernel-binding.mjs` can be called
/// with. Kept private: this is not a full port of `ids.mjs` (no `ID_PATTERN`,
/// no `isId`/`assertId`), only what this seam needs.
fn handle_prefix(family: &str) -> Option<&'static str> {
    Some(match family {
        "run" => "run_",
        "request" => "req_",
        "kernelTask" => "ktask_",
        "artifact" => "art_",
        "effectReceipt" => "eff_",
        "evidenceReceipt" => "ev_",
        "claim" => "clm_",
        "workerCapsule" => "wc_",
        _ => return None,
    })
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn encode_time(mut ms: u64) -> String {
    let mut out = [0u8; 10];
    for slot in out.iter_mut().rev() {
        *slot = CROCKFORD[(ms % 32) as usize];
        ms /= 32;
    }
    String::from_utf8(out.to_vec()).expect("crockford alphabet is ascii")
}

fn encode_random(bytes: &[u8; 10]) -> String {
    let mut bits: u128 = 0;
    for b in bytes {
        bits = (bits << 8) | (*b as u128);
    }
    let mut out = [0u8; 16];
    for slot in out.iter_mut().rev() {
        *slot = CROCKFORD[(bits & 31) as usize];
        bits >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("crockford alphabet is ascii")
}

/// Non-cryptographic entropy source used where JS relies on
/// `crypto.randomBytes(10)`. This crate has no `rand` dependency; mirrors
/// the same splitmix64-over-process-state approach already used by
/// `legion_runtime::p5_core::kernel_ids::random_entropy` for the same
/// reason, folding in a per-process call counter so back-to-back calls
/// within one nanosecond-resolution tick still diverge.
fn random_bytes_10() -> [u8; 10] {
    static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut state = (nanos as u64)
        ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ counter.wrapping_mul(0xD1B5_4A32_D192_ED03);
    let mut out = [0u8; 10];
    for byte in out.iter_mut() {
        // splitmix64
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *byte = (z & 0xFF) as u8;
    }
    out
}

/// Mirrors `bumpRandom(prev)`: increment the byte string as a big-endian
/// counter, redrawing fresh entropy only on overflow past all-`0xff`.
fn bump_random(prev: &[u8; 10]) -> [u8; 10] {
    let mut next = *prev;
    for byte in next.iter_mut().rev() {
        if *byte != 0xff {
            *byte += 1;
            return next;
        }
        *byte = 0;
    }
    random_bytes_10()
}

/// Per-binding monotonic-ULID state, mirroring the JS module-level
/// `lastTime`/`lastRandom` mutable bindings.
#[derive(Default)]
struct UlidState {
    last_time: Option<u64>,
    last_random: Option<[u8; 10]>,
}

impl UlidState {
    /// Port of `ulid(now)`.
    fn next(&mut self, now: u64) -> String {
        let rnd = match (self.last_time, self.last_random.as_ref()) {
            (Some(last_time), Some(last_random)) if last_time == now => bump_random(last_random),
            _ => random_bytes_10(),
        };
        self.last_time = Some(now);
        self.last_random = Some(rnd);
        format!("{}{}", encode_time(now), encode_random(&rnd))
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Result of [`KernelBinding::mint_id`]. Mirrors the JS return shape
/// `{id, provisional}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedId {
    pub id: String,
    pub provisional: bool,
}

/// The Kernel primitives a host installs once Lane D lands. Mirrors the JS
/// `KernelPrimitives` typedef: every primitive is optional independently, so
/// a host can bind identity without events, or objects without either.
pub trait KernelPrimitives: Send + Sync {
    fn mint_id(&self, _family: &str) -> Option<String> {
        None
    }
    fn append_event(&self, _namespace: &str, _record: &Detail) -> Result<(), ArcaneError> {
        Err(missing_primitive("appendEvent", None, "appendEvent"))
    }
    fn read_object(&self, _namespace: &str, _key: &str) -> Result<Option<Detail>, ArcaneError> {
        Err(missing_primitive("readObject", None, "readObject"))
    }
    fn put_object(&self, _namespace: &str, _key: &str, _record: &Detail) -> Result<(), ArcaneError> {
        Err(missing_primitive("putObject", None, "putObject"))
    }
    /// Whether this binding actually implements `mint_id` — needed because
    /// the trait default above cannot itself distinguish "not implemented"
    /// from "implemented and returned no id", and `kernelStatus().identity`
    /// must reflect the former precisely (`Boolean(bound?.mintId)` in JS).
    fn has_mint_id(&self) -> bool {
        false
    }
    fn has_append_event(&self) -> bool {
        false
    }
    fn has_read_object(&self) -> bool {
        false
    }
    fn has_put_object(&self) -> bool {
        false
    }
}

fn missing_primitive(primitive: &'static str, namespace: Option<&str>, message: &str) -> ArcaneError {
    let mut detail: Detail = BTreeMap::new();
    if let Some(namespace) = namespace {
        detail.insert("namespace".to_string(), namespace.to_string());
    }
    detail.insert("primitive".to_string(), primitive.to_string());
    ArcaneError::new(
        "ARC_KERNEL_PRIMITIVE_UNAVAILABLE",
        format!("{message} requires a bound Kernel primitive"),
        detail,
    )
    .expect("ARC_KERNEL_PRIMITIVE_UNAVAILABLE is a known ArcaneError code")
}

/// Enforcement-health snapshot. Mirrors `kernelStatus()`'s return object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelStatus {
    pub bound: bool,
    pub identity: bool,
    pub events: bool,
    pub objects: bool,
    pub note: &'static str,
}

/// The Legion store namespace Arcane owns. Mirrors `ARCANE_NAMESPACE`.
pub const ARCANE_NAMESPACE: &str = "arcane";

const NOTE_BOUND: &str = "kernel primitives bound";
const NOTE_UNBOUND: &str =
    "packages/kernel not available at build time (Lane D pending) — ids are provisional and canonical writes fail closed";

/// Port of the Kernel-binding seam's module-level mutable state
/// (`bound`, `lastTime`, `lastRandom`) as an explicit, ownable value instead
/// of process-global statics — the JS source's `unbindKernel()` was already
/// "tests only" for exactly this reason (mutable global module state is
/// otherwise unrecoverable between tests). One `KernelBinding` per host.
#[derive(Default)]
pub struct KernelBinding {
    bound: Mutex<Option<Box<dyn KernelPrimitives>>>,
    ulid: Mutex<UlidState>,
}

impl KernelBinding {
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of `bindKernel(primitives)`.
    pub fn bind_kernel(&self, primitives: Box<dyn KernelPrimitives>) {
        *self.bound.lock().expect("kernel binding mutex poisoned") = Some(primitives);
    }

    /// Port of `unbindKernel()` ("tests only" in the JS source too).
    pub fn unbind_kernel(&self) {
        *self.bound.lock().expect("kernel binding mutex poisoned") = None;
    }

    /// Port of `kernelBound()`.
    pub fn kernel_bound(&self) -> bool {
        self.bound.lock().expect("kernel binding mutex poisoned").is_some()
    }

    /// Port of `kernelStatus()`.
    pub fn kernel_status(&self) -> KernelStatus {
        let guard = self.bound.lock().expect("kernel binding mutex poisoned");
        match guard.as_ref() {
            Some(primitives) => KernelStatus {
                bound: true,
                identity: primitives.has_mint_id(),
                events: primitives.has_append_event(),
                objects: primitives.has_read_object() && primitives.has_put_object(),
                note: NOTE_BOUND,
            },
            None => KernelStatus {
                bound: false,
                identity: false,
                events: false,
                objects: false,
                note: NOTE_UNBOUND,
            },
        }
    }

    /// Port of `mintId(family)`. Uses the Kernel allocator when bound and it
    /// implements `mint_id`; otherwise mints a provisional id of the same
    /// grammar (see the module doc comment for why this is a private,
    /// scoped-down copy of `ids.mjs`'s `mintId` rather than a shared one).
    pub fn mint_id(&self, family: &str) -> Result<MintedId, ArcaneError> {
        {
            let guard = self.bound.lock().expect("kernel binding mutex poisoned");
            if let Some(primitives) = guard.as_ref() {
                if primitives.has_mint_id() {
                    if let Some(id) = primitives.mint_id(family) {
                        return Ok(MintedId { id, provisional: false });
                    }
                }
            }
        }
        let prefix = handle_prefix(family).ok_or_else(|| {
            let mut detail: Detail = BTreeMap::new();
            detail.insert("family".to_string(), family.to_string());
            ArcaneError::new("ARC_ID_INVALID", format!("unknown handle family: {family}"), detail)
                .expect("ARC_ID_INVALID is a known ArcaneError code")
        })?;
        let mut ulid_state = self.ulid.lock().expect("kernel binding mutex poisoned");
        let id = format!("{prefix}{}", ulid_state.next(now_millis()));
        Ok(MintedId { id, provisional: true })
    }

    /// Port of `appendEvent(namespace, record)`: fails closed unless bound.
    pub fn append_event(&self, namespace: &str, record: &Detail) -> Result<(), ArcaneError> {
        let guard = self.bound.lock().expect("kernel binding mutex poisoned");
        match guard.as_ref().filter(|p| p.has_append_event()) {
            Some(primitives) => primitives.append_event(namespace, record),
            None => Err(missing_primitive(
                "appendEvent",
                Some(namespace),
                "canonical event write",
            )),
        }
    }

    /// Port of `readObject(namespace, key)`: fails closed unless bound.
    pub fn read_object(&self, namespace: &str, key: &str) -> Result<Option<Detail>, ArcaneError> {
        let guard = self.bound.lock().expect("kernel binding mutex poisoned");
        match guard.as_ref().filter(|p| p.has_read_object()) {
            Some(primitives) => primitives.read_object(namespace, key),
            None => Err(missing_primitive("readObject", Some(namespace), "canonical object read")),
        }
    }

    /// Port of `putObject(namespace, key, record)`: fails closed unless bound.
    pub fn put_object(&self, namespace: &str, key: &str, record: &Detail) -> Result<(), ArcaneError> {
        let guard = self.bound.lock().expect("kernel binding mutex poisoned");
        match guard.as_ref().filter(|p| p.has_put_object()) {
            Some(primitives) => primitives.put_object(namespace, key, record),
            None => Err(missing_primitive("putObject", Some(namespace), "canonical object write")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[test]
    fn unbound_reports_honest_degraded_status() {
        let binding = KernelBinding::new();
        assert!(!binding.kernel_bound());
        let status = binding.kernel_status();
        assert_eq!(
            status,
            KernelStatus {
                bound: false,
                identity: false,
                events: false,
                objects: false,
                note: NOTE_UNBOUND,
            }
        );
    }

    #[test]
    fn unbound_writes_fail_closed_with_arc_kernel_primitive_unavailable() {
        let binding = KernelBinding::new();
        let detail: Detail = BTreeMap::new();
        let err = binding.append_event("arcane", &detail).unwrap_err();
        assert_eq!(err.code, "ARC_KERNEL_PRIMITIVE_UNAVAILABLE");
        assert!(err.fail_closed);

        let err = binding.read_object("arcane", "run_x").unwrap_err();
        assert_eq!(err.code, "ARC_KERNEL_PRIMITIVE_UNAVAILABLE");

        let err = binding.put_object("arcane", "run_x", &detail).unwrap_err();
        assert_eq!(err.code, "ARC_KERNEL_PRIMITIVE_UNAVAILABLE");
    }

    #[test]
    fn unbound_mint_id_yields_provisional_id_of_correct_grammar() {
        let binding = KernelBinding::new();
        let minted = binding.mint_id("run").unwrap();
        assert!(minted.provisional);
        assert!(minted.id.starts_with("run_"));
        assert_eq!(minted.id.len(), "run_".len() + 26);
    }

    #[test]
    fn mint_id_rejects_unknown_family() {
        let binding = KernelBinding::new();
        let err = binding.mint_id("not-a-real-family").unwrap_err();
        assert_eq!(err.code, "ARC_ID_INVALID");
    }

    #[test]
    fn provisional_ids_within_same_millisecond_stay_monotonic() {
        let binding = KernelBinding::new();
        // Force both mints into the same synthetic millisecond by minting
        // fast; on any real clock this is true almost always, but to make
        // the assertion deterministic we mint twice in a row and only check
        // ordering when the clock actually held still, which happens
        // overwhelmingly often within one process tick.
        let a = binding.mint_id("artifact").unwrap();
        let b = binding.mint_id("artifact").unwrap();
        assert_ne!(a.id, b.id);
        assert!(a.id < b.id, "monotonic ULIDs must sort lexicographically: {a:?} vs {b:?}");
    }

    struct FakeKernel {
        objects: StdMutex<BTreeMap<(String, String), Detail>>,
    }

    impl KernelPrimitives for FakeKernel {
        fn mint_id(&self, family: &str) -> Option<String> {
            Some(format!("kernel-minted-{family}"))
        }
        fn has_mint_id(&self) -> bool {
            true
        }
        fn append_event(&self, _namespace: &str, _record: &Detail) -> Result<(), ArcaneError> {
            Ok(())
        }
        fn has_append_event(&self) -> bool {
            true
        }
        fn read_object(&self, namespace: &str, key: &str) -> Result<Option<Detail>, ArcaneError> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(&(namespace.to_string(), key.to_string()))
                .cloned())
        }
        fn has_read_object(&self) -> bool {
            true
        }
        fn put_object(&self, namespace: &str, key: &str, record: &Detail) -> Result<(), ArcaneError> {
            self.objects
                .lock()
                .unwrap()
                .insert((namespace.to_string(), key.to_string()), record.clone());
            Ok(())
        }
        fn has_put_object(&self) -> bool {
            true
        }
    }

    #[test]
    fn bound_kernel_reports_full_status_and_uses_kernel_allocator() {
        let binding = KernelBinding::new();
        binding.bind_kernel(Box::new(FakeKernel {
            objects: StdMutex::new(BTreeMap::new()),
        }));
        assert!(binding.kernel_bound());
        assert_eq!(
            binding.kernel_status(),
            KernelStatus {
                bound: true,
                identity: true,
                events: true,
                objects: true,
                note: NOTE_BOUND,
            }
        );

        let minted = binding.mint_id("run").unwrap();
        assert_eq!(minted.id, "kernel-minted-run");
        assert!(!minted.provisional);
    }

    #[test]
    fn bound_kernel_round_trips_object_writes() {
        let binding = KernelBinding::new();
        binding.bind_kernel(Box::new(FakeKernel {
            objects: StdMutex::new(BTreeMap::new()),
        }));
        let mut record: Detail = BTreeMap::new();
        record.insert("status".to_string(), "sealed".to_string());
        binding.put_object("arcane", "run_1", &record).unwrap();
        let fetched = binding.read_object("arcane", "run_1").unwrap();
        assert_eq!(fetched, Some(record));
        let missing = binding.read_object("arcane", "run_2").unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn unbind_kernel_restores_fail_closed_behaviour() {
        let binding = KernelBinding::new();
        binding.bind_kernel(Box::new(FakeKernel {
            objects: StdMutex::new(BTreeMap::new()),
        }));
        assert!(binding.kernel_bound());
        binding.unbind_kernel();
        assert!(!binding.kernel_bound());
        let detail: Detail = BTreeMap::new();
        assert!(binding.append_event("arcane", &detail).is_err());
    }

    #[test]
    fn arcane_namespace_constant_matches_js() {
        assert_eq!(ARCANE_NAMESPACE, "arcane");
    }
}
