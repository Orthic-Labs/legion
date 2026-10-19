//! Fixed native-owner transaction, never a command runner or transferable grant.
//! Only protected enrollment selects adapters. Native owner retains its record
//! lock & immutable prepared inputs until commit/complete on this same pipe.
use legion_policy::frozen_scope::{self as policy, Operation};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Instant};

const CAP: usize = 32 * 1024;
const PROTOCOL: &str = "legion-native-consume-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsumeOperation {
    Build,
    Dequeue,
    Publish,
}
impl From<ConsumeOperation> for Operation {
    fn from(value: ConsumeOperation) -> Self {
        match value {
            ConsumeOperation::Build => Self::Build,
            ConsumeOperation::Dequeue => Self::Dequeue,
            ConsumeOperation::Publish => Self::Publish,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePin {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub operation: ConsumeOperation,
    pub executable: FilePin,
    /// Administrator inventories runtime/config dependencies; not caller paths.
    pub dependencies: Vec<FilePin>,
    pub uid: u32,
    pub home: PathBuf,
    pub endpoint: String,
    pub destination: String,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEffect {
    pub repository: String,
    pub operation: ConsumeOperation,
    pub native_record_id: String,
    pub source_oid: String,
    pub candidate: Option<String>,
    pub endpoint: String,
    pub destination: String,
    /// Exact immutable owner effect, source/provenance record & (for Publish)
    /// artifact bytes. RightKit adapter verifies their actual relationship.
    pub native_effect_sha256: String,
    pub provenance_sha256: String,
    pub artifact_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingConsume {
    pub transaction_nonce: String,
    pub prepared_sha256: String,
    pub freeze_revision: u64,
    pub prepared: PreparedEffect,
}

#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Prepared {
        protocol: String,
        preparation_nonce: String,
        effect: PreparedEffect,
    },
    Complete {
        protocol: String,
        transaction_nonce: String,
        prepared_sha256: String,
    },
}

fn fail(e: impl std::fmt::Display) -> String {
    format!("native_consumer_held: {e}")
}
fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pin_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(digest)
}
fn oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && !value.bytes().all(|b| b == b'0')
}

pub fn validate_enrollment(
    adapters: &[AdapterConfig],
    allowed: &[Operation],
) -> Result<(), String> {
    if adapters.len() > 3 {
        return Err(fail("at most one adapter per native operation"));
    }
    for (i, adapter) in adapters.iter().enumerate() {
        if adapters[..i]
            .iter()
            .any(|a| a.operation == adapter.operation)
            || !allowed.contains(&Operation::from(adapter.operation))
            || adapter.uid == 0
            || !adapter.home.is_absolute()
            || !adapter.executable.path.is_absolute()
            || !pin_digest(&adapter.executable.sha256)
            || adapter.dependencies.len() > 128
            || adapter
                .dependencies
                .iter()
                .any(|p| !p.path.is_absolute() || !pin_digest(&p.sha256))
            || !(1..=600).contains(&adapter.timeout_seconds)
            || !text(&adapter.endpoint)
            || !text(&adapter.destination)
        {
            return Err(fail("invalid protected adapter enrollment"));
        }
    }
    Ok(())
}

fn prepared(
    response: Response,
    adapter: &AdapterConfig,
    nonce: &str,
    record: &str,
) -> Result<PreparedEffect, String> {
    let Response::Prepared {
        protocol,
        preparation_nonce,
        effect,
    } = response
    else {
        return Err(fail("expected prepared before commit"));
    };
    if protocol != PROTOCOL
        || preparation_nonce != nonce
        || effect.operation != adapter.operation
        || effect.native_record_id != record
        || effect.endpoint != adapter.endpoint
        || effect.destination != adapter.destination
        || !text(&effect.repository)
        || !oid(&effect.source_oid)
        || !digest(&effect.native_effect_sha256)
        || !digest(&effect.provenance_sha256)
        || effect.candidate.as_ref().is_some_and(|v| !digest(v))
        || effect.artifact_sha256.as_ref().is_some_and(|v| !digest(v))
        || (effect.operation == ConsumeOperation::Publish && effect.artifact_sha256.is_none())
    {
        return Err(fail("prepared native record/effect binding mismatch"));
    }
    Ok(effect)
}

fn complete(response: Response, nonce: &str, expected: &str) -> Result<(), String> {
    match response {
        Response::Complete {
            protocol,
            transaction_nonce,
            prepared_sha256,
        } if protocol == PROTOCOL && transaction_nonce == nonce && prepared_sha256 == expected => {
            Ok(())
        }
        _ => Err(fail("completion does not bind committed transaction")),
    }
}

pub(super) fn ensure_before(deadline: Instant) -> Result<(), String> {
    deadline_check(deadline, Instant::now())
}
fn deadline_check(deadline: Instant, now: Instant) -> Result<(), String> {
    if now >= deadline {
        return Err(fail("native authorization deadline exhausted"));
    }
    Ok(())
}

fn authorize_and_commit<A, C, N>(
    effect: PreparedEffect,
    nonce: String,
    digest: String,
    deadline: Instant,
    now: N,
    authorize: A,
    commit: C,
) -> Result<PendingConsume, String>
where
    A: FnOnce(&PreparedEffect, &str, &str, Instant) -> Result<u64, String>,
    C: FnOnce(&PendingConsume) -> Result<(), String>,
    N: Fn() -> Instant,
{
    deadline_check(deadline, now())?;
    let revision = authorize(&effect, &nonce, &digest, deadline)?;
    // Even successful durable authorization cannot extend native transaction.
    // If callback exhausted budget, preserve its journal & never send commit.
    deadline_check(deadline, now())?;
    let pending = PendingConsume {
        transaction_nonce: nonce,
        prepared_sha256: digest,
        freeze_revision: revision,
        prepared: effect,
    };
    commit(&pending)?;
    Ok(pending)
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rightkit_child_process::OwnedCommand;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{BufRead, BufReader, Read, Write},
        os::unix::fs::MetadataExt,
        path::Path,
        process::Stdio,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    fn canonical(path: &Path) -> Result<(), String> {
        if !path.is_absolute() || path.canonicalize().map_err(fail)? != path {
            return Err(fail("adapter paths must be literal canonical paths"));
        }
        Ok(())
    }
    fn pin(pin: &FilePin, executable: bool, deadline: Instant) -> Result<(), String> {
        canonical(&pin.path)?;
        for (i, path) in pin.path.ancestors().enumerate() {
            let m = fs::symlink_metadata(path).map_err(fail)?;
            if m.uid() != 0
                || m.mode() & 0o022 != 0
                || m.file_type().is_symlink()
                || (i == 0 && !m.is_file())
                || (i != 0 && !m.is_dir())
                || (i != 0 && m.mode() & 0o005 != 0o005)
                || (i == 0 && executable && m.mode() & 0o005 != 0o005)
            {
                return Err(fail(
                    "adapter/dependency custody must be root-owned & immutable",
                ));
            }
        }
        let mut file = fs::File::open(&pin.path).map_err(fail)?;
        let mut hash = Sha256::new();
        let mut total = 0usize;
        let mut block = [0; 65536];
        loop {
            if Instant::now() >= deadline {
                return Err(fail("native pinning deadline exhausted"));
            }
            let n = file.read(&mut block).map_err(fail)?;
            if n == 0 {
                break;
            }
            if executable && total == 0 && (n < 4 || !native_magic(&block[..4])) {
                return Err(fail(
                    "adapter must be native executable, never interpreter script",
                ));
            }
            total += n;
            if total > 512 * 1024 * 1024 {
                return Err(fail("adapter dependency pin exceeds cap"));
            }
            hash.update(&block[..n]);
        }
        if total == 0 || pin.sha256 != format!("sha256:{}", hex::encode(hash.finalize())) {
            return Err(fail("adapter/dependency digest mismatch"));
        }
        Ok(())
    }
    fn native_magic(bytes: &[u8]) -> bool {
        matches!(
            bytes,
            b"\x7fELF"
                | b"\xfe\xed\xfa\xce"
                | b"\xce\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xcf"
                | b"\xcf\xfa\xed\xfe"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
                | b"\xca\xfe\xba\xbf"
                | b"\xbf\xba\xfe\xca"
        )
    }

    fn receive<T>(rx: &mpsc::Receiver<T>, deadline: Instant) -> Result<T, String> {
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| fail("native transaction deadline/pipe loss"))
    }

    fn nonce() -> Result<String, String> {
        let mut random = [0u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut random))
            .map_err(fail)?;
        Ok(hex::encode(random))
    }

    // Two bounded newline frames only. No stdout text/logs or third response.
    fn frames<R: Read + Send + 'static>(source: R) -> mpsc::Receiver<Result<Response, String>> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut input = BufReader::new(source);
            for _ in 0..3 {
                let mut bytes = Vec::new();
                let result = input
                    .by_ref()
                    .take((CAP + 1) as u64)
                    .read_until(b'\n', &mut bytes);
                match result {
                    Ok(0) => return,
                    Ok(_) if bytes.len() <= CAP && bytes.last() == Some(&b'\n') => {
                        let result = serde_json::from_slice(&bytes).map_err(fail);
                        let invalid = result.is_err();
                        if tx.send(result).is_err() || invalid {
                            return;
                        }
                    }
                    _ => {
                        let _ = tx.send(Err(fail("invalid/oversized native frame")));
                        return;
                    }
                }
            }
        });
        rx
    }

    pub fn consume<F>(
        adapter: &AdapterConfig,
        record: &str,
        authorize: F,
    ) -> Result<PendingConsume, String>
    where
        F: FnOnce(&PreparedEffect, &str, &str, Instant) -> Result<u64, String>,
    {
        if !text(record) {
            return Err(fail("invalid native record identifier"));
        }
        let deadline = Instant::now() + Duration::from_secs(adapter.timeout_seconds);
        pin(&adapter.executable, true, deadline)?;
        for dependency in &adapter.dependencies {
            pin(dependency, false, deadline)?;
        }
        canonical(&adapter.home)?;
        for ancestor in adapter
            .home
            .parent()
            .ok_or_else(|| fail("HOME parent missing"))?
            .ancestors()
        {
            let meta = fs::symlink_metadata(ancestor).map_err(fail)?;
            if !meta.is_dir()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || meta.file_type().is_symlink()
            {
                return Err(fail(
                    "HOME ancestry must be protected from nonroot replacement",
                ));
            }
        }
        let home = fs::symlink_metadata(&adapter.home).map_err(fail)?;
        if !home.is_dir() || home.uid() != adapter.uid || home.mode() & 0o022 != 0 {
            return Err(fail(
                "HOME must belong to enrolled nonroot UID & resist other writers",
            ));
        }
        let preparation_nonce = nonce()?;
        let mut command = OwnedCommand::new("/usr/bin/sudo");
        command.env_allowlist(std::iter::empty::<&str>());
        command.windows_hide();
        #[cfg(target_os = "linux")]
        command.kill_on_parent_exit(true);
        command
            .command_mut()
            .args([
                "-n",
                "-H",
                "-u",
                &format!("#{}", adapter.uid),
                "--",
                "/usr/bin/env",
                "-i",
            ])
            .arg(format!("HOME={}", adapter.home.display()))
            .args(["PATH=/usr/bin:/bin", "LC_ALL=C"])
            .arg(&adapter.executable.path)
            .arg("legion-native-consume-v1")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        ensure_before(deadline)?;
        let mut child = command.spawn().map_err(fail)?;
        let result = (|| {
            let responses = frames(child.take_stdout().ok_or_else(|| fail("stdout missing"))?);
            let mut stderr = child.take_stderr().ok_or_else(|| fail("stderr missing"))?;
            let (errors_tx, errors_rx) = mpsc::channel();
            thread::spawn(move || {
                let mut size = 0usize;
                let mut block = [0u8; 4096];
                let result = loop {
                    match stderr.read(&mut block) {
                        Ok(0) => break Ok(()),
                        Ok(n) => {
                            size = size.saturating_add(n);
                            if size > CAP {
                                break Err(fail("native stderr exceeded cap"));
                            }
                        }
                        Err(e) => break Err(fail(e)),
                    }
                };
                let _ = errors_tx.send(result);
            });
            let mut stdin = child.take_stdin().ok_or_else(|| fail("stdin missing"))?;
            let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>();
            let (ack_tx, ack_rx) = mpsc::channel();
            thread::spawn(move || {
                for bytes in write_rx {
                    let result = stdin
                        .write_all(&bytes)
                        .and_then(|_| stdin.flush())
                        .map_err(fail);
                    let failed = result.is_err();
                    let _ = ack_tx.send(result);
                    if failed {
                        break;
                    }
                }
            });
            let send = |value: serde_json::Value| -> Result<(), String> {
                if Instant::now() >= deadline {
                    return Err(fail("native transaction deadline exhausted"));
                }
                let mut bytes = serde_json::to_vec(&value).map_err(fail)?;
                if bytes.len() >= CAP {
                    return Err(fail("outbound frame exceeds cap"));
                }
                bytes.push(b'\n');
                write_tx.send(bytes).map_err(fail)?;
                receive(&ack_rx, deadline)?
            };
            send(
                serde_json::json!({"phase":"prepare","protocol":PROTOCOL,"preparation_nonce":preparation_nonce,
                "operation":adapter.operation,"native_record_id":record}),
            )?;
            let effect = prepared(
                receive(&responses, deadline)??,
                adapter,
                &preparation_nonce,
                record,
            )?;
            let sha256 = policy::sha256(&serde_json::to_vec(&effect).map_err(fail)?);
            // Caller independently checks Git/policy & fsyncs typed pending state.
            // No commit can leave this private pipe before durable authorization.
            let pending = authorize_and_commit(
                effect,
                nonce()?,
                sha256,
                deadline,
                Instant::now,
                authorize,
                |pending| {
                    send(serde_json::json!({"phase":"commit","protocol":PROTOCOL,
                    "transaction_nonce":pending.transaction_nonce,"prepared_sha256":pending.prepared_sha256}))
                },
            )?;
            drop(write_tx);
            complete(
                receive(&responses, deadline)??,
                &pending.transaction_nonce,
                &pending.prepared_sha256,
            )?;
            // Drain private pipes before reaping leader, preserving its process
            // group identity for cleanup if descendants retain either pipe.
            receive(&errors_rx, deadline)??;
            // Pipe must close after complete; extra frames never count as success.
            match responses.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Err(mpsc::RecvTimeoutError::Disconnected) => (),
                _ => return Err(fail("native stdout not closed cleanly after complete")),
            }
            if !child
                .wait_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(fail)?
                .is_some_and(|s| s.success())
            {
                return Err(fail("native completion exit uncertain"));
            }
            ensure_before(deadline)?;
            Ok(pending)
        })();
        // Also kill descendants retaining private pipes on failures before commit.
        if result.is_err() {
            let _ = child.terminate_tree_bounded(Duration::from_secs(3));
        }
        result
    }
}

#[cfg(unix)]
pub use unix::consume;
#[cfg(not(unix))]
pub fn consume<F>(_: &AdapterConfig, _: &str, _: F) -> Result<PendingConsume, String>
where
    F: FnOnce(&PreparedEffect, &str, &str, Instant) -> Result<u64, String>,
{
    Err(fail("authenticated Unix broker required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn adapter() -> AdapterConfig {
        AdapterConfig {
            operation: ConsumeOperation::Publish,
            executable: FilePin {
                path: "/protected/native".into(),
                sha256: format!("sha256:{}", policy::sha256(b"native")),
            },
            dependencies: vec![],
            uid: 501,
            home: "/home/owner".into(),
            endpoint: "owner-endpoint".into(),
            destination: "fixed-destination".into(),
            timeout_seconds: 30,
        }
    }
    fn frame() -> serde_json::Value {
        json!({"phase":"prepared","protocol":PROTOCOL,"preparation_nonce":"nonce","effect":{
            "repository":"repo","operation":"Publish","native_record_id":"record", "source_oid":"1".repeat(40),
            "candidate":null,"endpoint":"owner-endpoint","destination":"fixed-destination",
            "native_effect_sha256":policy::sha256(b"effect"),"provenance_sha256":policy::sha256(b"provenance"),
            "artifact_sha256":policy::sha256(b"artifact")}})
    }
    #[test]
    fn strict_protocol_requires_exact_transaction_source_destination_and_artifact() {
        assert!(prepared(
            serde_json::from_value(frame()).unwrap(),
            &adapter(),
            "nonce",
            "record"
        )
        .is_ok());
        for (key, value) in [
            ("source_oid", json!("HEAD")),
            ("destination", json!("other")),
            ("artifact_sha256", json!(null)),
            ("native_record_id", json!("other")),
            ("operation", json!("Build")),
        ] {
            let mut bad = frame();
            bad["effect"][key] = value;
            assert!(prepared(
                serde_json::from_value(bad).unwrap(),
                &adapter(),
                "nonce",
                "record"
            )
            .is_err());
        }
        assert!(prepared(
            serde_json::from_value(frame()).unwrap(),
            &adapter(),
            "other",
            "record"
        )
        .is_err());
        let mut bad = frame();
        bad["approved"] = json!(true);
        assert!(serde_json::from_value::<Response>(bad).is_err());
    }
    #[test]
    fn enrollment_denies_root_duplicates_and_wrong_operation() {
        assert!(validate_enrollment(&[], &[]).is_ok());
        assert!(validate_enrollment(&[adapter()], &[Operation::Publish]).is_ok());
        assert!(validate_enrollment(&[adapter()], &[Operation::Build]).is_err());
        assert!(validate_enrollment(&[adapter(), adapter()], &[Operation::Publish]).is_err());
        let mut root = adapter();
        root.uid = 0;
        assert!(validate_enrollment(&[root], &[Operation::Publish]).is_err());
    }
    #[test]
    fn no_prepared_or_replayed_completion_can_complete_transaction() {
        assert!(complete(serde_json::from_value(frame()).unwrap(), "nonce", "digest").is_err());
        let frame = json!({"phase":"complete","protocol":PROTOCOL,"transaction_nonce":"nonce","prepared_sha256":"digest"});
        assert!(complete(
            serde_json::from_value(frame.clone()).unwrap(),
            "nonce",
            "digest"
        )
        .is_ok());
        assert!(complete(serde_json::from_value(frame).unwrap(), "other", "digest").is_err());
    }
    #[test]
    fn commit_requires_successful_durable_authorization_and_preserves_uncertainty() {
        use std::cell::RefCell;
        let order = RefCell::new(Vec::new());
        let effect = prepared(
            serde_json::from_value(frame()).unwrap(),
            &adapter(),
            "nonce",
            "record",
        )
        .unwrap();
        let journal = RefCell::new(None);
        let result = authorize_and_commit(
            effect.clone(),
            "nonce".into(),
            "digest".into(),
            Instant::now() + std::time::Duration::from_secs(60),
            Instant::now,
            |effect, nonce, digest, _| {
                order.borrow_mut().push("durable");
                *journal.borrow_mut() = Some(PendingConsume {
                    transaction_nonce: nonce.into(),
                    prepared_sha256: digest.into(),
                    freeze_revision: 7,
                    prepared: effect.clone(),
                });
                Ok(7)
            },
            |pending| {
                order.borrow_mut().push("commit");
                assert_eq!(pending.freeze_revision, 7);
                assert!(journal.borrow().is_some());
                Err("pipe lost".into())
            },
        );
        assert!(result.is_err());
        assert_eq!(*order.borrow(), ["durable", "commit"]);
        assert!(journal.borrow().is_some());
        assert!(authorize_and_commit(
            effect,
            "nonce".into(),
            "digest".into(),
            Instant::now() + std::time::Duration::from_secs(60),
            Instant::now,
            |_, _, _, _| Err("denied".into()),
            |_| panic!("denial must not commit")
        )
        .is_err());
    }
    #[test]
    fn expired_or_over_budget_authorization_never_commits_and_preserves_journal() {
        use std::{cell::Cell, time::Duration};
        let effect = prepared(
            serde_json::from_value(frame()).unwrap(),
            &adapter(),
            "nonce",
            "record",
        )
        .unwrap();
        let start = Instant::now();
        let deadline = start + Duration::from_secs(1);
        assert!(authorize_and_commit(
            effect.clone(),
            "nonce".into(),
            "digest".into(),
            deadline,
            || deadline,
            |_, _, _, _| panic!("expired authorization must not start"),
            |_| panic!("expired authorization must not commit")
        )
        .is_err());
        let clock = Cell::new(start);
        let journal = Cell::new(false);
        let result = authorize_and_commit(
            effect,
            "nonce".into(),
            "digest".into(),
            deadline,
            || clock.get(),
            |_, _, _, observed_deadline| {
                assert_eq!(observed_deadline, deadline);
                journal.set(true);
                clock.set(deadline);
                Ok(1)
            },
            |_| panic!("late authorization must not commit"),
        );
        assert!(result.is_err());
        assert!(
            journal.get(),
            "durable pending state survives expiry after authorization"
        );
    }
}
