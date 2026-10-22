//! Gradle 9.2.1's uncontended cache lock opens wildcard UDP port 0.
//! JVM qualification admits UDP binding on all local addresses/ports.
//! This capability permits bind operations only. DenyNetwork is unchanged;
//! inbound, outbound, TCP & project writes remain denied, including descendants.
//! Native confinement controls must establish platform behavior before use is
//! counted as qualification; profile syntax alone proves no confinement.
use crate::{ExecutionReceipt, ExecutionState, SandboxAuthentication, SandboxGap};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Private fields bind fresh owner-only cache storage, immutable byte closure &
/// fixed wrapper requests. A receipt string cannot construct this capability.
pub struct GradleBindOnlySandbox {
    project: PathBuf,
    cache: PathBuf,
    java: Option<PathBuf>,
    closure: BTreeMap<PathBuf, String>,
    #[cfg(target_os = "macos")]
    identity: (u64, u64),
    cleanup: bool,
}

const DIST: &str = "home/wrapper/dists/gradle-9.2.1-bin/2t0n5ozlw9xmuyvbp7dnzaxug/gradle-9.2.1";
/// Verbatim admission scope from workspace decisions.md, 2026-10-20 (#79).
pub const QUALIFICATION_ADMISSION: &str = r#"in engine/crates/legion-effects/src/gradle_sandbox.rs profile_text only, allow (network-bind (local udp "*:*")) for the JVM harness process tree; network-outbound and all inbound accept remain denied"#;
fn gap(detail: impl std::fmt::Display) -> SandboxGap {
    SandboxGap::IpcNamespaceInvalid(format!("gradle-bind-only: {detail}"))
}
fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

impl GradleBindOnlySandbox {
    pub fn path(&self) -> &Path {
        &self.cache
    }

    #[cfg(target_os = "macos")]
    pub fn create(parent: &Path, project: &Path) -> Result<Self, SandboxGap> {
        use std::{
            fs,
            os::unix::fs::{DirBuilderExt, MetadataExt},
        };
        let parent = super::sandbox::canonical_owned_path(parent)?;
        let project = super::sandbox::canonical_owned_path(project)?;
        let cache = parent.join("jvm-owned");
        if cache.starts_with(&project) || project.starts_with(&cache) {
            return Err(gap("cache/project overlap"));
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&cache)
            .map_err(gap)?;
        let meta = fs::symlink_metadata(&cache).map_err(gap)?;
        Ok(Self {
            project,
            cache,
            java: None,
            closure: BTreeMap::new(),
            identity: (meta.dev(), meta.ino()),
            cleanup: true,
        })
    }

    #[cfg(not(target_os = "macos"))]
    pub fn create(_parent: &Path, _project: &Path) -> Result<Self, SandboxGap> {
        Err(SandboxGap::UnsupportedPlatform)
    }

    /// Seal all JDK/compiler/distribution/project inputs after staging. Caller
    /// still owns official archive enrollment & complete closure enumeration.
    /// This owner verifies every supplied byte & admits only its fixed argv.
    pub fn seal(
        &mut self,
        java: &Path,
        closure: BTreeMap<PathBuf, String>,
    ) -> Result<(), SandboxGap> {
        if self.java.is_some() || closure.is_empty() {
            return Err(gap("already sealed or empty closure"));
        }
        if java.file_name().and_then(|s| s.to_str()) != Some("java") || !closure.contains_key(java)
        {
            return Err(gap("JDK identity absent"));
        }
        let wrapper = self.project.join("gradle/wrapper/gradle-wrapper.jar");
        if closure.get(&wrapper).map(String::as_str)
            != Some("sha256:423cb469ccc0ecc31f0e4e1c309976198ccb734cdcbb7029d4bda0f18f57e8d9")
        {
            return Err(gap("official wrapper identity differs"));
        }
        let agent = self
            .cache
            .join(DIST)
            .join("lib/agents/gradle-instrumentation-agent-9.2.1.jar");
        if !closure.contains_key(&agent) {
            return Err(gap("sealed instrumentation agent absent"));
        }
        self.java = Some(java.into());
        self.closure = closure;
        self.revalidate()
    }

    pub fn args(&self, task: &str) -> Result<Vec<String>, SandboxGap> {
        let target = match task {
            "wrapper" => None,
            "compile" => Some("legionCompile"),
            "lint" => Some("legionLint"),
            "test" => Some("legionTest"),
            "dependency" => Some("legionDependency"),
            _ => return Err(gap("unsupported task")),
        };
        let agent = self
            .cache
            .join(DIST)
            .join("lib/agents/gradle-instrumentation-agent-9.2.1.jar");
        let home = self.cache.join("home");
        let temp = self.cache.join("tmp");
        let daemon_args=format!("-Xmx512m -Xms256m -XX:MaxMetaspaceSize=384m -XX:+HeapDumpOnOutOfMemoryError -Dfile.encoding=UTF-8 -Duser.language=en -Duser.country=US -Duser.variant= -Djava.io.tmpdir={}",temp.display());
        let mut args = vec![
            "-Xmx512m".into(),
            "-Xms256m".into(),
            "-XX:MaxMetaspaceSize=384m".into(),
            "-XX:+HeapDumpOnOutOfMemoryError".into(),
            "-Dfile.encoding=UTF-8".into(),
            "-Duser.language=en".into(),
            "-Duser.country=US".into(),
            "-Duser.variant=".into(),
            format!("-Djava.io.tmpdir={}", temp.display()),
            format!("-javaagent:{}", agent.display()),
            format!("-Dgradle.user.home={}", home.display()),
            "-cp".into(),
            self.project
                .join("gradle/wrapper/gradle-wrapper.jar")
                .to_string_lossy()
                .into_owned(),
            "org.gradle.wrapper.GradleWrapperMain".into(),
            format!("-Dorg.gradle.jvmargs={daemon_args}"),
            "--offline".into(),
            "--no-daemon".into(),
            "--console=plain".into(),
            "--no-configuration-cache".into(),
            "--gradle-user-home".into(),
            home.to_string_lossy().into_owned(),
            "--project-cache-dir".into(),
            self.cache.join("project").to_string_lossy().into_owned(),
        ];
        if let Some(target) = target {
            args.extend(["--rerun-tasks".into(), target.into()]);
        } else {
            args.push("--version".into());
        }
        Ok(args)
    }

    #[cfg(target_os = "macos")]
    pub fn revalidate(&self) -> Result<(), SandboxGap> {
        use std::{fs, os::unix::fs::MetadataExt};
        super::sandbox::canonical_owned_path(&self.cache)?;
        let meta = fs::symlink_metadata(&self.cache).map_err(gap)?;
        if (meta.dev(), meta.ino()) != self.identity
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o7777 != 0o700
        {
            return Err(gap("owned cache replaced"));
        }
        if self.java.is_none() || self.closure.is_empty() {
            return Err(gap("unsealed request"));
        }
        for (path, expected) in &self.closure {
            if !path.is_absolute()
                || path.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err(gap("noncanonical closure path"));
            }
            let meta = fs::symlink_metadata(path).map_err(gap)?;
            let actual = if let Some(link) = expected.strip_prefix("symlink:") {
                if !meta.file_type().is_symlink()
                    || fs::read_link(path).map_err(gap)?.to_string_lossy() != link
                {
                    return Err(gap("closure symlink changed"));
                }
                expected.clone()
            } else {
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err(gap("closure file changed"));
                }
                hash(&fs::read(path).map_err(gap)?)
            };
            if &actual != expected {
                return Err(gap("immutable closure changed"));
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    pub fn revalidate(&self) -> Result<(), SandboxGap> {
        Err(SandboxGap::UnsupportedPlatform)
    }

    pub fn retain_if_process_tree_unconfirmed(&mut self, receipt: &ExecutionReceipt) -> bool {
        let failed = receipt.state == ExecutionState::KillFailed
            || receipt
                .gaps
                .iter()
                .any(|g| g == "platform_process_tree_unconfirmed")
            || receipt.process_tree.started
                && (!receipt.process_tree.terminated || !receipt.process_tree.reaped);
        if failed {
            self.cleanup = false;
        }
        failed
    }

    #[cfg(target_os = "macos")]
    pub fn authenticate(
        &self,
        task: &str,
        profile_dir: &Path,
    ) -> Result<SandboxAuthentication, SandboxGap> {
        self.revalidate()?;
        authenticate_inner(
            self.java.as_ref().ok_or_else(|| gap("unsealed"))?,
            &self.args(task)?,
            &self.project,
            profile_dir,
        )
    }
    #[cfg(not(target_os = "macos"))]
    pub fn authenticate(
        &self,
        _task: &str,
        _profile_dir: &Path,
    ) -> Result<SandboxAuthentication, SandboxGap> {
        Err(SandboxGap::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
fn profile(project: &str) -> String {
    let project = project.replace('\\', "\\\\").replace('"', "\\\"");
    format!("(version 1)\n(allow default)\n(deny network*)\n(deny file-write* (subpath \"{project}\"))\n(allow file-write-data (require-all (subpath \"{project}\") (vnode-type DIRECTORY)))\n(allow network-bind (local udp \"*:*\"))\n")
}

#[cfg(target_os = "macos")]
fn authenticate_inner(
    executable: &Path,
    args: &[String],
    project: &Path,
    profile_dir: &Path,
) -> Result<SandboxAuthentication, SandboxGap> {
    use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};
    if !Path::new("/usr/bin/sandbox-exec").is_file() {
        return Err(SandboxGap::ToolMissing);
    }
    let project = super::sandbox::canonical_owned_path(project)?;
    let project = project.to_str().ok_or_else(|| gap("non-UTF8 project"))?;
    let text = profile(project);
    let sha = hash(text.as_bytes());
    fs::create_dir_all(profile_dir).map_err(gap)?;
    super::sandbox::canonical_owned_path(profile_dir)?;
    let path = profile_dir.join(format!("audit-gradle-{}.sb", &sha[7..]));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => file.write_all(text.as_bytes()).map_err(gap)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if path.is_symlink() || fs::read(&path).map_err(gap)? != text.as_bytes() {
                return Err(gap("profile drift"));
            }
        }
        Err(e) => return Err(gap(e)),
    }
    let mut wrapped_args = vec![
        "-f".into(),
        path.to_string_lossy().into_owned(),
        "--".into(),
        executable.to_string_lossy().into_owned(),
    ];
    wrapped_args.extend_from_slice(args);
    Ok(SandboxAuthentication {
        id: format!("sandbox:macos:gradle-bind-only:{}", &sha[7..]),
        network: true,
        filesystem_scope: Some(project.into()),
        wrapped_executable: "/usr/bin/sandbox-exec".into(),
        wrapped_args,
    })
}

impl Drop for GradleBindOnlySandbox {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::MetadataExt;
            if self.cleanup
                && std::fs::symlink_metadata(&self.cache).is_ok_and(|m| {
                    !m.file_type().is_symlink()
                        && (m.dev(), m.ino()) == self.identity
                        && m.uid() == unsafe { libc::geteuid() }
                })
            {
                let _ = std::fs::remove_dir_all(&self.cache);
            }
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::{
        ArtifactWriter, EffectExecutor, ExternalToolRequest, PolicyAuthorizer, PolicyDecision,
        SandboxReceipt, ToolOrigin,
    };
    use serde_json::{json, Value};
    use std::{
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream, UdpSocket},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::DirBuilderExt,
        },
        time::Duration,
    };

    struct Exact(ExternalToolRequest, Vec<u8>);
    impl PolicyAuthorizer for Exact {
        fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
            let allowed = r == &self.0
                && fs::read(&r.args[1]).ok().as_deref() == Some(self.1.as_slice())
                && fs::read(&r.executable).is_ok_and(|b| Some(hash(&b)) == r.expected_digest);
            PolicyDecision {
                allowed,
                policy_id: "gradle-bind-native-control".into(),
                policy_version: 1,
                policy_digest: hash(&self.1),
                reason: Some("exact shared-owner native confinement control".into()),
            }
        }
    }
    fn denied(error: std::io::Error) {
        assert!(
            matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)),
            "native permission denial required: {error}"
        );
    }
    /// An inherited descriptor must be absent (EBADF) in the sandboxed child:
    /// stronger than a Seatbelt EPERM, because a connected socket cannot be
    /// revoked by the sandbox.  Probes the raw number without wrapping it in an
    /// owning type, so a reused descriptor number can never be double-closed.
    fn absent(fd: std::os::fd::RawFd) {
        let errno = || std::io::Error::last_os_error().raw_os_error();
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) },
            -1,
            "fd {fd} open"
        );
        assert_eq!(errno(), Some(libc::EBADF), "fd {fd} must be EBADF");
        let sent = unsafe { libc::send(fd, b"forbidden".as_ptr().cast(), 9, 0) };
        assert_eq!((sent, errno()), (-1, Some(libc::EBADF)), "fd {fd} send");
        let mut buf = [0u8; 8];
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), 8, libc::MSG_DONTWAIT) };
        assert_eq!((got, errno()), (-1, Some(libc::EBADF)), "fd {fd} receive");
    }
    fn inherit(fd: std::os::fd::RawFd) {
        let old = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(old >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, old & !libc::FD_CLOEXEC) },
            0
        );
    }
    fn receipt(receipt: &ExecutionReceipt) -> Value {
        let value = json!({
            "schemaVersion": receipt.schema_version,
            "receiptId": receipt.receipt_id, "requestId": receipt.request_id,
            "providerId": receipt.provider_id, "planId": receipt.plan_id,
            "policyId": receipt.policy_id,
            "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
            "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
            "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}",e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}",e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified,"skippedByPolicy":e.version.skipped_by_policy}})),
            "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
            "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
            "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
            "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
            "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
            "exitCode": receipt.exit_code, "signal": receipt.signal,
            "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
            "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
            "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error},
            "gaps": receipt.gaps,
        });
        value
    }
    fn request_value(request: &ExternalToolRequest) -> Value {
        json!({"schemaVersion":request.schema_version,"requestId":request.request_id,
            "providerId":request.provider_id,"planId":request.plan_id,"policyId":request.policy_id,"taskId":request.task_id,
            "executable":request.executable,"args":request.args,"cwd":request.cwd,"origin":format!("{:?}",request.origin),
            "shell":request.shell,"expectedDigest":request.expected_digest,"acceptedExitCodes":request.accepted_exit_codes,
            "versionArgs":request.version_args,"skipVersionProbe":request.skip_version_probe,"versionRequirement":request.version_requirement,
            "environment":request.environment,"environmentAllowlist":request.environment_allowlist,
            "sensitiveArgumentIndexes":request.sensitive_argument_indexes,"sensitiveEnvironmentNames":request.sensitive_environment_names,
            "requiresNetworkSandbox":request.requires_network_sandbox,
            "sandbox":request.sandbox.as_ref().map(|s|json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope})),
            "timeoutMs":request.timeout_ms,"stdoutLimit":request.stdout_limit,"stderrLimit":request.stderr_limit})
    }
    fn artifact(root: &Path, a: Option<&crate::ArtifactRecord>) -> Value {
        a.map(|a|{let bytes=fs::read(root.join(&a.path)).unwrap();assert_eq!(hash(&bytes),a.digest);assert_eq!(bytes.len(),a.bytes);json!({"path":a.path,"absolutePath":root.join(&a.path),"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable,"rawBytes":bytes})}).unwrap_or(Value::Null)
    }

    #[test]
    fn gradle_udp_bind_admission_keeps_traffic_denied() {
        let text = profile("/owned/jvm-project");
        let network = text
            .lines()
            .filter(|line| line.contains("network"))
            .collect::<Vec<_>>();
        assert_eq!(
            network,
            [
                "(deny network*)",
                "(allow network-bind (local udp \"*:*\"))"
            ]
        );
        assert!(text.contains("(deny file-write* (subpath \"/owned/jvm-project\"))"));
        // Gradle 9 rejects project directories that fail access(W_OK).
        assert!(text.contains(
            "(allow file-write-data (require-all (subpath \"/owned/jvm-project\") (vnode-type DIRECTORY)))"
        ));
        assert!(!text.contains("*:0"));
    }

    #[test]
    #[ignore = "helper process for Gradle native confinement driver"]
    fn gradle_bind_only_worker() {
        let Ok(mode) = std::env::var("LEGION_GRADLE_NATIVE_MODE") else {
            return;
        };
        let state = PathBuf::from(std::env::var_os("LEGION_GRADLE_NATIVE_STATE").unwrap());
        fs::write(
            state.join(format!("{mode}.pid")),
            std::process::id().to_string(),
        )
        .unwrap();
        if mode == "hang" || mode == "orphan" || mode == "grandchild" {
            if mode != "grandchild" {
                let _child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "gradle_sandbox::tests::gradle_bind_only_worker",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("LEGION_GRADLE_NATIVE_MODE", "grandchild")
                    .spawn()
                    .unwrap();
                for _ in 0..100 {
                    if state.join("grandchild.pid").is_file() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(state.join("grandchild.pid").is_file());
                if mode == "orphan" {
                    return;
                }
            }
            std::thread::sleep(Duration::from_secs(60));
            return;
        }
        // Probe inherited descriptors before opening anything, so no new socket
        // can occupy an inherited descriptor number.
        let fd_of =
            |name: &str| -> std::os::fd::RawFd { std::env::var(name).unwrap().parse().unwrap() };
        for name in [
            "LEGION_GRADLE_INHERITED_UDP4",
            "LEGION_GRADLE_INHERITED_UDP6",
            "LEGION_GRADLE_INHERITED_TCP",
        ] {
            absent(fd_of(name));
        }
        for (family, address) in [("4", "0.0.0.0:0"), ("6", "[::]:0")] {
            let socket =
                UdpSocket::bind(address).expect("wildcard ephemeral bind must actually work");
            assert_ne!(socket.local_addr().unwrap().port(), 0);
            let target: std::net::SocketAddr = std::env::var(format!("LEGION_GRADLE_UDP{family}"))
                .unwrap()
                .parse()
                .unwrap();
            let assigned_port = std::env::var(format!("LEGION_GRADLE_ASSIGNED{family}"))
                .unwrap()
                .parse()
                .unwrap();
            let assigned = UdpSocket::bind(std::net::SocketAddr::new(
                socket.local_addr().unwrap().ip(),
                assigned_port,
            ))
            .expect("assigned UDP bind is explicitly admitted");
            assert_eq!(assigned.local_addr().unwrap().port(), assigned_port);
            println!("LEGION_NATIVE_ADMISSIONS|ipv{family}|ephemeral-udp-bind,assigned-udp-bind");
            denied(assigned.send_to(b"forbidden", target).unwrap_err());
            assigned
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            denied(assigned.recv_from(&mut [0u8; 16]).unwrap_err());
            denied(socket.send_to(b"forbidden", target).unwrap_err());
            socket
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            denied(socket.recv_from(&mut [0u8; 16]).unwrap_err());
            let tcp: std::net::SocketAddr = std::env::var(format!("LEGION_GRADLE_TCP{family}"))
                .unwrap()
                .parse()
                .unwrap();
            denied(TcpListener::bind(std::net::SocketAddr::new(tcp.ip(), 0)).unwrap_err());
            denied(TcpStream::connect_timeout(&tcp, Duration::from_millis(200)).unwrap_err());
            println!("LEGION_NATIVE_DENIALS|ipv{family}|udp-send,udp-receive,assigned-udp-send,assigned-udp-receive,inherited-send,inherited-receive,tcp-bind,tcp-connect");
        }
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(raw >= 0);
        let external = unsafe { UdpSocket::from_raw_fd(raw) };
        denied(external.send_to(b"forbidden", "192.0.2.1:9").unwrap_err());
        denied(
            TcpStream::connect_timeout(&"192.0.2.1:9".parse().unwrap(), Duration::from_millis(200))
                .unwrap_err(),
        );
        denied(
            fs::write(
                PathBuf::from(std::env::var_os("LEGION_GRADLE_NATIVE_PROJECT").unwrap())
                    .join("forbidden"),
                b"no",
            )
            .unwrap_err(),
        );
        println!("LEGION_NATIVE_DENIALS|external|udp,tcp,inherited-tcp-send,inherited-tcp-receive,project-write");
        println!("LEGION_GRADLE_BIND_ONLY_CONFINEMENT|pass");
    }

    #[test]
    #[ignore = "real macOS Seatbelt UDP-bind admission, traffic denial & process-tree controls"]
    fn gradle_bind_only_native_confinement() {
        let output = PathBuf::from(
            std::env::var_os("LEGION_JVM_CONFINEMENT_RECORD")
                .expect("explicit retained record required"),
        );
        assert!(!output.exists());
        let parent = output.parent().unwrap().canonicalize().unwrap();
        let root = parent.join("gradle-native-control");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let project = root.join("project");
        fs::create_dir(&project).unwrap();
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::write(project.join("host-write"), b"ready").unwrap();
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        let udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp6 = UdpSocket::bind("[::1]:0").unwrap();
        let inherited4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let inherited6 = UdpSocket::bind("[::1]:0").unwrap();
        for (sender, receiver) in [(&udp4, &inherited4), (&udp6, &inherited6)] {
            sender
                .send_to(b"ready", receiver.local_addr().unwrap())
                .unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_eq!(receiver.recv(&mut [0u8; 8]).unwrap(), 5);
            sender
                .send_to(b"denied", receiver.local_addr().unwrap())
                .unwrap();
            inherit(receiver.as_raw_fd());
        }
        let tcp4 = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp6 = TcpListener::bind("[::1]:0").unwrap();
        let mut inherited_tcp = TcpStream::connect(tcp4.local_addr().unwrap()).unwrap();
        let (mut peer, _) = tcp4.accept().unwrap();
        peer.write_all(b"ready").unwrap();
        assert_eq!(inherited_tcp.read(&mut [0u8; 8]).unwrap(), 5);
        peer.write_all(b"denied").unwrap();
        inherit(inherited_tcp.as_raw_fd());
        TcpStream::connect(tcp6.local_addr().unwrap()).unwrap();
        let assigned4 = UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let assigned6 = UdpSocket::bind("[::]:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut rows = Vec::new();
        for mode in ["confinement", "hang", "orphan"] {
            let _ = fs::remove_file(state.join("grandchild.pid"));
            let args = [
                "--exact",
                "gradle_sandbox::tests::gradle_bind_only_worker",
                "--ignored",
                "--nocapture",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
            // Private test-only constructor exercises identical production
            // profile. Public API never admits this worker executable/argv.
            let auth = authenticate_inner(&exe, &args, &project, &root.join("profiles")).unwrap();
            let env: BTreeMap<String, String> = [
                ("LEGION_GRADLE_NATIVE_MODE", mode.into()),
                (
                    "LEGION_GRADLE_NATIVE_STATE",
                    state.to_string_lossy().into_owned(),
                ),
                (
                    "LEGION_GRADLE_NATIVE_PROJECT",
                    project.to_string_lossy().into_owned(),
                ),
                ("LEGION_GRADLE_UDP4", udp4.local_addr().unwrap().to_string()),
                ("LEGION_GRADLE_UDP6", udp6.local_addr().unwrap().to_string()),
                ("LEGION_GRADLE_TCP4", tcp4.local_addr().unwrap().to_string()),
                ("LEGION_GRADLE_TCP6", tcp6.local_addr().unwrap().to_string()),
                ("LEGION_GRADLE_ASSIGNED4", assigned4.to_string()),
                ("LEGION_GRADLE_ASSIGNED6", assigned6.to_string()),
                (
                    "LEGION_GRADLE_INHERITED_UDP4",
                    inherited4.as_raw_fd().to_string(),
                ),
                (
                    "LEGION_GRADLE_INHERITED_UDP6",
                    inherited6.as_raw_fd().to_string(),
                ),
                (
                    "LEGION_GRADLE_INHERITED_TCP",
                    inherited_tcp.as_raw_fd().to_string(),
                ),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect();
            let request = ExternalToolRequest {
                request_id: format!("gradle-native-{mode}"),
                provider_id: "shared-gradle-confinement".into(),
                plan_id: hash(b"gradle-bind-only-native-v1"),
                policy_id: "gradle-bind-native-control".into(),
                executable: auth.wrapped_executable,
                args: auth.wrapped_args,
                expected_digest: Some(hash(&fs::read("/usr/bin/sandbox-exec").unwrap())),
                skip_version_probe: true,
                cwd: project.to_string_lossy().into_owned(),
                origin: ToolOrigin::System,
                requires_network_sandbox: true,
                sandbox: Some(SandboxReceipt {
                    id: auth.id,
                    network: auth.network,
                    filesystem_scope: auth.filesystem_scope,
                }),
                environment_allowlist: env.keys().cloned().collect(),
                environment: env,
                timeout_ms: if mode == "hang" { 1500 } else { 10000 },
                stdout_limit: 65536,
                stderr_limit: 65536,
                ..ExternalToolRequest::default()
            };
            let policy = Exact(request.clone(), fs::read(&request.args[1]).unwrap());
            let artifacts = root.join(mode).join("artifacts");
            let executor = EffectExecutor::new(
                crate::platform::unix::UnixProcess::new(),
                ArtifactWriter::new(&artifacts),
                policy,
            );
            let r = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(executor.execute(&request));
            let out = artifact(&artifacts, r.stdout.as_ref());
            let err = artifact(&artifacts, r.stderr.as_ref());
            let mut descendants = Vec::new();
            for name in [mode, "grandchild"] {
                let path = state.join(format!("{name}.pid"));
                if path.exists() {
                    let pid: libc::pid_t = fs::read_to_string(&path).unwrap().parse().unwrap();
                    let result = unsafe { libc::kill(pid, 0) };
                    let stopped = result == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
                    descendants.push(json!({"role":name,"pid":pid,"stopped":stopped}));
                }
            }
            rows.push(json!({"mode":mode,"request":request_value(&request),"profile":profile(project.to_str().unwrap()),"profileDigest":hash(profile(project.to_str().unwrap()).as_bytes()),"receipt":receipt(&r),"stdout":out,"stderr":err,"descendants":descendants}));
            fs::write(&output,serde_json::to_vec_pretty(&json!({"schema":"legion-gradle-bind-confinement/1","sandboxAdmission":QUALIFICATION_ADMISSION,"sourceDigest":hash(include_bytes!("gradle_sandbox.rs")),"complete":false,"controls":rows})).unwrap()).unwrap();
            assert_eq!(
                r.state,
                if mode == "hang" {
                    ExecutionState::Timeout
                } else {
                    ExecutionState::Completed
                }
            );
            assert_eq!(r.complete, mode != "hang");
            assert!(r.process_tree.started && r.process_tree.terminated && r.process_tree.reaped);
            assert!(rows.last().unwrap()["descendants"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["stopped"] == true));
            if mode == "confinement" {
                let bytes = rows.last().unwrap()["stdout"]["rawBytes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|b| b.as_u64().unwrap() as u8)
                    .collect::<Vec<_>>();
                assert!(String::from_utf8(bytes)
                    .unwrap()
                    .lines()
                    .any(|l| l == "LEGION_GRADLE_BIND_ONLY_CONFINEMENT|pass"));
            } else {
                assert_eq!(
                    rows.last().unwrap()["descendants"]
                        .as_array()
                        .unwrap()
                        .len(),
                    2
                );
            }
        }
        fs::write(&output,serde_json::to_vec_pretty(&json!({"schema":"legion-gradle-bind-confinement/1","sandboxAdmission":QUALIFICATION_ADMISSION,"sourceDigest":hash(include_bytes!("gradle_sandbox.rs")),"complete":true,"controls":rows})).unwrap()).unwrap();
    }
}
