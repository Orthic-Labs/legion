//! Parser tests are not native qualification evidence. Ignored native controls
//! below execute original compiler/analyzer/test programs through EffectExecutor.
use super::*;

fn external_path(name: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(name).expect("explicit retained external mobile SDK path required"),
    );
    assert!(
        path.is_absolute()
            && path.components().all(|component| matches!(
                component,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            ))
    );
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .canonicalize()
        .unwrap();
    let existing = path
        .ancestors()
        .find(|parent| parent.exists())
        .unwrap()
        .canonicalize()
        .unwrap();
    assert!(
        !existing.starts_with(repository),
        "native control output must be outside repository"
    );
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        assert!(!metadata.file_type().is_symlink());
    }
    path
}

fn fixture_base() -> PathBuf {
    let root = external_path("LEGION_MOBILE_SDK_SCRATCH");
    let root = root.join(format!(
        "mobile-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

fn parser_fixture() -> (PathBuf, Planned) {
    // Parser tests use disposable metadata, never claim an Apple SDK execution.
    let base = std::env::temp_dir().join(format!(
        "mobile-parser-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    // Match production's canonical root binding before deriving child paths.
    // Windows canonicalize adds its native extended-length prefix.
    std::fs::create_dir_all(&base).unwrap();
    let base = base.canonicalize().unwrap();
    let root = base.join("root");
    let stage = base.join("stage");
    for path in [&root, &stage] {
        std::fs::create_dir_all(path).unwrap();
    }
    let source = "let value: Int = 1\n";
    for path in [&root, &stage] {
        std::fs::write(path.join("App.swift"), source).unwrap();
    }
    let settings = base.join("SDKSettings.json");
    std::fs::write(&settings, b"parser test metadata").unwrap();
    std::fs::write(stage.join(".legion-swiftlint.yml"), LINT_CONFIG).unwrap();
    let binding = json!({"schema":"legion-mobile-inputs/1", "root":root,"stage":stage,
        "sources":{"App.swift":sha256_text(source.as_bytes())},"selected":["App.swift"],
        "platform":{"sdkSettings":settings,"sdkSettingsDigest":sha256_text(b"parser test metadata")}});
    std::fs::write(stage.join(BINDING), serde_json::to_vec(&binding).unwrap()).unwrap();
    let mut item = command(
        "analyzer",
        &["swiftlint"],
        &stage,
        vec![],
        Parser::MobileLint,
        &[0, 2],
    );
    item.source_path = Some("App.swift".into());
    item.env.push((
        BINDING_DIGEST_ENV,
        sha256_text(&std::fs::read(stage.join(BINDING)).unwrap()),
    ));
    (base, item)
}

#[test]
fn mobile_json_clean_planted_malformed_and_source_binding_controls() {
    let (base, mut item) = parser_fixture();
    assert!(parse(b"[]", Some(b""), Some(0), &item).unwrap().is_empty());
    let planted = json!([{"file":Path::new(&item.cwd_rel).join("App.swift"), "line":1,
        "rule_id":"force_cast","severity":"Warning","reason":"Force casts should be avoided"}]);
    let diagnostics = parse(
        &serde_json::to_vec(&planted).unwrap(),
        Some(b""),
        Some(2),
        &item,
    )
    .unwrap();
    assert_eq!(diagnostics[0].path, "App.swift");
    assert_eq!(diagnostics[0].rule, "swiftlint:force_cast");
    for bytes in [b"".as_slice(), b"{}", b"[", b"null"] {
        assert!(parse(bytes, Some(b""), Some(0), &item).is_err());
    }
    assert!(parse(b"[]", Some(b""), Some(2), &item).is_err());
    for (key, value) in [
        ("file", json!("../../App.swift")),
        ("line", json!(100)),
        ("severity", json!("unknown")),
        ("rule_id", json!("")),
    ] {
        let mut malformed = planted.clone();
        malformed[0][key] = value;
        assert!(parse(
            &serde_json::to_vec(&malformed).unwrap(),
            Some(b""),
            Some(2),
            &item
        )
        .is_err());
    }
    item.parser = Parser::MobileCompiler;
    item.programs = &["swiftc"];
    let diagnostic = format!(
        "{}:1:1: error: cannot convert value\n",
        Path::new(&item.cwd_rel).join("App.swift").display()
    );
    assert_eq!(
        parse(b"", Some(diagnostic.as_bytes()), Some(1), &item)
            .unwrap()
            .len(),
        1
    );
    assert!(parse(b"", Some(b"unexpected garbage"), Some(0), &item).is_err());
    assert!(parse(b"", Some(b"swiftc: error: missing SDK"), Some(1), &item).is_err());
    assert!(parse(b"", None, Some(0), &item).is_err());
    let source_path = base.join("root").join("App.swift");
    let staged_path = base.join("stage").join("App.swift");
    let original = std::fs::read(&source_path).unwrap();
    std::fs::write(&source_path, "changed\n").unwrap();
    assert_eq!(snapshot(&item).unwrap_err(), "mobile-source-changed");
    std::fs::write(&source_path, original).unwrap();
    assert!(snapshot(&item).is_ok());
    std::fs::write(&staged_path, "changed staged bytes\n").unwrap();
    assert_eq!(snapshot(&item).unwrap_err(), "mobile-source-changed");
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn mobile_sdk_metadata_drift_and_nonzero_test_exit_are_not_passes() {
    let (base, mut item) = parser_fixture();
    item.parser = Parser::MobileProcess;
    assert!(parse(b"tests passed", Some(b""), Some(0), &item)
        .unwrap()
        .is_empty());
    assert!(parse(b"tests failed", Some(b""), Some(1), &item).is_err());
    std::fs::write(base.join("SDKSettings.json"), "drift").unwrap();
    assert!(snapshot(&item).is_err());
    std::fs::remove_dir_all(base).unwrap();
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use legion_effects::{PolicyAuthorizer, PolicyDecision};
    use std::{io::Write, sync::Mutex};

    fn source_binding() -> BTreeMap<&'static str, String> {
        [
            ("mobile.rs", include_str!("mobile.rs")),
            ("mobile_sdk.rs", include_str!("mobile_sdk.rs")),
            (
                "mobile_sdk_enrollment.rs",
                include_str!("mobile_sdk_enrollment.rs"),
            ),
            ("mobile_sdk_tests.rs", include_str!("mobile_sdk_tests.rs")),
            ("tools.rs", include_str!("tools.rs")),
            ("native_commands.rs", include_str!("native_commands.rs")),
            ("evidence.rs", include_str!("evidence.rs")),
            (
                "execution_policy.rs",
                include_str!("../../execution_policy.rs"),
            ),
        ]
        .into_iter()
        .map(|(path, text)| (path, sha256_text(text.as_bytes())))
        .collect()
    }

    struct ExactPolicy {
        expected: ExternalToolRequest,
    }
    impl PolicyAuthorizer for ExactPolicy {
        fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
            PolicyDecision {
                allowed: request == &self.expected,
                policy_id: "legion-mobile-constructed-exact-sdk-v1".into(),
                policy_version: 1,
                policy_digest: sha256_text(format!("{:?}", self.expected).as_bytes()),
                reason: Some(
                    "exact constructed mobile SDK fixture only; no CLI owner admission".into(),
                ),
            }
        }
    }

    fn request_value(request: &ExternalToolRequest) -> Value {
        json!({"requestId":request.request_id,"providerId":request.provider_id,"planId":request.plan_id,
            "policyId":request.policy_id,"executable":request.executable,"args":request.args,
            "versionArgs":request.version_args,"cwd":request.cwd,"expectedDigest":request.expected_digest,
            "environment":request.environment,"allowlist":request.environment_allowlist,
            "acceptedExitCodes":request.accepted_exit_codes,"requiresNetworkSandbox":request.requires_network_sandbox,
            "schemaVersion":request.schema_version,"taskId":request.task_id,"origin":format!("{:?}",request.origin),
            "shell":request.shell,"skipVersionProbe":request.skip_version_probe,"versionRequirement":request.version_requirement,
            "sensitiveArgumentIndexes":request.sensitive_argument_indexes,"sensitiveEnvironmentNames":request.sensitive_environment_names,
            "timeoutMs":request.timeout_ms,"stdoutLimit":request.stdout_limit,"stderrLimit":request.stderr_limit,
            "sandbox":request.sandbox.as_ref().map(|sandbox| json!({"id":sandbox.id,"network":sandbox.network,"filesystemScope":sandbox.filesystem_scope}))})
    }

    struct RealTool<'a> {
        expected: Vec<ExternalToolRequest>,
        scratch: &'a AuditScratch,
        refused: bool,
        absent_sandbox: bool,
        observations: Mutex<Vec<Value>>,
    }
    #[async_trait::async_trait]
    impl ExternalProjectTool for RealTool<'_> {
        async fn execute(
            &self,
            mut request: ExternalToolRequest,
            cancellation: CancellationToken,
        ) -> ExecutionReceipt {
            let expected = self
                .expected
                .iter()
                .find(|expected| expected.request_id == request.request_id)
                .expect("request absent from exact frozen test policy");
            assert_eq!(&request, expected);
            let submitted_sandbox = request.sandbox.clone();
            // Negative control removes authenticated evidence, never disables requirement.
            if self.absent_sandbox {
                request.sandbox = None;
            }
            let receipt = if self.refused {
                crate::execution_policy::deny(&request).await
            } else {
                let executor = legion_effects::EffectExecutor::new(
                    legion_effects::platform::unix::UnixProcess::new(),
                    legion_effects::ArtifactWriter::new(self.scratch.artifacts_dir()),
                    ExactPolicy {
                        expected: if self.absent_sandbox {
                            request.clone()
                        } else {
                            expected.clone()
                        },
                    },
                );
                executor
                    .execute_with_cancellation(&request, cancellation)
                    .await
            };
            let stream = |record: Option<&legion_effects::ArtifactRecord>| -> Value {
                record.map(|record| {
                    let bytes = read_artifact(self.scratch, record).expect("retained immutable stream digest");
                    json!({"path":record.path,"digest":record.digest,"bytes":record.bytes,"rawBytes":bytes})
                }).unwrap_or(Value::Null)
            };
            self.observations.lock().unwrap().push(json!({
                "request":request_value(&request),
                "controlRemovedSandboxEvidence":self.absent_sandbox, "originalSandboxId":submitted_sandbox.map(|sandbox| sandbox.id),
                "executionReceipt":crate::execution_policy::receipt_json(&receipt),
                "stdout":stream(receipt.stdout.as_ref()),"stderr":stream(receipt.stderr.as_ref())}));
            receipt
        }
    }

    /// Independently seal every complete request before any execution occurs.
    fn expected(ctx: &ToolContext<'_>, commands: &[Planned]) -> Vec<ExternalToolRequest> {
        let mut resolver = Resolver::new(ctx);
        commands
            .iter()
            .enumerate()
            .map(|(sequence, command)| {
                let cwd = Path::new(&command.cwd_rel);
                let executable = resolver
                    .resolve(command, cwd)
                    .expect("native tool installed by managed CI");
                let executable_text = executable.to_str().unwrap();
                let auth = legion_effects::authenticate_sandbox(
                    executable_text,
                    &command.args,
                    cwd.to_str().unwrap(),
                    legion_effects::SandboxMode::DenyNetwork,
                    &ctx.scratch.sandbox_dir(),
                )
                .unwrap();
                let (mut environment, mut allowlist) = audit_environment(ctx.scratch);
                for name in [
                    "CARGO_HOME",
                    "RUSTUP_HOME",
                    "GOPATH",
                    "GOROOT",
                    "GOMODCACHE",
                ] {
                    if let Ok(value) = std::env::var(name) {
                        environment.insert(name.into(), value);
                        allowlist.insert(name.into());
                    }
                }
                for (name, value) in [
                    ("NO_COLOR", "1"),
                    ("CARGO_NET_OFFLINE", "true"),
                    ("CARGO_TERM_COLOR", "never"),
                ] {
                    environment.insert(name.into(), value.into());
                    allowlist.insert(name.into());
                }
                for (name, value) in &command.env {
                    environment.insert((*name).into(), value.clone());
                    allowlist.insert((*name).into());
                }
                let mut version_args: Vec<_> = auth.wrapped_args.iter().take(3).cloned().collect();
                version_args.extend([executable_text.into(), "--version".into()]);
                ExternalToolRequest {
                    request_id: format!(
                        "audit:code:code.mobile:{}:{sequence}:{}",
                        command.tool, ctx.inventory_digest
                    ),
                    provider_id: "code.mobile".into(),
                    plan_id: ctx.plan_digest.into(),
                    policy_id: "audit".into(),
                    task_id: Some(command.tool.into()),
                    executable: auth.wrapped_executable.clone(),
                    args: auth.wrapped_args,
                    cwd: command.cwd_rel.clone(),
                    shell: false,
                    expected_digest: resolver.digest(Path::new(&auth.wrapped_executable)),
                    accepted_exit_codes: command.accepted.iter().copied().collect(),
                    environment,
                    environment_allowlist: allowlist,
                    requires_network_sandbox: true,
                    sandbox: Some(legion_effects::SandboxReceipt {
                        id: auth.id,
                        network: auth.network,
                        filesystem_scope: auth.filesystem_scope,
                    }),
                    timeout_ms: 120_000,
                    stdout_limit: 32 * 1024 * 1024,
                    stderr_limit: 32 * 1024 * 1024,
                    version_args,
                    ..ExternalToolRequest::default()
                }
            })
            .collect()
    }

    fn files(control: &str) -> BTreeMap<String, String> {
        let mut files: BTreeMap<String, String> = BTreeMap::from([
            ("Package.swift".into(), "// swift-tools-version: 5.9\nimport PackageDescription\nlet package = Package(name: \"MobileSDK\", targets: [.target(name: \"MobileSDK\"), .target(name: \"ObjCBridge\", publicHeadersPath: \"include\"), .target(name: \"ObjCppBridge\", publicHeadersPath: \"include\"), .testTarget(name: \"MobileSDKTests\", dependencies: [\"MobileSDK\", \"ObjCBridge\", \"ObjCppBridge\"])])\n".into()),
            ("Sources/MobileSDK/Answer.swift".into(), "import Foundation\npublic func answer() -> Int { return NSNumber(value: 42).intValue }\n".into()),
            ("Tests/MobileSDKTests/AnswerTests.swift".into(), "import XCTest\n@testable import MobileSDK\nimport ObjCBridge\nimport ObjCppBridge\nfinal class AnswerTests: XCTestCase {\n    func testSwift() { XCTAssertEqual(answer(), 42) }\n    func testObjC() { XCTAssertEqual(mobile_objc_answer(), 42) }\n    func testObjCpp() { XCTAssertEqual(mobile_objcpp_answer(), 42) }\n}\n".into()),
            ("Sources/ObjCBridge/include/ObjCBridge.h".into(), "int mobile_objc_answer(void);\n".into()),
            ("Sources/ObjCBridge/Bridge.m".into(), "#import <Foundation/Foundation.h>\n#include \"include/ObjCBridge.h\"\nint mobile_objc_answer(void) { @autoreleasepool { return [[NSNumber numberWithInt:42] intValue]; } }\n".into()),
            ("Sources/ObjCppBridge/include/ObjCppBridge.h".into(), "#ifdef __cplusplus\nextern \"C\" {\n#endif\nint mobile_objcpp_answer(void);\n#ifdef __cplusplus\n}\n#endif\n".into()),
            ("Sources/ObjCppBridge/Bridge.mm".into(), "#import <Foundation/Foundation.h>\n#include \"include/ObjCppBridge.h\"\nnamespace mobile { int answer() { @autoreleasepool { return [[NSNumber numberWithInt:42] intValue]; } } }\nextern \"C\" int mobile_objcpp_answer(void) { return mobile::answer(); }\n".into()),
        ]);
        match control {
            "planted" => {
                files.insert("Sources/MobileSDK/Answer.swift".into(), "import Foundation\npublic func answer() -> Int { let value: Any = NSNumber(value: 42).intValue; return value as! Int }\n".into());
                for path in [
                    "Sources/ObjCBridge/Bridge.m",
                    "Sources/ObjCppBridge/Bridge.mm",
                ] {
                    // Analyzer-only defect remains unreachable from XCTest calls.
                    files.get_mut(path).unwrap().push_str(
                        "int mobile_analyzer_issue(void) { int *pointer = 0; return *pointer; }\n",
                    );
                }
            }
            "malformed" => {
                files.insert(
                    "Sources/MobileSDK/Answer.swift".into(),
                    "public func answer( -> Int {\n".into(),
                );
            }
            "standalone" => {
                files.remove("Package.swift");
                files.remove("Tests/MobileSDKTests/AnswerTests.swift");
            }
            "objc-compiler-failure" => {
                for path in [
                    "Sources/ObjCBridge/Bridge.m",
                    "Sources/ObjCppBridge/Bridge.mm",
                ] {
                    files
                        .get_mut(path)
                        .unwrap()
                        .push_str("int mobile_compiler_issue(void) { return missing_symbol; }\n");
                }
            }
            "test-failure" => {
                let source = files
                    .get_mut("Tests/MobileSDKTests/AnswerTests.swift")
                    .unwrap();
                *source = source.replace(
                    "XCTAssertEqual(answer(), 42)",
                    "XCTAssertEqual(answer(), -1)",
                );
            }
            "objc-test-failure" => {
                let source = files.get_mut("Sources/ObjCBridge/Bridge.m").unwrap();
                *source = source.replace("numberWithInt:42", "numberWithInt:-1");
            }
            "objcpp-test-failure" => {
                let source = files.get_mut("Sources/ObjCppBridge/Bridge.mm").unwrap();
                *source = source.replace("numberWithInt:42", "numberWithInt:-1");
            }
            _ => {}
        }
        files
    }

    /// Observe XCTest's native case completion lines from retained real bytes.
    /// A failed compiler/linker/launch never satisfies an assertion-failure control.
    fn native_tests_observed(raw: &[Value], failed: Option<&str>) -> bool {
        let Some(row) = raw.iter().find(|row| {
            row["request"]["requestId"]
                .as_str()
                .is_some_and(|id| id.contains(":test:"))
        }) else {
            return false;
        };
        if row["executionReceipt"]["processTree"]["started"] != true
            || row["executionReceipt"]["signal"] != Value::Null
            || row["executionReceipt"]["exitCode"].as_i64()
                != Some(if failed.is_some() { 1 } else { 0 })
        {
            return false;
        }
        let mut text = String::new();
        for stream in ["stdout", "stderr"] {
            let Some(values) = row[stream]["rawBytes"].as_array() else {
                return false;
            };
            let Some(bytes) = values
                .iter()
                .map(|value| value.as_u64().and_then(|value| u8::try_from(value).ok()))
                .collect::<Option<Vec<_>>>()
            else {
                return false;
            };
            let Ok(output) = String::from_utf8(bytes) else {
                return false;
            };
            text.push_str(&output);
        }
        ["testSwift", "testObjC", "testObjCpp"].iter().all(|case| {
            text.lines().any(|line| {
                line.contains("Test Case")
                    && line.contains(&format!("AnswerTests {case}]"))
                    && line.contains(if failed == Some(*case) {
                        " failed "
                    } else {
                        " passed "
                    })
            })
        })
    }

    #[tokio::test]
    #[ignore = "real native mobile SDK controls; managed macOS Xcode + SwiftLint, explicit external scratch/output required"]
    async fn native_mobile_sdk_controls() {
        let base = fixture_base();
        let output = external_path("LEGION_MOBILE_SDK_OUTPUT");
        std::fs::create_dir_all(output.parent().unwrap()).unwrap();
        let sdk = sdk(&base).expect("selected macOS SDK required");
        let swiftlint = std::env::var_os("PATH")
            .into_iter()
            .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .find_map(|directory| in_dir(&directory, "swiftlint"))
            .expect("managed SwiftLint required");
        let enrollment_path = external_path(enrollment::ENV);
        assert!(enrollment_path.is_absolute() && !enrollment_path.starts_with(&base));
        std::fs::create_dir_all(enrollment_path.parent().unwrap()).unwrap();
        let enrolled = enrollment::capture(&sdk, &swiftlint, &base)
            .expect("complete declared installed native roots required");
        let enrollment_bytes =
            std::fs::read(&enrollment_path).expect("managed filesystem preparation required");
        assert_eq!(
            serde_json::from_slice::<Value>(&enrollment_bytes).unwrap(),
            enrolled,
            "prepared enrollment differs from independently observed installed native roots"
        );
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap()
            .canonicalize()
            .unwrap();
        let source_enrollment_path = external_path("LEGION_MOBILE_SOURCE_ENROLLMENT");
        let source_enrollment_bytes =
            std::fs::read(&source_enrollment_path).expect("prepared full source closure required");
        let source_before =
            enrollment::source_snapshot(&repository).expect("full source closure before matrix");
        assert_eq!(
            serde_json::from_slice::<Value>(&source_enrollment_bytes).unwrap(),
            source_before
        );
        let source_enrollment_digest = sha256_text(&source_enrollment_bytes);
        let enrollment_digest = sha256_text(&enrollment_bytes);
        assert_eq!(std::fs::read(&enrollment_path).unwrap(), enrollment_bytes);
        let before = enrollment::descriptor(&base)
            .expect("initial native tree verification")
            .expect("enrollment required");
        let mut cases = Vec::new();
        for control in [
            "nonempty-clean",
            "standalone",
            "planted",
            "malformed",
            "objc-compiler-failure",
            "test-failure",
            "objc-test-failure",
            "objcpp-test-failure",
            "rejected-admission",
            "absent-sandbox",
            "missing-tool",
            "source-drift",
            "enrollment-drift",
        ] {
            println!(
                "REAL_SCANNER_CASE_START {}",
                json!({"providerId":"code.mobile", "caseId":control, "control":control})
            );
            std::io::stdout().flush().unwrap();
            let root = base.join(control).join("source");
            std::fs::create_dir_all(&root).unwrap();
            let fixture = files(control);
            let entries: Vec<_> = fixture
                .iter()
                .map(|(path, source)| {
                    std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
                    std::fs::write(root.join(path), source).unwrap();
                    InventoryEntry {
                        path: path.clone(),
                        symbols: Vec::new(),
                        dependencies: Vec::new(),
                        package_scripts: Vec::new(),
                        source_file: true,
                        digest: Some(sha256_text(source.as_bytes())),
                    }
                })
                .collect();
            let selected: BTreeSet<_> = entries
                .iter()
                .filter(|entry| {
                    Path::new(&entry.path)
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| ["swift", "m", "mm"].contains(&extension))
                })
                .map(|entry| entry.path.clone())
                .collect();
            let scratch =
                AuditScratch::with_scratch_dir(&root, base.join(control).join("run")).unwrap();
            let mut planned = Plan::default();
            plan(&root, &entries, &selected, &scratch, &mut planned);
            assert_eq!(
                planned
                    .commands
                    .iter()
                    .filter(|item| item.tool == "test")
                    .count(),
                usize::from(control != "standalone")
            );
            assert!(planned
                .commands
                .iter()
                .any(|item| item.programs == ["clang"]
                    && item.args.iter().any(|arg| arg == "objective-c++")));
            assert!(planned.deferred.is_empty());
            let placeholder = RealTool {
                expected: Vec::new(),
                scratch: &scratch,
                refused: false,
                absent_sandbox: false,
                observations: Mutex::new(Vec::new()),
            };
            let inventory_digest = sha256_text(&serde_json::to_vec(&fixture).unwrap());
            let plan_digest = sha256_text(&serde_json::to_vec(&json!({"inventory":inventory_digest,
                "commands":planned.commands.iter().map(|command| json!({"tool":command.tool,"argv":command.args,
                    "programs":command.programs,"accepted":command.accepted})).collect::<Vec<_>>(),
                "inputBinding":snapshot(&planned.commands[0]).unwrap()})).unwrap());
            let mut context = ToolContext {
                root: &root,
                tool: &placeholder,
                scratch: &scratch,
                sandbox: SandboxPolicy::Required,
                #[cfg(all(test, target_os = "macos"))]
                dotnet_qualification_loopback: false,
                search_path: None,
                plan_digest: &plan_digest,
                inventory_digest: &inventory_digest,
                provider_id: "code.mobile",
                per_tool_timeout_ms: 120_000,
                total_budget_ms: 900_000,
                output_limit: 32 * 1024 * 1024,
            };
            let frozen_binding = snapshot(&planned.commands[0]).unwrap();
            let requests = expected(&context, &planned.commands);
            let tool = RealTool {
                expected: requests,
                scratch: &scratch,
                refused: control == "rejected-admission",
                absent_sandbox: control == "absent-sandbox",
                observations: Mutex::new(Vec::new()),
            };
            context.tool = &tool;
            let no_path = [];
            if control == "missing-tool" {
                context.search_path = Some(&no_path);
            }
            if control == "source-drift" {
                std::fs::write(root.join("Sources/MobileSDK/Answer.swift"), "drift\n").unwrap();
            }
            if control == "enrollment-drift" {
                let mut changed = enrollment_bytes.clone();
                changed.push(b'\n');
                std::fs::write(&enrollment_path, changed).unwrap();
            }
            let mut resolver = Resolver::new(&context);
            let mut runs = Vec::new();
            for (sequence, command) in planned.commands.iter().enumerate() {
                let result = run_one(
                    &context,
                    &mut resolver,
                    command,
                    None,
                    sequence,
                    120_000,
                    CancellationToken::new(),
                )
                .await;
                runs.push(json!({"tool":command.tool,"programCandidates":command.programs,
                    "outcome":format!("{:?}", result.outcome), "receipt":result.receipt,
                    "findings":result.diagnostics.iter().map(|diag| json!({"path":diag.path,"line":diag.line,
                        "rule":diag.rule,"severity":diag.severity,"message":diag.message})).collect::<Vec<_>>()}));
            }
            let raw = tool.observations.into_inner().unwrap();
            let matched = match control {
                "nonempty-clean" | "standalone" => {
                    runs.iter().all(|run| {
                        run["outcome"] == "Ran" && run["findings"].as_array().unwrap().is_empty()
                    }) && (control == "standalone" || native_tests_observed(&raw, None))
                }
                "planted" => {
                    runs.iter().all(|run| run["outcome"] == "Ran")
                        && native_tests_observed(&raw, None)
                        && runs.iter().any(|run| {
                            run["findings"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|finding| finding["rule"] == "swiftlint:force_cast")
                        })
                        && [
                            "Sources/ObjCBridge/Bridge.m",
                            "Sources/ObjCppBridge/Bridge.mm",
                        ]
                        .iter()
                        .all(|path| {
                            runs.iter().any(|run| {
                                run["tool"] == "analyzer"
                                    && run["findings"].as_array().unwrap().iter().any(|finding| {
                                        finding["path"] == *path && finding["rule"] == "clang"
                                    })
                            })
                        })
                }
                "malformed" => runs
                    .iter()
                    .any(|run| run["tool"] == "compiler" && run["outcome"] != "Ran"),
                "objc-compiler-failure" => [
                    "Sources/ObjCBridge/Bridge.m",
                    "Sources/ObjCppBridge/Bridge.mm",
                ]
                .iter()
                .all(|path| {
                    runs.iter().any(|run| {
                        run["tool"] == "compiler"
                            && run["findings"].as_array().unwrap().iter().any(|finding| {
                                finding["path"] == *path && finding["severity"] == "error"
                            })
                    })
                }),
                "test-failure" | "objc-test-failure" | "objcpp-test-failure" => {
                    runs.iter()
                        .any(|run| run["tool"] == "test" && run["outcome"] != "Ran")
                        && native_tests_observed(
                            &raw,
                            Some(match control {
                                "objc-test-failure" => "testObjC",
                                "objcpp-test-failure" => "testObjCpp",
                                _ => "testSwift",
                            }),
                        )
                }
                "rejected-admission" => {
                    !raw.is_empty()
                        && runs
                            .iter()
                            .all(|run| run["outcome"] == "AdmissionUnavailable")
                        && raw
                            .iter()
                            .all(|row| row["executionReceipt"]["processTree"]["started"] == false)
                }
                "absent-sandbox" => {
                    !raw.is_empty()
                        && runs.iter().all(|run| run["outcome"] == "SandboxMissing")
                        && raw
                            .iter()
                            .all(|row| row["executionReceipt"]["processTree"]["started"] == false)
                }
                "missing-tool" => {
                    raw.is_empty() && runs.iter().all(|run| run["outcome"] == "Missing")
                }
                "source-drift" | "enrollment-drift" => {
                    raw.is_empty() && runs.iter().all(|run| run["outcome"] != "Ran")
                }
                _ => false,
            };
            if control == "enrollment-drift" {
                std::fs::write(&enrollment_path, &enrollment_bytes).unwrap();
            }
            cases.push(json!({"control":control,"matched":matched,"fixtureRoot":root,"scratchRoot":base.join(control).join("run"),
                "inputBinding":frozen_binding,
                "plannedCommands":planned.commands.iter().map(|command| json!({"tool":command.tool,"argv":command.args,
                    "programs":command.programs,"accepted":command.accepted})).collect::<Vec<_>>(),"plannedRequests":tool.expected.iter().map(request_value).collect::<Vec<_>>(),"planDigest":plan_digest,"inventoryDigest":inventory_digest,
                "fixtureSources":fixture,"runs":runs,
                "sdkExecutions":raw,"gaps":planned.notes,
                "positiveNativeTestCalls":if matches!(control, "nonempty-clean" | "planted") {
                    json!(["AnswerTests.testSwift", "AnswerTests.testObjC", "AnswerTests.testObjCpp"])
                } else { Value::Null }}));
            std::fs::write(&output, serde_json::to_vec_pretty(&json!({"schema":"legion-mobile-sdk-controls/1",
                "compiledSourceBinding":source_binding(),
                "provider":"code.mobile","contract":{"extensions":crate::native_providers::code::mobile::CONFIG.extensions,
                    "variants":crate::native_providers::code::mobile::CONFIG.variants,"tools":crate::native_providers::code::mobile::CONFIG.tools,
                    "requiredContext":crate::native_providers::code::mobile::CONFIG.required_context},
                "boundedMacosKnownAnswerEligible":false,"matrixState":"in-progress","admissionScope":"constructed exact SDK admission; production owner admission remains denied",
                "outsideBoundedMacosScope":["iOS/iPadOS device & simulator", "tvOS/watchOS/visionOS/Catalyst", "Xcode schemes/destinations/test plans", "project-defined flags/frameworks/dependencies"],
                "cases":cases})).unwrap()).unwrap();
            assert!(matched, "{control}: inspect retained {}", output.display());
        }
        let observed_after = enrollment::capture(&sdk, &swiftlint, &base)
            .expect("observed complete native closure after matrix");
        assert_eq!(observed_after, enrolled);
        let after = enrollment::descriptor(&base)
            .expect("final native tree verification")
            .expect("enrollment retained");
        assert_eq!(
            before, after,
            "installed native inputs changed during matrix"
        );
        assert_eq!(
            sha256_text(&std::fs::read(&enrollment_path).unwrap()),
            enrollment_digest
        );
        let positive_complete = ["nonempty-clean", "planted"].iter().all(|name| {
            cases.iter().any(|case| {
                case["control"] == *name
                    && case["matched"] == true
                    && ["compiler", "analyzer", "test"].iter().all(|tool| {
                        case["runs"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|run| run["tool"] == *tool && run["outcome"] == "Ran")
                    })
            })
        });
        let native_after_path = output.parent().unwrap().join("mobile-native-after.json");
        let native_after_bytes = serde_json::to_vec(&observed_after).unwrap();
        assert!(!native_after_path.exists());
        std::fs::write(&native_after_path, &native_after_bytes).unwrap();
        let native_after_digest = sha256_text(&native_after_bytes);
        assert_eq!(
            std::fs::read(&native_after_path).unwrap(),
            native_after_bytes
        );
        let source_after =
            enrollment::source_snapshot(&repository).expect("full source closure after matrix");
        assert_eq!(
            source_before, source_after,
            "production/harness/pipeline source changed during native controls"
        );
        assert_eq!(
            sha256_text(&std::fs::read(&source_enrollment_path).unwrap()),
            source_enrollment_digest
        );
        let eligible = positive_complete
            && cases.len() == 13
            && cases.iter().all(|case| case["matched"] == true);
        let mut record = json!({"schema":"legion-mobile-sdk-controls/2", "family":"code-mobile-sdk",
            "stage":"finding", "scope":"constructed macOS SwiftPM Swift/Objective-C/Objective-C++ compiler/analyzer/XCTest controls",
            "retainedRoot":output.parent().unwrap(),"repositoryRoot":repository,"modelCalls":0,
            "qualificationEligible":eligible,"productionQualification":false,"status":"observed-known-answer-controls",
            "sourceEnrollment":{"path":source_enrollment_path,"digest":source_enrollment_digest,"before":source_before,"after":source_after},
            "compiledSourceBinding":source_binding(),"provider":"code.mobile",
            "contract":{"extensions":crate::native_providers::code::mobile::CONFIG.extensions,
                "variants":crate::native_providers::code::mobile::CONFIG.variants,
                "tools":crate::native_providers::code::mobile::CONFIG.tools,
                "requiredContext":crate::native_providers::code::mobile::CONFIG.required_context},
            "matrixState":"complete","boundedMacosKnownAnswerEligible":eligible,
            "wholePlatformQualified":false,"productionOwnerAdmissionQualified":false,
            "admissionScope":"constructed exact SDK admission; production owner admission remains denied",
            "nativeEnrollment":{"path":enrollment_path,"digest":enrollment_digest,"before":before,"after":after,
                "observedBefore":{"path":enrollment_path,"digest":enrollment_digest},
                "observedAfter":{"path":native_after_path,"digest":native_after_digest}},
            "boundedScope":"macOS host SwiftPM: Swift + Objective-C + Objective-C++, Foundation + XCTest; SwiftLint & clang analyzer",
            "outsideBoundedMacosScope":["iOS/iPadOS device & simulator", "tvOS/watchOS/visionOS/Catalyst",
                "Xcode schemes/destinations/test plans", "project-defined flags/frameworks/dependencies"],
            "cases":cases});
        let qualification_digest = sha256_text(&serde_json::to_vec(&record).unwrap());
        record["qualificationDigest"] = json!(qualification_digest);
        let record_bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(&output, &record_bytes).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), record_bytes);
        println!(
            "CODE_MOBILE_SDK_ACCURACY_ARTIFACT {}",
            json!({"provider":"code.mobile", "path":output,
            "sha256":sha256_text(&record_bytes),"bytes":record_bytes.len(),"qualificationDigest":qualification_digest,
            "qualificationEligible":eligible,"productionQualification":false})
        );
        assert!(eligible);
    }
}
