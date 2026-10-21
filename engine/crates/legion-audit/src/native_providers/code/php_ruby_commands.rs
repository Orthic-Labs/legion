//! PHP/Ruby project operations use frozen source copies & exact SDK admission.
//! Composer's advisory input is an enrolled, untouched official query snapshot;
//! this never claims current Packagist coverage or substitutes a Ruby scanner.
use super::*;
#[path = "php_ruby_enrollment.rs"]
mod runtime;

const ENV: &str = "LEGION_PHP_RUBY_SDK_ENROLLMENT_JSON";
const INPUT_ENV: &str = "LEGION_PHP_RUBY_FROZEN_INPUTS";
const DIGEST_ENV: &str = "LEGION_PHP_RUBY_FROZEN_DIGEST";
const KIND_ENV: &str = "LEGION_PHP_RUBY_COMMAND";
const MAX_FILES: usize = 2048;
const MAX_BYTES: usize = 64 * 1024 * 1024;

// A genuine second SDK execution reads PHPUnit's original JUnit output. DOM
// parsing rejects DTD/entity input; zero tests/assertions, skips & failed tests
// cannot satisfy the shared test operation. No report is manufactured here.
const JUNIT_CHECK: &str = r#"$p=$argv[1];$s=file_get_contents($p);if($s===false||strlen($s)>4194304||str_contains($s,'<!DOCTYPE')||str_contains($s,'<!ENTITY')){fwrite(STDERR,'invalid PHPUnit report');exit(2);}libxml_use_internal_errors(true);$d=new DOMDocument();if(!$d->loadXML($s,LIBXML_NONET)||$d->documentElement->tagName!=='testsuites'){fwrite(STDERR,'invalid PHPUnit XML');exit(2);}$x=new DOMXPath($d);$tests=0;$assertions=0;foreach($x->query('/testsuites/testsuite') as $n){foreach(['tests','assertions','errors','failures','skipped'] as $a){if(!preg_match('/^[0-9]+$/D',$n->getAttribute($a))){exit(2);}}$tests+=(int)$n->getAttribute('tests');$assertions+=(int)$n->getAttribute('assertions');if((int)$n->getAttribute('errors')||(int)$n->getAttribute('failures')||(int)$n->getAttribute('skipped')){exit(1);}}$cases=$x->query('//testcase');if($tests<1||$assertions<1||$cases->length!==$tests||$x->query('//failure|//error|//skipped')->length){exit(1);}echo json_encode(['schema'=>'legion-phpunit-assertions/1','tests'=>$tests,'assertions'=>$assertions,'reportDigest'=>'sha256:'.hash('sha256',$s)],JSON_THROW_ON_ERROR);"#;

pub(super) fn is_php_ruby(parser: Parser) -> bool {
    matches!(
        parser,
        Parser::ComposerValidate
            | Parser::ComposerAudit
            | Parser::PhpStan
            | Parser::PhpUnit
            | Parser::PhpUnitReport
            | Parser::RubyRake
    )
}

fn safe(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\n', '\r', '\0'])
        && Path::new(path)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}

fn read_json(path: &Path) -> Result<(Value, String), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "php-ruby-input-missing")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 128 * 1024 * 1024
    {
        return Err("php-ruby-input-invalid".into());
    }
    let bytes = std::fs::read(path).map_err(|_| "php-ruby-input-unreadable")?;
    let value = serde_json::from_slice(&bytes).map_err(|_| "php-ruby-input-json")?;
    Ok((value, sha256_text(&bytes)))
}

fn enrollment(root: &Path) -> Result<(Value, Value), String> {
    let path = PathBuf::from(std::env::var_os(ENV).ok_or("php-ruby-enrollment-unavailable")?);
    let root = root.canonicalize().map_err(|_| "php-ruby-root")?;
    let canonical = path
        .canonicalize()
        .map_err(|_| "php-ruby-enrollment-missing")?;
    if !path.is_absolute() || path != canonical || path.starts_with(&root) {
        return Err("php-ruby-enrollment-location".into());
    }
    let (value, digest) = read_json(&path)?;
    if value["schema"] != "legion-php-ruby-sdk-enrollment/1" {
        return Err("php-ruby-enrollment-schema".into());
    }
    for name in ["php", "ruby", "bundle", "rubocop"] {
        let tool = &value["tools"][name];
        let path = Path::new(tool["path"].as_str().ok_or("php-ruby-tool-path")?);
        if !path.is_absolute()
            || path.starts_with(&root)
            || std::fs::read(path)
                .ok()
                .map(|bytes| sha256_text(&bytes))
                .as_deref()
                != tool["digest"].as_str()
        {
            return Err(format!("php-ruby-tool-changed:{name}"));
        }
    }
    for name in ["composer", "phpstan", "phpunit"] {
        let asset = &value["assets"][name];
        let path = Path::new(asset["path"].as_str().ok_or("php-ruby-asset-path")?);
        if !path.is_absolute()
            || path.starts_with(&root)
            || std::fs::read(path)
                .ok()
                .map(|bytes| sha256_text(&bytes))
                .as_deref()
                != asset["digest"].as_str()
        {
            return Err(format!("php-ruby-asset-changed:{name}"));
        }
        let (version, digest) = match name {
            "composer" => (
                "2.10.3",
                "sha256:7a2d379d5b8ffdaa028580ef26494c36d2feef4b178d3dd1473a4dbc5e17c8d6",
            ),
            "phpstan" => (
                "2.3.1",
                "sha256:85157dba3d95d77ca603d2b7303aa78a538f9e3b56ccad07dd794c53aa96d1ae",
            ),
            _ => (
                "13.4.3",
                "sha256:f9f8f986f2b6e862187a04619eb01b5960cea77bb39bd1e38d3e396a99eae516",
            ),
        };
        if asset["version"] != version || asset["digest"] != digest {
            return Err("php-ruby-official-asset-pin".into());
        }
    }
    let advisory = &value["advisory"];
    if advisory["packages"] != json!(["symfony/process"])
        || advisory["digest"]
            != "sha256:20e797fa56d83ba55647bf7616700fade0d35d4bec515d85c88098ed8cce8430"
        || advisory["bytes"] != 1637
    {
        return Err("php-ruby-advisory-official-capture-pin".into());
    }
    for (path, digest) in [("path", "digest"), ("provenanceFile", "provenanceDigest")] {
        if std::fs::read(advisory[path].as_str().ok_or("php-ruby-advisory-path")?)
            .ok()
            .map(|raw| sha256_text(&raw))
            .as_deref()
            != advisory[digest].as_str()
        {
            return Err("php-ruby-advisory-input-changed".into());
        }
    }
    Ok((value, json!({"path":path,"digest":digest})))
}

pub(super) fn closure_snapshot(root: &Path) -> Result<Option<Value>, String> {
    let (enrolled, descriptor) = enrollment(root)?;
    let php = runtime::replay(&enrolled["runtime"]["php"], root)?;
    let ruby = runtime::replay(&enrolled["runtime"]["ruby"], root)?;
    Ok(Some(json!({"enrollment":descriptor,"php":php,"ruby":ruby})))
}

fn checked_source(root: &Path, relative: &str, expected: &str) -> Result<Vec<u8>, String> {
    if !safe(relative) {
        return Err("php-ruby-unsafe-source".into());
    }
    let mut path = root.to_path_buf();
    for part in Path::new(relative).components() {
        path.push(part);
        if std::fs::symlink_metadata(&path)
            .map_err(|_| "php-ruby-source-missing")?
            .file_type()
            .is_symlink()
        {
            return Err("php-ruby-source-symlink".into());
        }
    }
    let bytes = std::fs::read(path).map_err(|_| "php-ruby-source-unreadable")?;
    if sha256_text(&bytes) != expected {
        return Err("php-ruby-source-changed".into());
    }
    Ok(bytes)
}

fn binding(command: &Planned) -> Result<Value, String> {
    let path = command
        .env
        .iter()
        .find(|(key, _)| *key == INPUT_ENV)
        .map(|(_, value)| value)
        .ok_or("php-ruby-binding-path")?;
    let (value, digest) = read_json(Path::new(path))?;
    if command
        .env
        .iter()
        .find(|(key, _)| *key == DIGEST_ENV)
        .map(|(_, value)| value)
        != Some(&digest)
    {
        return Err("php-ruby-binding-changed".into());
    }
    if value["schema"] != "legion-php-ruby-inputs/1"
        || value["stage"].as_str() != Some(command.cwd_rel.as_str())
    {
        return Err("php-ruby-binding-schema".into());
    }
    Ok(value)
}

pub(super) fn snapshot(command: &Planned) -> Result<Value, String> {
    let value = binding(command)?;
    let original = Path::new(value["root"].as_str().ok_or("php-ruby-original-root")?);
    let stage = Path::new(value["stage"].as_str().ok_or("php-ruby-stage")?);
    let sources = value["sources"].as_object().ok_or("php-ruby-source-map")?;
    for (path, digest) in sources {
        for root in [original, stage] {
            checked_source(root, path, digest.as_str().ok_or("php-ruby-source-digest")?)?;
        }
    }
    // No file introduced by project code can quietly become an unbound input
    // to a later command. Operational outputs live outside this source stage.
    let mut staged = BTreeSet::new();
    for entry in walkdir::WalkDir::new(stage).follow_links(false) {
        let entry = entry.map_err(|_| "php-ruby-stage-walk")?;
        if entry.file_type().is_symlink()
            || (!entry.file_type().is_file() && !entry.file_type().is_dir())
        {
            return Err("php-ruby-stage-special-file".into());
        }
        if entry.file_type().is_file() {
            staged.insert(
                entry
                    .path()
                    .strip_prefix(stage)
                    .map_err(|_| "php-ruby-stage-path")?
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    if staged != sources.keys().cloned().collect() {
        return Err("php-ruby-stage-file-set-changed".into());
    }
    for (path, digest) in value["ownedFiles"]
        .as_object()
        .ok_or("php-ruby-owned-map")?
    {
        if std::fs::read(path)
            .ok()
            .map(|bytes| sha256_text(&bytes))
            .as_deref()
            != digest.as_str()
        {
            return Err("php-ruby-owned-input-changed".into());
        }
    }
    let (_, descriptor) = enrollment(original)?;
    if descriptor != value["enrollment"] {
        return Err("php-ruby-enrollment-changed".into());
    }
    Ok(
        json!({"bindingDigest":command.env.iter().find(|(key,_)| *key==DIGEST_ENV).map(|(_,value)|value),"inputs":value}),
    )
}

pub(super) fn resolve(ctx: &ToolContext<'_>, command: &Planned, name: &str) -> Option<PathBuf> {
    let (enrollment, _) = enrollment(ctx.root).ok()?;
    let expected = Path::new(enrollment["tools"][name]["path"].as_str()?)
        .canonicalize()
        .ok()?;
    let dirs = ctx.search_path.map(<[PathBuf]>::to_vec).unwrap_or_else(|| {
        std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default()
    });
    let _ = command;
    dirs.iter()
        .filter_map(|dir| in_dir(dir, name))
        .find(|path| path.canonicalize().ok().as_ref() == Some(&expected))
}

pub(super) fn version_args(command: &Planned) -> Vec<String> {
    if matches!(command.parser, Parser::RubyRake) {
        return vec!["--version".into()];
    }
    if command.parser == Parser::PhpUnitReport {
        return vec!["--version".into()];
    }
    vec!["-n".into(), command.args[1].clone(), "--version".into()]
}

fn command(
    tool: &'static str,
    parser: Parser,
    stage: &Path,
    args: Vec<String>,
    env: &[(&'static str, String)],
    accepted: &'static [i32],
) -> Planned {
    Planned {
        tool,
        programs: if parser == Parser::RubyRake {
            &["ruby"]
        } else {
            &["php"]
        },
        local_bin: false,
        sibling_of: None,
        requires: None,
        cwd_rel: stage.to_string_lossy().into_owned(),
        args,
        parser,
        accepted,
        env: env.to_vec(),
        diagnostics_on_stderr: false,
        source_path: None,
        source_digest: None,
    }
}

pub(super) fn plan(
    root: &Path,
    entries: &[InventoryEntry],
    selected: &BTreeSet<String>,
    scratch: &AuditScratch,
    plan: &mut Plan,
) {
    let failure = |plan: &mut Plan, reason: &'static str| {
        for task in ["package", "type", "test", "security"] {
            plan.not_planned.insert(task, reason);
        }
    };
    let Ok((enrolled, descriptor)) = enrollment(root) else {
        failure(plan, "php-ruby-enrollment-unavailable");
        return;
    };
    let base = scratch.tmp_dir().join("php-ruby-sdk");
    let stage = base.join("source");
    let home = base.join("home");
    let output = base.join("output");
    let prepare = || -> Result<(Value, Vec<(&'static str, String)>), String> {
        for dir in [&stage, &home, &output] {
            std::fs::create_dir_all(dir).map_err(|_| "php-ruby-scratch")?;
        }
        if entries.len() > MAX_FILES {
            return Err("php-ruby-source-budget".into());
        }
        let mut sources = BTreeMap::new();
        let mut bytes = 0usize;
        for entry in entries {
            let expected = entry.digest.as_deref().ok_or("php-ruby-source-unfrozen")?;
            let raw = checked_source(root, &entry.path, expected)?;
            bytes += raw.len();
            if bytes > MAX_BYTES {
                return Err("php-ruby-source-budget".into());
            }
            let target = stage.join(&entry.path);
            std::fs::create_dir_all(target.parent().ok_or("php-ruby-parent")?)
                .map_err(|_| "php-ruby-stage")?;
            std::fs::write(target, &raw).map_err(|_| "php-ruby-stage")?;
            sources.insert(entry.path.clone(), expected.to_owned());
        }
        let composer: Value = serde_json::from_slice(
            &std::fs::read(stage.join("composer.json"))
                .map_err(|_| "php-ruby-composer-manifest-missing")?,
        )
        .map_err(|_| "php-ruby-composer-manifest-json")?;
        let lock: Value = serde_json::from_slice(
            &std::fs::read(stage.join("composer.lock"))
                .map_err(|_| "php-ruby-composer-lock-missing")?,
        )
        .map_err(|_| "php-ruby-composer-lock-json")?;
        let mut packages = BTreeSet::new();
        for key in ["packages", "packages-dev"] {
            for package in lock[key]
                .as_array()
                .ok_or("php-ruby-composer-lock-packages")?
            {
                let name = package["name"]
                    .as_str()
                    .ok_or("php-ruby-composer-lock-name")?;
                if !packages.insert(name.to_owned()) || package["version"].as_str().is_none() {
                    return Err("php-ruby-composer-lock-duplicate".into());
                }
            }
        }
        if packages.is_empty() {
            return Err("php-ruby-composer-lock-empty".into());
        }
        let covered: BTreeSet<String> = enrolled["advisory"]["packages"]
            .as_array()
            .ok_or("php-ruby-advisory-packages")?
            .iter()
            .map(|p| {
                p.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "php-ruby-advisory-package".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let advisory_covered = packages.is_subset(&covered)
            && composer.get("repositories").is_none()
            && composer["config"].get("audit").is_none()
            && composer["config"].get("policy").is_none();
        let repo = base.join("repository");
        std::fs::create_dir_all(&repo).map_err(|_| "php-ruby-repository")?;
        let feed = enrolled["advisory"]["path"]
            .as_str()
            .ok_or("php-ruby-advisory-path")?;
        let metadata=serde_json::to_vec(&json!({"packages":{},"metadata-url":"p2/%package%.json","available-packages":covered,"security-advisories":{"metadata":false,"api-url":format!("file://{feed}")}})).map_err(|_|"php-ruby-repository-json")?;
        let config=serde_json::to_vec(&json!({"repositories":{"packagist.org":{"type":"composer","url":format!("file://{}",repo.to_string_lossy())}}})).map_err(|_|"php-ruby-config-json")?;
        let repo_file = repo.join("packages.json");
        let config_file = home.join("config.json");
        std::fs::write(&repo_file, &metadata).map_err(|_| "php-ruby-repository-write")?;
        std::fs::write(&config_file, &config).map_err(|_| "php-ruby-config-write")?;
        let mut owned = BTreeMap::new();
        owned.insert(
            repo_file.to_string_lossy().into_owned(),
            sha256_text(&metadata),
        );
        owned.insert(
            config_file.to_string_lossy().into_owned(),
            sha256_text(&config),
        );
        owned.insert(
            feed.to_owned(),
            enrolled["advisory"]["digest"]
                .as_str()
                .ok_or("php-ruby-advisory-digest")?
                .to_owned(),
        );
        let php: Vec<String> = selected
            .iter()
            .filter(|p| Path::new(p).extension().and_then(|p| p.to_str()) == Some("php"))
            .cloned()
            .collect();
        // NEON supports includes, exclusions & ignored diagnostics with syntax
        // beyond token matching. Keep original config frozen, but do not claim
        // complete type coverage without proving that configuration's scope.
        let type_suppressed = sources.keys().any(|path| {
            if path.ends_with(".neon") || path.ends_with(".neon.dist") {
                true
            } else if path.ends_with(".php") {
                std::fs::read_to_string(stage.join(path))
                    .ok()
                    .is_none_or(|text| text.contains("@phpstan-ignore"))
            } else {
                false
            }
        });
        let value = json!({"typeSuppressionUnsupported":type_suppressed,"schema":"legion-php-ruby-inputs/1","root":root,"stage":stage,"sources":sources,"selectedPhp":php,"ownedFiles":owned,"enrollment":descriptor,"advisoryCovered":advisory_covered,"lockedPackages":packages,"output":output});
        let raw = serde_json::to_vec(&value).map_err(|_| "php-ruby-binding-json")?;
        let input = base.join("inputs.json");
        std::fs::write(&input, &raw).map_err(|_| "php-ruby-binding-write")?;
        let env = vec![
            (INPUT_ENV, input.to_string_lossy().into_owned()),
            (DIGEST_ENV, sha256_text(&raw)),
            ("HOME", home.to_string_lossy().into_owned()),
            ("COMPOSER_HOME", home.to_string_lossy().into_owned()),
            (
                "COMPOSER_CACHE_DIR",
                output.join("composer-cache").to_string_lossy().into_owned(),
            ),
            ("COMPOSER_DISABLE_NETWORK", "1".into()),
            ("COMPOSER_NO_INTERACTION", "1".into()),
            (
                "GEM_HOME",
                enrolled["gemRoot"]
                    .as_str()
                    .ok_or("php-ruby-gem-root")?
                    .into(),
            ),
            (
                "GEM_PATH",
                enrolled["gemRoot"]
                    .as_str()
                    .ok_or("php-ruby-gem-root")?
                    .into(),
            ),
            (
                "BUNDLE_GEMFILE",
                stage.join("Gemfile").to_string_lossy().into_owned(),
            ),
            ("BUNDLE_FROZEN", "true".into()),
            ("BUNDLE_DISABLE_VERSION_CHECK", "true".into()),
            (
                "BUNDLE_USER_HOME",
                output.join("bundle").to_string_lossy().into_owned(),
            ),
            ("RUBYOPT", String::new()),
            ("RUBYLIB", String::new()),
        ];
        Ok((value, env))
    };
    let (inputs, env) = match prepare() {
        Ok(v) => v,
        Err(reason) => {
            failure(plan, "php-ruby-input-incomplete");
            plan.notes.push(reason);
            return;
        }
    };
    let mut add = |task, parser, kind: &str, args, accepted| {
        let mut env = env.clone();
        env.push((KIND_ENV, kind.into()));
        plan.commands
            .push(command(task, parser, &stage, args, &env, accepted));
    };
    let phar = |name: &str| {
        vec![
            "-n".into(),
            enrolled["assets"][name]["path"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        ]
    };
    let mut args = phar("composer");
    args.extend(
        [
            "--no-plugins",
            "--no-scripts",
            "validate",
            "--strict",
            "--no-check-publish",
        ]
        .map(str::to_owned),
    );
    add(
        "package",
        Parser::ComposerValidate,
        "composer-validate",
        args,
        &[0],
    );
    let mut args = phar("phpstan");
    args.extend(
        [
            "analyse",
            "--error-format=json",
            "--no-progress",
            "--no-interaction",
            "--debug",
            "--level=max",
            // `php -n` loads no ini, so PHP's 128M default applies; run
            // 39613219626 exhausted it parsing the PHPUnit phar autoload.
            "--memory-limit=1G",
        ]
        .map(str::to_owned),
    );
    args.push("--autoload-file".into());
    args.push(
        enrolled["assets"]["phpunit"]["path"]
            .as_str()
            .unwrap_or_default()
            .into(),
    );
    if stage.join("phpstan.neon").is_file() {
        args.push("--configuration".into());
        args.push(stage.join("phpstan.neon").to_string_lossy().into_owned());
    } else if stage.join("phpstan.neon.dist").is_file() {
        args.push("--configuration".into());
        args.push(
            stage
                .join("phpstan.neon.dist")
                .to_string_lossy()
                .into_owned(),
        );
    }
    args.push("--".into());
    args.extend(
        inputs["selectedPhp"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|p| stage.join(p).to_string_lossy().into_owned()),
    );
    if inputs["typeSuppressionUnsupported"] != true {
        add("type", Parser::PhpStan, "phpstan", args, &[0, 1]);
    }
    let report = output.join("phpunit.xml");
    let mut args = phar("phpunit");
    args.extend(
        [
            "--colors=never",
            "--no-output",
            "--do-not-record-test-run-history",
            "--do-not-cache-test-index",
            "--fail-on-empty-test-suite",
            "--fail-on-risky",
            "--fail-on-warning",
            "--fail-on-notice",
            "--fail-on-deprecation",
            "--log-junit",
        ]
        .map(str::to_owned),
    );
    args.push(report.to_string_lossy().into_owned());
    add("test", Parser::PhpUnit, "phpunit", args, &[0]);
    add(
        "test",
        Parser::PhpUnitReport,
        "phpunit-report",
        vec![
            "-n".into(),
            "-r".into(),
            JUNIT_CHECK.into(),
            report.to_string_lossy().into_owned(),
        ],
        &[0],
    );
    add(
        "test",
        Parser::RubyRake,
        "rake",
        vec![
            enrolled["tools"]["bundle"]["path"]
                .as_str()
                .unwrap_or_default()
                .into(),
            "exec".into(),
            "rake".into(),
            "test".into(),
        ],
        &[0],
    );
    if inputs["advisoryCovered"] == true {
        let mut args = phar("composer");
        args.extend(
            [
                "--no-plugins",
                "--no-scripts",
                "audit",
                "--locked",
                "--format=json",
                "--no-interaction",
            ]
            .map(str::to_owned),
        );
        add(
            "security",
            Parser::ComposerAudit,
            "composer-audit",
            args,
            &[0, 1],
        );
    }
    if inputs["advisoryCovered"] != true {
        plan.not_planned
            .insert("security", "composer-advisory-query-coverage-missing");
    }
    if inputs["typeSuppressionUnsupported"] == true {
        plan.not_planned
            .insert("type", "phpstan-suppression-or-external-configuration");
    }
}

pub(super) fn parse(
    bytes: &[u8],
    stderr: Option<&[u8]>,
    exit: Option<i32>,
    command: &Planned,
) -> Result<Vec<Diag>, String> {
    let snap = snapshot(command)?;
    let inputs = &snap["inputs"];
    let root = Path::new(inputs["root"].as_str().ok_or("php-ruby-root")?);
    let stage = Path::new(&command.cwd_rel);
    let text = std::str::from_utf8(bytes).map_err(|_| "php-ruby-output-utf8")?;
    let error = std::str::from_utf8(stderr.ok_or("php-ruby-stderr-missing")?)
        .map_err(|_| "php-ruby-stderr-utf8")?;
    match command.parser {
        Parser::ComposerValidate => {
            // Validate legitimately writes validation notices to stderr. Its
            // strict zero exit & explicit original lock are necessary together.
            if exit != Some(0)
                || !text.contains("composer.json is valid")
                || text.contains("not up to date")
                || error.contains("Warning")
                || error.contains("Error")
            {
                return Err("composer-validation-incomplete".into());
            }
            Ok(vec![])
        }
        Parser::PhpUnit => {
            if exit != Some(0) || !text.trim().is_empty() || !error.trim().is_empty() {
                return Err("phpunit-failed-or-unexpected-output".into());
            }
            Ok(vec![])
        }
        Parser::PhpUnitReport => {
            let value: Value = serde_json::from_slice(bytes).map_err(|_| "phpunit-report-json")?;
            let report =
                Path::new(inputs["output"].as_str().ok_or("phpunit-output")?).join("phpunit.xml");
            if exit != Some(0)
                || !error.trim().is_empty()
                || value["schema"] != "legion-phpunit-assertions/1"
                || value["tests"].as_u64().unwrap_or(0) == 0
                || value["assertions"].as_u64().unwrap_or(0) == 0
                || std::fs::read(report)
                    .ok()
                    .map(|raw| sha256_text(&raw))
                    .as_deref()
                    != value["reportDigest"].as_str()
            {
                return Err("phpunit-assertions-unproven".into());
            }
            Ok(vec![])
        }
        Parser::RubyRake => {
            let summary =
                Regex::new(r"(?m)^(\d+) runs, (\d+) assertions, 0 failures, 0 errors, 0 skips\r?$")
                    .map_err(|_| "rake-summary-regex")?;
            let matches = summary.captures_iter(text).collect::<Vec<_>>();
            // The pinned bundler re-declares Gem::Platform constants that a
            // newer host RubyGems already defines; exactly that warning pair
            // is runtime noise. Every other stderr line still disqualifies.
            let redefinition = Regex::new(
                r"^/\S+/bundler-[0-9.]+/lib/bundler/rubygems_ext\.rb:\d+: warning: already initialized constant Gem::Platform::[A-Z0-9_]+$|^/\S+/rubygems/platform\.rb:\d+: warning: previous definition of [A-Z0-9_]+ was here$",
            )
            .map_err(|_| "rake-warning-regex")?;
            let error = error
                .lines()
                .filter(|line| !redefinition.is_match(line))
                .collect::<Vec<_>>()
                .join("\n");
            if exit != Some(0)
                || matches.len() != 1
                || matches[0][1].parse::<u64>().unwrap_or(0) == 0
                || matches[0][2].parse::<u64>().unwrap_or(0) == 0
                || error.contains("warning:")
                || error.contains("Error")
            {
                return Err("rake-assertions-unproven".into());
            }
            Ok(vec![])
        }
        Parser::PhpStan => {
            if !error.trim().is_empty() {
                return Err("phpstan-stderr".into());
            }
            let offset = text.find('{').ok_or("phpstan-json-missing")?;
            let scanned = text[..offset]
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let expected = inputs["selectedPhp"]
                .as_array()
                .ok_or("phpstan-selected")?
                .iter()
                .filter_map(Value::as_str)
                .map(|path| stage.join(path).to_string_lossy().into_owned())
                .collect::<BTreeSet<_>>();
            if scanned.len() != expected.len()
                || scanned.into_iter().collect::<BTreeSet<_>>() != expected
                || expected.is_empty()
            {
                return Err("phpstan-unexamined-selected-files".into());
            }
            let value: Value = serde_json::from_str(&text[offset..]).map_err(|_| "phpstan-json")?;
            if value["totals"]["errors"] != 0
                || value["errors"].as_array().is_none_or(|v| !v.is_empty())
            {
                return Err("phpstan-operational-errors".into());
            }
            let mut diagnostics = Vec::new();
            for (path, row) in value["files"].as_object().ok_or("phpstan-files")? {
                if !expected.contains(path) {
                    return Err("phpstan-outside-selected".into());
                }
                let relative = Path::new(path)
                    .strip_prefix(stage)
                    .map_err(|_| "phpstan-path")?;
                let messages = row["messages"].as_array().ok_or("phpstan-messages")?;
                if row["errors"].as_u64() != Some(messages.len() as u64) {
                    return Err("phpstan-message-count".into());
                }
                for message in messages {
                    diagnostics.push(Diag {
                        rule: format!(
                            "phpstan:{}",
                            message["identifier"].as_str().ok_or("phpstan-rule")?
                        ),
                        severity: "warning",
                        path: root.join(relative).to_string_lossy().into_owned(),
                        line: line_of(message["line"].as_u64()),
                        message: shorten(message["message"].as_str().ok_or("phpstan-message")?),
                    });
                }
            }
            if value["totals"]["file_errors"].as_u64() != Some(diagnostics.len() as u64)
                || exit != Some(if diagnostics.is_empty() { 0 } else { 1 })
            {
                return Err("phpstan-exit-count".into());
            }
            Ok(diagnostics)
        }
        Parser::ComposerAudit => {
            if !error.trim().is_empty() {
                return Err("composer-audit-stderr".into());
            }
            let value: Value = serde_json::from_slice(bytes).map_err(|_| "composer-audit-json")?;
            let object = value.as_object().ok_or("composer-audit-object")?;
            for (name, row) in object {
                if ![
                    "advisories",
                    "abandoned",
                    "ignored-advisories",
                    "unreachable-repositories",
                    "filter",
                ]
                .contains(&name.as_str())
                {
                    return Err("composer-audit-unexpected-field".into());
                }
                if name != "advisories"
                    && !row.is_null()
                    && !row.as_array().is_some_and(Vec::is_empty)
                    && !row.as_object().is_some_and(Map::is_empty)
                {
                    return Err(format!("composer-audit-incomplete:{name}"));
                }
            }
            if !object.contains_key("advisories")
                || !object.contains_key("abandoned")
                || !object.contains_key("filter")
            {
                return Err("composer-audit-envelope-incomplete".into());
            }
            let empty = Map::new();
            let advisories = if value["advisories"].as_array().is_some_and(Vec::is_empty) {
                &empty
            } else {
                value["advisories"]
                    .as_object()
                    .ok_or("composer-audit-advisories")?
            };
            let packages = inputs["lockedPackages"]
                .as_array()
                .ok_or("composer-lock-packages")?;
            let mut out = Vec::new();
            for (package, rows) in advisories {
                if !packages.iter().any(|name| name.as_str() == Some(package)) {
                    return Err("composer-audit-outside-lock".into());
                }
                for advisory in rows.as_array().ok_or("composer-audit-rows")? {
                    if advisory["packageName"] != package.as_str()
                        || advisory["affectedVersions"].as_str().is_none()
                        || advisory["sources"].as_array().is_none_or(Vec::is_empty)
                        || advisory["reportedAt"].as_str().is_none()
                    {
                        return Err("composer-audit-row".into());
                    }
                    out.push(Diag {
                        rule: format!(
                            "composer-audit:{}",
                            advisory["advisoryId"]
                                .as_str()
                                .ok_or("composer-advisory-id")?
                        ),
                        severity: "error",
                        path: root.join("composer.lock").to_string_lossy().into_owned(),
                        line: 1,
                        message: shorten(
                            advisory["title"]
                                .as_str()
                                .ok_or("composer-advisory-title")?,
                        ),
                    });
                }
            }
            if exit != Some(if out.is_empty() { 0 } else { 1 }) {
                return Err("composer-audit-exit".into());
            }
            Ok(out)
        }
        _ => Err("php-ruby-parser".into()),
    }
}
