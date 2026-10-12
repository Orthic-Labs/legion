//! Native implementation of `legacy.framework.major-suite`.
//!
//! Framework output remains candidate-only: candidates are retained in details
//! and never promoted to ProviderResult findings.

use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::ProviderStatus;
use serde_json::{json, Value};

use super::common::{denominator, digest_text, line_at, source_files, ProviderInput};

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    level: &'static str,
    pattern: &'static str,
    message: &'static str,
}

fn rules(family: &str) -> &'static [Rule] {
    match family {
        "next" => &[
            Rule {
                id: "next-public-secret",
                level: "error",
                pattern: r"NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD)",
                message: "Secret-like configuration uses the browser-exposed NEXT_PUBLIC_ prefix.",
            },
            Rule {
                id: "next-unsafe-html",
                level: "warning",
                pattern: r"dangerouslySetInnerHTML\s*=",
                message: "Raw HTML rendering requires a proven sanitization boundary.",
            },
            Rule {
                id: "next-unvalidated-redirect",
                level: "warning",
                pattern: r"(?:redirect|NextResponse\.redirect)\s*\([^\n]*(?:searchParams|query|request\.url)",
                message: "Request-controlled data may reach a redirect target.",
            },
        ],
        "vue" => &[Rule {
            id: "vue-v-html",
            level: "warning",
            pattern: r"\bv-html\s*=",
            message: "v-html renders raw HTML and requires sanitization.",
        }],
        "nuxt" => &[
            Rule {
                id: "nuxt-public-secret",
                level: "error",
                pattern: r"(?i)public\s*:\s*\{[\s\S]{0,400}(?:secret|token|password|privateKey)\s*:",
                message: "Secret-like runtime configuration is placed in Nuxt public config.",
            },
            Rule {
                id: "nuxt-ssr-disabled",
                level: "note",
                pattern: r"\bssr\s*:\s*false",
                message: "SSR is disabled; confirm this matches product and security assumptions.",
            },
        ],
        "angular" => &[
            Rule {
                id: "angular-trust-bypass",
                level: "error",
                pattern: r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(",
                message: "Angular sanitization is explicitly bypassed.",
            },
            Rule {
                id: "angular-inner-html",
                level: "warning",
                pattern: r"\[innerHTML\]\s*=",
                message: "Dynamic HTML binding requires trust and sanitization review.",
            },
        ],
        "svelte" => &[Rule {
            id: "svelte-raw-html",
            level: "warning",
            pattern: r"\{@html\s+",
            message: "Svelte raw HTML rendering requires sanitization.",
        }],
        "sveltekit" => &[
            Rule {
                id: "sveltekit-public-env-secret",
                level: "error",
                pattern: r"\$env/(?:static|dynamic)/public[\s\S]{0,160}(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY)",
                message: "Secret-like value is imported through SvelteKit public environment APIs.",
            },
            Rule {
                id: "sveltekit-unvalidated-redirect",
                level: "warning",
                pattern: r"redirect\s*\([^,]+,\s*(?:url|event\.url|searchParams)",
                message: "Request-controlled data may reach a redirect target.",
            },
        ],
        "express" => &[
            Rule {
                id: "express-trust-proxy-all",
                level: "warning",
                pattern: r#"set\s*\(\s*['"]trust proxy['"]\s*,\s*true\s*\)"#,
                message: "Express trusts every proxy; verify deployment boundaries.",
            },
            Rule {
                id: "express-open-cors",
                level: "warning",
                pattern: r#"cors\s*\(\s*(?:\{|\))[\s\S]{0,200}(?:origin\s*:\s*['"]\*['"]|$)"#,
                message: "Express CORS appears broadly permissive.",
            },
            Rule {
                id: "express-error-leak",
                level: "warning",
                pattern: r"res\.(?:send|json)\s*\([^\n]*(?:err\.stack|error\.stack)",
                message: "Server error stack may be returned to clients.",
            },
        ],
        "fastify" => &[
            Rule {
                id: "fastify-open-cors",
                level: "warning",
                pattern: r#"register\s*\([^\n]*cors[\s\S]{0,250}origin\s*:\s*(?:true|['"]\*['"])"#,
                message: "Fastify CORS accepts arbitrary origins.",
            },
            Rule {
                id: "fastify-schema-missing",
                level: "note",
                pattern: r#"\.(?:get|post|put|patch|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s*)?\("#,
                message: "Route declaration has no visible validation schema.",
            },
        ],
        "nest" => &[
            Rule {
                id: "nest-open-cors",
                level: "warning",
                pattern: r#"enableCors\s*\(\s*(?:\{|\))[\s\S]{0,200}(?:origin\s*:\s*(?:true|['"]\*['"])|$)"#,
                message: "Nest CORS appears broadly permissive.",
            },
            Rule {
                id: "nest-validation-missing-transform",
                level: "note",
                pattern: r"useGlobalPipes\s*\(\s*new\s+ValidationPipe\s*\(\s*\{",
                message: "Nest ValidationPipe does not visibly enable transformation.",
            },
        ],
        "electron" => &[
            Rule {
                id: "electron-node-integration",
                level: "error",
                pattern: r"nodeIntegration\s*:\s*true",
                message: "Electron renderer has Node integration enabled.",
            },
            Rule {
                id: "electron-context-isolation",
                level: "error",
                pattern: r"contextIsolation\s*:\s*false",
                message: "Electron context isolation is disabled.",
            },
            Rule {
                id: "electron-web-security",
                level: "error",
                pattern: r"webSecurity\s*:\s*false",
                message: "Electron web security is disabled.",
            },
            Rule {
                id: "electron-shell-open-external",
                level: "warning",
                pattern: r"shell\.openExternal\s*\([^\n]*(?:url|href|input|request)",
                message: "Potentially untrusted URL reaches shell.openExternal.",
            },
        ],
        "django" => &[
            Rule {
                id: "django-debug",
                level: "error",
                pattern: r"(?m)^\s*DEBUG\s*=\s*True\b",
                message: "Django DEBUG is enabled in tracked configuration.",
            },
            Rule {
                id: "django-hosts-all",
                level: "warning",
                pattern: r#"(?m)^\s*ALLOWED_HOSTS\s*=\s*\[[^\]]*['"]\*['"]"#,
                message: "Django accepts every Host header.",
            },
            Rule {
                id: "django-csrf-exempt",
                level: "warning",
                pattern: r"@csrf_exempt\b",
                message: "Django CSRF protection is bypassed for this view.",
            },
            Rule {
                id: "django-mark-safe",
                level: "warning",
                pattern: r"\bmark_safe\s*\(",
                message: "Django output is explicitly marked safe.",
            },
        ],
        "fastapi" => &[
            Rule {
                id: "fastapi-open-cors",
                level: "warning",
                pattern: r#"allow_origins\s*=\s*\[[^\]]*['"]\*['"]"#,
                message: "FastAPI CORS accepts every origin.",
            },
            Rule {
                id: "fastapi-no-response-model",
                level: "note",
                pattern: r"@(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^\n]*\)\s*\n(?:async\s+)?def\s+",
                message: "FastAPI route has no visible response_model contract.",
            },
        ],
        "flask" => &[
            Rule {
                id: "flask-debug",
                level: "error",
                pattern: r"app\.run\s*\([^)]*debug\s*=\s*True",
                message: "Flask debug mode is enabled.",
            },
            Rule {
                id: "flask-secret-fallback",
                level: "high",
                pattern: r#"SECRET_KEY['"]?\s*\]\s*=\s*(?:os\.environ\.get\([^)]*\)\s+or\s+)?['"][^'"]+['"]"#,
                message: "Flask secret key has a tracked fallback value.",
            },
            Rule {
                id: "flask-render-template-string",
                level: "warning",
                pattern: r"render_template_string\s*\([^\n]*(?:request|input|user)",
                message: "Request-controlled data may reach a Jinja template source.",
            },
        ],
        "spring" => &[
            Rule {
                id: "spring-csrf-disabled",
                level: "warning",
                pattern: r"csrf\s*\([^)]*\)\s*\.disable\s*\(|(?s)csrf\s*\{[^}]*disable\s*\(",
                message: "Spring Security CSRF protection is disabled; prove the application is stateless.",
            },
            Rule {
                id: "spring-sensitive-permit-all",
                level: "error",
                pattern: r"(?is)requestMatchers\s*\([^)]*(?:admin|internal|actuator)[^)]*\)\s*\.permitAll\s*\(",
                message: "Sensitive-looking Spring route is configured permitAll.",
            },
            Rule {
                id: "spring-spel-input",
                level: "error",
                pattern: r"SpelExpressionParser[\s\S]{0,500}parseExpression\s*\(\s*(?:request|input|value|expression)",
                message: "Potentially variable input reaches a SpEL parser.",
            },
        ],
        "ktor" => &[
            Rule {
                id: "ktor-any-host",
                level: "warning",
                pattern: r"anyHost\s*\(\s*\)",
                message: "Ktor CORS permits any host.",
            },
            Rule {
                id: "ktor-forwarded-headers",
                level: "note",
                pattern: r"XForwardedHeaders",
                message: "Forwarded headers are trusted; verify proxy boundaries.",
            },
        ],
        "rails" => &[
            Rule {
                id: "rails-forgery-skip",
                level: "warning",
                pattern: r"skip_(?:before_action|before_filter)\s+:verify_authenticity_token|skip_forgery_protection",
                message: "Rails request forgery protection is bypassed.",
            },
            Rule {
                id: "rails-html-safe",
                level: "warning",
                pattern: r"\.html_safe\b|raw\s*\(",
                message: "Rails output is explicitly marked HTML-safe.",
            },
            Rule {
                id: "rails-constantize-input",
                level: "error",
                pattern: r"(?:params|request)[^\n]*\.constantize\b",
                message: "Request-controlled value may select a Ruby constant.",
            },
        ],
        "phoenix" => &[
            Rule {
                id: "phoenix-check-origin-disabled",
                level: "warning",
                pattern: r"check_origin:\s*false",
                message: "Phoenix origin checks are disabled.",
            },
            Rule {
                id: "phoenix-raw-html",
                level: "warning",
                pattern: r"raw\s*\(",
                message: "Phoenix template emits raw HTML.",
            },
        ],
        "flutter" => &[
            Rule {
                id: "flutter-bad-cert-callback",
                level: "error",
                pattern: r"badCertificateCallback\s*=\s*[^;]*=>\s*true",
                message: "Flutter/Dart accepts every TLS certificate.",
            },
            Rule {
                id: "flutter-webview-js-unrestricted",
                level: "warning",
                pattern: r"JavaScriptMode\.unrestricted",
                message: "Flutter WebView enables unrestricted JavaScript.",
            },
        ],
        "go-web" => &[
            Rule {
                id: "go-http-no-timeouts",
                level: "warning",
                pattern: r"http\.Server\s*\{",
                message: "Go HTTP server has no visible timeout configuration.",
            },
            Rule {
                id: "go-template-html",
                level: "warning",
                pattern: r"template\.HTML\s*\([^\n]*(?:request|input|user)",
                message: "Potentially untrusted content is cast to trusted template HTML.",
            },
        ],
        "rust-web" => &[
            Rule {
                id: "rust-web-unbounded-body",
                level: "note",
                pattern: r"(?:axum|actix_web|warp|rocket)[\s\S]{0,800}(?:Bytes|String|Json)<|web::Payload",
                message: "Request body handling should have an explicit size bound.",
            },
            Rule {
                id: "rust-web-command-input",
                level: "error",
                pattern: r"Command::new\s*\([^)]*\)[\s\S]{0,200}arg\s*\([^\n]*(?:query|path|body|input)",
                message: "Request-derived data may reach a process argument.",
            },
        ],
        _ => &[],
    }
}

/// Go web-framework module paths. `go.mod` records versioned module paths
/// (`github.com/labstack/echo/v4`), so a family match is by path prefix.
const GO_WEB_MODULES: &[&str] = &[
    "github.com/gin-gonic/gin",
    "github.com/labstack/echo",
    "github.com/gofiber/fiber",
    "github.com/go-chi/chi",
    "github.com/gorilla/mux",
];

fn is_go_web_module(lower: &str) -> bool {
    GO_WEB_MODULES.iter().any(|module| {
        lower == *module
            || lower
                .strip_prefix(*module)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Maps a manifest dependency name (as inventory discovery records it: package
/// names, Cargo/PyPI/Go/SwiftPM names, Maven and Gradle `group:artifact` and
/// plugin ids, gem names, mix atoms, pub package names) to a framework family.
/// JVM framework markers follow Maven/Gradle coordinate semantics: a
/// `group:artifact` is classified from its group, while Gradle plugin ids are
/// matched as exact ids. This avoids both missing framework modules and
/// accepting similarly-prefixed unrelated coordinates.
fn family_name(dependency: &str) -> Option<&'static str> {
    let lower = dependency.to_ascii_lowercase();
    if is_go_web_module(&lower) {
        return Some("go-web");
    }
    if let Some((group, _artifact)) = lower.split_once(':') {
        if group == "org.springframework" || group.starts_with("org.springframework.") {
            return Some("spring");
        }
        return (group == "io.ktor").then_some("ktor");
    }
    match lower.as_str() {
        "org.springframework.boot" => return Some("spring"),
        "io.ktor.plugin" => return Some("ktor"),
        _ => {}
    }
    match lower.as_str() {
        "rails" => Some("rails"),
        "phoenix" => Some("phoenix"),
        "flutter" => Some("flutter"),
        "next" => Some("next"),
        "react" => Some("react"),
        "vue" => Some("vue"),
        "nuxt" => Some("nuxt"),
        "angular" | "@angular/core" => Some("angular"),
        "svelte" => Some("svelte"),
        "@sveltejs/kit" => Some("sveltekit"),
        "astro" => Some("astro"),
        "remix" | "@remix-run/react" | "@remix-run/node" => Some("remix"),
        "express" => Some("express"),
        "fastify" => Some("fastify"),
        "@nestjs/core" | "@nestjs/common" => Some("nest"),
        "electron" => Some("electron"),
        "django" => Some("django"),
        "flask" => Some("flask"),
        "fastapi" => Some("fastapi"),
        "axum" | "actix-web" | "rocket" | "warp" => Some("rust-web"),
        _ => None,
    }
}

/// A manifest declares a dependency for its own directory subtree; the source
/// files (which carry no dependencies themselves) are attributed through it.
fn manifest_dir(path: &str) -> &str {
    path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("")
}

fn in_scope(dir: &str, path: &str) -> bool {
    dir.is_empty() || path.starts_with(&format!("{dir}/"))
}

/// Source languages a family's rules are written for. Applied only to files
/// attributed through a manifest, so a Python file under a Next.js root is not
/// scanned with Next rules.
fn family_applies_to(family: &str, path: &str) -> bool {
    let ext = path
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();
    let allowed: &[&str] = match family {
        "django" | "flask" | "fastapi" => &["py"],
        "rust-web" => &["rs"],
        "go-web" => &["go"],
        "spring" | "ktor" => &["java", "kt", "kts"],
        "rails" => &["rb", "erb"],
        "phoenix" => &["ex", "exs", "heex", "eex"],
        "flutter" => &["dart"],
        _ => &[
            "js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "vue", "svelte", "astro", "html",
        ],
    };
    allowed.contains(&ext.as_str())
}

fn find_rule_match(rule: Rule, text: &str) -> Option<usize> {
    let regex = regex::Regex::new(rule.pattern).ok()?;
    if rule.id == "nest-validation-missing-transform" {
        let transform = regex::Regex::new(r"transform\s*:\s*true").ok()?;
        for found in regex.find_iter(text) {
            let tail = text.get(found.end()..)?;
            let transform_in_window = transform
                .find_iter(tail)
                .any(|token| tail[..token.start()].encode_utf16().count() <= 200);
            if !transform_in_window {
                return Some(found.start());
            }
        }
        return None;
    }
    if rule.id == "go-http-no-timeouts" {
        let timeout =
            regex::Regex::new(r"ReadHeaderTimeout|ReadTimeout|WriteTimeout|IdleTimeout").ok()?;
        for found in regex.find_iter(text) {
            let tail = text.get(found.end()..)?;
            let timeout_in_window = timeout
                .find_iter(tail)
                .any(|field| tail[..field.start()].encode_utf16().count() <= 500);
            if !timeout_in_window {
                return Some(found.start());
            }
        }
        return None;
    }
    regex.find(text).map(|found| found.start())
}

pub fn run_framework_suite(input: &ProviderInput<'_>) -> Result<Value, crate::error::AuditError> {
    let selected = denominator(input)?;
    let (files, unreadable) = source_files(input, &selected);
    // Dependencies are recorded on manifests, not on the source files the
    // selector returns; derive (family, manifest directory) scopes from the
    // whole inventory so source files can be attributed to a family.
    let mut scopes: BTreeSet<(&'static str, String)> = BTreeSet::new();
    for entry in &input.inventory.entries {
        let dir = manifest_dir(&entry.path).to_owned();
        for dependency in &entry.dependencies {
            if let Some(family) = family_name(dependency) {
                scopes.insert((family, dir.clone()));
            }
        }
    }
    let mut grouped: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (entry, text) in &files {
        let mut matched: BTreeSet<&'static str> = BTreeSet::new();
        for dependency in &entry.dependencies {
            if let Some(family) = family_name(dependency) {
                matched.insert(family);
            }
        }
        for (family, dir) in &scopes {
            if in_scope(dir, &entry.path) && family_applies_to(family, &entry.path) {
                matched.insert(*family);
            }
        }
        for family in matched {
            grouped
                .entry(family.to_owned())
                .or_default()
                .push((entry.path.clone(), text.clone()));
        }
    }
    let mut gap_items: Vec<Value> = unreadable
        .iter()
        .map(|path| json!({"kind":"denominator-file-unreadable","path":path}))
        .collect();
    let mut families = Vec::new();
    let mut candidates = Vec::new();
    for (family, family_files) in grouped {
        let no_rules = rules(&family).is_empty();
        let mut rows = Vec::new();
        for (file, text) in family_files {
            for rule in rules(&family) {
                if let Some(offset) = find_rule_match(*rule, &text) {
                    let line = line_at(&text, offset);
                    rows.push(json!({"id":digest_text(&format!("{}\0{}\0{}", rule.id, file, line)),"ruleId":rule.id,"severityHint":if matches!(rule.level,"error"|"high"){"high"}else if rule.level=="warning"{"medium"}else{"low"},"claim":rule.message,"file":file,"line":line}));
                }
            }
        }
        candidates.extend(rows.clone());
        // A selected family without rules is unproven, never a silent clean.
        let status = if no_rules {
            "unproven"
        } else if rows.is_empty() {
            "pass"
        } else {
            "candidates"
        };
        let family_gaps = if no_rules {
            let kind = format!("no-rules-for-family:{family}");
            gap_items.push(json!({"kind": kind.clone()}));
            vec![json!({"kind": kind})]
        } else {
            Vec::new()
        };
        families.push(json!({"family":format!("framework.{family}"),"status":status,"complete":unreadable.is_empty() && !no_rules,"candidates":rows,"findings":[],"coverageGaps":family_gaps}));
    }
    if families.is_empty() {
        let kind = if selected.entries.is_empty() {
            "framework-denominator-zero"
        } else {
            "framework-no-family-detected"
        };
        gap_items.push(json!({"kind": kind}));
        families.push(json!({"status":"unproven","complete":false,"coverageGaps":[{"kind":kind}]}));
    }
    Ok(json!({"results":families,"candidates":candidates,"coverageGaps":gap_items}))
}

pub fn execute(
    input: &ProviderInput<'_>,
) -> Result<legion_contracts::ProviderResult, crate::error::AuditError> {
    let selected = denominator(input)?;
    let (files, mut gaps) = source_files(input, &selected);
    let analysis = run_framework_suite(input)?;
    if selected.entries.is_empty() {
        gaps.push("framework-denominator-zero".into());
    }
    let candidates = analysis
        .get("candidates")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    if let Some(items) = analysis.get("coverageGaps").and_then(Value::as_array) {
        gaps.extend(items.iter().filter_map(|item| {
            item.get("kind")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        }));
    }
    let complete = gaps.is_empty() && files.len() == selected.entries.len();
    let mut details = BTreeMap::new();
    details.insert("analysis".into(), analysis);
    details.insert("candidates".into(), candidates);
    details.insert(
        "status".into(),
        Value::String(if complete {
            "pass".into()
        } else {
            "unproven".into()
        }),
    );
    super::common::result(
        input,
        if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        &selected,
        files.len(),
        Vec::new(),
        gaps.clone(),
        gaps,
        details,
    )
}

#[cfg(test)]
mod tests {
    use super::{family_name, find_rule_match, rules};

    #[test]
    fn jvm_framework_markers_follow_coordinate_groups_and_exact_plugin_ids() {
        assert_eq!(
            family_name("org.springframework.security:spring-security-config"),
            Some("spring")
        );
        assert_eq!(
            family_name("org.springframeworkevil:spring-security-config"),
            None
        );
        assert_eq!(family_name("io.ktor:ktor-server-core"), Some("ktor"));
        assert_eq!(family_name("io.ktor.plugin"), Some("ktor"));
        assert_eq!(family_name("io.ktorevil:ktor-server-core"), None);
    }

    #[test]
    fn legacy_framework_rule_shapes_preserve_context_and_formatting() {
        let positive_fixtures = [
            ("next", "next-public-secret", "NEXT_PUBLIC_API_SECRET"),
            (
                "next",
                "next-unsafe-html",
                "dangerouslySetInnerHTML \t= value",
            ),
            (
                "next",
                "next-unvalidated-redirect",
                "redirect (path, request.url)",
            ),
            ("vue", "vue-v-html", "<div v-html \t=\"value\">"),
            (
                "nuxt",
                "nuxt-public-secret",
                "public : {\n apiToken : value }",
            ),
            ("nuxt", "nuxt-ssr-disabled", "ssr : false"),
            (
                "angular",
                "angular-trust-bypass",
                "bypassSecurityTrustResourceUrl (value)",
            ),
            ("angular", "angular-inner-html", "[innerHTML] \t= value"),
            ("svelte", "svelte-raw-html", "{@html\n value}"),
            (
                "sveltekit",
                "sveltekit-public-env-secret",
                "$env/static/public\nAPI_SECRET",
            ),
            (
                "sveltekit",
                "sveltekit-unvalidated-redirect",
                "redirect(303, event.url)",
            ),
            (
                "express",
                "express-trust-proxy-all",
                "app.set (\"trust proxy\", true)",
            ),
            ("express", "express-open-cors", "cors({ origin : '*' })"),
            (
                "express",
                "express-error-leak",
                "res.json({ error: err.stack })",
            ),
            (
                "fastify",
                "fastify-open-cors",
                "app.register(cors, { origin : true })",
            ),
            (
                "fastify",
                "fastify-schema-missing",
                "app.get ('/health', async () => {})",
            ),
            ("nest", "nest-open-cors", "app.enableCors({ origin: '*' })"),
            (
                "nest",
                "nest-validation-missing-transform",
                "useGlobalPipes(new ValidationPipe({ whitelist: true }))",
            ),
            (
                "electron",
                "electron-node-integration",
                "nodeIntegration : true",
            ),
            (
                "electron",
                "electron-context-isolation",
                "contextIsolation : false",
            ),
            ("electron", "electron-web-security", "webSecurity : false"),
            (
                "electron",
                "electron-shell-open-external",
                "shell.openExternal (request.url)",
            ),
            ("django", "django-debug", "  DEBUG \t= True"),
            (
                "django",
                "django-hosts-all",
                "ALLOWED_HOSTS = ['*', 'example.com']",
            ),
            ("django", "django-csrf-exempt", "@csrf_exempt"),
            ("django", "django-mark-safe", "mark_safe (value)"),
            ("fastapi", "fastapi-open-cors", "allow_origins = ['*']"),
            (
                "fastapi",
                "fastapi-no-response-model",
                "@router.get('/health')\ndef check(): pass",
            ),
            (
                "flask",
                "flask-debug",
                "app.run (host='0.0.0.0', debug = True)",
            ),
            (
                "flask",
                "flask-secret-fallback",
                "app.config['SECRET_KEY'] = 'tracked-fallback'",
            ),
            (
                "flask",
                "flask-render-template-string",
                "render_template_string(template, user.name)",
            ),
            (
                "spring",
                "spring-csrf-disabled",
                "http.csrf (config).disable ()",
            ),
            (
                "spring",
                "spring-sensitive-permit-all",
                "requestMatchers('/admin/**').permitAll()",
            ),
            (
                "spring",
                "spring-spel-input",
                "SpelExpressionParser().parseExpression(request.value)",
            ),
            ("ktor", "ktor-any-host", "anyHost ( )"),
            ("ktor", "ktor-forwarded-headers", "XForwardedHeaders"),
            (
                "rails",
                "rails-forgery-skip",
                "skip_before_action :verify_authenticity_token",
            ),
            ("rails", "rails-html-safe", "value.html_safe"),
            (
                "rails",
                "rails-constantize-input",
                "params[:type].constantize",
            ),
            (
                "phoenix",
                "phoenix-check-origin-disabled",
                "check_origin: false",
            ),
            ("phoenix", "phoenix-raw-html", "raw (value)"),
            (
                "flutter",
                "flutter-bad-cert-callback",
                "badCertificateCallback = (cert) => true",
            ),
            (
                "flutter",
                "flutter-webview-js-unrestricted",
                "JavaScriptMode.unrestricted",
            ),
            (
                "go-web",
                "go-http-no-timeouts",
                "server := http.Server { Handler: mux }",
            ),
            ("go-web", "go-template-html", "template.HTML(userInput)"),
            (
                "rust-web",
                "rust-web-unbounded-body",
                "axum::body::Bytes<Body>",
            ),
            (
                "rust-web",
                "rust-web-command-input",
                "Command::new(program).arg(query)",
            ),
        ];
        for (family, id, source) in positive_fixtures {
            let rule = rules(family).iter().find(|rule| rule.id == id).unwrap();
            assert!(find_rule_match(*rule, source).is_some(), "{id}: {source}");
        }
    }

    #[test]
    fn legacy_framework_rules_do_not_flag_safe_contexts_or_unrelated_tokens() {
        let negative_fixtures = [
            ("next", "next-public-secret", "NEXT_PUBLIC_API_BASE_URL"),
            (
                "next",
                "next-unvalidated-redirect",
                "redirect('/home', { permanent: true })",
            ),
            ("nuxt", "nuxt-public-secret", "public: { siteName: 'Acme' }"),
            (
                "sveltekit",
                "sveltekit-public-env-secret",
                "$env/static/private/API_SECRET",
            ),
            (
                "express",
                "express-trust-proxy-all",
                "app.set('trust proxy', 1)",
            ),
            (
                "fastify",
                "fastify-open-cors",
                "app.register(cors, { origin: ['https://app.example'] })",
            ),
            (
                "nest",
                "nest-validation-missing-transform",
                "useGlobalPipes(new ValidationPipe({ transform: true }))",
            ),
            ("django", "django-debug", "logger.info('DEBUG = True')"),
            ("flask", "flask-debug", "app.run(debug=False)"),
            (
                "spring",
                "spring-sensitive-permit-all",
                "requestMatchers('/public/**').permitAll()",
            ),
            (
                "go-web",
                "go-http-no-timeouts",
                "http.Server{ ReadHeaderTimeout: time.Second }",
            ),
            ("go-web", "go-template-html", "template.HTML(staticMarkup)"),
            (
                "rust-web",
                "rust-web-command-input",
                "Command::new(program).arg(staticName)",
            ),
        ];
        for (family, id, source) in negative_fixtures {
            let rule = rules(family).iter().find(|rule| rule.id == id).unwrap();
            assert!(find_rule_match(*rule, source).is_none(), "{id}: {source}");
        }
    }

    #[test]
    fn legacy_context_windows_are_unicode_safe_and_allow_tokens_to_cross_boundary() {
        let nest = rules("nest")
            .iter()
            .find(|rule| rule.id == "nest-validation-missing-transform")
            .unwrap();
        let go = rules("go-web")
            .iter()
            .find(|rule| rule.id == "go-http-no-timeouts")
            .unwrap();

        // The old JavaScript regex window counts UTF-16 code units. A token
        // may start at the last in-window position and finish beyond it.
        let unicode_prefix = "😀".repeat(100);
        let nest_transform_crossing = format!(
            "useGlobalPipes(new ValidationPipe({{{}transform: true",
            unicode_prefix
        );
        assert!(find_rule_match(*nest, &nest_transform_crossing).is_none());

        let go_timeout_crossing = format!(
            "http.Server{{ {}ReadHeaderTimeout: time.Second",
            "x".repeat(499)
        );
        assert!(find_rule_match(*go, &go_timeout_crossing).is_none());

        let go_timeout_unicode = format!(
            "http.Server{{{}ReadHeaderTimeout: time.Second",
            "😀".repeat(250)
        );
        assert!(find_rule_match(*go, &go_timeout_unicode).is_none());

        let nest_transform_outside = format!(
            "useGlobalPipes(new ValidationPipe({{{}xtransform: true",
            unicode_prefix
        );
        assert!(find_rule_match(*nest, &nest_transform_outside).is_some());

        let go_timeout_outside = format!(
            "http.Server{{ {}xReadHeaderTimeout: time.Second",
            "x".repeat(500)
        );
        assert!(find_rule_match(*go, &go_timeout_outside).is_some());
    }
}
