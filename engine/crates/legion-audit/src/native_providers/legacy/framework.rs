//! Native implementation of `legacy.framework.major-suite`.
//!
//! Framework output remains candidate-only: candidates are retained in details
//! and never promoted to ProviderResult findings.

use std::collections::BTreeMap;

use legion_contracts::ProviderStatus;
use serde_json::{json, Value};

use super::common::{
    denominator, digest_text, line_at, occurrences_ascii_case_insensitive, source_files,
    ProviderInput,
};

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    level: &'static str,
    needle: &'static str,
    message: &'static str,
}

fn rules(family: &str) -> &'static [Rule] {
    match family {
        "next" => &[Rule { id: "next-public-secret", level: "error", needle: "NEXT_PUBLIC_", message: "Secret-like configuration uses the browser-exposed NEXT_PUBLIC_ prefix." }, Rule { id: "next-unsafe-html", level: "warning", needle: "dangerouslySetInnerHTML=", message: "Raw HTML rendering requires a proven sanitization boundary." }, Rule { id: "next-unvalidated-redirect", level: "warning", needle: "NextResponse.redirect(", message: "Request-controlled data may reach a redirect target." }],
        "vue" => &[Rule { id: "vue-v-html", level: "warning", needle: "v-html=", message: "v-html renders raw HTML and requires sanitization." }],
        "nuxt" => &[Rule { id: "nuxt-public-secret", level: "error", needle: "public:", message: "Secret-like runtime configuration is placed in Nuxt public config." }, Rule { id: "nuxt-ssr-disabled", level: "note", needle: "ssr: false", message: "SSR is disabled; confirm this matches product and security assumptions." }],
        "angular" => &[Rule { id: "angular-trust-bypass", level: "error", needle: "bypassSecurityTrust", message: "Angular sanitization is explicitly bypassed." }, Rule { id: "angular-inner-html", level: "warning", needle: "[innerHTML]=", message: "Dynamic HTML binding requires trust and sanitization review." }],
        "svelte" => &[Rule { id: "svelte-raw-html", level: "warning", needle: "{@html ", message: "Svelte raw HTML rendering requires sanitization." }],
        "sveltekit" => &[Rule { id: "sveltekit-public-env-secret", level: "error", needle: "/public", message: "Secret-like value is imported through SvelteKit public environment APIs." }, Rule { id: "sveltekit-unvalidated-redirect", level: "warning", needle: "redirect(", message: "Request-controlled data may reach a redirect target." }],
        "express" => &[Rule { id: "express-trust-proxy-all", level: "warning", needle: "trust proxy', true", message: "Express trusts every proxy; verify deployment boundaries." }, Rule { id: "express-open-cors", level: "warning", needle: "origin: '*'", message: "Express CORS appears broadly permissive." }, Rule { id: "express-error-leak", level: "warning", needle: "err.stack", message: "Server error stack may be returned to clients." }],
        "fastify" => &[Rule { id: "fastify-open-cors", level: "warning", needle: "origin: true", message: "Fastify CORS accepts arbitrary origins." }, Rule { id: "fastify-schema-missing", level: "note", needle: ".get(", message: "Route declaration has no visible validation schema." }],
        "nest" => &[Rule { id: "nest-open-cors", level: "warning", needle: "enableCors(", message: "Nest CORS appears broadly permissive." }, Rule { id: "nest-validation-missing-transform", level: "note", needle: "ValidationPipe(", message: "Nest ValidationPipe does not visibly enable transformation." }],
        "electron" => &[Rule { id: "electron-node-integration", level: "error", needle: "nodeIntegration: true", message: "Electron renderer has Node integration enabled." }, Rule { id: "electron-context-isolation", level: "error", needle: "contextIsolation: false", message: "Electron context isolation is disabled." }, Rule { id: "electron-web-security", level: "error", needle: "webSecurity: false", message: "Electron web security is disabled." }, Rule { id: "electron-shell-open-external", level: "warning", needle: "shell.openExternal(", message: "Potentially untrusted URL reaches shell.openExternal." }],
        "django" => &[Rule { id: "django-debug", level: "error", needle: "DEBUG = True", message: "Django DEBUG is enabled in tracked configuration." }, Rule { id: "django-hosts-all", level: "warning", needle: "ALLOWED_HOSTS = [\"*\"]", message: "Django accepts every Host header." }, Rule { id: "django-csrf-exempt", level: "warning", needle: "@csrf_exempt", message: "Django CSRF protection is bypassed for this view." }, Rule { id: "django-mark-safe", level: "warning", needle: "mark_safe(", message: "Django output is explicitly marked safe." }],
        "fastapi" => &[Rule { id: "fastapi-open-cors", level: "warning", needle: "allow_origins = [\"*\"]", message: "FastAPI CORS accepts every origin." }, Rule { id: "fastapi-no-response-model", level: "note", needle: "@app.get(", message: "FastAPI route has no visible response_model contract." }],
        "flask" => &[Rule { id: "flask-debug", level: "error", needle: "debug=True", message: "Flask debug mode is enabled." }, Rule { id: "flask-secret-fallback", level: "high", needle: "SECRET_KEY", message: "Flask secret key has a tracked fallback value." }, Rule { id: "flask-render-template-string", level: "warning", needle: "render_template_string(", message: "Request-controlled data may reach a Jinja template source." }],
        "spring" => &[Rule { id: "spring-csrf-disabled", level: "warning", needle: ".disable(", message: "Spring Security CSRF protection is disabled; prove the application is stateless." }, Rule { id: "spring-sensitive-permit-all", level: "error", needle: ".permitAll(", message: "Sensitive-looking Spring route is configured permitAll." }, Rule { id: "spring-spel-input", level: "error", needle: "parseExpression(", message: "Potentially variable input reaches a SpEL parser." }],
        "ktor" => &[Rule { id: "ktor-any-host", level: "warning", needle: "anyHost()", message: "Ktor CORS permits any host." }, Rule { id: "ktor-forwarded-headers", level: "note", needle: "XForwardedHeaders", message: "Forwarded headers are trusted; verify proxy boundaries." }],
        "rails" => &[Rule { id: "rails-forgery-skip", level: "warning", needle: "skip_forgery_protection", message: "Rails request forgery protection is bypassed." }, Rule { id: "rails-html-safe", level: "warning", needle: ".html_safe", message: "Rails output is explicitly marked HTML-safe." }, Rule { id: "rails-constantize-input", level: "error", needle: ".constantize", message: "Request-controlled value may select a Ruby constant." }],
        "phoenix" => &[Rule { id: "phoenix-check-origin-disabled", level: "warning", needle: "check_origin: false", message: "Phoenix origin checks are disabled." }, Rule { id: "phoenix-raw-html", level: "warning", needle: "raw(", message: "Phoenix template emits raw HTML." }],
        "flutter" => &[Rule { id: "flutter-bad-cert-callback", level: "error", needle: "badCertificateCallback", message: "Flutter/Dart accepts every TLS certificate." }, Rule { id: "flutter-webview-js-unrestricted", level: "warning", needle: "JavaScriptMode.unrestricted", message: "Flutter WebView enables unrestricted JavaScript." }],
        "go-web" => &[Rule { id: "go-http-no-timeouts", level: "warning", needle: "http.Server", message: "Go HTTP server has no visible timeout configuration." }, Rule { id: "go-template-html", level: "warning", needle: "template.HTML(", message: "Potentially untrusted content is cast to trusted template HTML." }],
        "rust-web" => &[Rule { id: "rust-web-unbounded-body", level: "note", needle: "Bytes<", message: "Request body handling should have an explicit size bound." }, Rule { id: "rust-web-command-input", level: "error", needle: "Command::new", message: "Request-derived data may reach a process argument." }],
        _ => &[],
    }
}

fn family_name(dependency: &str) -> Option<&'static str> {
    match dependency.to_ascii_lowercase().as_str() {
        "next" => Some("next"),
        "react" => Some("react"),
        "vue" => Some("vue"),
        "nuxt" => Some("nuxt"),
        "angular" => Some("angular"),
        "svelte" => Some("svelte"),
        "astro" => Some("astro"),
        "remix" => Some("remix"),
        "express" => Some("express"),
        "fastify" => Some("fastify"),
        "django" => Some("django"),
        "flask" => Some("flask"),
        _ => None,
    }
}

fn matches_rule(rule: Rule, text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let needle = rule.needle.to_ascii_lowercase();
    if rule.id == "next-public-secret" {
        return occurrences_ascii_case_insensitive(text, "NEXT_PUBLIC_")
            .iter()
            .any(|offset| {
                let tail = &text[*offset..text.len().min(*offset + 100)].to_ascii_uppercase();
                ["SECRET", "TOKEN", "KEY", "PASSWORD"]
                    .iter()
                    .any(|word| tail.contains(word))
            });
    }
    lower.contains(&needle)
}

pub fn run_framework_suite(input: &ProviderInput<'_>) -> Result<Value, crate::error::AuditError> {
    let selected = denominator(input)?;
    let (files, unreadable) = source_files(input, &selected);
    let mut grouped: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (entry, text) in &files {
        for dependency in &entry.dependencies {
            if let Some(family) = family_name(dependency) {
                grouped
                    .entry(family.into())
                    .or_default()
                    .push((entry.path.clone(), text.clone()));
            }
        }
    }
    let mut families = Vec::new();
    let mut candidates = Vec::new();
    for (family, family_files) in grouped {
        let mut rows = Vec::new();
        for (file, text) in family_files {
            for rule in rules(&family) {
                if matches_rule(*rule, &text) {
                    let line = line_at(
                        &text,
                        occurrences_ascii_case_insensitive(&text, rule.needle)
                            .first()
                            .copied()
                            .unwrap_or(0),
                    );
                    rows.push(json!({"id":digest_text(&format!("{}\0{}\0{}", rule.id, file, line)),"ruleId":rule.id,"severityHint":if matches!(rule.level,"error"|"high"){"high"}else if rule.level=="warning"{"medium"}else{"low"},"claim":rule.message,"file":file,"line":line}));
                }
            }
        }
        candidates.extend(rows.clone());
        families.push(json!({"family":format!("framework.{family}"),"status":if rows.is_empty(){"pass"}else{"candidates"},"complete":unreadable.is_empty(),"candidates":rows,"findings":[]}));
    }
    if families.is_empty() {
        families.push(json!({"status":"unproven","complete":false,"coverageGaps":[{"kind":"framework-denominator-zero"}]}));
    }
    Ok(
        json!({"results":families,"candidates":candidates,"coverageGaps":unreadable.iter().map(|path|json!({"kind":"denominator-file-unreadable","path":path})).collect::<Vec<_>>() }),
    )
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
        ProviderStatus::Complete,
        complete,
        &selected,
        files.len(),
        Vec::new(),
        gaps.clone(),
        gaps,
        details,
    )
}
