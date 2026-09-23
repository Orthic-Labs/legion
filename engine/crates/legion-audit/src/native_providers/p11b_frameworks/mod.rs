//! Packet P11b — the 20 `src/providers/frameworks/*/index.mjs` platform
//! packs not covered by P11 (`p11_frameworks`) or by the pre-existing
//! `native_providers::architecture::{backend,frontend,data}` ports.
//!
//! Each JS pack exports `{ id, version, detect({projection}), analyze({files,readFile}) }`
//! and emits `{ ruleId, severityHint, claim, file }` observations from
//! deterministic regex rules over file contents. This module is a faithful,
//! read-only structural port: one submodule per framework, each with a
//! `detect` and `analyze` function plus the shared `Observation` type below.
//!
//! The JS source uses a handful of negative lookaheads
//! (`(?!...)`), which the `regex` crate does not support. Those rules are
//! reimplemented with explicit substring scans that reproduce the same
//! semantics (see `fastapi`, `next`, and `react` submodules) rather than
//! silently dropped or approximated with a different rule.
//!
//! Not yet wired into `NativeProviderRegistry::execute` dispatch — see
//! `full-P11b.md` for the integration patch this packet leaves for the
//! `native_providers::mod` owner.

use regex::Regex;

/// One structural finding, mirroring the JS `{ ruleId, severityHint, claim, file }` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub rule_id: &'static str,
    pub severity_hint: &'static str,
    pub claim: &'static str,
    pub file: String,
}

fn obs(rule_id: &'static str, severity_hint: &'static str, claim: &'static str, file: &str) -> Observation {
    Observation { rule_id, severity_hint, claim, file: file.to_string() }
}

/// `projection?.auditFacts?.packageManifests` as JSON-stringified entries
/// (mirrors `JSON.stringify(m)` used throughout the JS packs for substring
/// or regex matching against manifest contents).
pub type Manifests<'a> = &'a [String];

fn manifest_matches(manifests: Manifests, re: &Regex) -> bool {
    manifests.iter().any(|m| re.is_match(m))
}

fn manifest_includes(manifests: Manifests, needle: &str) -> bool {
    manifests.iter().any(|m| m.contains(needle))
}

/// `(files, readFile)` as already-materialized `(path, content)` pairs —
/// this port takes ownership of file reading upstream of these pure
/// analyzers, exactly as `native_providers::architecture` does.
pub type FileText<'a> = &'a [(String, String)];

// ---------------------------------------------------------------------
// apple/index.mjs
// ---------------------------------------------------------------------
pub mod apple {
    use super::*;

    pub fn detect(files: &[String]) -> bool {
        let swift_re = Regex::new(r"\.(swift|m|mm)$").unwrap();
        let plist_re = Regex::new(r"(\.entitlements|Info\.plist|\.xcodeproj)").unwrap();
        files.iter().any(|f| swift_re.is_match(f)) || files.iter().any(|f| plist_re.is_match(f))
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let ats_disabled = Regex::new(r"NSAllowsArbitraryLoads\s*=\s*true").unwrap();
        let ats_disabled_plist = Regex::new(r"NSAllowsArbitraryLoads</key>\s*<true/>").unwrap();
        let ats_webview = Regex::new(r#"NSAllowsArbitraryLoadsInWebContent["']?\s*[:=]\s*true"#).unwrap();
        let webview_js = Regex::new(r"UIWebView\b|WKWebView[\s\S]{0,200}?javaScriptEnabled\s*=\s*true").unwrap();
        let oauth_cb = Regex::new(r#"https?://[^"']*//(?:callback|oauth|auth)"#).unwrap();
        let oauth_guard = Regex::new(r"state|pkce|code_verifier").unwrap();
        let storage_sensitive =
            Regex::new(r"UserDefaults\.standard\.set\s*\([^)]*(?:token|secret|key)").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if ats_disabled.is_match(text) || ats_disabled_plist.is_match(text) {
                out.push(obs("apple.ats-disabled", "high", "ATS (arbitrary loads) is disabled.", file));
            }
            if ats_webview.is_match(text) {
                out.push(obs("apple.ats-webview", "medium", "ATS disabled in WebView content.", file));
            }
            if webview_js.is_match(text) {
                out.push(obs(
                    "apple.webview-js",
                    "medium",
                    "WebView enables JavaScript without visible boundary.",
                    file,
                ));
            }
            if oauth_cb.is_match(text) && !oauth_guard.is_match(text) {
                out.push(obs(
                    "apple.oauth-callback",
                    "medium",
                    "OAuth callback without visible state/PKCE.",
                    file,
                ));
            }
            if storage_sensitive.is_match(text) {
                out.push(obs(
                    "apple.storage-sensitive",
                    "high",
                    "Sensitive value stored in UserDefaults.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// aspnet/index.mjs
// ---------------------------------------------------------------------
pub mod aspnet {
    use super::*;

    pub fn detect(manifests: Manifests, files: &[String]) -> bool {
        let re = Regex::new(r"(?i)aspnet|microsoft\.aspnetcore").unwrap();
        manifest_matches(manifests, &re) || files.iter().any(|f| f.ends_with(".csproj"))
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let cors_origin = Regex::new(r"AllowAnyOrigin\s*\(\s*\)").unwrap();
        let cors_creds = Regex::new(r"AllowCredentials\s*\(\s*\)").unwrap();
        let authorize = Regex::new(r"\[Authorize\]").unwrap();
        let http_verb = Regex::new(r"Http(Get|Post|Put|Delete)\s*\]").unwrap();
        let sensitive = Regex::new(r"(?i)admin|internal").unwrap();
        let dev_exception = Regex::new(r"\.UseDeveloperExceptionPage\s*\(\s*\)").unwrap();
        let bind = Regex::new(r"Bind\s*\([^)]*\)").unwrap();
        let antiforgery = Regex::new(r"\[ValidateAntiForgeryToken\]").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if !file.ends_with(".cs") {
                continue;
            }
            if cors_origin.is_match(text) || cors_creds.is_match(text) {
                out.push(obs("aspnet.cors-permissive", "medium", "CORS is broadly permissive.", file));
            }
            if !authorize.is_match(text) && http_verb.is_match(text) && sensitive.is_match(text) {
                out.push(obs(
                    "aspnet.sensitive-route-no-auth",
                    "high",
                    "Sensitive endpoint lacks [Authorize].",
                    file,
                ));
            }
            if dev_exception.is_match(text) {
                out.push(obs(
                    "aspnet.developer-exception-page",
                    "high",
                    "Developer exception page is enabled.",
                    file,
                ));
            }
            if bind.is_match(text) && !antiforgery.is_match(text) {
                out.push(obs(
                    "aspnet.unvalidated-bind",
                    "medium",
                    "Model binding without visible anti-forgery validation.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// django/index.mjs
// ---------------------------------------------------------------------
pub mod django {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        manifest_includes(manifests, "django")
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let debug_true = Regex::new(r"(?m)^\s*DEBUG\s*=\s*True\b").unwrap();
        let allowed_hosts = Regex::new(r#"(?m)^\s*ALLOWED_HOSTS\s*=\s*\[[^\]]*['"]\*['"]"#).unwrap();
        let csrf_exempt = Regex::new(r"@csrf_exempt\b").unwrap();
        let mark_safe = Regex::new(r"\bmark_safe\s*\(").unwrap();
        let raw_fstring = Regex::new(r#"\.raw\s*\(\s*f["']"#).unwrap();
        let extra_where = Regex::new(r"\.extra\s*\(\s*where\s*=").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if debug_true.is_match(text) {
                out.push(obs("django.settings.debug", "high", "Django DEBUG is enabled.", file));
            }
            if allowed_hosts.is_match(text) {
                out.push(obs(
                    "django.settings.hosts-all",
                    "medium",
                    "ALLOWED_HOSTS accepts every host.",
                    file,
                ));
            }
            if csrf_exempt.is_match(text) {
                out.push(obs("django.csrf-exempt", "medium", "CSRF protection bypassed for this view.", file));
            }
            if mark_safe.is_match(text) {
                out.push(obs("django.output-mark-safe", "medium", "Output explicitly marked safe.", file));
            }
            if raw_fstring.is_match(text) || extra_where.is_match(text) {
                out.push(obs("django.orm.raw-sql", "high", "Raw SQL with interpolated input.", file));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// entity-framework/index.mjs
// ---------------------------------------------------------------------
pub mod entity_framework {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        let re = Regex::new(r"(?i)entityframework|microsoft\.entityframework").unwrap();
        manifest_matches(manifests, &re)
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let raw_sql1 = Regex::new(r#"FromSqlRaw\s*\([^)]*(?:\$|f"|\+)"#).unwrap();
        let raw_sql2 = Regex::new(r"ExecuteSqlRaw\s*\([^)]*\+").unwrap();
        let query = Regex::new(r"\.(?:Where|FirstOrDefault|ToList|SingleOrDefault)\s*\(").unwrap();
        let tenant = Regex::new(r"(?i)tenant|workspace|org_?id").unwrap();
        let save = Regex::new(r"\.SaveChangesAsync?\s*\(").unwrap();
        let txn = Regex::new(r"BeginTransaction|TransactionScope").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if !file.ends_with(".cs") {
                continue;
            }
            if raw_sql1.is_match(text) || raw_sql2.is_match(text) {
                out.push(obs("ef.raw-sql-interpolation", "high", "Raw SQL with interpolated input.", file));
            }
            if query.is_match(text) && !tenant.is_match(text) {
                out.push(obs(
                    "ef.missing-tenant-filter",
                    "medium",
                    "EF query has no visible tenant filter.",
                    file,
                ));
            }
            if save.is_match(text) && !txn.is_match(text) {
                out.push(obs("ef.no-transaction", "low", "Save without a visible transaction.", file));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// fastapi/index.mjs
// ---------------------------------------------------------------------
pub mod fastapi {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        manifest_includes(manifests, "fastapi")
    }

    /// JS: `/@(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^\n]*\)\s*\n(?:async\s+)?def\s+[^\n]*\n(?![\s\S]{0,300}response_model)/`
    /// — a route decorator + def line not followed by `response_model` within 300 chars.
    /// Reimplemented as an explicit scan since `regex` has no lookahead.
    fn route_missing_response_model(text: &str) -> bool {
        let route_def = Regex::new(
            r"(?m)@(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^\n]*\)\s*\n(?:async\s+)?def\s+[^\n]*\n",
        )
        .unwrap();
        for m in route_def.find_iter(text) {
            let tail_start = m.end();
            let tail_end = (tail_start + 300).min(text.len());
            let tail = &text[tail_start..tail_end];
            if !tail.contains("response_model") {
                return true;
            }
        }
        false
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let cors_all = Regex::new(r#"allow_origins\s*=\s*\[[^\]]*['"]\*['"]"#).unwrap();
        let bg_task = Regex::new(r"BackgroundTasks\b[\s\S]{0,300}?add_task\s*\([^\n]*(?:request|input|user)")
            .unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if cors_all.is_match(text) {
                out.push(obs("fastapi.cors-all-origins", "medium", "CORS accepts every origin.", file));
            }
            if route_missing_response_model(text) {
                out.push(obs(
                    "fastapi.no-response-model",
                    "low",
                    "Route has no visible response_model contract.",
                    file,
                ));
            }
            if bg_task.is_match(text) {
                out.push(obs(
                    "fastapi.background-task-input",
                    "medium",
                    "Background task consumes request-derived input.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// flask/index.mjs
// ---------------------------------------------------------------------
pub mod flask {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        manifest_includes(manifests, "flask")
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let debug = Regex::new(r"app\.run\s*\([^)]*debug\s*=\s*True").unwrap();
        let secret_fallback = Regex::new(
            r#"(?:secret_key|SECRET_KEY)['"]?\s*\]?\s*=\s*(?:os\.environ\.get\([^)]*\)\s+or\s+)?['"][^'"]+['"]"#,
        )
        .unwrap();
        let template_input =
            Regex::new(r"render_template_string\s*\([^\n]*(?:request|input|user)").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if debug.is_match(text) {
                out.push(obs("flask.debug-enabled", "high", "Flask debug mode is enabled.", file));
            }
            if secret_fallback.is_match(text) {
                out.push(obs("flask.secret-fallback", "high", "Secret key has a tracked fallback value.", file));
            }
            if template_input.is_match(text) {
                out.push(obs(
                    "flask.template-string-input",
                    "high",
                    "Request-controlled data reaches a Jinja template source.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// flutter/index.mjs
// ---------------------------------------------------------------------
pub mod flutter {
    use super::*;

    pub fn detect(manifests: Manifests, files: &[String]) -> bool {
        let dart_re = Regex::new(r"\.dart$").unwrap();
        let flutter_re = Regex::new(r"(?i)flutter").unwrap();
        files.iter().any(|f| dart_re.is_match(f)) && manifest_matches(manifests, &flutter_re)
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let bad_cert = Regex::new(r"badCertificateCallback\s*[:=]\s*[\s\S]{0,80}?=>\s*true").unwrap();
        let js_unrestricted = Regex::new(r"JavaScriptMode\.unrestricted").unwrap();
        let method_channel = Regex::new(r"MethodChannel\s*\([^)]*\)").unwrap();
        let channel_handler = Regex::new(r"invokeMethod|setMethodCallHandler").unwrap();
        let shared_prefs = Regex::new(r"SharedPreferences|shared_preferences").unwrap();
        let sensitive = Regex::new(r"(?i)token|secret|password").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if !file.ends_with(".dart") {
                continue;
            }
            if bad_cert.is_match(text) {
                out.push(obs("flutter.bad-cert-callback", "high", "All TLS certificates accepted.", file));
            }
            if js_unrestricted.is_match(text) {
                out.push(obs(
                    "flutter.webview-js-unrestricted",
                    "medium",
                    "WebView enables unrestricted JavaScript.",
                    file,
                ));
            }
            if method_channel.is_match(text) && !channel_handler.is_match(text) {
                out.push(obs(
                    "flutter.unscoped-channel",
                    "low",
                    "Platform channel without visible handler.",
                    file,
                ));
            }
            if shared_prefs.is_match(text) && sensitive.is_match(text) {
                out.push(obs(
                    "flutter.storage-sensitive",
                    "high",
                    "Sensitive value stored in SharedPreferences.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// go-web/index.mjs
// ---------------------------------------------------------------------
pub mod go_web {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        let re = Regex::new(r"(?i)gin|echo|fiber|chi").unwrap();
        manifest_matches(manifests, &re)
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let http_server = Regex::new(r"http\.Server\s*\{").unwrap();
        let timeouts = Regex::new(r"ReadHeaderTimeout|ReadTimeout|WriteTimeout|IdleTimeout").unwrap();
        let body = Regex::new(r"r\.Body|http\.MaxBytesReader").unwrap();
        let bound = Regex::new(r"MaxBytesReader|io\.LimitReader").unwrap();
        let exec_cmd = Regex::new(r"exec\.Command(?:Context)?\s*\([^)]*\)").unwrap();
        let req_input = Regex::new(r"r\.(?:FormValue|URL|Header)|request|req\.").unwrap();
        let file_sink = Regex::new(r"os\.(?:OpenFile|WriteFile|Create)\s*\(").unwrap();
        let req_input2 = Regex::new(r"r\.(?:FormValue|URL|Header)|request").unwrap();
        let route = Regex::new(r"(?:r|router|e|app)\.(?:GET|POST|PUT|DELETE|PATCH)\s*\(").unwrap();
        let auth = Regex::new(r"(?i)auth|middleware|jwt").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if !file.ends_with(".go") {
                continue;
            }
            if http_server.is_match(text) && !timeouts.is_match(text) {
                out.push(obs(
                    "go-web.http-no-timeouts",
                    "medium",
                    "HTTP server has no visible timeout configuration.",
                    file,
                ));
            }
            if body.is_match(text) && !bound.is_match(text) {
                out.push(obs(
                    "go-web.unbounded-body",
                    "medium",
                    "Request body has no visible size bound.",
                    file,
                ));
            }
            if exec_cmd.is_match(text) && req_input.is_match(text) {
                out.push(obs(
                    "go-web.command-input",
                    "high",
                    "Request-derived data may reach a process argument.",
                    file,
                ));
            }
            if file_sink.is_match(text) && req_input2.is_match(text) {
                out.push(obs(
                    "go-web.file-sink-input",
                    "high",
                    "Request-derived data reaches a file sink.",
                    file,
                ));
            }
            if route.is_match(text) && !auth.is_match(text) {
                out.push(obs("go-web.route-no-auth", "medium", "Route has no visible auth middleware.", file));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// grpc/index.mjs
// ---------------------------------------------------------------------
pub mod grpc {
    use super::*;

    pub fn detect(manifests: Manifests, files: &[String]) -> bool {
        let re = Regex::new(r"(?i)grpc|protobuf").unwrap();
        manifest_matches(manifests, &re) || files.iter().any(|f| f.ends_with(".proto"))
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let service = Regex::new(r"service\s+\w+\s*\{").unwrap();
        let auth = Regex::new(r"(?i)auth|interceptor|metadata").unwrap();
        let new_server = Regex::new(r"grpc\.NewServer\s*\(").unwrap();
        let limits = Regex::new(r"KeepaliveParams|EnforcementPolicy|MaxRecvMsgSize").unwrap();
        let streaming = Regex::new(r"rpc\s+\w+\s*\(\s*stream|stream\s+\w+\s*\)\s*(?:returns)?").unwrap();
        let flow_control = Regex::new(r"MaxRecvMsgSize|recv\(\)").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if service.is_match(text) && !auth.is_match(text) {
                out.push(obs("grpc.service-no-auth", "medium", "gRPC service has no visible auth interceptor.", file));
            }
            if new_server.is_match(text) && !limits.is_match(text) {
                out.push(obs(
                    "grpc.server-no-limits",
                    "medium",
                    "gRPC server has no visible limit/deadline configuration.",
                    file,
                ));
            }
            if streaming.is_match(text) && !flow_control.is_match(text) {
                out.push(obs(
                    "grpc.unbounded-stream",
                    "low",
                    "Streaming RPC has no visible flow control.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// ktor/index.mjs
// ---------------------------------------------------------------------
pub mod ktor {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        let re = Regex::new(r"(?i)ktor").unwrap();
        manifest_matches(manifests, &re)
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let any_host = Regex::new(r"anyHost\s*\(\s*\)").unwrap();
        let forwarded = Regex::new(r"XForwardedHeaders").unwrap();
        let sensitive_route =
            Regex::new(r#"route\s*\(\s*["'][^"']*(?:admin|internal|api/admin)"#).unwrap();
        let guard = Regex::new(r"authenticate|validate|session").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if any_host.is_match(text) {
                out.push(obs("ktor.cors-any-host", "medium", "CORS permits any host.", file));
            }
            if forwarded.is_match(text) {
                out.push(obs(
                    "ktor.forwarded-headers",
                    "low",
                    "Forwarded headers trusted; verify proxy boundaries.",
                    file,
                ));
            }
            if sensitive_route.is_match(text) && !guard.is_match(text) {
                out.push(obs(
                    "ktor.sensitive-route-no-auth",
                    "high",
                    "Sensitive route has no visible auth.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// laravel/index.mjs
// ---------------------------------------------------------------------
pub mod laravel {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        let re = Regex::new(r"(?i)laravel").unwrap();
        manifest_matches(manifests, &re)
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let raw_sql = Regex::new(r"DB::(?:select|statement|unprepared)\s*\([^)]*(\$|\.)").unwrap();
        let unescaped_blade = Regex::new(r"\{!![^!]*\$[^!]*!!\}").unwrap();
        let mass_assign =
            Regex::new(r"(?:Model::|\w+::create|\w+::update|->fill)\s*\([^)]*(?:request|input)").unwrap();
        let guard = Regex::new(r"fillable|guarded").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if raw_sql.is_match(text) {
                out.push(obs("laravel.raw-sql-interpolation", "high", "Raw SQL with interpolated input.", file));
            }
            if unescaped_blade.is_match(text) {
                out.push(obs("laravel.unescaped-blade", "medium", "Unescaped Blade output.", file));
            }
            if mass_assign.is_match(text) && !guard.is_match(text) {
                out.push(obs(
                    "laravel.mass-assignment",
                    "medium",
                    "Mass assignment without visible fillable/guarded.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// next/index.mjs
// ---------------------------------------------------------------------
pub mod next {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        manifest_includes(manifests, "next")
    }

    /// JS: `/fetch\s*\([^)]*\)(?![\s\S]{0,200}next:\s*\{[\s\S]{0,60}revalidate)/`
    fn fetch_unbounded_revalidate(text: &str) -> bool {
        let fetch_call = Regex::new(r"fetch\s*\([^)]*\)").unwrap();
        let revalidate = Regex::new(r"next:\s*\{[\s\S]{0,60}?revalidate").unwrap();
        for m in fetch_call.find_iter(text) {
            let tail_end = (m.end() + 200).min(text.len());
            if !revalidate.is_match(&text[m.end()..tail_end]) {
                return true;
            }
        }
        false
    }

    /// JS: `/<Image\b(?![\s\S]{0,200}(?:width|height|fill)\s*=)/`
    fn image_unbounded(text: &str) -> bool {
        let image_tag = Regex::new(r"<Image\b").unwrap();
        let dims = Regex::new(r"(?:width|height|fill)\s*=").unwrap();
        for m in image_tag.find_iter(text) {
            let tail_end = (m.end() + 200).min(text.len());
            if !dims.is_match(&text[m.end()..tail_end]) {
                return true;
            }
        }
        false
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let ext_re = Regex::new(r"\.(js|ts|jsx|tsx)$").unwrap();
        let handler = Regex::new(
            r"(?:export\s+async\s+function\s+\w+\s*\([^)]*\)|export\s+const\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*(?:=>)?\s*\{)",
        )
        .unwrap();
        let params = Regex::new(r"params|searchParams").unwrap();
        let auth = Regex::new(r"auth|session|getServerSession|requireAuth").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if !ext_re.is_match(file) {
                continue;
            }
            if handler.is_match(text) && params.is_match(text) && !auth.is_match(text) {
                out.push(obs(
                    "next.route.missing-auth",
                    "high",
                    "A route handler consumes request parameters without visible authentication.",
                    file,
                ));
            }
            if fetch_unbounded_revalidate(text) {
                out.push(obs(
                    "next.cache.unbounded-revalidate",
                    "medium",
                    "A fetch has no visible revalidation policy.",
                    file,
                ));
            }
            if image_unbounded(text) {
                out.push(obs(
                    "next.image.unbounded",
                    "low",
                    "next/image lacks explicit dimensions or fill.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// rails/index.mjs
// ---------------------------------------------------------------------
pub mod rails {
    use super::*;

    pub fn detect(manifests: Manifests, files: &[String]) -> bool {
        let re = Regex::new(r"(?i)rails").unwrap();
        let gemfile_re = Regex::new(r"(Gemfile|\.gemspec)$").unwrap();
        manifest_matches(manifests, &re) || files.iter().any(|f| gemfile_re.is_match(f))
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let forgery_bypass = Regex::new(
            r"skip_(?:before_action|before_filter)\s+:verify_authenticity_token|skip_forgery_protection",
        )
        .unwrap();
        let raw_html = Regex::new(r"\.html_safe\b|raw\s*\(").unwrap();
        let constantize = Regex::new(r"\.constantize\b").unwrap();
        let params_request = Regex::new(r"params|request").unwrap();
        let where_params = Regex::new(r"\.where\s*\([^)]*params").unwrap();
        let strong_params = Regex::new(r"strong_params|permit").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if forgery_bypass.is_match(text) {
                out.push(obs("rails.forgery-bypass", "medium", "Request forgery protection bypassed.", file));
            }
            if raw_html.is_match(text) {
                out.push(obs("rails.raw-html", "medium", "Output marked HTML-safe.", file));
            }
            if constantize.is_match(text) && params_request.is_match(text) {
                out.push(obs(
                    "rails.constantize-input",
                    "high",
                    "Request-controlled value selects a constant.",
                    file,
                ));
            }
            if where_params.is_match(text) && !strong_params.is_match(text) {
                out.push(obs(
                    "rails.mass-assignment-query",
                    "medium",
                    "Query built from raw params without visible permitting.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// react-native/index.mjs
// ---------------------------------------------------------------------
pub mod react_native {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        let re = Regex::new(r"(?i)react-native|expo").unwrap();
        manifest_matches(manifests, &re)
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let open_url = Regex::new(r"Linking\.openURL\s*\([^)]*(?:url|input|request)").unwrap();
        let open_url_guard = Regex::new(r"canOpenURL|allowlist").unwrap();
        let bridge = Regex::new(r"NativeModules\.|requireNativeComponent\s*\(").unwrap();
        let bridge_guard = Regex::new(r"checkPermissions|hasPermission").unwrap();
        let storage = Regex::new(r"AsyncStorage|MMKV").unwrap();
        let sensitive = Regex::new(r"(?i)token|secret|password").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if open_url.is_match(text) && !open_url_guard.is_match(text) {
                out.push(obs(
                    "react-native.openurl-unvalidated",
                    "high",
                    "External URL opened without visible validation.",
                    file,
                ));
            }
            if bridge.is_match(text) && !bridge_guard.is_match(text) {
                out.push(obs(
                    "react-native.unscoped-bridge",
                    "medium",
                    "Native bridge without visible permission check.",
                    file,
                ));
            }
            if storage.is_match(text) && sensitive.is_match(text) {
                out.push(obs(
                    "react-native.storage-sensitive",
                    "high",
                    "Sensitive value in async local storage.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// react/index.mjs
// ---------------------------------------------------------------------
pub mod react {
    use super::*;
    use serde_json::Value;

    const REACT_PACKAGES: [&str; 2] = ["react", "react-dom"];

    fn record_name(item: &Value) -> String {
        match item {
            Value::String(s) => s.to_lowercase(),
            _ => item
                .get("name")
                .or_else(|| item.get("id"))
                .or_else(|| item.get("framework"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase(),
        }
    }

    fn blueprint_record_selects_react(record: &Value) -> bool {
        match record {
            Value::Array(items) => items.iter().any(|item| REACT_PACKAGES.contains(&record_name(item).as_str())),
            Value::Object(map) => map.iter().any(|(name, item)| {
                REACT_PACKAGES.contains(&name.to_lowercase().as_str())
                    || REACT_PACKAGES.contains(&record_name(item).as_str())
            }),
            _ => false,
        }
    }

    fn manifest_declares_react(manifest: &Value) -> bool {
        let lists = [
            manifest.get("dependencies"),
            manifest.get("devDependencies"),
            manifest.get("peerDependencies"),
            manifest.get("optionalDependencies"),
        ];
        for list in lists.into_iter().flatten() {
            if let Value::Array(items) = list {
                if items.iter().any(|v| matches!(v.as_str(), Some(s) if REACT_PACKAGES.contains(&s))) {
                    return true;
                }
            }
            if let Value::Object(map) = list {
                if map.keys().any(|k| REACT_PACKAGES.contains(&k.as_str())) {
                    return true;
                }
            }
        }
        false
    }

    /// `projection` here is a plain `serde_json::Value` mirroring the JS object shape
    /// (`frameworks`/`blueprint.frameworks`, `selectedFrameworks`/`auditFacts.selectedFrameworks`,
    /// `auditFacts.nestedPackageManifests`/`auditFacts.workspaceManifests`).
    fn blueprint_selects_nested_react(projection: &Value) -> bool {
        let frameworks = projection
            .get("frameworks")
            .or_else(|| projection.get("blueprint").and_then(|b| b.get("frameworks")));
        if let Some(f) = frameworks {
            if blueprint_record_selects_react(f) {
                return true;
            }
        }
        let hints = projection
            .get("selectedFrameworks")
            .or_else(|| projection.get("auditFacts").and_then(|a| a.get("selectedFrameworks")));
        if let Some(Value::Array(items)) = hints {
            if items.iter().any(|item| REACT_PACKAGES.contains(&record_name(item).as_str())) {
                return true;
            }
        }
        let nested = projection.get("auditFacts").and_then(|a| {
            a.get("nestedPackageManifests").or_else(|| a.get("workspaceManifests"))
        });
        if let Some(Value::Array(items)) = nested {
            if items.iter().any(manifest_declares_react) {
                return true;
            }
        }
        false
    }

    pub fn detect(manifests: Manifests, projection: &Value) -> bool {
        if manifests.iter().any(|m| m.contains("react")) {
            return true;
        }
        blueprint_selects_nested_react(projection)
    }

    /// JS: `/useEffect\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,600}?\}\s*\)(?!\s*,\s*\[)/`
    fn effect_missing_deps(text: &str) -> bool {
        let re = Regex::new(r"useEffect\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,600}?\}\s*\)").unwrap();
        let followed_by_deps = Regex::new(r"^\s*,\s*\[").unwrap();
        for m in re.find_iter(text) {
            let tail_end = text.len().min(m.end() + 32);
            if !followed_by_deps.is_match(&text[m.end()..tail_end]) {
                return true;
            }
        }
        false
    }

    /// JS: `/<img\b(?![\s\S]{0,200}alt=)/`
    fn img_missing_alt(text: &str) -> bool {
        let img_tag = Regex::new(r"<img\b").unwrap();
        let alt = Regex::new(r"alt=").unwrap();
        for m in img_tag.find_iter(text) {
            let tail_end = (m.end() + 200).min(text.len());
            if !alt.is_match(&text[m.end()..tail_end]) {
                return true;
            }
        }
        false
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let ext_re = Regex::new(r"\.(jsx|tsx|js|ts)$").unwrap();
        let conditional_hook =
            Regex::new(r"if\s*\([^)]*\)\s*\{\s*(?:useState|useEffect|useMemo|useCallback)\s*\(").unwrap();
        let dangerous_html = Regex::new(r"dangerouslySetInnerHTML\s*=").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if !ext_re.is_match(file) {
                continue;
            }
            if conditional_hook.is_match(text) {
                out.push(obs(
                    "react.hooks.conditional-call",
                    "high",
                    "A React hook is called conditionally, violating the rules of hooks.",
                    file,
                ));
            }
            if effect_missing_deps(text) {
                out.push(obs(
                    "react.effects.missing-deps",
                    "medium",
                    "useEffect is called without a dependency array.",
                    file,
                ));
            }
            if img_missing_alt(text) {
                out.push(obs("react.a11y.img-alt", "medium", "An img element has no alt attribute.", file));
            }
            if dangerous_html.is_match(text) {
                out.push(obs(
                    "react.security.dangerous-html",
                    "high",
                    "Raw HTML rendering requires a proven sanitization boundary.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// spring/index.mjs
// ---------------------------------------------------------------------
pub mod spring {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        let re = Regex::new(r"(?i)spring").unwrap();
        manifest_matches(manifests, &re)
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let csrf_disabled = Regex::new(
            r"(?s)csrf\s*\([^)]*\)\s*\.disable\s*\(|csrf\s*\{[^}]*disable\s*\(|csrf\s*\([^)]*csrf\s*\.disable\s*\(",
        )
        .unwrap();
        let sensitive_permit_all = Regex::new(
            r"(?is)requestMatchers\s*\([^)]*(?:admin|internal|actuator)[^)]*\)\s*\.permitAll\s*\(",
        )
        .unwrap();
        let spel_input = Regex::new(
            r"SpelExpressionParser[\s\S]{0,500}?parseExpression\s*\(\s*(?:request|input|value|expression)",
        )
        .unwrap();
        let request_param = Regex::new(r"@RequestParam\s*\([^)]*\)").unwrap();
        let valid = Regex::new(r"valid|@Valid").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if csrf_disabled.is_match(text) {
                out.push(obs("spring.csrf-disabled", "medium", "Spring Security CSRF is disabled.", file));
            }
            if sensitive_permit_all.is_match(text) {
                out.push(obs("spring.sensitive-permit-all", "high", "Sensitive route is permitAll.", file));
            }
            if spel_input.is_match(text) {
                out.push(obs("spring.spel-input", "high", "Variable input reaches a SpEL parser.", file));
            }
            if request_param.is_match(text) && !valid.is_match(text) {
                out.push(obs(
                    "spring.unvalidated-param",
                    "medium",
                    "Request parameter lacks visible validation.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// sqlalchemy/index.mjs
// ---------------------------------------------------------------------
pub mod sqlalchemy {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        manifest_includes(manifests, "sqlalchemy")
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let raw_text = Regex::new(r#"text\s*\(\s*f["']"#).unwrap();
        let raw_exec = Regex::new(r#"execute\s*\(\s*f["']"#).unwrap();
        let query = Regex::new(r"\.query\s*\([^)]*\)\s*\.(?:filter|all|first)\s*\(").unwrap();
        let tenant = Regex::new(r"(?i)tenant|workspace|org_?id").unwrap();
        let commit = Regex::new(r"\bsession\.commit\s*\(").unwrap();
        let txn_boundary = Regex::new(r"(?i)begin|transaction").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if raw_text.is_match(text) || raw_exec.is_match(text) {
                out.push(obs(
                    "sqlalchemy.raw-sql-interpolation",
                    "high",
                    "Raw SQL text with interpolated input.",
                    file,
                ));
            }
            if query.is_match(text) && !tenant.is_match(text) {
                out.push(obs(
                    "sqlalchemy.missing-tenant-filter",
                    "medium",
                    "Query has no visible tenant filter.",
                    file,
                ));
            }
            // JS: `!begin|transaction.test(text.slice(0, text.indexOf('session.commit')))`
            // — checked against the text BEFORE the first `session.commit` occurrence.
            if commit.is_match(text) {
                let prefix_end = text.find("session.commit").unwrap_or(0);
                let prefix = &text[..prefix_end];
                if !txn_boundary.is_match(prefix) {
                    out.push(obs(
                        "sqlalchemy.transaction-boundary",
                        "low",
                        "Commit without a visible transaction boundary.",
                        file,
                    ));
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// symfony/index.mjs
// ---------------------------------------------------------------------
pub mod symfony {
    use super::*;

    pub fn detect(manifests: Manifests) -> bool {
        let re = Regex::new(r"(?i)symfony").unwrap();
        manifest_matches(manifests, &re)
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let untrusted_bind = Regex::new(r"->bind\s*\([^)]*(?:request|input)").unwrap();
        let sensitive_route = Regex::new(
            r"access_control\s*:\s*\[[^\]]*path:\s*\^(?:/admin|/internal)",
        )
        .unwrap();
        let role_gate = Regex::new(r"role:\s*ROLE_ADMIN").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if untrusted_bind.is_match(text) {
                out.push(obs(
                    "symfony.untrusted-bind",
                    "medium",
                    "Request-derived data bound without visible validation.",
                    file,
                ));
            }
            if sensitive_route.is_match(text) && !role_gate.is_match(text) {
                out.push(obs(
                    "symfony.sensitive-route-no-role",
                    "high",
                    "Sensitive route has no visible role gate.",
                    file,
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// tauri/index.mjs
// ---------------------------------------------------------------------
pub mod tauri {
    use super::*;

    pub fn detect(files: &[String]) -> bool {
        let re = Regex::new(r"tauri\.conf\.(json|json5)$|Tauri\.toml$").unwrap();
        files.iter().any(|f| re.is_match(f))
    }

    /// JS: `/devUrl["']?\s*[:=]\s*["'](?!https?:)/` — a `devUrl` assignment
    /// whose quoted value does not start with `http:`/`https:`.
    fn non_http_dev_url(text: &str) -> bool {
        let prefix = Regex::new(r#"devUrl["']?\s*[:=]\s*["']"#).unwrap();
        let http_prefix = Regex::new(r"^https?:").unwrap();
        for m in prefix.find_iter(text) {
            if !http_prefix.is_match(&text[m.end()..]) {
                return true;
            }
        }
        false
    }

    pub fn analyze(files: FileText) -> Vec<Observation> {
        let insecure_transport =
            Regex::new(r#"dangerousInsecureTransportProtocol["']?\s*[:=]\s*true"#).unwrap();
        let shell_open_all = Regex::new(r#""shell"\s*:\s*\{\s*"open"\s*:\s*true"#).unwrap();
        let capability_file = Regex::new(r"(?:capabilities?/|capabilities?\.json)").unwrap();
        let fs_broad_scope = Regex::new(r#""fs"\s*:\s*\{[\s\S]{0,300}?"scope"\s*:\s*\["\*\*""#).unwrap();
        let sidecar = Regex::new(r#""sidecar"\s*:\s*true"#).unwrap();
        let updater = Regex::new(r#"updater["']?\s*[:=]"#).unwrap();
        let signature = Regex::new(r"pubkey|signature|key").unwrap();

        let mut out = Vec::new();
        for (file, text) in files {
            if insecure_transport.is_match(text) {
                out.push(obs(
                    "tauri.updater.insecure-transport",
                    "high",
                    "Updater permits insecure transport.",
                    file,
                ));
            }
            if non_http_dev_url(text) {
                out.push(obs("tauri.window.non-http-dev-url", "medium", "Dev URL is not http(s).", file));
            }
            if shell_open_all.is_match(text) {
                out.push(obs("tauri.shell.open-all", "medium", "shell.open is broadly enabled.", file));
            }
            if capability_file.is_match(file) && fs_broad_scope.is_match(text) {
                out.push(obs(
                    "tauri.fs.broad-scope",
                    "medium",
                    "Filesystem scope is broadly permissive.",
                    file,
                ));
            }
            if sidecar.is_match(text) {
                out.push(obs("tauri.sidecar-enabled", "low", "Sidecar binary execution is enabled.", file));
            }
            if updater.is_match(text) && !signature.is_match(text) {
                out.push(obs(
                    "tauri.updater.no-signature",
                    "high",
                    "Updater has no visible signature verification.",
                    file,
                ));
            }
        }
        out
    }
}
