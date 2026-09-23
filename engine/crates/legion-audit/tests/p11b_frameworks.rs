//! CI tests for Packet P11b — the 20 `frameworks/*/index.mjs` platform packs
//! ported to `native_providers::p11b_frameworks`. Run with:
//!   cargo test --manifest-path engine/Cargo.toml -p legion-audit --test p11b_frameworks

use legion_audit::native_providers::p11b_frameworks::*;

fn files(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect()
}

fn manifests(strs: &[&str]) -> Vec<String> {
    strs.iter().map(|s| s.to_string()).collect()
}

#[test]
fn apple_detects_and_flags_ats_disabled() {
    assert!(apple::detect(&["App.swift".into()]));
    assert!(!apple::detect(&["main.rs".into()]));
    let f = files(&[("Info.plist", "<key>NSAllowsArbitraryLoads</key>\n<true/>")]);
    let out = apple::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "apple.ats-disabled"));
}

#[test]
fn apple_flags_sensitive_userdefaults() {
    let f = files(&[("A.swift", "UserDefaults.standard.set(token, forKey: \"t\")")]);
    let out = apple::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "apple.storage-sensitive"));
}

#[test]
fn aspnet_flags_permissive_cors_and_dev_exception_page() {
    assert!(aspnet::detect(&manifests(&["{\"Microsoft.AspNetCore\":\"1\"}"]), &[]));
    let f = files(&[
        ("A.cs", "app.UseCors(p => p.AllowAnyOrigin());"),
        ("B.cs", "app.UseDeveloperExceptionPage();"),
    ]);
    let out = aspnet::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "aspnet.cors-permissive"));
    assert!(out.iter().any(|o| o.rule_id == "aspnet.developer-exception-page"));
}

#[test]
fn django_flags_debug_and_raw_sql() {
    assert!(django::detect(&manifests(&["[\"django==4.0\"]"])));
    let f = files(&[
        ("settings.py", "DEBUG = True\n"),
        ("views.py", "Model.objects.raw(f\"SELECT * FROM t WHERE id={id}\")"),
    ]);
    let out = django::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "django.settings.debug"));
    assert!(out.iter().any(|o| o.rule_id == "django.orm.raw-sql"));
}

#[test]
fn entity_framework_flags_raw_sql_and_missing_tenant_filter() {
    assert!(entity_framework::detect(&manifests(&["{\"Microsoft.EntityFrameworkCore\":\"7\"}"])));
    let f = files(&[
        ("A.cs", "db.Database.ExecuteSqlRaw(\"DELETE FROM t WHERE id=\" + id);"),
        ("B.cs", "var x = ctx.Widgets.Where(w => w.Id == id).ToList();"),
    ]);
    let out = entity_framework::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "ef.raw-sql-interpolation"));
    assert!(out.iter().any(|o| o.rule_id == "ef.missing-tenant-filter"));
}

#[test]
fn fastapi_flags_cors_all_and_missing_response_model() {
    assert!(fastapi::detect(&manifests(&["[\"fastapi\"]"])));
    let f = files(&[
        ("a.py", "allow_origins=[\"*\"]"),
        (
            // The route-missing-response-model check (both this Rust port and
            // its JS source, index.mjs's `(?![\s\S]{0,300}response_model)`
            // lookahead) is a plain substring scan with no word boundaries;
            // the previous fixture text ("...without_response_model_marker")
            // itself contained the literal substring "response_model" and so
            // was always treated as present, suppressing the finding under
            // test in both implementations.
            "b.py",
            "@app.get(\"/x\")\nasync def handler():\n    return do_other_stuff_for_a_while()\n",
        ),
    ]);
    let out = fastapi::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "fastapi.cors-all-origins"));
    assert!(out.iter().any(|o| o.rule_id == "fastapi.no-response-model"));
}

#[test]
fn fastapi_response_model_present_suppresses_finding() {
    let f = files(&[(
        "b.py",
        "@app.get(\"/x\")\nasync def handler():\n    return X(response_model=Y)\n",
    )]);
    let out = fastapi::analyze(&f);
    assert!(!out.iter().any(|o| o.rule_id == "fastapi.no-response-model"));
}

#[test]
fn flask_flags_debug_mode_and_template_string_input() {
    assert!(flask::detect(&manifests(&["[\"flask\"]"])));
    let f = files(&[
        ("app.py", "app.run(debug=True)"),
        ("v.py", "render_template_string(request.args.get('t'))"),
    ]);
    let out = flask::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "flask.debug-enabled"));
    assert!(out.iter().any(|o| o.rule_id == "flask.template-string-input"));
}

#[test]
fn flutter_requires_dart_file_and_manifest() {
    assert!(flutter::detect(&manifests(&["{\"flutter\":{}}"]), &["lib/main.dart".into()]));
    assert!(!flutter::detect(&manifests(&["{}"]), &["lib/main.dart".into()]));
    let f = files(&[("lib/net.dart", "badCertificateCallback: (cert, host, port) => true")]);
    let out = flutter::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "flutter.bad-cert-callback"));
}

#[test]
fn go_web_flags_no_timeouts_and_route_without_auth() {
    assert!(go_web::detect(&manifests(&["[\"github.com/gin-gonic/gin\"]"])));
    let f = files(&[
        ("s.go", "srv := &http.Server{Addr: \":8080\"}"),
        ("r.go", "router.GET(\"/x\", handler)"),
    ]);
    let out = go_web::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "go-web.http-no-timeouts"));
    assert!(out.iter().any(|o| o.rule_id == "go-web.route-no-auth"));
}

#[test]
fn grpc_flags_service_without_auth() {
    assert!(grpc::detect(&manifests(&["[\"google.golang.org/grpc\"]"]), &[]));
    assert!(grpc::detect(&manifests(&["[]"]), &["api.proto".into()]));
    let f = files(&[("s.go", "service Widget {\n  rpc Get(Req) returns (Res);\n}")]);
    let out = grpc::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "grpc.service-no-auth"));
}

#[test]
fn ktor_flags_any_host_cors_and_sensitive_route() {
    assert!(ktor::detect(&manifests(&["[\"io.ktor:ktor-server-core\"]"])));
    let f = files(&[
        ("A.kt", "cors { anyHost() }"),
        ("B.kt", "route(\"/admin/reset\") { get { } }"),
    ]);
    let out = ktor::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "ktor.cors-any-host"));
    assert!(out.iter().any(|o| o.rule_id == "ktor.sensitive-route-no-auth"));
}

#[test]
fn laravel_flags_raw_sql_and_unescaped_blade() {
    assert!(laravel::detect(&manifests(&["{\"require\":{\"laravel/framework\":\"10\"}}"])));
    let f = files(&[
        ("A.php", "DB::select(\"SELECT * FROM t WHERE id=\" . $id);"),
        ("B.blade.php", "{!! $userSuppliedHtml !!}"),
    ]);
    let out = laravel::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "laravel.raw-sql-interpolation"));
    assert!(out.iter().any(|o| o.rule_id == "laravel.unescaped-blade"));
}

#[test]
fn next_flags_route_missing_auth_and_unbounded_fetch_and_image() {
    assert!(next::detect(&manifests(&["{\"dependencies\":{\"next\":\"14\"}}"])));
    let f = files(&[
        (
            "app/api/x/route.ts",
            "export async function GET(req) {\n  return Response.json(params);\n}",
        ),
        ("lib/data.ts", "const r = await fetch('https://x.example/api');"),
        ("app/page.tsx", "<Image src=\"/a.png\" />"),
    ]);
    let out = next::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "next.route.missing-auth"));
    assert!(out.iter().any(|o| o.rule_id == "next.cache.unbounded-revalidate"));
    assert!(out.iter().any(|o| o.rule_id == "next.image.unbounded"));
}

#[test]
fn next_fetch_followed_by_revalidate_and_image_with_dims_suppress_findings() {
    // The ported rule (like the original JS regex) only "sees" a revalidate
    // marker that appears AFTER a fetch(...) call's closing paren, within
    // 200 chars — not one embedded inside the call's own argument list,
    // since `[^)]*` already consumes up to the call's first `)`.
    let f = files(&[
        (
            "lib/data.ts",
            "const r = await fetch(url); // next: { revalidate: 60 }",
        ),
        ("app/page.tsx", "<Image src=\"/a.png\" width={10} height={10} />"),
    ]);
    let out = next::analyze(&f);
    assert!(!out.iter().any(|o| o.rule_id == "next.cache.unbounded-revalidate"));
    assert!(!out.iter().any(|o| o.rule_id == "next.image.unbounded"));
}

#[test]
fn rails_flags_forgery_bypass_and_raw_html() {
    assert!(rails::detect(&manifests(&["[\"rails\"]"]), &[]));
    assert!(rails::detect(&manifests(&["[]"]), &["Gemfile".into()]));
    let f = files(&[
        ("c.rb", "skip_before_action :verify_authenticity_token"),
        ("v.erb", "<%= raw(user_input) %>"),
    ]);
    let out = rails::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "rails.forgery-bypass"));
    assert!(out.iter().any(|o| o.rule_id == "rails.raw-html"));
}

#[test]
fn react_native_flags_unvalidated_openurl_and_sensitive_storage() {
    assert!(react_native::detect(&manifests(&["{\"dependencies\":{\"react-native\":\"0.73\"}}"])));
    let f = files(&[
        ("a.js", "Linking.openURL(request.url)"),
        ("b.js", "AsyncStorage.setItem('token', value)"),
    ]);
    let out = react_native::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "react-native.openurl-unvalidated"));
    assert!(out.iter().any(|o| o.rule_id == "react-native.storage-sensitive"));
}

#[test]
fn react_detects_via_package_manifest_and_flags_hooks_and_a11y() {
    assert!(react::detect(
        &manifests(&["{\"dependencies\":{\"react\":\"18\"}}"]),
        &serde_json::json!({}),
    ));
    let f = files(&[
        ("A.jsx", "function C() {\n  if (cond) {\n    useState(0);\n  }\n}"),
        ("B.jsx", "function D() {\n  useEffect(() => { doThing(); });\n}"),
        ("C.jsx", "const el = <img src=\"a.png\" />;"),
        ("D.jsx", "<div dangerouslySetInnerHTML={{__html: raw}} />"),
    ]);
    let out = react::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "react.hooks.conditional-call"));
    assert!(out.iter().any(|o| o.rule_id == "react.effects.missing-deps"));
    assert!(out.iter().any(|o| o.rule_id == "react.a11y.img-alt"));
    assert!(out.iter().any(|o| o.rule_id == "react.security.dangerous-html"));
}

#[test]
fn react_detects_via_nested_workspace_manifest() {
    let projection = serde_json::json!({
        "auditFacts": {
            "nestedPackageManifests": [{"dependencies": {"react": "18.0.0"}}]
        }
    });
    assert!(react::detect(&manifests(&["{}"]), &projection));
}

#[test]
fn react_effect_with_deps_array_suppresses_finding() {
    let f = files(&[("B.jsx", "function D() {\n  useEffect(() => { doThing(); }, [x]);\n}")]);
    let out = react::analyze(&f);
    assert!(!out.iter().any(|o| o.rule_id == "react.effects.missing-deps"));
}

#[test]
fn spring_flags_csrf_disabled_and_sensitive_permit_all() {
    assert!(spring::detect(&manifests(&["{\"org.springframework\":\"6\"}"])));
    let f = files(&[
        ("A.java", "http.csrf(csrf -> csrf.disable());"),
        ("B.java", "http.authorizeHttpRequests(a -> a.requestMatchers(\"/admin/**\").permitAll());"),
    ]);
    let out = spring::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "spring.csrf-disabled"));
    assert!(out.iter().any(|o| o.rule_id == "spring.sensitive-permit-all"));
}

#[test]
fn sqlalchemy_flags_raw_sql_and_commit_without_transaction() {
    assert!(sqlalchemy::detect(&manifests(&["[\"sqlalchemy\"]"])));
    let f = files(&[
        ("a.py", "conn.execute(f\"SELECT * FROM t WHERE id={id}\")"),
        ("b.py", "do_work()\nsession.commit()"),
    ]);
    let out = sqlalchemy::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "sqlalchemy.raw-sql-interpolation"));
    assert!(out.iter().any(|o| o.rule_id == "sqlalchemy.transaction-boundary"));
}

#[test]
fn sqlalchemy_commit_after_begin_suppresses_boundary_finding() {
    let f = files(&[("b.py", "session.begin()\nsession.commit()")]);
    let out = sqlalchemy::analyze(&f);
    assert!(!out.iter().any(|o| o.rule_id == "sqlalchemy.transaction-boundary"));
}

#[test]
fn symfony_flags_untrusted_bind_and_sensitive_route_without_role() {
    assert!(symfony::detect(&manifests(&["{\"symfony/framework-bundle\":\"6\"}"])));
    let f = files(&[
        ("A.php", "$form->bind($request);"),
        (
            // The `sensitive_route` regex (both this port and its JS source
            // at src/providers/frameworks/symfony/index.mjs:16) requires a
            // literal `[` right after `access_control:` — flow-style YAML —
            // and never matches YAML's block-list `-` syntax. The previous
            // fixture used block-list syntax, so neither implementation
            // would ever flag it.
            "security.yaml",
            "access_control: [{ path: ^/admin, roles: PUBLIC_ACCESS }]",
        ),
    ]);
    let out = symfony::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "symfony.untrusted-bind"));
    assert!(out.iter().any(|o| o.rule_id == "symfony.sensitive-route-no-role"));
}

#[test]
fn tauri_detects_via_conf_file_and_flags_insecure_transport_and_no_signature() {
    assert!(tauri::detect(&["tauri.conf.json".into()]));
    let f = files(&[
        ("tauri.conf.json", "{\"dangerousInsecureTransportProtocol\": true}"),
        ("tauri.conf2.json", "{\"updater\": {\"active\": true}}"),
    ]);
    let out = tauri::analyze(&f);
    assert!(out.iter().any(|o| o.rule_id == "tauri.updater.insecure-transport"));
    assert!(out.iter().any(|o| o.rule_id == "tauri.updater.no-signature"));
}

#[test]
fn tauri_updater_with_pubkey_suppresses_no_signature_finding() {
    let f = files(&[("tauri.conf.json", "{\"updater\": {\"pubkey\": \"abc\"}}")]);
    let out = tauri::analyze(&f);
    assert!(!out.iter().any(|o| o.rule_id == "tauri.updater.no-signature"));
}
