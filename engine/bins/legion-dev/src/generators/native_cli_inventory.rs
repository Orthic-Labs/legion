// Port of `scripts/native-cli/inventory.mjs`. Freezes the Node/Rust CLI
// command and nested-route inventory. The frozen Node surface
// (`tests/native-cli-characterization/node-surface.json`) is read as data —
// only the Rust side (`engine/bins/legion/src/cli.rs` and
// `engine/bins/legion/src/commands/*.rs`) is parsed here, matching the Node
// script exactly (it never re-derives the Node surface either).

use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

fn kebab(value: &str) -> String {
    let re = Regex::new(r"([a-z])([A-Z])").unwrap();
    re.replace_all(value, "$1-$2").to_lowercase()
}

/// Parse the Rust `enum Command { ... }` block and return its kebab-case
/// variant names, sorted.
fn rust_commands(source: &str) -> Result<Vec<String>, String> {
    let block_re = Regex::new(r"(?s)enum Command \{(.*?)\n\}").unwrap();
    let block = block_re
        .captures(source)
        .ok_or("cannot parse Rust Command enum")?;
    let body = &block[1];
    let variant_re = Regex::new(r"(?m)^\s+([A-Z][A-Za-z0-9]*)\(").unwrap();
    let excluded = ["M1ConfigArgs", "ServeArgs"];
    let mut names: Vec<String> = variant_re
        .captures_iter(body)
        .map(|c| c[1].to_string())
        .filter(|name| !excluded.contains(&name.as_str()))
        .map(|name| kebab(&name))
        .collect();
    names.sort();
    Ok(names)
}

#[derive(Clone, Debug)]
struct DispatchRoute {
    command: String,
    #[allow(dead_code)]
    handler: Option<String>,
}

/// Parse the Rust `dispatch` function's `match command { ... }` block into a
/// map of kebab command name -> matched handler expression text.
fn rust_dispatch_map(source: &str) -> Result<BTreeMap<String, String>, String> {
    let dispatch_re = Regex::new(
        r"(?s)async fn dispatch\(.*?let result: CommandResult = match command \{(.*?)\n    \};",
    )
    .unwrap();
    let dispatch_block = dispatch_re
        .captures(source)
        .ok_or("cannot parse Rust dispatch")?;
    let body = dispatch_block[1].to_string();

    let mut map: BTreeMap<String, String> = BTreeMap::new();

    let single_re = Regex::new(r"Command::([A-Za-z]+)\([^)]*\) => ([^\n,]+)").unwrap();
    for cap in single_re.captures_iter(&body) {
        map.insert(kebab(&cap[1]), cap[2].trim().to_string());
    }

    // The JS port relies on a lookahead (`(?=,?\n\s*Command::|$)`) to skip
    // past a match arm's own nested `}` lines (e.g. an `if` block inside the
    // arm) when hunting for the arm's real closing brace; the `regex` crate
    // has no lookahead, so this walks brace depth explicitly instead, which
    // is exact rather than heuristic for well-formed Rust source.
    let open_re = Regex::new(r"Command::([A-Za-z]+)\([^)]*\) => \{").unwrap();
    let handler_re = Regex::new(r"(commands::[a-z_]+::run)").unwrap();
    let bytes = body.as_bytes();
    for cap in open_re.captures_iter(&body) {
        let variant = kebab(&cap[1]);
        let open_at = cap.get(0).unwrap().end(); // just past the `{`
        let mut depth: i32 = 1;
        let mut i = open_at;
        let mut close_at = None;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close_at = Some(i);
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if let Some(close) = close_at {
            let block_body = &body[open_at..close];
            if let Some(handler) = handler_re.captures(block_body) {
                map.insert(variant, handler[1].to_string());
            }
        }
    }

    Ok(map)
}

fn enum_values(source: &str, name: &str) -> Vec<String> {
    let pattern = format!(r"(?s)enum {name} \{{(.*?)\n\}}");
    let re = Regex::new(&pattern).unwrap();
    match re.captures(source) {
        Some(block) => {
            let variant_re = Regex::new(r"(?m)^\s+([A-Z][A-Za-z0-9]*)\(").unwrap();
            variant_re
                .captures_iter(&block[1])
                .map(|c| kebab(&c[1]))
                .collect()
        }
        None => Vec::new(),
    }
}

#[derive(Clone, Debug, serde::Serialize)]
struct RouteRow {
    route: String,
    command: String,
    subcommand: String,
    source: String,
}

/// Enumerate typed Rust nested enums, plus string-routed CommonArgs modules.
fn rust_nested_routes(
    source: &str,
    module_sources: &BTreeMap<String, String>,
    expected_routes: &[String],
) -> Vec<RouteRow> {
    let expected: BTreeSet<&str> = expected_routes.iter().map(|s| s.as_str()).collect();
    let typed: [(&str, &str); 4] = [
        ("run", "RunCommand"),
        ("completion", "CompletionCommand"),
        ("host", "HostCommand"),
        ("state", "StateCommand"),
    ];

    let mut by_route: BTreeMap<String, RouteRow> = BTreeMap::new();

    for (command, enum_name) in typed {
        for value in enum_values(source, enum_name) {
            let route = format!("{command}.{value}");
            by_route.insert(
                route.clone(),
                RouteRow {
                    route,
                    command: command.to_string(),
                    subcommand: value,
                    source: format!("enum {enum_name}"),
                },
            );
        }
    }
    for value in enum_values(source, "HostEventsCommand") {
        let route = format!("host.events.{value}");
        by_route.insert(
            route.clone(),
            RouteRow {
                route,
                command: "host".to_string(),
                subcommand: format!("events.{value}"),
                source: "enum HostEventsCommand".to_string(),
            },
        );
    }

    let some_re = Regex::new(r#"Some\("([a-z][a-z-]*)"\)"#).unwrap();
    for (command, module_source) in module_sources {
        for cap in some_re.captures_iter(module_source) {
            let value = &cap[1];
            let route = format!("{command}.{value}");
            if value != "help" && (expected.is_empty() || expected.contains(route.as_str())) {
                by_route.insert(
                    route.clone(),
                    RouteRow {
                        route,
                        command: command.clone(),
                        subcommand: value.to_string(),
                        source: format!("commands/{command}.rs"),
                    },
                );
            }
        }
        if command == "authority" && expected.contains("authority.proof.inspect") {
            by_route.insert(
                "authority.proof.inspect".to_string(),
                RouteRow {
                    route: "authority.proof.inspect".to_string(),
                    command: "authority".to_string(),
                    subcommand: "proof.inspect".to_string(),
                    source: "commands/authority.rs".to_string(),
                },
            );
        }
    }

    let mut rows: Vec<RouteRow> = by_route.into_values().collect();
    rows.sort_by(|a, b| a.route.cmp(&b.route));
    rows
}

fn route_mismatches(node_routes: &[Value], rust_routes: &[RouteRow]) -> Vec<String> {
    let rust: BTreeSet<&str> = rust_routes.iter().map(|r| r.route.as_str()).collect();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for route in node_routes {
        let route_str = route
            .as_object()
            .and_then(|o| o.get("route"))
            .and_then(Value::as_str)
            .or_else(|| route.as_str())
            .unwrap_or_default();
        if !rust.contains(route_str) && seen.insert(route_str.to_string()) {
            out.push(route_str.to_string());
        }
    }
    out.sort();
    out
}

struct RustInfo {
    tier: &'static str,
    handler: String,
}

fn classify_rust(handler: &str) -> RustInfo {
    if handler.contains("root_projection!") {
        return RustInfo { tier: "stub", handler: "native_root_projection".into() };
    }
    if handler.contains("common_projection!") {
        return RustInfo { tier: "stub", handler: "native_common_projection".into() };
    }
    if handler.contains("native_doctor") {
        return RustInfo { tier: "partial", handler: "native_doctor".into() };
    }
    if handler.contains("native_plan") {
        return RustInfo { tier: "partial", handler: "native_plan".into() };
    }
    if handler.contains("native_run") {
        return RustInfo { tier: "partial", handler: "native_run".into() };
    }
    if handler.contains("native_verify") {
        return RustInfo { tier: "partial", handler: "native_verify".into() };
    }
    if handler.contains("native_report") {
        return RustInfo { tier: "partial", handler: "native_report".into() };
    }
    if handler.contains("native_completion") {
        return RustInfo { tier: "partial", handler: "native_completion".into() };
    }
    if handler.contains("native_state") {
        return RustInfo { tier: "partial", handler: "native_state".into() };
    }
    if handler.contains("native_host") {
        return RustInfo { tier: "partial", handler: "native_host".into() };
    }
    if handler.contains("native_schedule") {
        return RustInfo { tier: "divergent", handler: "native_schedule".into() };
    }
    if handler.starts_with("commands::") {
        return RustInfo { tier: "native", handler: handler.to_string() };
    }
    if handler.contains("native_m1_") {
        return RustInfo { tier: "native", handler: handler.to_string() };
    }
    if handler.contains("providers()") {
        return RustInfo { tier: "static", handler: "providers".into() };
    }
    if handler.contains("languages()") {
        return RustInfo { tier: "static", handler: "languages".into() };
    }
    RustInfo { tier: "unknown", handler: handler.to_string() }
}

fn all_rust_module_sources(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let dir = root.join("engine/bins/legion/src/commands");
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let stem = path.file_stem().unwrap().to_string_lossy().replace('_', "-");
            let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            out.insert(stem, text);
        }
    }
    Ok(out)
}

fn inventory_closure(counts: &Map<String, Value>) -> Value {
    let blocking_keys = [
        "rustStubs",
        "rustPartial",
        "rustDivergent",
        "rustUnknown",
        "uncharacterizedNodeCommands",
    ];
    let mut blockers = Map::new();
    let mut ok = true;
    for key in blocking_keys {
        let value = counts.get(key).and_then(Value::as_i64).unwrap_or(0);
        if value != 0 {
            ok = false;
        }
        blockers.insert(key.to_string(), json!(value));
    }
    json!({ "ok": ok, "blockers": blockers })
}

fn md_join(mut items: Vec<String>, sep: &str, empty: &str) -> String {
    if items.is_empty() {
        return empty.to_string();
    }
    items.iter_mut().for_each(|_| {});
    items.join(sep)
}

pub fn run(root: &Path) -> bool {
    match run_inner(root) {
        Ok(ok) => ok,
        Err(err) => {
            eprintln!("legion-dev: native-cli-inventory: {err}");
            false
        }
    }
}

fn run_inner(root: &Path) -> Result<bool, String> {
    let out_dir = root.join("dist/native-cli");
    let out_json = out_dir.join("behavior-inventory.json");
    let out_md = root.join("docs/plans/native-cli-behavior-inventory.md");

    let frozen_node_path = root.join("tests/native-cli-characterization/node-surface.json");
    let frozen_node: Value = serde_json::from_str(
        &fs::read_to_string(&frozen_node_path).map_err(|e| format!("{}: {e}", frozen_node_path.display()))?,
    )
    .map_err(|e| format!("{}: {e}", frozen_node_path.display()))?;
    if frozen_node.get("schemaVersion").and_then(Value::as_i64) != Some(1)
        || frozen_node.get("kind").and_then(Value::as_str) != Some("legion-frozen-node-cli-surface")
    {
        return Err("frozen Node CLI surface is invalid".to_string());
    }

    let rust_cli_path = root.join("engine/bins/legion/src/cli.rs");
    let rust_cli = fs::read_to_string(&rust_cli_path).map_err(|e| format!("{}: {e}", rust_cli_path.display()))?;

    let fixtures_path = root.join("tests/native-cli-characterization/fixtures.json");
    let fixtures_doc: Value = serde_json::from_str(
        &fs::read_to_string(&fixtures_path).map_err(|e| format!("{}: {e}", fixtures_path.display()))?,
    )
    .map_err(|e| format!("{}: {e}", fixtures_path.display()))?;
    let fixtures = fixtures_doc
        .get("fixtures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let node: Vec<String> = frozen_node["commands"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let dispatched_routes = frozen_node["dispatchRoutes"].as_array().cloned().unwrap_or_default();
    let dispatched: Vec<String> = dispatched_routes
        .iter()
        .filter_map(|r| r.get("command").and_then(Value::as_str).map(str::to_string))
        .collect();
    let nested_node = frozen_node["nestedRoutes"].as_array().cloned().unwrap_or_default();
    let nested_node_strings: Vec<String> = nested_node
        .iter()
        .filter_map(|r| r.get("route").and_then(Value::as_str).map(str::to_string))
        .collect();

    let rust = rust_commands(&rust_cli)?;
    let dispatch = rust_dispatch_map(&rust_cli)?;
    let module_sources = all_rust_module_sources(root)?;
    let nested_rust = rust_nested_routes(&rust_cli, &module_sources, &nested_node_strings);

    let nested_route_mismatches = route_mismatches(&nested_node, &nested_rust);

    let mut union: BTreeSet<String> = BTreeSet::new();
    union.extend(node.iter().cloned());
    union.extend(rust.iter().cloned());
    let union: Vec<String> = union.into_iter().collect();

    let characterized: BTreeSet<String> = fixtures
        .iter()
        .filter_map(|f| f.get("command").and_then(Value::as_str).map(str::to_string))
        .collect();

    let mut rows: Vec<Value> = Vec::new();
    let mut rust_stubs = 0i64;
    let mut rust_partial = 0i64;
    let mut rust_divergent = 0i64;
    let mut rust_unknown = 0i64;
    for command in &union {
        let in_node = node.contains(command);
        let in_rust = rust.contains(command);
        let node_dispatches = dispatched.contains(command);
        let rust_handler = dispatch.get(command);
        let rust_info = rust_handler.map(|h| classify_rust(h));

        let mut gap = "none".to_string();
        if in_node && !node_dispatches {
            gap = "node-help-only".to_string();
        } else if in_node && in_rust && rust_info.as_ref().map(|i| i.tier) == Some("stub") {
            gap = "rust-stub".to_string();
        } else if in_node
            && in_rust
            && matches!(rust_info.as_ref().map(|i| i.tier), Some("partial") | Some("divergent"))
        {
            gap = format!("rust-{}", rust_info.as_ref().unwrap().tier);
        } else if in_node && in_rust && rust_info.as_ref().map(|i| i.tier) == Some("unknown") {
            gap = "rust-unknown".to_string();
        } else if !in_node && in_rust {
            gap = "rust-only".to_string();
        } else if in_node && !in_rust {
            gap = "node-only".to_string();
        }

        if let Some(info) = &rust_info {
            match info.tier {
                "stub" => rust_stubs += 1,
                "partial" => rust_partial += 1,
                "divergent" => rust_divergent += 1,
                "unknown" => rust_unknown += 1,
                _ => {}
            }
        }

        let node_route = dispatched_routes
            .iter()
            .find(|r| r.get("command").and_then(Value::as_str) == Some(command.as_str()))
            .and_then(|r| r.get("source"))
            .cloned()
            .unwrap_or(Value::Null);

        rows.push(json!({
            "command": command,
            "node": in_node,
            "nodeDispatched": node_dispatches,
            "nodeRoute": node_route,
            "rust": in_rust,
            "rustHandler": rust_handler.cloned().map(Value::String).unwrap_or(Value::Null),
            "rustTier": rust_info.as_ref().map(|i| i.tier).map(|t| Value::String(t.to_string())).unwrap_or(Value::Null),
            "gap": gap,
        }));
    }

    let uncharacterized: Vec<String> = node
        .iter()
        .filter(|c| !characterized.contains(*c))
        .cloned()
        .collect();

    let mut counts = Map::new();
    counts.insert("nodeHelp".into(), json!(node.len()));
    counts.insert("nodeDispatched".into(), json!(dispatched.len()));
    counts.insert("rust".into(), json!(rust.len()));
    counts.insert("union".into(), json!(union.len()));
    counts.insert("nodeRuntimeRoutes".into(), json!(dispatched_routes.len()));
    counts.insert("nestedNodeRoutes".into(), json!(nested_node.len()));
    counts.insert("nestedRustRoutes".into(), json!(nested_rust.len()));
    counts.insert("nestedRouteMismatches".into(), json!(nested_route_mismatches.len()));
    counts.insert("rustStubs".into(), json!(rust_stubs));
    counts.insert("rustPartial".into(), json!(rust_partial));
    counts.insert("rustDivergent".into(), json!(rust_divergent));
    counts.insert("rustUnknown".into(), json!(rust_unknown));
    counts.insert("characterizationFixtures".into(), json!(fixtures.len()));
    counts.insert(
        "characterizationCommands".into(),
        json!(union.iter().filter(|c| characterized.contains(*c)).count()),
    );
    counts.insert(
        "characterizationSubcommands".into(),
        json!(fixtures
            .iter()
            .filter(|f| f.get("subcommand").map(|v| !v.is_null()).unwrap_or(false))
            .count()),
    );
    counts.insert("uncharacterizedNodeCommands".into(), json!(uncharacterized.len()));

    let mut closure = inventory_closure(&counts);
    let mut closure_ok = closure["ok"].as_bool().unwrap_or(false);
    if !nested_route_mismatches.is_empty() {
        closure_ok = false;
        closure["ok"] = json!(false);
        closure["blockers"]["nestedRouteMismatches"] = json!(nested_route_mismatches.len());
    }

    let mut inventory = Map::new();
    inventory.insert("schemaVersion".into(), json!(1));
    inventory.insert("kind".into(), json!("legion-native-cli-behavior-inventory"));
    inventory.insert("generatedAt".into(), json!(chrono_now_iso()));
    inventory.insert("counts".into(), Value::Object(counts.clone()));
    inventory.insert(
        "invariants".into(),
        json!({
            "productCompositionSource": "legion.exe loads Legion assets only from installed/staged release root; cwd is the operated-on repository, never an alternate runtime source.",
            "jsPermittedOnly": "build, generation, lint, test harness — not Legion CLI semantics",
        }),
    );
    inventory.insert("commands".into(), Value::Array(rows.clone()));
    let routes_value = json!({
        "node": nested_node,
        "rust": nested_rust.iter().map(|r| json!({
            "route": r.route, "command": r.command, "subcommand": r.subcommand, "source": r.source,
        })).collect::<Vec<_>>(),
        "mismatches": nested_route_mismatches,
    });
    inventory.insert("routes".into(), routes_value);
    inventory.insert("closure".into(), closure.clone());

    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let json_text = format!("{}\n", serde_json::to_string_pretty(&Value::Object(inventory)).map_err(|e| e.to_string())?);
    fs::write(&out_json, &json_text).map_err(|e| e.to_string())?;

    let md_lines = build_markdown(&counts, &nested_node, &nested_rust, &nested_route_mismatches, &rows, &node, &characterized);
    fs::create_dir_all(out_md.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&out_md, &md_lines).map_err(|e| e.to_string())?;

    let summary = json!({
        "ok": closure_ok,
        "outJson": out_json.display().to_string(),
        "outMd": out_md.display().to_string(),
        "counts": counts,
        "blockers": closure["blockers"],
    });
    println!("{}", serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?);

    Ok(closure_ok)
}

// `generatedAt` is informational only (never compared for byte-identity —
// the Node script itself embeds `new Date().toISOString()`), so an RFC 3339
// UTC timestamp without pulling in a chrono dependency is sufficient here.
fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let days = secs / 86400;
    let mut rem = secs % 86400;
    let hour = rem / 3600;
    rem %= 3600;
    let minute = rem / 60;
    let second = rem % 60;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

// Howard Hinnant's civil_from_days algorithm (days since 1970-01-01 -> y/m/d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[allow(clippy::too_many_arguments)]
fn build_markdown(
    counts: &Map<String, Value>,
    nested_node: &[Value],
    nested_rust: &[RouteRow],
    mismatches: &[String],
    rows: &[Value],
    node: &[String],
    characterized: &BTreeSet<String>,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("# Native CLI behavior inventory".to_string());
    lines.push(String::new());
    lines.push("Generated by `cargo run -q --locked --manifest-path engine/Cargo.toml -p legion-dev -- native-cli-inventory`. Do not hand-edit.".to_string());
    lines.push(String::new());
    lines.push("| Metric | Count |".to_string());
    lines.push("| --- | ---: |".to_string());
    for (key, value) in counts {
        lines.push(format!("| {key} | {} |", value_as_count(value)));
    }
    lines.push(String::new());
    lines.push("## Nested routes".to_string());
    lines.push(String::new());
    let node_routes_text = md_join(
        nested_node
            .iter()
            .filter_map(|r| r.get("route").and_then(Value::as_str))
            .map(|r| format!("`{r}`"))
            .collect(),
        ", ",
        "none",
    );
    lines.push(format!("Node routes: {node_routes_text}."));
    lines.push(String::new());
    let rust_routes_text = md_join(
        nested_rust.iter().map(|r| format!("`{}`", r.route)).collect(),
        ", ",
        "none",
    );
    lines.push(format!("Rust routes: {rust_routes_text}."));
    lines.push(String::new());
    let mismatch_text = md_join(mismatches.iter().map(|m| format!("`{m}`")).collect(), ", ", "none");
    lines.push(format!("Route mismatches: {mismatch_text}."));
    lines.push(String::new());
    lines.push("## Command matrix".to_string());
    lines.push(String::new());
    lines.push("| Command | Node | Dispatched | Rust | Rust tier | Gap |".to_string());
    lines.push("| --- | --- | --- | --- | --- | --- |".to_string());
    for row in rows {
        let command = row["command"].as_str().unwrap_or_default();
        let node_yes = if row["node"].as_bool().unwrap_or(false) { "yes" } else { "no" };
        let dispatched_yes = if row["nodeDispatched"].as_bool().unwrap_or(false) { "yes" } else { "no" };
        let rust_yes = if row["rust"].as_bool().unwrap_or(false) { "yes" } else { "no" };
        let tier = row["rustTier"].as_str().unwrap_or("\u{2014}");
        let gap = row["gap"].as_str().unwrap_or_default();
        lines.push(format!(
            "| `{command}` | {node_yes} | {dispatched_yes} | {rust_yes} | {tier} | {gap} |"
        ));
    }
    lines.push(String::new());
    let uncharacterized_text = md_join(
        node.iter()
            .filter(|c| !characterized.contains(*c))
            .map(|c| format!("`{c}`"))
            .collect(),
        ", ",
        "none",
    );
    lines.push(format!("Uncharacterized Node commands: {uncharacterized_text}."));
    lines.push(String::new());
    lines.join("\n")
}

fn value_as_count(value: &Value) -> String {
    if let Some(n) = value.as_i64() {
        n.to_string()
    } else {
        value.to_string()
    }
}
