//! Bounded, read-only SwiftUI Instruments trace analysis.
//!
//! Recording and export stay with mobile `profile` / `profile.export` plans.
//! This module accepts exported XML or an already-built analysis value, parses
//! only bounded row evidence, and never turns absent evidence into a success.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const MAX_XML_BYTES: usize = 32 * 1024 * 1024;
const MAX_NODES: usize = 120_000;
const MAX_DEPTH: usize = 64;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_ROWS: usize = 100_000;
const MAX_TOP: usize = 100;

#[derive(Clone, Debug)]
struct XmlNode {
    name: String,
    attrs: BTreeMap<String, String>,
    children: Vec<XmlNode>,
    text: String,
}

#[derive(Clone, Debug)]
struct TraceRow {
    index: usize,
    lane: String,
    name: String,
    symbol: String,
    message: String,
    process: String,
    subsystem: String,
    category: String,
    event_type: String,
    run: String,
    destination: String,
    source: String,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
    duration_ns: Option<u64>,
    coverage_pct: Option<f64>,
}

#[derive(Clone, Copy, Debug)]
struct Window {
    start_ns: u64,
    end_ns: u64,
}

/// Analyze exported Instruments XML or a pure analysis value.
pub fn invoke(arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "swiftui trace arguments must be a JSON object".to_string())?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("analyze")
        .to_ascii_lowercase();

    match operation.as_str() {
        "parse" => parse_operation(object),
        "analyze" | "full" => analyze_operation(object),
        "list-runs" | "runs" => list_runs_operation(object),
        "list-logs" | "logs" => discovery_operation(object, Discovery::Logs),
        "list-signposts" | "signposts" => discovery_operation(object, Discovery::Signposts),
        "fanin-for" | "fanin" => fanin_operation(object),
        "summary" => summary_operation(object),
        other => Err(format!(
            "unsupported SwiftUI trace operation: {other}; use parse, analyze, list-runs, list-logs, list-signposts, fanin-for, or summary"
        )),
    }
}

/// Describe supported pure operations. Capture/export are mobile profile plans.
pub fn catalog() -> Value {
    json!({
        "schemaVersion": 1,
        "module": "swiftui-trace",
        "readOnly": true,
        "limits": {
            "maxXmlBytes": MAX_XML_BYTES,
            "maxNodes": MAX_NODES,
            "maxRows": MAX_ROWS,
            "maxTop": MAX_TOP
        },
        "operations": {
            "parse": {"input": "xml", "purpose": "bounded XML row/lane inventory"},
            "analyze": {"input": "xml, top?, windowMs?", "purpose": "lane evidence and cross-lane correlations"},
            "list-runs": {"input": "xml", "purpose": "run metadata discovery"},
            "list-logs": {"input": "xml, filters?", "purpose": "filtered log evidence"},
            "list-signposts": {"input": "xml, filters?", "purpose": "signpost intervals and points"},
            "fanin-for": {"input": "xml, destinationContains, top?", "purpose": "cause graph incoming sources"},
            "summary": {"input": "analysis", "purpose": "evidence-aware text summary"}
        },
        "captureExport": "Delegate recording to mobile profile and XML export to mobile profile.export typed argv plans."
    })
}

fn parse_operation(object: &Map<String, Value>) -> Result<Value, String> {
    let rows = load_rows(object)?;
    if rows.is_empty() {
        return Err("trace XML contains no bounded row evidence".to_string());
    }
    Ok(json!({
        "operation": "parse",
        "status": "ok",
        "rows": rows.len(),
        "lanes": lane_counts(&rows),
        "evidence": rows.iter().map(row_value).collect::<Vec<_>>()
    }))
}

fn analyze_operation(object: &Map<String, Value>) -> Result<Value, String> {
    let rows = load_rows(object)?;
    if rows.is_empty() {
        return Err("trace XML contains no bounded row evidence".to_string());
    }
    let top = top_value(object)?;
    let window = parse_window(object)?;
    let filtered: Vec<TraceRow> = rows
        .into_iter()
        .filter(|row| row_in_window(row, window))
        .collect();
    if filtered.is_empty() {
        return Err("requested trace window contains no evidence".to_string());
    }
    let lanes = [
        "time-profiler",
        "hangs",
        "hitches",
        "swiftui",
        "swiftui-causes",
    ];
    let lane_values: Vec<Value> = lanes
        .iter()
        .map(|lane| lane_value(lane, &filtered, top))
        .collect();
    let correlations = correlate(&filtered, top);
    let runs = run_values(&filtered);
    let mut output = json!({
        "operation": "analyze",
        "status": "ok",
        "rows": filtered.len(),
        "lanes": lane_values,
        "correlations": correlations,
        "runsAvailable": runs,
        "coveragePct": coverage_value(&filtered)
    });
    if let Some(window) = window {
        output["windowMs"] = json!({
            "start": window.start_ns as f64 / 1_000_000.0,
            "end": window.end_ns as f64 / 1_000_000.0
        });
    }
    Ok(output)
}

fn list_runs_operation(object: &Map<String, Value>) -> Result<Value, String> {
    let xml = required_xml(object)?;
    let root = parse_xml(xml)?;
    let mut runs = Vec::new();
    collect_runs(&root, &mut runs);
    if runs.is_empty() {
        return Ok(json!({"operation": "list-runs", "status": "no_evidence", "runs": []}));
    }
    Ok(json!({"operation": "list-runs", "status": "ok", "runs": runs}))
}

#[derive(Clone, Copy)]
enum Discovery {
    Logs,
    Signposts,
}

fn discovery_operation(object: &Map<String, Value>, discovery: Discovery) -> Result<Value, String> {
    let rows = load_rows(object)?;
    let top = top_value(object)?;
    let window = parse_window(object)?;
    let mut selected = Vec::new();
    for row in rows.iter().filter(|row| row_in_window(row, window)) {
        let matches = match discovery {
            Discovery::Logs => {
                row.lane == "logs" || contains_any(&row.event_type, &["log", "os_log"])
            }
            Discovery::Signposts => {
                row.lane == "signposts" || contains_any(&row.event_type, &["signpost"])
            }
        };
        if matches && matches_filters(row, object) {
            selected.push(row_value(row));
            if selected.len() >= top {
                break;
            }
        }
    }
    let name = match discovery {
        Discovery::Logs => "list-logs",
        Discovery::Signposts => "list-signposts",
    };
    let status = if selected.is_empty() {
        "no_evidence"
    } else {
        "ok"
    };
    Ok(json!({"operation": name, "status": status, "count": selected.len(), "entries": selected}))
}

fn fanin_operation(object: &Map<String, Value>) -> Result<Value, String> {
    let needle = object
        .get("destinationContains")
        .or_else(|| object.get("destination_contains"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "destinationContains must be a non-empty string".to_string())?
        .to_ascii_lowercase();
    let top = top_value(object)?;
    let window = parse_window(object)?;
    let rows = load_rows(object)?;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut destination = String::new();
    for row in rows.iter().filter(|row| row_in_window(row, window)) {
        if row.lane != "swiftui-causes" && row.destination.is_empty() {
            continue;
        }
        if !row.destination.to_ascii_lowercase().contains(&needle) {
            continue;
        }
        if destination.is_empty() {
            destination = row.destination.clone();
        }
        let source = if row.source.is_empty() {
            row.symbol.clone()
        } else {
            row.source.clone()
        };
        if !source.is_empty() {
            *counts.entry(source).or_insert(0) += 1;
        }
    }
    let mut sources: Vec<Value> = counts
        .into_iter()
        .map(|(source, count)| json!({"source": source, "count": count}))
        .collect();
    sources.sort_by(|left, right| {
        right["count"]
            .as_u64()
            .cmp(&left["count"].as_u64())
            .then_with(|| left["source"].as_str().cmp(&right["source"].as_str()))
    });
    sources.truncate(top);
    let status = if sources.is_empty() {
        "no_evidence"
    } else {
        "ok"
    };
    Ok(
        json!({"operation": "fanin-for", "status": status, "destination": destination, "sources": sources}),
    )
}

fn summary_operation(object: &Map<String, Value>) -> Result<Value, String> {
    let analysis = object
        .get("analysis")
        .ok_or_else(|| "summary requires analysis object".to_string())?;
    let map = analysis
        .as_object()
        .ok_or_else(|| "analysis must be a JSON object".to_string())?;
    let status = map
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let rows = map.get("rows").and_then(Value::as_u64).unwrap_or(0);
    let coverage = map
        .get("coveragePct")
        .and_then(Value::as_f64)
        .map(|value| format!("{value:.1}%"))
        .unwrap_or_else(|| "unavailable".to_string());
    let lane_count = map
        .get("lanes")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let text = format!("Trace status {status}; {rows} evidence rows; {lane_count} lanes; main-running coverage {coverage}.");
    Ok(
        json!({"operation": "summary", "status": status, "text": text, "evidenceRows": rows, "lanes": lane_count, "coveragePct": map.get("coveragePct").cloned().unwrap_or(Value::Null)}),
    )
}

fn load_rows(object: &Map<String, Value>) -> Result<Vec<TraceRow>, String> {
    let xml = required_xml(object)?;
    let root = parse_xml(xml)?;
    let mut nodes = Vec::new();
    collect_rows(&root, &mut nodes);
    if nodes.len() > MAX_ROWS {
        return Err(format!("trace row count exceeds {MAX_ROWS}"));
    }
    Ok(nodes
        .into_iter()
        .enumerate()
        .map(|(index, node)| row_from_node(index, node))
        .collect())
}

fn required_xml<'a>(object: &'a Map<String, Value>) -> Result<&'a str, String> {
    let xml = object
        .get("xml")
        .and_then(Value::as_str)
        .ok_or_else(|| "xml is required".to_string())?;
    if xml.is_empty() {
        return Err("xml must not be empty".to_string());
    }
    if xml.len() > MAX_XML_BYTES {
        return Err(format!("xml exceeds {MAX_XML_BYTES} bytes"));
    }
    Ok(xml)
}

fn top_value(object: &Map<String, Value>) -> Result<usize, String> {
    let top = object.get("top").and_then(Value::as_u64).unwrap_or(10) as usize;
    if top == 0 || top > MAX_TOP {
        return Err(format!("top must be between 1 and {MAX_TOP}"));
    }
    Ok(top)
}

fn parse_window(object: &Map<String, Value>) -> Result<Option<Window>, String> {
    let value = object.get("windowMs").or_else(|| object.get("window_ms"));
    let Some(value) = value else {
        return Ok(None);
    };
    let map = value
        .as_object()
        .ok_or_else(|| "windowMs must be an object".to_string())?;
    let start = map
        .get("start")
        .and_then(Value::as_f64)
        .ok_or_else(|| "windowMs.start must be a number".to_string())?;
    let end = map
        .get("end")
        .and_then(Value::as_f64)
        .ok_or_else(|| "windowMs.end must be a number".to_string())?;
    if !start.is_finite() || !end.is_finite() || start < 0.0 || end < start {
        return Err("windowMs must have finite non-negative start <= end".to_string());
    }
    Ok(Some(Window {
        start_ns: (start * 1_000_000.0) as u64,
        end_ns: (end * 1_000_000.0) as u64,
    }))
}

fn row_in_window(row: &TraceRow, window: Option<Window>) -> bool {
    let Some(window) = window else {
        return true;
    };
    let start = row.start_ns.or(row.end_ns).unwrap_or(0);
    let end = row.end_ns.or(row.start_ns).unwrap_or(start);
    end >= window.start_ns && start <= window.end_ns
}

fn matches_filters(row: &TraceRow, object: &Map<String, Value>) -> bool {
    let contains = |key: &str, haystack: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .map_or(true, |needle| {
                haystack
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
    };
    contains("subsystem", &row.subsystem)
        && contains("category", &row.category)
        && contains("messageContains", &row.message)
        && contains("nameContains", &row.name)
        && contains("eventType", &row.event_type)
}

fn lane_counts(rows: &[TraceRow]) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        *counts.entry(row.lane.clone()).or_insert(0) += 1;
    }
    json!(counts)
}

fn lane_value(lane: &str, rows: &[TraceRow], top: usize) -> Value {
    let mut selected: Vec<&TraceRow> = rows.iter().filter(|row| row.lane == lane).collect();
    selected.sort_by(|left, right| {
        right
            .duration_ns
            .unwrap_or(0)
            .cmp(&left.duration_ns.unwrap_or(0))
            .then_with(|| left.index.cmp(&right.index))
    });
    let evidence = selected
        .iter()
        .take(top)
        .map(|row| row_value(row))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        json!({"lane": lane, "status": "no_evidence", "reason": "no matching lane rows", "count": 0, "evidence": []})
    } else {
        json!({"lane": lane, "status": "ok", "count": selected.len(), "evidence": evidence})
    }
}

fn correlate(rows: &[TraceRow], top: usize) -> Vec<Value> {
    let hitches: Vec<&TraceRow> = rows.iter().filter(|row| row.lane == "hitches").collect();
    let symbols: Vec<&TraceRow> = rows
        .iter()
        .filter(|row| row.lane == "time-profiler" && !row.symbol.is_empty())
        .collect();
    let swiftui: Vec<&TraceRow> = rows.iter().filter(|row| row.lane == "swiftui").collect();
    let mut values = Vec::new();
    for hitch in hitches.iter().take(top) {
        for symbol in symbols.iter() {
            let overlap = overlap_ns(hitch, symbol);
            if overlap > 0 {
                values.push(json!({"kind": "hitch-symbol", "hitch": row_value(hitch), "symbol": symbol.symbol, "overlapNs": overlap}));
            }
        }
        for update in swiftui.iter() {
            let overlap = overlap_ns(hitch, update);
            if overlap > 0 {
                values.push(json!({"kind": "hitch-swiftui", "hitch": row_value(hitch), "update": row_value(update), "overlapNs": overlap}));
            }
        }
    }
    values.sort_by(|left, right| right["overlapNs"].as_u64().cmp(&left["overlapNs"].as_u64()));
    values.truncate(top);
    values
}

fn overlap_ns(left: &TraceRow, right: &TraceRow) -> u64 {
    let left_start = left.start_ns.unwrap_or(0);
    let right_start = right.start_ns.unwrap_or(0);
    let left_end = left
        .end_ns
        .or(left
            .duration_ns
            .map(|duration| left_start.saturating_add(duration)))
        .unwrap_or(left_start);
    let right_end = right
        .end_ns
        .or(right
            .duration_ns
            .map(|duration| right_start.saturating_add(duration)))
        .unwrap_or(right_start);
    left_end
        .min(right_end)
        .saturating_sub(left_start.max(right_start))
}

fn coverage_value(rows: &[TraceRow]) -> Value {
    let values: Vec<f64> = rows.iter().filter_map(|row| row.coverage_pct).collect();
    if values.is_empty() {
        Value::Null
    } else {
        Value::from(values.iter().sum::<f64>() / values.len() as f64)
    }
}

fn run_values(rows: &[TraceRow]) -> Vec<Value> {
    let mut values = BTreeMap::new();
    for row in rows {
        if !row.run.is_empty() {
            values.insert(row.run.clone(), ());
        }
    }
    values.into_keys().map(Value::String).collect()
}

fn row_value(row: &TraceRow) -> Value {
    json!({
        "index": row.index,
        "lane": row.lane,
        "name": row.name,
        "symbol": row.symbol,
        "message": row.message,
        "process": row.process,
        "subsystem": row.subsystem,
        "category": row.category,
        "eventType": row.event_type,
        "run": row.run,
        "destination": row.destination,
        "source": row.source,
        "startNs": row.start_ns,
        "endNs": row.end_ns,
        "durationNs": row.duration_ns,
        "coveragePct": row.coverage_pct
    })
}

fn row_from_node(index: usize, node: &XmlNode) -> TraceRow {
    let lane_hint = find_value(node, &["lane", "schema", "instrument", "kind", "type"]);
    let event_type =
        find_value(node, &["event-type", "event_type", "type", "kind"]).unwrap_or_default();
    let name = find_value(node, &["name", "title", "label", "event-name"]).unwrap_or_default();
    let symbol =
        find_value(node, &["symbol", "symbol-name", "function", "frame"]).unwrap_or_default();
    let message =
        find_value(node, &["message", "format", "description"]).unwrap_or_else(|| node_text(node));
    let start_ns = find_number(
        node,
        &["start-ns", "start_ns", "start", "timestamp", "time"],
    );
    let end_ns = find_number(node, &["end-ns", "end_ns", "end"]);
    let duration_ns =
        find_number(node, &["duration-ns", "duration_ns", "duration"]).or_else(|| {
            match (start_ns, end_ns) {
                (Some(start), Some(end)) if end >= start => Some(end - start),
                _ => None,
            }
        });
    let combined = format!(
        "{} {} {} {}",
        lane_hint.as_deref().unwrap_or_default(),
        event_type,
        name,
        message
    )
    .to_ascii_lowercase();
    let lane = classify_lane(&combined, node.name.as_str());
    TraceRow {
        index,
        lane,
        name,
        symbol,
        message,
        process: find_value(node, &["process", "process-name", "process_name"]).unwrap_or_default(),
        subsystem: find_value(node, &["subsystem"]).unwrap_or_default(),
        category: find_value(node, &["category"]).unwrap_or_default(),
        event_type,
        run: find_value(node, &["run", "run-number", "run_number"]).unwrap_or_default(),
        destination: find_value(node, &["destination", "dest", "target"]).unwrap_or_default(),
        source: find_value(node, &["source", "cause", "origin"]).unwrap_or_default(),
        start_ns,
        end_ns,
        duration_ns,
        coverage_pct: find_number_f64(node, &["coverage", "coverage-pct", "coverage_pct"]),
    }
}

fn classify_lane(combined: &str, tag: &str) -> String {
    let text = format!("{combined} {tag}").to_ascii_lowercase();
    if contains_any(&text, &["cause", "invalidation", "fanin", "fan-in"]) {
        "swiftui-causes"
    } else if contains_any(&text, &["signpost"]) {
        "signposts"
    } else if contains_any(&text, &["log", "os_log"]) {
        "logs"
    } else if contains_any(&text, &["hitch", "animation frame", "frame hitch"]) {
        "hitches"
    } else if contains_any(&text, &["hang", "blocked", "main thread stall"]) {
        "hangs"
    } else if contains_any(
        &text,
        &["swiftui", "view update", "body", "invalidation", "layout"],
    ) {
        "swiftui"
    } else if contains_any(
        &text,
        &[
            "time profiler",
            "time-profile",
            "kperf",
            "sample",
            "cpu",
            "stack",
            "symbol",
        ],
    ) {
        "time-profiler"
    } else {
        "other"
    }
    .to_string()
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn find_value(node: &XmlNode, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(value) = node.attrs.get(&normalize_name(name)) {
            return Some(value.clone());
        }
    }
    let current = normalize_name(&node.name);
    if names.iter().any(|name| normalize_name(name) == current) {
        let value = node_text(node);
        if !value.is_empty() {
            return Some(value);
        }
    }
    for child in &node.children {
        if let Some(value) = find_value(child, names) {
            return Some(value);
        }
    }
    None
}

fn find_number(node: &XmlNode, names: &[&str]) -> Option<u64> {
    let value = find_value(node, names)?;
    parse_time_value(&value, names.first().copied().unwrap_or_default()).ok()
}

fn find_number_f64(node: &XmlNode, names: &[&str]) -> Option<f64> {
    let value: f64 = find_value(node, names)?
        .trim()
        .trim_end_matches('%')
        .parse()
        .ok()?;
    value.is_finite().then_some(value)
}

fn parse_time_value(value: &str, field: &str) -> Result<u64, String> {
    let compact = value.trim().replace(',', "");
    let lower = compact.to_ascii_lowercase();
    let (number, multiplier) = if let Some(value) = lower.strip_suffix("ns") {
        (value, 1.0)
    } else if let Some(value) = lower.strip_suffix("us") {
        (value, 1_000.0)
    } else if let Some(value) = lower.strip_suffix("ms") {
        (value, 1_000_000.0)
    } else if let Some(value) = lower.strip_suffix('s') {
        (value, 1_000_000_000.0)
    } else if field.contains("ms") {
        (lower.as_str(), 1_000_000.0)
    } else {
        (lower.as_str(), 1.0)
    };
    let parsed: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("invalid time value: {value}"))?;
    if !parsed.is_finite() || parsed < 0.0 || parsed * multiplier > u64::MAX as f64 {
        return Err(format!("invalid time value: {value}"));
    }
    Ok((parsed * multiplier) as u64)
}

fn node_text(node: &XmlNode) -> String {
    let mut output = node.text.clone();
    for child in &node.children {
        if !output.is_empty() {
            output.push(' ');
        }
        output.push_str(&node_text(child));
        if output.len() >= MAX_TEXT_BYTES {
            break;
        }
    }
    output.truncate(MAX_TEXT_BYTES);
    output.trim().to_string()
}

fn collect_rows<'a>(node: &'a XmlNode, rows: &mut Vec<&'a XmlNode>) {
    if rows.len() >= MAX_ROWS {
        return;
    }
    let name = normalize_name(&node.name);
    if matches!(
        name.as_str(),
        "row" | "event" | "sample" | "interval" | "signpost" | "log" | "update" | "cause"
    ) {
        rows.push(node);
    }
    for child in &node.children {
        collect_rows(child, rows);
    }
}

fn collect_runs(node: &XmlNode, runs: &mut Vec<Value>) {
    if normalize_name(&node.name) == "run" {
        let number = node
            .attrs
            .get("number")
            .cloned()
            .or_else(|| find_value(node, &["number", "id"]));
        if let Some(number) = number {
            runs.push(json!({
                "number": number,
                "template": find_value(node, &["template", "template-name", "template_name"]),
                "duration": find_value(node, &["duration", "duration-s", "duration_s"]),
                "start": find_value(node, &["start", "start-date", "start_date"]),
                "end": find_value(node, &["end", "end-date", "end_date"])
            }));
        }
    }
    for child in &node.children {
        collect_runs(child, runs);
    }
}

fn normalize_name(name: &str) -> String {
    name.rsplit(':')
        .next()
        .unwrap_or(name)
        .replace('-', "_")
        .to_ascii_lowercase()
}

fn parse_xml(input: &str) -> Result<XmlNode, String> {
    if input.len() > MAX_XML_BYTES {
        return Err(format!("xml exceeds {MAX_XML_BYTES} bytes"));
    }
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut roots = Vec::new();
    let mut cursor = 0;
    let bytes = input.as_bytes();
    let mut nodes = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'<' {
            let end = input[cursor..]
                .find('<')
                .map_or(bytes.len(), |offset| cursor + offset);
            if let Some(node) = stack.last_mut() {
                append_text(&mut node.text, decode_entities(&input[cursor..end]));
            }
            cursor = end;
            continue;
        }
        if input[cursor..].starts_with("<!--") {
            cursor = cursor
                + input[cursor + 4..]
                    .find("-->")
                    .ok_or_else(|| "unterminated XML comment".to_string())?
                + 7;
            continue;
        }
        if input[cursor..].starts_with("<![CDATA[") {
            let start = cursor + 9;
            let end = start
                + input[start..]
                    .find("]]>")
                    .ok_or_else(|| "unterminated CDATA".to_string())?;
            if let Some(node) = stack.last_mut() {
                append_text(&mut node.text, input[start..end].to_string());
            }
            cursor = end + 3;
            continue;
        }
        if input[cursor..].starts_with("<?") || input[cursor..].starts_with("<!") {
            cursor = find_tag_end(input, cursor + 2)? + 1;
            continue;
        }
        let end = find_tag_end(input, cursor + 1)?;
        let raw = input[cursor + 1..end].trim();
        if let Some(close) = raw.strip_prefix('/') {
            let name = close.trim();
            let node = stack
                .pop()
                .ok_or_else(|| "unexpected XML closing tag".to_string())?;
            if normalize_name(&node.name) != normalize_name(name) {
                return Err(format!("mismatched XML closing tag: {name}"));
            }
            attach_node(&mut stack, &mut roots, node);
        } else {
            let self_closing = raw.ends_with('/');
            let body = raw.trim_end_matches('/').trim();
            let (name, attrs) = parse_tag(body)?;
            nodes += 1;
            if nodes > MAX_NODES {
                return Err(format!("XML node count exceeds {MAX_NODES}"));
            }
            if stack.len() >= MAX_DEPTH {
                return Err(format!("XML nesting exceeds {MAX_DEPTH}"));
            }
            let node = XmlNode {
                name,
                attrs,
                children: Vec::new(),
                text: String::new(),
            };
            if self_closing {
                attach_node(&mut stack, &mut roots, node);
            } else {
                stack.push(node);
            }
        }
        cursor = end + 1;
    }
    if !stack.is_empty() {
        return Err("unterminated XML element".to_string());
    }
    if roots.len() != 1 {
        return Err("XML must contain exactly one root element".to_string());
    }
    Ok(roots.remove(0))
}

fn find_tag_end(input: &str, start: usize) -> Result<usize, String> {
    let mut quote = None;
    for (offset, byte) in input.as_bytes()[start..].iter().enumerate() {
        match (quote, byte) {
            (None, b'"') | (None, b'\'') => quote = Some(*byte),
            (Some(value), byte) if *byte == value => quote = None,
            (None, b'>') => return Ok(start + offset),
            _ => {}
        }
    }
    Err("unterminated XML tag".to_string())
}

fn parse_tag(body: &str) -> Result<(String, BTreeMap<String, String>), String> {
    let mut chars = body.char_indices().peekable();
    while chars.peek().is_some_and(|(_, value)| value.is_whitespace()) {
        chars.next();
    }
    let name_start = chars.peek().map(|(index, _)| *index).unwrap_or(0);
    while chars
        .peek()
        .is_some_and(|(_, value)| !value.is_whitespace())
    {
        chars.next();
    }
    let name_end = chars.peek().map(|(index, _)| *index).unwrap_or(body.len());
    let name = body[name_start..name_end].to_string();
    if name.is_empty() {
        return Err("XML tag has no name".to_string());
    }
    let mut attrs = BTreeMap::new();
    let mut cursor = name_end;
    while cursor < body.len() {
        while cursor < body.len() && body.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= body.len() {
            break;
        }
        let key_start = cursor;
        while cursor < body.len()
            && !body.as_bytes()[cursor].is_ascii_whitespace()
            && body.as_bytes()[cursor] != b'='
        {
            cursor += 1;
        }
        let key = normalize_name(&body[key_start..cursor]);
        while cursor < body.len() && body.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= body.len() || body.as_bytes()[cursor] != b'=' {
            return Err(format!("XML attribute {key} missing ="));
        }
        cursor += 1;
        while cursor < body.len() && body.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= body.len() || !matches!(body.as_bytes()[cursor], b'"' | b'\'') {
            return Err(format!("XML attribute {key} is not quoted"));
        }
        let quote = body.as_bytes()[cursor];
        cursor += 1;
        let value_start = cursor;
        while cursor < body.len() && body.as_bytes()[cursor] != quote {
            cursor += 1;
        }
        if cursor >= body.len() {
            return Err(format!("XML attribute {key} is unterminated"));
        }
        attrs.insert(key, decode_entities(&body[value_start..cursor]));
        cursor += 1;
    }
    Ok((name, attrs))
}

fn attach_node(stack: &mut Vec<XmlNode>, roots: &mut Vec<XmlNode>, node: XmlNode) {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else {
        roots.push(node);
    }
}

fn append_text(target: &mut String, value: String) {
    if target.len() < MAX_TEXT_BYTES {
        let remaining = MAX_TEXT_BYTES - target.len();
        let mut end = value.len().min(remaining);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        target.push_str(&value[..end]);
    }
}

fn decode_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lanes_without_faking_missing_evidence() {
        let xml = r#"<trace><row lane="hitches" start="1ms" duration="4ms"><name>Frame hitch</name></row><row lane="time-profiler" start="2ms" duration="2ms"><symbol>render()</symbol></row></trace>"#;
        let value = invoke(&json!({"operation":"analyze","xml":xml,"top":5})).unwrap();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["lanes"][0]["status"], "ok");
        assert_eq!(value["lanes"][1]["status"], "no_evidence");
    }

    #[test]
    fn filters_discovery_and_reports_no_evidence() {
        let xml =
            r#"<trace><row lane="logs" subsystem="ui"><message>Loaded</message></row></trace>"#;
        let value =
            invoke(&json!({"operation":"list-logs","xml":xml,"subsystem":"network"})).unwrap();
        assert_eq!(value["status"], "no_evidence");
    }

    #[test]
    fn correlates_intervals_and_fanin_sources() {
        let xml = r#"<trace><row lane="hitches" start="10ms" duration="10ms"/><row lane="time-profiler" start="12ms" duration="3ms"><symbol>draw()</symbol></row><row lane="swiftui-causes" destination="Editor" source="Settings"><time>1ms</time></row></trace>"#;
        let value = invoke(&json!({"operation":"analyze","xml":xml})).unwrap();
        assert_eq!(value["correlations"][0]["overlapNs"], 3_000_000);
        let fanin =
            invoke(&json!({"operation":"fanin-for","xml":xml,"destinationContains":"edit"}))
                .unwrap();
        assert_eq!(fanin["sources"][0]["source"], "Settings");
    }

    #[test]
    fn rejects_unbounded_or_malformed_xml() {
        assert!(invoke(&json!({"operation":"parse","xml":"<trace>"})).is_err());
        assert!(invoke(&json!({"operation":"parse","xml":""})).is_err());
    }
}
