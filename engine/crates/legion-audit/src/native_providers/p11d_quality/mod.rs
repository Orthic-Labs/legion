//! Packet P11d — the provider suite orchestrators that have a production
//! caller: `data_suite` and `infrastructure_suite` (dispatched by
//! `legacy::candidate_suites`) and `security_suite` (its five heuristic packs
//! are dispatched by `native_providers::security::packs`). Provider modules
//! with no production caller (ai-quality, accessibility, generic-source,
//! framework suites) were removed in the native-provider sweep.

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn digest_id(parts: &[&str]) -> String {
    format!("sha256:{}", sha256_hex(parts.join("\0").as_bytes()))
}

/// Preserve separate observations when one rule matches several writes on one
/// source line. Original adapter identity remains explicit in each record.
fn assign_candidate_instances(candidates: &mut [Value]) {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for candidate in candidates {
        let Some(original) = candidate
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let ordinal = counts.entry(original.clone()).or_default();
        candidate["sourceCandidateId"] = json!(original);
        candidate["sourceInstance"] = json!(*ordinal);
        if *ordinal > 0 {
            candidate["id"] = json!(digest_id(&[&original, &ordinal.to_string()]));
        }
        *ordinal += 1;
    }
}

/// Largest char boundary at or below `index` (clamped to the text length), so
/// byte-window slices never split a multi-byte character.
fn char_floor(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn line_at(text: &str, index: usize) -> usize {
    text.get(..index.min(text.len()))
        .unwrap_or("")
        .matches('\n')
        .count()
        + 1
}

// =====================================================================
// providers/data-suite.mjs :: runDataSuite
// =====================================================================
pub mod data_suite {
    use super::*;

    const DATA_EXTENSIONS: &[&str] = &[
        "sql", "ts", "tsx", "js", "mjs", "cjs", "py", "php", "rb", "go", "rs", "java", "kt", "cs",
    ];

    /// Whether the data suite inspects this path (by extension).
    pub fn inspects(file: &str) -> bool {
        let ext = std::path::Path::new(file)
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        DATA_EXTENSIONS.contains(&ext.as_str())
    }

    fn severity_hint(level: &str) -> &'static str {
        match level {
            "error" => "high",
            "warning" => "medium",
            _ => "low",
        }
    }

    fn candidate(rule_id: &str, level: &str, message: &str, file: &str, line: usize) -> Value {
        json!({
            "id": digest_id(&[rule_id, file, &line.to_string()]),
            "ruleId": rule_id, "severityHint": severity_hint(level), "claim": message, "file": file, "line": line,
            "evidence": [{"file": file, "line": line, "endLine": line}],
        })
    }

    struct Rule {
        id: &'static str,
        level: &'static str,
        message: &'static str,
        patterns: &'static [&'static str],
    }

    // Lookahead-free rules stay data-driven. Three JS rules use `(?!...)`
    // (unsupported by the `regex` crate) and are reimplemented below as
    // explicit scans with identical semantics.
    const RULES: &[Rule] = &[
        Rule {
            id: "data.sql-interpolation",
            level: "error",
            message: "SQL text appears to interpolate or concatenate variable input.",
            patterns: &[
                r#"(?is)(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP)[^\n;]*(?:\$\{|\+\s*(?:req|request|input|user|params|query)|format\s*\(|f['"])"#,
            ],
        },
        Rule {
            id: "data.destructive-migration",
            level: "warning",
            message: "Migration contains a destructive DROP operation; require backup, rollback, and compatibility evidence.",
            patterns: &[r#"(?i)\bDROP\s+(?:TABLE|COLUMN|DATABASE|INDEX)\b"#],
        },
        Rule {
            id: "data.sqlite-foreign-keys-off",
            level: "error",
            message: "SQLite foreign-key enforcement is disabled.",
            patterns: &[r#"(?i)PRAGMA\s+foreign_keys\s*=\s*(?:OFF|0)"#],
        },
        Rule {
            id: "data.redis-keys",
            level: "warning",
            message: "Redis KEYS can block the server; use bounded SCAN for production paths.",
            patterns: &[r#"\.(?:keys|KEYS)\s*\(\s*['"][^'"]*['"]\s*\)"#],
        },
        Rule {
            id: "data.mongo-javascript",
            level: "error",
            message: "MongoDB server-side JavaScript evaluation is used.",
            patterns: &[r#"(?i)\$(?:where|function)\b|mapReduce\s*\("#],
        },
    ];

    /// JS: `/\bADD\s+(?:COLUMN\s+)?[A-Za-z0-9_"\`]+[^;\n]*\bNOT\s+NULL\b(?![^;\n]*\bDEFAULT\b)/i`
    /// — `NOT NULL` not followed by `DEFAULT` before the next `;`/newline.
    fn collect_not_null_migration(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r#"(?i)\bADD\s+(?:COLUMN\s+)?[A-Za-z0-9_"`]+[^;\n]*\bNOT\s+NULL\b"#).unwrap()
        });
        for m in re.find_iter(text) {
            let rest_end = text[m.end()..]
                .find(|c| c == ';' || c == '\n')
                .map(|i| m.end() + i)
                .unwrap_or(text.len());
            let rest = &text[m.end()..rest_end];
            if !rest.to_lowercase().contains("default") {
                candidates.push(candidate(
                    "data.not-null-migration",
                    "warning",
                    "Migration adds NOT NULL without a visible default/backfill sequence.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    /// JS: `/sqlite(?:3)?[\s\S]{0,200}(?:connect|open)\s*\((?![\s\S]{0,300}(?:busy_timeout|timeout))/is`
    /// — an sqlite connect/open call not followed within 300 chars by a busy-timeout mention.
    fn collect_sqlite_no_busy_timeout(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"(?is)sqlite(?:3)?[\s\S]{0,200}(?:connect|open)\s*\(").unwrap()
        });
        for m in re.find_iter(text) {
            let end = char_floor(text, m.end() + 300);
            let window = &text[m.end()..end];
            if !Regex::new(r"(?i)busy_timeout|timeout")
                .unwrap()
                .is_match(window)
            {
                candidates.push(candidate("data.sqlite-no-busy-timeout", "note", "SQLite connection is configured without a visible busy timeout; assess lock contention.", file, line_at(text, m.start())));
            }
        }
    }

    /// Bound call arguments without joining unrelated statements. Strings and
    /// nested option objects remain intact so TTL evidence binds this write.
    fn call_arguments(text: &str, open: usize) -> Option<(Vec<String>, usize)> {
        let mut depth = 0usize;
        let mut quote = None;
        let mut escaped = false;
        let mut start = open + 1;
        let mut args = Vec::new();
        for (offset, character) in text[open..].char_indices() {
            let index = open + offset;
            if let Some(delimiter) = quote {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == delimiter {
                    quote = None;
                }
                continue;
            }
            match character {
                '\'' | '"' | '`' => quote = Some(character),
                '(' | '[' | '{' => depth += 1,
                ')' if depth == 1 => {
                    args.push(text[start..index].trim().to_owned());
                    return Some((args, index + 1));
                }
                ')' | ']' | '}' => depth = depth.checked_sub(1)?,
                ',' if depth == 1 => {
                    args.push(text[start..index].trim().to_owned());
                    start = index + 1;
                }
                _ => {}
            }
        }
        None
    }

    fn code_line(text: &str, offset: usize) -> bool {
        let bytes = text.as_bytes();
        let mut index = 0;
        let mut quote = None;
        let mut line_comment = false;
        let mut block_comment = false;
        while index < offset {
            let byte = bytes[index];
            if line_comment {
                if byte == b'\n' {
                    line_comment = false;
                }
            } else if block_comment {
                if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    block_comment = false;
                    index += 1;
                }
            } else if let Some(delimiter) = quote {
                if byte == b'\\' {
                    index += 1;
                } else if byte == delimiter {
                    quote = None;
                }
            } else if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
                line_comment = true;
                index += 1;
            } else if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
                block_comment = true;
                index += 1;
            } else if byte == b'#' {
                line_comment = true;
            } else if matches!(byte, b'\'' | b'"' | b'`') {
                quote = Some(byte);
            }
            index += 1;
        }
        quote.is_none() && !line_comment && !block_comment
    }

    fn enclosing_block_start(text: &str, offset: usize) -> usize {
        let mut braces = Vec::new();
        for (index, character) in text[..offset].char_indices() {
            if (character == '{' || character == '}') && code_line(text, index) {
                if character == '{' {
                    braces.push(index);
                } else {
                    braces.pop();
                }
            }
        }
        // Include the function name/atomicity comment before its opening brace.
        braces
            .last()
            .map(|open| text[..*open].rfind('\n').map_or(0, |index| index + 1))
            .unwrap_or(0)
    }

    struct RedisReceiver {
        name: String,
        start: usize,
        end: usize,
        shadows: Vec<(usize, usize)>,
    }

    struct FunctionScope {
        parameters: Vec<String>,
        start: usize,
        end: usize,
    }

    fn lexical_pairs(text: &str, open: char, close: char) -> Vec<(usize, usize)> {
        let mut stack = Vec::new();
        let mut pairs = Vec::new();
        for (index, character) in text.char_indices() {
            if !matches!(character, c if c == open || c == close) || !code_line(text, index) {
                continue;
            }
            if character == open {
                stack.push(index);
            } else if let Some(start) = stack.pop() {
                pairs.push((start, index));
            }
        }
        pairs
    }

    /// Locate a body after an optional TS return annotation. Type-literal and generic
    /// braces belong to the annotation; they cannot become an executable body.
    fn function_body_start(text: &str, parameters_end: usize) -> Option<usize> {
        let mut annotation = false;
        let mut needs_type = true;
        let mut stack = Vec::new();
        let mut arrow_end = None;
        for (relative, character) in text[parameters_end..].char_indices() {
            let index = parameters_end + relative;
            if character.is_whitespace() || !code_line(text, index) {
                continue;
            }
            if character == '/'
                && text
                    .as_bytes()
                    .get(index + 1)
                    .is_some_and(|byte| matches!(*byte, b'/' | b'*'))
            {
                continue;
            }
            if !annotation {
                if character == '{' {
                    return Some(index);
                }
                if character != ':' {
                    return None;
                }
                annotation = true;
                continue;
            }
            if !stack.is_empty() {
                match character {
                    '(' | '[' | '{' | '<' => stack.push(character),
                    ')' | ']' | '}' | '>' => {
                        let expected = match character {
                            ')' => '(',
                            ']' => '[',
                            '}' => '{',
                            _ => '<',
                        };
                        // A function type's => is not a generic closing bracket.
                        if character == '>'
                            && text.as_bytes().get(index.wrapping_sub(1)) == Some(&b'=')
                        {
                            continue;
                        }
                        if stack.pop()? != expected {
                            return None;
                        }
                    }
                    _ => {}
                }
                continue;
            }
            match character {
                '{' if !needs_type => return Some(index),
                '(' | '[' | '{' | '<' => {
                    stack.push(character);
                    needs_type = false;
                }
                '=' if text.as_bytes().get(index + 1) == Some(&b'>') => {
                    needs_type = true;
                    arrow_end = Some(index + 1);
                }
                '>' if arrow_end == Some(index) => {}
                '|' | '&' => needs_type = true,
                '.' => {}
                character if character.is_alphanumeric() || matches!(character, '_' | '$') => {
                    needs_type = false;
                }
                // Unsupported or incomplete annotation syntax stays unresolved.
                _ => return None,
            }
        }
        None
    }

    fn arrow_expression_end(text: &str, start: usize) -> Option<usize> {
        let mut stack = Vec::new();
        for (relative, character) in text[start..].char_indices() {
            let index = start + relative;
            if !code_line(text, index) {
                continue;
            }
            match character {
                '(' | '[' | '{' => stack.push(character),
                ')' | ']' | '}' => {
                    if stack.is_empty() {
                        return Some(index);
                    }
                    let expected = match character {
                        ')' => '(',
                        ']' => '[',
                        _ => '{',
                    };
                    if stack.pop()? != expected {
                        return None;
                    }
                }
                ',' | ';' if stack.is_empty() => return Some(index),
                _ => {}
            }
        }
        stack.is_empty().then_some(text.len())
    }

    fn function_scopes(text: &str, blocks: &[(usize, usize)]) -> Vec<FunctionScope> {
        let declarations =
            Regex::new(r"\bfunction\s*(?:\*\s*)?(?:[A-Za-z_$][\w$]*\s*)?\(").unwrap();
        let mut signatures = Vec::new();
        let mut scopes = declarations
            .find_iter(text)
            .filter(|matched| code_line(text, matched.start()))
            .filter_map(|matched| {
                let (parameters, end) = call_arguments(text, matched.end() - 1)?;
                let body = function_body_start(text, end)?;
                let (_, end) = blocks.iter().find(|(start, _)| *start == body)?;
                signatures.push((matched.start(), body));
                Some(FunctionScope {
                    parameters,
                    start: body,
                    end: *end,
                })
            })
            .collect::<Vec<_>>();
        let parentheses = lexical_pairs(text, '(', ')');
        let bare_parameter = Regex::new(r"([A-Za-z_$][\w$]*)$").unwrap();
        for (arrow, _) in text.match_indices("=>") {
            if !code_line(text, arrow)
                || signatures
                    .iter()
                    .any(|(start, body)| *start < arrow && arrow < *body)
            {
                continue;
            }
            let prefix = text[..arrow].trim_end();
            let parameters = if prefix.ends_with(')') {
                let close = prefix.len() - 1;
                let Some((open, _)) = parentheses.iter().find(|(_, end)| *end == close) else {
                    continue;
                };
                let Some((parameters, _)) = call_arguments(text, *open) else {
                    continue;
                };
                parameters
            } else if let Some(parameter) = bare_parameter.captures(prefix) {
                vec![parameter[1].to_owned()]
            } else {
                continue;
            };
            let after_arrow = arrow + 2;
            let tail = &text[after_arrow..];
            let start = after_arrow + tail.len() - tail.trim_start().len();
            let end = if text.as_bytes().get(start) == Some(&b'{') {
                blocks
                    .iter()
                    .find(|(open, _)| *open == start)
                    .map(|(_, end)| *end)
            } else {
                arrow_expression_end(text, start)
            };
            if let Some(end) = end {
                scopes.push(FunctionScope {
                    parameters,
                    start,
                    end,
                });
            }
        }
        scopes
    }

    fn loop_header_scope(
        text: &str,
        declaration: usize,
        parentheses: &[(usize, usize)],
        blocks: &[(usize, usize)],
    ) -> Option<(usize, usize)> {
        let for_header = Regex::new(r"\bfor(?:\s+await)?\s*$").unwrap();
        let (open, close) = parentheses.iter().find(|(open, close)| {
            *open < declaration
                && declaration < *close
                && text[open + 1..declaration].trim().is_empty()
                && for_header.is_match(&text[..*open])
        })?;
        let after_header = close + 1;
        let remaining = &text[after_header..];
        let body = after_header + remaining.len() - remaining.trim_start().len();
        let end = if text.as_bytes().get(body) == Some(&b'{') {
            blocks
                .iter()
                .find(|(start, _)| *start == body)
                .map(|(_, end)| *end)?
        } else {
            arrow_expression_end(text, body)?
        };
        Some((*open, end))
    }

    fn receiver_shadow_ranges(
        text: &str,
        name: &str,
        function: &FunctionScope,
        functions: &[FunctionScope],
        blocks: &[(usize, usize)],
    ) -> Vec<(usize, usize)> {
        let parameter_name = Regex::new(r"^\s*([A-Za-z_$][\w$]*)\s*(?:\?|:|$)").unwrap();
        let mut shadows = functions
            .iter()
            .filter(|nested| {
                nested.start > function.start
                    && nested.end < function.end
                    && nested.parameters.iter().any(|parameter| {
                        parameter_name
                            .captures(parameter)
                            .is_some_and(|capture| capture[1] == *name)
                    })
            })
            .map(|nested| (nested.start, nested.end))
            .collect::<Vec<_>>();
        let declarations =
            Regex::new(&format!(r"\b(const|let|var)\s+{}\b", regex::escape(name))).unwrap();
        let parentheses = lexical_pairs(text, '(', ')');
        for declaration in declarations.captures_iter(text) {
            let offset = declaration.get(0).unwrap().start();
            if offset <= function.start || offset >= function.end || !code_line(text, offset) {
                continue;
            }
            if &declaration[1] == "var" {
                if let Some(scope) = functions
                    .iter()
                    .filter(|scope| scope.start < offset && offset < scope.end)
                    .min_by_key(|scope| scope.end - scope.start)
                {
                    // A same-function var redeclares its parameter; its initializer can replace
                    // that value. A nested function's var instead shadows for its full lifetime.
                    let start = if scope.start == function.start {
                        offset
                    } else {
                        scope.start
                    };
                    shadows.push((start, scope.end));
                }
            } else if let Some(scope) = loop_header_scope(text, offset, &parentheses, blocks) {
                // A lexical declaration in a for header owns the header & loop body, not
                // the surrounding function block. `var` retains its function lifetime above.
                shadows.push(scope);
            } else if let Some((start, end)) = blocks
                .iter()
                .filter(|(start, end)| *start < offset && offset < *end)
                .min_by_key(|(start, end)| end - start)
            {
                shadows.push((*start, *end));
            }
        }
        shadows
    }

    fn redis_receivers(text: &str) -> Vec<RedisReceiver> {
        let imported = Regex::new(r#"(?i)(?:from\s*['"](?:redis|ioredis)['"]|require\s*\(\s*['"](?:redis|ioredis)['"]|import\s+redis\b|from\s+redis\b)"#).unwrap().is_match(text);
        if !imported {
            return Vec::new();
        }
        let bindings = Regex::new(r"(?m)\b([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?(?:Redis|redis\.Redis|redis\.StrictRedis|createClient|redis\.createClient)\s*\(").unwrap();
        let mut receivers = bindings
            .captures_iter(text)
            .filter(|capture| code_line(text, capture.get(0).unwrap().start()))
            .map(|capture| RedisReceiver {
                name: capture[1].to_owned(),
                start: capture.get(0).unwrap().end(),
                end: text.len(),
                shadows: Vec::new(),
            })
            .collect::<Vec<_>>();

        // Injected clients have no constructor in this file. Bind known exported Redis types
        // to their actual import alias, then confine each parameter to its function body.
        let imports =
            Regex::new(r#"\bimport\s+(?:type\s+)?\{([^}]+)\}\s+from\s*['"]redis['"]"#).unwrap();
        let exported_type = Regex::new(
            r"^(?:type\s+)?(RedisClientType|RedisClusterType)(?:\s+as\s+([A-Za-z_$][\w$]*))?$",
        )
        .unwrap();
        let types = imports
            .captures_iter(text)
            .filter(|capture| code_line(text, capture.get(0).unwrap().start()))
            .flat_map(|capture| {
                capture[1]
                    .split(',')
                    .filter_map(|item| {
                        let binding = exported_type.captures(item.trim())?;
                        Some(
                            binding
                                .get(2)
                                .unwrap_or_else(|| binding.get(1).unwrap())
                                .as_str()
                                .to_owned(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        if types.is_empty() {
            return receivers;
        }
        let blocks = lexical_pairs(text, '{', '}');
        let functions = function_scopes(text, &blocks);
        for function in &functions {
            for parameter in &function.parameters {
                for type_name in &types {
                    let annotation = Regex::new(&format!(
                        r"^\s*([A-Za-z_$][\w$]*)\s*\??\s*:\s*{}\s*(?:<[^>]*>\s*)?$",
                        regex::escape(type_name)
                    ))
                    .unwrap();
                    let Some(binding) = annotation.captures(parameter) else {
                        continue;
                    };
                    let name = binding[1].to_owned();
                    let shadows =
                        receiver_shadow_ranges(text, &name, function, &functions, &blocks);
                    receivers.push(RedisReceiver {
                        name,
                        start: function.start,
                        end: function.end,
                        shadows,
                    });
                }
            }
        }
        receivers
    }

    fn positive_ttl(arguments: &[String]) -> bool {
        let options = arguments.get(2..).unwrap_or_default().join(",");
        if options.contains("...") || options.contains("**") {
            return false;
        }
        // Literal positive expirations only. Variables retain unknown status.
        let expiry_keys = Regex::new(r#"(?i)['"]?(?:EX|PX|EXAT|PXAT)['"]?\s*[:,=]"#).unwrap();
        if expiry_keys.find_iter(&options).count() != 1 {
            return false;
        }
        Regex::new(
            r#"(?i)(?:['"]?(?:EX|PX|EXAT|PXAT)['"]?\s*[:,=]\s*)([1-9][0-9]*)(?:\s*[,}\)]|\s*$)"#,
        )
        .unwrap()
        .is_match(&options)
    }

    fn collect_redis_unbounded_value(text: &str, file: &str, candidates: &mut Vec<Value>) {
        let ephemeral =
            Regex::new(r"(?i)session|cache|token|temp|ephemeral|lock|nonce|otp").unwrap();
        let mut observed_calls = std::collections::BTreeSet::new();
        for receiver in redis_receivers(text) {
            let calls = Regex::new(&format!(
                r"\b{}\.(set|hset)\s*\(",
                regex::escape(&receiver.name)
            ))
            .unwrap();
            for capture in calls.captures_iter(text) {
                let matched = capture.get(0).unwrap();
                if matched.start() < receiver.start
                    || matched.start() >= receiver.end
                    || receiver
                        .shadows
                        .iter()
                        .any(|(start, end)| matched.start() >= *start && matched.start() < *end)
                    || !code_line(text, matched.start())
                    || !observed_calls.insert(matched.start())
                {
                    continue;
                }
                let Some((args, end)) = call_arguments(text, matched.end() - 1) else {
                    continue;
                };
                if args.len() < 2 {
                    continue;
                }
                let key = &args[0];
                let tail = &text[end..char_floor(text, end + 300)];
                let expire = Regex::new(&format!(
                    r"^\s*;?\s*(?:await\s+)?{}\.(?:expire|pexpire)\s*\(",
                    regex::escape(&receiver.name)
                ))
                .unwrap();
                let expires_same_key = expire
                    .find(tail)
                    .and_then(|matched| call_arguments(tail, matched.end() - 1))
                    .is_some_and(|(expiry, _)| {
                        expiry.first() == Some(key)
                            && expiry
                                .get(1)
                                .is_some_and(|value| value.parse::<u64>().is_ok_and(|ttl| ttl > 0))
                    });
                if (capture.get(1).unwrap().as_str() == "set" && positive_ttl(&args))
                    || expires_same_key
                {
                    continue;
                }
                let required = ephemeral.is_match(key);
                let mut value = candidate(
                    "data.redis-unbounded-value",
                    "warning",
                    if required {
                        "Redis ephemeral key write has no bound positive expiration."
                    } else {
                        "Redis write retention policy is unknown; establish durable-key intent or bind expiration."
                    },
                    file,
                    line_at(text, matched.start()),
                );
                value["applicability"] = json!({"library":"redis","receiver":receiver.name,"retentionPolicy":if required {"ephemeral-ttl-required"} else {"unknown-durable-intent"},"status":if required {"applicable"} else {"unknown"}});
                candidates.push(value);
            }
        }
    }

    fn collect_transaction_missing(text: &str, file: &str, candidates: &mut Vec<Value>) {
        // A receiver name alone (db, model, store) is not database evidence.
        let library = Regex::new(r#"(?i)(?:from\s*['"](?:@prisma/client|knex|sequelize|better-sqlite3|typeorm|mongoose)['"]|require\s*\(\s*['"](?:knex|sequelize|better-sqlite3|mongoose)['"])"#).unwrap();
        if !library.is_match(text) {
            return;
        }
        let bindings = Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?(?:PrismaClient|Sequelize|Database|knex|createConnection|createDataSource)\s*\(").unwrap();
        let atomic =
            Regex::new(r"(?i)\b(?:atomic|atomically|transfer|debit|credit|all.or.nothing)\b")
                .unwrap();
        for binding in bindings.captures_iter(text) {
            if !code_line(text, binding.get(0).unwrap().start()) {
                continue;
            }
            let receiver = &binding[1];
            let writes = Regex::new(&format!(r"\b{}(?:\.[A-Za-z_$][\w$]*)?\.(?:insert|update|delete|save|create|insertOne|updateOne|deleteOne)\s*\(", regex::escape(receiver))).unwrap();
            let matches = writes
                .find_iter(text)
                .filter(|matched| code_line(text, matched.start()))
                .collect::<Vec<_>>();
            for pair in matches.windows(2) {
                if pair[1].start().saturating_sub(pair[0].start()) > 500 {
                    continue;
                }
                let start = enclosing_block_start(text, pair[0].start());
                if start != enclosing_block_start(text, pair[1].start()) {
                    continue;
                }
                let end = char_floor(text, pair[1].end() + 300);
                let context = &text[start..end];
                // Transaction evidence must be executable & bound to this receiver.
                let transaction_bound = Regex::new(&format!(
                    r"\b{}\.(?:\$?transaction|beginTransaction)\s*\(",
                    regex::escape(receiver)
                ))
                .unwrap();
                if transaction_bound
                    .find_iter(context)
                    .any(|matched| code_line(text, start + matched.start()))
                {
                    continue;
                }
                let required = atomic.is_match(context);
                let mut value = candidate(
                    "data.transaction-missing",
                    "warning",
                    if required {
                        "Related database writes require atomicity but have no visible transaction boundary."
                    } else {
                        "Multiple database writes have unknown atomicity requirements; verify transaction scope."
                    },
                    file,
                    line_at(text, pair[0].start()),
                );
                value["applicability"] = json!({"library":"database","receiver":receiver,"atomicity":if required {"required"} else {"unknown"},"status":if required {"applicable"} else {"unknown"}});
                candidates.push(value);
                break;
            }
        }
    }

    pub fn run_data_suite(root: &std::path::Path, files: &[String]) -> Value {
        let mut candidates = Vec::new();
        for file in files {
            let ext = std::path::Path::new(file)
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            if !DATA_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            for rule in RULES {
                for pattern in rule.patterns {
                    let re = Regex::new(pattern).unwrap();
                    for m in re.find_iter(&text) {
                        candidates.push(candidate(
                            rule.id,
                            rule.level,
                            rule.message,
                            file,
                            line_at(&text, m.start()),
                        ));
                    }
                }
            }
            collect_not_null_migration(&text, file, &mut candidates);
            collect_sqlite_no_busy_timeout(&text, file, &mut candidates);
            collect_redis_unbounded_value(&text, file, &mut candidates);
            collect_transaction_missing(&text, file, &mut candidates);
        }
        assign_candidate_instances(&mut candidates);
        json!({
            "schemaVersion": 1, "provider": "data.internal-suite", "providerVersion": "1.0.0",
            "ownerProvider": "data.internal-suite", "phase": "runtime", "role": "candidate-generator",
            "status": if candidates.is_empty() { "pass" } else { "candidates" },
            "complete": true, "applicable": true, "required": true,
            "coverage": { "pathCount": files.len(), "rules": RULES.len() + 4 },
            "candidates": candidates, "findings": [], "receipts": [], "coverageGaps": [], "degradation": [],
        })
    }
}

// =====================================================================
// providers/infrastructure-suite.mjs :: runInfrastructureSuite
// =====================================================================
pub mod infrastructure_suite {
    use super::*;

    fn severity_hint(level: &str) -> &'static str {
        match level {
            "critical" | "error" => "high",
            "warning" => "medium",
            _ => "low",
        }
    }

    fn candidate(rule_id: &str, level: &str, message: &str, file: &str, line: usize) -> Value {
        json!({
            "id": digest_id(&[rule_id, file, &line.to_string()]),
            "ruleId": rule_id, "severityHint": severity_hint(level), "claim": message, "file": file, "line": line,
            "evidence": [{"file": file, "line": line, "endLine": line}],
        })
    }

    type Applies = fn(&str, &str) -> bool;

    struct Rule {
        id: &'static str,
        level: &'static str,
        message: &'static str,
        pattern: &'static str,
        applies: Applies,
    }

    fn is_dockerfile(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)^Dockerfile").unwrap().is_match(
            std::path::Path::new(file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(""),
        )
    }
    fn is_dockerfile_no_user(file: &str, text: &str) -> bool {
        is_dockerfile(file, text) && !Regex::new(r"(?im)^\s*USER\s+").unwrap().is_match(text)
    }
    fn is_yaml(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.ya?ml$").unwrap().is_match(file)
    }
    fn is_workflow(file: &str, _text: &str) -> bool {
        file.starts_with(".github/workflows/")
    }
    fn is_workflow_pr_target(file: &str, text: &str) -> bool {
        is_workflow(file, text) && text.contains("pull_request_target")
    }
    fn is_tf(file: &str, _text: &str) -> bool {
        file.ends_with(".tf")
    }
    fn is_release_script(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.(?:sh|ps1|mjs|cjs|js|py|rb|yml|yaml|toml|json)$")
            .unwrap()
            .is_match(file)
    }
    fn is_release_script_narrow(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.(?:sh|ps1|mjs|cjs|js|py|rb)$")
            .unwrap()
            .is_match(file)
    }
    fn is_tauri_conf(file: &str, _text: &str) -> bool {
        Regex::new(r"(?:tauri\.conf\.(?:json|json5)|Tauri\.toml)$")
            .unwrap()
            .is_match(file)
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "container.latest-tag",
            level: "warning",
            message: "Container base image is unpinned or uses latest.",
            pattern: r"(?im)^\s*FROM\s+[^\s:@]+(?::latest)?\s*$",
            applies: is_dockerfile,
        },
        Rule {
            id: "container.remote-add",
            level: "warning",
            message: "Docker ADD fetches a mutable remote resource without explicit integrity verification.",
            pattern: r"(?im)^\s*ADD\s+https?://",
            applies: is_dockerfile,
        },
        Rule {
            id: "container.curl-pipe-shell",
            level: "error",
            message: "Container build pipes remote content directly to a shell.",
            pattern: r"(?i)(?:curl|wget)[^\n|]*\|\s*(?:sh|bash|zsh)",
            applies: is_dockerfile,
        },
        Rule {
            id: "container-root-user",
            level: "warning",
            message: "Container has no explicit non-root USER.",
            pattern: r"(?im)^\s*FROM\s+",
            applies: is_dockerfile_no_user,
        },
        Rule {
            id: "k8s-privileged",
            level: "error",
            message: "Kubernetes workload enables privileged mode.",
            pattern: r"(?i)privileged:\s*true",
            applies: is_yaml,
        },
        Rule {
            id: "k8s-host-namespace",
            level: "error",
            message: "Kubernetes workload joins a host namespace.",
            pattern: r"(?i)(?:hostNetwork|hostPID|hostIPC):\s*true",
            applies: is_yaml,
        },
        Rule {
            id: "k8s-unpinned-image",
            level: "warning",
            message: "Kubernetes image is not digest-pinned.",
            pattern: r"(?im)image:\s*[^\s@]+(?::latest)?\s*$",
            applies: is_yaml,
        },
        Rule {
            id: "k8s-secret-literal",
            level: "error",
            message: "Secret-like value appears inline in deployment YAML.",
            pattern: r#"(?i)(?:password|secret|token|api[_-]?key):\s*['"]?[^\s${][^\n]{5,}"#,
            applies: is_yaml,
        },
        Rule {
            id: "actions-write-all",
            level: "error",
            message: "GitHub Actions grants write-all permissions.",
            pattern: r"(?i)permissions:\s*write-all",
            applies: is_workflow,
        },
        Rule {
            id: "actions-unpinned",
            level: "warning",
            message: "GitHub Action is not pinned to an immutable commit.",
            pattern: r"(?im)uses:\s*[^\s@]+@(?:main|master|latest|v?\d+(?:\.\d+)?)\s*$",
            applies: is_workflow,
        },
        Rule {
            id: "actions-expression-in-shell",
            level: "error",
            message: "Attacker-controlled event data is interpolated directly into a shell command.",
            pattern: r"(?i)run:\s*[^\n]*\$\{\{\s*github\.event\.",
            applies: is_workflow,
        },
        Rule {
            id: "actions-pr-target-checkout",
            level: "critical",
            message: "Privileged pull_request_target workflow checks out attacker-controlled head code.",
            pattern: r"(?i)ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}",
            applies: is_workflow_pr_target,
        },
        Rule {
            id: "terraform-open-ingress",
            level: "error",
            message: "Terraform security rule allows global IPv4 access.",
            pattern: r#"(?i)cidr_blocks\s*=\s*\[[^\]]*['"]0\.0\.0\.0/0['"][^\]]*\]"#,
            applies: is_tf,
        },
        Rule {
            id: "terraform-public-storage",
            level: "error",
            message: "Infrastructure configuration enables public storage access.",
            pattern: r"(?i)(?:acl\s*=\s*['\x22]public|public_access\s*=\s*true|block_public_acls\s*=\s*false)",
            applies: is_tf,
        },
        Rule {
            id: "release-mutable-download",
            level: "warning",
            message: "Release tooling downloads from a mutable latest URL.",
            pattern: r#"(?i)https?://[^\s'"]+/(?:latest|releases/latest|download/latest)[^\s'"]*"#,
            applies: is_release_script,
        },
        Rule {
            id: "tauri-updater-insecure",
            level: "error",
            message: "Tauri updater permits insecure transport.",
            pattern: r"(?i)dangerousInsecureTransportProtocol\s*[:=]\s*true",
            applies: is_tauri_conf,
        },
    ];

    /// JS: `/(?:curl|wget|Invoke-WebRequest|fetch\s*\()[\s\S]{0,300}https?:\/\/(?![\s\S]{0,500}(?:sha256|checksum|digest|integrity))/is`
    /// (unsupported lookahead) — a download call whose URL has no integrity
    /// keyword within 500 chars after it.
    fn collect_release_download_no_hash(file: &str, text: &str, candidates: &mut Vec<Value>) {
        if !is_release_script_narrow(file, text) {
            return;
        }
        static PREFIX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let prefix_re = PREFIX.get_or_init(|| {
            Regex::new(r"(?is)(?:curl|wget|Invoke-WebRequest|fetch\s*\()[\s\S]{0,300}https?://")
                .unwrap()
        });
        static INTEGRITY: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let integrity_re =
            INTEGRITY.get_or_init(|| Regex::new(r"(?i)sha256|checksum|digest|integrity").unwrap());
        for m in prefix_re.find_iter(text) {
            let end = char_floor(text, m.end() + 500);
            if !integrity_re.is_match(&text[m.end()..end]) {
                candidates.push(candidate(
                    "release-download-no-hash",
                    "warning",
                    "Downloaded release artifact has no nearby integrity verification.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    pub fn run_infrastructure_suite(root: &std::path::Path, files: &[String]) -> Value {
        let mut candidates = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            for rule in RULES {
                if !(rule.applies)(file, &text) {
                    continue;
                }
                let re = Regex::new(rule.pattern).unwrap();
                for m in re.find_iter(&text) {
                    candidates.push(candidate(
                        rule.id,
                        rule.level,
                        rule.message,
                        file,
                        line_at(&text, m.start()),
                    ));
                }
            }
            collect_release_download_no_hash(file, &text, &mut candidates);
        }
        assign_candidate_instances(&mut candidates);
        json!({
            "schemaVersion": 1, "provider": "infrastructure.internal-suite", "providerVersion": "1.0.0",
            "ownerProvider": "infrastructure.internal-suite", "phase": "runtime", "role": "candidate-generator",
            "status": if candidates.is_empty() { "pass" } else { "candidates" },
            "complete": true, "applicable": true, "required": true,
            "coverage": { "pathCount": files.len(), "rules": RULES.len() + 1 },
            "candidates": candidates, "findings": [], "receipts": [], "coverageGaps": [], "degradation": [],
        })
    }
}

// =====================================================================
// providers/security-suite.mjs
//
// Lives in `security_suite.rs`. Production dispatch of its five packs is
// `native_providers::security::packs` (provider ids `security.credentials`,
// `security.insecure-defaults`, `security.misuse-resistance`,
// `security.agentic-ci`, `security.agent-skill-mcp`).
// =====================================================================
pub mod security_suite;
