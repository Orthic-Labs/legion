//! Port of `skills/designer/engine/scripts/live/svelte-component.mjs`.
//!
//! This chunk ports the pure, testable parsing/rewriting core: mustache
//! expression extraction, prop-contract derivation, `.svelte` file
//! parsing, opening-tag/attribute merging, the accepted-variant CSS
//! sanitizer (a hand-rolled CSS rule parser + selector rewriter), and the
//! static authoring-guidance payload.
//!
//! NOT ported in this chunk (filesystem/session orchestration tied to the
//! Node CLI's on-disk session store under `node_modules/.impeccable-live/`
//! and the OS temp dir; no Rust caller exists for this workflow yet):
//! `ensureRuntimeHelper`, `scaffoldSvelteComponentSession`,
//! `scaffoldSvelteComponentInsertSession`, `findSvelteComponentManifest`,
//! `readManifest`, `resolveSourceFile`, `inlineSvelteComponentAccept`,
//! `inlineSvelteComponentInsertAccept`, `removeSvelteComponentSession`,
//! `removeAllSvelteComponentSessions`, `deferredAcceptsPath`,
//! `readDeferredAccepts`, `writeDeferredAccept`,
//! `applyDeferredSvelteComponentAccepts`. These call the pure functions
//! ported here for their actual logic; only the fs glue is left.

use std::collections::HashSet;

pub const SVELTE_COMPONENT_ROOT: &str = "node_modules/.impeccable-live";
pub const DEFERRED_ACCEPTS_FILE: &str = ".impeccable/live/deferred-svelte-component-accepts.json";

/// One entry of a prop contract: `{ prop, expr, placeholder }` in the JS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropContractEntry {
    pub prop: String,
    pub expr: String,
    pub placeholder: String,
}

/// Port of `extractMustacheExpressions`: ordered, unique `{expr}` mustache
/// expressions found in markup, skipping lines that start with `<!--`
/// after trimming.
pub fn extract_mustache_expressions(text: &str) -> Vec<String> {
    let mut expressions = Vec::new();
    let mut seen = HashSet::new();
    for line in text.split('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with("<!--") {
            continue;
        }
        for expr in mustache_matches(line) {
            let expr = expr.trim().to_string();
            if expr.is_empty() || seen.contains(&expr) {
                continue;
            }
            seen.insert(expr.clone());
            expressions.push(expr);
        }
    }
    expressions
}

/// Finds `{...}` spans with no nested `{`/`}` (matches JS `/\{([^{}]+)\}/g`).
fn mustache_matches(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'{' && bytes[j] != b'}' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'}' {
                out.push(&line[start..j]);
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Port of `buildPropContract`.
pub fn build_prop_contract(expressions: &[String]) -> Vec<PropContractEntry> {
    expressions
        .iter()
        .enumerate()
        .map(|(index, expr)| {
            let prop = derive_prop_name(expr, index);
            PropContractEntry {
                prop,
                expr: expr.clone(),
                placeholder: format!("{{{}}}", expr),
            }
        })
        .collect()
}

/// Port of `derivePropName`: matches trailing `.ident` or `[ident]` (plain
/// identifier only — JS regex is `/(?:\.|\[)(\w+)\s*\]?$/` then validated
/// against `/^[A-Za-z_$][\w$]*$/`).
fn derive_prop_name(expr: &str, index: usize) -> String {
    if let Some(tail) = trailing_dot_or_bracket_ident(expr) {
        if is_valid_ident(&tail) {
            return tail;
        }
    }
    format!("prop{}", index)
}

fn trailing_dot_or_bracket_ident(expr: &str) -> Option<String> {
    // Reproduce `(?:\.|\[)(\w+)\s*\]?$`: find the LAST '.' or '[' such that
    // everything after it is `\w+` optionally followed by whitespace and an
    // optional trailing ']'.
    let chars: Vec<char> = expr.chars().collect();
    let mut end = chars.len();
    // Strip an optional trailing ']'.
    if end > 0 && chars[end - 1] == ']' {
        end -= 1;
    }
    // Strip trailing whitespace before that.
    let mut word_end = end;
    while word_end > 0 && chars[word_end - 1].is_whitespace() {
        word_end -= 1;
    }
    // Walk back over \w characters.
    let mut word_start = word_end;
    while word_start > 0 && (chars[word_start - 1].is_alphanumeric() || chars[word_start - 1] == '_') {
        word_start -= 1;
    }
    if word_start == word_end {
        return None;
    }
    if word_start == 0 {
        return None;
    }
    let sep = chars[word_start - 1];
    if sep != '.' && sep != '[' {
        return None;
    }
    Some(chars[word_start..word_end].iter().collect())
}

fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

/// Port of `substituteExprsWithProps`.
pub fn substitute_exprs_with_props(markup: &str, contract: &[PropContractEntry]) -> String {
    let mut out = markup.to_string();
    for entry in contract {
        out = out.replace(&entry.placeholder, &format!("{{{}}}", entry.prop));
    }
    out
}

/// Port of `substitutePropsWithExprs`.
pub fn substitute_props_with_exprs(markup: &str, contract: &[PropContractEntry]) -> String {
    let mut out = markup.to_string();
    for entry in contract {
        let prop_placeholder = format!("{{{}}}", entry.prop);
        out = out.replace(&prop_placeholder, &format!("{{{}}}", entry.expr));
    }
    out
}

/// Result of `parseSvelteComponentFile`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedSvelteFile {
    pub markup: String,
    pub css_lines: Vec<String>,
    pub style_block: String,
}

/// Port of `parseSvelteComponentFile`.
pub fn parse_svelte_component_file(content: &str) -> ParsedSvelteFile {
    let script_re = script_block_regex();
    let without_script = if let Some(m) = script_re.find(content) {
        &content[m.end()..]
    } else {
        content
    };

    let style_re = style_block_regex();
    let style_match = style_re.find(without_script);
    let (markup, style_block) = match style_match {
        Some(m) => (without_script[..m.start()].trim().to_string(), m.as_str().to_string()),
        None => (without_script.trim().to_string(), String::new()),
    };

    let mut css_lines: Vec<String> = if !style_block.is_empty() {
        let inner = strip_style_tags(&style_block);
        inner.split('\n').map(|l| l.trim_end().to_string()).collect()
    } else {
        Vec::new()
    };
    while css_lines.first().is_some_and(|l| l.trim().is_empty()) {
        css_lines.remove(0);
    }
    while css_lines.last().is_some_and(|l| l.trim().is_empty()) {
        css_lines.pop();
    }

    ParsedSvelteFile { markup, css_lines, style_block }
}

fn script_block_regex() -> regex::Regex {
    // JS: /^([\s\S]*?)<script\b[^>]*>[\s\S]*?<\/script>/i (non-greedy, from start)
    regex::RegexBuilder::new(r"(?s)^.*?<script\b[^>]*>.*?</script>")
        .case_insensitive(true)
        .build()
        .expect("valid regex")
}

fn style_block_regex() -> regex::Regex {
    regex::RegexBuilder::new(r"(?s)<style\b[^>]*>.*?</style\s*>")
        .case_insensitive(true)
        .build()
        .expect("valid regex")
}

fn strip_style_tags(style_block: &str) -> String {
    let open_re = regex::RegexBuilder::new(r"^<style\b[^>]*>")
        .case_insensitive(true)
        .build()
        .unwrap();
    let close_re = regex::RegexBuilder::new(r"</style\s*>$")
        .case_insensitive(true)
        .build()
        .unwrap();
    let s = open_re.replace(style_block, "");
    close_re.replace(&s, "").into_owned()
}

/// Port of the private `buildPropsScript` helper.
pub fn build_props_script(contract: &[PropContractEntry]) -> String {
    if contract.is_empty() {
        return "<script>\n  /** @type {Record<string, never>} */\n  let {} = $props();\n</script>\n"
            .to_string();
    }
    let names = contract.iter().map(|c| c.prop.as_str()).collect::<Vec<_>>().join(", ");
    let type_fields = contract
        .iter()
        .map(|c| format!("    {}: string;", c.prop))
        .collect::<Vec<_>>()
        .join("\n");
    format!("<script>\n  /** @type {{{{\n{}\n  }}}} */\n  let {{ {} }} = $props();\n</script>\n", type_fields, names)
}

/// Port of `buildVariantStub`.
pub fn build_variant_stub(variant_num: i64, original_with_props: &str, contract: &[PropContractEntry]) -> String {
    let props_comment = if !contract.is_empty() {
        let joined = contract
            .iter()
            .map(|c| format!("{} <- {{{}}}", c.prop, c.expr))
            .collect::<Vec<_>>()
            .join(", ");
        format!("\n<!-- Props: {} -->\n", joined)
    } else {
        String::new()
    };
    format!(
        "{}{}{}\n\n<style>\n  /* Variant {}: add scoped CSS here */\n</style>\n",
        build_props_script(contract),
        props_comment,
        original_with_props.trim(),
        variant_num
    )
}

/// Port of `buildInsertVariantStub`.
pub fn build_insert_variant_stub(variant_num: i64) -> String {
    format!(
        "{}<div class=\"impeccable-insert-preview\">Insert variant {}</div>\n\n<style>\n  .impeccable-insert-preview {{ display: block; }}\n</style>\n",
        build_props_script(&[]),
        variant_num
    )
}

/// Result of `matchOpeningTag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningTag {
    pub raw: String,
    pub prefix: String,
    pub tag: String,
    pub attrs: String,
    pub close: String,
    pub index: usize,
}

/// Port of `matchOpeningTag`.
pub fn match_opening_tag(markup: &str) -> Option<OpeningTag> {
    let re = regex::Regex::new(r"^(\s*<)([A-Za-z][\w:-]*)([^>]*?)(/?>)").unwrap();
    let caps = re.captures(markup)?;
    let whole = caps.get(0)?;
    Some(OpeningTag {
        raw: whole.as_str().to_string(),
        prefix: caps.get(1)?.as_str().to_string(),
        tag: caps.get(2)?.as_str().to_string(),
        attrs: caps.get(3).map(|m| m.as_str().to_string()).unwrap_or_default(),
        close: caps.get(4)?.as_str().to_string(),
        index: whole.start(),
    })
}

/// One parsed attribute segment (mirrors the JS `Map` entries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrSegment {
    pub name: String,
    pub raw: String,
    pub start: usize,
    pub end: usize,
}

/// Port of `parseAttrSegments`: ordered map keyed by attribute name (last
/// occurrence wins, matching JS `Map.set` semantics), values keep insertion
/// order of first-seen positions via a parallel `Vec` for iteration.
pub fn parse_attr_segments(attrs: &str) -> Vec<AttrSegment> {
    let re = regex::Regex::new(
        r#"(?x)
        ([A-Za-z_:][\w:.\-]*)
        (?:\s*=\s*(?:"[^"]*"|'[^']*'|\{[^}]*\}|[^\s"'>=]+))?
        "#,
    )
    .unwrap();
    let mut out: Vec<AttrSegment> = Vec::new();
    for m in re.find_iter(attrs) {
        let raw = m.as_str().to_string();
        let name_caps = re.captures(m.as_str()).unwrap();
        let name = name_caps.get(1).unwrap().as_str().to_string();
        let seg = AttrSegment { name: name.clone(), raw, start: m.start(), end: m.end() };
        if let Some(existing) = out.iter_mut().find(|s| s.name == name) {
            *existing = seg;
        } else {
            out.push(seg);
        }
    }
    out
}

fn find_attr<'a>(segs: &'a [AttrSegment], name: &str) -> Option<&'a AttrSegment> {
    segs.iter().find(|s| s.name == name)
}

/// Port of `mergeStaticClassAttr`.
pub fn merge_static_class_attr(original_class: &AttrSegment, variant_class: &AttrSegment) -> Option<String> {
    let class_value_re = regex::Regex::new(r#"class\s*=\s*(["'])(.*?)\1"#).unwrap();
    let original_value = class_value_re.captures(&original_class.raw)?;
    let variant_value = class_value_re.captures(&variant_class.raw)?;
    let quote = variant_value.get(1)?.as_str();
    let mut seen = HashSet::new();
    let mut classes = Vec::new();
    for cls in variant_value.get(2)?.as_str().split_whitespace().chain(original_value.get(2)?.as_str().split_whitespace()) {
        if !cls.is_empty() && seen.insert(cls) {
            classes.push(cls);
        }
    }
    Some(format!("class={}{}{}", quote, classes.join(" "), quote))
}

/// Port of `mergeOriginalTopLevelAttrs`.
pub fn merge_original_top_level_attrs(markup: &str, original_markup: &str) -> String {
    let variant_open = match match_opening_tag(markup) {
        Some(v) => v,
        None => return markup.to_string(),
    };
    let original_open = match match_opening_tag(original_markup) {
        Some(v) => v,
        None => return markup.to_string(),
    };
    if variant_open.tag.to_lowercase() != original_open.tag.to_lowercase() {
        return markup.to_string();
    }

    let variant_attrs_segs = parse_attr_segments(&variant_open.attrs);
    let original_attrs_segs = parse_attr_segments(&original_open.attrs);

    let mut additions: Vec<String> = Vec::new();
    let mut attrs = variant_open.attrs.clone();

    let original_class = find_attr(&original_attrs_segs, "class");
    let variant_class = find_attr(&variant_attrs_segs, "class");
    let attrs_changed;
    if let (Some(oc), Some(vc)) = (original_class, variant_class) {
        if let Some(merged) = merge_static_class_attr(oc, vc) {
            attrs = format!("{}{}{}", &attrs[..vc.start], merged, &attrs[vc.end..]);
        }
        attrs_changed = attrs != variant_open.attrs;
    } else {
        attrs_changed = false;
        if let Some(oc) = original_class {
            if variant_class.is_none() {
                additions.push(oc.raw.clone());
            }
        }
    }

    for seg in &original_attrs_segs {
        if seg.name == "class" {
            continue;
        }
        if find_attr(&variant_attrs_segs, &seg.name).is_none() {
            additions.push(seg.raw.clone());
        }
    }

    if additions.is_empty() && !attrs_changed {
        return markup.to_string();
    }

    let addition_str: String = additions.iter().map(|a| format!(" {}", a.trim())).collect();
    let next_open = format!("{}{}{}{}{}", variant_open.prefix, variant_open.tag, attrs, addition_str, variant_open.close);
    format!(
        "{}{}{}",
        &markup[..variant_open.index],
        next_open,
        &markup[variant_open.index + variant_open.raw.len()..]
    )
}

/// Port of `svelteMarkupHasVisibleContent`.
pub fn svelte_markup_has_visible_content(markup: &str) -> bool {
    let script_re = regex::RegexBuilder::new(r"(?is)<script[\s\S]*?</script>").build().unwrap();
    let style_re = regex::RegexBuilder::new(r"(?is)<style[\s\S]*?</style>").build().unwrap();
    let comment_re = regex::RegexBuilder::new(r"(?s)<!--[\s\S]*?-->").build().unwrap();
    let tag_re = regex::Regex::new(r"<[^>]+>").unwrap();
    let ws_re = regex::Regex::new(r"\s+").unwrap();

    let mut text = script_re.replace_all(markup, "").into_owned();
    text = style_re.replace_all(&text, "").into_owned();
    text = comment_re.replace_all(&text, "").into_owned();
    text = tag_re.replace_all(&text, " ").into_owned();
    text = ws_re.replace_all(&text, " ").trim().to_string();
    if !text.is_empty() {
        return true;
    }
    let media_re = regex::RegexBuilder::new(
        r"<(img|svg|canvas|video|audio|picture|input|button|select|textarea)\b",
    )
    .case_insensitive(true)
    .build()
    .unwrap();
    media_re.is_match(markup)
}

// ---------------------------------------------------------------------
// CSS rule parsing / sanitization (accepted-variant CSS)
// ---------------------------------------------------------------------

/// One parsed `{ prelude { body } }` CSS rule (mirrors JS `{prelude, body}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CssRule {
    pub prelude: String,
    pub body: String,
}

/// Port of `parseCssRules`: a hand-rolled brace-depth CSS rule splitter
/// that respects quoted strings and `/* comments */`.
pub fn parse_css_rules(css: &str) -> Vec<CssRule> {
    let chars: Vec<char> = css.chars().collect();
    let n = chars.len();
    let mut rules = Vec::new();
    let mut i = 0usize;
    while i < n {
        while i < n && chars[i].is_whitespace() {
            i += 1;
        }
        let prelude_start = i;
        while i < n && chars[i] != '{' {
            i += 1;
        }
        if i >= n {
            break;
        }
        let prelude: String = chars[prelude_start..i].iter().collect::<String>().trim().to_string();
        i += 1;
        let body_start = i;
        let mut depth = 1i32;
        let mut quote: Option<char> = None;
        let mut comment = false;
        while i < n && depth > 0 {
            let ch = chars[i];
            let next = if i + 1 < n { Some(chars[i + 1]) } else { None };
            if comment {
                if ch == '*' && next == Some('/') {
                    comment = false;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if let Some(q) = quote {
                if ch == '\\' {
                    i += 2;
                    continue;
                }
                if ch == q {
                    quote = None;
                }
                i += 1;
                continue;
            }
            if ch == '/' && next == Some('*') {
                comment = true;
                i += 2;
                continue;
            }
            if ch == '"' || ch == '\'' {
                quote = Some(ch);
                i += 1;
                continue;
            }
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
            }
            i += 1;
        }
        let body_end = std::cmp::max(body_start, i.saturating_sub(1));
        let body: String = chars[body_start..body_end].iter().collect();
        if !prelude.is_empty() {
            rules.push(CssRule { prelude, body });
        }
    }
    rules
}

fn escape_regexp(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn variant_selector_regex(variant_num: i64) -> regex::Regex {
    let pat = format!(
        r#"\[data-impeccable-variant=(["']){}\1\]"#,
        escape_regexp(&variant_num.to_string())
    );
    regex::Regex::new(&pat).unwrap()
}

fn selector_has_variant(selector: &str, variant_num: i64) -> bool {
    variant_selector_regex(variant_num).is_match(selector)
}

/// Port of `splitSelectorList`.
pub fn split_selector_list(prelude: &str) -> Vec<String> {
    let chars: Vec<char> = prelude.chars().collect();
    let mut selectors = Vec::new();
    let mut start = 0usize;
    let mut bracket = 0i32;
    let mut paren = 0i32;
    let mut quote: Option<char> = None;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == '\\' {
                i += 1;
            } else if ch == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '[' => bracket += 1,
            ']' => bracket = (bracket - 1).max(0),
            '(' => paren += 1,
            ')' => paren = (paren - 1).max(0),
            ',' if bracket == 0 && paren == 0 => {
                selectors.push(chars[start..i].iter().collect::<String>());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    selectors.push(chars[start..].iter().collect::<String>());
    selectors
}

/// Result of `rewriteParamSelectors`.
struct ParamRewrite {
    keep: bool,
    selector: String,
}

/// Port of `rewriteParamSelectors`. `param_values` maps param key -> raw
/// JSON-ish string value (JS receives arbitrary JSON values coerced with
/// `String(actual)`); callers pass the already-stringified value plus a
/// `false_like` flag for the falsy-check branch.
fn rewrite_param_selectors(selector: &str, param_values: Option<&std::collections::HashMap<String, ParamValue>>) -> ParamRewrite {
    let re = regex::Regex::new(r#"\[data-p-([A-Za-z0-9_-]+)(?:=(["'])(.*?)\2)?\]"#).unwrap();
    let mut keep = true;
    let result = {
        let mut out = String::new();
        let mut last = 0usize;
        for caps in re.captures_iter(selector) {
            let m = caps.get(0).unwrap();
            out.push_str(&selector[last..m.start()]);
            last = m.end();
            let key = caps.get(1).unwrap().as_str();
            let expected = caps.get(3).map(|c| c.as_str());
            match param_values.and_then(|pv| pv.get(key)) {
                None => {
                    // attribute not in paramValues -> drop it (replacement is "")
                }
                Some(actual) => {
                    if let Some(expected) = expected {
                        if actual.as_display() != expected {
                            keep = false;
                        }
                    } else if actual.is_falsy() {
                        keep = false;
                    }
                }
            }
        }
        out.push_str(&selector[last..]);
        out
    };
    ParamRewrite { keep, selector: result }
}

/// A param value as passed to CSS rewriting: mirrors JS's loose typing
/// (`false`, `null`/`undefined`, the strings `"false"`/`"off"`/`"0"` are
/// all falsy per `bakeParamValuesInCss`/selector-rewrite semantics).
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    Bool(bool),
    Null,
    Str(String),
    Num(f64),
}

impl ParamValue {
    fn as_display(&self) -> String {
        match self {
            ParamValue::Bool(b) => b.to_string(),
            ParamValue::Null => "null".to_string(),
            ParamValue::Str(s) => s.clone(),
            ParamValue::Num(n) => {
                if n.fract() == 0.0 {
                    format!("{}", *n as i64)
                } else {
                    n.to_string()
                }
            }
        }
    }

    fn is_falsy(&self) -> bool {
        match self {
            ParamValue::Bool(b) => !*b,
            ParamValue::Null => true,
            ParamValue::Str(s) => s == "false" || s == "off" || s == "0",
            ParamValue::Num(_) => false,
        }
    }
}

/// Port of `rewriteAcceptedSvelteSelectorPart`.
fn rewrite_accepted_svelte_selector_part(
    selector: &str,
    variant_num: i64,
    param_values: Option<&std::collections::HashMap<String, ParamValue>>,
    root_tag: &str,
    from_scope: bool,
) -> String {
    let mut out = selector.trim().to_string();
    let has_variant = regex::Regex::new(r"data-impeccable-variant").unwrap().is_match(&out);
    if has_variant && !selector_has_variant(&out, variant_num) {
        return String::new();
    }
    if has_variant {
        out = variant_selector_regex(variant_num).replace_all(&out, "").into_owned();
        let attr_re = regex::Regex::new(r#"\[data-impeccable-variant=(["']).*?\1\]"#).unwrap();
        out = attr_re.replace_all(&out, "").into_owned();
    }

    let param_result = rewrite_param_selectors(&out, param_values);
    if !param_result.keep {
        return String::new();
    }
    out = param_result.selector;

    let scope_child_re = regex::Regex::new(r":scope(?:\[[^\]]+\])?\s*>\s*").unwrap();
    out = scope_child_re.replace_all(&out, "").into_owned();
    let scope_re = regex::Regex::new(r":scope(?:\[[^\]]+\])?").unwrap();
    out = scope_re.replace_all(&out, root_tag).into_owned();
    let ws_re = regex::Regex::new(r"\s+").unwrap();
    out = ws_re.replace_all(&out, " ").trim().to_string();

    let combinator_re = regex::Regex::new(r"^[>+~]\s*").unwrap();
    out = combinator_re.replace(&out, "").trim().to_string();

    if out.is_empty() && (has_variant || from_scope) {
        return if !root_tag.is_empty() { root_tag.to_string() } else { ":global(*)".to_string() };
    }
    out
}

/// Port of `rewriteAcceptedSvelteSelector`.
fn rewrite_accepted_svelte_selector(
    prelude: &str,
    variant_num: i64,
    param_values: Option<&std::collections::HashMap<String, ParamValue>>,
    root_tag: &str,
    from_scope: bool,
) -> String {
    split_selector_list(prelude)
        .into_iter()
        .filter_map(|selector| {
            let next = rewrite_accepted_svelte_selector_part(&selector, variant_num, param_values, root_tag, from_scope);
            if next.is_empty() {
                None
            } else {
                Some(next)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_css_rule(selector: &str, body: &str) -> String {
    format!("{} {{ {} }}", selector, body.trim())
}

/// Port of `appendSanitizedCssRule`.
fn append_sanitized_css_rule(
    output: &mut Vec<String>,
    rule: &CssRule,
    variant_num: i64,
    param_values: Option<&std::collections::HashMap<String, ParamValue>>,
    root_tag: &str,
) {
    let prelude = rule.prelude.trim();
    let body = rule.body.trim();
    let ready_re = regex::Regex::new(r"--impeccable-variant-ready\s*:").unwrap();
    if prelude.is_empty() || body.is_empty() || ready_re.is_match(body) {
        return;
    }

    let scope_re = regex::RegexBuilder::new(r"^@scope\b").case_insensitive(true).build().unwrap();
    if scope_re.is_match(prelude) {
        let variant_attr_re = regex::Regex::new(r"data-impeccable-variant").unwrap();
        if variant_attr_re.is_match(prelude) && !selector_has_variant(prelude, variant_num) {
            return;
        }
        let inner = parse_css_rules(body);
        for inner_rule in inner {
            let rewritten_prelude =
                rewrite_accepted_svelte_selector(&inner_rule.prelude, variant_num, param_values, root_tag, true);
            if rewritten_prelude.is_empty() || ready_re.is_match(inner_rule.body.trim()) {
                continue;
            }
            output.push(format_css_rule(&rewritten_prelude, inner_rule.body.trim()));
        }
        return;
    }

    let rewritten_prelude = rewrite_accepted_svelte_selector(prelude, variant_num, param_values, root_tag, false);
    if rewritten_prelude.is_empty() {
        return;
    }
    output.push(format_css_rule(&rewritten_prelude, body));
}

/// Port of `sanitizeAcceptedSvelteCss`.
pub fn sanitize_accepted_svelte_css(
    css_lines: &[String],
    variant_num: i64,
    param_values: Option<&std::collections::HashMap<String, ParamValue>>,
    root_tag: &str,
) -> Vec<String> {
    let css = css_lines.join("\n");
    let marker_re = regex::Regex::new(r"data-impeccable-variant|impeccable-variant-ready").unwrap();
    if !marker_re.is_match(&css) {
        return css_lines.to_vec();
    }

    let rules = parse_css_rules(&css);
    let mut output = Vec::new();
    for rule in &rules {
        append_sanitized_css_rule(&mut output, rule, variant_num, param_values, root_tag);
    }
    output
        .join("\n")
        .split('\n')
        .map(|l| l.trim_end().to_string())
        .filter(|l| !l.trim().is_empty())
        .collect()
}

/// Port of `bakeParamValuesInCss`.
pub fn bake_param_values_in_css(
    css_lines: &[String],
    param_values: Option<&std::collections::HashMap<String, ParamValue>>,
) -> Vec<String> {
    let Some(param_values) = param_values else {
        return css_lines.to_vec();
    };
    if param_values.is_empty() {
        return css_lines.to_vec();
    }
    css_lines
        .iter()
        .map(|line| {
            let mut out = line.clone();
            for (key, value) in param_values {
                let var_name = format!("--p-{}", key);
                let pat = format!(r"var\({}(?:,\s*[^)]+)?\)", escape_regexp(&var_name));
                let re = regex::Regex::new(&pat).unwrap();
                out = re.replace_all(&out, value.as_display().as_str()).into_owned();
            }
            out
        })
        .collect()
}

/// Port of `findLastStyleCloseLine`.
fn find_last_style_close_line(lines: &[String]) -> Option<usize> {
    let re = regex::Regex::new(r"</style\s*>").unwrap();
    lines.iter().rposition(|line| re.is_match(line))
}

/// Port of `appendCssToSvelteStyle`.
pub fn append_css_to_svelte_style(lines: &[String], css_lines: &[String]) -> Vec<String> {
    let close_idx = find_last_style_close_line(lines);
    let mut prepared: Vec<String> = vec![String::new()];
    for line in css_lines {
        if line.trim().is_empty() {
            prepared.push(String::new());
        } else {
            prepared.push(format!("  {}", line.trim_start()));
        }
    }
    match close_idx {
        None => {
            let mut out = lines.to_vec();
            out.push(String::new());
            out.push("<style>".to_string());
            out.extend(prepared[1..].iter().cloned());
            out.push("</style>".to_string());
            out
        }
        Some(idx) => {
            let mut out = lines[..idx].to_vec();
            out.extend(prepared);
            out.extend(lines[idx..].iter().cloned());
            out
        }
    }
}

/// Static CSS-authoring guidance payload, mirroring `buildSvelteComponentCssAuthoring`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvelteComponentCssAuthoring {
    pub mode: &'static str,
    pub strategy: &'static str,
    pub rule_pattern: &'static str,
    pub selector_examples: Vec<&'static str>,
    pub requirements: Vec<&'static str>,
    pub forbidden: Vec<&'static str>,
    pub params_file: &'static str,
}

/// Port of `buildSvelteComponentCssAuthoring`.
pub fn build_svelte_component_css_authoring(count: usize) -> SvelteComponentCssAuthoring {
    SvelteComponentCssAuthoring {
        mode: "svelte-component",
        strategy: "component-style-block",
        rule_pattern: ".semantic-class { ... }",
        selector_examples: vec![".expense-row { padding: 22px; }"; count],
        requirements: vec![
            "Write each variant as a real Svelte component file (v1.svelte, v2.svelte, ...).",
            "Keep the prop names from propContract; bind dynamic text with {propName}, not literal snapshot text.",
            "Put variant CSS in the component <style> block using semantic class selectors.",
            "Author param-driven CSS against var(--p-<id>, default) and [data-p-<id>] using :global(...) so the runtime knob values reach the mounted root.",
            "Declare params in componentDir/params.json keyed by variant number (e.g. {\"1\": [...], \"2\": [...]}), NOT as a data-impeccable-params attribute.",
            "Do not use @scope or data-impeccable-variant selectors in component files.",
            "Do not edit the route source file during generation; only edit files under componentDir.",
        ],
        forbidden: vec![
            "Do not use @scope blocks in Svelte component variants.",
            "Do not copy live DOM snapshot text into markup when propContract provides bindings.",
            "Do not add data-impeccable-* attributes inside component files. Svelte parses { in attribute values as an expression, so data-impeccable-params with JSON breaks the build; use componentDir/params.json instead.",
        ],
        params_file: "params.json",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn extracts_ordered_unique_mustache_expressions() {
        let text = "<p>{a.b}</p>\n<span>{c[d]}</span>\n<!-- {skipped} -->\n<p>{a.b}</p>";
        assert_eq!(extract_mustache_expressions(text), vec!["a.b".to_string(), "c[d]".to_string()]);
    }

    #[test]
    fn derives_prop_names_from_trailing_ident() {
        let contract = build_prop_contract(&["user.name".to_string(), "items[0]".to_string(), "weird!!".to_string()]);
        assert_eq!(contract[0].prop, "name");
        // "items[0]": tail "0" is not a valid identifier start (digit), so it
        // falls back to `prop<index>` — index 1 here.
        assert_eq!(contract[1].prop, "prop1");
        assert_eq!(contract[2].prop, "prop2");
    }

    #[test]
    fn prop_name_falls_back_when_tail_not_valid_ident() {
        // "items[0]" -> tail "0", first char is a digit, invalid start -> prop1.
        let contract = build_prop_contract(&["items[0]".to_string()]);
        assert_eq!(contract[0].prop, "prop0");
        let contract2 = build_prop_contract(&["plain".to_string()]);
        assert_eq!(contract2[0].prop, "prop0");
    }

    #[test]
    fn substitute_round_trip() {
        let contract = build_prop_contract(&["user.name".to_string()]);
        let markup = "<p>{user.name}</p>";
        let with_props = substitute_exprs_with_props(markup, &contract);
        assert_eq!(with_props, "<p>{name}</p>");
        let back = substitute_props_with_exprs(&with_props, &contract);
        assert_eq!(back, markup);
    }

    #[test]
    fn parses_svelte_component_file() {
        let src = "<script>\n  let x = 1;\n</script>\n<div>Hello</div>\n<style>\n  div { color: red; }\n</style>\n";
        let parsed = parse_svelte_component_file(src);
        assert_eq!(parsed.markup, "<div>Hello</div>");
        assert_eq!(parsed.css_lines, vec!["  div { color: red; }".to_string()]);
    }

    #[test]
    fn parses_file_with_no_style_block() {
        let src = "<script>\n  let x = 1;\n</script>\n<div>Hi</div>\n";
        let parsed = parse_svelte_component_file(src);
        assert_eq!(parsed.markup, "<div>Hi</div>");
        assert!(parsed.css_lines.is_empty());
        assert!(parsed.style_block.is_empty());
    }

    #[test]
    fn builds_props_script_for_empty_and_nonempty_contract() {
        let empty = build_props_script(&[]);
        assert!(empty.contains("let {} = $props();"));
        let contract = build_prop_contract(&["a.b".to_string()]);
        let script = build_props_script(&contract);
        assert!(script.contains("let { b } = $props();"));
        assert!(script.contains("b: string;"));
    }

    #[test]
    fn builds_variant_stub_with_props_comment() {
        let contract = build_prop_contract(&["a.b".to_string()]);
        let stub = build_variant_stub(2, "<p>{b}</p>", &contract);
        assert!(stub.contains("<!-- Props: b <- {a.b} -->"));
        assert!(stub.contains("Variant 2: add scoped CSS here"));
    }

    #[test]
    fn builds_insert_variant_stub() {
        let stub = build_insert_variant_stub(3);
        assert!(stub.contains("Insert variant 3"));
        assert!(stub.contains("let {} = $props();"));
    }

    #[test]
    fn matches_opening_tag() {
        let tag = match_opening_tag("  <div class=\"a\">content</div>").unwrap();
        assert_eq!(tag.tag, "div");
        assert_eq!(tag.attrs.trim(), "class=\"a\"");
        assert_eq!(tag.close, ">");
    }

    #[test]
    fn no_opening_tag_match_returns_none() {
        assert!(match_opening_tag("just text").is_none());
    }

    #[test]
    fn parses_attr_segments() {
        let segs = parse_attr_segments(r#" class="a b" data-x id='y'"#);
        let names: Vec<&str> = segs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["class", "data-x", "id"]);
    }

    #[test]
    fn merges_static_class_attrs() {
        let variant = AttrSegment { name: "class".into(), raw: r#"class="foo bar""#.into(), start: 0, end: 0 };
        let original = AttrSegment { name: "class".into(), raw: r#"class="bar baz""#.into(), start: 0, end: 0 };
        let merged = merge_static_class_attr(&original, &variant).unwrap();
        assert_eq!(merged, r#"class="foo bar baz""#);
    }

    #[test]
    fn merges_original_top_level_attrs_adds_missing_and_merges_class() {
        let variant_markup = r#"<div class="foo">x</div>"#;
        let original_markup = r#"<div class="bar" data-testid="row">y</div>"#;
        let merged = merge_original_top_level_attrs(variant_markup, original_markup);
        assert!(merged.contains(r#"class="foo bar""#));
        assert!(merged.contains(r#"data-testid="row""#));
    }

    #[test]
    fn merge_returns_unchanged_when_tags_differ() {
        let variant_markup = "<span>x</span>";
        let original_markup = "<div>y</div>";
        assert_eq!(merge_original_top_level_attrs(variant_markup, original_markup), variant_markup);
    }

    #[test]
    fn detects_visible_content() {
        assert!(svelte_markup_has_visible_content("<p>Hello</p>"));
        assert!(!svelte_markup_has_visible_content("<!-- just a comment -->"));
        assert!(svelte_markup_has_visible_content(r#"<img src="x.png" />"#));
        assert!(!svelte_markup_has_visible_content("  \n  "));
    }

    #[test]
    fn parses_simple_css_rules() {
        let rules = parse_css_rules(".a { color: red; } .b { color: blue; }");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].prelude, ".a");
        assert_eq!(rules[0].body.trim(), "color: red;");
    }

    #[test]
    fn parses_nested_scope_css_rule() {
        let rules = parse_css_rules("@scope ([data-impeccable-variant=\"1\"]) { .row { padding: 4px; } }");
        assert_eq!(rules.len(), 1);
        assert!(rules[0].prelude.starts_with("@scope"));
        assert!(rules[0].body.contains(".row"));
    }

    #[test]
    fn sanitizes_variant_scoped_css_for_matching_variant() {
        let css = vec![
            r#"@scope ([data-impeccable-variant="1"]) { .row { padding: 4px; } }"#.to_string(),
            r#"@scope ([data-impeccable-variant="2"]) { .row { padding: 8px; } }"#.to_string(),
        ];
        let out = sanitize_accepted_svelte_css(&css, 1, None, "div");
        let joined = out.join("\n");
        assert!(joined.contains("padding: 4px"));
        assert!(!joined.contains("padding: 8px"));
    }

    #[test]
    fn sanitize_passthrough_when_no_variant_markers() {
        let css = vec![".plain { color: red; }".to_string()];
        let out = sanitize_accepted_svelte_css(&css, 1, None, "div");
        assert_eq!(out, css);
    }

    #[test]
    fn rewrites_param_selectors_dropping_falsy() {
        let mut params = HashMap::new();
        params.insert("show".to_string(), ParamValue::Bool(false));
        let css = vec![r#"@scope ([data-impeccable-variant="1"]) { .row[data-p-show] { display: block; } }"#.to_string()];
        let out = sanitize_accepted_svelte_css(&css, 1, Some(&params), "div");
        // The rule's selector becomes empty after the param drop (falsy show),
        // so it should be filtered out entirely (rewrite_param_selectors keeps=false).
        assert!(out.is_empty());
    }

    #[test]
    fn bakes_param_values_into_css_var_defaults() {
        let mut params = HashMap::new();
        params.insert("size".to_string(), ParamValue::Num(24.0));
        let css = vec!["  width: var(--p-size, 16px);".to_string()];
        let out = bake_param_values_in_css(&css, Some(&params));
        assert_eq!(out, vec!["  width: 24;".to_string()]);
    }

    #[test]
    fn bake_passthrough_without_params() {
        let css = vec!["a { color: red; }".to_string()];
        assert_eq!(bake_param_values_in_css(&css, None), css);
    }

    #[test]
    fn appends_css_to_existing_style_block() {
        let lines: Vec<String> = "<div>x</div>\n<style>\n  a { color: red; }\n</style>"
            .split('\n')
            .map(String::from)
            .collect();
        let out = append_css_to_svelte_style(&lines, &["b { color: blue; }".to_string()]);
        let joined = out.join("\n");
        assert!(joined.contains("b { color: blue; }"));
        assert!(joined.trim_end().ends_with("</style>"));
    }

    #[test]
    fn appends_new_style_block_when_absent() {
        let lines: Vec<String> = vec!["<div>x</div>".to_string()];
        let out = append_css_to_svelte_style(&lines, &["a { color: red; }".to_string()]);
        assert_eq!(out.last().unwrap(), "</style>");
        assert!(out.contains(&"<style>".to_string()));
    }

    #[test]
    fn css_authoring_payload_matches_shape() {
        let payload = build_svelte_component_css_authoring(2);
        assert_eq!(payload.mode, "svelte-component");
        assert_eq!(payload.selector_examples.len(), 2);
        assert_eq!(payload.requirements.len(), 7);
        assert_eq!(payload.forbidden.len(), 3);
    }

    #[test]
    fn constants_match_js_source() {
        assert_eq!(SVELTE_COMPONENT_ROOT, "node_modules/.impeccable-live");
        assert_eq!(DEFERRED_ACCEPTS_FILE, ".impeccable/live/deferred-svelte-component-accepts.json");
    }
}
