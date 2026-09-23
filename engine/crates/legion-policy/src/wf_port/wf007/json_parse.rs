//! Minimal read-only JSON parser for wf007's transcript-line reading
//! (`user_intent::entry_text`).
//!
//! `legion-policy` depends on `serde_json` only as a dev-dependency (see
//! `Cargo.toml`), so runtime transcript parsing cannot use it without a
//! dependency-graph change this owner may not make (see the wf007 report's
//! "shared-file patches" section for the proposed `Cargo.toml` amendment).
//! Until that lands, this hand-rolled recursive-descent parser stands in:
//! it accepts the full JSON grammar (objects, arrays, strings with standard
//! escapes, numbers, booleans, null) and is used strictly read-only, so a
//! permissive/lenient subset is not a soundness concern the way it would be
//! for `canon::canonical_json`'s write side.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Option<Value> {
    let mut chars = input.char_indices().peekable();
    let value = parse_value(input, &mut chars)?;
    skip_ws(input, &mut chars);
    if chars.peek().is_some() {
        return None;
    }
    Some(value)
}

type Chars<'a> = std::iter::Peekable<std::str::CharIndices<'a>>;

fn skip_ws(_input: &str, chars: &mut Chars) {
    while let Some(&(_, c)) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
}

fn parse_value(input: &str, chars: &mut Chars) -> Option<Value> {
    skip_ws(input, chars);
    match chars.peek()?.1 {
        '{' => parse_object(input, chars),
        '[' => parse_array(input, chars),
        '"' => parse_string(input, chars).map(Value::String),
        't' => {
            consume_literal(chars, "true")?;
            Some(Value::Bool(true))
        }
        'f' => {
            consume_literal(chars, "false")?;
            Some(Value::Bool(false))
        }
        'n' => {
            consume_literal(chars, "null")?;
            Some(Value::Null)
        }
        c if c == '-' || c.is_ascii_digit() => parse_number(input, chars),
        _ => None,
    }
}

fn consume_literal(chars: &mut Chars, lit: &str) -> Option<()> {
    for expected in lit.chars() {
        let (_, c) = chars.next()?;
        if c != expected {
            return None;
        }
    }
    Some(())
}

fn parse_object(input: &str, chars: &mut Chars) -> Option<Value> {
    chars.next(); // consume '{'
    let mut pairs = Vec::new();
    skip_ws(input, chars);
    if chars.peek()?.1 == '}' {
        chars.next();
        return Some(Value::Object(pairs));
    }
    loop {
        skip_ws(input, chars);
        let key = parse_string(input, chars)?;
        skip_ws(input, chars);
        if chars.next()?.1 != ':' {
            return None;
        }
        let value = parse_value(input, chars)?;
        pairs.push((key, value));
        skip_ws(input, chars);
        match chars.next()?.1 {
            ',' => continue,
            '}' => break,
            _ => return None,
        }
    }
    Some(Value::Object(pairs))
}

fn parse_array(input: &str, chars: &mut Chars) -> Option<Value> {
    chars.next(); // consume '['
    let mut items = Vec::new();
    skip_ws(input, chars);
    if chars.peek()?.1 == ']' {
        chars.next();
        return Some(Value::Array(items));
    }
    loop {
        let value = parse_value(input, chars)?;
        items.push(value);
        skip_ws(input, chars);
        match chars.next()?.1 {
            ',' => continue,
            ']' => break,
            _ => return None,
        }
    }
    Some(Value::Array(items))
}

fn parse_string(_input: &str, chars: &mut Chars) -> Option<String> {
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut out = String::new();
    loop {
        let (_, c) = chars.next()?;
        match c {
            '"' => break,
            '\\' => {
                let (_, esc) = chars.next()?;
                match esc {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000C}'),
                    'u' => {
                        let mut hex = String::new();
                        for _ in 0..4 {
                            hex.push(chars.next()?.1);
                        }
                        let cp = u32::from_str_radix(&hex, 16).ok()?;
                        out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    }
                    _ => return None,
                }
            }
            c => out.push(c),
        }
    }
    Some(out)
}

fn parse_number(input: &str, chars: &mut Chars) -> Option<Value> {
    let start = chars.peek()?.0;
    if chars.peek()?.1 == '-' {
        chars.next();
    }
    while chars.peek().map(|&(_, c)| c.is_ascii_digit()).unwrap_or(false) {
        chars.next();
    }
    if chars.peek().map(|&(_, c)| c == '.').unwrap_or(false) {
        chars.next();
        while chars.peek().map(|&(_, c)| c.is_ascii_digit()).unwrap_or(false) {
            chars.next();
        }
    }
    if chars.peek().map(|&(_, c)| c == 'e' || c == 'E').unwrap_or(false) {
        chars.next();
        if chars.peek().map(|&(_, c)| c == '+' || c == '-').unwrap_or(false) {
            chars.next();
        }
        while chars.peek().map(|&(_, c)| c.is_ascii_digit()).unwrap_or(false) {
            chars.next();
        }
    }
    let end = chars.peek().map(|&(i, _)| i).unwrap_or(input.len());
    input[start..end].parse::<f64>().ok().map(Value::Number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_with_nested_array_and_string_escapes() {
        let v = parse(r#"{"a":1,"b":["x\n","y"],"c":null,"d":true}"#).unwrap();
        assert_eq!(v.get("a"), Some(&Value::Number(1.0)));
        assert_eq!(v.get("b").unwrap().as_array().unwrap()[0], Value::String("x\n".into()));
        assert_eq!(v.get("c"), Some(&Value::Null));
        assert_eq!(v.get("d"), Some(&Value::Bool(true)));
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(parse(r#"{"a":1} garbage"#).is_none());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse("{not json}").is_none());
    }
}
