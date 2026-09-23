//! Minimal, dependency-free JSON value used by [`super::minimize`].
//!
//! This crate has no `serde_json` dependency (see the wf002 report's
//! shared-file patch), so the minimize port needs its own small JSON
//! reader/writer for review/receipt/decision documents. It supports exactly
//! the shapes those documents use: objects, arrays, strings, numbers,
//! booleans and null — enough to be a faithful, if hand-rolled, stand-in for
//! `JSON.parse`/`JSON.stringify(value, null, 2)` with `sortKeysDeep`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    /// Always key-sorted (`BTreeMap`), matching `sortKeysDeep`.
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object().and_then(|m| m.get(key))
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Json::as_str)
    }

    pub fn get_array(&self, key: &str) -> Option<&[Json]> {
        self.get(key).and_then(Json::as_array)
    }

    /// `JSON.stringify(sortKeysDeep(value), null, 2) + "\n"`.
    pub fn to_pretty_string(&self) -> String {
        let mut out = String::new();
        write_pretty(self, 0, &mut out);
        out.push('\n');
        out
    }

    /// Compact form (used for hashing where indentation is irrelevant).
    pub fn to_compact_string(&self) -> String {
        let mut out = String::new();
        write_compact(self, &mut out);
        out
    }

    pub fn parse(text: &str) -> Result<Json, String> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            pos: 0,
        };
        parser.skip_ws();
        let value = parser.parse_value()?;
        parser.skip_ws();
        if parser.pos != parser.bytes.len() {
            return Err("trailing content after JSON value".to_string());
        }
        Ok(value)
    }
}

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Json::String(value.to_string())
    }
}

impl From<String> for Json {
    fn from(value: String) -> Self {
        Json::String(value)
    }
}

impl From<Vec<Json>> for Json {
    fn from(value: Vec<Json>) -> Self {
        Json::Array(value)
    }
}

fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(n: f64, out: &mut String) {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        let _ = write!(out, "{}", n as i64);
    } else {
        let _ = write!(out, "{n}");
    }
}

fn write_compact(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(n) => write_number(*n, out),
        Json::String(s) => escape_into(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_compact(item, out);
            }
            out.push(']');
        }
        Json::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_into(k, out);
                out.push(':');
                write_compact(v, out);
            }
            out.push('}');
        }
    }
}

fn write_pretty(value: &Json, indent: usize, out: &mut String) {
    match value {
        Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => write_compact(value, out),
        Json::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                write_pretty(item, indent + 2, out);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        Json::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            let len = map.len();
            for (i, (k, v)) in map.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                escape_into(k, out);
                out.push_str(": ");
                write_pretty(v, indent + 2, out);
                if i + 1 < len {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && (self.bytes[self.pos] as char).is_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", byte as char, self.pos))
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_string().map(Json::String),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b't') => self.parse_literal("true", Json::Bool(true)),
            Some(b'f') => self.parse_literal("false", Json::Bool(false)),
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(format!("unexpected byte at {}", self.pos)),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(literal.as_bytes()) {
            self.pos += literal.len();
            Ok(value)
        } else {
            Err(format!("expected literal '{literal}' at {}", self.pos))
        }
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|e| e.to_string())?;
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|e| e.to_string())
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let esc = self.peek().ok_or("unterminated escape")?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .map_err(|e| e.to_string())?;
                            let code = u32::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                            self.pos += 4;
                            if let Some(c) = char::from_u32(code) {
                                out.push(c);
                            }
                        }
                        other => return Err(format!("invalid escape \\{}", other as char)),
                    }
                }
                _ => {
                    // Re-decode as UTF-8 by pushing raw byte through a small
                    // buffer; ASCII-fast-path covers the vast majority of
                    // content these documents contain.
                    if b < 0x80 {
                        out.push(b as char);
                    } else {
                        // Multi-byte UTF-8: back up and decode the full
                        // sequence via str::from_utf8 on a growing window.
                        let start = self.pos - 1;
                        let mut end = self.pos;
                        while end < self.bytes.len()
                            && std::str::from_utf8(&self.bytes[start..end]).is_err()
                        {
                            end += 1;
                        }
                        let s = std::str::from_utf8(&self.bytes[start..end])
                            .map_err(|e| e.to_string())?;
                        out.push_str(s);
                        self.pos = end;
                    }
                }
            }
        }
        Ok(out)
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.pos)),
            }
        }
        Ok(Json::Array(items))
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.pos)),
            }
        }
        Ok(Json::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_object_with_sorted_keys() {
        let mut map = BTreeMap::new();
        map.insert("b".to_string(), Json::Number(2.0));
        map.insert("a".to_string(), Json::String("x".to_string()));
        let value = Json::Object(map);
        let pretty = value.to_pretty_string();
        assert!(pretty.find("\"a\"").unwrap() < pretty.find("\"b\"").unwrap());
        let parsed = Json::parse(&pretty).unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn parses_nested_arrays_and_escapes() {
        let text = r#"{"list":["a\"b",1,true,null]}"#;
        let parsed = Json::parse(text).unwrap();
        let list = parsed.get_array("list").unwrap();
        assert_eq!(list[0], Json::String("a\"b".to_string()));
        assert_eq!(list[1], Json::Number(1.0));
        assert_eq!(list[2], Json::Bool(true));
        assert_eq!(list[3], Json::Null);
    }
}
