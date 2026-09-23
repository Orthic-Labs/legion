//! Minimal, dependency-free JSON parser for wf067's on-disk record shapes.
//!
//! Not a general-purpose parser: supports exactly what
//! `authority-binding-store.mjs` and `authority-invocation-proof.mjs` write
//! back to disk (flat/shallow objects of strings, numbers, bools, null, and
//! nested objects/arrays of the same). Sufficient to round-trip records this
//! module itself serialized with `canonical::Json`.

use super::canonical::Json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self { bytes: s.as_bytes(), pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, b: u8) -> Result<(), ParseError> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(ParseError(format!("expected '{}' at byte {}", b as char, self.pos)))
        }
    }

    fn parse_value(&mut self) -> Result<Json, ParseError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') => {
                self.expect_lit("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.expect_lit("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.expect_lit("null")?;
                Ok(Json::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(ParseError(format!("unexpected byte at {}", self.pos))),
        }
    }

    fn expect_lit(&mut self, lit: &str) -> Result<(), ParseError> {
        let end = self.pos + lit.len();
        if end <= self.bytes.len() && &self.bytes[self.pos..end] == lit.as_bytes() {
            self.pos = end;
            Ok(())
        } else {
            Err(ParseError(format!("expected literal '{lit}' at {}", self.pos)))
        }
    }

    fn parse_object(&mut self) -> Result<Json, ParseError> {
        self.expect(b'{')?;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(out));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            out.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(ParseError(format!("expected ',' or '}}' at {}", self.pos))),
            }
        }
        Ok(Json::Obj(out))
    }

    fn parse_array(&mut self) -> Result<Json, ParseError> {
        self.expect(b'[')?;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(out));
        }
        loop {
            let value = self.parse_value()?;
            out.push(value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(ParseError(format!("expected ',' or ']' at {}", self.pos))),
            }
        }
        Ok(Json::Arr(out))
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(ParseError("unterminated string".into())),
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => {
                            out.push('"');
                            self.pos += 1;
                        }
                        Some(b'\\') => {
                            out.push('\\');
                            self.pos += 1;
                        }
                        Some(b'/') => {
                            out.push('/');
                            self.pos += 1;
                        }
                        Some(b'n') => {
                            out.push('\n');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            out.push('\r');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            out.push('\t');
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            if self.pos + 4 > self.bytes.len() {
                                return Err(ParseError("truncated unicode escape".into()));
                            }
                            let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .map_err(|_| ParseError("invalid unicode escape".into()))?;
                            let cp = u32::from_str_radix(hex, 16).map_err(|_| ParseError("invalid unicode escape".into()))?;
                            if let Some(c) = char::from_u32(cp) {
                                out.push(c);
                            }
                            self.pos += 4;
                        }
                        _ => return Err(ParseError("invalid escape".into())),
                    }
                }
                Some(_) => {
                    // Fast path: consume one UTF-8 scalar.
                    let rest = std::str::from_utf8(&self.bytes[self.pos..]).map_err(|_| ParseError("invalid utf8".into()))?;
                    let c = rest.chars().next().ok_or_else(|| ParseError("invalid utf8".into()))?;
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
        Ok(out)
    }

    fn parse_number(&mut self) -> Result<Json, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
        if is_float {
            text.parse::<f64>().map(Json::F64).map_err(|e| ParseError(e.to_string()))
        } else {
            text.parse::<i64>().map(Json::I64).map_err(|e| ParseError(e.to_string()))
        }
    }
}

/// Parse a JSON document into `Json`. Trailing content after the value is
/// ignored (matching `JSON.parse` on a whole-document string is stricter,
/// but this module only ever parses whole files it wrote itself).
pub fn parse(text: &str) -> Result<Json, ParseError> {
    let mut p = Parser::new(text);
    let v = p.parse_value()?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_object_with_string_number_bool_null() {
        let text = r#"{"a":1,"b":"x","c":true,"d":null}"#;
        let v = parse(text).unwrap();
        assert_eq!(v.get("a"), Some(&Json::I64(1)));
        assert_eq!(v.get("b").and_then(|j| j.as_str()), Some("x"));
        assert_eq!(v.get("c").and_then(|j| j.as_bool()), Some(true));
        assert_eq!(v.get("d"), Some(&Json::Null));
    }

    #[test]
    fn parses_nested_arrays_and_objects() {
        let text = r#"{"arr":[1,2,{"x":"y"}]}"#;
        let v = parse(text).unwrap();
        if let Some(Json::Arr(items)) = v.get("arr") {
            assert_eq!(items.len(), 3);
            assert_eq!(items[2].get("x").and_then(|j| j.as_str()), Some("y"));
        } else {
            panic!("expected array");
        }
    }

    #[test]
    fn parses_escaped_strings() {
        let text = r#"{"s":"line\nbreak \"quote\""}"#;
        let v = parse(text).unwrap();
        assert_eq!(v.get("s").and_then(|j| j.as_str()), Some("line\nbreak \"quote\""));
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse("{").is_err());
        assert!(parse("{\"a\":}").is_err());
    }
}
