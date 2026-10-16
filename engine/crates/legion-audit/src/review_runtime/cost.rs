//! Exact provider-reported USD decimals; never a price estimate or invoice charge.

/// Bound numeric work before normalizing JSON decimal/exponent notation.
pub(crate) fn normalize(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 128 || value.starts_with('-') {
        return None;
    }
    let (mantissa, exponent) = match value.find(['e', 'E']) {
        Some(index) => (&value[..index], value[index + 1..].parse::<i32>().ok()?),
        None => (value, 0),
    };
    if !(-128..=128).contains(&exponent) {
        return None;
    }
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (mantissa.contains('.') && fraction.is_empty())
    {
        return None;
    }
    let mut digits = format!("{whole}{fraction}");
    let decimal = whole.len() as i32 + exponent;
    if decimal <= 0 {
        digits = format!("0.{}{digits}", "0".repeat((-decimal) as usize));
    } else if decimal as usize >= digits.len() {
        digits.push_str(&"0".repeat(decimal as usize - digits.len()));
    } else {
        digits.insert(decimal as usize, '.');
    }
    let trimmed = digits.trim_start_matches('0');
    let mut normalized = if trimmed.is_empty() {
        "0".into()
    } else if trimmed.starts_with('.') {
        format!("0{trimmed}")
    } else {
        trimmed.to_owned()
    };
    if normalized.contains('.') {
        normalized = normalized
            .trim_end_matches('0')
            .trim_end_matches('.')
            .into();
    }
    (normalized.len() <= 128).then_some(normalized)
}

pub(crate) fn add(left: &str, right: &str) -> Option<String> {
    let left = normalize(left)?;
    let right = normalize(right)?;
    let scale = |value: &str| value.split_once('.').map_or(0, |(_, part)| part.len());
    let places = scale(&left).max(scale(&right));
    let integer = |value: &str| {
        let mut digits = value.replace('.', "");
        digits.push_str(&"0".repeat(places - scale(value)));
        digits
    };
    let left = integer(&left);
    let right = integer(&right);
    let mut sum = Vec::new();
    let mut carry = 0;
    let mut l = left.bytes().rev();
    let mut r = right.bytes().rev();
    loop {
        let (a, b) = (l.next(), r.next());
        if a.is_none() && b.is_none() && carry == 0 {
            break;
        }
        let digit = a.map_or(0, |n| n - b'0') + b.map_or(0, |n| n - b'0') + carry;
        sum.push(b'0' + digit % 10);
        carry = digit / 10;
    }
    while sum.len() <= places {
        sum.push(b'0');
    }
    sum.reverse();
    let mut sum = String::from_utf8(sum).ok()?;
    if places > 0 {
        sum.insert(sum.len() - places, '.');
    }
    normalize(&sum)
}

/// Read root numeric lexeme from already validated JSON, preserving precision
/// that a serde_json floating-point Value would otherwise round. Last key wins,
/// matching serde_json object decoding. Nested values cannot supply root cost.
pub(super) fn native_root_cost(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut depth = 0usize;
    let mut cursor = 0usize;
    let mut cost = None;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth = depth.saturating_sub(1),
            b'"' => {
                let start = cursor;
                cursor += 1;
                while cursor < bytes.len() && bytes[cursor] != b'"' {
                    if bytes[cursor] == b'\\' {
                        cursor += 1;
                    }
                    cursor += 1;
                }
                let end = cursor + 1;
                let mut value = end;
                while value < bytes.len() && bytes[value].is_ascii_whitespace() {
                    value += 1;
                }
                if depth == 1
                    && bytes.get(value) == Some(&b':')
                    && serde_json::from_str::<String>(&line[start..end])
                        .ok()
                        .as_deref()
                        == Some("total_cost_usd")
                {
                    value += 1;
                    while value < bytes.len() && bytes[value].is_ascii_whitespace() {
                        value += 1;
                    }
                    let start = value;
                    while value < bytes.len()
                        && !matches!(bytes[value], b',' | b'}')
                        && !bytes[value].is_ascii_whitespace()
                    {
                        value += 1;
                    }
                    cost = normalize(&line[start..value]);
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    cost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_cost_is_exact_decimal_not_float_or_nested_cost() {
        assert_eq!(add("0.1", "0.2").as_deref(), Some("0.3"));
        assert_eq!(
            add("0.000000000000000001", "1e-18").as_deref(),
            Some("0.000000000000000002")
        );
        assert_eq!(normalize("2.5000e-2").as_deref(), Some("0.025"));
        assert_eq!(
            native_root_cost(
                r#"{"total_cost_usd":0.1234567890123456789,"usage":{"total_cost_usd":99}}"#
            )
            .as_deref(),
            Some("0.1234567890123456789")
        );
        for value in ["-1", "NaN", "inf", "null", "\"0.1\"", "1e999", "1.2.3"] {
            assert_eq!(normalize(value), None, "{value}");
        }
        assert_eq!(
            native_root_cost(r#"{"total_cost_usd":1,"total_cost_usd":null}"#),
            None
        );
        assert_eq!(native_root_cost(r#"{"usage":{"total_cost_usd":1}}"#), None);
    }
}
