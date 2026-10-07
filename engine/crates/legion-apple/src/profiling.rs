//! Typed native profiling plans & bounded pure sample aggregation.
//!
//! This ports reviewed Instruments/native-app-performance parsing. XML
//! parsing, address filtering, ranking, bounded `atos` argv preparation, and
//! symbol output remain pure; effect plans stay in canonical mobile routes.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_ADDRESSES: usize = 200_000;
const MAX_TOP: usize = 1_000;
const MAX_ATOS_BATCH: usize = 80;
const MAX_SYMBOL_BYTES: usize = 1_048_576;

/// Parse exported samples or prepare bounded symbol batches. Typed effect
/// plans for `profile.export`, `memory.inspect`, and `symbolicate` remain
/// canonical in `mobile.rs`; this module owns pure evidence transforms.
pub fn invoke(operation: &str, arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    match operation.to_ascii_lowercase().as_str() {
        "profile.parse" | "profile_parse" => {
            let text = required_text(object, "xml")?;
            let addresses = parse_time_sample_addresses(&text)?;
            Ok(
                json!({"addresses": addresses, "count": addresses.len(), "parser": "kperf-time-sample-v1"}),
            )
        }
        "profile.symbols" | "profile_symbols" => profile_symbols(object),
        other => Err(format!("unknown profiling operation: {other}")),
    }
}

fn profile_symbols(object: &Map<String, Value>) -> Result<Value, String> {
    let load_address = required_string(object, "load_address")
        .or_else(|_| required_string(object, "loadAddress"))?;
    let base = parse_hex_address(&load_address)?;
    let vmsize = object
        .get("text_size")
        .or_else(|| object.get("textSize"))
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX - base);
    let top = match object.get("top") {
        None => 30,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| "top must be a non-negative integer".to_string())?
            as usize,
    };
    if top == 0 || top > MAX_TOP {
        return Err(format!("top must be between 1 and {MAX_TOP}"));
    }
    let addresses = if let Some(xml) = object.get("xml").and_then(Value::as_str) {
        parse_time_sample_addresses(xml)?
    } else {
        let values = object
            .get("addresses")
            .and_then(Value::as_array)
            .ok_or_else(|| "xml or addresses is required".to_string())?;
        if values.len() > MAX_ADDRESSES {
            return Err(format!("addresses exceed {MAX_ADDRESSES}"));
        }
        values
            .iter()
            .map(|value| {
                parse_hex_address(
                    value
                        .as_str()
                        .ok_or_else(|| "addresses must contain strings".to_string())?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let rows = rank_addresses(&addresses, base, vmsize, top);
    let binary = object
        .get("binary_path")
        .or_else(|| object.get("binary"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let arch = object.get("arch").and_then(Value::as_str).unwrap_or("");
    let address_args: Vec<String> = rows
        .iter()
        .map(|(address, _)| format!("0x{address:x}"))
        .collect();
    let mut batches = Vec::new();
    for chunk in address_args.chunks(MAX_ATOS_BATCH) {
        let mut argv = vec!["-o".to_string(), binary.to_string()];
        if !arch.is_empty() {
            argv.extend(["-arch".to_string(), arch.to_string()]);
        }
        argv.extend(["-l".to_string(), load_address.clone()]);
        argv.extend(chunk.iter().cloned());
        batches.push(json!({"executable":"/usr/bin/atos","argv": argv, "count": chunk.len()}));
    }
    let symbol_csv = match object.get("symbols") {
        None => Value::Null,
        Some(Value::Array(symbols)) => {
            let symbols = symbols
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| "symbols must contain strings".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            Value::String(assemble_symbol_csv(&rows, &symbols)?)
        }
        Some(_) => return Err("symbols must be an array of strings".to_string()),
    };
    Ok(json!({
        "operation": "profile.symbols",
        "binary": binary,
        "loadAddress": load_address,
        "textRange": {"base": base, "endExclusive": base.saturating_add(vmsize)},
        "rankedAddresses": rows.iter().map(|(address,count)| json!({"address":format!("0x{address:x}"),"count":count})).collect::<Vec<_>>(),
        "batches": batches,
        "symbolCsv": symbol_csv,
        "effects": ["prepare bounded symbol argv; execution belongs to mobile symbolicate route"],
        "notes": ["Use binary/dSYM from exact trace build; unsymbolicated addresses are evidence gaps."]
    }))
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    let value = object
        .get(key)
        .ok_or_else(|| format!("{key} is required"))?;
    let string = value
        .as_str()
        .ok_or_else(|| format!("{key} must be a string"))?;
    if string.is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    Ok(string.to_string())
}

fn required_text(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    let text = required_string(object, key)?;
    if text.len() > MAX_INPUT_BYTES {
        return Err(format!("{key} exceeds {MAX_INPUT_BYTES} bytes"));
    }
    Ok(text)
}

fn parse_hex_address(value: &str) -> Result<u64, String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| "load_address must be hexadecimal with 0x prefix".to_string())?;
    u64::from_str_radix(value, 16).map_err(|_| "load_address is invalid hexadecimal".to_string())
}

/// Parse referenced kperf call-stack addresses from exported time-sample XML.
pub fn parse_time_sample_addresses(xml: &str) -> Result<Vec<u64>, String> {
    if xml.len() > MAX_INPUT_BYTES {
        return Err(format!("XML exceeds {MAX_INPUT_BYTES} bytes"));
    }
    let mut definitions = BTreeMap::new();
    let mut references = Vec::new();
    let mut active_definition: Option<String> = None;
    let mut text_capture_start = None;
    let mut row_depth = 0_usize;
    let mut cursor = 0;
    while let Some((tag, start, after)) = next_xml_tag(xml, &mut cursor)? {
        if tag.name == "row" && !tag.closing && !tag.self_closing {
            row_depth = row_depth.saturating_add(1);
        } else if tag.name == "row" && tag.closing {
            row_depth = row_depth.saturating_sub(1);
        } else if tag.name == "text-addresses" && !tag.closing {
            text_capture_start = Some(after);
        } else if tag.name == "text-addresses" && tag.closing {
            if let (Some(id), Some(content_start)) =
                (active_definition.as_ref(), text_capture_start.take())
            {
                definitions.insert(id.clone(), parse_addresses(&xml[content_start..start])?);
            }
        } else if tag.name == "kperf-bt" && !tag.closing {
            if let Some(reference) = tag.attrs.get("ref") {
                references.push(reference.clone());
            }
            if let Some(id) = tag.attrs.get("id") {
                active_definition = Some(id.clone());
                if row_depth > 0 && tag.attrs.get("ref").is_none() {
                    references.push(id.clone());
                }
            }
            if tag.self_closing {
                active_definition = None;
            }
        } else if tag.name == "kperf-bt" && tag.closing {
            active_definition = None;
        }
    }
    let mut addresses = Vec::new();
    for reference in references {
        if let Some(values) = definitions.get(&reference) {
            if values.len() > MAX_ADDRESSES.saturating_sub(addresses.len()) {
                return Err(format!("sample addresses exceed {MAX_ADDRESSES}"));
            }
            addresses.extend(values);
        }
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err(format!("sample addresses exceed {MAX_ADDRESSES}"));
    }
    Ok(addresses)
}

struct XmlTag {
    name: String,
    attrs: BTreeMap<String, String>,
    closing: bool,
    self_closing: bool,
}

fn next_xml_tag(xml: &str, cursor: &mut usize) -> Result<Option<(XmlTag, usize, usize)>, String> {
    while *cursor < xml.len() {
        let relative = match xml[*cursor..].find('<') {
            Some(relative) => relative,
            None => {
                *cursor = xml.len();
                return Ok(None);
            }
        };
        let start = *cursor + relative;
        if xml[start..].starts_with("<!--") {
            let end = xml[start + 4..]
                .find("-->")
                .ok_or_else(|| "unterminated XML comment".to_string())?
                + start
                + 7;
            *cursor = end;
            continue;
        }
        let mut quote = None;
        let mut end = None;
        for (offset, character) in xml[start + 1..].char_indices() {
            match (quote, character) {
                (None, '\"') | (None, '\'') => quote = Some(character),
                (Some(current), character) if current == character => quote = None,
                (None, '>') => {
                    end = Some(start + 1 + offset);
                    break;
                }
                _ => {}
            }
        }
        let end = end.ok_or_else(|| "unterminated XML tag".to_string())?;
        let mut body = xml[start + 1..end].trim();
        if body.starts_with('?') || body.starts_with('!') {
            *cursor = end + 1;
            continue;
        }
        let closing = body.starts_with('/');
        if closing {
            body = body[1..].trim_start();
        }
        let self_closing = !closing && body.ends_with('/');
        if self_closing {
            body = body[..body.len() - 1].trim_end();
        }
        let name_end = body.find(char::is_whitespace).unwrap_or(body.len());
        let name = body[..name_end].trim_end_matches('/').to_string();
        if name.is_empty() {
            return Err("XML tag has no name".to_string());
        }
        let attrs = if closing {
            BTreeMap::new()
        } else {
            parse_xml_attributes(&body[name_end..])?
        };
        *cursor = end + 1;
        return Ok(Some((
            XmlTag {
                name,
                attrs,
                closing,
                self_closing,
            },
            start,
            end + 1,
        )));
    }
    Ok(None)
}

fn parse_xml_attributes(mut text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut attrs = BTreeMap::new();
    while !text.trim().is_empty() {
        text = text.trim_start();
        let name_end = text
            .find(|character: char| character.is_whitespace() || character == '=')
            .unwrap_or(text.len());
        let name = &text[..name_end];
        if name.is_empty() {
            return Err("XML attribute has no name".to_string());
        }
        text = text[name_end..].trim_start();
        if !text.starts_with('=') {
            return Err(format!("XML attribute {name} has no value"));
        }
        text = text[1..].trim_start();
        let quote = text
            .chars()
            .next()
            .ok_or_else(|| format!("XML attribute {name} has no value"))?;
        if quote != '"' && quote != '\'' {
            return Err(format!("XML attribute {name} must be quoted"));
        }
        text = &text[quote.len_utf8()..];
        let end = text
            .find(quote)
            .ok_or_else(|| format!("XML attribute {name} is unterminated"))?;
        attrs.insert(name.to_string(), text[..end].to_string());
        text = &text[end + quote.len_utf8()..];
    }
    Ok(attrs)
}

fn parse_addresses(text: &str) -> Result<Vec<u64>, String> {
    text.split_whitespace()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("invalid decimal sample address: {value}"))
        })
        .collect()
}

/// Keep only app `__TEXT` addresses and rank by sample count, deterministic on ties.
pub fn rank_addresses(addresses: &[u64], base: u64, vmsize: u64, top: usize) -> Vec<(u64, u64)> {
    let end = base.saturating_add(vmsize);
    let mut counts = BTreeMap::new();
    for address in addresses
        .iter()
        .copied()
        .filter(|address| *address >= base && *address < end)
    {
        *counts.entry(address).or_insert(0_u64) += 1;
    }
    let mut rows: Vec<_> = counts.into_iter().collect();
    rows.sort_by(|(left_address, left_count), (right_address, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_address.cmp(right_address))
    });
    rows.truncate(top);
    rows
}

/// Assemble bounded `address,count,symbol` output from matching atos rows.
pub fn assemble_symbol_csv(rows: &[(u64, u64)], symbols: &[&str]) -> Result<String, String> {
    if rows.len() != symbols.len() {
        return Err("symbol output count does not match ranked address count".to_string());
    }
    let mut output = String::from("address,count,symbol\n");
    for ((address, count), symbol) in rows.iter().zip(symbols) {
        if symbol.contains('\n') || symbol.contains('\r') {
            return Err("symbol output must be one line per address".to_string());
        }
        if symbol.len() > MAX_SYMBOL_BYTES {
            return Err(format!("symbol exceeds {MAX_SYMBOL_BYTES} bytes"));
        }
        output.push_str(&format!("0x{address:x},{count},"));
        if symbol.contains(',') || symbol.contains('"') {
            output.push('"');
            output.push_str(&symbol.replace('"', "\"\""));
            output.push('"');
        } else {
            output.push_str(symbol);
        }
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_referenced_kperf_addresses_and_filters_range() {
        let xml = r#"<?xml version="1.0"?><root><kperf-bt id="a"><text-addresses>4096 8192</text-addresses></kperf-bt><row><kperf-bt ref="a"/></row><row><kperf-bt ref="a"/></row><row><kperf-bt id="inline"><text-addresses>12288</text-addresses></kperf-bt></row></root>"#;
        let addresses = parse_time_sample_addresses(xml).unwrap();
        assert_eq!(addresses, vec![4096, 8192, 4096, 8192, 12288]);
        assert_eq!(rank_addresses(&addresses, 4096, 1, 10), vec![(4096, 2)]);
    }

    #[test]
    fn symbol_batches_require_load_range_bounds() {
        let symbols = invoke("profile.symbols", &json!({"binary_path":"/tmp/a","load_address":"0x1000","text_size":4096,"addresses":["0x1001"]})).unwrap();
        assert_eq!(symbols["batches"][0]["executable"], "/usr/bin/atos");
        assert_eq!(
            assemble_symbol_csv(&[(0x1001, 2)], &["Demo.work"]).unwrap(),
            "address,count,symbol\n0x1001,2,Demo.work\n"
        );
        assert_eq!(
            assemble_symbol_csv(&[(0x1001, 2)], &["Demo, \"work\""]).unwrap(),
            "address,count,symbol\n0x1001,2,\"Demo, \"\"work\"\"\"\n"
        );
        assert!(assemble_symbol_csv(&[(0x1001, 2)], &["bad\nrow"]).is_err());
        assert!(invoke(
            "profile.symbols",
            &json!({"binary_path":"x","load_address":"bad","addresses":[]})
        )
        .is_err());
    }
}
