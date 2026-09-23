//! Port of `src/providers/visual-core.mjs`.
//!
//! Faithful Rust port of Node's hand-rolled, dependency-free PNG codec
//! (`encodePng`/`decodePng`/`comparePng`) plus the coverage-matrix and
//! `auditVisualArtifacts`/`analyze` entry points. `legion-audit` carries no
//! image or compression crate, so this module also carries its own minimal
//! RFC 1950 (zlib) / RFC 1951 (DEFLATE) codec: a stored-block encoder (valid
//! DEFLATE, matches the original's byte-for-byte non-goal — only pixel
//! fidelity is a contract, not compressed-stream identity with Node's zlib)
//! and a full inflate decoder (stored + fixed + dynamic Huffman) so PNGs
//! produced by real screenshot tooling can still be decoded.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------
// CRC32 (PNG chunk trailer)
// ---------------------------------------------------------------------

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc ^ 0xffff_ffff
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in bytes {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    out
}

// ---------------------------------------------------------------------
// zlib/DEFLATE — minimal stored-block encoder
// ---------------------------------------------------------------------

fn zlib_deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 65535 * 5 + 8);
    // zlib header: CMF=0x78 (deflate, 32K window), FLG=0x9C (default level,
    // no dict) — (0x78 << 8 | 0x9C) % 31 == 0, as RFC 1950 requires.
    out.push(0x78);
    out.push(0x9c);
    if data.is_empty() {
        out.push(0x01); // BFINAL=1, BTYPE=00, byte-aligned
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0xffffu16.to_le_bytes());
    } else {
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + 65535).min(data.len());
            let is_last = end == data.len();
            out.push(if is_last { 0x01 } else { 0x00 });
            let len = (end - offset) as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(&data[offset..end]);
            offset = end;
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

// ---------------------------------------------------------------------
// zlib/DEFLATE — full inflate decoder (RFC 1951 stored/fixed/dynamic)
// ---------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    byte: usize,
    bit: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, byte: 0, bit: 0 }
    }

    fn align_to_byte(&mut self) {
        if self.bit != 0 {
            self.byte += 1;
            self.bit = 0;
        }
    }

    fn read_bit(&mut self) -> Result<u32, String> {
        let byte = *self.data.get(self.byte).ok_or("inflate: unexpected end of stream")?;
        let value = u32::from((byte >> self.bit) & 1);
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.byte += 1;
        }
        Ok(value)
    }

    fn read_bits(&mut self, count: u32) -> Result<u32, String> {
        let mut value = 0u32;
        for i in 0..count {
            value |= self.read_bit()? << i;
        }
        Ok(value)
    }

    fn read_u16_le(&mut self) -> Result<u16, String> {
        let lo = *self.data.get(self.byte).ok_or("inflate: unexpected end of stream")?;
        let hi = *self.data.get(self.byte + 1).ok_or("inflate: unexpected end of stream")?;
        self.byte += 2;
        Ok(u16::from(lo) | (u16::from(hi) << 8))
    }
}

/// Canonical Huffman decode table, following the classic `puff.c` layout:
/// `count[len]` is how many codes of that length exist, and `symbol` lists
/// the symbols in canonical-code order.
struct Huffman {
    count: [u16; 16],
    symbol: Vec<u16>,
}

fn construct(lengths: &[u8]) -> Huffman {
    let mut count = [0u16; 16];
    for &length in lengths {
        count[length as usize] += 1;
    }
    count[0] = 0;
    let mut offsets = [0u16; 16];
    for len in 1..16 {
        offsets[len] = offsets[len - 1] + count[len - 1];
    }
    let mut symbol = vec![0u16; lengths.len()];
    for (sym, &length) in lengths.iter().enumerate() {
        if length != 0 {
            symbol[offsets[length as usize] as usize] = sym as u16;
            offsets[length as usize] += 1;
        }
    }
    Huffman { count, symbol }
}

fn decode_symbol(reader: &mut BitReader, huff: &Huffman) -> Result<u16, String> {
    let mut code: i32 = 0;
    let mut first: i32 = 0;
    let mut index: i32 = 0;
    for len in 1..16usize {
        code |= reader.read_bit()? as i32;
        let count = huff.count[len] as i32;
        if code - first < count {
            return Ok(huff.symbol[(index + (code - first)) as usize]);
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    Err("inflate: invalid Huffman code".to_string())
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn fixed_huffman() -> (Huffman, Huffman) {
    let mut lit_lengths = [0u8; 288];
    for (i, item) in lit_lengths.iter_mut().enumerate() {
        *item = if i < 144 {
            8
        } else if i < 256 {
            9
        } else if i < 280 {
            7
        } else {
            8
        };
    }
    let dist_lengths = [5u8; 30];
    (construct(&lit_lengths), construct(&dist_lengths))
}

fn dynamic_huffman(reader: &mut BitReader) -> Result<(Huffman, Huffman), String> {
    let hlit = reader.read_bits(5)? as usize + 257;
    let hdist = reader.read_bits(5)? as usize + 1;
    let hclen = reader.read_bits(4)? as usize + 4;
    let mut cl_lengths = [0u8; 19];
    for &order in CODE_LENGTH_ORDER.iter().take(hclen) {
        cl_lengths[order] = reader.read_bits(3)? as u8;
    }
    let cl_huff = construct(&cl_lengths);
    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0;
    while i < lengths.len() {
        let symbol = decode_symbol(reader, &cl_huff)?;
        match symbol {
            0..=15 => {
                lengths[i] = symbol as u8;
                i += 1;
            }
            16 => {
                let repeat = reader.read_bits(2)? + 3;
                let previous = if i == 0 { return Err("inflate: repeat with no previous length".into()) } else { lengths[i - 1] };
                for _ in 0..repeat {
                    if i >= lengths.len() { break; }
                    lengths[i] = previous;
                    i += 1;
                }
            }
            17 => {
                let repeat = reader.read_bits(3)? + 3;
                i += repeat as usize;
            }
            18 => {
                let repeat = reader.read_bits(7)? + 11;
                i += repeat as usize;
            }
            _ => return Err("inflate: invalid code-length symbol".into()),
        }
    }
    lengths.truncate(hlit + hdist);
    let lit_huff = construct(&lengths[..hlit]);
    let dist_huff = construct(&lengths[hlit..]);
    Ok((lit_huff, dist_huff))
}

fn inflate_block(reader: &mut BitReader, out: &mut Vec<u8>, lit: &Huffman, dist: &Huffman) -> Result<(), String> {
    loop {
        let symbol = decode_symbol(reader, lit)?;
        if symbol < 256 {
            out.push(symbol as u8);
        } else if symbol == 256 {
            return Ok(());
        } else {
            let index = (symbol - 257) as usize;
            if index >= LENGTH_BASE.len() {
                return Err("inflate: invalid length symbol".into());
            }
            let length = LENGTH_BASE[index] as usize + reader.read_bits(u32::from(LENGTH_EXTRA[index]))? as usize;
            let dist_symbol = decode_symbol(reader, dist)? as usize;
            if dist_symbol >= DIST_BASE.len() {
                return Err("inflate: invalid distance symbol".into());
            }
            let distance = DIST_BASE[dist_symbol] as usize + reader.read_bits(u32::from(DIST_EXTRA[dist_symbol]))? as usize;
            if distance == 0 || distance > out.len() {
                return Err("inflate: invalid back-reference distance".into());
            }
            let start = out.len() - distance;
            for offset in 0..length {
                let byte = out[start + offset];
                out.push(byte);
            }
        }
    }
}

/// Inflates a raw DEFLATE stream (RFC 1951, no zlib wrapper).
fn inflate_raw(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = BitReader::new(data);
    let mut out = Vec::new();
    loop {
        let is_final = reader.read_bit()? == 1;
        let btype = reader.read_bits(2)?;
        match btype {
            0 => {
                reader.align_to_byte();
                let len = reader.read_u16_le()?;
                let _nlen = reader.read_u16_le()?;
                for _ in 0..len {
                    let byte = *reader.data.get(reader.byte).ok_or("inflate: unexpected end of stream")?;
                    out.push(byte);
                    reader.byte += 1;
                }
            }
            1 => {
                let (lit, dist) = fixed_huffman();
                inflate_block(&mut reader, &mut out, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = dynamic_huffman(&mut reader)?;
                inflate_block(&mut reader, &mut out, &lit, &dist)?;
            }
            _ => return Err("inflate: reserved block type".into()),
        }
        if is_final {
            break;
        }
    }
    Ok(out)
}

/// Inflates a zlib-wrapped DEFLATE stream (RFC 1950), as produced by Node's
/// `zlib.deflateSync`/consumed by `zlib.inflateSync`.
fn inflate_zlib(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 6 {
        return Err("inflate: zlib stream too short".into());
    }
    inflate_raw(&data[2..data.len() - 4])
}

// ---------------------------------------------------------------------
// PNG encode/decode
// ---------------------------------------------------------------------

pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
    pub digest: String,
}

const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

pub fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>, String> {
    if width == 0 || height == 0 {
        return Err("invalid PNG dimensions".to_string());
    }
    if rgba.len() as u64 != u64::from(width) * u64::from(height) * 4 {
        return Err("RGBA byte length does not match dimensions".to_string());
    }
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);

    let stride = width as usize * 4;
    let mut rows = Vec::with_capacity(height as usize * (stride + 1));
    for y in 0..height as usize {
        rows.push(0u8);
        rows.extend_from_slice(&rgba[y * stride..(y + 1) * stride]);
    }
    let idat = zlib_deflate_stored(&rows);

    let mut out = Vec::new();
    out.extend_from_slice(&PNG_SIGNATURE);
    out.extend(png_chunk(b"IHDR", &ihdr));
    out.extend(png_chunk(b"IDAT", &idat));
    out.extend(png_chunk(b"IEND", &[]));
    Ok(out)
}

fn paeth(a: i32, b: i32, c: i32) -> u8 {
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

pub fn decode_png(buffer: &[u8]) -> Result<DecodedImage, String> {
    if buffer.len() < 8 || buffer[..8] != PNG_SIGNATURE {
        return Err("not a PNG file".to_string());
    }
    let mut offset = 8usize;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut interlace = 0u8;
    let mut idat: Vec<u8> = Vec::new();
    while offset + 12 <= buffer.len() {
        let length = u32::from_be_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
        let kind = &buffer[offset + 4..offset + 8];
        let data_start = offset + 8;
        let data_end = data_start + length;
        if data_end > buffer.len() {
            return Err("truncated PNG chunk".to_string());
        }
        let data = &buffer[data_start..data_end];
        match kind {
            b"IHDR" => {
                width = u32::from_be_bytes(data[0..4].try_into().unwrap());
                height = u32::from_be_bytes(data[4..8].try_into().unwrap());
                bit_depth = data[8];
                color_type = data[9];
                interlace = data[12];
            }
            b"IDAT" => idat.extend_from_slice(data),
            b"IEND" => break,
            _ => {}
        }
        offset = data_end + 4;
    }
    if width == 0 || height == 0 || bit_depth != 8 || interlace != 0 {
        return Err("only non-interlaced 8-bit PNGs are supported".to_string());
    }
    let channels: usize = match color_type {
        6 => 4,
        2 => 3,
        0 => 1,
        other => return Err(format!("unsupported PNG color type {other}")),
    };
    let raw = inflate_zlib(&idat)?;
    let stride = width as usize * channels;
    let expected = height as usize * (stride + 1);
    if raw.len() != expected {
        return Err(format!("PNG data length mismatch: {} != {}", raw.len(), expected));
    }
    let mut decoded = vec![0u8; height as usize * stride];
    let mut source = 0usize;
    for y in 0..height as usize {
        let filter = raw[source];
        source += 1;
        let row_start = y * stride;
        for x in 0..stride {
            let value = raw[source];
            source += 1;
            let left = if x >= channels { decoded[row_start + x - channels] } else { 0 };
            let up = if y > 0 { decoded[row_start - stride + x] } else { 0 };
            let up_left = if y > 0 && x >= channels { decoded[row_start - stride + x - channels] } else { 0 };
            let recon: u8 = match filter {
                0 => value,
                1 => value.wrapping_add(left),
                2 => value.wrapping_add(up),
                3 => value.wrapping_add(((left as u32 + up as u32) / 2) as u8),
                4 => value.wrapping_add(paeth(left as i32, up as i32, up_left as i32)),
                other => return Err(format!("unsupported PNG filter {other}")),
            };
            decoded[row_start + x] = recon;
        }
    }
    let mut rgba = vec![0u8; width as usize * height as usize * 4];
    for pixel in 0..(width as usize * height as usize) {
        let src = pixel * channels;
        let dst = pixel * 4;
        match channels {
            4 => rgba[dst..dst + 4].copy_from_slice(&decoded[src..src + 4]),
            3 => {
                rgba[dst..dst + 3].copy_from_slice(&decoded[src..src + 3]);
                rgba[dst + 3] = 255;
            }
            _ => {
                rgba[dst] = decoded[src];
                rgba[dst + 1] = decoded[src];
                rgba[dst + 2] = decoded[src];
                rgba[dst + 3] = 255;
            }
        }
    }
    Ok(DecodedImage { width, height, rgba, digest: sha256_digest(buffer) })
}

// ---------------------------------------------------------------------
// comparePng
// ---------------------------------------------------------------------

struct Mask {
    x: i64,
    y: i64,
    width: i64,
    height: i64,
}

fn masks_from(value: &Value) -> Vec<Mask> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| Mask {
                    x: item.get("x").and_then(Value::as_i64).unwrap_or(0),
                    y: item.get("y").and_then(Value::as_i64).unwrap_or(0),
                    width: item.get("width").and_then(Value::as_i64).unwrap_or(0),
                    height: item.get("height").and_then(Value::as_i64).unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn in_mask(x: i64, y: i64, masks: &[Mask]) -> bool {
    masks.iter().any(|mask| x >= mask.x && y >= mask.y && x < mask.x + mask.width && y < mask.y + mask.height)
}

pub fn compare_png(expected_bytes: &[u8], actual_bytes: &[u8], options: &Value) -> Result<Value, String> {
    let expected = decode_png(expected_bytes)?;
    let actual = decode_png(actual_bytes)?;
    if expected.width != actual.width || expected.height != actual.height {
        return Ok(serde_json::json!({
            "status": "different-dimensions",
            "expected": { "width": expected.width, "height": expected.height },
            "actual": { "width": actual.width, "height": actual.height },
            "changedPixels": Value::Null,
            "changedRatio": 1,
        }));
    }
    let threshold = options.get("channelThreshold").and_then(Value::as_i64).unwrap_or(0);
    let max_changed_ratio = options.get("maxChangedRatio").and_then(Value::as_f64).unwrap_or(0.0);
    let masks_value = options.get("masks").cloned().unwrap_or(Value::Array(vec![]));
    let masks = masks_from(&masks_value);
    let mut compared_pixels: u64 = 0;
    let mut changed_pixels: u64 = 0;
    let mut max_channel_delta: i64 = 0;
    let mut total_channel_delta: i64 = 0;
    for y in 0..expected.height as i64 {
        for x in 0..expected.width as i64 {
            if in_mask(x, y, &masks) {
                continue;
            }
            compared_pixels += 1;
            let offset = ((y as u32 * expected.width + x as u32) * 4) as usize;
            let mut changed = false;
            for channel in 0..4 {
                let delta = (i64::from(expected.rgba[offset + channel]) - i64::from(actual.rgba[offset + channel])).abs();
                max_channel_delta = max_channel_delta.max(delta);
                total_channel_delta += delta;
                if delta > threshold {
                    changed = true;
                }
            }
            if changed {
                changed_pixels += 1;
            }
        }
    }
    let changed_ratio = if compared_pixels > 0 { changed_pixels as f64 / compared_pixels as f64 } else { 0.0 };
    Ok(serde_json::json!({
        "status": if changed_ratio <= max_changed_ratio { "match" } else { "different" },
        "width": expected.width,
        "height": expected.height,
        "comparedPixels": compared_pixels,
        "changedPixels": changed_pixels,
        "changedRatio": changed_ratio,
        "maxChannelDelta": max_channel_delta,
        "meanChannelDelta": if compared_pixels > 0 { total_channel_delta as f64 / (compared_pixels as f64 * 4.0) } else { 0.0 },
        "expectedDigest": expected.digest,
        "actualDigest": actual.digest,
        "thresholds": { "channelThreshold": threshold, "maxChangedRatio": max_changed_ratio },
        "masks": masks_value,
    }))
}

// ---------------------------------------------------------------------
// buildCoverageMatrix
// ---------------------------------------------------------------------

fn field(item: &Value, key: &str) -> String {
    item.get(key).and_then(Value::as_str).unwrap_or("default").to_string()
}

fn case_key(item: &Value) -> String {
    let route = item.get("route").and_then(Value::as_str).unwrap_or("/");
    format!(
        "{}|{}|{}|{}|{}|{}",
        route,
        field(item, "state"),
        field(item, "viewport"),
        field(item, "theme"),
        field(item, "locale"),
        field(item, "platform"),
    )
}

fn cartesian(dimensions: &Value) -> Result<Vec<Value>, String> {
    let names = ["routes", "states", "viewports", "themes", "locales", "platforms"];
    let short = ["route", "state", "viewport", "theme", "locale", "platform"];
    let mut rows: Vec<Map<String, Value>> = vec![Map::new()];
    for (name, key) in names.iter().zip(short.iter()) {
        let values: Vec<Value> = dimensions
            .get(*name)
            .and_then(Value::as_array)
            .filter(|items| !items.is_empty())
            .cloned()
            .unwrap_or_else(|| vec![Value::String("default".to_string())]);
        let mut next = Vec::with_capacity(rows.len() * values.len());
        for row in &rows {
            for value in &values {
                let mut clone = row.clone();
                clone.insert((*key).to_string(), value.clone());
                next.push(clone);
            }
        }
        rows = next;
        if rows.len() > 10_000 {
            return Err("visual coverage matrix exceeds 10,000 cases; provide explicit expected.cases".to_string());
        }
    }
    Ok(rows.into_iter().map(Value::Object).collect())
}

pub fn build_coverage_matrix(spec: &Value) -> Result<Value, String> {
    let expected = spec.get("expected").cloned().unwrap_or(Value::Null);
    let declared_cases = expected.get("cases").and_then(Value::as_array).cloned();
    let expected_cases = match declared_cases {
        Some(cases) => cases,
        None => cartesian(&expected)?,
    };
    let captures: Vec<Value> = spec.get("captures").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut capture_by_key: HashMap<String, &Value> = HashMap::new();
    for capture in &captures {
        capture_by_key.insert(case_key(capture), capture);
    }
    let cases: Vec<Value> = expected_cases
        .iter()
        .map(|item| {
            let route = item.get("route").and_then(Value::as_str).unwrap_or("/").to_string();
            let mut normalized = serde_json::json!({
                "route": route,
                "state": field(item, "state"),
                "viewport": field(item, "viewport"),
                "theme": field(item, "theme"),
                "locale": field(item, "locale"),
                "platform": field(item, "platform"),
            });
            let key = case_key(&normalized);
            let capture = capture_by_key.get(&key).copied();
            let object = normalized.as_object_mut().unwrap();
            object.insert("covered".into(), Value::Bool(capture.is_some()));
            object.insert("captureId".into(), capture.and_then(|c| c.get("id")).cloned().unwrap_or(Value::Null));
            normalized
        })
        .collect();
    let covered_count = cases.iter().filter(|item| item.get("covered") == Some(&Value::Bool(true))).count();
    let missing_count = cases.len() - covered_count;
    let complete = missing_count == 0;
    Ok(serde_json::json!({
        "expectedCount": cases.len(),
        "coveredCount": covered_count,
        "missingCount": missing_count,
        "complete": complete,
        "cases": cases,
    }))
}

// ---------------------------------------------------------------------
// auditVisualArtifacts / analyze
// ---------------------------------------------------------------------

pub fn audit_visual_artifacts(root: &std::path::Path, spec: &Value) -> Result<Value, String> {
    let coverage = build_coverage_matrix(spec)?;
    let mut captures: Vec<Value> = Vec::new();
    let mut findings: Vec<Value> = Vec::new();
    let raw_captures: Vec<Value> = spec.get("captures").and_then(Value::as_array).cloned().unwrap_or_default();
    let diff_defaults = spec.get("diff").cloned().unwrap_or(Value::Object(Map::new()));

    for capture in &raw_captures {
        let id = capture.get("id").cloned().unwrap_or(Value::Null);
        let path = capture.get("path").and_then(Value::as_str);
        let Some(path) = path else {
            captures.push(serde_json::json!({ "id": id, "status": "unproven", "reason": "capture-missing", "path": Value::Null }));
            continue;
        };
        let actual_path = root.join(path);
        if !actual_path.exists() {
            captures.push(serde_json::json!({ "id": id, "status": "unproven", "reason": "capture-missing", "path": path }));
            continue;
        }
        let baseline = capture.get("baseline").and_then(Value::as_str);
        let Some(baseline) = baseline else {
            let bytes = std::fs::read(&actual_path).map_err(|error| error.to_string())?;
            captures.push(serde_json::json!({ "id": id, "status": "captured-no-baseline", "path": path, "digest": sha256_digest(&bytes) }));
            continue;
        };
        let baseline_path = root.join(baseline);
        if !baseline_path.exists() {
            captures.push(serde_json::json!({ "id": id, "status": "unproven", "reason": "baseline-missing", "path": path, "baseline": baseline }));
            continue;
        }
        let capture_diff_options = capture.get("diff").cloned().unwrap_or_else(|| diff_defaults.clone());
        let expected_bytes = std::fs::read(&baseline_path).map_err(|error| error.to_string())?;
        let actual_bytes = std::fs::read(&actual_path).map_err(|error| error.to_string())?;
        let diff = compare_png(&expected_bytes, &actual_bytes, &capture_diff_options)?;
        let status = diff.get("status").and_then(Value::as_str).unwrap_or("different").to_string();
        captures.push(serde_json::json!({ "id": id, "status": status, "path": path, "baseline": baseline, "diff": diff }));
        if status != "match" {
            let changed_ratio = diff.get("changedRatio").and_then(Value::as_f64).unwrap_or(1.0);
            let detail = if status == "different-dimensions" {
                "Rendered dimensions differ from the baseline.".to_string()
            } else {
                format!("{:.3}% of compared pixels changed.", changed_ratio * 100.0)
            };
            findings.push(serde_json::json!({
                "id": sha256_digest(format!("visual-regression\0{}", id.as_str().unwrap_or_default()).as_bytes()),
                "ruleId": "visual.regression",
                "severity": if changed_ratio >= 0.1 { "high" } else { "medium" },
                "title": format!("Visual regression in {}", id.as_str().unwrap_or_default()),
                "detail": detail,
                "evidence": [{ "actual": path, "baseline": baseline }],
            }));
        }
    }

    let review_required = captures.iter().any(|item| item.get("status") == Some(&Value::String("captured-no-baseline".into())));
    let cases = coverage.get("cases").and_then(Value::as_array).cloned().unwrap_or_default();
    let expected_count = coverage.get("expectedCount").and_then(Value::as_u64).unwrap_or(0);
    let empty_matrix = expected_count == 0;
    let coverage_complete = coverage.get("complete") == Some(&Value::Bool(true));
    let unproven = captures.iter().any(|item| item.get("status") == Some(&Value::String("unproven".into())))
        || !coverage_complete
        || review_required
        || empty_matrix;

    let mut coverage_gaps: Vec<Value> = Vec::new();
    if empty_matrix {
        coverage_gaps.push(serde_json::json!({ "kind": "visual-cases-missing", "detail": "visual spec declares no expected cases; nothing is proven" }));
    }
    for item in cases.iter().filter(|item| item.get("covered") != Some(&Value::Bool(true))) {
        coverage_gaps.push(serde_json::json!({ "kind": "missing-visual-case", "case": item }));
    }
    for item in captures.iter().filter(|item| item.get("status") == Some(&Value::String("unproven".into()))) {
        coverage_gaps.push(serde_json::json!({ "kind": item.get("reason").cloned().unwrap_or(Value::Null), "captureId": item.get("id").cloned().unwrap_or(Value::Null) }));
    }
    for item in captures.iter().filter(|item| item.get("status") == Some(&Value::String("captured-no-baseline".into()))) {
        coverage_gaps.push(serde_json::json!({ "kind": "visual-review-or-baseline-required", "captureId": item.get("id").cloned().unwrap_or(Value::Null) }));
    }

    let examined = captures.iter().filter(|item| {
        let status = item.get("status").and_then(Value::as_str);
        status.is_some() && status != Some("unproven")
    }).count();

    Ok(serde_json::json!({
        "schemaVersion": 1,
        "kind": "audit-visual-result",
        "status": if !findings.is_empty() { "fail" } else if unproven { "unproven" } else { "pass" },
        "complete": !unproven,
        "reviewRequired": review_required,
        "coverage": coverage,
        "denominator": { "kind": "visual-artifacts", "expected": expected_count, "examined": examined },
        "captures": captures,
        "findings": findings,
        "coverageGaps": coverage_gaps,
    }))
}

pub fn analyze(root: &std::path::Path, artifacts: &Value) -> Value {
    let spec = artifacts.get("visualSpec");
    let Some(spec) = spec.filter(|value| !value.is_null()) else {
        return serde_json::json!({
            "status": "unproven", "complete": false,
            "denominator": { "kind": "visual-artifacts", "expected": 0, "examined": 0 },
            "findings": [], "coverageGaps": [{ "kind": "visual-spec-missing" }],
        });
    };
    match audit_visual_artifacts(root, spec) {
        Ok(result) => serde_json::json!({
            "status": result.get("status").cloned().unwrap_or(Value::String("unproven".into())),
            "complete": result.get("complete").cloned().unwrap_or(Value::Bool(false)),
            "reviewRequired": result.get("reviewRequired") == Some(&Value::Bool(true)),
            "denominator": result.get("denominator").cloned().unwrap_or_else(|| serde_json::json!({ "kind": "visual-artifacts", "expected": 0, "examined": 0 })),
            "findings": result.get("findings").cloned().unwrap_or(Value::Array(vec![])),
            "coverageGaps": result.get("coverageGaps").cloned().unwrap_or(Value::Array(vec![])),
        }),
        Err(error) => serde_json::json!({
            "status": "unproven", "complete": false,
            "denominator": { "kind": "visual-artifacts", "expected": 0, "examined": 0 },
            "findings": [], "coverageGaps": [{ "kind": "visual-spec-invalid", "detail": error.chars().take(200).collect::<String>() }],
        }),
    }
}
