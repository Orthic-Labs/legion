//! Bounded pixel comparison for frozen Audit Visual captures.
//!
//! PNG bytes are decoded to RGBA before comparison so encoding metadata does
//! not count as a rendered-pixel change. Raw-byte digests remain separate
//! evidence and belong to the caller.

use std::io::Cursor;

use image::{ImageFormat, ImageReader, Limits};
use serde::Serialize;

pub const MAX_ENCODED_PNG_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PNG_DIMENSION: u32 = 16_384;
pub const MAX_DECODED_PNG_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MASKS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PngDimensions {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MaskRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffOptions {
    pub channel_threshold: f64,
    pub max_changed_ratio: f64,
    pub masks: Vec<MaskRect>,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            channel_threshold: 0.0,
            max_changed_ratio: 0.0,
            masks: Vec::new(),
        }
    }
}

/// Validates frozen comparison policy before captures are processed.
/// Bounds against concrete image dimensions are checked again by `compare_png`.
pub fn validate_options(options: &DiffOptions) -> Result<(), String> {
    if !options.channel_threshold.is_finite() || !(0.0..=255.0).contains(&options.channel_threshold)
    {
        return Err("channel threshold must be finite and between 0 and 255".into());
    }
    if !options.max_changed_ratio.is_finite() || !(0.0..=1.0).contains(&options.max_changed_ratio) {
        return Err("maximum changed ratio must be finite and between 0 and 1".into());
    }
    if options.masks.len() > MAX_MASKS {
        return Err(format!("at most {MAX_MASKS} pixel masks are allowed"));
    }
    for (index, mask) in options.masks.iter().enumerate() {
        let right = mask.x.checked_add(mask.width);
        let bottom = mask.y.checked_add(mask.height);
        if mask.width == 0
            || mask.height == 0
            || right.is_none_or(|edge| edge > MAX_PNG_DIMENSION)
            || bottom.is_none_or(|edge| edge > MAX_PNG_DIMENSION)
        {
            return Err(format!(
                "pixel mask {index} must be a positive rectangle within the maximum image dimensions"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PngUnproven {
    EncodedImageTooLarge {
        bytes: usize,
        maximum: usize,
    },
    DecodeFailed(String),
    DecodedImageTooLarge {
        width: u32,
        height: u32,
    },
    InvalidOptions(String),
    MaskOutsideImage {
        index: usize,
        dimensions: PngDimensions,
    },
    NoComparedPixels,
}

impl std::fmt::Display for PngUnproven {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncodedImageTooLarge { bytes, maximum } => {
                write!(f, "encoded PNG has {bytes} bytes (maximum {maximum})")
            }
            Self::DecodeFailed(reason) => write!(f, "PNG decode failed: {reason}"),
            Self::DecodedImageTooLarge { width, height } => write!(
                f,
                "decoded PNG dimensions {width}x{height} exceed the configured bounds"
            ),
            Self::InvalidOptions(reason) => write!(f, "invalid pixel comparison options: {reason}"),
            Self::MaskOutsideImage { index, dimensions } => write!(
                f,
                "pixel mask {index} falls outside image dimensions {}x{}",
                dimensions.width, dimensions.height
            ),
            Self::NoComparedPixels => write!(f, "pixel masks cover the entire image"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PixelStatus {
    Match,
    Different,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PixelDiff {
    pub status: PixelStatus,
    pub width: u32,
    pub height: u32,
    pub changed_ratio: f64,
    pub changed_pixels: u64,
    pub compared_pixels: u64,
    pub max_channel_delta: u8,
    pub mean_channel_delta: f64,
    pub channel_threshold: f64,
    pub max_changed_ratio: f64,
    pub masks: Vec<MaskRect>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PngComparison {
    Compared(PixelDiff),
    DifferentDimensions {
        actual: PngDimensions,
        baseline: PngDimensions,
    },
    Unproven(PngUnproven),
}

struct DecodedPng {
    dimensions: PngDimensions,
    rgba: image::RgbaImage,
}

fn decode_png(bytes: &[u8]) -> Result<DecodedPng, PngUnproven> {
    if bytes.len() > MAX_ENCODED_PNG_BYTES {
        return Err(PngUnproven::EncodedImageTooLarge {
            bytes: bytes.len(),
            maximum: MAX_ENCODED_PNG_BYTES,
        });
    }

    let mut reader = ImageReader::with_format(Cursor::new(bytes), ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_PNG_DIMENSION);
    limits.max_image_height = Some(MAX_PNG_DIMENSION);
    limits.max_alloc = Some(MAX_DECODED_PNG_BYTES);
    reader.limits(limits);
    let decoded = reader
        .decode()
        .map_err(|error| PngUnproven::DecodeFailed(error.to_string()))?;
    let (width, height) = (decoded.width(), decoded.height());
    let dimensions = PngDimensions { width, height };
    let decoded_bytes = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|pixels| pixels.checked_mul(4));
    if width == 0
        || height == 0
        || width > MAX_PNG_DIMENSION
        || height > MAX_PNG_DIMENSION
        || decoded_bytes.is_none_or(|bytes| bytes > MAX_DECODED_PNG_BYTES)
    {
        return Err(PngUnproven::DecodedImageTooLarge { width, height });
    }
    Ok(DecodedPng {
        dimensions,
        rgba: decoded.into_rgba8(),
    })
}

/// Fully decodes a PNG within fixed encoded-byte, dimension, and allocation
/// bounds, returning its true decoded dimensions.
pub fn inspect_png(bytes: &[u8]) -> Result<PngDimensions, PngUnproven> {
    decode_png(bytes).map(|decoded| decoded.dimensions)
}

fn row_mask_intervals(masks: &[MaskRect], y: u32) -> Vec<(u32, u32)> {
    let mut intervals = masks
        .iter()
        .filter(|mask| y >= mask.y && y < mask.y + mask.height)
        .map(|mask| (mask.x, mask.x + mask.width))
        .collect::<Vec<_>>();
    intervals.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

/// Decodes and compares two PNGs in RGBA space. Masked pixels are omitted;
/// an invalid policy, malformed image, or mask that leaves no compared pixels
/// returns typed `Unproven`, never a clean match.
pub fn compare_png(actual: &[u8], baseline: &[u8], options: &DiffOptions) -> PngComparison {
    if let Err(error) = validate_options(options) {
        return PngComparison::Unproven(PngUnproven::InvalidOptions(error));
    }
    let actual = match decode_png(actual) {
        Ok(decoded) => decoded,
        Err(error) => return PngComparison::Unproven(error),
    };
    let baseline = match decode_png(baseline) {
        Ok(decoded) => decoded,
        Err(error) => return PngComparison::Unproven(error),
    };
    if actual.dimensions != baseline.dimensions {
        return PngComparison::DifferentDimensions {
            actual: actual.dimensions,
            baseline: baseline.dimensions,
        };
    }

    let dimensions = actual.dimensions;
    for (index, mask) in options.masks.iter().enumerate() {
        if mask.x + mask.width > dimensions.width || mask.y + mask.height > dimensions.height {
            return PngComparison::Unproven(PngUnproven::MaskOutsideImage { index, dimensions });
        }
    }

    let mut changed_pixels = 0_u64;
    let mut compared_pixels = 0_u64;
    let mut max_channel_delta = 0_u8;
    let mut total_channel_delta = 0_u64;
    let mut compared_channels = 0_u64;
    for y in 0..dimensions.height {
        let intervals = row_mask_intervals(&options.masks, y);
        let mut interval_index = 0;
        for x in 0..dimensions.width {
            while interval_index < intervals.len() && x >= intervals[interval_index].1 {
                interval_index += 1;
            }
            if interval_index < intervals.len() && x >= intervals[interval_index].0 {
                continue;
            }
            compared_pixels += 1;
            let actual_pixel = actual.rgba.get_pixel(x, y).0;
            let baseline_pixel = baseline.rgba.get_pixel(x, y).0;
            let mut pixel_changed = false;
            for channel in 0..4 {
                let delta = actual_pixel[channel].abs_diff(baseline_pixel[channel]);
                max_channel_delta = max_channel_delta.max(delta);
                total_channel_delta += u64::from(delta);
                compared_channels += 1;
                pixel_changed |= f64::from(delta) > options.channel_threshold;
            }
            if pixel_changed {
                changed_pixels += 1;
            }
        }
    }
    if compared_pixels == 0 {
        return PngComparison::Unproven(PngUnproven::NoComparedPixels);
    }
    let changed_ratio = changed_pixels as f64 / compared_pixels as f64;
    let mean_channel_delta = total_channel_delta as f64 / compared_channels as f64;
    PngComparison::Compared(PixelDiff {
        status: if changed_ratio <= options.max_changed_ratio {
            PixelStatus::Match
        } else {
            PixelStatus::Different
        },
        width: dimensions.width,
        height: dimensions.height,
        changed_ratio,
        changed_pixels,
        compared_pixels,
        max_channel_delta,
        mean_channel_delta,
        channel_threshold: options.channel_threshold,
        max_changed_ratio: options.max_changed_ratio,
        masks: options.masks.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, Rgba, RgbaImage};

    fn png(width: u32, height: u32, pixels: &[[u8; 4]]) -> Vec<u8> {
        let mut image = RgbaImage::new(width, height);
        for (pixel, rgba) in image.pixels_mut().zip(pixels.iter().copied()) {
            *pixel = Rgba(rgba);
        }
        let mut encoded = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(image)
            .write_to(&mut encoded, ImageFormat::Png)
            .unwrap();
        encoded.into_inner()
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0_u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn with_text_metadata(mut png: Vec<u8>) -> Vec<u8> {
        let chunk_type = *b"tEXt";
        let payload = b"Comment\0different metadata";
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(&chunk_type);
        chunk.extend_from_slice(payload);
        let checksum = crc32(&chunk[4..]);
        chunk.extend_from_slice(&checksum.to_be_bytes());
        let iend = png.len() - 12;
        png.splice(iend..iend, chunk);
        png
    }

    #[test]
    fn metadata_or_encoding_bytes_do_not_change_equal_pixels() {
        let first = png(1, 1, &[[10, 20, 30, 255]]);
        let second = with_text_metadata(first.clone());
        assert_ne!(first, second);
        let result = compare_png(&first, &second, &DiffOptions::default());
        let PngComparison::Compared(diff) = result else {
            panic!("expected a pixel comparison");
        };
        assert_eq!(diff.status, PixelStatus::Match);
        assert_eq!(diff.changed_ratio, 0.0);
    }

    #[test]
    fn one_changed_pixel_reports_exact_ratio() {
        let actual = png(2, 1, &[[0, 0, 0, 255], [255, 255, 255, 255]]);
        let baseline = png(2, 1, &[[0, 0, 0, 255], [0, 0, 0, 255]]);
        let result = compare_png(&actual, &baseline, &DiffOptions::default());
        let PngComparison::Compared(diff) = result else {
            panic!("expected a pixel comparison");
        };
        assert_eq!(diff.status, PixelStatus::Different);
        assert_eq!(diff.changed_pixels, 1);
        assert_eq!(diff.compared_pixels, 2);
        assert_eq!(diff.changed_ratio, 0.5);
        assert_eq!(diff.max_channel_delta, 255);
    }

    #[test]
    fn channel_threshold_and_mask_are_applied_to_pixels() {
        let actual = png(2, 1, &[[10, 20, 30, 255], [200, 0, 0, 255]]);
        let baseline = png(2, 1, &[[11, 20, 30, 255], [0, 0, 0, 255]]);
        let options = DiffOptions {
            channel_threshold: 1.0,
            max_changed_ratio: 0.0,
            masks: vec![MaskRect {
                x: 1,
                y: 0,
                width: 1,
                height: 1,
            }],
        };
        let result = compare_png(&actual, &baseline, &options);
        let PngComparison::Compared(diff) = result else {
            panic!("expected a pixel comparison");
        };
        assert_eq!(diff.status, PixelStatus::Match);
        assert_eq!(diff.compared_pixels, 1);
        assert_eq!(diff.changed_pixels, 0);
        assert_eq!(diff.max_channel_delta, 1);
    }

    #[test]
    fn different_dimensions_have_distinct_status() {
        let actual = png(1, 1, &[[0, 0, 0, 255]]);
        let baseline = png(2, 1, &[[0, 0, 0, 255], [0, 0, 0, 255]]);
        assert!(matches!(
            compare_png(&actual, &baseline, &DiffOptions::default()),
            PngComparison::DifferentDimensions { .. }
        ));
    }

    #[test]
    fn corrupt_png_is_unproven() {
        assert!(matches!(
            compare_png(b"not PNG", b"not PNG", &DiffOptions::default()),
            PngComparison::Unproven(PngUnproven::DecodeFailed(_))
        ));
    }

    #[test]
    fn invalid_options_are_rejected_before_comparison() {
        let options = DiffOptions {
            channel_threshold: f64::NAN,
            ..DiffOptions::default()
        };
        assert!(validate_options(&options).is_err());
    }

    #[test]
    fn full_image_mask_is_unproven() {
        let bytes = png(1, 1, &[[0, 0, 0, 255]]);
        let options = DiffOptions {
            masks: vec![MaskRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }],
            ..DiffOptions::default()
        };
        assert_eq!(
            compare_png(&bytes, &bytes, &options),
            PngComparison::Unproven(PngUnproven::NoComparedPixels)
        );
    }
}
