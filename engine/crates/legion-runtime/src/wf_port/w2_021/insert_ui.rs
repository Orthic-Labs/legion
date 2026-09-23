//! Port of `skills/designer/engine/scripts/live/insert-ui.mjs`.
//!
//! Pure geometry/state helpers for live-mode insert UI. `findInsertAnchorInDom`
//! needs a live `Document`/`querySelectorAll` and is not ported here
//! (frontier, browser-only — see the chunk's `mod.rs` header).

pub const PLACEHOLDER_DEFAULT_HEIGHT: f64 = 80.0;
pub const PLACEHOLDER_MIN_HEIGHT: f64 = 48.0;
pub const PLACEHOLDER_MIN_WIDTH: f64 = 120.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertPosition {
    Before,
    After,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertAxis {
    Row,
    Column,
}

#[derive(Debug, Clone, Default)]
pub struct ContainerStyle {
    pub display: Option<String>,
    pub flex_direction: Option<String>,
    pub grid_template_columns: Option<String>,
    pub grid_auto_flow: Option<String>,
}

pub fn detect_insert_axis_from_style(style: &ContainerStyle) -> InsertAxis {
    let display = style.display.as_deref().unwrap_or("block");
    if display.contains("flex") {
        let dir = style.flex_direction.as_deref().unwrap_or("row");
        return if dir.starts_with("row") {
            InsertAxis::Row
        } else {
            InsertAxis::Column
        };
    }
    if display == "grid" || display == "inline-grid" {
        let flow = style.grid_auto_flow.as_deref().unwrap_or("row");
        if flow.contains("column") {
            return InsertAxis::Column;
        }
        let cols = style.grid_template_columns.as_deref().unwrap_or("").trim();
        if !cols.is_empty() && cols != "none" {
            let col_count = cols.split_whitespace().filter(|s| !s.is_empty()).count();
            if col_count > 1 {
                return InsertAxis::Row;
            }
        }
        return InsertAxis::Row;
    }
    InsertAxis::Column
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Rect {
    pub top: f64,
    pub left: f64,
    pub width: f64,
    pub height: f64,
    pub bottom: Option<f64>,
    pub right: Option<f64>,
}

impl Rect {
    fn bottom(&self) -> f64 {
        self.bottom.unwrap_or(self.top + self.height)
    }
    fn right(&self) -> f64 {
        self.right.unwrap_or(self.left + self.width)
    }
}

pub fn compute_insert_position(
    client_x: f64,
    client_y: f64,
    rect: Option<&Rect>,
    axis: InsertAxis,
) -> InsertPosition {
    let rect = match rect {
        Some(r) => r,
        None => return InsertPosition::After,
    };
    if axis == InsertAxis::Row {
        if !rect.left.is_finite() || !rect.width.is_finite() || rect.width <= 0.0 {
            return InsertPosition::After;
        }
        let mid = rect.left + rect.width / 2.0;
        return if client_x < mid {
            InsertPosition::Before
        } else {
            InsertPosition::After
        };
    }
    if !rect.top.is_finite() || !rect.height.is_finite() || rect.height <= 0.0 {
        return InsertPosition::After;
    }
    let mid = rect.top + rect.height / 2.0;
    if client_y < mid {
        InsertPosition::Before
    } else {
        InsertPosition::After
    }
}

pub struct CanCreateInsertInput<'a> {
    pub prompt: Option<&'a str>,
    pub comments: &'a [serde_json::Value],
    pub strokes: &'a [Vec<(f64, f64)>],
}

/// Whether Create is allowed for an insert session: requires a non-empty
/// prompt OR at least one annotation (a comment, or a stroke with >= 2
/// points).
pub fn can_create_insert(input: &CanCreateInsertInput) -> bool {
    let has_prompt = input.prompt.map(|p| !p.trim().is_empty()).unwrap_or(false);
    let has_comments = !input.comments.is_empty();
    let has_strokes = input.strokes.iter().any(|s| s.len() >= 2);
    has_prompt || has_comments || has_strokes
}

/// Tooltip/title when Create is disabled.
pub fn insert_create_disabled_reason(input: &CanCreateInsertInput) -> Option<&'static str> {
    if can_create_insert(input) {
        None
    } else {
        Some("Add a prompt or annotate the placeholder to create")
    }
}

#[derive(Debug, Clone)]
pub struct InsertLine {
    pub axis: InsertAxis,
    pub top: f64,
    pub left: f64,
    pub width: f64,
    pub height: f64,
}

/// Fixed-position insert line coordinates (viewport px).
pub fn insert_line_coords(rect: &Rect, position: InsertPosition, axis: InsertAxis) -> InsertLine {
    if axis == InsertAxis::Row {
        let right = rect.right();
        let x = if position == InsertPosition::Before {
            rect.left - 2.0
        } else {
            right + 2.0
        };
        return InsertLine {
            axis: InsertAxis::Row,
            top: rect.top,
            left: x,
            width: 0.0,
            height: rect.height,
        };
    }
    let bottom = rect.bottom();
    let y = if position == InsertPosition::Before {
        rect.top - 2.0
    } else {
        bottom + 2.0
    };
    InsertLine {
        axis: InsertAxis::Column,
        top: y,
        left: rect.left,
        width: rect.width,
        height: 0.0,
    }
}

/// Cursor while hovering an insert boundary.
pub fn cursor_for_insert_axis(axis: InsertAxis) -> &'static str {
    match axis {
        InsertAxis::Row => "ew-resize",
        InsertAxis::Column => "ns-resize",
    }
}

#[derive(Debug, Clone)]
pub struct Sibling<T: Clone> {
    pub el: T,
    pub rect: Rect,
}

fn group_sibling_rows<T: Clone>(siblings: &[Sibling<T>], row_threshold: f64) -> Vec<Vec<Sibling<T>>> {
    let mut sorted: Vec<Sibling<T>> = siblings.to_vec();
    sorted.sort_by(|a, b| {
        a.rect
            .top
            .partial_cmp(&b.rect.top)
            .unwrap()
            .then(a.rect.left.partial_cmp(&b.rect.left).unwrap())
    });
    let mut rows: Vec<Vec<Sibling<T>>> = Vec::new();
    for entry in sorted {
        let mut placed = false;
        for row in rows.iter_mut() {
            if (entry.rect.top - row[0].rect.top).abs() <= row_threshold {
                row.push(entry.clone());
                placed = true;
                break;
            }
        }
        if !placed {
            rows.push(vec![entry]);
        }
    }
    rows
}

fn horizontal_overlap(a: &Rect, b: &Rect) -> f64 {
    let left = a.left.max(b.left);
    let right = a.right().min(b.right());
    (right - left).max(0.0)
}

#[derive(Debug, Clone)]
pub struct GapHit<T: Clone> {
    pub anchor: T,
    pub position: InsertPosition,
    pub axis: InsertAxis,
    pub line: InsertLine,
}

#[derive(Debug, Clone, Copy)]
pub struct GapOpts {
    pub slop: f64,
    pub min_overlap: f64,
}

impl Default for GapOpts {
    fn default() -> Self {
        Self {
            slop: 12.0,
            min_overlap: 0.25,
        }
    }
}

/// Hit-test the gap between adjacent siblings (flex rows, grid columns,
/// stacked blocks).
pub fn hit_sibling_insert_gap<T: Clone>(
    client_x: f64,
    client_y: f64,
    siblings: &[Sibling<T>],
    opts: GapOpts,
) -> Option<GapHit<T>> {
    if siblings.len() < 2 {
        return None;
    }
    let slop = opts.slop;
    let min_overlap = opts.min_overlap;

    for row in group_sibling_rows(siblings, 8.0) {
        if row.len() < 2 {
            continue;
        }
        let mut sorted = row.clone();
        sorted.sort_by(|a, b| a.rect.left.partial_cmp(&b.rect.left).unwrap());
        for i in 0..sorted.len() - 1 {
            let a = &sorted[i];
            let b = &sorted[i + 1];
            let a_right = a.rect.right();
            let b_left = b.rect.left;
            if b_left <= a_right {
                continue;
            }
            let top = a.rect.top.max(b.rect.top);
            let a_bottom = a.rect.bottom();
            let b_bottom = b.rect.bottom();
            let bottom = a_bottom.min(b_bottom);
            let span = bottom - top;
            let min_h = a.rect.height.min(b.rect.height);
            if span < min_h * min_overlap {
                continue;
            }
            let in_x = client_x >= a_right - slop && client_x <= b_left + slop;
            let in_y = client_y >= top - slop && client_y <= bottom + slop;
            if !in_x || !in_y {
                continue;
            }
            let mid_x = (a_right + b_left) / 2.0;
            return Some(GapHit {
                anchor: b.el.clone(),
                position: InsertPosition::Before,
                axis: InsertAxis::Row,
                line: InsertLine {
                    axis: InsertAxis::Row,
                    left: mid_x,
                    top,
                    width: 0.0,
                    height: span,
                },
            });
        }
    }

    let mut sorted_col: Vec<Sibling<T>> = siblings.to_vec();
    sorted_col.sort_by(|a, b| {
        a.rect
            .top
            .partial_cmp(&b.rect.top)
            .unwrap()
            .then(a.rect.left.partial_cmp(&b.rect.left).unwrap())
    });
    for i in 0..sorted_col.len().saturating_sub(1) {
        let a = &sorted_col[i];
        let b = &sorted_col[i + 1];
        let overlap = horizontal_overlap(&a.rect, &b.rect);
        let min_w = a.rect.width.min(b.rect.width);
        if overlap < min_w * min_overlap {
            continue;
        }
        let a_bottom = a.rect.bottom();
        let gap_top = a_bottom;
        let gap_bottom = b.rect.top;
        if gap_bottom <= gap_top {
            continue;
        }
        let overlap_left = a.rect.left.max(b.rect.left);
        let overlap_right = a.rect.right().min(b.rect.right());
        let in_y = client_y >= gap_top - slop && client_y <= gap_bottom + slop;
        let in_x = client_x >= overlap_left - slop && client_x <= overlap_right + slop;
        if !in_y || !in_x {
            continue;
        }
        let mid_y = (gap_top + gap_bottom) / 2.0;
        return Some(GapHit {
            anchor: b.el.clone(),
            position: InsertPosition::Before,
            axis: InsertAxis::Column,
            line: InsertLine {
                axis: InsertAxis::Column,
                top: mid_y,
                left: overlap_left,
                width: overlap,
                height: 0.0,
            },
        });
    }

    None
}

/// Resolve insert hover target, side, axis, and indicator line for the
/// pointer.
pub fn resolve_insert_hover<T: Clone>(
    client_x: f64,
    client_y: f64,
    target: T,
    rect: &Rect,
    axis: InsertAxis,
    siblings: &[Sibling<T>],
) -> GapHit<T> {
    if let Some(gap) = hit_sibling_insert_gap(client_x, client_y, siblings, GapOpts::default()) {
        return gap;
    }
    let position = compute_insert_position(client_x, client_y, Some(rect), axis);
    let line = insert_line_coords(rect, position, axis);
    GapHit {
        anchor: target,
        position,
        axis,
        line,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlaceholderSizing {
    Flex { flex: String, min_width: f64 },
    Percent,
    Auto,
    Explicit { width: f64 },
}

pub struct PlaceholderSizingInput<'a> {
    pub axis: InsertAxis,
    pub parent_display: Option<&'a str>,
    pub parent_width: Option<f64>,
    pub anchor_flex: Option<&'a str>,
}

/// How the in-flow placeholder should participate in layout. Prefer implicit
/// sizing (flex / %) so row inserts don't inherit the full parent width in px.
pub fn placeholder_sizing(input: &PlaceholderSizingInput) -> PlaceholderSizing {
    let display = input.parent_display.unwrap_or("block");
    let w = input.parent_width.filter(|w| w.is_finite()).unwrap_or(0.0);

    if input.axis == InsertAxis::Row {
        if display.contains("flex") {
            let flex = match input.anchor_flex {
                Some(f) if f != "none" && f != "0 1 auto" => f.to_string(),
                _ => "1 1 0".to_string(),
            };
            return PlaceholderSizing::Flex {
                flex,
                min_width: 0.0,
            };
        }
        if display == "grid" || display == "inline-grid" {
            return PlaceholderSizing::Auto;
        }
    }

    if w >= PLACEHOLDER_MIN_WIDTH {
        return PlaceholderSizing::Percent;
    }

    PlaceholderSizing::Explicit {
        width: PLACEHOLDER_MIN_WIDTH.max(if w > 0.0 { w } else { PLACEHOLDER_MIN_WIDTH }),
    }
}

/// Width kinds that need materializing to px before edge-resize.
pub fn placeholder_width_is_implicit(kind: &PlaceholderSizing) -> bool {
    matches!(
        kind,
        PlaceholderSizing::Flex { .. } | PlaceholderSizing::Percent | PlaceholderSizing::Auto
    )
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ClampOpts {
    pub min_width: Option<f64>,
    pub min_height: Option<f64>,
    pub max_width: Option<f64>,
}

/// Clamp user-resized placeholder dimensions.
pub fn clamp_placeholder_size(
    width: f64,
    height: f64,
    parent_width: f64,
    opts: ClampOpts,
) -> (f64, f64) {
    let min_w = opts.min_width.unwrap_or(PLACEHOLDER_MIN_WIDTH);
    let min_h = opts.min_height.unwrap_or(PLACEHOLDER_MIN_HEIGHT);
    let max_w = opts
        .max_width
        .unwrap_or_else(|| min_w.max(if parent_width > 0.0 { parent_width } else { min_w }));
    let w = max_w.min(min_w.max(width.round()));
    let h = min_h.max(height.round());
    (w, h)
}

/// CSS cursor for a placeholder edge resize handle.
pub fn cursor_for_placeholder_edge(edge: char) -> &'static str {
    match edge {
        'n' | 's' => "ns-resize",
        'e' | 'w' => "ew-resize",
        _ => "default",
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlaceholderBox {
    pub width: f64,
    pub height: f64,
    pub margin_left: f64,
    pub margin_top: f64,
}

/// Compute placeholder box after dragging one edge (in-flow margins shift
/// for n/w).
pub fn resize_placeholder_from_edge(
    start: PlaceholderBox,
    edge: char,
    dx: f64,
    dy: f64,
    parent_width: f64,
    opts: ClampOpts,
) -> PlaceholderBox {
    let mut base = start;
    match edge {
        'e' => base.width = start.width + dx,
        'w' => {
            base.width = start.width - dx;
            base.margin_left = start.margin_left + dx;
        }
        's' => base.height = start.height + dy,
        'n' => {
            base.height = start.height - dy;
            base.margin_top = start.margin_top + dy;
        }
        _ => {}
    }

    let (clamped_w, clamped_h) = clamp_placeholder_size(base.width, base.height, parent_width, opts);
    if edge == 'w' {
        base.margin_left = start.margin_left + start.width - clamped_w;
    } else if edge == 'n' {
        base.margin_top = start.margin_top + start.height - clamped_h;
    }

    PlaceholderBox {
        width: clamped_w,
        height: clamped_h,
        margin_left: base.margin_left.round(),
        margin_top: base.margin_top.round(),
    }
}

/// Pick and insert toggles are independent but turning one ON turns the
/// other OFF.
pub fn apply_pick_toggle(pick_active: bool, insert_active: bool) -> (bool, bool) {
    let next_pick = !pick_active;
    (next_pick, if next_pick { false } else { insert_active })
}

pub fn apply_insert_toggle(pick_active: bool, insert_active: bool) -> (bool, bool) {
    let next_insert = !insert_active;
    (if next_insert { false } else { pick_active }, next_insert)
}

/// Whether a variant wrapper is currently shown (handles `hidden` and
/// `display: none`).
pub fn is_variant_shown(hidden: bool, display_none: bool) -> bool {
    !hidden && !display_none
}
