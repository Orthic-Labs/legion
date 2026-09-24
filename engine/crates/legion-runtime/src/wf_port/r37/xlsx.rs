//! Port of `google_report.py`'s `generate_xlsx`: an Excel workbook built with
//! `openpyxl` in the Python original. No spreadsheet crate is in this
//! packet's allowed-crate list, so this port writes the `.xlsx` OOXML package
//! directly with the `zip` crate already a dependency of this crate
//! (precedent: `wf_port::w2_007::html2pptx` builds a `.pptx` -- also a zip of
//! XML -- the same way). Same sheets, same columns, same row-truncation
//! (`[:500]`), same header styling intent (navy fill / white bold text),
//! same severity-fill logic, same auto-width formula (`min(max_len + 4, 60)`),
//! same `auto_filter`/`freeze_panes` on the data sheets.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::jget::{arr, get_str, get_str_or, obj};
use super::report::ReportType;

#[derive(Clone)]
enum Cell {
    S(String),
    N(f64),
}

impl Cell {
    fn width_len(&self) -> usize {
        match self {
            Cell::S(s) => s.chars().count(),
            Cell::N(n) => format!("{n}").chars().count(),
        }
    }
}

/// Style id for a data cell, matching `_severity_fill`'s four buckets plus
/// "no fill".
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fill {
    None,
    Green,
    Amber,
    Red,
    Cream,
}

/// Port of `_severity_fill`.
fn severity_fill(severity: &str) -> Fill {
    let s = severity.to_lowercase();
    if matches!(s.as_str(), "critical" | "fail" | "high") {
        Fill::Red
    } else if matches!(s.as_str(), "warning" | "warn" | "medium") {
        Fill::Amber
    } else if matches!(s.as_str(), "pass" | "good" | "low") {
        Fill::Green
    } else {
        Fill::Cream
    }
}

struct Sheet {
    name: String,
    rows: Vec<Vec<Cell>>,
    /// (row 1-based, col 0-based) -> fill override, applied on top of the
    /// header style for row 1 or the plain body style otherwise.
    cell_fill: std::collections::HashMap<(usize, usize), Fill>,
    header_row: Option<usize>, // 1-based row that gets `_style_header`
    auto_filter_cols: Option<usize>,
    freeze_panes: bool,
}

impl Sheet {
    fn new(name: &str) -> Self {
        Sheet {
            name: name.to_string(),
            rows: Vec::new(),
            cell_fill: std::collections::HashMap::new(),
            header_row: None,
            auto_filter_cols: None,
            freeze_panes: false,
        }
    }

    fn append(&mut self, row: Vec<Cell>) -> usize {
        self.rows.push(row);
        self.rows.len()
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Excel column letters for a 0-based column index (`0` -> `A`, `26` -> `AA`).
fn col_letter(mut idx: usize) -> String {
    let mut s = String::new();
    idx += 1;
    while idx > 0 {
        let rem = (idx - 1) % 26;
        s.insert(0, (b'A' + rem as u8) as char);
        idx = (idx - 1) / 26;
    }
    s
}

fn fill_style_id(fill: Fill, header: bool) -> u32 {
    if header {
        return 1;
    }
    match fill {
        Fill::None => 0,
        Fill::Green => 2,
        Fill::Amber => 3,
        Fill::Red => 4,
        Fill::Cream => 5,
    }
}

fn sheet_xml(sheet: &Sheet) -> String {
    let mut cols_by_width: Vec<usize> = Vec::new();
    for row in &sheet.rows {
        for (i, c) in row.iter().enumerate() {
            if cols_by_width.len() <= i {
                cols_by_width.resize(i + 1, 0);
            }
            cols_by_width[i] = cols_by_width[i].max(c.width_len());
        }
    }
    let mut cols_xml = String::new();
    if !cols_by_width.is_empty() {
        cols_xml.push_str("<cols>");
        for (i, max_len) in cols_by_width.iter().enumerate() {
            let width = (*max_len as f64 + 4.0).min(60.0).max(8.0);
            cols_xml.push_str(&format!(
                "<col min=\"{}\" max=\"{}\" width=\"{width}\" customWidth=\"1\"/>",
                i + 1,
                i + 1
            ));
        }
        cols_xml.push_str("</cols>");
    }

    let mut sheet_data = String::from("<sheetData>");
    for (r_i, row) in sheet.rows.iter().enumerate() {
        let r = r_i + 1;
        sheet_data.push_str(&format!("<row r=\"{r}\">"));
        let is_header = sheet.header_row == Some(r);
        for (c_i, cell) in row.iter().enumerate() {
            let cell_ref = format!("{}{r}", col_letter(c_i));
            let fill = sheet.cell_fill.get(&(r, c_i)).copied().unwrap_or(Fill::None);
            let style = fill_style_id(fill, is_header);
            match cell {
                Cell::S(s) => {
                    sheet_data.push_str(&format!(
                        "<c r=\"{cell_ref}\" t=\"inlineStr\" s=\"{style}\"><is><t xml:space=\"preserve\">{}</t></is></c>",
                        xml_escape(s)
                    ));
                }
                Cell::N(n) => {
                    sheet_data.push_str(&format!("<c r=\"{cell_ref}\" s=\"{style}\"><v>{n}</v></c>"));
                }
            }
        }
        sheet_data.push_str("</row>");
    }
    sheet_data.push_str("</sheetData>");

    let sheet_views = if sheet.freeze_panes {
        "<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews>"
    } else {
        "<sheetViews><sheetView workbookViewId=\"0\"/></sheetViews>"
    };

    let auto_filter = match sheet.auto_filter_cols {
        Some(n) if !sheet.rows.is_empty() => format!(
            "<autoFilter ref=\"A1:{}{}\"/>",
            col_letter(n.saturating_sub(1)),
            sheet.rows.len()
        ),
        _ => String::new(),
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">{sheet_views}{cols_xml}{sheet_data}{auto_filter}</worksheet>"
    )
}

const STYLES_XML: &str = r##"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2">
<font><sz val="10"/><name val="Calibri"/></font>
<font><sz val="11"/><name val="Calibri"/><b/><color rgb="FFFFFFFF"/></font>
</fonts>
<fills count="6">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF1E3A5F"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFD4EDDA"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFF3CD"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFF8D7DA"/></patternFill></fill>
</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="6">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="center" vertical="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"/>
<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/>
<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/>
<xf numFmtId="0" fontId="0" fillId="1" borderId="0" xfId="0" applyFill="1"/>
</cellXfs>
</styleSheet>"##;

fn content_types_xml(sheet_count: usize) -> String {
    let mut overrides = String::new();
    for i in 1..=sheet_count {
        overrides.push_str(&format!(
            "<Override PartName=\"/xl/worksheets/sheet{i}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
<Default Extension=\"xml\" ContentType=\"application/xml\"/>\
<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>\
<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>\
{overrides}</Types>"
    )
}

const PACKAGE_RELS_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";

fn workbook_xml(sheets: &[Sheet]) -> String {
    let mut sheets_xml = String::new();
    for (i, s) in sheets.iter().enumerate() {
        sheets_xml.push_str(&format!(
            "<sheet name=\"{}\" sheetId=\"{}\" r:id=\"rId{}\"/>",
            xml_escape(&s.name),
            i + 1,
            i + 1
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets>{sheets_xml}</sheets></workbook>"
    )
}

fn workbook_rels_xml(sheet_count: usize) -> String {
    let mut rels = String::new();
    for i in 1..=sheet_count {
        rels.push_str(&format!(
            "<Relationship Id=\"rId{i}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{i}.xml\"/>"
        ));
    }
    let styles_id = sheet_count + 1;
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">{rels}<Relationship Id=\"rId{styles_id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>"
    )
}

fn ctr_val(v: &Value) -> f64 {
    v.as_f64().unwrap_or(0.0)
}

/// Port of `generate_xlsx`. Returns `None` where the Python returned `None`
/// (there `openpyxl` missing; here `zip` is a hard dependency of this crate,
/// so this port always writes the file when called -- `None` is unreachable
/// in this port and kept only to preserve the signature's shape for callers
/// mirroring the Python `Optional[str]` return).
pub fn generate_xlsx(
    data: &Value,
    domain: &str,
    _report_type: &str,
    output_dir: &Path,
    timestamp: &str,
) -> Option<PathBuf> {
    let report_type = ReportType::parse(_report_type);
    let mut sheets = Vec::new();

    // ── Summary sheet ──────────────────────────────────────────────────────
    let mut summary = Sheet::new("Summary");
    summary.append(vec![Cell::S("Google SEO Report".into()), Cell::S(String::new()), Cell::S(String::new())]);
    summary.append(vec![Cell::S("Domain".into()), Cell::S(domain.into())]);
    summary.append(vec![Cell::S("Report Type".into()), Cell::S(_report_type.into())]);
    summary.append(vec![Cell::S("Generated".into()), Cell::S(timestamp.into())]);
    summary.append(vec![]);

    let wants_cwv = matches!(report_type, Some(ReportType::CwvAudit) | Some(ReportType::Full));
    if wants_cwv {
        let psi = if data.get("psi").is_some() { obj(data, "psi") } else { data };
        let mobile = {
            let inner = obj(psi, "psi");
            inner.get("mobile").cloned().unwrap_or_else(|| psi.clone())
        };
        let scores = obj(&mobile, "lighthouse_scores");
        if let Some(scores_obj) = scores.as_object() {
            if !scores_obj.is_empty() {
                summary.append(vec![Cell::S("Lighthouse Scores".into()), Cell::S(String::new())]);
                let header_row = summary.append(vec![Cell::S("Category".into()), Cell::S("Score".into())]);
                summary.header_row = Some(header_row);
                for cat in ["performance", "accessibility", "best_practices", "seo"] {
                    // Python looks up `scores.get(cat)`, where cat uses
                    // underscores but the JSON key is hyphenated for
                    // "best_practices"/"best-practices" -- ported verbatim,
                    // including this same-shaped miss the Python has (the
                    // source never remaps "best_practices" to
                    // "best-practices" either, so this lookup returns None
                    // there too; kept identical rather than "fixed").
                    if let Some(val) = scores.get(cat).and_then(|v| v.as_f64()) {
                        let display = if val <= 1.0 { (val * 100.0).round() } else { val };
                        let row = summary.append(vec![
                            Cell::S(cat.replace('_', " ").split(' ').map(title_word).collect::<Vec<_>>().join(" ")),
                            Cell::N(display),
                        ]);
                        let sev = if display >= 90.0 { "pass" } else if display >= 50.0 { "warning" } else { "fail" };
                        summary.cell_fill.insert((row, 1), severity_fill(sev));
                    }
                }
                summary.append(vec![]);
            }
        }

        let crux = obj(data, "crux");
        let metrics = obj(crux, "metrics");
        if let Some(m_obj) = metrics.as_object() {
            if !m_obj.is_empty() {
                summary.append(vec![Cell::S("Core Web Vitals (Field Data)".into()), Cell::S(String::new())]);
                summary.append(vec![Cell::S("Metric".into()), Cell::S("Value".into()), Cell::S("Rating".into())]);
                for (name, md) in m_obj {
                    if md.is_object() {
                        let p75 = md
                            .get("percentile_p75")
                            .or_else(|| md.get("p75"))
                            .map(|v| Cell::S(get_display(v)))
                            .unwrap_or_else(|| Cell::S(String::new()));
                        let rating = get_str_or(md, "category", "");
                        summary.append(vec![Cell::S(name.clone()), p75, Cell::S(rating)]);
                    }
                }
                summary.append(vec![]);
            }
        }
    }
    sheets.push(summary);

    // ── Queries sheet ──────────────────────────────────────────────────────
    let gsc = obj(data, "gsc");
    let queries = {
        let q = arr(gsc, "queries");
        if !q.is_empty() { q } else { arr(gsc, "rows") }
    };
    if !queries.is_empty() {
        let mut ws = Sheet::new("Queries");
        let header_row = ws.append(vec![
            Cell::S("Query".into()),
            Cell::S("Clicks".into()),
            Cell::S("Impressions".into()),
            Cell::S("CTR".into()),
            Cell::S("Position".into()),
        ]);
        ws.header_row = Some(header_row);
        for row_data in queries.iter().take(500) {
            if !row_data.is_object() {
                continue;
            }
            let keys = arr(row_data, "keys");
            let query = if !keys.is_empty() {
                keys[0].as_str().unwrap_or("").to_string()
            } else {
                get_str(row_data, "query")
            };
            let ctr = row_data.get("ctr");
            let ctr_cell = match ctr.and_then(|v| v.as_f64()) {
                Some(f) => Cell::S(format!("{:.2}%", f * 100.0)),
                None => Cell::S(ctr.map(get_display).unwrap_or_default()),
            };
            let position = row_data.get("position");
            let pos_cell = match position.and_then(|v| v.as_f64()) {
                Some(f) => Cell::N((f * 10.0).round() / 10.0),
                None => Cell::S(position.map(get_display).unwrap_or_default()),
            };
            ws.append(vec![
                Cell::S(query),
                Cell::N(ctr_val(row_data.get("clicks").unwrap_or(&Value::Null))),
                Cell::N(ctr_val(row_data.get("impressions").unwrap_or(&Value::Null))),
                ctr_cell,
                pos_cell,
            ]);
        }
        ws.auto_filter_cols = Some(5);
        ws.freeze_panes = true;
        sheets.push(ws);
    }

    // ── Pages sheet ───────────────────────────────────────────────────────
    let pages = arr(gsc, "pages");
    if !pages.is_empty() {
        let mut ws = Sheet::new("Pages");
        let header_row = ws.append(vec![
            Cell::S("Page".into()),
            Cell::S("Clicks".into()),
            Cell::S("Impressions".into()),
            Cell::S("CTR".into()),
            Cell::S("Position".into()),
        ]);
        ws.header_row = Some(header_row);
        for row_data in pages.iter().take(500) {
            if !row_data.is_object() {
                continue;
            }
            let keys = arr(row_data, "keys");
            let page = if !keys.is_empty() {
                keys[0].as_str().unwrap_or("").to_string()
            } else {
                get_str(row_data, "page")
            };
            let ctr = row_data.get("ctr");
            let ctr_cell = match ctr.and_then(|v| v.as_f64()) {
                Some(f) => Cell::S(format!("{:.2}%", f * 100.0)),
                None => Cell::S(ctr.map(get_display).unwrap_or_default()),
            };
            let position = row_data.get("position");
            let pos_cell = match position.and_then(|v| v.as_f64()) {
                Some(f) => Cell::N((f * 10.0).round() / 10.0),
                None => Cell::S(position.map(get_display).unwrap_or_default()),
            };
            ws.append(vec![
                Cell::S(page),
                Cell::N(ctr_val(row_data.get("clicks").unwrap_or(&Value::Null))),
                Cell::N(ctr_val(row_data.get("impressions").unwrap_or(&Value::Null))),
                ctr_cell,
                pos_cell,
            ]);
        }
        ws.auto_filter_cols = Some(5);
        ws.freeze_panes = true;
        sheets.push(ws);
    }

    // ── Indexation sheet ─────────────────────────────────────────────────
    let inspection = obj(data, "inspection");
    let results = arr(inspection, "results");
    if !results.is_empty() {
        let mut ws = Sheet::new("Indexation");
        let header_row = ws.append(vec![
            Cell::S("URL".into()),
            Cell::S("Verdict".into()),
            Cell::S("Coverage State".into()),
            Cell::S("Indexing State".into()),
            Cell::S("Crawled As".into()),
            Cell::S("Last Crawl".into()),
        ]);
        ws.header_row = Some(header_row);
        for item in results.iter().take(500) {
            if !item.is_object() {
                continue;
            }
            let result_data = if item.get("inspectionResult").is_some() {
                obj(item, "inspectionResult")
            } else {
                item
            };
            let idx = obj(result_data, "indexStatusResult");
            let url = item
                .get("url")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| get_str(result_data, "inspectedUrl"));
            ws.append(vec![
                Cell::S(url),
                Cell::S(get_str(idx, "verdict")),
                Cell::S(get_str(idx, "coverageState")),
                Cell::S(get_str(idx, "indexingState")),
                Cell::S(get_str(idx, "crawledAs")),
                Cell::S(get_str(idx, "lastCrawlTime")),
            ]);
        }
        ws.auto_filter_cols = Some(6);
        ws.freeze_panes = true;
        sheets.push(ws);
    }

    // Python's filename uses its own `datetime.now()` timestamp
    // (`%Y%m%d-%H%M`), distinct from the report's `timestamp`/`timestamp_short`
    // -- ported by having the caller pass the same clock-derived string in
    // both places rather than reading the clock a second time here.
    let filename = format!("Google-SEO-Report-{domain}-{}.xlsx", timestamp.replace([' ', ':'], "-"));
    let filepath = output_dir.join(filename);
    write_xlsx(&sheets, &filepath).ok()?;
    Some(filepath)
}

fn get_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn title_word(w: &str) -> String {
    let mut c = w.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn write_xlsx(sheets: &[Sheet], out_path: &Path) -> Result<(), String> {
    let file = std::fs::File::create(out_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut write_part = |zip: &mut zip::ZipWriter<std::fs::File>, name: &str, content: &[u8]| -> Result<(), String> {
        zip.start_file(name, options).map_err(|e| e.to_string())?;
        zip.write_all(content).map_err(|e| e.to_string())
    };

    write_part(&mut zip, "[Content_Types].xml", content_types_xml(sheets.len()).as_bytes())?;
    write_part(&mut zip, "_rels/.rels", PACKAGE_RELS_XML.as_bytes())?;
    write_part(&mut zip, "xl/workbook.xml", workbook_xml(sheets).as_bytes())?;
    write_part(&mut zip, "xl/_rels/workbook.xml.rels", workbook_rels_xml(sheets.len()).as_bytes())?;
    write_part(&mut zip, "xl/styles.xml", STYLES_XML.as_bytes())?;
    for (i, s) in sheets.iter().enumerate() {
        write_part(&mut zip, &format!("xl/worksheets/sheet{}.xml", i + 1), sheet_xml(s).as_bytes())?;
    }
    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn col_letter_wraps_past_z() {
        assert_eq!(col_letter(0), "A");
        assert_eq!(col_letter(25), "Z");
        assert_eq!(col_letter(26), "AA");
    }

    #[test]
    fn severity_fill_buckets() {
        assert!(matches!(severity_fill("Critical"), Fill::Red));
        assert!(matches!(severity_fill("warn"), Fill::Amber));
        assert!(matches!(severity_fill("pass"), Fill::Green));
        assert!(matches!(severity_fill("other"), Fill::Cream));
    }

    #[test]
    fn generate_xlsx_writes_a_readable_zip() {
        let dir = std::env::temp_dir().join(format!(
            "r37_xlsx_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let data = json!({
            "psi": {"lighthouse_scores": {"performance": 88, "seo": 100}},
            "gsc": {"rows": [{"query": "widgets", "clicks": 3, "impressions": 40, "ctr": 0.075, "position": 4.2}]},
            "inspection": {"results": [{"url": "https://x.com/", "inspectionResult": {"indexStatusResult": {"verdict": "PASS"}}}]}
        });
        let path = generate_xlsx(&data, "example.com", "full", &dir, "2026-01-01 12:00").unwrap();
        assert!(path.exists());
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.contains(&"xl/worksheets/sheet1.xml".to_string()));
        assert!(names.iter().any(|n| n == "xl/worksheets/sheet2.xml"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
