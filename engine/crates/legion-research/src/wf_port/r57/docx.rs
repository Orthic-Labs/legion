//! Packet r57: minimal WordprocessingML (.docx) writer.
//!
//! Ports the low-level docx helpers of `generate_pack.py` (`new_doc`, `para`,
//! `bordered_table`, page breaks, `doc.save`). Produces a valid, minimal
//! .docx: `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`,
//! `word/styles.xml` with the Normal style set to Times New Roman 12pt,
//! matching `new_doc()`.

use std::io::Write;
use std::path::Path;

use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

/// Paragraph alignment, mirroring `docx.enum.text.WD_ALIGN_PARAGRAPH`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Left,
    Center,
    Right,
    Justify,
}

impl Align {
    fn xml_val(self) -> Option<&'static str> {
        match self {
            Align::Left => None,
            Align::Center => Some("center"),
            Align::Right => Some("right"),
            Align::Justify => Some("both"),
        }
    }
}

/// Mirrors `para(doc, text="", bold=False, italic=False, align=None, size=12, space_after=6)`.
#[derive(Clone, Debug)]
pub struct ParaSpec {
    pub text: String,
    pub bold: bool,
    pub italic: bool,
    pub align: Option<Align>,
    pub size: u32,
    pub space_after: u32,
}

impl Default for ParaSpec {
    fn default() -> Self {
        ParaSpec {
            text: String::new(),
            bold: false,
            italic: false,
            align: None,
            size: 12,
            space_after: 6,
        }
    }
}

/// Builder helper mirroring the `para(...)` call's keyword defaults.
pub fn para(text: impl Into<String>) -> ParaSpec {
    ParaSpec {
        text: text.into(),
        ..ParaSpec::default()
    }
}

impl ParaSpec {
    pub fn bold(mut self, v: bool) -> Self {
        self.bold = v;
        self
    }
    pub fn italic(mut self, v: bool) -> Self {
        self.italic = v;
        self
    }
    pub fn align(mut self, a: Align) -> Self {
        self.align = Some(a);
        self
    }
    pub fn space_after(mut self, pt: u32) -> Self {
        self.space_after = pt;
        self
    }
}

enum Block {
    Para(ParaSpec),
    Table {
        headers: Option<Vec<String>>,
        rows: Vec<Vec<String>>,
    },
    PageBreak,
}

/// Mirrors `new_doc()` plus the accumulation performed by every `build_*`
/// function before `doc.save(path)`.
pub struct Doc {
    blocks: Vec<Block>,
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

impl Doc {
    pub fn new() -> Self {
        Doc { blocks: Vec::new() }
    }

    /// Mirrors `para(doc, ...)`.
    pub fn para(&mut self, spec: ParaSpec) {
        self.blocks.push(Block::Para(spec));
    }

    /// Mirrors `bordered_table(doc, headers, rows)`.
    pub fn table(&mut self, headers: Option<Vec<String>>, rows: Vec<Vec<String>>) {
        self.blocks.push(Block::Table { headers, rows });
    }

    /// Mirrors `doc.add_page_break()`.
    pub fn page_break(&mut self) {
        self.blocks.push(Block::PageBreak);
    }

    fn paragraph_xml(spec: &ParaSpec) -> String {
        let mut ppr = String::new();
        ppr.push_str(&format!(
            "<w:spacing w:after=\"{}\"/>",
            spec.space_after * 20
        ));
        if let Some(val) = spec.align.and_then(Align::xml_val) {
            ppr.push_str(&format!("<w:jc w:val=\"{}\"/>", val));
        }
        let mut run = String::new();
        if !spec.text.is_empty() {
            let mut rpr = String::new();
            if spec.bold {
                rpr.push_str("<w:b/>");
            }
            if spec.italic {
                rpr.push_str("<w:i/>");
            }
            rpr.push_str(&format!("<w:sz w:val=\"{}\"/>", spec.size * 2));
            run = format!(
                "<w:r><w:rPr>{}</w:rPr><w:t xml:space=\"preserve\">{}</w:t></w:r>",
                rpr,
                xml_escape(&spec.text)
            );
        }
        format!("<w:p><w:pPr>{}</w:pPr>{}</w:p>", ppr, run)
    }

    fn page_break_xml() -> String {
        "<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>".to_string()
    }

    fn table_xml(headers: &Option<Vec<String>>, rows: &[Vec<String>]) -> String {
        let ncols = headers
            .as_ref()
            .map(|h| h.len())
            .unwrap_or_else(|| rows.first().map(|r| r.len()).unwrap_or(0));
        let mut xml = String::new();
        xml.push_str("<w:tbl><w:tblPr><w:tblStyle w:val=\"TableGrid\"/><w:tblW w:w=\"0\" w:type=\"auto\"/><w:tblBorders>");
        for edge in ["top", "left", "bottom", "right", "insideH", "insideV"] {
            xml.push_str(&format!(
                "<w:{} w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"auto\"/>",
                edge
            ));
        }
        xml.push_str("</w:tblBorders></w:tblPr><w:tblGrid>");
        for _ in 0..ncols.max(1) {
            xml.push_str("<w:gridCol/>");
        }
        xml.push_str("</w:tblGrid>");

        let cell = |text: &str, bold: bool, center: bool| -> String {
            let mut ppr = String::new();
            if center {
                ppr.push_str("<w:jc w:val=\"center\"/>");
            }
            let mut rpr = String::new();
            if bold {
                rpr.push_str("<w:b/>");
            }
            format!(
                "<w:tc><w:tcPr/><w:p><w:pPr>{}</w:pPr><w:r><w:rPr>{}</w:rPr><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p></w:tc>",
                ppr,
                rpr,
                xml_escape(text)
            )
        };

        if let Some(hdrs) = headers {
            xml.push_str("<w:tr>");
            for h in hdrs {
                xml.push_str(&cell(h, true, true));
            }
            xml.push_str("</w:tr>");
        }
        for row in rows {
            xml.push_str("<w:tr>");
            for val in row {
                xml.push_str(&cell(val, false, false));
            }
            xml.push_str("</w:tr>");
        }
        xml.push_str("</w:tbl>");
        xml
    }

    fn body_xml(&self) -> String {
        let mut body = String::new();
        for block in &self.blocks {
            match block {
                Block::Para(spec) => body.push_str(&Self::paragraph_xml(spec)),
                Block::Table { headers, rows } => body.push_str(&Self::table_xml(headers, rows)),
                Block::PageBreak => body.push_str(&Self::page_break_xml()),
            }
        }
        body.push_str("<w:sectPr/>");
        body
    }

    /// Mirrors `doc.save(path)`. Writes a minimal but valid .docx zip.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        zip.start_file("[Content_Types].xml", options)?;
        zip.write_all(CONTENT_TYPES.as_bytes())?;

        zip.start_file("_rels/.rels", options)?;
        zip.write_all(RELS.as_bytes())?;

        zip.start_file("word/_rels/document.xml.rels", options)?;
        zip.write_all(DOCUMENT_RELS.as_bytes())?;

        zip.start_file("word/styles.xml", options)?;
        zip.write_all(STYLES.as_bytes())?;

        zip.start_file("word/document.xml", options)?;
        let document = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>{}</w:body></w:document>",
            self.body_xml()
        );
        zip.write_all(document.as_bytes())?;

        zip.finish()?;
        Ok(())
    }
}

impl Default for Doc {
    fn default() -> Self {
        Self::new()
    }
}

const CONTENT_TYPES: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
<Default Extension=\"xml\" ContentType=\"application/xml\"/>\
<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
<Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>\
</Types>";

const RELS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
</Relationships>";

const DOCUMENT_RELS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>\
</Relationships>";

/// Mirrors `new_doc()`: the Normal style is Times New Roman, 12pt.
const STYLES: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
<w:docDefaults/>\
<w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\">\
<w:name w:val=\"Normal\"/>\
<w:rPr><w:rFonts w:ascii=\"Times New Roman\" w:hAnsi=\"Times New Roman\" w:cs=\"Times New Roman\"/><w:sz w:val=\"24\"/></w:rPr>\
</w:style>\
<w:style w:type=\"table\" w:styleId=\"TableGrid\">\
<w:name w:val=\"Table Grid\"/>\
</w:style>\
</w:styles>";
