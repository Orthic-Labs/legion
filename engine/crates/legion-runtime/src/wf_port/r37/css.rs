//! Port of `_build_css`: the A4 report CSS, extracted verbatim (brace-for-brace)
//! from `google_report.py`'s f-string. The only interpolation the Python does
//! is `{domain}` inside the `@bottom-right` page rule; ported as a
//! `.replace("{domain}", domain)` pass over the raw template below rather than
//! `format!`, since the CSS itself is full of literal `{`/`}` braces.

const CSS_TEMPLATE: &str = r###"  @page {
    size: A4;
    margin: 22mm 18mm 25mm 18mm;
    @bottom-center {
      content: "Page " counter(page) " of " counter(pages);
      font-size: 9pt;
      color: #6b7280;
      font-family: 'DejaVu Serif', 'Times New Roman', Georgia, serif;
    }
    @bottom-left {
      content: "Confidential";
      font-size: 7pt;
      color: #d6d3cc;
      font-family: 'DejaVu Serif', 'Times New Roman', Georgia, serif;
    }
    @bottom-right {
      content: "{domain} Google SEO Report";
      font-size: 8pt;
      color: #cbd5e1;
      font-family: 'DejaVu Serif', 'Times New Roman', Georgia, serif;
    }
  }

  @page :first {
    margin: 0;
    @bottom-left { content: none; }
    @bottom-center { content: none; }
    @bottom-right { content: none; }
  }

  @page toc {
    @bottom-center {
      content: counter(page);
      font-size: 9pt;
      color: #6b7280;
    }
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  body {
    font-family: 'Times New Roman', 'DejaVu Serif', Georgia, serif;
    font-size: 10pt;
    line-height: 1.55;
    color: #1e293b;
    background: white;
  }

  /* ─── Title Page (Clean White) ─── */
  .title-page {
    page: first;
    width: 210mm;
    height: 297mm;
    background: #ffffff;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    color: #1a1a2e;
    position: relative;
    padding: 50mm 30mm 40mm 30mm;
    border-top: 6mm solid #1e3a5f;
  }

  .title-page .badge {
    background: #f7f6f3;
    border: 1px solid #d6d3cc;
    border-radius: 20px;
    padding: 6px 18px;
    font-size: 9pt;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 15mm;
    color: #1e3a5f;
  }

  .title-page h1 {
    font-size: 28pt;
    font-weight: bold;
    margin-bottom: 5mm;
    letter-spacing: -0.5px;
    line-height: 1.2;
    color: #1a1a2e;
  }

  .title-page .subtitle {
    font-size: 13pt;
    color: #6b7280;
    margin-bottom: 12mm;
    font-weight: 300;
  }

  .title-page .url {
    font-size: 12pt;
    color: #1e3a5f;
    margin-bottom: 15mm;
    padding: 4mm 8mm;
    border: 1px solid #d6d3cc;
    border-radius: 6px;
    background: #faf9f7;
  }

  .title-page .score-box {
    background: #faf9f7;
    border: 2px solid #d6d3cc;
    border-radius: 12px;
    padding: 6mm 12mm;
    margin-bottom: 15mm;
  }

  .title-page .score-number {
    font-size: 42pt;
    font-weight: bold;
    color: #1e3a5f;
    line-height: 1;
  }

  .title-page .score-label {
    font-size: 10pt;
    color: #6b7280;
    margin-top: 2mm;
  }

  .title-page .meta {
    font-size: 9pt;
    color: #6b7280;
    margin-top: 8mm;
    padding-top: 5mm;
    border-top: 1px solid #d6d3cc;
  }

  .title-page .meta span {
    margin: 0 8px;
  }

  /* ─── Table of Contents ─── */
  .toc-page {
    page: toc;
    page-break-before: always;
  }

  .toc-page h2 {
    font-size: 18pt;
    color: #1e3a5f;
    margin-bottom: 8mm;
    padding-bottom: 3mm;
    border-bottom: 2px solid #1e3a5f;
  }

  .toc-list {
    list-style: none;
    padding: 0;
  }

  .toc-list li {
    padding: 2mm 0;
    border-bottom: 1px solid #f1f5f9;
    overflow: hidden;
  }

  .toc-list li.toc-section {
    font-weight: bold;
    font-size: 11pt;
    padding-top: 4mm;
    color: #0f172a;
  }

  .toc-list li.toc-sub {
    padding-left: 8mm;
    font-size: 9.5pt;
    color: #475569;
  }

  .toc-score {
    display: inline-block;
    float: right;
    padding: 1px 8px;
    border-radius: 10px;
    font-size: 9pt;
    font-weight: bold;
    color: white;
  }

  .score-good { background: #2d6a4f; }
  .score-warn { background: #d4740e; }
  .score-bad { background: #c53030; }

  /* ─── Section Styles ─── */
  div.section {
    page-break-before: always;
  }

  .section-header {
    background: #faf9f7;
    border-left: 4px solid #1e3a5f;
    padding: 5mm 6mm;
    margin-bottom: 6mm;
    page-break-after: avoid;
  }

  .section-header h2 {
    font-size: 16pt;
    color: #0f172a;
    margin-bottom: 1mm;
  }

  .section-header .section-score {
    font-size: 12pt;
    font-weight: bold;
    float: right;
    margin-top: -6mm;
  }

  h3 {
    font-size: 12pt;
    color: #1e3a5f;
    margin-top: 6mm;
    margin-bottom: 3mm;
    padding-bottom: 1.5mm;
    border-bottom: 1px solid #d6d3cc;
    page-break-after: avoid;
  }

  h4 {
    font-size: 10.5pt;
    color: #334155;
    margin-top: 4mm;
    margin-bottom: 2mm;
    page-break-after: avoid;
  }

  p {
    margin-bottom: 3mm;
    color: #334155;
  }

  .highlight {
    background: #fef3c7;
    border-left: 3px solid #d4740e;
    padding: 3mm 4mm;
    margin: 4mm 0;
    font-size: 9.5pt;
    /* allow page breaks to prevent white gaps */
  }

  .critical-box {
    background: #fef2f2;
    border-left: 3px solid #c53030;
    padding: 3mm 4mm;
    margin: 4mm 0;
    font-size: 9.5pt;
    /* allow page breaks to prevent white gaps */
  }

  .success-box {
    background: #f0fdf4;
    border-left: 3px solid #2d6a4f;
    padding: 3mm 4mm;
    margin: 4mm 0;
    font-size: 9.5pt;
    /* allow page breaks to prevent white gaps */
  }

  /* ─── Tables ─── */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 4mm 0 6mm 0;
    font-size: 9pt;
  }

  thead th {
    background: #f7f6f3;
    color: #0f172a;
    font-weight: bold;
    padding: 3mm 4mm;
    text-align: left;
    border-bottom: 2px solid #d6d3cc;
    font-size: 9pt;
  }

  tbody td {
    padding: 2.5mm 3mm;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: top;
  }

  tbody tr:nth-child(even) {
    background: #fdfcfa;
  }

  .status-pass {
    color: #2d6a4f;
    font-weight: bold;
  }

  .status-fail {
    color: #c53030;
    font-weight: bold;
  }

  .status-warn {
    color: #d4740e;
    font-weight: bold;
  }

  .status-partial {
    color: #4a5568;
    font-weight: bold;
  }

  /* ─── Charts ─── */
  .chart-container {
    text-align: center;
    margin: 4mm 0;
  }

  .chart-container img {
    max-width: 100%;
    max-height: 120mm;
    height: auto;
  }

  .chart-caption {
    font-size: 8.5pt;
    color: #6b7280;
    font-style: italic;
    margin-top: 2mm;
    text-align: center;
  }

  .chart-half {
    display: inline-block;
    width: 48%;
    vertical-align: top;
    text-align: center;
    margin: 2mm 0;
  }

  .chart-half img {
    max-width: 100%;
    height: auto;
  }

  /* ─── Two column layout ─── */
  .two-col {
    display: table;
    width: 100%;
    table-layout: fixed;
    margin: 3mm 0;
  }

  .two-col .col {
    display: table-cell;
    vertical-align: top;
    padding: 0 2mm;
  }

  .four-col {
    display: table;
    width: 100%;
    table-layout: fixed;
    margin: 3mm 0;
  }

  .four-col .col {
    display: table-cell;
    vertical-align: top;
    padding: 0 1.5mm;
  }

  /* ─── Metric Cards ─── */
  .metric-card {
    background: #faf9f7;
    border: 1px solid #d6d3cc;
    border-radius: 6px;
    padding: 2.5mm 3mm;
    text-align: center;
    margin: 2mm 0;
  }

  .metric-card .value {
    font-size: 14pt;
    font-weight: bold;
    line-height: 1.2;
  }

  .metric-card .label {
    font-size: 7.5pt;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 1mm;
  }

  /* ─── Action Plan ─── */
  .action-item {
    background: #faf9f7;
    border-radius: 4px;
    padding: 3mm 4mm;
    margin: 3mm 0;
    border-left: 3px solid #cbd5e1;
    /* allow page breaks to prevent white gaps */
  }

  .action-item.critical {
    border-left-color: #c53030;
    background: #fdf2f2;
  }

  .action-item.high {
    border-left-color: #d4740e;
    background: #fdf8ef;
  }

  .action-item.medium {
    border-left-color: #1e3a5f;
    background: #f0f4f8;
  }

  .action-item.low {
    border-left-color: #94a3b8;
  }

  .action-item h4 {
    margin-top: 0;
    margin-bottom: 1.5mm;
    border-bottom: none;
    padding-bottom: 0;
  }

  .action-item .effort {
    font-size: 8.5pt;
    color: #64748b;
    float: right;
  }

  .priority-tag {
    display: inline-block;
    padding: 0.5mm 3mm;
    border-radius: 3px;
    font-size: 8pt;
    font-weight: bold;
    color: white;
    margin-right: 2mm;
    vertical-align: middle;
  }

  .priority-critical { background: #c53030; }
  .priority-high { background: #d4740e; }
  .priority-medium { background: #1e3a5f; }
  .priority-low { background: #94a3b8; }

  /* ─── Code blocks ─── */
  .code-block {
    background: #1e293b;
    color: #e2e8f0;
    padding: 3mm 4mm;
    border-radius: 4px;
    font-family: 'DejaVu Sans Mono', monospace;
    font-size: 8pt;
    line-height: 1.6;
    margin: 3mm 0;
    white-space: pre-wrap;
    word-break: break-all;
    /* allow page breaks to prevent white gaps */
  }

  /* ─── Divider ─── */
  .divider {
    border: none;
    border-top: 1px solid #d6d3cc;
    margin: 5mm 0;
  }

  /* ─── Roadmap ─── */
  .roadmap-phase {
    background: #faf9f7;
    border-radius: 6px;
    padding: 4mm 5mm;
    margin: 4mm 0;
    border: 1px solid #d6d3cc;
    /* allow page breaks to prevent white gaps */
  }

  .roadmap-phase h4 {
    margin-top: 0;
    border-bottom: none;
    color: #1e3a5f;
  }

  .roadmap-phase ul {
    margin: 2mm 0 0 5mm;
    padding: 0;
  }

  .roadmap-phase li {
    margin-bottom: 1.5mm;
    font-size: 9.5pt;
    color: #334155;
  }

  /* ─── Lists ─── */
  ul {
    margin-left: 5mm;
    margin-bottom: 3mm;
  }

  li {
    margin-bottom: 1.5mm;
  }

  /* ─── Data freshness ─── */
  .data-freshness {
    font-size: 8pt;
    color: #6b7280;
    font-style: italic;
    margin-top: 4mm;
    padding-top: 2mm;
    border-top: 1px solid #d6d3cc;
  }"###;

/// Port of `_build_css(domain: str) -> str`.
pub fn build_css(domain: &str) -> String {
    CSS_TEMPLATE.replace("{domain}", domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolates_domain_into_bottom_right_page_rule() {
        let css = build_css("example.com");
        assert!(css.contains("example.com Google SEO Report"));
        assert!(!css.contains("{domain}"));
    }

    #[test]
    fn keeps_literal_css_braces() {
        let css = build_css("x.com");
        assert!(css.contains("@page {"));
        assert!(css.contains(".title-page {"));
    }
}
