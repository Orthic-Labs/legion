//! Integration test for packet r01: the `html2pptx.js` gaps closed on top
//! of the existing w2_007 port — the `PageDriver` trait (live-DOM layout
//! walk boundary) and the PPTX (OOXML zip) writer that replaces
//! `pptxgenjs`. No network access and no real browser: `FakeDriver`/
//! `FakeImages` stand in for the CDP tab and the filesystem.

use legion_runtime::wf_port::w2_007::html2pptx::{self, ImageSource, PageDriver};
use std::collections::HashMap;
use std::path::Path;

struct FakeDriver {
    body: serde_json::Value,
    slide: serde_json::Value,
    calls: u32,
}

impl PageDriver for FakeDriver {
    fn navigate_file(&mut self, _path: &Path) -> Result<(), String> {
        Ok(())
    }
    fn set_viewport(&mut self, _width: u32, _height: u32) -> Result<(), String> {
        Ok(())
    }
    fn evaluate_json(&mut self, _script: &str) -> Result<serde_json::Value, String> {
        // `run_html2pptx` calls `evaluate_json` exactly twice, in order:
        // body dimensions first, then the DOM-walk extraction.
        self.calls += 1;
        if self.calls == 1 {
            Ok(self.body.clone())
        } else {
            Ok(self.slide.clone())
        }
    }
}

struct FakeImages(HashMap<&'static str, (Vec<u8>, &'static str)>);

impl ImageSource for FakeImages {
    fn read(&mut self, path: &str) -> Result<(Vec<u8>, String), String> {
        self.0
            .get(path)
            .map(|(b, e)| (b.clone(), e.to_string()))
            .ok_or_else(|| format!("no fake image for {path}"))
    }
}

#[test]
fn r01_html2pptx_end_to_end_from_dom_walk_to_pptx_zip() {
    let mut driver = FakeDriver {
        calls: 0,
        body: serde_json::json!({ "width": 1280.0, "height": 720.0, "scrollWidth": 1280.0, "scrollHeight": 720.0 }),
        slide: serde_json::json!({
            "background": { "type": "color", "value": "FFFFFF" },
            "elements": [{
                "type": "p",
                "text": "Packet r01",
                "position": { "x": 1.0, "y": 1.0, "w": 4.0, "h": 0.6 },
                "style": { "fontSize": 24.0, "color": "202020", "align": "left" }
            }],
            "placeholders": [],
            "errors": []
        }),
    };

    let outcome = html2pptx::run_html2pptx(&mut driver, "slide.html", Path::new("/decks"), None, None)
        .expect("no validation errors");
    assert!(outcome.placeholders.is_empty());

    let mut images = FakeImages(HashMap::new());
    let dir = std::env::temp_dir().join(format!("legion-r01-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("r01.pptx");

    html2pptx::write_pptx_from_slide_data(&out, 13.333, 7.5, &outcome.slide_data, &mut images)
        .expect("writes a valid pptx zip");

    let file = std::fs::File::open(&out).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    assert!(zip.by_name("ppt/slides/slide1.xml").is_ok());

    std::fs::remove_dir_all(&dir).ok();
}
