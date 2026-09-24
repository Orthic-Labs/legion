//! Production-entry-point tests for wf_port packet r00
//! (`skills/designer/engine/huashu/scripts/{export_deck_pptx.mjs,
//! export_deck_stage_pdf.mjs, fetch_images.py, gen_deck_thumbs.mjs}`).
//!
//! Exercises the public `run()`/`fetch()` entry points of each module, not
//! just their internal helpers, using fakes for all filesystem/network/
//! browser I/O — per the packet brief, no test here touches the network or
//! launches a real browser.

use legion_runtime::wf_port::r00::export_deck_pptx;
use legion_runtime::wf_port::r00::export_deck_stage_pdf;
use legion_runtime::wf_port::r00::gen_deck_thumbs;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---- export_deck_stage_pdf ----

struct FakeStagePdfFs {
    existing: Vec<PathBuf>,
    writes: RefCell<HashMap<PathBuf, Vec<u8>>>,
}
impl export_deck_stage_pdf::FileSystem for FakeStagePdfFs {
    fn exists(&self, path: &Path) -> bool {
        self.existing.iter().any(|p| p == path)
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.writes
            .borrow_mut()
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }
}

struct FakeStagePdfBrowser;
impl export_deck_stage_pdf::DeckStageBrowser for FakeStagePdfBrowser {
    fn navigate(&mut self, _url: &str, _w: u32, _h: u32) -> Result<(), String> {
        Ok(())
    }
    fn evaluate_flatten(&mut self, _script: &str) -> Result<u32, String> {
        Ok(4)
    }
    fn print_to_pdf(&mut self, _out: &Path, _w: u32, _h: u32) -> Result<Vec<u8>, String> {
        Ok(b"%PDF-1.4".to_vec())
    }
}

#[test]
fn export_deck_stage_pdf_end_to_end_via_run() {
    let html = PathBuf::from("/deck.html");
    let out = PathBuf::from("/deck.pdf");
    let fs = FakeStagePdfFs {
        existing: vec![html.clone()],
        writes: RefCell::new(HashMap::new()),
    };
    let mut browser = FakeStagePdfBrowser;
    let args = export_deck_stage_pdf::Args {
        html,
        out: out.clone(),
        width: 1920,
        height: 1080,
    };
    let outcome = export_deck_stage_pdf::run(&fs, &mut browser, &args).unwrap();
    assert_eq!(outcome.section_count, 4);
    assert_eq!(fs.writes.borrow().get(&out).unwrap(), b"%PDF-1.4");
}

// ---- gen_deck_thumbs ----

struct FakeThumbsFs {
    dirs: Vec<PathBuf>,
    entries: HashMap<PathBuf, Vec<String>>,
    writes: RefCell<HashMap<PathBuf, Vec<u8>>>,
}
impl gen_deck_thumbs::FileSystem for FakeThumbsFs {
    fn dir_exists(&self, path: &Path) -> bool {
        self.dirs.iter().any(|p| p == path)
    }
    fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn read_dir_names(&self, path: &Path) -> std::io::Result<Vec<String>> {
        Ok(self.entries.get(path).cloned().unwrap_or_default())
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.writes
            .borrow_mut()
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }
}

const ONE_PX_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
    0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
    0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8,
    0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D, 0xB0, 0x00, 0x00, 0x00,
    0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

struct FakeThumbsBrowser;
impl gen_deck_thumbs::ThumbBrowser for FakeThumbsBrowser {
    fn screenshot_png(&mut self, _url: &str, _w: u32, _h: u32) -> Result<Vec<u8>, String> {
        Ok(ONE_PX_PNG.to_vec())
    }
}

#[test]
fn gen_deck_thumbs_end_to_end_via_run() {
    let slides = PathBuf::from("/slides");
    let out = PathBuf::from("/thumbs");
    let fs = FakeThumbsFs {
        dirs: vec![slides.clone()],
        entries: HashMap::from([(slides.clone(), vec!["01-cover.html".to_string()])]),
        writes: RefCell::new(HashMap::new()),
    };
    let mut browser = FakeThumbsBrowser;
    let mut args = gen_deck_thumbs::Args::default();
    args.slides = slides;
    args.out = out.clone();
    args.width = 1;
    let outcome = gen_deck_thumbs::run(&fs, &mut browser, &args).unwrap();
    assert_eq!(outcome.ok_count, 1);
    assert!(fs.writes.borrow().contains_key(&out.join("01-cover.jpg")));
}

// ---- export_deck_pptx ----

struct FakePptxFs {
    names: Vec<String>,
}
impl export_deck_pptx::FileSystem for FakePptxFs {
    fn read_dir_names(&self, _path: &Path) -> std::io::Result<Vec<String>> {
        Ok(self.names.clone())
    }
}

struct RecordingConverter;
impl export_deck_pptx::SlideConverter<Vec<String>> for RecordingConverter {
    fn convert(&mut self, slide_path: &Path, pres: &mut Vec<String>) -> Result<(), String> {
        pres.push(slide_path.file_name().unwrap().to_string_lossy().to_string());
        Ok(())
    }
}

#[test]
fn export_deck_pptx_end_to_end_via_run() {
    let fs = FakePptxFs {
        names: vec!["02-b.html".to_string(), "01-a.html".to_string()],
    };
    let mut converter = RecordingConverter;
    let mut pres: Vec<String> = vec![];
    let args = export_deck_pptx::Args {
        slides: PathBuf::from("/slides"),
        out: PathBuf::from("/deck.pptx"),
    };
    let outcome = export_deck_pptx::run(&fs, &mut converter, &mut pres, &args).unwrap();
    assert_eq!(outcome.converted, 2);
    assert_eq!(pres, vec!["01-a.html".to_string(), "02-b.html".to_string()]);
}
