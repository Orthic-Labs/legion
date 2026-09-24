//! Integration test for packet r32 (`skills/seo/extensions/banana/scripts/edit.py`),
//! exercising the port through the crate's public `wf_port::r32` module.
//! Detailed unit tests live alongside the source in `src/wf_port/r32/edit.rs`;
//! this file checks the public API surface is reachable and wired together.

use legion_runtime::wf_port::r32::edit::{
    decode_base64, encode_base64, parse_args, DEFAULT_MODEL,
};

#[test]
fn public_api_is_reachable() {
    let args = parse_args(&[
        "--image".into(),
        "photo.png".into(),
        "--prompt".into(),
        "remove background".into(),
    ])
    .unwrap();
    assert_eq!(args.image, "photo.png");
    assert_eq!(args.model, DEFAULT_MODEL);

    let round_tripped = decode_base64(&encode_base64(b"hello world")).unwrap();
    assert_eq!(round_tripped, b"hello world");
}
