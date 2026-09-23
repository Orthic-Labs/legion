//! Production-entry-point tests for packet Q0's ported legacy scripts
//! (`legion_runtime::wf_port::q_q0`), exercised the way the legacy CLIs
//! were: argv in, `.env` text in, JSON response body in.

use legion_runtime::wf_port::q_q0::fetch_images::{
    api_query_string, output_filename, safe_slug, strip_html_tags, thumb_extension,
};
use legion_runtime::wf_port::q_q0::tts_doubao::{
    parse_args, parse_dotenv, parse_tts_response, TtsRequest, TtsResponseError,
};

#[test]
fn tts_doubao_cli_roundtrip_success() {
    let argv = [
        "--text",
        "你好世界",
        "--out",
        "/workspace/out/demo.mp3",
        "--speed",
        "1.2",
        "--voice",
        "voice-42",
    ];
    let args = parse_args(argv);
    assert_eq!(args.text.as_deref(), Some("你好世界"));
    assert_eq!(args.out.as_deref(), Some("/workspace/out/demo.mp3"));
    assert_eq!(args.speed, "1.2");
    assert_eq!(args.voice.as_deref(), Some("voice-42"));
    assert_eq!(args.encoding, "mp3");

    let dotenv = "DOUBAO_TTS_API_KEY=key-abc\nDOUBAO_TTS_VOICE_ID=default-voice\n";
    let env = parse_dotenv(dotenv);
    assert_eq!(
        env,
        vec![
            ("DOUBAO_TTS_API_KEY".to_string(), "key-abc".to_string()),
            ("DOUBAO_TTS_VOICE_ID".to_string(), "default-voice".to_string()),
        ]
    );

    let req = TtsRequest {
        cluster: "volcano_icl".to_string(),
        voice_id: args.voice.unwrap(),
        encoding: args.encoding,
        speed: args.speed.parse().unwrap(),
        reqid: "fixed-req-id".to_string(),
        text: args.text.unwrap(),
    };
    let body = req.build_body();
    assert_eq!(body["audio"]["voice_type"], "voice-42");
    assert_eq!(body["audio"]["speed_ratio"], 1.2);

    let response = r#"{"code":3000,"message":"ok","data":"aGVsbG8="}"#;
    let audio_b64 = parse_tts_response(response).unwrap();
    assert_eq!(audio_b64, "aGVsbG8=");
}

#[test]
fn tts_doubao_cli_reports_api_error() {
    let response = r#"{"code":4001,"message":"invalid voice_type"}"#;
    let err = parse_tts_response(response).unwrap_err();
    assert_eq!(
        err,
        TtsResponseError::ApiError {
            code: 4001,
            message: "invalid voice_type".to_string()
        }
    );
}

#[test]
fn fetch_images_cli_derives_filenames_and_query() {
    // Mirrors: python3 scripts/fetch_images.py --query "Petronas Towers"
    //   --out /workspace/assets/img --count 2 --width 1600
    let qs = api_query_string("Petronas Towers", 2, 1600);
    assert!(qs.contains("gsrsearch=Petronas+Towers"));
    assert!(qs.contains("iiurlwidth=1600"));

    let title = "File:Petronas Towers at dusk.jpg";
    let ext = thumb_extension("https://upload.wikimedia.org/commons/thumb/x/Petronas.jpg?w=1600");
    assert_eq!(ext, ".jpg");

    let fname = output_filename("Petronas Towers", title, &ext);
    assert!(fname.ends_with(".jpg"));
    assert!(!fname.contains("File:"));
    assert!(!fname.contains(' '));

    let artist = strip_html_tags(
        r#"<a href="//commons.wikimedia.org/wiki/User:Jane">Jane Doe</a>"#,
    );
    assert_eq!(artist, "Jane Doe");

    assert_eq!(safe_slug("Langkawi beach!"), "Langkawi_beach_");
}
