//! Native App Store Connect build upload operation.
//!
//! Apple first reserves a build upload and its file, then returns presigned
//! upload operations.  Only URLs returned by that authenticated response are
//! used for asset transfer; ASC credentials never cross into asset hosts.

use reqwest::{Client, Method, Url};
use serde_json::{json, Map, Value};
use md5::Md5;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_UPLOAD_OPERATIONS: usize = 2_000;
const MAX_OPERATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPLOAD_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_STRING_BYTES: usize = 4 * 1024;

pub async fn invoke(arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "upload arguments must be a JSON object".to_string())?;
    let artifact = artifact_path(object)?;
    let file = inspect_artifact(&artifact)?;
    let app_id = required_string(object, &["appId", "app_id", "app"])?;
    let version = required_string(object, &["version", "cfBundleShortVersionString"])?;
    let build_number = required_string(object, &["buildNumber", "build_number", "cfBundleVersion"])?;
    let platform = platform(object, &artifact)?;
    let execute = object.get("execute").and_then(Value::as_bool).unwrap_or(false);
    let effect = effect_classification(execute);
    if !execute {
        return Ok(json!({
            "ok": true,
            "dryRun": true,
            "executeRequired": true,
            "operation": "build-upload",
            "artifact": {"fileName": file.name, "fileSize": file.size, "platform": platform},
            "reservation": {"method": "POST", "path": "/v1/buildUploads", "appId": app_id, "version": version, "buildNumber": build_number},
            "fileReservation": {"method": "POST", "path": "/v1/buildUploadFiles"},
            "effects": effect.clone(),
            "effectClassification": effect.clone(),
            "processingState": Value::Null,
            "published": false
        }));
    }

    let reservation = api_json(
        "POST",
        "/v1/buildUploads",
        json!({"data":{"type":"buildUploads","attributes":{"cfBundleShortVersionString":version,"cfBundleVersion":build_number,"platform":platform},"relationships":{"app":{"data":{"type":"apps","id":app_id}}}}}),
    )
    .await?;
    let upload_id = data_id(&reservation)?;
    let file_reservation = api_json(
        "POST",
        "/v1/buildUploadFiles",
        json!({"data":{"type":"buildUploadFiles","attributes":{"fileName":file.name,"fileSize":file.size,"uti":file.uti},"relationships":{"buildUpload":{"data":{"type":"buildUploads","id":upload_id}}}}}),
    )
    .await?;
    let file_id = data_id(&file_reservation)?;
    let attributes = resource_data(&file_reservation)
        .and_then(|data| data.get("attributes"))
        .ok_or_else(|| "App Store Connect upload file response omitted attributes".to_string())?;
    let expected_size = attributes.get("fileSize").and_then(Value::as_u64).unwrap_or(file.size);
    if expected_size != file.size {
        return Err(format!("App Store Connect reserved file size {expected_size} differs from local file size {}", file.size));
    }
    let operations = parse_operations(attributes.get("uploadOperations"))?;
    let mut source = open_artifact(&artifact, file.size)?;
    upload_operations(&mut source, &operations, file.size).await?;
    let checksums = attributes.get("sourceFileChecksums").cloned();
    let computed = if let Some(expected) = checksums.as_ref() {
        Some(verify_checksums(&mut source, expected, file.size)?)
    } else {
        None
    };
    let commit_attributes = match computed {
        Some(checksums) => json!({"uploaded": true, "sourceFileChecksums": checksums}),
        None => json!({"uploaded": true}),
    };
    let committed = api_json(
        "PATCH",
        &format!("/v1/buildUploadFiles/{file_id}"),
        json!({"data":{"type":"buildUploadFiles","id":file_id,"attributes":commit_attributes}}),
    )
    .await?;
    Ok(json!({
        "ok": true,
        "dryRun": false,
        "operation": "build-upload",
        "uploadId": upload_id,
        "fileId": file_id,
        "artifact": {"fileName": file.name, "fileSize": file.size, "platform": platform},
        "uploaded": true,
        "processingState": processing_state(&committed),
        "reservation": reservation,
        "fileReservation": file_reservation,
        "commit": committed,
        "effects": effect.clone(),
        "effectClassification": effect.clone(),
        "published": false
    }))
}

#[derive(Debug, Clone)]
struct Artifact {
    name: String,
    size: u64,
    uti: &'static str,
}

fn artifact_path(object: &Map<String, Value>) -> Result<String, String> {
    for key in ["artifact", "filePath", "file_path", "ipa", "pkg", "path"] {
        if let Some(value) = object.get(key).and_then(Value::as_str) {
            if value.trim().is_empty() || value.len() > 4 * 1024 {
                return Err("artifact path is empty or exceeds path limit".to_string());
            }
            return Ok(value.to_string());
        }
    }
    Err("artifact path is required (IPA or PKG)".to_string())
}

fn inspect_artifact(path: &str) -> Result<Artifact, String> {
    let path_ref = Path::new(path);
    let link_metadata = fs::symlink_metadata(path_ref).map_err(|_| "could not inspect upload artifact".to_string())?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err("upload artifact must be a regular non-symlink file".to_string());
    }
    let size = link_metadata.len();
    if size == 0 || size > MAX_ARTIFACT_BYTES {
        return Err(format!("upload artifact size must be between 1 and {MAX_ARTIFACT_BYTES} bytes"));
    }
    let name = path_ref
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "upload artifact filename is invalid".to_string())?;
    let extension = path_ref.extension().and_then(|value| value.to_str()).unwrap_or("").to_ascii_lowercase();
    let uti = match extension.as_str() {
        "ipa" => "com.apple.itunes.ipa",
        "pkg" => "com.apple.installer-package",
        _ => return Err("upload artifact must end in .ipa or .pkg".to_string()),
    };
    if name.len() > MAX_STRING_BYTES {
        return Err("upload artifact filename exceeds limit".to_string());
    }
    Ok(Artifact {name: name.to_string(), size, uti})
}

fn open_artifact(path: &str, expected_size: u64) -> Result<File, String> {
    let file = OpenOptions::new().read(true).open(path).map_err(|_| "could not open upload artifact".to_string())?;
    let link_metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect upload artifact".to_string())?;
    if link_metadata.file_type().is_symlink() {
        return Err("upload artifact became a symlink before upload".to_string());
    }
    let metadata = file.metadata().map_err(|_| "could not stat upload artifact".to_string())?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err("upload artifact changed size before upload".to_string());
    }
    Ok(file)
}

fn required_string(object: &Map<String, Value>, keys: &[&str]) -> Result<String, String> {
    for key in keys {
        if let Some(value) = object.get(*key).and_then(Value::as_str) {
            let value = value.trim();
            if !value.is_empty() && value.len() <= MAX_STRING_BYTES && safe_id(value) {
                return Ok(value.to_string());
            }
        }
    }
    Err(format!("required upload field is missing or invalid: {}", keys[0]))
}

fn safe_id(value: &str) -> bool {
    !value.chars().any(|character| character.is_control() || matches!(character, '/' | '\\' | '?' | '#'))
}

fn platform(object: &Map<String, Value>, path: &str) -> Result<&'static str, String> {
    if let Some(value) = object.get("platform").and_then(Value::as_str) {
        return match value.to_ascii_uppercase().as_str() {
            "IOS" => Ok("IOS"),
            "MAC_OS" | "MACOS" => Ok("MAC_OS"),
            "TV_OS" | "TVOS" => Ok("TV_OS"),
            "VISION_OS" | "VISIONOS" => Ok("VISION_OS"),
            _ => Err("platform must be IOS, MAC_OS, TV_OS, or VISION_OS".to_string()),
        };
    }
    if path.to_ascii_lowercase().ends_with(".pkg") { Ok("MAC_OS") } else { Ok("IOS") }
}

#[derive(Debug, Clone)]
struct UploadOperation {
    method: Method,
    url: Url,
    offset: u64,
    length: u64,
    headers: Vec<(String, String)>,
}

fn parse_operations(value: Option<&Value>) -> Result<Vec<UploadOperation>, String> {
    let values = value.and_then(Value::as_array).ok_or_else(|| "App Store Connect returned no upload operations".to_string())?;
    if values.is_empty() || values.len() > MAX_UPLOAD_OPERATIONS {
        return Err("App Store Connect upload operation count is outside limit".to_string());
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let object = value.as_object().ok_or_else(|| "upload operation must be an object".to_string())?;
        let method = match object.get("method").and_then(Value::as_str).unwrap_or("PUT").to_ascii_uppercase().as_str() {
            "PUT" => Method::PUT,
            "POST" => Method::POST,
            _ => return Err("upload operation method must be PUT or POST".to_string()),
        };
        let raw_url = object.get("url").and_then(Value::as_str).ok_or_else(|| "upload operation URL is missing".to_string())?;
        let url = Url::parse(raw_url).map_err(|_| "Apple upload operation URL is invalid".to_string())?;
        if url.scheme() != "https" || url.username() != "" || url.password().is_some() || url.fragment().is_some() {
            return Err("Apple upload operation URL must be HTTPS without credentials or fragments".to_string());
        }
        let offset = object.get("offset").and_then(Value::as_u64).ok_or_else(|| "upload operation offset is missing".to_string())?;
        let length = object.get("length").and_then(Value::as_u64).ok_or_else(|| "upload operation length is missing".to_string())?;
        if length == 0 || length > MAX_OPERATION_BYTES as u64 {
            return Err("upload operation length exceeds bound".to_string());
        }
        let mut headers = Vec::new();
        if let Some(values) = object.get("requestHeaders").and_then(Value::as_array) {
            for value in values {
                let value = value.as_object().ok_or_else(|| "upload request header must be an object".to_string())?;
                let name = value.get("name").and_then(Value::as_str).unwrap_or("").trim();
                let header_value = value.get("value").and_then(Value::as_str).unwrap_or("");
                if name.is_empty()
                    || name.len() > MAX_STRING_BYTES
                    || header_value.len() > MAX_STRING_BYTES
                    || ["authorization", "host", "content-length"].iter().any(|blocked| name.eq_ignore_ascii_case(blocked))
                {
                    return Err("upload request header is invalid".to_string());
                }
                headers.push((name.to_string(), header_value.to_string()));
            }
        }
        result.push(UploadOperation {method, url, offset, length, headers});
    }
    Ok(result)
}

fn validate_operations(operations: &[UploadOperation], size: u64) -> Result<(), String> {
    let mut ranges = operations.iter().map(|operation| (operation.offset, operation.length)).collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|range| range.0);
    let mut expected = 0u64;
    for (offset, length) in ranges {
        if offset != expected || offset.checked_add(length).is_none() {
            return Err("Apple upload operations do not form an exact contiguous file plan".to_string());
        }
        expected += length;
    }
    if expected != size { return Err("Apple upload operations do not cover exact artifact size".to_string()); }
    Ok(())
}

async fn upload_operations(file: &mut File, operations: &[UploadOperation], size: u64) -> Result<(), String> {
    validate_operations(operations, size)?;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(900))
        .build()
        .map_err(|_| "could not construct presigned upload client".to_string())?;
    for operation in operations {
        file.seek(SeekFrom::Start(operation.offset)).map_err(|_| "could not seek upload artifact".to_string())?;
        let mut body = vec![0u8; operation.length as usize];
        file.read_exact(&mut body).map_err(|_| "could not read upload artifact chunk".to_string())?;
        let mut request = client.request(operation.method.clone(), operation.url.clone()).body(body);
        for (name, value) in &operation.headers { request = request.header(name, value); }
        let response = request.send().await.map_err(|_| "presigned upload request failed".to_string())?;
        let status = response.status();
        consume_upload_response(response).await?;
        if !status.is_success() { return Err(format!("presigned upload returned HTTP {status}")); }
    }
    Ok(())
}

async fn consume_upload_response(mut response: reqwest::Response) -> Result<(), String> {
    if response.content_length().is_some_and(|length| length > MAX_UPLOAD_RESPONSE_BYTES as u64) {
        return Err("presigned upload response exceeds bound".to_string());
    }
    let mut length = 0usize;
    while let Some(chunk) = response.chunk().await.map_err(|_| "could not read presigned upload response".to_string())? {
        length = length.saturating_add(chunk.len());
        if length > MAX_UPLOAD_RESPONSE_BYTES { return Err("presigned upload response exceeds bound".to_string()); }
    }
    Ok(())
}

async fn api_json(method: &str, path: &str, body: Value) -> Result<Value, String> {
    let request = json!({"action":"request","method":method,"path":path,"body":body,"execute":true});
    let result = super::invoke(&request).await?;
    if !result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Err(format!("App Store Connect upload API returned HTTP {}", result.get("status").and_then(Value::as_u64).unwrap_or(0)));
    }
    Ok(result)
}

fn data_id(value: &Value) -> Result<String, String> {
    let id = resource_data(value).and_then(|data| data.get("id")).and_then(Value::as_str).ok_or_else(|| "App Store Connect response omitted resource ID".to_string())?;
    if !safe_id(id) || id.is_empty() { return Err("App Store Connect resource ID is invalid".to_string()); }
    Ok(id.to_string())
}

fn resource_data(value: &Value) -> Option<&Value> {
    value
        .get("data")
        .and_then(|payload| payload.get("data"))
        .or_else(|| value.get("data"))
}

fn verify_checksums(file: &mut File, expected: &Value, size: u64) -> Result<Value, String> {
    let mut result = Map::new();
    for key in ["file", "composite"] {
        let Some(checksum) = expected.get(key).and_then(Value::as_object) else { continue };
        let algorithm = checksum.get("algorithm").and_then(Value::as_str).unwrap_or("").to_ascii_uppercase();
        let expected_hash = checksum.get("hash").and_then(Value::as_str).unwrap_or("");
        if expected_hash.is_empty() { return Err("App Store Connect checksum hash is missing".to_string()); }
        file.seek(SeekFrom::Start(0)).map_err(|_| "could not seek artifact for checksum".to_string())?;
        let actual = match algorithm.as_str() {
            "SHA256" => {
                let mut hasher = Sha256::new();
                read_hash_input(file, size, |chunk| hasher.update(chunk))?;
                hex::encode(hasher.finalize())
            }
            "MD5" => {
                let mut hasher = Md5::new();
                read_hash_input(file, size, |chunk| hasher.update(chunk))?;
                hex::encode(hasher.finalize())
            }
            _ => return Err(format!("unsupported App Store Connect checksum algorithm: {algorithm}")),
        };
        if !actual.eq_ignore_ascii_case(expected_hash) { return Err(format!("{key} checksum mismatch")); }
        result.insert(key.to_string(), json!({"hash": actual, "algorithm": algorithm}));
    }
    Ok(Value::Object(result))
}

fn read_hash_input(file: &mut File, size: u64, mut update: impl FnMut(&[u8])) -> Result<(), String> {
    let mut remaining = size;
    let mut buffer = [0u8; 1024 * 1024];
    while remaining > 0 {
        let read = file.read(&mut buffer).map_err(|_| "could not read artifact for checksum".to_string())?;
        if read == 0 { return Err("artifact ended before checksum size".to_string()); }
        update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(())
}

fn processing_state(value: &Value) -> Value {
    value
        .get("processingState")
        .cloned()
        .or_else(|| resource_data(value).and_then(|data| data.pointer("/attributes/state/state")).cloned())
        .unwrap_or(Value::Null)
}

fn effect_classification(execute: bool) -> Value {
    json!({
        "classifications": if execute { json!(["NetworkEgress", "CredentialAccess", "ExternalSideEffect"]) } else { json!([]) },
        "publish": false,
        "executeExplicit": execute
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dry_run_effects_do_not_upload() {
        assert_eq!(effect_classification(false)["publish"], false);
        assert!(parse_operations(Some(&json!([]))).is_err());
    }

    #[test]
    fn operation_ranges_must_cover_exact_file() {
        let url = Url::parse("https://uploads.example.invalid/chunk").unwrap();
        let operation = UploadOperation {method: Method::PUT, url, offset: 0, length: 2, headers: Vec::new()};
        assert!(validate_operations(&[operation], 3).is_err());
    }
}
