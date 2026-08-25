#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
mod error;
mod protocol;

use error::HookError;
use protocol::{HookRequest, HookResponse};

/// Translate a versioned host frame into an explicit fidelity result. This
/// binary deliberately does not inspect tool names, classify effects, load
/// policy, or synthesize a decision: those are Legion-core responsibilities.
pub fn dispatch(request: HookRequest) -> HookResponse {
    let event_type = request.event_type.clone();
    if let Err(error) = request.validate() {
        return response_for_error(event_type, error);
    }
    HookResponse::unsupported(request.event_type)
}

fn response_for_error(event_type: String, error: HookError) -> HookResponse {
    let health = match error {
        HookError::InvalidRequest(_)
        | HookError::MalformedInput(_)
        | HookError::UnsupportedVersion(_) => "strong",
        HookError::Io(_) | HookError::Serialization(_) => "unsupported",
    };
    HookResponse::denied(event_type, error.code(), error.public_message(), health)
}

fn read_request() -> Result<Vec<u8>, HookError> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| HookError::Io(error.to_string()))?;
    if input.iter().all(u8::is_ascii_whitespace) {
        return Err(HookError::invalid("request is empty"));
    }
    Ok(input)
}

fn write_response(response: HookResponse) -> Result<(), HookError> {
    let bytes = serde_json::to_vec(&response.to_value())
        .map_err(|error| HookError::Serialization(error.to_string()))?;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    stdout
        .write_all(&bytes)
        .map_err(|error| HookError::Io(error.to_string()))?;
    stdout
        .write_all(b"\n")
        .map_err(|error| HookError::Io(error.to_string()))?;
    stdout
        .flush()
        .map_err(|error| HookError::Io(error.to_string()))
}

fn error_response(error: HookError) -> HookResponse {
    response_for_error("unknown".into(), error)
}

fn main() {
    let response = match read_request() {
        Ok(input) => match HookRequest::parse(&input) {
            Ok(request) => dispatch(request),
            Err(error) => error_response(error),
        },
        Err(error) => error_response(error),
    };
    let _ = write_response(response);
}
