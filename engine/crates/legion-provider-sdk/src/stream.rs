//! Bounded OpenAI-compatible SSE decoding.

use std::{collections::BTreeMap, fmt};

use serde_json::Value;

use crate::inference::{InferenceError, InferenceErrorCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLimits {
    pub max_frame_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 256 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamEvent {
    Started {
        model: Option<String>,
    },
    Delta {
        text: String,
    },
    Completed {
        text: String,
        model: Option<String>,
        finish_reason: Option<String>,
        usage: BTreeMap<String, u64>,
    },
    Failed {
        partial: String,
        diagnostic: String,
    },
    Cancelled {
        partial: String,
    },
}

#[derive(Clone, Debug)]
pub struct SseDecoder {
    limits: StreamLimits,
    frame: Vec<u8>,
    total: usize,
    text: String,
    model: Option<String>,
    finish_reason: Option<String>,
    usage: BTreeMap<String, u64>,
    started: bool,
    terminal: bool,
}

impl SseDecoder {
    pub fn new(limits: StreamLimits) -> Self {
        Self {
            limits,
            frame: Vec::new(),
            total: 0,
            text: String::new(),
            model: None,
            finish_reason: None,
            usage: BTreeMap::new(),
            started: false,
            terminal: false,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<StreamEvent>, InferenceError> {
        if self.terminal {
            return Ok(Vec::new());
        }
        let Some(total) = self.total.checked_add(bytes.len()) else {
            return Ok(vec![self.fail_event("stream byte counter overflow")]);
        };
        self.total = total;
        if self.total > self.limits.max_body_bytes {
            return Ok(vec![self.fail_event("stream body exceeds configured limit")]);
        }
        let mut events = Vec::new();
        for byte in bytes {
            self.frame.push(*byte);
            if self.frame.len() > self.limits.max_frame_bytes {
                return Ok(vec![
                    self.fail_event("stream frame exceeds configured limit")
                ]);
            }
            if self.frame.ends_with(b"\n\n") || self.frame.ends_with(b"\r\n\r\n") {
                let frame = std::mem::take(&mut self.frame);
                match self.event_from_frame(&frame) {
                    Ok(Some(event)) => events.push(event),
                    Ok(None) => {}
                    Err(error) => {
                        events.push(self.fail_event(&error.message));
                        break;
                    }
                }
            }
        }
        Ok(events)
    }

    pub fn finish(&mut self) -> Result<StreamEvent, InferenceError> {
        if self.terminal {
            return Err(self.fail("stream already terminated"));
        }
        if !self.frame.is_empty() {
            return Ok(self.fail_event("stream ended with an incomplete frame"));
        }
        Ok(self.fail_event("stream ended before terminal event"))
    }

    pub fn cancel(&mut self) -> StreamEvent {
        self.terminal = true;
        StreamEvent::Cancelled {
            partial: self.text.clone(),
        }
    }

    /// Convert any decoder-side failure into a terminal event while retaining
    /// accumulated response text for diagnostics.
    pub fn failed(&mut self, diagnostic: impl Into<String>) -> StreamEvent {
        self.fail_event(&diagnostic.into())
    }

    fn event_from_frame(&mut self, frame: &[u8]) -> Result<Option<StreamEvent>, InferenceError> {
        let raw = std::str::from_utf8(frame).map_err(|_| self.fail("stream frame is not UTF-8"))?;
        let data = raw
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            return Ok(None);
        }
        if data == "[DONE]" {
            self.terminal = true;
            return Ok(Some(StreamEvent::Completed {
                text: self.text.clone(),
                model: self.model.clone(),
                finish_reason: self.finish_reason.clone(),
                usage: self.usage.clone(),
            }));
        }
        let value: Value =
            serde_json::from_str(&data).map_err(|_| self.fail("malformed stream JSON"))?;
        if !self.started {
            self.started = true;
            self.model = value
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        let choices = value
            .get("choices")
            .and_then(Value::as_array)
            .ok_or_else(|| self.fail("stream event has no choices"))?;
        let choice = choices
            .first()
            .ok_or_else(|| self.fail("stream event has no choice"))?;
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish_reason = Some(reason.to_owned());
        }
        if let Some(model) = value.get("model").and_then(Value::as_str) {
            self.model = Some(model.to_owned());
        }
        if let Some(usage) = value.get("usage").and_then(Value::as_object) {
            for (key, val) in usage {
                if let Some(number) = val.as_u64() {
                    self.usage.insert(key.clone(), number);
                }
            }
        }
        let text = choice
            .get("delta")
            .and_then(|delta| delta.get("content"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if text.is_empty() {
            return Ok(Some(StreamEvent::Started {
                model: self.model.clone(),
            }));
        }
        self.text.push_str(&text);
        Ok(Some(StreamEvent::Delta { text }))
    }

    fn fail_event(&mut self, diagnostic: &str) -> StreamEvent {
        self.terminal = true;
        StreamEvent::Failed {
            partial: self.text.clone(),
            diagnostic: diagnostic.to_owned(),
        }
    }
    fn fail(&self, message: &str) -> InferenceError {
        InferenceError::new(InferenceErrorCode::MalformedStream, message)
    }
}

impl fmt::Display for StreamLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "frame <= {} bytes, body <= {} bytes",
            self.max_frame_bytes, self.max_body_bytes
        )
    }
}
