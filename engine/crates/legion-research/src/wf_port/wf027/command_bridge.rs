//! Port of `src/lib/research-core/providers/command_bridge.py`.

use std::env;

use serde_json::{json, Map};

use super::support::{command_json, data_only_envelope, publisher_from_url, seed_id, stable_hit_id, today, WfError};
use super::types::{LocatedPassage, OpenedSource, Provider, SearchHit};

/// Port of `CommandBridgeProvider`.
#[derive(Debug)]
pub struct CommandBridgeProvider {
    pub name: String,
    command: Vec<String>,
}

impl CommandBridgeProvider {
    pub const EXTERNAL_OPS: [&'static str; 3] = ["search", "open", "find"];

    /// Port of `__init__`: reads `env_var`, `shlex.split`s it into a command.
    pub fn new(name: impl Into<String>, env_var: &str) -> Result<Self, WfError> {
        let name = name.into();
        let raw = env::var(env_var).unwrap_or_default();
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(WfError::NotConfigured(format!("{env_var} is not configured")));
        }
        let command = super::support::shell_split(raw);
        Ok(Self { name, command })
    }
}

impl Provider for CommandBridgeProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn search(
        &self,
        query: &str,
        limit: usize,
        seed_chain: &[String],
    ) -> Result<Vec<SearchHit>, WfError> {
        let seed = seed_id(query);
        let mut chain = seed_chain.to_vec();
        chain.push(seed.clone());
        let payload = json!({"op": "search", "query": query, "limit": limit});
        let data = command_json(&self.command, &payload, 90)?;
        let results = data
            .get("results")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut hits = Vec::new();
        for row in results.into_iter().take(limit) {
            let url = row
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| WfError::Provider("provider search row missing url".into()))?
                .to_string();
            let title = row
                .get("title")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| url.clone());
            let publisher = row
                .get("publisher")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| publisher_from_url(&url));
            let snippet = row
                .get("snippet")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let metadata = row
                .get("metadata")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            hits.push(SearchHit {
                id: stable_hit_id(&self.name, &url),
                url,
                title,
                publisher,
                snippet,
                suggested_by: seed.clone(),
                seed_chain: chain.clone(),
                provider: self.name.clone(),
                metadata,
            });
        }
        Ok(hits)
    }

    fn open(&self, url: &str) -> Result<OpenedSource, WfError> {
        let payload = json!({"op": "open", "url": url});
        let data = command_json(&self.command, &payload, 90)?;
        let body = data
            .get("content")
            .and_then(|v| v.as_str())
            .or_else(|| data.get("body").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        if body.is_empty() {
            return Err(WfError::Provider(
                "provider open returned an empty body".into(),
            ));
        }
        let (envelope, digest) = data_only_envelope(&body);
        let title = data
            .get("title")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| url.to_string());
        let publisher = data
            .get("publisher")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| publisher_from_url(url));
        let retrieved_at = data
            .get("retrieved_at")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(today);
        let metadata = data
            .get("metadata")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        Ok(OpenedSource {
            url: url.to_string(),
            title,
            publisher,
            retrieved_at,
            content: envelope,
            content_sha256: digest,
            instruction_policy: "data_only".into(),
            provider: self.name.clone(),
            metadata,
        })
    }

    fn find(&self, opened: &OpenedSource, pattern: &str) -> Result<Option<LocatedPassage>, WfError> {
        let payload = json!({"op": "find", "url": opened.url, "pattern": pattern});
        let data = command_json(&self.command, &payload, 90)?;
        if data.get("found").and_then(|v| v.as_bool()) == Some(false) {
            return Ok(None);
        }
        let text = data
            .get("text")
            .and_then(|v| v.as_str())
            .or_else(|| data.get("quote_or_paraphrase").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        if text.is_empty() {
            return Ok(None);
        }
        let locator = data
            .get("locator")
            .and_then(|v| v.as_str())
            .unwrap_or("provider-locator")
            .to_string();
        let is_paraphrase = data
            .get("is_paraphrase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let metadata: Map<String, serde_json::Value> = data
            .get("metadata")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        Ok(Some(LocatedPassage {
            url: opened.url.clone(),
            locator,
            text,
            is_paraphrase,
            provider: self.name.clone(),
            metadata,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_errors_when_env_var_unset() {
        let var = "WF027_COMMAND_BRIDGE_TEST_UNSET";
        env::remove_var(var);
        let err = CommandBridgeProvider::new("legal-authority", var).unwrap_err();
        assert_eq!(err, WfError::NotConfigured(format!("{var} is not configured")));
    }

    #[test]
    fn new_splits_command_string() {
        let var = "WF027_COMMAND_BRIDGE_TEST_SET";
        env::set_var(var, "python3 '/path with space/bridge.py' --flag");
        let provider = CommandBridgeProvider::new("legal-authority", var).unwrap();
        assert_eq!(provider.name, "legal-authority");
        assert_eq!(
            provider.command,
            vec!["python3", "/path with space/bridge.py", "--flag"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
        );
        env::remove_var(var);
    }

    #[test]
    fn external_ops_matches_python_frozenset() {
        assert_eq!(
            CommandBridgeProvider::EXTERNAL_OPS,
            ["search", "open", "find"]
        );
    }
}
