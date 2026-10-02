use std::sync::RwLock;

use serde_json::{json, Value};

use crate::config::{DEEPSEEK_MODELS, QWEN_MODELS};

const CREATED_AT: &str = "2026-01-01T00:00:00Z";

fn display_token(token: &str) -> String {
    match token.to_ascii_lowercase().as_str() {
        "claude" => "Claude".into(),
        "deepseek" => "DeepSeek".into(),
        "glm" => "GLM".into(),
        "gpt" => "GPT".into(),
        "kimi" => "Kimi".into(),
        "minimax" => "MiniMax".into(),
        "mimo" => "MiMo".into(),
        "qwen" => "Qwen".into(),
        _ => {
            let mut chars = token.chars();
            match chars.next() {
                Some(first) if first.is_ascii_alphabetic() => {
                    format!("{}{}", first.to_ascii_uppercase(), chars.as_str())
                }
                _ => token.to_string(),
            }
        }
    }
}

fn humanize_model_id(id: &str) -> Option<String> {
    if id.is_empty()
        || !id.is_ascii()
        || id.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'/'))
        })
    {
        return None;
    }
    let segments: Vec<String> = id
        .split('/')
        .map(|segment| {
            segment
                .split(['-', '_'])
                .filter(|part| !part.is_empty())
                .map(display_token)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    (!segments.iter().any(String::is_empty)).then(|| segments.join(" / "))
}

pub(crate) fn science_safe_display_name(id: &str, candidate: &str) -> String {
    let claude_like = id
        .rsplit('/')
        .next()
        .is_some_and(|segment| segment.to_ascii_lowercase().starts_with("claude-"));
    if claude_like && candidate.eq_ignore_ascii_case(id) {
        if let Some(generated) = humanize_model_id(id) {
            return generated;
        }
    }
    candidate.to_string()
}

/// Process-local relay model discovery cache.
///
/// The cache deliberately has no TTL, persistence, or cross-process sharing. Only a
/// successful, non-empty relay `/v1/models` response may replace the last known IDs;
/// custom OpenAI providers, empty lists, transport errors, and JSON errors leave it
/// untouched. Request transforms clone a short snapshot and never hold this lock while
/// serializing, logging, or performing network I/O.
#[derive(Debug, Default)]
pub struct RelayModelCache {
    models: RwLock<Vec<String>>,
}

impl RelayModelCache {
    pub fn snapshot(&self) -> Vec<String> {
        match self.models.read() {
            Ok(models) => models.clone(),
            // A poisoned writer may have left a partially updated value. Fail safe to
            // passthrough model names for this request instead of panicking or failing
            // the whole gateway.
            Err(_) => Vec::new(),
        }
    }

    pub fn update_from_live_models(&self, provider: &str, ids: &[String]) {
        if provider != "relay" || ids.is_empty() {
            return;
        }
        match self.models.write() {
            Ok(mut models) => *models = ids.to_vec(),
            Err(poisoned) => {
                // A fresh successful discovery is authoritative, so replace the
                // potentially inconsistent value and heal the lock for later requests.
                *poisoned.into_inner() = ids.to_vec();
                self.models.clear_poison();
            }
        }
    }
}

pub fn deepseek_models_response() -> Value {
    static_models_response(DEEPSEEK_MODELS)
}

pub fn qwen_models_response() -> Value {
    static_models_response(QWEN_MODELS)
}

pub fn force_shell_response(model: &str) -> Value {
    json!({
        "data": [{
            "type": "model",
            "id": "claude-opus-4-8",
            "display_name": model,
            "supports_tools": null,
            "created_at": CREATED_AT,
        }],
        "has_more": false,
        "first_id": "claude-opus-4-8",
        "last_id": "claude-opus-4-8",
    })
}

pub fn normalize_live_models_response(raw: &Value) -> Value {
    normalize_live_models(raw).0
}

pub fn normalize_live_models(raw: &Value) -> (Value, Vec<String>) {
    let data = raw
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| raw.as_array().cloned())
        .unwrap_or_default();
    let mut out = Vec::new();
    let mut ids = Vec::new();
    for item in data {
        let Some(id) = item.get("id").and_then(Value::as_str) else {
            continue;
        };
        if id.is_empty() {
            continue;
        }
        ids.push(id.to_string());
        let supports_tools = item
            .get("supported_parameters")
            .and_then(Value::as_array)
            .map(|params| params.iter().any(|param| param.as_str() == Some("tools")))
            .map(Value::Bool)
            .unwrap_or(Value::Null);
        let display_name = science_safe_display_name(
            id,
            item.get("display_name")
                .and_then(Value::as_str)
                .unwrap_or(id),
        );
        out.push(json!({
            "type": "model",
            "id": id,
            "display_name": display_name,
            "supports_tools": supports_tools,
            "created_at": CREATED_AT,
        }));
    }
    let response = json!({
        "data": out,
        "has_more": false,
        "first_id": out.first().and_then(|m| m.get("id")).cloned().unwrap_or(Value::Null),
        "last_id": out.last().and_then(|m| m.get("id")).cloned().unwrap_or(Value::Null),
    });
    (response, ids)
}

fn static_models_response(models: &[(&str, &str)]) -> Value {
    let data: Vec<Value> = models
        .iter()
        .map(|(id, display)| {
            json!({
                "type": "model",
                "id": id,
                "display_name": display,
                "supports_tools": null,
                "created_at": CREATED_AT,
            })
        })
        .collect();
    json!({
        "data": data,
        "has_more": false,
        "first_id": models.first().map(|m| m.0),
        "last_id": models.last().map(|m| m.0),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        deepseek_models_response, force_shell_response, normalize_live_models,
        normalize_live_models_response, qwen_models_response, RelayModelCache,
    };
    use serde_json::json;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn models_body_matches_deepseek_shell_contract() {
        let v = deepseek_models_response();
        assert_eq!(v["data"][0]["id"], "claude-opus-4-8");
        assert_eq!(v["data"][0]["display_name"], "DeepSeek V4 Pro");
        assert_eq!(v["first_id"], "claude-opus-4-8");
        assert_eq!(v["last_id"], "claude-haiku-4-5");
    }

    #[test]
    fn models_body_matches_qwen_static_contract() {
        let v = qwen_models_response();
        assert_eq!(v["data"][0]["id"], "qwen3.7-max");
        assert_eq!(v["data"][0]["display_name"], "Qwen 3.7 Max");
        assert_eq!(v["first_id"], "qwen3.7-max");
        assert_eq!(v["last_id"], "qwen-turbo");
    }

    #[test]
    fn force_shell_response_matches_python_contract() {
        let v = force_shell_response("glm-4.5");
        assert_eq!(v["data"][0]["id"], "claude-opus-4-8");
        assert_eq!(v["data"][0]["display_name"], "glm-4.5");
        assert_eq!(v["first_id"], "claude-opus-4-8");
        assert_eq!(v["last_id"], "claude-opus-4-8");
    }

    #[test]
    fn live_models_response_normalizes_supported_parameters() {
        let v = normalize_live_models_response(&json!({"data": [
            {"id": "glm-4.5", "supported_parameters": ["tools", "temperature"]},
            {"id": "glm-lite", "supported_parameters": ["temperature"]},
            {"id": "glm-x"},
            {"no_id": true}
        ]}));
        assert_eq!(v["data"][0]["id"], "glm-4.5");
        assert_eq!(v["data"][0]["supports_tools"], true);
        assert_eq!(v["data"][1]["supports_tools"], false);
        assert!(v["data"][2]["supports_tools"].is_null());
        assert_eq!(v["first_id"], "glm-4.5");
        assert_eq!(v["last_id"], "glm-x");
    }

    #[test]
    fn normalize_live_models_returns_only_valid_ids_in_order() {
        let (response, ids) = normalize_live_models(&json!({"data": [
            {"id": "first", "display_name": "First"},
            {"id": ""},
            {"missing": "id"},
            {"id": "last"}
        ]}));
        assert_eq!(ids, vec!["first", "last"]);
        assert_eq!(response["first_id"], "first");
        assert_eq!(response["last_id"], "last");
    }

    #[test]
    fn normalize_live_models_humanizes_machine_displays_without_changing_ids() {
        let response = normalize_live_models_response(&json!({"data": [
            {"id": "kimi-k3"},
            {"id": "qwen-plus-latest", "display_name": "qwen-plus-latest"},
            {"id": "claude-sonnet-5", "display_name": "claude-sonnet-5"},
            {"id": "vendor/model-v2", "display_name": "compact-label"},
            {"id": "vendor-model", "display_name": "Vendor Model Pro"}
        ]}));
        let data = response["data"].as_array().unwrap();
        assert_eq!(data[0]["id"], "kimi-k3");
        assert_eq!(data[0]["display_name"], "kimi-k3");
        assert_eq!(data[1]["id"], "qwen-plus-latest");
        assert_eq!(data[1]["display_name"], "qwen-plus-latest");
        assert_eq!(data[2]["id"], "claude-sonnet-5");
        assert_eq!(data[2]["display_name"], "Claude Sonnet 5");
        assert_eq!(data[3]["id"], "vendor/model-v2");
        assert_eq!(data[3]["display_name"], "compact-label");
        assert_eq!(data[4]["id"], "vendor-model");
        assert_eq!(data[4]["display_name"], "Vendor Model Pro");
    }

    #[test]
    fn relay_cache_only_accepts_successful_nonempty_relay_ids() {
        let cache = RelayModelCache::default();
        let first = vec!["claude-haiku-4-5-20251001".to_string()];
        cache.update_from_live_models("relay", &first);
        assert_eq!(cache.snapshot(), first);

        cache.update_from_live_models("openai-custom", &["other".to_string()]);
        cache.update_from_live_models("openai-responses", &["other".to_string()]);
        cache.update_from_live_models("relay", &[]);
        assert_eq!(cache.snapshot(), first);
    }

    #[test]
    fn relay_cache_is_safe_for_concurrent_snapshots_and_updates() {
        let cache = Arc::new(RelayModelCache::default());
        let mut workers = Vec::new();
        for worker in 0..8 {
            let cache = Arc::clone(&cache);
            workers.push(thread::spawn(move || {
                for iteration in 0..256 {
                    if worker % 2 == 0 {
                        cache.update_from_live_models(
                            "relay",
                            &[format!("model-{worker}-{iteration}")],
                        );
                    } else {
                        let _ = cache.snapshot();
                    }
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(cache.snapshot().len(), 1);
    }

    #[test]
    fn poisoned_cache_fails_safe_then_successful_refresh_heals_it() {
        let cache = Arc::new(RelayModelCache::default());
        cache.update_from_live_models("relay", &["known-good".to_string()]);
        let poison_target = Arc::clone(&cache);
        let _ = thread::spawn(move || {
            let _guard = poison_target.models.write().unwrap();
            panic!("intentional cache poison");
        })
        .join();

        assert!(cache.snapshot().is_empty());
        cache.update_from_live_models("relay", &["fresh-good".to_string()]);
        assert_eq!(cache.snapshot(), vec!["fresh-good"]);
    }
}
