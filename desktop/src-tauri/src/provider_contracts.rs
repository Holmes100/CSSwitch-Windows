use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const STATIC_PROVIDER_CONTRACTS_JSON: &str =
    include_str!("../../../catalog/provider-contracts.v1.json");

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CredentialSource {
    #[default]
    ApiKey,
    #[serde(alias = "keychain_oauth")]
    CsswitchOauth,
    None,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ModelPolicy {
    #[default]
    SavedCatalog,
    DynamicCatalog,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthMode {
    ApiKey,
    #[serde(alias = "keychain_oauth")]
    CsswitchOauth,
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthScheme {
    AnthropicXApiKey,
    AnthropicDual,
    Bearer,
    CsswitchOauth,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ModelDiscovery {
    BuiltinStatic,
    AnthropicModelsOrManual,
    OpenaiModelsOrManual,
    CodexAccountCatalog,
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Transport {
    AnthropicMessages,
    OpenaiChat,
    OpenaiResponses,
    CodexResponsesSse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EndpointPolicy {
    GatewayManagedOfficial,
    ProfileRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EndpointJoin {
    ManagedOfficial,
    AnthropicV1,
    OpenaiV1,
    OpenaiPath,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScratchPolicy {
    UpstreamProbe,
    GatewayOwnedAuth,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TimeoutPolicy {
    pub(crate) connect_ms: u64,
    pub(crate) total_ms: u64,
    pub(crate) read_idle_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachePolicy {
    pub(crate) normal_ttl_seconds: u64,
    pub(crate) stale_ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderContract {
    pub(crate) id: String,
    pub(crate) template_ids: Vec<String>,
    pub(crate) api_formats: Vec<String>,
    pub(crate) adapter: String,
    pub(crate) auth_mode: AuthMode,
    pub(crate) auth_scheme: AuthScheme,
    pub(crate) credential_sources: Vec<CredentialSource>,
    pub(crate) default_credential_source: CredentialSource,
    pub(crate) model_policies: Vec<ModelPolicy>,
    pub(crate) default_model_policy: ModelPolicy,
    pub(crate) model_discovery: ModelDiscovery,
    pub(crate) transport: Transport,
    pub(crate) endpoint_policy: EndpointPolicy,
    pub(crate) endpoint_join: EndpointJoin,
    pub(crate) api_key_env: Option<String>,
    pub(crate) scratch_policy: ScratchPolicy,
    pub(crate) thinking_policy: String,
    #[serde(default)]
    pub(crate) upstream_client_version: Option<String>,
    pub(crate) timeouts: TimeoutPolicy,
    pub(crate) cache: CachePolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderContractCatalog {
    pub(crate) schema_version: u32,
    pub(crate) contracts: Vec<ProviderContract>,
}

pub(crate) fn static_catalog_digest() -> String {
    format!(
        "{:x}",
        Sha256::digest(STATIC_PROVIDER_CONTRACTS_JSON.as_bytes())
    )
}

pub(crate) fn load_provider_contracts() -> Result<ProviderContractCatalog, String> {
    let mut catalog: ProviderContractCatalog = serde_json::from_str(STATIC_PROVIDER_CONTRACTS_JSON)
        .map_err(|error| format!("provider contract catalog JSON 解析失败：{error}"))?;
    // Codex 功能已移除：静态 catalog JSON（位于 crate 外，gateway 等仍消费）保留原样，
    // 但 codex adapter 的 contract 不再参与桌面端运行时匹配/校验。
    catalog.contracts.retain(|contract| contract.adapter != "codex");
    validate_provider_contracts(&catalog)?;
    Ok(catalog)
}

pub(crate) fn validate_provider_contracts(catalog: &ProviderContractCatalog) -> Result<(), String> {
    if catalog.schema_version != 1 {
        return Err(format!(
            "不支持的 provider contract schema_version：{}",
            catalog.schema_version
        ));
    }
    let mut ids = BTreeSet::new();
    let mut match_keys = BTreeSet::new();
    let allowed_adapters = [
        "deepseek",
        "qwen",
        "relay",
        "openai-custom",
        "openai-responses",
    ];
    let allowed_formats = ["anthropic", "openai_chat", "openai_responses"];
    if catalog.contracts.is_empty() {
        return Err("provider contract catalog 不能为空".into());
    }
    for contract in &catalog.contracts {
        if contract.id.trim().is_empty() || !ids.insert(contract.id.clone()) {
            return Err(format!("provider contract id 为空或重复：{}", contract.id));
        }
        if contract.template_ids.is_empty()
            || contract.api_formats.is_empty()
            || contract.adapter.trim().is_empty()
        {
            return Err(format!(
                "provider contract 匹配或 adapter 为空：{}",
                contract.id
            ));
        }
        if contract
            .template_ids
            .iter()
            .any(|value| value.trim().is_empty())
            || contract
                .api_formats
                .iter()
                .any(|value| value.trim().is_empty())
        {
            return Err(format!(
                "provider contract template_id/api_format 不得为空：{}",
                contract.id
            ));
        }
        if !allowed_adapters.contains(&contract.adapter.as_str())
            || contract
                .api_formats
                .iter()
                .any(|format| !allowed_formats.contains(&format.as_str()))
        {
            return Err(format!(
                "provider contract adapter/api_format 不在运行时允许列表：{}",
                contract.id
            ));
        }
        if !contract
            .credential_sources
            .contains(&contract.default_credential_source)
            || !contract
                .model_policies
                .contains(&contract.default_model_policy)
        {
            return Err(format!(
                "provider contract 默认策略不在允许集合：{}",
                contract.id
            ));
        }
        if contract
            .credential_sources
            .iter()
            .enumerate()
            .any(|(index, source)| contract.credential_sources[index + 1..].contains(source))
            || contract
                .model_policies
                .iter()
                .enumerate()
                .any(|(index, policy)| contract.model_policies[index + 1..].contains(policy))
        {
            return Err(format!(
                "provider contract credential/model policy 存在重复项：{}",
                contract.id
            ));
        }
        match contract.auth_mode {
            AuthMode::ApiKey if contract.api_key_env.as_deref().unwrap_or("").is_empty() => {
                return Err(format!(
                    "API-key contract 缺少 api_key_env：{}",
                    contract.id
                ));
            }
            AuthMode::CsswitchOauth | AuthMode::None if contract.api_key_env.is_some() => {
                return Err(format!(
                    "非 API-key contract 不得声明 api_key_env：{}",
                    contract.id
                ));
            }
            _ => {}
        }
        let expected_source = match contract.auth_mode {
            AuthMode::ApiKey => CredentialSource::ApiKey,
            AuthMode::CsswitchOauth => CredentialSource::CsswitchOauth,
            AuthMode::None => CredentialSource::None,
        };
        if contract.default_credential_source != expected_source
            || contract
                .credential_sources
                .iter()
                .any(|source| *source != expected_source)
        {
            return Err(format!(
                "provider contract auth_mode 与 credential_sources 不一致：{}",
                contract.id
            ));
        }
        if contract.timeouts.connect_ms == 0
            || contract.timeouts.total_ms < contract.timeouts.connect_ms
            || contract.timeouts.read_idle_ms == 0
        {
            return Err(format!("provider contract 超时策略非法：{}", contract.id));
        }
        if contract.cache.stale_ttl_seconds < contract.cache.normal_ttl_seconds {
            return Err(format!(
                "provider contract stale cache TTL 小于 normal TTL：{}",
                contract.id
            ));
        }
        if !matches!(
            contract.thinking_policy.as_str(),
            "" | "adaptive" | "enabled"
        ) {
            return Err(format!(
                "provider contract thinking_policy 非法：{}",
                contract.id
            ));
        }
        let has_codex_characteristic = contract.adapter == "codex"
            || contract.auth_mode == AuthMode::CsswitchOauth
            || contract
                .credential_sources
                .contains(&CredentialSource::CsswitchOauth)
            || contract.default_credential_source == CredentialSource::CsswitchOauth
            || contract.model_discovery == ModelDiscovery::CodexAccountCatalog
            || contract.transport == Transport::CodexResponsesSse
            || contract.scratch_policy == ScratchPolicy::GatewayOwnedAuth
            || contract
                .model_policies
                .contains(&ModelPolicy::DynamicCatalog)
            || contract.default_model_policy == ModelPolicy::DynamicCatalog;
        if has_codex_characteristic {
            return Err(format!(
                "OAuth/动态目录 contract 已随 Codex 功能移除，不再被允许：{}",
                contract.id
            ));
        }
        let expected_transport = match contract.adapter.as_str() {
            "deepseek" | "relay" => Transport::AnthropicMessages,
            "qwen" | "openai-custom" => Transport::OpenaiChat,
            "openai-responses" => Transport::OpenaiResponses,
            _ => {
                return Err(format!("contract adapter 非法：{}", contract.id));
            }
        };
        let expected_endpoint = match contract.adapter.as_str() {
            "deepseek" | "qwen" => EndpointPolicy::GatewayManagedOfficial,
            _ => EndpointPolicy::ProfileRequired,
        };
        let expected_join = match contract.id.as_str() {
            "gemini-openai-chat" => EndpointJoin::OpenaiPath,
            _ => match contract.adapter.as_str() {
                "deepseek" | "qwen" => EndpointJoin::ManagedOfficial,
                "relay" => EndpointJoin::AnthropicV1,
                "openai-custom" | "openai-responses" => EndpointJoin::OpenaiV1,
                _ => {
                    return Err(format!("contract adapter 非法：{}", contract.id));
                }
            },
        };
        let expected_auth_scheme = match contract.id.as_str() {
            "opencode-go-anthropic" => AuthScheme::Bearer,
            _ => match contract.adapter.as_str() {
                "deepseek" => AuthScheme::AnthropicXApiKey,
                "relay" => AuthScheme::AnthropicDual,
                "qwen" | "openai-custom" | "openai-responses" => AuthScheme::Bearer,
                _ => {
                    return Err(format!("contract adapter 非法：{}", contract.id));
                }
            },
        };
        if contract.auth_mode != AuthMode::ApiKey
            || contract.auth_scheme != expected_auth_scheme
            || contract.scratch_policy != ScratchPolicy::UpstreamProbe
            || contract.transport != expected_transport
            || contract.endpoint_policy != expected_endpoint
            || contract.endpoint_join != expected_join
            || contract.cache.normal_ttl_seconds != 0
            || contract.cache.stale_ttl_seconds != 0
            || contract.upstream_client_version.is_some()
        {
            return Err(format!(
                "API provider contract 的 auth/transport/endpoint/cache 组合非法：{}",
                contract.id
            ));
        }

        let expected = match contract.id.as_str() {
                "deepseek-native" => (
                    &["deepseek"][..],
                    &["anthropic"][..],
                    "deepseek",
                    "DEEPSEEK_API_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::BuiltinStatic,
                    Transport::AnthropicMessages,
                    EndpointPolicy::GatewayManagedOfficial,
                    EndpointJoin::ManagedOfficial,
                    AuthScheme::AnthropicXApiKey,
                    "",
                ),
                "qwen-native" => (
                    &["qwen"][..],
                    &["openai_chat"][..],
                    "qwen",
                    "DASHSCOPE_API_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::BuiltinStatic,
                    Transport::OpenaiChat,
                    EndpointPolicy::GatewayManagedOfficial,
                    EndpointJoin::ManagedOfficial,
                    AuthScheme::Bearer,
                    "",
                ),
                "anthropic-relay" => (
                    &["glm", "xiaomi", "siliconflow", "minimax", "openrouter"][..],
                    &["anthropic"][..],
                    "relay",
                    "CSSWITCH_RELAY_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::AnthropicModelsOrManual,
                    Transport::AnthropicMessages,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::AnthropicV1,
                    AuthScheme::AnthropicDual,
                    "adaptive",
                ),
                "kimi-anthropic-relay" => (
                    &["kimi"][..],
                    &["anthropic"][..],
                    "relay",
                    "CSSWITCH_RELAY_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::AnthropicModelsOrManual,
                    Transport::AnthropicMessages,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::AnthropicV1,
                    AuthScheme::AnthropicDual,
                    "enabled",
                ),
                "custom-anthropic" => (
                    &["custom"][..],
                    &["anthropic"][..],
                    "relay",
                    "CSSWITCH_RELAY_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::AnthropicModelsOrManual,
                    Transport::AnthropicMessages,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::AnthropicV1,
                    AuthScheme::AnthropicDual,
                    "adaptive",
                ),
                "custom-openai-chat" => (
                    &["custom-openai", "custom"][..],
                    &["openai_chat"][..],
                    "openai-custom",
                    "CSSWITCH_OPENAI_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::OpenaiModelsOrManual,
                    Transport::OpenaiChat,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::OpenaiV1,
                    AuthScheme::Bearer,
                    "",
                ),
                "custom-openai-responses" => (
                    &["custom-openai-responses", "custom"][..],
                    &["openai_responses"][..],
                    "openai-responses",
                    "CSSWITCH_OPENAI_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::OpenaiModelsOrManual,
                    Transport::OpenaiResponses,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::OpenaiV1,
                    AuthScheme::Bearer,
                    "",
                ),
                "opencode-go-openai-chat" => (
                    &["opencode-go-openai"][..],
                    &["openai_chat"][..],
                    "openai-custom",
                    "CSSWITCH_OPENAI_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::OpenaiModelsOrManual,
                    Transport::OpenaiChat,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::OpenaiV1,
                    AuthScheme::Bearer,
                    "",
                ),
                "opencode-go-anthropic" => (
                    &["opencode-go-anthropic"][..],
                    &["anthropic"][..],
                    "relay",
                    "CSSWITCH_RELAY_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::AnthropicModelsOrManual,
                    Transport::AnthropicMessages,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::AnthropicV1,
                    AuthScheme::Bearer,
                    "",
                ),
                "grok-openai-chat" => (
                    &["grok"][..],
                    &["openai_chat"][..],
                    "openai-custom",
                    "CSSWITCH_OPENAI_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::OpenaiModelsOrManual,
                    Transport::OpenaiChat,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::OpenaiV1,
                    AuthScheme::Bearer,
                    "",
                ),
                "gemini-openai-chat" => (
                    &["gemini"][..],
                    &["openai_chat"][..],
                    "openai-custom",
                    "CSSWITCH_OPENAI_KEY",
                    &[ModelPolicy::SavedCatalog][..],
                    ModelPolicy::SavedCatalog,
                    ModelDiscovery::OpenaiModelsOrManual,
                    Transport::OpenaiChat,
                    EndpointPolicy::ProfileRequired,
                    EndpointJoin::OpenaiPath,
                    AuthScheme::Bearer,
                    "",
                ),
                _ => {
                    return Err(format!("未知 API provider contract id：{}", contract.id));
                }
            };
            let strings_equal = |actual: &[String], expected: &[&str]| {
                actual.len() == expected.len()
                    && actual
                        .iter()
                        .zip(expected.iter())
                        .all(|(actual, expected)| actual == expected)
            };
            if !strings_equal(&contract.template_ids, expected.0)
                || !strings_equal(&contract.api_formats, expected.1)
                || contract.adapter != expected.2
                || contract.api_key_env.as_deref() != Some(expected.3)
                || contract.model_policies != expected.4
                || contract.default_model_policy != expected.5
                || contract.model_discovery != expected.6
                || contract.transport != expected.7
                || contract.endpoint_policy != expected.8
                || contract.endpoint_join != expected.9
                || contract.auth_scheme != expected.10
                || contract.thinking_policy != expected.11
            {
                return Err(format!(
                    "API provider contract 偏离已验证运行时矩阵：{}",
                    contract.id
                ));
            }
        for template_id in &contract.template_ids {
            for api_format in &contract.api_formats {
                if !match_keys.insert((template_id.clone(), api_format.clone())) {
                    return Err(format!(
                        "provider contract 匹配重复：template_id={template_id} api_format={api_format}"
                    ));
                }
            }
        }
    }
    let expected_ids: BTreeSet<String> = [
        "deepseek-native",
        "qwen-native",
        "anthropic-relay",
        "kimi-anthropic-relay",
        "custom-anthropic",
        "custom-openai-chat",
        "custom-openai-responses",
        "opencode-go-openai-chat",
        "opencode-go-anthropic",
        "grok-openai-chat",
        "gemini-openai-chat",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    if ids != expected_ids {
        return Err("provider contract catalog 缺少必需 contract 或含未知 contract".into());
    }
    Ok(())
}

pub(crate) fn contract_for(
    template_id: &str,
    api_format: &str,
) -> Result<ProviderContract, String> {
    let catalog = load_provider_contracts()?;
    let exact = catalog.contracts.into_iter().find(|contract| {
        contract.template_ids.iter().any(|id| id == template_id)
            && contract.api_formats.iter().any(|fmt| fmt == api_format)
    });
    exact.ok_or_else(|| {
        format!("没有匹配的 provider contract：template_id={template_id} api_format={api_format}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_catalog_value() -> serde_json::Value {
        serde_json::from_str(STATIC_PROVIDER_CONTRACTS_JSON).unwrap()
    }

    fn validate_value(value: serde_json::Value) -> Result<(), String> {
        let catalog: ProviderContractCatalog =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        validate_provider_contracts(&catalog)
    }

    #[test]
    fn static_provider_contracts_load_and_are_unambiguous() {
        let catalog = load_provider_contracts().unwrap();
        assert_eq!(catalog.schema_version, 1);
        assert_eq!(catalog.contracts.len(), 11);
        assert_eq!(static_catalog_digest().len(), 64);
        assert!(contract_for("codex", "openai_responses").is_err());
    }

    #[test]
    fn custom_api_format_selects_distinct_runtime_contract() {
        assert_eq!(
            contract_for("custom", "openai_chat").unwrap().adapter,
            "openai-custom"
        );
        assert_eq!(
            contract_for("custom", "openai_responses").unwrap().adapter,
            "openai-responses"
        );
    }

    #[test]
    fn catalog_rejects_unknown_fields_and_empty_contracts() {
        let mut unknown = parsed_catalog_value();
        unknown["contracts"][0]["surprise"] = serde_json::json!(true);
        assert!(validate_value(unknown).is_err());

        let mut empty = parsed_catalog_value();
        empty["contracts"] = serde_json::json!([]);
        assert!(validate_value(empty).is_err());
    }

    #[test]
    fn api_contract_runtime_matrix_rejects_behavior_mutations() {
        for (field, value) in [
            ("api_key_env", serde_json::json!("TYPO_API_KEY")),
            ("auth_scheme", serde_json::json!("bearer")),
            ("model_discovery", serde_json::json!("none")),
            ("api_formats", serde_json::json!(["openai_responses"])),
            ("thinking_policy", serde_json::json!("enabled")),
        ] {
            let mut mutated = parsed_catalog_value();
            mutated["contracts"][0][field] = value;
            assert!(
                validate_value(mutated).is_err(),
                "deepseek mutation {field} must fail closed"
            );
        }
    }

    #[test]
    fn codex_contract_is_filtered_from_the_runtime_catalog() {
        // 静态 JSON（crate 外共享资源）仍含 codex-oauth：加载器必须把它剔除出运行时 catalog，
        // 且校验器对任何携带 Codex 特征的 contract 直接拒绝（所以未过滤的原表无法通过校验）。
        assert!(load_provider_contracts()
            .unwrap()
            .contracts
            .iter()
            .all(|contract| contract.adapter != "codex"));
        assert!(validate_value(parsed_catalog_value()).is_err());
    }

    #[test]
    fn duplicate_policy_entries_are_rejected() {
        let mut mutated = parsed_catalog_value();
        mutated["contracts"][0]["credential_sources"] = serde_json::json!(["api_key", "api_key"]);
        assert!(validate_value(mutated).is_err());

        let mut mutated = parsed_catalog_value();
        mutated["contracts"][0]["model_policies"] =
            serde_json::json!(["optional_fixed", "optional_fixed"]);
        assert!(validate_value(mutated).is_err());
    }

    #[test]
    fn legacy_keychain_oauth_value_reads_but_serializes_as_csswitch_oauth() {
        let source: CredentialSource = serde_json::from_str("\"keychain_oauth\"").unwrap();
        let mode: AuthMode = serde_json::from_str("\"keychain_oauth\"").unwrap();
        assert_eq!(source, CredentialSource::CsswitchOauth);
        assert_eq!(mode, AuthMode::CsswitchOauth);
        assert_eq!(
            serde_json::to_string(&source).unwrap(),
            "\"csswitch_oauth\""
        );
        assert_eq!(serde_json::to_string(&mode).unwrap(), "\"csswitch_oauth\"");
    }
}
