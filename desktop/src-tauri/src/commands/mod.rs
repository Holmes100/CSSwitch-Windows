use serde::Serialize;

pub(crate) mod diagnostics;
pub(crate) mod profiles;
pub(crate) mod runtime;
pub(crate) mod skill_install;
pub(crate) mod skill_listing;

/// 通用可序列化命令错误：原位于 codex 命令模块，Codex 功能移除后仅保留
/// 文本消息形态，供 runtime/profiles 等非 Codex 命令继续作为返回类型使用。
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RuntimeCommandError {
    Message(String),
}

impl From<String> for RuntimeCommandError {
    fn from(error: String) -> Self {
        Self::Message(error)
    }
}

impl From<&str> for RuntimeCommandError {
    fn from(error: &str) -> Self {
        Self::Message(error.to_string())
    }
}

impl std::fmt::Display for RuntimeCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => formatter.write_str(message),
        }
    }
}
