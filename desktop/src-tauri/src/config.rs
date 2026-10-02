//! 本地配置读写：正式构建使用 `~/.csswitch/config.json`，Acceptance 构建使用
//! `~/.csswitch-acceptance/config.json`。多 profile + 多模型目录形态（schema v4）。
//!
//! 安全要求（对齐 spec §3 / §5.1，参考 CC Switch 的明文本地存储但加严文件安全）：
//!   - 目录 0700，文件 0600。
//!   - 读/写前 `lstat`（symlink_metadata）拒绝符号链接，绝不跟随写到别处或读到别处。
//!   - 写用「临时文件（O_CREAT|O_EXCL, 0600）+ 原子 rename」，避免半写与竞态。
//!   - profile key 明文存盘（用户已知悉），但**绝不进日志**；回显给前端只给掩码（末 4 位）。
//!
//! 存储升级：schema_version 探测 + v1（旧固定槽）→ canonical v2 → v3 → v4，
//! 迁移留不可覆盖的版本备份，普通覆盖前留滚动 `config.json.bak`，
//! 清 key / 删 profile 后净化滚动备份（旧明文 key 不可从 .bak 恢复）。
//!
//! 所有函数以显式 `dir` 参数工作，便于用临时目录做无副作用的单元测试；
//! 生产代码用 [`default_dir`]；目录名由编译期构建变体固定，不能由运行时输入改写。

use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::model_catalog::{ModelRoute, RoleBindings};
use crate::provider_contracts::{CredentialSource, ModelPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 进程内配置访问互斥锁：序列化所有 config 读/写。
/// （原 v2 降级终态机制已随 Codex 功能移除一并删除。）
static CONFIG_ACCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) const PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE: &str =
    "pending-authority-cleanup.v1.json";

#[cfg(test)]
#[allow(dead_code)] // 仅 unix 门控测试会触发观察记录；Windows 测试构建下保持编译
#[derive(Clone, Debug)]
pub(crate) struct AtomicWritePreRenameObservation {
    pub(crate) temp_path: PathBuf,
    pub(crate) target_path: PathBuf,
    pub(crate) temp_device: u64,
    pub(crate) temp_inode: u64,
    pub(crate) config_access_held: bool,
}

#[cfg(test)]
#[allow(dead_code)] // 仅 unix 门控测试会武装 failpoint；Windows 测试构建下保持编译
struct AtomicWritePreRenameFailpoint {
    id: u64,
    directory_device: u64,
    directory_inode: u64,
    observation: std::sync::Arc<std::sync::Mutex<Option<AtomicWritePreRenameObservation>>>,
}

#[cfg(test)]
static ATOMIC_WRITE_PRE_RENAME_FAILPOINT: std::sync::LazyLock<
    std::sync::Mutex<Option<AtomicWritePreRenameFailpoint>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
#[allow(dead_code)] // 仅 unix 门控测试会分配 failpoint id；Windows 测试构建下保持编译
static ATOMIC_WRITE_PRE_RENAME_FAILPOINT_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

#[cfg(test)]
#[allow(dead_code)] // 仅 unix 门控测试会构造 guard；Windows 测试构建下保持编译
pub(crate) struct AtomicWritePreRenameFailpointGuard {
    id: u64,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingCleanupIdentity {
    pub(crate) managed_id: String,
    pub(crate) path: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) marker: String,
}

#[cfg(test)]
#[allow(dead_code)] // 仅 unix 测试会触发；Windows 测试构建下保持编译
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupLifecycleEvent {
    Register(PendingCleanupIdentity),
    Remove {
        identity: PendingCleanupIdentity,
        not_found: bool,
    },
    Clear,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupPublishFault {
    Register,
    Clear,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // 仅 unix 测试会触发；Windows 测试构建下保持编译
pub(crate) enum PendingCleanupInitialTicket {
    Present(PendingCleanupIdentity),
    Missing(PendingCleanupIdentity),
}

#[cfg(test)]
impl PendingCleanupInitialTicket {
    fn identity(&self) -> &PendingCleanupIdentity {
        match self {
            Self::Present(identity) | Self::Missing(identity) => identity,
        }
    }
}

#[cfg(test)]
#[allow(dead_code)] // 仅 unix 测试会触发；Windows 测试构建下保持编译
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupRemovalOutcome {
    Removed,
    AlreadyAbsent,
    Error,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // 仅 unix 测试会触发；Windows 测试构建下保持编译
pub(crate) enum PendingCleanupFinalState {
    NotFound,
    Present(PendingCleanupIdentity),
    Error,
}

#[cfg(test)]
#[allow(dead_code)] // 仅 unix 测试会触发；Windows 测试构建下保持编译
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupRaceAction {
    Recreate { path: PathBuf, marker: String },
    Delete { path: PathBuf },
}

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PendingCleanupLifecycleObservation {
    pub(crate) events: Vec<PendingCleanupLifecycleEvent>,
    pub(crate) attempted_register: Option<PendingCleanupIdentity>,
    pub(crate) validated_loader_count: usize,
    pub(crate) initial_ticket_count: usize,
    pub(crate) race_hook_count: usize,
    pub(crate) delete_attempt_count: usize,
    pub(crate) completion_count: usize,
    pub(crate) causal_mismatch_count: usize,
    pub(crate) race_identity: Option<PendingCleanupIdentity>,
}

#[cfg(test)]
#[derive(Default)]
#[allow(dead_code)]
struct PendingCleanupLifecycleSeam {
    registered_identity: Option<PendingCleanupIdentity>,
    initial_ticket: Option<PendingCleanupInitialTicket>,
    race_action: Option<PendingCleanupRaceAction>,
    observation: PendingCleanupLifecycleObservation,
    publish_fault: Option<PendingCleanupPublishFault>,
}

#[cfg(test)]
static PENDING_CLEANUP_LIFECYCLE_SEAM: std::sync::LazyLock<
    std::sync::Mutex<Option<PendingCleanupLifecycleSeam>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
pub(crate) struct PendingCleanupLifecycleGuard;

#[cfg(test)]
impl Drop for PendingCleanupLifecycleGuard {
    fn drop(&mut self) {
        *PENDING_CLEANUP_LIFECYCLE_SEAM
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) fn test_arm_pending_cleanup_lifecycle(
    publish_fault: Option<PendingCleanupPublishFault>,
) -> PendingCleanupLifecycleGuard {
    *PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(PendingCleanupLifecycleSeam {
        publish_fault,
        ..Default::default()
    });
    PendingCleanupLifecycleGuard
}

#[cfg(test)]
pub(crate) fn test_pending_cleanup_lifecycle_observation() -> PendingCleanupLifecycleObservation {
    let seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    seam.as_ref()
        .map(|seam| seam.observation.clone())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_pending_cleanup_register_publish_attempt(
    identity: PendingCleanupIdentity,
) -> io::Result<()> {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(seam) = seam.as_mut() else {
        return Ok(());
    };
    seam.observation.attempted_register = Some(identity);
    if seam.publish_fault == Some(PendingCleanupPublishFault::Register) {
        return Err(io::Error::other(
            "test-only pending cleanup REGISTER publish failure",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_pending_cleanup_clear_publish_attempt() -> io::Result<()> {
    let seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if seam
        .as_ref()
        .is_some_and(|seam| seam.publish_fault == Some(PendingCleanupPublishFault::Clear))
    {
        return Err(io::Error::other(
            "test-only pending cleanup CLEAR publish failure",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_observe_pending_cleanup_register_published(identity: PendingCleanupIdentity) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.registered_identity = Some(identity.clone());
        seam.observation
            .events
            .push(PendingCleanupLifecycleEvent::Register(identity));
    }
}

#[cfg(test)]
pub(crate) fn test_observe_pending_cleanup_manifest_validated(identity: PendingCleanupIdentity) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.registered_identity = Some(identity.clone());
        seam.observation.validated_loader_count += 1;
        seam.observation
            .events
            .push(PendingCleanupLifecycleEvent::Register(identity));
    }
}

#[cfg(test)]
pub(crate) fn test_observe_pending_cleanup_initial_ticket(ticket: PendingCleanupInitialTicket) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(seam) = seam.as_mut() else {
        return;
    };
    seam.observation.initial_ticket_count += 1;
    if seam.registered_identity.as_ref() != Some(ticket.identity()) {
        seam.observation.causal_mismatch_count += 1;
        return;
    }
    seam.initial_ticket = Some(ticket);
}

#[cfg(all(test, unix))]
pub(crate) fn test_configure_pending_cleanup_race(action: PendingCleanupRaceAction) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.race_action = Some(action);
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_pending_cleanup_race_hook() -> io::Result<()> {
    let action = {
        let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(seam) = seam.as_mut() else {
            return Ok(());
        };
        seam.observation.race_hook_count += 1;
        seam.race_action.clone()
    };
    let race_identity = match action {
        Some(PendingCleanupRaceAction::Recreate { path, marker }) => {
            fs::create_dir(&path)?;
            crate::platform::set_path_mode(&path, 0o700)?;
            let marker_path = path.join(".csswitch-one-click-rollback.marker");
            fs::write(&marker_path, format!("{marker}\n"))?;
            crate::platform::set_path_mode(&marker_path, 0o600)?;
            let identity = crate::platform::identity_of_path(&path)?;
            Some(PendingCleanupIdentity {
                managed_id: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_string(),
                path,
                device: identity.dev,
                inode: identity.ino,
                marker,
            })
        }
        Some(PendingCleanupRaceAction::Delete { path }) => {
            fs::remove_dir_all(path)?;
            None
        }
        None => None,
    };
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.observation.race_identity = race_identity;
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_observe_pending_cleanup_delete_attempt() {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.observation.delete_attempt_count += 1;
    }
}

#[cfg(test)]
pub(crate) fn test_observe_pending_cleanup_completion(
    outcome: PendingCleanupRemovalOutcome,
    final_state: PendingCleanupFinalState,
) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(seam) = seam.as_mut() else {
        return;
    };
    seam.observation.completion_count += 1;
    let Some(ticket) = seam.initial_ticket.take() else {
        seam.observation.causal_mismatch_count += 1;
        return;
    };
    let event = match (ticket, outcome, final_state) {
        (
            PendingCleanupInitialTicket::Present(identity),
            PendingCleanupRemovalOutcome::Removed,
            PendingCleanupFinalState::NotFound,
        ) => Some(PendingCleanupLifecycleEvent::Remove {
            identity,
            not_found: false,
        }),
        (
            PendingCleanupInitialTicket::Missing(identity),
            PendingCleanupRemovalOutcome::AlreadyAbsent,
            PendingCleanupFinalState::NotFound,
        ) => Some(PendingCleanupLifecycleEvent::Remove {
            identity,
            not_found: true,
        }),
        _ => None,
    };
    if let Some(event) = event {
        seam.observation.events.push(event);
    } else {
        seam.observation.causal_mismatch_count += 1;
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_observe_pending_cleanup_clear_published() {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.observation
            .events
            .push(PendingCleanupLifecycleEvent::Clear);
    }
}

#[cfg(test)]
impl Drop for AtomicWritePreRenameFailpointGuard {
    fn drop(&mut self) {
        let mut failpoint = ATOMIC_WRITE_PRE_RENAME_FAILPOINT
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if failpoint.as_ref().is_some_and(|armed| armed.id == self.id) {
            *failpoint = None;
        }
    }
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_pending_manifest_pre_rename_failure(
    directory: &Path,
) -> io::Result<(
    AtomicWritePreRenameFailpointGuard,
    std::sync::Arc<std::sync::Mutex<Option<AtomicWritePreRenameObservation>>>,
)> {
    let expected = default_dir().canonicalize()?;
    let actual = directory.canonicalize()?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test-only manifest failpoint requires the exact config directory",
        ));
    }
    let metadata = actual.symlink_metadata()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test-only manifest failpoint requires a regular config directory",
        ));
    }
    let identity = crate::platform::identity_of_path(&actual)?;
    let id = ATOMIC_WRITE_PRE_RENAME_FAILPOINT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let observation = std::sync::Arc::new(std::sync::Mutex::new(None));
    let armed = AtomicWritePreRenameFailpoint {
        id,
        directory_device: identity.dev,
        directory_inode: identity.ino,
        observation: observation.clone(),
    };
    *ATOMIC_WRITE_PRE_RENAME_FAILPOINT
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(armed);
    Ok((AtomicWritePreRenameFailpointGuard { id }, observation))
}

fn config_access() -> std::sync::MutexGuard<'static, ()> {
    CONFIG_ACCESS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
fn atomic_write_pre_rename_failure(
    secure: &SecureDir,
    target: &str,
    temp: &str,
    _bytes: &[u8],
) -> io::Result<()> {
    let failpoint = ATOMIC_WRITE_PRE_RENAME_FAILPOINT
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(armed) = failpoint.as_ref() else {
        return Ok(());
    };
    if target != PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE {
        return Ok(());
    }
    let directory = crate::platform::identity_of_file(&secure.file)?;
    if directory.dev != armed.directory_device || directory.ino != armed.directory_inode {
        return Ok(());
    }
    let temp_path = secure.path.join(temp);
    let target_path = secure.path.join(target);
    let metadata = temp_path.symlink_metadata()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || crate::platform::metadata_mode(&metadata) & 0o777 != 0o600
    {
        return Err(io::Error::other(
            "test-only pre-rename observation rejected an unsafe temp",
        ));
    }
    let temp_identity = crate::platform::identity_of_path(&temp_path)?;
    *armed
        .observation
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(AtomicWritePreRenameObservation {
        temp_path,
        target_path,
        temp_device: temp_identity.dev,
        temp_inode: temp_identity.ino,
        config_access_held: CONFIG_ACCESS.try_lock().is_err(),
    });
    Err(io::Error::other(
        "test-only pending manifest failure after temp sync before rename",
    ))
}

/// 以此前 [`SecureDir::read_regular_snapshot`] 记录的 mode 恢复文件权限。
/// unix 直接 chmod；Windows 的 mode 是 [`crate::platform::metadata_mode`] 的
/// 合成值，经 [`crate::platform::set_path_mode`] 映射回只读位。
fn restore_file_mode(file: &fs::File, path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        let _ = path;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let _ = file;
        crate::platform::set_path_mode(path, mode)
    }
}

pub(crate) fn default_proxy_port() -> u16 {
    18991
}
pub(crate) fn default_sandbox_port() -> u16 {
    8990
}
pub(crate) fn default_mode() -> String {
    "proxy".to_string()
}

pub(crate) fn validate_runtime_ports(proxy_port: u16, sandbox_port: u16) -> Result<(), String> {
    if proxy_port == 8765 || sandbox_port == 8765 {
        return Err("端口 8765 是真实 Science 实例保留端口，不能用。".into());
    }
    if proxy_port == 0 || sandbox_port == 0 {
        return Err("端口不能为 0。".into());
    }
    if proxy_port == sandbox_port {
        return Err("代理端口与沙箱端口不能相同。".into());
    }
    Ok(())
}

/// 当前配置 schema 版本。>4 的文件由更新版本 app 写入，本版本拒绝启动（不误改）。
pub const CURRENT_SCHEMA_VERSION: u32 = 4;

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingCommit {
    pub profile_id: String,
    pub route_fp: String,
    pub catalog_fp: String,
    pub binding_fp: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayRuntimeJournalIdentity {
    pub provider: String,
    pub shim: String,
    pub launch_id: String,
    #[serde(default)]
    pub provider_contract_id: String,
    #[serde(default)]
    pub provider_contract_digest: String,
    pub catalog_fp: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTransactionJournal {
    pub transaction_id: String,
    pub target_profile_id: String,
    pub stage: String,
    pub previous_binding: Option<RuntimeBindingCommit>,
    #[serde(default)]
    pub previous_gateway: Option<GatewayRuntimeJournalIdentity>,
}

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

/// 一条命名配置。API key profile 的 key 明文存盘、只回掩码；OAuth profile 只存固定 opaque ref。
/// 运行行为由 `template_id + api_format` 经 provider-contract catalog 派生，不靠展示字段猜身份。
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub template_id: String,
    pub category: String,
    pub api_format: String,
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    /// v3 单模型的进程内兼容影子。v4 canonical 配置不再序列化该字段；
    /// load/normalize 从 default_model_route_id 回填，旧调用点在分模块迁移期间仍可读。
    #[serde(default, skip_serializing)]
    pub model: String,
    #[serde(default)]
    pub model_catalog: Vec<ModelRoute>,
    #[serde(default)]
    pub default_model_route_id: String,
    #[serde(default)]
    pub role_bindings: RoleBindings,
    #[serde(default)]
    pub credential_source: CredentialSource,
    #[serde(default)]
    pub credential_ref: Option<String>,
    #[serde(default)]
    pub model_policy: ModelPolicy,
    #[serde(default)]
    pub website_url: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub icon_color: Option<String>,
    #[serde(default)]
    pub sort_index: Option<i64>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// 顶层配置。字段都有默认值，缺字段的旧文件也能读。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    /// 生效 profile 的 id；空=无生效配置（运行时据此停代理、要求用户选）。
    #[serde(default)]
    pub active_id: String,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default = "default_sandbox_port")]
    pub sandbox_port: u16,
    /// 用户显式授权隔离 Science 通过系统 OpenSSH 读取 `~/.ssh/config`。
    /// 默认关闭；不复制或链接 `.ssh`，只在启动时注入受控 PATH wrapper。
    #[serde(default)]
    pub reuse_system_ssh: bool,
    /// 代理的 path-secret。**持久化**并跨代理重启/切 profile/重开 app 复用，
    /// 这样已在跑的沙箱（其 ANTHROPIC_BASE_URL 里嵌了该 secret）不会因代理换 secret 而 403。
    /// 首次为空，由后端生成一次后写回。
    #[serde(default)]
    pub secret: String,
    /// 运行模式："proxy"（第三方）| "official"（真实 Claude Science）。
    #[serde(default = "default_mode")]
    pub mode: String,
    /// 一次性迁移提示（#9 甲：回填默认模型后告知用户）。get_config 读后清空。
    #[serde(default)]
    pub pending_notice: Option<String>,
    /// Last fully healthy gateway + isolated Science binding. Contains hashes
    /// and public identities only; never credentials, endpoints, URLs or prompts.
    #[serde(default)]
    pub runtime_binding: Option<RuntimeBindingCommit>,
    #[serde(default)]
    pub runtime_transaction: Option<RuntimeTransactionJournal>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema_version: CURRENT_SCHEMA_VERSION,
            profiles: Vec::new(),
            active_id: String::new(),
            proxy_port: default_proxy_port(),
            sandbox_port: default_sandbox_port(),
            reuse_system_ssh: false,
            secret: String::new(),
            mode: default_mode(),
            pending_notice: None,
            runtime_binding: None,
            runtime_transaction: None,
            extra: BTreeMap::new(),
        }
    }
}

pub(crate) fn require_no_runtime_transaction(cfg: &Config) -> Result<(), String> {
    if cfg.runtime_transaction.is_some() {
        Err(
            "code=runtime_transaction_in_progress 运行时事务尚未结束；请先完成恢复或重试一键开始。"
                .into(),
        )
    } else {
        Ok(())
    }
}

impl Config {
    /// 当前选择 profile（active_id 空或悬空 → None）。
    pub fn active_profile(&self) -> Option<&Profile> {
        if self.active_id.is_empty() {
            return None;
        }
        self.profile_by_id(&self.active_id)
    }
    pub fn profile_by_id(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }
    pub fn profile_by_id_mut(&mut self, id: &str) -> Option<&mut Profile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }
}

/// 16 字节随机 → 32 hex 字符。/dev/urandom（unix）；不可用时退回「时间纳秒
/// ⊕ 进程内计数器」，保证同进程内连调也不碰撞。
pub fn new_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 16];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    static FALLBACK_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = FALLBACK_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mixed = n ^ ((counter as u128) << 64);
    format!("{mixed:032x}")
}

/// epoch 毫秒（用作 created_at / sort_index 初值）。
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------- 版本探测 ----------
#[derive(Debug, Clone, PartialEq)]
pub enum VersionKind {
    Legacy,
    V2,
    V3,
    V4,
    TooNew(u32),
}

#[derive(Deserialize)]
struct VersionProbe {
    #[serde(default)]
    schema_version: u32,
}

/// 先只解析 schema_version 判版本，避免用「必填字段缺失」误判旧文件。
/// <2（含缺失=0）→ Legacy；==2 → V2；==3 → V3；==4 → V4；>4 → TooNew。
pub fn detect_version(data: &[u8]) -> io::Result<VersionKind> {
    let probe: VersionProbe = serde_json::from_slice(data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config.json 解析失败：{e}"),
        )
    })?;
    Ok(match probe.schema_version {
        v if v < 2 => VersionKind::Legacy,
        2 => VersionKind::V2,
        3 => VersionKind::V3,
        v if v == CURRENT_SCHEMA_VERSION => VersionKind::V4,
        v => VersionKind::TooNew(v),
    })
}

/// 旧固定槽 → 新 profile 列表。空槽（key/base_url/model 全空）跳过；
/// 旧 provider 指针命中已迁 profile → active_id 指它，否则 ""（不静默选第一条）。
pub fn migrate_v1_to_v2(
    mut legacy: crate::config_legacy::ConfigV1,
) -> crate::config_legacy::ConfigV2 {
    // 先把遗留裸 relay 槽归位到 relay-<preset>。
    crate::templates::migrate_legacy_relay(&mut legacy.providers, &mut legacy.provider);
    let ts = now_ms();
    let mut profiles = Vec::new();
    let mut active_id = String::new();
    for (i, (slot, pc)) in legacy.providers.iter().enumerate() {
        if pc.key.is_empty() && pc.base_url.is_empty() && pc.model.is_empty() {
            continue;
        }
        let tid = crate::templates::template_id_for_legacy_slot(slot);
        let tpl = crate::templates::by_id(tid);
        let id = new_id();
        let base_url = if pc.base_url.is_empty() {
            tpl.map(|t| t.base_url.to_string()).unwrap_or_default()
        } else {
            pc.base_url.clone()
        };
        profiles.push(crate::config_legacy::ProfileV2 {
            id: id.clone(),
            name: tpl
                .map(|t| t.name.to_string())
                .unwrap_or_else(|| slot.clone()),
            template_id: tid.to_string(),
            category: tpl
                .map(|t| t.category.to_string())
                .unwrap_or_else(|| "custom".into()),
            api_format: tpl
                .map(|t| t.api_format.to_string())
                .unwrap_or_else(|| "anthropic".into()),
            base_url,
            api_key: pc.key.clone(),
            model: pc.model.clone(),
            website_url: tpl.map(|t| t.website_url.to_string()),
            icon: tpl.map(|t| t.icon.to_string()),
            icon_color: tpl.map(|t| t.icon_color.to_string()),
            sort_index: Some(i as i64),
            created_at: Some(ts),
            notes: None,
        });
        if *slot == legacy.provider {
            active_id = id;
        }
    }
    crate::config_legacy::ConfigV2 {
        schema_version: 2,
        profiles,
        active_id,
        proxy_port: legacy.proxy_port,
        sandbox_port: legacy.sandbox_port,
        reuse_system_ssh: false,
        secret: legacy.secret,
        mode: legacy.mode,
        pending_notice: None,
    }
}

pub fn migrate_v2_to_v3(
    v2: crate::config_legacy::ConfigV2,
) -> io::Result<crate::config_legacy::ConfigV3> {
    let mut profiles = Vec::with_capacity(v2.profiles.len());
    for p in v2.profiles {
        let template_id = if crate::templates::by_id(&p.template_id).is_some() {
            p.template_id
        } else {
            "custom".to_string()
        };
        let api_format = if p.api_format.trim().is_empty() {
            crate::templates::by_id(&template_id)
                .map(|template| template.api_format.to_string())
                .unwrap_or_else(|| "anthropic".to_string())
        } else {
            p.api_format
        };
        let contract = crate::provider_contracts::contract_for(&template_id, &api_format)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let model_policy = if contract.default_model_policy == ModelPolicy::DynamicCatalog {
            crate::config_legacy::ModelPolicyV3::DynamicCatalog
        } else if matches!(template_id.as_str(), "deepseek" | "qwen") {
            crate::config_legacy::ModelPolicyV3::OptionalFixed
        } else {
            crate::config_legacy::ModelPolicyV3::RequiredFixed
        };
        profiles.push(crate::config_legacy::ProfileV3 {
            id: p.id,
            name: p.name,
            template_id,
            category: p.category,
            api_format,
            base_url: p.base_url,
            api_key: p.api_key,
            model: p.model,
            credential_source: contract.default_credential_source,
            credential_ref: None,
            model_policy,
            website_url: p.website_url,
            icon: p.icon,
            icon_color: p.icon_color,
            sort_index: p.sort_index,
            created_at: p.created_at,
            notes: p.notes,
            extra: BTreeMap::new(),
        });
    }
    Ok(crate::config_legacy::ConfigV3 {
        schema_version: 3,
        profiles,
        active_id: v2.active_id,
        proxy_port: v2.proxy_port,
        sandbox_port: v2.sandbox_port,
        reuse_system_ssh: v2.reuse_system_ssh,
        secret: v2.secret,
        mode: v2.mode,
        pending_notice: v2.pending_notice,
        extra: BTreeMap::new(),
    })
}

fn legacy_native_model<'a>(template_id: &str, model: &'a str) -> Option<&'a str> {
    match (template_id, model.trim()) {
        ("deepseek", "claude-opus-4-8") => Some("deepseek-v4-pro"),
        ("deepseek", "claude-sonnet-5" | "claude-sonnet-4-6" | "claude-haiku-4-5") => {
            Some("deepseek-v4-flash")
        }
        ("qwen", "claude-opus-4-8") => Some("qwen3.7-max"),
        ("qwen", "claude-sonnet-5" | "claude-sonnet-4-6") => Some("qwen-plus-latest"),
        ("qwen", "claude-haiku-4-5") => Some("qwen-turbo"),
        (_, "") => None,
        (_, value) => Some(value),
    }
}

fn set_catalog_default(
    routes: &mut [ModelRoute],
    default_selector: &mut String,
    upstream_model: &str,
) -> bool {
    if let Some(index) = routes
        .iter()
        .position(|route| route.upstream_model == upstream_model)
    {
        routes.swap(0, index);
        *default_selector = routes[0].selector_id.clone();
        true
    } else {
        false
    }
}

fn append_notice(existing: Option<String>, next: String) -> Option<String> {
#[allow(dead_code)] // 仅 unix 测试会触发；Windows 测试构建下保持编译
    Some(match existing {
        Some(existing) if !existing.trim().is_empty() => format!("{existing}\n{next}"),
        _ => next,
    })
}

pub fn migrate_v3_to_v4(v3: crate::config_legacy::ConfigV3) -> io::Result<Config> {
    let mut profiles = Vec::with_capacity(v3.profiles.len());
    let mut incomplete_ids = BTreeSet::new();
    // Codex 功能已移除：v3 文件里的 Codex profile 在 contract 解析之前先丢弃
    // （否则 contract_for("codex") 失败会拒载整个配置），数量交给 normalize_active 汇总提示。
    let mut removed_codex_ids = BTreeSet::new();
    for mut p in v3.profiles {
        if p.template_id == "codex" {
            removed_codex_ids.insert(p.id.clone());
            continue;
        }
        if crate::templates::by_id(&p.template_id).is_none() {
            p.template_id = "custom".into();
        }
        if p.api_format.trim().is_empty() {
            p.api_format = crate::templates::by_id(&p.template_id)
                .map(|template| template.api_format.to_string())
                .unwrap_or_else(|| "anthropic".into());
        }
        let contract = crate::provider_contracts::contract_for(&p.template_id, &p.api_format)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let dynamic = contract.default_model_policy == ModelPolicy::DynamicCatalog;
        if (p.model_policy == crate::config_legacy::ModelPolicyV3::DynamicCatalog) != dynamic {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "profile `{}` 的 v3 model_policy 与 provider contract 不一致",
                    p.id
                ),
            ));
        }
        let (mut model_catalog, mut default_model_route_id, role_bindings) = if dynamic {
            (Vec::new(), String::new(), RoleBindings::default())
        } else if matches!(p.template_id.as_str(), "deepseek" | "qwen") {
            let (mut routes, mut default, bindings) =
                crate::model_catalog::preset_catalog(&p.template_id)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let raw = p.model.trim();
            if let Some(index) = routes
                .iter()
                .position(|route| !raw.is_empty() && route.selector_id == raw)
            {
                routes.swap(0, index);
                default = routes[0].selector_id.clone();
            } else if let Some(legacy) = legacy_native_model(&p.template_id, &p.model) {
                if !set_catalog_default(&mut routes, &mut default, legacy) {
                    let (manual, manual_default, _) = crate::model_catalog::single_route_catalog(
                        &crate::model_catalog::namespace_for(&p.template_id, &p.api_format),
                        legacy,
                        None,
                        None,
                    )
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    routes.insert(0, manual.into_iter().next().expect("single route"));
                    default = manual_default;
                }
            }
            let mut bindings = bindings;
            // A v3 profile had only one model field, so its migrated Sonnet
            // route must follow that selected default. The remaining role
            // bindings retain the preset's quality/fast choices.
            bindings.sonnet = default.clone();
            (routes, default, bindings)
        } else {
            if let Some(model) = legacy_native_model(&p.template_id, &p.model) {
                crate::model_catalog::single_route_catalog(
                    &crate::model_catalog::namespace_for(&p.template_id, &p.api_format),
                    model,
                    None,
                    None,
                )
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            } else {
                incomplete_ids.insert(p.id.clone());
                (Vec::new(), String::new(), RoleBindings::default())
            }
        };
        let model = model_catalog
            .iter()
            .find(|route| route.selector_id == default_model_route_id)
            .map(|route| route.upstream_model.clone())
            .unwrap_or_default();
        profiles.push(Profile {
            id: p.id,
            name: p.name,
            template_id: p.template_id,
            category: p.category,
            api_format: p.api_format,
            base_url: p.base_url,
            api_key: p.api_key,
            model,
            model_catalog: std::mem::take(&mut model_catalog),
            default_model_route_id: std::mem::take(&mut default_model_route_id),
            role_bindings,
            credential_source: p.credential_source,
            credential_ref: p.credential_ref,
            model_policy: if dynamic {
                ModelPolicy::DynamicCatalog
            } else {
                ModelPolicy::SavedCatalog
            },
            website_url: p.website_url,
            icon: p.icon,
            icon_color: p.icon_color,
            sort_index: p.sort_index,
            created_at: p.created_at,
            notes: p.notes,
            extra: p.extra,
        });
    }
    let incomplete_active = incomplete_ids.contains(&v3.active_id);
    let codex_active_removed = removed_codex_ids.contains(&v3.active_id);
    let pending_notice = {
        let mut notice = v3.pending_notice;
        if !incomplete_ids.is_empty() {
            notice = append_notice(
                notice,
                format!(
                    "{} 个旧静态配置缺少模型目录，已保留为未完成配置{}。",
                    incomplete_ids.len(),
                    if incomplete_active {
                        "；原生效配置已安全取消激活"
                    } else {
                        ""
                    }
                ),
            );
        }
        if !removed_codex_ids.is_empty() {
            notice = append_notice(
                notice,
                format!("已移除 {} 个 Codex 配置", removed_codex_ids.len()),
            );
        }
        notice
    };
    Ok(Config {
        schema_version: CURRENT_SCHEMA_VERSION,
        profiles,
        active_id: if incomplete_active || codex_active_removed {
            String::new()
        } else {
            v3.active_id
        },
        proxy_port: v3.proxy_port,
        sandbox_port: v3.sandbox_port,
        reuse_system_ssh: v3.reuse_system_ssh,
        secret: v3.secret,
        mode: v3.mode,
        pending_notice,
        runtime_binding: None,
        runtime_transaction: None,
        extra: v3.extra,
    })
}

#[cfg(not(feature = "acceptance-build"))]
pub(crate) const CONFIG_DIR_NAME: &str = ".csswitch";
#[cfg(feature = "acceptance-build")]
pub(crate) const CONFIG_DIR_NAME: &str = ".csswitch-acceptance";

fn default_dir_from_home(home: &Path) -> PathBuf {
    home.join(CONFIG_DIR_NAME)
}

/// 构建变体固定的配置目录。正式构建为 `$HOME/.csswitch`，Acceptance 为
/// `$HOME/.csswitch-acceptance`；两者不会因 Finder 使用同一个 HOME 而互相迁移配置。
pub fn default_dir() -> PathBuf {
    let home = crate::platform::home_dir().unwrap_or_else(|| PathBuf::from("."));
    default_dir_from_home(&home)
}

pub(crate) fn read_pending_authority_cleanup_manifest(dir: &Path) -> io::Result<Option<Vec<u8>>> {
    let _config_access = config_access();
    let secure = match SecureDir::open(dir, false) {
        Ok(secure) => secure,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    secure.read_regular("pending-authority-cleanup.v1.json")
}

pub(crate) fn write_pending_authority_cleanup_manifest(
    dir: &Path,
    bytes: &[u8],
    expected_before: Option<&[u8]>,
) -> io::Result<()> {
    let _config_access = config_access();
    let secure = SecureDir::open(dir, true)?;
    atomic_write_named_bytes_in(
        &secure,
        "pending-authority-cleanup.v1.json",
        bytes,
        expected_before,
        |secure| secure.sync(),
    )
}

pub(crate) fn write_pending_authority_cleanup_manifest_if_absent(
    dir: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    let _config_access = config_access();
    let secure = SecureDir::open(dir, true)?;
    atomic_write_named_bytes_if_absent_in(
        &secure,
        "pending-authority-cleanup.v1.json",
        bytes,
        |secure| secure.sync(),
    )
}

#[cfg(test)]
fn config_path(dir: &Path) -> PathBuf {
    dir.join("config.json")
}

const MAX_CONFIG_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// 若 path 存在且是符号链接则报错（不跟随）。path 不存在返回 Ok。
pub(crate) fn assert_not_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("拒绝符号链接（防跟随写/读到别处）：{}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// 确保配置目录存在且是普通目录、权限 0700。目录是符号链接则拒绝。
fn ensure_dir(dir: &Path) -> io::Result<()> {
    assert_not_symlink(dir)?;
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// 配置文件的所有关键操作都锚定到同一个已打开目录描述符。即使路径名随后被
/// rename/替换，openat/renameat/linkat 仍只作用于最初审计过的目录。
///
/// Windows 分支：std 无 openat，目录锚定退化为「目录句柄（仅用于身份比较与
/// flush）+ path 拼接操作」，打开前后用 `symlink_metadata` 拒绝符号链接。
/// 路径锚定的 TOCTOU 窗口是已接受的弱化（见 platform.rs 头部语义注释）；
/// unix 分支保持 fd 锚定实现完全不变。
struct SecureDir {
    /// unix：目录 fd（openat 锚定）；windows：目录句柄（身份锚定 + FlushFileBuffers）。
    file: fs::File,
    path: PathBuf,
    normalize_file_permissions: bool,
}

impl SecureDir {
    fn open(path: &Path, create: bool) -> io::Result<Self> {
        Self::open_with_policy(path, create, true)
    }

    /// 用户自己选择的 export 父目录必须已存在，且 CSSwitch 不得擅自 chmod 它。
    /// （生产调用方已随 Codex export 功能移除；当前仅 unix 门控测试使用。）
    #[cfg(all(test, unix))]
    fn open_unmanaged(path: &Path) -> io::Result<Self> {
        Self::open_with_policy(path, false, false)
    }

    #[cfg(unix)]
    fn open_with_policy(
        path: &Path,
        create: bool,
        normalize_permissions: bool,
    ) -> io::Result<Self> {
        assert_not_symlink(path)?;
        if create {
            ensure_dir(path)?;
        }
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path)?;
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("配置目录不是目录：{}", path.display()),
            ));
        }
        if normalize_permissions {
            file.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            normalize_file_permissions: normalize_permissions,
        })
    }

    #[cfg(windows)]
    fn open_with_policy(
        path: &Path,
        create: bool,
        normalize_permissions: bool,
    ) -> io::Result<Self> {
        assert_not_symlink(path)?;
        if create {
            ensure_dir(path)?;
        }
        let file = crate::platform::open_dir(path)?;
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("配置目录不是目录：{}", path.display()),
            ));
        }
        if normalize_permissions {
            // Windows 默认 ACL 已仅当前用户可读；合成 0700 由 platform 处理。
            crate::platform::make_dir_private(path)?;
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            normalize_file_permissions: normalize_permissions,
        })
    }

    /// 目录内文件名校验：拒绝空名、路径分隔符逃逸与 NUL。
    fn validate_name(name: &str) -> io::Result<()> {
        let illegal = if cfg!(windows) {
            name.as_bytes()
                .iter()
                .any(|&b| b == b'/' || b == b'\\' || b == b':')
        } else {
            name.as_bytes().contains(&b'/')
        };
        if name.is_empty() || illegal {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "配置目录内部文件名非法",
            ));
        }
        if name.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "配置目录内部文件名包含 NUL",
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn name(name: &str) -> io::Result<CString> {
        Self::validate_name(name)?;
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "配置目录内部文件名包含 NUL"))
    }

    #[cfg(unix)]
    fn read_regular_snapshot(&self, name: &str) -> io::Result<Option<(Vec<u8>, u32)>> {
        let name = Self::name(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            if error.raw_os_error() == Some(libc::ELOOP) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝配置目录内的符号链接",
                ));
            }
            return Err(error);
        }
        let file = unsafe { fs::File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝配置目录内的非普通文件",
            ));
        }
        if self.normalize_file_permissions && metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝配置目录内具有多个 hard link 的文件",
            ));
        }
        if metadata.len() > MAX_CONFIG_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "配置或备份文件过大",
            ));
        }
        let mut mode = metadata.permissions().mode() & 0o777;
        if self.normalize_file_permissions {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            mode = 0o600;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_CONFIG_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "配置或备份文件过大",
            ));
        }
        Ok(Some((bytes, mode)))
    }

    /// Windows：std 无 openat，退化为 path 打开 + 打开前后 symlink_metadata
    /// 复查拒绝符号链接（FILE_FLAG_OPEN_REPARSE_POINT 不跟随 reparse point）。
    /// 先以 symlink_metadata 预检 NotFound / 非普通文件，等价 unix 的
    /// O_NONBLOCK 不阻塞语义；行为契约与 unix 分支一致。
    #[cfg(windows)]
    fn read_regular_snapshot(&self, name: &str) -> io::Result<Option<(Vec<u8>, u32)>> {
        use std::os::windows::fs::OpenOptionsExt;
        Self::validate_name(name)?;
        let path = self.path.join(name);
        let pre = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if pre.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝配置目录内的符号链接",
            ));
        }
        if !pre.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝配置目录内的非普通文件",
            ));
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(crate::platform::no_follow_flags())
            .open(&path)?;
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝配置目录内的符号链接",
            ));
        }
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝配置目录内的非普通文件",
            ));
        }
        let identity = crate::platform::identity_of_file(&file)?;
        if self.normalize_file_permissions && identity.nlink != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝配置目录内具有多个 hard link 的文件",
            ));
        }
        if metadata.len() > MAX_CONFIG_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "配置或备份文件过大",
            ));
        }
        let mut mode = crate::platform::metadata_mode(&metadata) & 0o777;
        if self.normalize_file_permissions {
            crate::platform::make_file_private(&file)?;
            mode = 0o600;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_CONFIG_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "配置或备份文件过大",
            ));
        }
        Ok(Some((bytes, mode)))
    }

    /// 只确认模块自有 pending 名是否为普通文件；不 chmod、不要求单 hard link。
    #[cfg(unix)]
    fn regular_exists_allow_hardlinks(&self, name: &str) -> io::Result<bool> {
        let name = Self::name(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            if error.raw_os_error() == Some(libc::ELOOP) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝版本备份 pending 符号链接",
                ));
            }
            return Err(error);
        }
        let file = unsafe { fs::File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝非普通版本备份 pending 文件",
            ));
        }
        Ok(true)
    }

    /// Windows：symlink_metadata 预检 + 符号链接/非普通文件拒绝，契约同 unix。
    #[cfg(windows)]
    fn regular_exists_allow_hardlinks(&self, name: &str) -> io::Result<bool> {
        Self::validate_name(name)?;
        let path = self.path.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝版本备份 pending 符号链接",
            ));
        }
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝非普通版本备份 pending 文件",
            ));
        }
        Ok(true)
    }

    fn read_regular(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        self.read_regular_snapshot(name)
            .map(|snapshot| snapshot.map(|(bytes, _)| bytes))
    }

    #[cfg(unix)]
    fn create_new(&self, name: &str) -> io::Result<fs::File> {
        let name = Self::name(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    /// Windows：create_new 即 O_CREAT|O_EXCL 语义（已存在即失败），加 no-follow
    /// 打开标志并在创建后确认不是 reparse point、收紧私有权限。
    #[cfg(windows)]
    fn create_new(&self, name: &str) -> io::Result<fs::File> {
        use std::os::windows::fs::OpenOptionsExt;
        Self::validate_name(name)?;
        let path = self.path.join(name);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(crate::platform::no_follow_flags())
            .open(&path)?;
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拒绝配置目录内的符号链接",
            ));
        }
        crate::platform::make_file_private(&file)?;
        Ok(file)
    }

    #[cfg(unix)]
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let from = Self::name(from)?;
        let to = Self::name(to)?;
        let result = unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                from.as_ptr(),
                self.file.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Windows：std rename 覆盖语义与 POSIX rename 相同（同卷原子）。
    #[cfg(windows)]
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        Self::validate_name(from)?;
        Self::validate_name(to)?;
        fs::rename(self.path.join(from), self.path.join(to))
    }

    #[cfg(unix)]
    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        let from = Self::name(from)?;
        let to = Self::name(to)?;
        let result = unsafe {
            libc::linkat(
                self.file.as_raw_fd(),
                from.as_ptr(),
                self.file.as_raw_fd(),
                to.as_ptr(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Windows：std hard_link 即 no-replace（目标已存在 → ERROR_FILE_EXISTS）。
    #[cfg(windows)]
    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        Self::validate_name(from)?;
        Self::validate_name(to)?;
        crate::platform::link_no_replace(&self.path.join(from), &self.path.join(to))
    }

    #[cfg(unix)]
    fn unlink(&self, name: &str) -> io::Result<()> {
        let name = Self::name(name)?;
        let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    fn unlink(&self, name: &str) -> io::Result<()> {
        Self::validate_name(name)?;
        fs::remove_file(self.path.join(name))
    }

    fn sync(&self) -> io::Result<()> {
        // unix：目录 fd fsync；windows：目录句柄 FlushFileBuffers（元数据落盘尽力语义）。
        self.file.sync_all()
    }

    fn display_path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

}

// ---------- 备份 ----------
/// 迁移前备份旧 config.json → config.json.v1.bak。源不存在 / 备份失败 → Err（中止迁移）。
#[cfg(test)]
pub fn write_migration_backup(dir: &Path) -> io::Result<()> {
    let secure = SecureDir::open(dir, false)?;
    let data = secure
        .read_regular("config.json")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config.json 不存在"))?;
    write_versioned_backup_bytes_in(&secure, 1, &data).map(|_| ())
}

fn backup_suffix() -> String {
    let millis = now_ms();
    let id = new_id();
    format!("{millis}-{}", &id[..8])
}

fn backup_content_suffix(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 版本迁移备份：固定名存在且内容相同就复用；内容不同时写唯一后缀，永不覆盖。
/// temp 在同目录完整 fsync 后用 hard_link 原子发布，link 本身具有 O_EXCL 语义。
#[cfg(test)]
fn write_versioned_backup_bytes(dir: &Path, version: u32, bytes: &[u8]) -> io::Result<PathBuf> {
    let secure = SecureDir::open(dir, true)?;
    write_versioned_backup_bytes_in(&secure, version, bytes)
}

fn write_versioned_backup_bytes_in(
    secure: &SecureDir,
    version: u32,
    bytes: &[u8],
) -> io::Result<PathBuf> {
    let primary = format!("config.json.v{version}.bak");
    let content_suffix = backup_content_suffix(bytes);
    let alternate = format!("config.json.v{version}.bak.{content_suffix}");
    let pending = format!(".config.json.v{version}.bak.pending-{content_suffix}");

    // link+dir-fsync 后若进程崩溃，pending hard link 可能在重启后重新出现。
    // 当前迁移输入在 backup 成功前不会改变，因此内容哈希能稳定定位并清理残留。
    if secure.regular_exists_allow_hardlinks(&pending)? {
        secure.unlink(&pending)?;
        secure.sync()?;
    }
    let target = match secure.read_regular(&primary)? {
        Some(existing) if existing == bytes => return Ok(secure.display_path(&primary)),
        Some(_) => alternate,
        None => primary.clone(),
    };
    if let Some(existing) = secure.read_regular(&target)? {
        if existing == bytes {
            return Ok(secure.display_path(&target));
        }
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "版本备份哈希目标冲突",
        ));
    }
    let result = (|| -> io::Result<()> {
        let mut file = secure.create_new(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        secure.link(&pending, &target)?;
        if let Err(error) = secure.sync() {
            let _ = secure.unlink(&target);
            let _ = secure.unlink(&pending);
            let _ = secure.sync();
            return Err(error);
        }
        secure.unlink(&pending)?;
        secure.sync()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = secure.unlink(&pending);
    }
    result?;
    Ok(secure.display_path(&target))
}

/// 普通保存前的单份滚动备份 → config.json.bak。best-effort（调用方可忽略 Err），但写法仍原子/0600。
pub fn write_rolling_backup(dir: &Path) -> io::Result<()> {
    let _config_access = config_access();
    write_rolling_backup_unlocked(dir)
}

fn write_rolling_backup_unlocked(dir: &Path) -> io::Result<()> {
    let secure = SecureDir::open(dir, false)?;
    let data = secure
        .read_regular("config.json")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config.json 不存在"))?;
    atomic_write_named_bytes_in(&secure, "config.json.bak", &data, None, |secure| {
        secure.sync()
    })
}

/// 清 key / 删 profile 后净化滚动备份：直接删，避免旧明文 key 残留可恢复。
pub fn drop_rolling_backup(dir: &Path) {
    let _config_access = config_access();
    if let Ok(secure) = SecureDir::open(dir, false) {
        let _ = secure.unlink("config.json.bak");
        let _ = secure.sync();
    }
}

/// 从 `dir/config.json` 读配置。文件不存在返回 [`Config::default`]。
/// v1/v2/v3 先完整解析、迁移、校验，再写不可覆盖的版本备份，最后只原子提交一次 v4。
/// v4 悬空 active_id 归一化为空。文件/目录是符号链接则报错（不跟随读）。
pub fn load_from(dir: &Path) -> io::Result<Config> {
    let _config_access = config_access();
    load_from_unlocked(dir)
}

fn load_from_unlocked(dir: &Path) -> io::Result<Config> {
    // 目录本身也不许是符号链接：否则攻击者把 ~/.csswitch 换成软链就能让读取跟随到别处。
    assert_not_symlink(dir)?;
    let secure = match SecureDir::open(dir, false) {
        Ok(secure) => secure,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(error) => return Err(error),
    };
    let data = match secure.read_regular("config.json")? {
        Some(data) => data,
        None => return Ok(Config::default()),
    };
    match detect_version(&data)? {
        VersionKind::TooNew(v) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config.json 由更新版本（schema {v}）写入，请升级 CSSwitch 后再打开。"),
        )),
        VersionKind::Legacy => {
            let legacy: crate::config_legacy::ConfigV1 =
                serde_json::from_slice(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("旧 config 解析失败：{e}"),
                    )
                })?;
            let v2 = migrate_v1_to_v2(legacy);
            let canonical_v2 = serde_json::to_vec_pretty(&v2).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("v2 备份序列化失败：{error}"),
                )
            })?;
            let cfg = normalize_active(migrate_v3_to_v4(migrate_v2_to_v3(v2)?)?);
            validate_loaded_ports(&cfg)?;
            validate_profile_contracts(&cfg)?;
            write_versioned_backup_bytes_in(&secure, 1, &data)?;
            write_versioned_backup_bytes_in(&secure, 2, &canonical_v2)?;
            commit_migrated_config(&secure, &data, &cfg)?;
            Ok(cfg)
        }
        VersionKind::V2 => {
            let v2: crate::config_legacy::ConfigV2 =
                serde_json::from_slice(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("v2 config.json 解析失败：{e}"),
                    )
                })?;
            let canonical_v2 = serde_json::to_vec_pretty(&v2).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("v2 备份序列化失败：{error}"),
                )
            })?;
            let cfg = normalize_active(migrate_v3_to_v4(migrate_v2_to_v3(v2)?)?);
            validate_loaded_ports(&cfg)?;
            validate_profile_contracts(&cfg)?;
            write_versioned_backup_bytes_in(&secure, 2, &canonical_v2)?;
            commit_migrated_config(&secure, &data, &cfg)?;
            Ok(cfg)
        }
        VersionKind::V3 => {
            let v3: crate::config_legacy::ConfigV3 =
                serde_json::from_slice(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("v3 config.json 解析失败：{e}"),
                    )
                })?;
            let cfg = normalize_active(migrate_v3_to_v4(v3)?);
            validate_loaded_ports(&cfg)?;
            validate_profile_contracts(&cfg)?;
            write_versioned_backup_bytes_in(&secure, 3, &data)?;
            commit_migrated_config(&secure, &data, &cfg)?;
            Ok(cfg)
        }
        VersionKind::V4 => {
            let cfg: Config = serde_json::from_slice(&data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("v4 config.json 解析失败：{e}"),
                )
            })?;
            let cfg = normalize_active(cfg);
            validate_loaded_ports(&cfg)?;
            validate_profile_contracts(&cfg)?;
            Ok(cfg)
        }
    }
}

fn commit_migrated_config(secure: &SecureDir, original: &[u8], cfg: &Config) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(cfg).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("v4 配置序列化失败：{error}"),
        )
    })?;
    let decoded: Config = serde_json::from_slice(&json).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("v4 配置回读验证失败：{error}"),
        )
    })?;
    let decoded = normalize_active(decoded);
    validate_loaded_ports(&decoded)?;
    validate_profile_contracts(&decoded)?;
    atomic_write_named_bytes_in(secure, "config.json", &json, Some(original), |secure| {
        secure.sync()
    })?;

    let published = secure
        .read_regular("config.json")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "v4 配置提交后消失"));
    let post_check = published.and_then(|published| {
        if published != json {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v4 配置提交后字节校验不一致",
            ));
        }
        let reread: Config = serde_json::from_slice(&published).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("v4 配置提交后解析失败：{error}"),
            )
        })?;
        let reread = normalize_active(reread);
        validate_loaded_ports(&reread)?;
        validate_profile_contracts(&reread)
    });
    if let Err(post_error) = post_check {
        return match atomic_write_named_bytes_in(
            secure,
            "config.json",
            original,
            Some(&json),
            |secure| secure.sync(),
        ) {
            Ok(()) => Err(post_error),
            Err(rollback_error) => Err(io::Error::other(format!(
                "v4 配置提交后验证失败：{post_error}；恢复原配置也失败：{rollback_error}"
            ))),
        };
    }
    Ok(())
}

fn validate_loaded_ports(cfg: &Config) -> io::Result<()> {
    validate_runtime_ports(cfg.proxy_port, cfg.sandbox_port).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config.json 端口无效：{e}"),
        )
    })
}

/// 追加一次性迁移提示；get_config 读出后清空。
fn append_pending_notice(cfg: &mut Config, message: String) {
    cfg.pending_notice = Some(match cfg.pending_notice.take() {
        Some(existing) if !existing.trim().is_empty() => format!("{existing}\n{message}"),
        _ => message,
    });
}

/// 加载后归一化不变式（spec §4）：
/// - Codex 功能已移除：旧文件里的 Codex profile 与 `experimental_codex_enabled` /
///   `codex_network` 遗留键在 contract 校验【前】丢弃（credential_source=CsswitchOauth
///   已不被任何 contract 允许，留着会让整个配置拒载），并按需追加一次性提示；
/// - `template_id` 未命中注册表 → 归一化为 `custom`（保留连接字段；据它派生 adapter/UI 能力）；
/// - `active_id` 指向不存在的 profile → 归一化为空（运行时据此停代理、要求用户选）。
fn normalize_active(mut cfg: Config) -> Config {
    let codex_profiles_before = cfg.profiles.len();
    cfg.profiles
        .retain(|profile| profile.template_id != "codex");
    if cfg.profiles.len() != codex_profiles_before {
        let removed = codex_profiles_before - cfg.profiles.len();
        append_pending_notice(&mut cfg, format!("已移除 {removed} 个 Codex 配置"));
        if cfg
            .profile_by_id(&cfg.active_id)
            .is_none()
            && !cfg.active_id.is_empty()
        {
            // active 指向的 Codex profile 已被移除 → 清空（下方悬空归一化也会兜底）。
            cfg.active_id.clear();
        }
    }
    let mut codex_settings_removed = false;
    if cfg.extra.remove("experimental_codex_enabled") == Some(serde_json::Value::Bool(true)) {
        codex_settings_removed = true;
    }
    if let Some(value) = cfg.extra.remove("codex_network") {
        let is_default = value == serde_json::json!({"mode": "auto", "proxy_url": ""});
        if !is_default {
            codex_settings_removed = true;
        }
    }
    if codex_settings_removed {
        append_pending_notice(&mut cfg, "已移除 Codex 实验功能相关设置".into());
    }
    for p in cfg.profiles.iter_mut() {
        if p.api_format.trim().is_empty() {
            p.api_format = crate::templates::by_id(&p.template_id)
                .map(|template| template.api_format.to_string())
                .unwrap_or_else(|| "anthropic".to_string());
        }
        let known_contract =
            crate::provider_contracts::contract_for(&p.template_id, &p.api_format).is_ok();
        if crate::templates::by_id(&p.template_id).is_none() && !known_contract {
            p.template_id = "custom".to_string();
        }
        p.model = p
            .model_catalog
            .iter()
            .find(|route| route.selector_id == p.default_model_route_id)
            .map(|route| route.upstream_model.clone())
            .unwrap_or_default();
    }
    if !cfg.active_id.is_empty() && cfg.profile_by_id(&cfg.active_id).is_none() {
        cfg.active_id.clear();
    }
    cfg
}

fn validate_profile_contracts(cfg: &Config) -> io::Result<()> {
    if cfg.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("只接受 canonical schema v{CURRENT_SCHEMA_VERSION}"),
        ));
    }
    let mut ids = BTreeSet::new();
    for reserved in [
        "schema_version",
        "profiles",
        "active_id",
        "proxy_port",
        "sandbox_port",
        "reuse_system_ssh",
        // 已移除的 Codex 实验字段不算保留字：normalize_active 会在校验前收下并丢弃，
        // 这里保留冲突检测只针对现存 canonical 字段。
        "secret",
        "mode",
        "pending_notice",
        "runtime_binding",
        "runtime_transaction",
    ] {
        if cfg.extra.contains_key(reserved) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config extension 与 canonical 字段冲突：{reserved}"),
            ));
        }
    }
    for profile in &cfg.profiles {
        for reserved in [
            "id",
            "name",
            "template_id",
            "category",
            "api_format",
            "base_url",
            "api_key",
            "model",
            "model_catalog",
            "default_model_route_id",
            "role_bindings",
            "credential_source",
            "credential_ref",
            "model_policy",
            "website_url",
            "icon",
            "icon_color",
            "sort_index",
            "created_at",
            "notes",
        ] {
            if profile.extra.contains_key(reserved) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "profile `{}` extension 与 canonical 字段冲突：{reserved}",
                        profile.id
                    ),
                ));
            }
        }
        if profile.id.trim().is_empty() || profile.id.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "profile id 不能为空且不得超过 256 字节",
            ));
        }
        if !ids.insert(profile.id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("profile id 重复：{}", profile.id),
            ));
        }
        let contract =
            crate::provider_contracts::contract_for(&profile.template_id, &profile.api_format)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if !contract
            .credential_sources
            .contains(&profile.credential_source)
            || !contract.model_policies.contains(&profile.model_policy)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "profile `{}` 的 credential/model policy 不符合 provider contract",
                    profile.id
                ),
            ));
        }
        match profile.model_policy {
            ModelPolicy::DynamicCatalog => {
                if !profile.model_catalog.is_empty()
                    || !profile.default_model_route_id.is_empty()
                    || !profile.role_bindings.all_empty()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("动态目录 profile `{}` 含静态目录", profile.id),
                    ));
                }
            }
            ModelPolicy::SavedCatalog if profile.model_catalog.is_empty() => {
                if cfg.active_id == profile.id
                    || !profile.default_model_route_id.is_empty()
                    || !profile.role_bindings.all_empty()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("未完成静态 profile `{}` 不得激活或保存悬空绑定", profile.id),
                    ));
                }
            }
            ModelPolicy::SavedCatalog => {
                crate::model_catalog::validate_saved_catalog(
                    &profile.model_catalog,
                    &profile.default_model_route_id,
                    &profile.role_bindings,
                )
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("profile `{}` 模型目录无效：{error}", profile.id),
                    )
                })?;
            }
        }
        match profile.credential_source {
            CredentialSource::ApiKey if profile.credential_ref.is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("API-key profile `{}` 不得保存 credential_ref", profile.id),
                ));
            }
            CredentialSource::CsswitchOauth => {
                if !profile.api_key.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("OAuth profile `{}` 不得保存 api_key", profile.id),
                    ));
                }
            }
            CredentialSource::None
                if profile.credential_ref.is_some() || !profile.api_key.is_empty() =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("无凭据 profile `{}` 不得保存 credential 数据", profile.id),
                ));
            }
            _ => {}
        }
    }
    if !cfg.active_id.is_empty() && !ids.contains(&cfg.active_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("active_id 指向不存在的 profile：{}", cfg.active_id),
        ));
    }
    Ok(())
}

/// 原子写 `dir/config.json`（0600）。目录/目标文件是符号链接则拒绝。
#[allow(dead_code)]
pub fn save_to(dir: &Path, cfg: &Config) -> io::Result<()> {
    let _config_access = config_access();
    save_to_unlocked(dir, cfg)
}

fn save_to_unlocked(dir: &Path, cfg: &Config) -> io::Result<()> {
    let secure = SecureDir::open(dir, true)?;
    save_to_secure(&secure, cfg)
}

fn save_to_secure(secure: &SecureDir, cfg: &Config) -> io::Result<()> {
    if cfg.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("只能保存 schema v{CURRENT_SCHEMA_VERSION} 配置"),
        ));
    }
    validate_loaded_ports(cfg)?;
    validate_profile_contracts(cfg)?;
    let json = serde_json::to_vec_pretty(cfg).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config 序列化失败：{e}"),
        )
    })?;

    atomic_write_named_bytes_in(secure, "config.json", &json, None, |secure| secure.sync())
}

#[derive(Debug)]
struct AtomicRollbackUncertain {
    commit: String,
    rollback: String,
}

impl std::fmt::Display for AtomicRollbackUncertain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "配置提交同步失败，且回滚失败：commit={}; rollback={}",
            self.commit, self.rollback
        )
    }
}

impl std::error::Error for AtomicRollbackUncertain {}

#[cfg(all(test, unix))]
fn atomic_rollback_is_uncertain(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<AtomicRollbackUncertain>())
}

/// 先发布临时文件，再持久化目录项。若发布后的同步失败，恢复发布前字节并再次
/// 同步，保证 `Err` 的可观察语义是目标文件未改变。测试可注入 commit sync 失败。
enum AtomicWriteExpectedBefore<'a> {
    Any,
    Exact(&'a [u8]),
    Absent,
}

fn atomic_write_named_bytes_in<F>(
    secure: &SecureDir,
    target: &str,
    bytes: &[u8],
    expected_before: Option<&[u8]>,
    commit_sync: F,
) -> io::Result<()>
where
    F: FnOnce(&SecureDir) -> io::Result<()>,
{
    atomic_write_named_bytes_with_expectation_in(
        secure,
        target,
        bytes,
        expected_before
            .map(AtomicWriteExpectedBefore::Exact)
            .unwrap_or(AtomicWriteExpectedBefore::Any),
        commit_sync,
    )
}

fn atomic_write_named_bytes_if_absent_in<F>(
    secure: &SecureDir,
    target: &str,
    bytes: &[u8],
    commit_sync: F,
) -> io::Result<()>
where
    F: FnOnce(&SecureDir) -> io::Result<()>,
{
    atomic_write_named_bytes_with_expectation_in(
        secure,
        target,
        bytes,
        AtomicWriteExpectedBefore::Absent,
        commit_sync,
    )
}

fn atomic_write_named_bytes_with_expectation_in<F>(
    secure: &SecureDir,
    target: &str,
    bytes: &[u8],
    expected_before: AtomicWriteExpectedBefore<'_>,
    commit_sync: F,
) -> io::Result<()>
where
    F: FnOnce(&SecureDir) -> io::Result<()>,
{
    let before = secure.read_regular_snapshot(target)?;
    match expected_before {
        AtomicWriteExpectedBefore::Any => {}
        AtomicWriteExpectedBefore::Exact(expected)
            if before.as_ref().map(|(bytes, _)| bytes.as_slice()) == Some(expected) => {}
        AtomicWriteExpectedBefore::Absent if before.is_none() => {}
        _ => {
            return Err(io::Error::other("配置在迁移提交前被外部进程修改"));
        }
    }
    let suffix = backup_suffix();
    let tmp = format!(".{target}.tmp-{}-{suffix}", std::process::id());

    let mut file = secure.create_new(&tmp)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = secure.unlink(&tmp);
        return Err(error);
    }
    drop(file);

    #[cfg(test)]
    if let Err(error) = atomic_write_pre_rename_failure(secure, target, &tmp, bytes) {
        let _ = secure.unlink(&tmp);
        return Err(error);
    }

    match (before.as_ref(), secure.read_regular(target)) {
        (Some((expected, _)), Ok(Some(actual))) if expected == &actual => {}
        (None, Ok(None)) => {}
        (_, Ok(_)) => {
            let _ = secure.unlink(&tmp);
            return Err(io::Error::other("配置在提交前被并发修改"));
        }
        (_, Err(error)) => {
            let _ = secure.unlink(&tmp);
            return Err(error);
        }
    }

    if let Err(error) = secure.rename(&tmp, target) {
        let _ = secure.unlink(&tmp);
        return Err(error);
    }

    if let Err(commit_error) = commit_sync(secure) {
            let restore = if let Some((old_bytes, old_mode)) = before {
                let restore_tmp = format!(".{target}.restore-{}-{suffix}", std::process::id());
                let restore_result = (|| -> io::Result<()> {
                    let mut restore_file = secure.create_new(&restore_tmp)?;
                    restore_file.write_all(&old_bytes)?;
                    restore_file_mode(
                        &restore_file,
                        &secure.display_path(&restore_tmp),
                        old_mode,
                    )?;
                    restore_file.sync_all()?;
                    drop(restore_file);
                    secure.rename(&restore_tmp, target)?;
                    secure.sync()
                })();
            if restore_result.is_err() {
                let _ = secure.unlink(&restore_tmp);
            }
            restore_result
        } else {
            secure.unlink(target).and_then(|_| secure.sync())
        };
        if let Err(restore_error) = restore {
            return Err(io::Error::other(AtomicRollbackUncertain {
                commit: commit_error.to_string(),
                rollback: restore_error.to_string(),
            }));
        }
        return Err(commit_error);
    }
    Ok(())
}

/// 序列化的「读-改-写」：进程内全局写锁下 load → apply → save，避免并发命令
/// 各读一份旧 config、各改一个字段、互相覆盖。
pub fn update<F: FnOnce(&mut Config)>(dir: &Path, f: F) -> io::Result<Config> {
    let _config_access = config_access();
    let mut cfg = load_from_unlocked(dir)?;
    f(&mut cfg);
    save_to_unlocked(dir, &cfg)?;
    Ok(cfg)
}

/// Serialized fallible read-modify-write. If the caller rejects the in-memory
/// mutation, no config or rolling backup is written.
pub fn update_result<T, F>(dir: &Path, f: F) -> Result<T, String>
where
    F: FnOnce(&mut Config) -> Result<(T, bool), String>,
{
    let _config_access = config_access();
    let mut cfg = load_from_unlocked(dir).map_err(|error| error.to_string())?;
    let (result, changed) = f(&mut cfg)?;
    if changed {
        save_to_unlocked(dir, &cfg).map_err(|error| error.to_string())?;
    }
    Ok(result)
}

/// Fallible serialized update whose rolling backup is created only after the
/// closure accepts the mutation. Backup remains best-effort, matching existing
/// profile-save behavior, while a guard error leaves both files untouched.
pub fn update_result_with_rolling_backup<T, F>(dir: &Path, f: F) -> Result<T, String>
where
    F: FnOnce(&mut Config) -> Result<(T, bool), String>,
{
    let _config_access = config_access();
    let mut cfg = load_from_unlocked(dir).map_err(|error| error.to_string())?;
    let (result, changed) = f(&mut cfg)?;
    if changed {
        let _ = write_rolling_backup_unlocked(dir);
        save_to_unlocked(dir, &cfg).map_err(|error| error.to_string())?;
    }
    Ok(result)
}

/// 掩码：固定 4 个圆点 + 末 4 位（`••••tail`）。空 key 返回空串；≤4 位全遮。
/// 定长而非随 key 长度增长：长 key 的掩码不会在列表里撑出横向溢出（WKWebView 不给连续
/// 圆点断行，`word-break` 拦不住），且不泄漏 key 长度。绝不返回完整 key，是回显前端的唯一形式。
pub fn mask(key: &str) -> String {
    let n = key.chars().count();
    if n == 0 {
        String::new()
    } else if n <= 4 {
        "•".repeat(n)
    } else {
        let last4: String = key.chars().skip(n - 4).collect();
        format!("••••{last4}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, FileTypeExt};

    fn tmpdir() -> PathBuf {
        // 每个测试用「进程 id + 线程 id」独立子目录，避免并行测试相互踩。
        let base = std::env::temp_dir().join(format!("csswitch-cfg-test-{}", std::process::id()));
        let d = base.join(format!("{:?}", std::thread::current().id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// 跨平台 mode 读取：unix 为真实 POSIX mode；Windows 为 platform 层合成值
    /// （目录 0700 / 可写文件 0600 / 只读文件 0500），0600/0700 断言两平台同语义。
    fn mode_of(p: &Path) -> u32 {
        crate::platform::metadata_mode(&fs::metadata(p).unwrap()) & 0o777
    }

    fn saved_profile(id: &str, template_id: &str, api_format: &str, upstream: &str) -> Profile {
        let (model_catalog, default_model_route_id, role_bindings) =
            crate::model_catalog::new_profile_catalog(template_id, api_format, Some(upstream))
                .unwrap();
        Profile {
            id: id.into(),
            template_id: template_id.into(),
            api_format: api_format.into(),
            model: upstream.into(),
            model_catalog,
            default_model_route_id,
            role_bindings,
            model_policy: ModelPolicy::SavedCatalog,
            ..Default::default()
        }
    }

    // ---------- A1: 结构 + 访问器 + new_id/now_ms ----------
    #[test]
    fn config_default_is_v4_empty() {
        let c = Config::default();
        assert_eq!(c.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(c.schema_version, 4);
        assert!(c.profiles.is_empty());
        assert_eq!(c.active_id, "");
        assert_eq!(c.proxy_port, 18991);
        assert!(!c.reuse_system_ssh);
        assert_eq!(c.mode, "proxy");
    }

    #[test]
    fn default_dir_is_compile_time_isolated_by_build_variant() {
        let home = Path::new("/tmp/csswitch-home-contract");
        let got = default_dir_from_home(home);
        #[cfg(feature = "acceptance-build")]
        assert_eq!(got, home.join(".csswitch-acceptance"));
        #[cfg(not(feature = "acceptance-build"))]
        assert_eq!(got, home.join(".csswitch"));
    }

    #[test]
    fn existing_v3_without_removed_codex_fields_loads_normally() {
        let d = tmpdir();
        fs::write(
            d.join("config.json"),
            br#"{"schema_version":3,"profiles":[],"active_id":"","proxy_port":18991,"sandbox_port":18765,"reuse_system_ssh":false,"secret":"","mode":"proxy","pending_notice":null}"#,
        )
        .unwrap();
        crate::platform::set_path_mode(&d.join("config.json"), 0o600).unwrap();

        let cfg = load_from(&d).unwrap();
        assert_eq!(cfg.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(cfg.pending_notice.is_none());
    }

    #[test]
    fn profile_accessors_by_id_and_active() {
        let p = Profile {
            id: "abc".into(),
            name: "DS".into(),
            template_id: "deepseek".into(),
            category: "cn_official".into(),
            api_format: "anthropic".into(),
            base_url: "https://api.deepseek.com/anthropic".into(),
            api_key: "sk-1".into(),
            model: String::new(),
            ..Default::default()
        };
        let c = Config {
            profiles: vec![p.clone()],
            active_id: "abc".into(),
            ..Default::default()
        };
        assert_eq!(c.profile_by_id("abc").unwrap().name, "DS");
        assert!(c.profile_by_id("nope").is_none());
        assert_eq!(c.active_profile().unwrap().id, "abc");
        let c2 = Config {
            active_id: "".into(),
            ..c.clone()
        };
        assert!(c2.active_profile().is_none());
    }

    #[test]
    fn v3_empty_static_profile_is_preserved_incomplete_and_deactivated() {
        let v3 = crate::config_legacy::ConfigV3 {
            profiles: vec![crate::config_legacy::ProfileV3 {
                id: "p1".into(),
                name: "我的 GLM".into(),
                template_id: "glm".into(),
                category: "cn_official".into(),
                api_format: "anthropic".into(),
                model_policy: crate::config_legacy::ModelPolicyV3::RequiredFixed,
                ..Default::default()
            }],
            active_id: "p1".into(),
            schema_version: 3,
            ..crate::config_legacy::ConfigV3::default()
        };
        let cfg = migrate_v3_to_v4(v3).unwrap();
        assert!(cfg.profiles[0].model_catalog.is_empty());
        assert!(cfg.active_id.is_empty());
        assert!(cfg.pending_notice.unwrap().contains("取消激活"));
    }

    #[test]
    fn new_id_is_unique_hex_and_now_ms_positive() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(now_ms() > 0);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let d = tmpdir().join(".csswitch");
        let p = Profile {
            name: "DeepSeek".into(),
            category: "cn_official".into(),
            base_url: "https://api.deepseek.com/anthropic".into(),
            api_key: "sk-abcdef1234".into(),
            ..saved_profile("id1", "deepseek", "anthropic", "deepseek-v4-pro")
        };
        let cfg = Config {
            profiles: vec![p],
            active_id: "id1".into(),
            proxy_port: 12345,
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        let got = load_from(&d).unwrap();
        assert_eq!(got, cfg);
        assert_eq!(got.active_profile().unwrap().api_key, "sk-abcdef1234");
    }

    #[test]
    fn load_rejects_invalid_runtime_ports() {
        let cases = [
            ("proxy_8765", 8765, 8990),
            ("sandbox_8765", 18991, 8765),
            ("proxy_zero", 0, 8990),
            ("sandbox_zero", 18991, 0),
            ("same_ports", 18991, 18991),
        ];
        for (name, proxy_port, sandbox_port) in cases {
            let d = tmpdir().join(format!(".csswitch-{name}"));
            fs::create_dir_all(&d).unwrap();
            fs::write(
                config_path(&d),
                format!(
                    r#"{{"schema_version":2,"profiles":[],"active_id":"","proxy_port":{proxy_port},"sandbox_port":{sandbox_port}}}"#
                ),
            )
            .unwrap();
            let err = load_from(&d).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{name}");
            assert!(
                err.to_string().contains("config.json 端口无效"),
                "error should identify invalid config ports for {name}: {err}"
            );
        }
    }

    #[test]
    fn load_rejects_legacy_invalid_ports_before_v2_save() {
        let d = tmpdir().join(".csswitch-legacy-bad-port");
        fs::create_dir_all(&d).unwrap();
        let legacy = r#"{
            "provider":"deepseek",
            "proxy_port":18991,
            "sandbox_port":8765,
            "secret":"sec",
            "mode":"proxy",
            "providers":{"deepseek":{"key":"sk-ds","base_url":"","model":""}}
        }"#;
        fs::write(config_path(&d), legacy).unwrap();
        let err = load_from(&d).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let after = fs::read_to_string(config_path(&d)).unwrap();
        assert!(
            !after.contains("\"schema_version\""),
            "invalid legacy config should not be saved as v2: {after}"
        );
        assert!(
            !d.join("config.json.v1.bak").exists(),
            "旧配置未通过完整校验时不得发布迁移备份"
        );
    }

    // ---------- A2: 版本探测 ----------
    #[test]
    fn detect_version_missing_field_is_legacy() {
        let d = br#"{"provider":"deepseek","providers":{}}"#;
        assert!(matches!(detect_version(d).unwrap(), VersionKind::Legacy));
    }
    #[test]
    fn detect_version_two_is_v2() {
        let d = br#"{"schema_version":2,"profiles":[],"active_id":""}"#;
        assert!(matches!(detect_version(d).unwrap(), VersionKind::V2));
    }
    #[test]
    fn detect_version_three_is_v3() {
        let d = br#"{"schema_version":3}"#;
        assert!(matches!(detect_version(d).unwrap(), VersionKind::V3));
    }
    #[test]
    fn detect_version_four_is_v4() {
        let d = br#"{"schema_version":4}"#;
        assert!(matches!(detect_version(d).unwrap(), VersionKind::V4));
    }
    #[test]
    fn detect_version_garbage_errors() {
        assert!(detect_version(b"not json").is_err());
    }

    // ---------- A4: 迁移 v1 → v2 ----------
    #[test]
    fn migrate_maps_slots_to_profiles_and_active() {
        use crate::config_legacy::{ConfigV1, ProviderCfgV1};
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "deepseek".to_string(),
            ProviderCfgV1 {
                key: "sk-ds".into(),
                base_url: "".into(),
                model: "".into(),
            },
        );
        providers.insert(
            "relay-glm".to_string(),
            ProviderCfgV1 {
                key: "glmk".into(),
                base_url: "https://open.bigmodel.cn/api/anthropic".into(),
                model: "glm-5".into(),
            },
        );
        providers.insert(
            "qwen".to_string(),
            ProviderCfgV1 {
                key: "".into(),
                base_url: "".into(),
                model: "".into(),
            },
        ); // 空槽
        let legacy = ConfigV1 {
            provider: "relay-glm".into(),
            proxy_port: 18991,
            sandbox_port: 8990,
            secret: "sec".into(),
            mode: "proxy".into(),
            providers,
        };
        let cfg = migrate_v1_to_v2(legacy);
        assert_eq!(cfg.schema_version, 2);
        assert_eq!(cfg.profiles.len(), 2, "空 qwen 槽跳过");
        let glm = cfg
            .profiles
            .iter()
            .find(|p| p.template_id == "glm")
            .unwrap();
        assert_eq!(glm.api_key, "glmk");
        assert_eq!(glm.base_url, "https://open.bigmodel.cn/api/anthropic");
        assert_eq!(glm.model, "glm-5");
        assert_eq!(glm.api_format, "anthropic");
        assert_eq!(
            cfg.active_id, glm.id,
            "旧 provider=relay-glm → 生效指该 profile"
        );
        assert_eq!(cfg.secret, "sec");
    }

    #[test]
    fn migrate_invalid_active_yields_empty() {
        use crate::config_legacy::{ConfigV1, ProviderCfgV1};
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "deepseek".to_string(),
            ProviderCfgV1 {
                key: "k".into(),
                base_url: "".into(),
                model: "".into(),
            },
        );
        // 旧 provider 指向空/不存在的槽 → active_id 必须为空（不静默选第一条）。
        let legacy = ConfigV1 {
            provider: "qwen".into(),
            proxy_port: 18991,
            sandbox_port: 8990,
            secret: "".into(),
            mode: "proxy".into(),
            providers,
        };
        let cfg = migrate_v1_to_v2(legacy);
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.active_id, "", "非法 active → 空，等用户选");
    }

    #[test]
    fn migrate_legacy_bare_relay_slot() {
        use crate::config_legacy::{ConfigV1, ProviderCfgV1};
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "relay".to_string(),
            ProviderCfgV1 {
                key: "rk".into(),
                base_url: "https://open.bigmodel.cn/api/anthropic".into(),
                model: "".into(),
            },
        );
        let legacy = ConfigV1 {
            provider: "relay".into(),
            proxy_port: 18991,
            sandbox_port: 8990,
            secret: "".into(),
            mode: "proxy".into(),
            providers,
        };
        let cfg = migrate_v1_to_v2(legacy);
        let glm = cfg
            .profiles
            .iter()
            .find(|p| p.template_id == "glm")
            .unwrap();
        assert_eq!(glm.api_key, "rk");
        assert_eq!(cfg.active_id, glm.id);
    }

    // ---------- A5: 备份基础设施 ----------
    #[test]
    fn migration_backup_copies_and_is_0600() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), b"OLD-V1-BYTES").unwrap();
        write_migration_backup(&d).unwrap();
        let bak = d.join("config.json.v1.bak");
        assert_eq!(fs::read(&bak).unwrap(), b"OLD-V1-BYTES");
        assert_eq!(mode_of(&bak), 0o600);
    }
    #[test]
    fn migration_backup_missing_source_errors() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        assert!(write_migration_backup(&d).is_err());
    }
    #[test]
    fn rolling_backup_then_drop_removes_key_recoverability() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), br#"{"api_key":"sk-SECRET-TAIL"}"#).unwrap();
        write_rolling_backup(&d).unwrap();
        let bak = d.join("config.json.bak");
        assert!(fs::read_to_string(&bak).unwrap().contains("sk-SECRET-TAIL"));
        drop_rolling_backup(&d);
        assert!(
            !bak.exists(),
            "净化后滚动备份应删除，清了的 key 不可从 .bak 恢复"
        );
    }
    // unix 专属：symlink() 构造符号链接攻击场景（Windows 无 std symlink 组合校验等价物）。
    #[cfg(unix)]
    #[test]
    fn backup_rejects_symlinked_target() {
        let base = tmpdir();
        let d = base.join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), b"X").unwrap();
        let elsewhere = base.join("elsewhere");
        fs::write(&elsewhere, b"ORIG").unwrap();
        symlink(&elsewhere, d.join("config.json.v1.bak")).unwrap();
        assert!(write_migration_backup(&d).is_err());
        assert_eq!(fs::read(&elsewhere).unwrap(), b"ORIG");
    }

    // ---------- A6: load_from 整合 ----------
    #[test]
    fn load_migrates_old_file_and_writes_v1_bak() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(
            config_path(&d),
            br#"{"provider":"deepseek","providers":{"deepseek":{"key":"sk-x"}}}"#,
        )
        .unwrap();
        let cfg = load_from(&d).unwrap();
        assert_eq!(cfg.schema_version, 4);
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.active_profile().unwrap().api_key, "sk-x");
        assert!(d.join("config.json.v1.bak").exists(), "迁移必须留 v1 备份");
        assert!(
            d.join("config.json.v2.bak").exists(),
            "迁移必须留 canonical v2 备份"
        );
        // 落盘后再读是 v4（幂等，不再迁移）。
        let again = load_from(&d).unwrap();
        assert_eq!(again, cfg);
        assert_eq!(again.schema_version, 4);
    }
    #[test]
    fn load_too_new_errors() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), br#"{"schema_version":9,"profiles":[]}"#).unwrap();
        let e = load_from(&d).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("更新版本"));
    }
    #[test]
    fn load_normalizes_dangling_active() {
        let d = tmpdir().join(".csswitch");
        let cfg = Config {
            active_id: "ghost".into(),
            profiles: vec![Profile {
                id: "real".into(),
                template_id: "deepseek".into(),
                api_format: "anthropic".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        let got = load_from(&d).unwrap();
        assert_eq!(got.active_id, "", "悬空 active → 归一化为空");
    }

    // ---------- MP-2 Minor [2]: template_id 未命中 → 归一 custom ----------
    #[test]
    fn load_normalizes_unknown_template_id_to_custom() {
        let d = tmpdir().join(".csswitch");
        let (model_catalog, default_model_route_id, role_bindings) =
            crate::model_catalog::single_route_catalog(
                "custom-anthropic",
                "relay-model-v1",
                None,
                None,
            )
            .unwrap();
        // 造一条 template_id 未命中注册表的 v2 profile（连接字段保留）。
        let cfg = Config {
            active_id: "p1".into(),
            profiles: vec![Profile {
                id: "p1".into(),
                name: "野模板".into(),
                template_id: "totally-unknown-xyz".into(),
                api_format: "anthropic".into(),
                base_url: "https://relay.example/claude".into(),
                api_key: "sk-x".into(),
                model: "relay-model-v1".into(),
                model_catalog,
                default_model_route_id,
                role_bindings,
                model_policy: ModelPolicy::SavedCatalog,
                ..Default::default()
            }],
            ..Default::default()
        };
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        let got = load_from(&d).unwrap();
        let p = got.profile_by_id("p1").unwrap();
        assert_eq!(p.template_id, "custom", "未命中 template_id → 归一 custom");
        assert_eq!(p.base_url, "https://relay.example/claude", "连接字段保留");
        assert_eq!(p.api_key, "sk-x");
        assert_eq!(got.active_id, "p1", "active 仍有效，不被清空");
    }

    // ---------- 既有安全/权限不变量（保留） ----------
    #[test]
    fn load_missing_returns_default() {
        let d = tmpdir().join(".csswitch");
        let cfg = load_from(&d).unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.schema_version, 4);
        assert_eq!(cfg.proxy_port, 18991);
    }

    #[test]
    fn save_sets_dir_0700_and_file_0600() {
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        assert_eq!(mode_of(&d), 0o700, "dir must be 0700");
        assert_eq!(mode_of(&config_path(&d)), 0o600, "file must be 0600");
    }

    // unix 专属：from_mode(0o644) 主动放宽 POSIX 权限位再验证 load 收紧。
    #[cfg(unix)]
    #[test]
    fn load_resets_widened_perms_to_0600() {
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        let p = config_path(&d);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        load_from(&d).unwrap();
        assert_eq!(mode_of(&p), 0o600, "load must reset perms to 0600");
    }

    #[cfg(unix)]
    #[test]
    fn save_rejects_symlinked_file_and_leaves_target_untouched() {
        let base = tmpdir();
        let d = base.join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        let target = base.join("real-elsewhere.txt");
        fs::write(&target, b"ORIGINAL").unwrap();
        symlink(&target, config_path(&d)).unwrap();
        let err = save_to(&d, &Config::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&target).unwrap(), b"ORIGINAL");
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_file() {
        let base = tmpdir();
        let d = base.join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        let target = base.join("secret.txt");
        fs::write(&target, b"{\"schema_version\":2}").unwrap();
        symlink(&target, config_path(&d)).unwrap();
        let err = load_from(&d).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // unix 专属：mkfifo + O_NONBLOCK 不阻塞打开验证。
    #[cfg(unix)]
    #[test]
    fn load_rejects_fifo_without_blocking() {
        let d = tmpdir().join(".csswitch-fifo");
        fs::create_dir_all(&d).unwrap();
        let path = config_path(&d);
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let error = load_from(&d).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn versioned_backup_rejects_fifo_target_without_overwrite() {
        let d = tmpdir().join(".csswitch-backup-fifo");
        fs::create_dir_all(&d).unwrap();
        let target = d.join("config.json.v2.bak");
        let c_path = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(write_versioned_backup_bytes(&d, 2, b"safe-bytes").is_err());
        assert!(fs::symlink_metadata(target).unwrap().file_type().is_fifo());
    }

    #[test]
    fn versioned_backup_recovers_published_pending_hardlink_after_crash() {
        let d = tmpdir().join(".csswitch-backup-recovery");
        fs::create_dir_all(&d).unwrap();
        let bytes = b"migration-source-bytes";
        let suffix = backup_content_suffix(bytes);
        let pending = d.join(format!(".config.json.v2.bak.pending-{suffix}"));
        let target = d.join("config.json.v2.bak");
        fs::write(&pending, bytes).unwrap();
        fs::hard_link(&pending, &target).unwrap();
        assert_eq!(crate::platform::identity_of_path(&target).unwrap().nlink, 2);

        let published = write_versioned_backup_bytes(&d, 2, bytes).unwrap();
        assert_eq!(published, target);
        assert!(!pending.exists());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(crate::platform::identity_of_path(&target).unwrap().nlink, 1);
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_dir() {
        let base = tmpdir();
        let realdir = base.join("realdir");
        fs::create_dir_all(&realdir).unwrap();
        fs::write(realdir.join("config.json"), b"{\"schema_version\":2}").unwrap();
        let link = base.join(".csswitch");
        symlink(&realdir, &link).unwrap();
        let err = load_from(&link).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dir_rejects_symlinked_dir() {
        let base = tmpdir();
        let realdir = base.join("realdir");
        fs::create_dir_all(&realdir).unwrap();
        let link = base.join(".csswitch");
        symlink(&realdir, &link).unwrap();
        let err = save_to(&link, &Config::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn no_tmp_file_left_after_save() {
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        let leftovers: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".config.json.tmp")
            })
            .collect();
        assert!(leftovers.is_empty(), "临时文件应已 rename 掉");
    }

    #[test]
    fn update_applies_and_persists() {
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        update(&d, |c| {
            c.profiles.push(Profile {
                name: "Q".into(),
                ..saved_profile("id1", "qwen", "openai_chat", "qwen-plus-latest")
            });
            c.active_id = "id1".into();
        })
        .unwrap();
        let got = load_from(&d).unwrap();
        assert_eq!(got.active_id, "id1");
        assert_eq!(got.active_profile().unwrap().name, "Q");
    }

    #[test]
    fn secret_persists_and_survives_reload() {
        // path-secret 一旦生成必须持久化，代理重启/重开 app 仍是同一个值。
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        assert!(load_from(&d).unwrap().secret.is_empty(), "初始应为空");
        update(&d, |c| c.secret = "deadbeef00112233".into()).unwrap();
        assert_eq!(load_from(&d).unwrap().secret, "deadbeef00112233");
        // 再改别的字段，secret 不受影响。
        update(&d, |c| c.proxy_port = 20000).unwrap();
        assert_eq!(load_from(&d).unwrap().secret, "deadbeef00112233");
    }

    #[test]
    fn v2_migration_preserves_api_key_profile_and_settings() {
        let d = tmpdir().join(".csswitch-v2-migration");
        fs::create_dir_all(&d).unwrap();
        let v2 = crate::config_legacy::ConfigV2 {
            schema_version: 2,
            profiles: vec![crate::config_legacy::ProfileV2 {
                id: "api-1".into(),
                name: "GLM".into(),
                template_id: "glm".into(),
                category: "cn_official".into(),
                api_format: "anthropic".into(),
                base_url: "https://open.bigmodel.cn/api/anthropic".into(),
                api_key: "sk-existing".into(),
                model: "glm-5.2".into(),
                ..Default::default()
            }],
            active_id: "api-1".into(),
            proxy_port: 19001,
            sandbox_port: 19002,
            reuse_system_ssh: true,
            secret: "persistent-secret".into(),
            mode: "proxy".into(),
            pending_notice: Some("keep-me".into()),
        };
        let canonical = serde_json::to_vec_pretty(&v2).unwrap();
        fs::write(config_path(&d), &canonical).unwrap();

        let migrated = load_from(&d).unwrap();
        assert_eq!(migrated.schema_version, 4);
        assert_eq!(migrated.active_id, "api-1");
        assert_eq!(migrated.proxy_port, 19001);
        assert_eq!(migrated.sandbox_port, 19002);
        assert!(migrated.reuse_system_ssh);
        assert_eq!(migrated.secret, "persistent-secret");
        let profile = migrated.active_profile().unwrap();
        assert_eq!(profile.api_key, "sk-existing");
        assert_eq!(profile.model, "glm-5.2");
        assert_eq!(profile.credential_source, CredentialSource::ApiKey);
        assert_eq!(profile.model_policy, ModelPolicy::SavedCatalog);
        assert_eq!(fs::read(d.join("config.json.v2.bak")).unwrap(), canonical);
    }

    #[test]
    fn v3_to_v4_preserves_unknown_fields_drops_codex_settings_and_raw_backup_byte_for_byte() {
        let d = tmpdir().join(".csswitch-v3-extensions");
        fs::create_dir_all(&d).unwrap();
        let raw = br#"{
  "schema_version": 3,
  "profiles": [{
    "id": "qwen-legacy",
    "name": "Qwen",
    "template_id": "qwen",
    "category": "cn_official",
    "api_format": "openai_chat",
    "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "api_key": "test-only",
    "model": "claude-sonnet-5",
    "credential_source": "api_key",
    "model_policy": "optional_fixed",
    "future_profile": {"keep": 2}
  }],
  "active_id": "qwen-legacy",
  "proxy_port": 19031,
  "sandbox_port": 19032,
  "codex_network": {"mode": "auto", "proxy_url": "", "future_network": 3},
  "mode": "proxy",
  "future_top": [1, 2, 3]
}"#;
        fs::write(config_path(&d), raw).unwrap();
        let migrated = load_from(&d).unwrap();
        assert_eq!(migrated.extra["future_top"], serde_json::json!([1, 2, 3]));
        assert_eq!(migrated.profiles[0].extra["future_profile"]["keep"], 2);
        // 已移除的 Codex 网络设置不进 canonical v4，且因非默认值追加一次性提示。
        assert!(!migrated.extra.contains_key("codex_network"));
        let notice = migrated.pending_notice.clone().unwrap_or_default();
        assert!(
            notice.contains("已移除 Codex 实验功能相关设置"),
            "notice={notice}"
        );
        assert_eq!(migrated.profiles[0].model, "qwen-plus-latest");
        assert_eq!(fs::read(d.join("config.json.v3.bak")).unwrap(), raw);
        let canonical: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path(&d)).unwrap()).unwrap();
        assert_eq!(canonical["schema_version"], 4);
        assert!(canonical.get("codex_network").is_none());
        assert!(canonical["profiles"][0].get("model").is_none());

        update(&d, |cfg| cfg.pending_notice = Some("unrelated".into())).unwrap();
        let again = load_from(&d).unwrap();
        assert_eq!(again.extra["future_top"], serde_json::json!([1, 2, 3]));
        assert_eq!(again.profiles[0].extra["future_profile"]["keep"], 2);
        assert_eq!(fs::read(d.join("config.json.v3.bak")).unwrap(), raw);
    }

    // v4 旧文件：Codex profile 与遗留开关在加载时被丢弃，active 悬空被归一化，并追加一次性提示。
    #[test]
    fn v4_legacy_codex_profile_and_flag_are_dropped_with_notice() {
        let d = tmpdir().join(".csswitch-v4-codex-legacy");
        fs::create_dir_all(&d).unwrap();
        // selector_id 是 SHA256 派生的 v1 别名，无法手写；用真实 helper 生成。
        let namespace = crate::model_catalog::namespace_for("glm", "anthropic");
        let selector = crate::model_catalog::selector_id_v1(&namespace, "glm-5.2");
        let raw = format!(
            r#"{{
  "schema_version": 4,
  "profiles": [
    {{
      "id": "codex-1",
      "name": "Codex account",
      "template_id": "codex",
      "category": "experimental",
      "api_format": "openai_responses",
      "base_url": "",
      "api_key": "",
      "model": "",
      "credential_source": "csswitch_oauth",
      "credential_ref": "csswitch:codex:default",
      "model_policy": "dynamic_catalog"
    }},
    {{
      "id": "api-1",
      "name": "GLM",
      "template_id": "glm",
      "category": "cn_official",
      "api_format": "anthropic",
      "base_url": "https://open.bigmodel.cn/api/anthropic",
      "api_key": "sk-existing",
      "model": "",
      "credential_source": "api_key",
      "model_policy": "saved_catalog",
      "model_catalog": [
        {{
          "selector_id": "{selector}",
          "display_name": "GLM",
          "upstream_model": "glm-5.2",
          "supports_tools": true
        }}
      ],
      "default_model_route_id": "{selector}",
      "role_bindings": {{"sonnet": "{selector}", "opus": "{selector}", "haiku": "{selector}", "fable": "{selector}"}}
    }}
  ],
  "active_id": "codex-1",
  "experimental_codex_enabled": true,
  "codex_network": {{"mode": "custom", "proxy_url": "http://127.0.0.1:7890"}},
  "proxy_port": 18991,
  "sandbox_port": 18765,
  "mode": "proxy"
}}"#);
        fs::write(config_path(&d), raw).unwrap();
        crate::platform::set_path_mode(&config_path(&d), 0o600).unwrap();

        let cfg = load_from(&d).unwrap();
        assert_eq!(cfg.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(cfg.profiles.len(), 1, "codex profile must be dropped");
        assert_eq!(cfg.profiles[0].id, "api-1");
        assert!(
            cfg.active_id.is_empty(),
            "active pointed at the removed codex profile"
        );
        assert!(!cfg.extra.contains_key("experimental_codex_enabled"));
        assert!(!cfg.extra.contains_key("codex_network"));
        let notice = cfg.pending_notice.clone().unwrap_or_default();
        assert!(notice.contains("已移除 1 个 Codex 配置"), "notice={notice}");
        assert!(
            notice.contains("已移除 Codex 实验功能相关设置"),
            "notice={notice}"
        );

        // 再次加载已提交的 v4（无 Codex 内容）不再追加新提示，notice 保持原样。
        let notice_before = cfg.pending_notice.clone();
        update(&d, |cfg| cfg.proxy_port = 18992).unwrap();
        let again = load_from(&d).unwrap();
        assert_eq!(again.profiles.len(), 1);
        assert_eq!(again.pending_notice, notice_before);
    }

    #[test]
    fn v4_route_and_role_extensions_survive_unrelated_update() {
        let d = tmpdir().join(".csswitch-v4-route-extensions");
        let mut profile = saved_profile("p1", "qwen", "openai_chat", "qwen-plus-latest");
        profile.model_catalog[0]
            .extra
            .insert("future_route".into(), serde_json::json!({"keep": true}));
        profile
            .role_bindings
            .extra
            .insert("future_role".into(), serde_json::json!(7));
        let cfg = Config {
            profiles: vec![profile],
            active_id: "p1".into(),
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        update(&d, |cfg| cfg.proxy_port = 19041).unwrap();
        let got = load_from(&d).unwrap();
        assert_eq!(
            got.profiles[0].model_catalog[0].extra["future_route"]["keep"],
            true
        );
        assert_eq!(got.profiles[0].role_bindings.extra["future_role"], 7);
    }

    #[test]
    fn native_v3_model_variants_preserve_the_selected_upstream() {
        for (template_id, api_format, old_model, expected, expected_len) in [
            ("deepseek", "anthropic", "", "deepseek-v4-flash", 2),
            (
                "deepseek",
                "anthropic",
                "claude-haiku-4-5",
                "deepseek-v4-flash",
                2,
            ),
            (
                "deepseek",
                "anthropic",
                "deepseek-v4-pro",
                "deepseek-v4-pro",
                2,
            ),
            ("qwen", "openai_chat", "claude-opus-4-8", "qwen3.7-max", 3),
            ("qwen", "openai_chat", "qwen-turbo", "qwen-turbo", 3),
            (
                "qwen",
                "openai_chat",
                "future-qwen-exact",
                "future-qwen-exact",
                4,
            ),
        ] {
            let v3 = crate::config_legacy::ConfigV3 {
                schema_version: 3,
                profiles: vec![crate::config_legacy::ProfileV3 {
                    id: "p".into(),
                    name: "legacy".into(),
                    template_id: template_id.into(),
                    api_format: api_format.into(),
                    model: old_model.into(),
                    model_policy: crate::config_legacy::ModelPolicyV3::OptionalFixed,
                    credential_source: CredentialSource::ApiKey,
                    ..Default::default()
                }],
                ..Default::default()
            };
            let migrated = migrate_v3_to_v4(v3).unwrap();
            assert_eq!(
                migrated.profiles[0].model, expected,
                "{template_id}:{old_model}"
            );
            assert_eq!(migrated.profiles[0].model_catalog.len(), expected_len);
            assert_eq!(
                migrated.profiles[0].role_bindings.sonnet,
                migrated.profiles[0].default_model_route_id,
                "{template_id}:{old_model} must keep migrated default/Sonnet aligned"
            );
        }

        let selector = crate::model_catalog::selector_id_v1("qwen", "qwen-turbo");
        let v3 = crate::config_legacy::ConfigV3 {
            schema_version: 3,
            profiles: vec![crate::config_legacy::ProfileV3 {
                id: "p".into(),
                template_id: "qwen".into(),
                api_format: "openai_chat".into(),
                model: selector,
                model_policy: crate::config_legacy::ModelPolicyV3::OptionalFixed,
                credential_source: CredentialSource::ApiKey,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            migrate_v3_to_v4(v3).unwrap().profiles[0].model,
            "qwen-turbo"
        );
    }

    #[test]
    fn v2_backup_collision_never_overwrites_existing_bytes() {
        let d = tmpdir().join(".csswitch-v2-collision");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("config.json.v2.bak"), b"OLD-UNRELATED-BYTES").unwrap();
        fs::write(
            config_path(&d),
            br#"{"schema_version":2,"profiles":[],"active_id":"","proxy_port":18991,"sandbox_port":8990,"reuse_system_ssh":false,"secret":"","mode":"proxy","pending_notice":null}"#,
        )
        .unwrap();
        load_from(&d).unwrap();
        assert_eq!(
            fs::read(d.join("config.json.v2.bak")).unwrap(),
            b"OLD-UNRELATED-BYTES"
        );
        let alternates: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("config.json.v2.bak.")
            })
            .collect();
        assert_eq!(alternates.len(), 1);
    }

    #[test]
    fn commit_sync_failure_restores_byte_identical_config_without_residue() {
        let d = tmpdir().join(".csswitch-sync-rollback");
        save_to(&d, &Config::default()).unwrap();
        let before = fs::read(config_path(&d)).unwrap();
        let secure = SecureDir::open(&d, false).unwrap();
        let error = atomic_write_named_bytes_in(
            &secure,
            "config.json",
            br#"{"schema_version":3,"changed":true}"#,
            None,
            |_| Err(io::Error::other("injected fsync failure")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected fsync failure"));
        assert_eq!(fs::read(config_path(&d)).unwrap(), before);
        let leftovers: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.contains(".tmp-") || name.contains(".restore-") || name.contains(".rollback-")
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    // unix 专属：以 chmod 0o500（目录只读）注入 commit sync 失败并验证回滚不确定。
    #[cfg(unix)]
    #[test]
    fn commit_and_rollback_double_failure_is_terminal_uncertain() {
        let d = tmpdir().join(".csswitch-sync-rollback-double-fail");
        save_to(&d, &Config::default()).unwrap();
        let secure = SecureDir::open(&d, false).unwrap();
        let error = atomic_write_named_bytes_in(
            &secure,
            "config.json",
            br#"{"schema_version":3,"changed":true}"#,
            None,
            |secure| {
                fs::set_permissions(&secure.path, fs::Permissions::from_mode(0o500))?;
                Err(io::Error::other("injected commit sync failure"))
            },
        )
        .unwrap_err();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(atomic_rollback_is_uncertain(&error));
        assert!(error.to_string().contains("回滚失败"));
    }

    #[test]
    fn clearing_key_removes_old_secret_from_every_regular_config_file() {
        let d = tmpdir().join(".csswitch-clear-key");
        let mut cfg = Config {
            profiles: vec![Profile {
                api_key: "sk-must-not-survive".into(),
                ..saved_profile("api-1", "deepseek", "anthropic", "deepseek-v4-pro")
            }],
            active_id: "api-1".into(),
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        write_rolling_backup(&d).unwrap();
        cfg.profiles[0].api_key.clear();
        save_to(&d, &cfg).unwrap();
        drop_rolling_backup(&d);
        for entry in fs::read_dir(&d).unwrap().filter_map(Result::ok) {
            if entry.file_type().unwrap().is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(!bytes
                    .windows(b"sk-must-not-survive".len())
                    .any(|window| { window == b"sk-must-not-survive" }));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_export_commit_preserves_existing_user_file_bytes_and_mode() {
        let root = tmpdir();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let destination = root.join("existing-export.json");
        fs::write(&destination, b"user-owned-before").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644)).unwrap();
        let export_dir = SecureDir::open_unmanaged(&root).unwrap();
        assert!(atomic_write_named_bytes_in(
            &export_dir,
            "existing-export.json",
            b"replacement",
            None,
            |_| Err(io::Error::other("injected export dir fsync failure")),
        )
        .is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"user-owned-before");
        assert_eq!(mode_of(&destination), 0o644);
        assert_eq!(mode_of(&root), 0o755);
    }

    #[test]
    fn mask_hides_all_but_last4() {
        assert_eq!(mask("sk-1234567890ab"), "••••90ab"); // 定长 4 点 + 末4
        assert_eq!(mask(""), "");
        assert_eq!(mask("abc"), "•••");
        assert_eq!(mask("abcd"), "••••");
        assert_eq!(mask("abcde"), "••••bcde"); // 定长 4 点 + 末4
        let full = "sk-secret-tail9999";
        assert!(!mask(full).contains("secret"));
        // 定长：掩码总长恒为 8（4 点 + 末4），不随 key 长度变长、不泄漏长度
        assert_eq!(
            mask("sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaa1234").chars().count(),
            8
        );
    }
}
