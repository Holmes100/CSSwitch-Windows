use std::io::Read;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ---------- 跨平台 VFS 别名（unix 保持 libc 原生类型；Windows 用合成等价物） ----------

/// 文件 kind 位：unix 直接来自 libc；Windows 本地定义同样的八进制值。
#[cfg(unix)]
use libc::{S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};

#[cfg(windows)]
const S_IFMT: u32 = 0o170_000;
#[cfg(windows)]
const S_IFDIR: u32 = 0o040_000;
#[cfg(windows)]
const S_IFREG: u32 = 0o100_000;
#[cfg(windows)]
const S_IFLNK: u32 = 0o120_000;

/// open(2) flag 子集：unix 传给 libc；Windows 由 open_destination_at 自行解释
/// （读/写 + O_CREAT|O_EXCL → create_new，另加 no-follow custom_flags）。
#[cfg(unix)]
use libc::{O_CREAT, O_EXCL, O_RDONLY, O_WRONLY};

#[cfg(windows)]
const O_RDONLY: i32 = 0;
#[cfg(windows)]
const O_WRONLY: i32 = 1;
#[cfg(windows)]
const O_CREAT: i32 = 0x0100;
#[cfg(windows)]
const O_EXCL: i32 = 0x0400;

/// fstatat 等价物：unix 原生 `libc::stat`；Windows 为字段语义一致的合成结构
/// （mode 为合成值，见 platform.rs 头部说明；uid/gid 恒 0）。
#[cfg(unix)]
type EntryStat = libc::stat;
#[cfg(unix)]
type ModeT = libc::mode_t;

#[cfg(windows)]
#[derive(Clone, Copy)]
struct EntryStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    st_nlink: u64,
    st_size: u64,
    st_mtime: i64,
    st_mtime_nsec: i64,
}

#[cfg(windows)]
type ModeT = u32;

/// 目录句柄：unix 为 fd 锚定的 File（openat 语义）；Windows 为句柄 + 完整
/// 路径（std 无 openat，路径锚定退化为路径访问，属已接受的平台弱化）。
#[cfg(not(windows))]
type DirHandle = std::fs::File;

#[cfg(windows)]
struct DirHandle {
    file: std::fs::File,
    path: PathBuf,
}

/// 目录句柄内的 File（读 metadata / 身份 / sync 用）。
#[cfg(not(windows))]
fn dir_file(handle: &DirHandle) -> &std::fs::File {
    handle
}

/// 目录句柄内的 File（Windows 模式存于结构体内）。
#[cfg(windows)]
fn dir_file(handle: &DirHandle) -> &std::fs::File {
    &handle.file
}

/// 目录句柄锚定的完整路径（仅 Windows 路径锚定模式使用）。
#[cfg(windows)]
fn dir_path(handle: &DirHandle) -> &Path {
    &handle.path
}

/// 目录句柄 metadata。
fn handle_metadata(handle: &DirHandle) -> std::io::Result<std::fs::Metadata> {
    dir_file(handle).metadata()
}

/// 目录句柄 sync：unix 为真实目录 fsync；Windows 只读目录句柄不支持
/// FlushFileBuffers（需写访问），目录持久化由 NTFS 元数据日志保证，忽略之。
fn handle_sync(handle: &DirHandle) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        dir_file(handle).sync_all()
    }
    #[cfg(windows)]
    {
        let _ = dir_file(handle).sync_all();
        Ok(())
    }
}

/// 复制目录句柄（unix dup fd；Windows 克隆句柄并保留锚定路径）。
fn dir_try_clone(handle: &DirHandle) -> std::io::Result<DirHandle> {
    #[cfg(not(windows))]
    {
        handle.try_clone()
    }
    #[cfg(windows)]
    {
        Ok(DirHandle {
            file: handle.file.try_clone()?,
            path: handle.path.clone(),
        })
    }
}

/// 当前进程 POSIX uid（Windows 无此概念，返回 0，与合成 EntryStat.st_uid 对齐）。
fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(windows)]
    {
        0
    }
}

/// OsStr → UTF-8 字节（unix 原生 as_bytes；Windows 要求名字为合法 UTF-8）。
fn os_str_bytes(value: &std::ffi::OsStr) -> std::io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(value.as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        value
            .to_str()
            .map(str::as_bytes)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "路径名不是合法 UTF-8")
            })
    }
}

/// OsStr → CString（同时完成 NUL 校验；Windows 侧要求 UTF-8 可编码）。
fn cstring_from_os(value: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    Ok(std::ffi::CString::new(os_str_bytes(value)?)?)
}

/// 把新文件收紧为指定 mode：unix 真实 chmod；Windows 按 POSIX 写位映射只读
/// 属性（0o200 缺失 → 只读），其余私有性由默认 ACL 保证（语义弱化已接受）。
fn apply_file_mode(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let mut permissions = file.metadata()?.permissions();
        let readonly = mode & 0o200 == 0;
        if permissions.readonly() != readonly {
            permissions.set_readonly(readonly);
            file.set_permissions(permissions)?;
        }
        Ok(())
    }
}

/// 把目录收紧为指定 mode：unix 真实 chmod；Windows 无 POSIX mode（默认 ACL
/// 已私有），按平台原语处理（make_dir_private 为 no-op）。
fn apply_dir_mode(handle: &DirHandle, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        dir_file(handle).set_permissions(std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let path = dir_path(handle).to_path_buf();
        crate::platform::make_dir_private(&path)?;
        let _ = mode;
        Ok(())
    }
}

/// 已打开文件的硬链接数（unix MetadataExt；Windows 经平台身份原语）。
fn file_nlink(file: &std::fs::File) -> std::io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(file.metadata()?.nlink())
    }
    #[cfg(windows)]
    {
        Ok(crate::platform::identity_of_file(file)?.nlink)
    }
}

/// metadata 的 (mtime 秒, 纳秒) 对（unix 原生；Windows 由 SystemTime 合成）。
fn metadata_mtime_pair(metadata: &std::fs::Metadata) -> (i64, i64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (metadata.mtime(), metadata.mtime_nsec())
    }
    #[cfg(windows)]
    {
        match metadata.modified() {
            Ok(modified) => match modified.duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => (
                    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
                    i64::from(duration.subsec_nanos()),
                ),
                Err(error) => {
                    let earlier = error.duration();
                    (
                        -i64::try_from(earlier.as_secs()).unwrap_or(i64::MAX),
                        -i64::from(earlier.subsec_nanos()),
                    )
                }
            },
            Err(_) => (0, 0),
        }
    }
}

/// clonefile 失败是否意味着「本机不支持克隆，应走有界独立拷贝回退」。
#[cfg(unix)]
fn clone_unsupported(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOTSUP) | Some(libc::EXDEV))
}

/// Windows 无 fclonefileat：一律走回退路径（普通 read/write 复制）。
#[cfg(windows)]
fn clone_unsupported(_error: &std::io::Error) -> bool {
    true
}

#[cfg(windows)]
fn entry_stat_from_metadata(
    metadata: &std::fs::Metadata,
    identity: crate::platform::FileIdentity,
) -> EntryStat {
    let kind = if metadata.file_type().is_symlink() {
        S_IFLNK
    } else if metadata.is_dir() {
        S_IFDIR
    } else {
        S_IFREG
    };
    let (st_mtime, st_mtime_nsec) = metadata_mtime_pair(metadata);
    EntryStat {
        st_dev: identity.dev,
        st_ino: identity.ino,
        st_mode: kind | crate::platform::metadata_mode(metadata),
        st_uid: 0,
        st_gid: 0,
        st_nlink: identity.nlink,
        st_size: metadata.len(),
        st_mtime,
        st_mtime_nsec,
    }
}

use csswitch_skill_install_core::{open_science_health_session_before, ScienceHealthSession};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{Manager, Runtime};

use crate::runtime::operation::{
    self, OperationKind, OperationStage, OperationTrace, POLL_INTERVAL_MS,
};
use crate::runtime::proxy::ProxyAction;
use crate::runtime::proxy_lifecycle::{
    current_skill_install_bridge_key, ensure_proxy, skill_install_bridge_dir, start_proxy_for,
};
use crate::runtime::science::{
    probe_known_runtime, probe_sandbox_runtime_cached, runtime_identity_is_current,
    sandbox_data_dir, sandbox_home, sandbox_listener_matches_runtime, sandbox_url,
    select_science_runtime_cached, stop_sandbox, stop_sandbox_with_launch_token,
    SandboxScienceState, ScienceManagedLaunchToken, ScienceRuntimeIdentity, ScienceRuntimeSource,
};
use crate::runtime::skill_install_bridge::{
    configure_third_party_after_science_start, inspect_while_science_running,
    invalidate_route_configuration, mark_route_configuration_current,
    register_before_science_start, route_configuration_is_current, RegistrationStatus,
};
use crate::runtime::system::{asset_root, log_path, open_in_browser, open_log, redact, tail_file};
use crate::{
    config, lifecycle, lock, oauth_forge, proc, AppState, HistoryRecoveryChoice,
    HistoryRecoverySession, SharedAppState,
};

#[allow(clippy::useless_conversion)]
#[cfg(unix)]
fn inode_u64(value: libc::ino_t) -> Option<u64> {
    u64::try_from(value).ok()
}

/// Windows 身份原语已给出 u64 inode，无需转换。
#[cfg(windows)]
fn inode_u64(value: u64) -> Option<u64> {
    Some(value)
}

#[allow(dead_code)]
fn stop_sandbox_state<R: Runtime>(
    app: &tauri::AppHandle<R>,
    st: &mut AppState,
) -> Result<(), String> {
    let runtime = st.science_runtime.clone();
    let result = stop_sandbox(app, &mut st.sandbox, &mut st.sandbox_url, runtime.as_ref());
    if result.is_ok() {
        st.science_confirmed_stopped = runtime;
        st.science_runtime = None;
    }
    result
}

fn open_science_surface<R: Runtime>(
    app: &tauri::AppHandle<R>,
    url: &str,
) -> Result<&'static str, String> {
    if std::env::var("CSSWITCH_SCIENCE_WEBVIEW_SPIKE")
        .ok()
        .as_deref()
        == Some("1")
    {
        if let Some(win) = app.get_webview_window("science") {
            let _ = win.close();
        }
        let parsed = url
            .parse()
            .map_err(|e| format!("Science URL 解析失败：{e}"))?;
        match tauri::WebviewWindowBuilder::new(app, "science", tauri::WebviewUrl::External(parsed))
            .title("Claude Science")
            .inner_size(1100.0, 800.0)
            .build()
        {
            Ok(win) => {
                let _ = win.set_focus();
                return Ok("webview");
            }
            Err(_) => {
                // Spike-only path: construction failure falls through to the existing browser surface.
            }
        }
    }
    open_in_browser(url)?;
    Ok("browser")
}

fn installer_status_json(status: &RegistrationStatus) -> Value {
    match status {
        RegistrationStatus::Warning(message) => {
            json!({"status": status.code(), "message": message})
        }
        _ => json!({"status": status.code()}),
    }
}

fn append_installer_note(mut message: String, status: &RegistrationStatus) -> String {
    if let Some(note) = status.user_note() {
        message.push_str(&format!(" {note}"));
    }
    message
}

struct AuthorityTreeSnapshot {
    scope: AuthoritySnapshotScope,
    source: PathBuf,
    backup: PathBuf,
    existed: bool,
    source_parent: Option<DirHandle>,
    source_name: Option<std::ffi::CString>,
    backup_identity: Option<(u64, u64, ModeT)>,
    backup_parent: Option<DirHandle>,
    backup_name: Option<std::ffi::CString>,
}

/// readdir 流（unix 专用；Windows 用 read_dir 枚举，无需流包装）。
#[cfg(unix)]
struct AuthorityDirectoryStream(*mut libc::DIR);

#[cfg(unix)]
impl Drop for AuthorityDirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

const MAX_AUTHORITY_SNAPSHOT_ENTRIES: usize = 131_072;
const MAX_AUTHORITY_SNAPSHOT_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_AUTHORITY_SNAPSHOT_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
// 单文件可复制上限：超过即视为 Science 自有大内容，跳过复制（原地保留）。
// 真机实测数据目录含 200-500MB 级文件（Electron 主程序、Agent 产物 CSV）。
const MAX_AUTHORITY_SNAPSHOT_COPYABLE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AUTHORITY_FULL_COPY_FILE_BYTES: u64 = MAX_AUTHORITY_SNAPSHOT_FILE_BYTES;
const MAX_AUTHORITY_FULL_COPY_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const SCIENCE_OWNED_OPAQUE_ROOTS: [&str; 5] =
    ["conda", "runtime", "seed-assets", "r-libs", "sbx-bind-src"];
pub(crate) const SCIENCE_PROTECTED_AUTHORITY_ENTRIES: [&str; 10] = [
    "encryption.key",
    ".oauth-tokens",
    "active-org.json",
    ".key-backups",
    "auth-owner.lock",
    "config.toml",
    "csswitch-ssh-bridge.v1.json",
    "mcp",
    ".csswitch-route-state.json",
    "orgs",
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum AuthoritySnapshotScope {
    ScienceData,
    SandboxState,
    CsswitchRuntime,
    ManagedReceipt,
    #[default]
    Test,
}

impl AuthoritySnapshotScope {
    fn code(self) -> &'static str {
        match self {
            Self::ScienceData => "science_data",
            Self::SandboxState => "sandbox_state",
            Self::CsswitchRuntime => "csswitch_runtime",
            Self::ManagedReceipt => "managed_receipt",
            Self::Test => "test",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum AuthoritySnapshotCategory {
    CondaCache,
    ScienceRuntime,
    Skills,
    OrgState,
    #[default]
    Other,
}

impl AuthoritySnapshotCategory {
    fn code(self) -> &'static str {
        match self {
            Self::CondaCache => "conda_cache",
            Self::ScienceRuntime => "science_runtime",
            Self::Skills => "skills",
            Self::OrgState => "org_state",
            Self::Other => "other",
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct SandboxSessionTestSeams {
    cleanup_fault: Option<(PathBuf, String, PathBuf)>,
    cleanup_calls: usize,
    capture_fail_source: Option<PathBuf>,
    authority_clone_errno: Option<(std::thread::ThreadId, i32)>,
    authority_fallback_fail_after_create: Option<std::thread::ThreadId>,
    authority_completion_sync_failure: Option<std::thread::ThreadId>,
    authority_cleanup_parent_sync_failure: Option<std::thread::ThreadId>,
    directory_barrier: Option<(PathBuf, PathBuf)>,
    snapshot_parent_barrier: Option<(PathBuf, PathBuf)>,
    one_click_capture: Option<(PathBuf, PathBuf, bool, u32, PathBuf)>,
    catalog_failure_port: Option<u16>,
    catalog_bypass_port: Option<u16>,
    prior_restart_post_spawn_failure_port: Option<u16>,
    prior_restart_post_spawn_identity: Option<(u32, String)>,
    rollback_diagnostic_canary: Option<String>,
    rollback_diagnostic_snapshot: Option<PathBuf>,
}

#[cfg(test)]
static SANDBOX_SESSION_TEST_SEAMS: std::sync::LazyLock<std::sync::Mutex<SandboxSessionTestSeams>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(SandboxSessionTestSeams::default()));

#[cfg(test)]
#[allow(dead_code)] // 仅 unix 门控测试会构造 guard；Windows 测试构建下保持编译
pub(crate) struct SandboxSessionTestSeamGuard;

#[cfg(test)]
impl Drop for SandboxSessionTestSeamGuard {
    fn drop(&mut self) {
        *SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = SandboxSessionTestSeams::default();
    }
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_authority_snapshot_cleanup_fault(
    scope: PathBuf,
    mode: &str,
    log: PathBuf,
) -> SandboxSessionTestSeamGuard {
    let mut seams = SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    seams.cleanup_fault = Some((scope, mode.to_string(), log));
    seams.cleanup_calls = 0;
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_authority_snapshot_capture_failure(
    source: PathBuf,
) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .capture_fail_source = Some(source);
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
fn test_arm_authority_snapshot_clone_errno(errno: i32) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .authority_clone_errno = Some((std::thread::current().id(), errno));
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
fn test_arm_authority_snapshot_fallback_create_failure() -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .authority_fallback_fail_after_create = Some(std::thread::current().id());
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
fn test_arm_authority_snapshot_completion_sync_failure() -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .authority_completion_sync_failure = Some(std::thread::current().id());
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
fn test_arm_authority_cleanup_parent_sync_failure() -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .authority_cleanup_parent_sync_failure = Some(std::thread::current().id());
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_authority_snapshot_directory_barrier(
    source: PathBuf,
    barrier: PathBuf,
) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .directory_barrier = Some((source, barrier));
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
fn test_arm_authority_snapshot_parent_barrier(
    target: PathBuf,
    barrier: PathBuf,
) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .snapshot_parent_barrier = Some((target, barrier));
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_one_click_snapshot_capture(
    config_dir: PathBuf,
    observation: PathBuf,
    fail: bool,
    expected_prior_pid: u32,
    expected_receipt: PathBuf,
) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .one_click_capture = Some((
        config_dir,
        observation,
        fail,
        expected_prior_pid,
        expected_receipt,
    ));
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_healthy_reopen_catalog_failure(port: u16) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .catalog_failure_port = Some(port);
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_gateway_catalog_bypass(port: u16) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .catalog_bypass_port = Some(port);
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_prior_restart_post_spawn_failure(port: u16) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .prior_restart_post_spawn_failure_port = Some(port);
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
pub(crate) fn test_prior_restart_post_spawn_identity() -> Option<(u32, String)> {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .prior_restart_post_spawn_identity
        .clone()
}

#[cfg(all(test, unix))]
pub(crate) fn test_arm_rollback_diagnostic_canary(canary: &str) -> SandboxSessionTestSeamGuard {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .rollback_diagnostic_canary = Some(canary.to_string());
    SandboxSessionTestSeamGuard
}

#[cfg(all(test, unix))]
pub(crate) fn test_rollback_diagnostic_snapshot() -> Option<PathBuf> {
    SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .rollback_diagnostic_snapshot
        .clone()
}

fn sync_authority_cleanup_parent(parent: &DirHandle) -> std::io::Result<()> {
    #[cfg(test)]
    if SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .authority_cleanup_parent_sync_failure
        .is_some_and(|thread| thread == std::thread::current().id())
    {
        #[cfg(unix)]
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
        #[cfg(windows)]
        return Err(std::io::Error::other(
            "test-only authority cleanup parent sync failure",
        ));
    }
    handle_sync(parent)
}

fn remove_authority_snapshot_root(
    entry: &PendingCleanupEntry,
    expected_parent: &Path,
) -> std::io::Result<()> {
    let path = &entry.path;
    #[cfg(test)]
    {
        let observation = {
            let mut seams = SANDBOX_SESSION_TEST_SEAMS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let configured = seams
                .cleanup_fault
                .as_ref()
                .filter(|(scope, _, _)| path.starts_with(scope))
                .cloned();
            configured.map(|(_, mode, log_path)| {
                let attempt = seams.cleanup_calls;
                seams.cleanup_calls += 1;
                let injected = mode == "persistent" || (mode == "once" && attempt == 0);
                (attempt, injected, log_path)
            })
        };
        if let Some((attempt, injected, log_path)) = observation {
            if let Ok(mut log) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
            {
                use std::io::Write;
                let _ = writeln!(
                    log,
                    "{}\t{}\t{}",
                    attempt + 1,
                    if injected { "injected" } else { "real" },
                    path.display()
                );
            }
            if injected {
                return Err(std::io::Error::other(
                    "test-only authority snapshot cleanup failure",
                ));
            }
        }
    }
    let parent = AuthorityTreeSnapshot::open_absolute_directory(expected_parent)
        .map_err(|e| { eprintln!("[cleanup-diag] open_absolute_directory: {e}"); e })?;
    let name = AuthorityTreeSnapshot::destination_name(path).map_err(std::io::Error::other)?;
    let tombstone_name = std::ffi::CString::new(cleanup_tombstone_name(entry))
        .map_err(|_| std::io::Error::other("invalid cleanup tombstone name"))?;
    let inspect =
        |name: &std::ffi::CStr| match AuthorityTreeSnapshot::stat_destination_at(&parent, name) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        };
    // mac 上 EntryStat=libc::stat 的 st_dev 非 u64，try_from 是真转换；Windows 侧类型已是 u64。
    #[allow(clippy::useless_conversion)]
    let identity_matches = |current: &EntryStat| {
        current.st_mode & S_IFMT == S_IFDIR
            && u64::try_from(current.st_dev).ok() == Some(entry.device)
            && inode_u64(current.st_ino) == Some(entry.inode)
            && current.st_mode & 0o777 == 0o700
            && current.st_uid == current_uid()
    };
    let current_stat = inspect(&name)?;
    let tombstone_stat = inspect(&tombstone_name)?;
    match (current_stat, tombstone_stat) {
        (None, None) => return sync_authority_cleanup_parent(&parent),
        (Some(current), None) if identity_matches(&current) => {
            let rename_result: Result<(), std::io::Error> = {
                #[cfg(unix)]
                {
                    use std::os::fd::AsRawFd;
                    let renamed = unsafe {
                        libc::renameat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            parent.as_raw_fd(),
                            tombstone_name.as_ptr(),
                        )
                    };
                    if renamed == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                }
                #[cfg(windows)]
                {
                    // Windows 无 renameat：以“不覆盖 rename”原语按完整路径把
                    // 快照目录改名为 tombstone（目标此前已确认不存在）。
                    let from = dir_path(&parent).join(name.to_string_lossy().as_ref());
                    let to = dir_path(&parent).join(tombstone_name.to_string_lossy().as_ref());
                    crate::platform::rename_no_replace(&from, &to)
                }
            };
            match rename_result {
                Ok(()) => {
                    sync_authority_cleanup_parent(&parent)?;
                }
                Err(e) if e.raw_os_error() == Some(5) => {
                    // Windows 实测（0.1.56 真机 + 本测试）：即使目录树内句柄均
                    // 已声明共享删除，MoveFileExW 对目录改名仍可能报
                    // ACCESS_DENIED。墓碑改名只为崩溃可发现性，而快照目录内
                    // 本就有 marker 标识身份——直接原地删除同样可被下次启动
                    // 识别并继续修复。
                    AuthorityTreeSnapshot::remove_tree_at(&parent, &name)?;
                    sync_authority_cleanup_parent(&parent)?;
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
        (None, Some(current)) if identity_matches(&current) => {
            sync_authority_cleanup_parent(&parent)?;
        }
        _ => {
            eprintln!("[cleanup-diag] identity mismatch: neither (present,matches) nor (tombstone,matches)");
            return Err(std::io::Error::other(
                "authority snapshot cleanup identity changed",
            ))
        }
    }
    let tombstone = AuthorityTreeSnapshot::stat_destination_at(&parent, &tombstone_name)?;
    if !identity_matches(&tombstone) {
        eprintln!("[cleanup-diag] tombstone identity changed after rename");
        return Err(std::io::Error::other(
            "authority snapshot cleanup tombstone identity changed",
        ));
    }
    if let Err(e) = AuthorityTreeSnapshot::remove_tree_at(&parent, &tombstone_name) {
        eprintln!("[cleanup-diag] remove_tree_at: {e}");
        return Err(e);
    }
    if let Err(e) = sync_authority_cleanup_parent(&parent) {
        eprintln!("[cleanup-diag] final sync: {e}");
        return Err(e);
    }
    Ok(())
}



fn remove_authority_snapshot_root_with_retry(
    entry: &PendingCleanupEntry,
    expected_parent: &Path,
) -> Result<(), String> {
    match remove_authority_snapshot_root(entry, expected_parent) {
        Ok(()) => Ok(()),
        Err(first) => {
            // Windows：刚终止的 daemon/子进程释放目录句柄需要时间；退避重试
            // 三次（共约 6 秒）仍失败才放弃。
            let mut last = first;
            for _ in 0..3 {
                std::thread::sleep(std::time::Duration::from_millis(2_000));
                match remove_authority_snapshot_root(entry, expected_parent) {
                    Ok(()) => return Ok(()),
                    Err(second) => last = second,
                }
            }
            Err(format!("首次清理失败：{last}；退避重试三次仍失败"))
        }
    }
}

const PENDING_CLEANUP_MARKER_FILE: &str = ".csswitch-one-click-rollback.marker";
const MAX_PENDING_CLEANUP_MANIFEST_BYTES: usize = 64 * 1024;

fn cleanup_tombstone_name(entry: &PendingCleanupEntry) -> String {
    format!("{}.deleting", entry.managed_id)
}

fn cleanup_tombstone_path(entry: &PendingCleanupEntry) -> PathBuf {
    entry
        .path
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join(cleanup_tombstone_name(entry))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingCleanupManifest {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disposition: Option<PendingCleanupDisposition>,
    entries: Vec<PendingCleanupEntry>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PendingCleanupDisposition {
    ActiveRecovery,
    CleanupOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingCleanupEntry {
    managed_id: String,
    path: PathBuf,
    device: u64,
    inode: u64,
    marker: String,
}

#[derive(Clone)]
struct AuthorityCleanupContext {
    config_dir: PathBuf,
    expected_snapshot_parent: PathBuf,
    managed_id: String,
    root: PathBuf,
    expected_root_identity: Option<(u64, u64)>,
    state: SharedAppState,
}

struct RegisteredAuthorityCleanup {
    manifest_raw: Vec<u8>,
    entry: PendingCleanupEntry,
}

#[derive(Clone)]
struct PendingCleanupClearRetry {
    config_dir: PathBuf,
    manifest_raw: Vec<u8>,
    entry: PendingCleanupEntry,
}

static PENDING_CLEANUP_CLEAR_RETRY: std::sync::LazyLock<
    std::sync::Mutex<Option<PendingCleanupClearRetry>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

enum PendingCleanupTargetState {
    Missing,
    Present(PendingCleanupEntry),
    Unsafe,
}

fn cleanup_required_error(primary: &str, path: &Path, code: &str) -> String {
    format!(
        "{primary}；status=degraded；recovery_status=cleanup_required；recovery_path={}；cleanup_code={code}",
        path.display()
    )
}

fn pending_cleanup_name_is_valid(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(".one-click-rollback-") else {
        return false;
    };
    suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn pending_cleanup_manifest_bytes(
    entries: Vec<PendingCleanupEntry>,
    disposition: PendingCleanupDisposition,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&PendingCleanupManifest {
        schema_version: 2,
        disposition: Some(disposition),
        entries,
    })
    .map_err(|_| "cleanup_manifest_encode_failed：无法编码待清理事务清单。".into())
}

fn parse_pending_cleanup_manifest(bytes: &[u8]) -> Result<PendingCleanupManifest, String> {
    if bytes.is_empty() || bytes.len() > MAX_PENDING_CLEANUP_MANIFEST_BYTES {
        return Err("cleanup_manifest_invalid：待清理事务清单大小非法，已在运行前拒绝。".into());
    }
    let manifest: PendingCleanupManifest = serde_json::from_slice(bytes)
        .map_err(|_| "cleanup_manifest_invalid：待清理事务清单格式非法，已在运行前拒绝。")?;
    let schema_valid = match manifest.schema_version {
        1 => manifest.disposition.is_none(),
        2 => manifest.disposition.is_some(),
        _ => false,
    };
    if !schema_valid || manifest.entries.len() > 1 {
        return Err(
            "cleanup_manifest_invalid：待清理事务清单版本或条目数量非法，已在运行前拒绝。".into(),
        );
    }
    Ok(manifest)
}

fn pending_cleanup_requires_recovery(manifest: &PendingCleanupManifest) -> bool {
    manifest.disposition == Some(PendingCleanupDisposition::ActiveRecovery)
}

fn read_marker(path: &Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "cleanup_identity_invalid：事务快照 marker 不可用。".to_string())?;
    let identity = crate::platform::identity_of_path(path)
        .map_err(|_| "cleanup_identity_invalid：事务快照 marker 身份不安全。".to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !crate::platform::file_owner_is_current(&metadata)
        || crate::platform::metadata_mode(&metadata) & 0o777 != 0o600
        || identity.nlink != 1
        || metadata.len() > 256
    {
        return Err("cleanup_identity_invalid：事务快照 marker 身份不安全。".into());
    }
    let mut file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Windows：FILE_FLAG_OPEN_REPARSE_POINT 打开 reparse point 本身
            // （不跟随），随后以打开后身份复核防替换。
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(crate::platform::no_follow_flags())
                .open(path)
        }
    }
    .map_err(|_| "cleanup_identity_invalid：无法安全打开事务快照 marker。")?;
    let opened = crate::platform::identity_of_file(&file)
        .map_err(|_| "cleanup_identity_invalid：无法复核事务快照 marker。")?;
    if opened.dev != identity.dev || opened.ino != identity.ino {
        return Err("cleanup_identity_changed：事务快照 marker 在读取前发生变化。".into());
    }
    let mut bytes = Vec::new();
    std::io::Read::take(&mut file, 257)
        .read_to_end(&mut bytes)
        .map_err(|_| "cleanup_identity_invalid：无法读取事务快照 marker。")?;
    if bytes.len() > 256 {
        return Err("cleanup_identity_invalid：事务快照 marker 过大。".into());
    }
    String::from_utf8(bytes)
        .map_err(|_| "cleanup_identity_invalid：事务快照 marker 不是 UTF-8。".into())
}

fn inspect_pending_cleanup_target(entry: &PendingCleanupEntry) -> PendingCleanupTargetState {
#[allow(dead_code)] // 仅 unix 测试会触发；Windows 测试构建下保持编译
    let (actual_path, metadata, is_tombstone) = match std::fs::symlink_metadata(&entry.path) {
        Ok(metadata) => (entry.path.clone(), metadata, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let tombstone = cleanup_tombstone_path(entry);
            match std::fs::symlink_metadata(&tombstone) {
                Ok(metadata) => (tombstone, metadata, true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return PendingCleanupTargetState::Missing
                }
                Err(_) => return PendingCleanupTargetState::Unsafe,
            }
        }
        Err(_) => return PendingCleanupTargetState::Unsafe,
    };
    let marker = match read_marker(&actual_path.join(PENDING_CLEANUP_MARKER_FILE)) {
        Ok(marker) => marker,
        Err(_) if is_tombstone => format!("{}\n", entry.marker),
        Err(_) => return PendingCleanupTargetState::Unsafe,
    };
    let marker = marker.strip_suffix('\n').unwrap_or(&marker).to_string();
    let identity = match crate::platform::identity_of_path(&actual_path) {
        Ok(identity) => identity,
        Err(_) => return PendingCleanupTargetState::Unsafe,
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !crate::platform::file_owner_is_current(&metadata)
        || crate::platform::metadata_mode(&metadata) & 0o777 != 0o700
    {
        return PendingCleanupTargetState::Unsafe;
    }
    PendingCleanupTargetState::Present(PendingCleanupEntry {
        managed_id: entry.managed_id.clone(),
        path: entry.path.clone(),
        device: identity.dev,
        inode: identity.ino,
        marker,
    })
}

fn validate_pending_cleanup_entry(
    entry: &PendingCleanupEntry,
    expected_parent: &Path,
) -> Result<PendingCleanupTargetState, String> {
    if !pending_cleanup_name_is_valid(&entry.managed_id)
        || entry.marker != entry.managed_id
        || entry.path.parent() != Some(expected_parent)
        || entry.path.file_name().and_then(|name| name.to_str()) != Some(entry.managed_id.as_str())
    {
        return Err(
            "cleanup_manifest_invalid：待清理事务清单路径或 managed_id 非法，已在运行前拒绝。"
                .into(),
        );
    }
    match inspect_pending_cleanup_target(entry) {
        PendingCleanupTargetState::Missing => Ok(PendingCleanupTargetState::Missing),
        PendingCleanupTargetState::Present(current)
            if current.device == entry.device
                && current.inode == entry.inode
                && current.marker == entry.marker =>
        {
            Ok(PendingCleanupTargetState::Present(current))
        }
        _ => Err(
            "cleanup_manifest_identity_mismatch：待清理事务快照身份不一致，已在运行前拒绝。".into(),
        ),
    }
}

#[cfg(test)]
fn test_pending_cleanup_identity(entry: &PendingCleanupEntry) -> config::PendingCleanupIdentity {
    config::PendingCleanupIdentity {
        managed_id: entry.managed_id.clone(),
        path: entry.path.clone(),
        device: entry.device,
        inode: entry.inode,
        marker: entry.marker.clone(),
    }
}

impl AuthorityCleanupContext {
    fn new(config_dir: &Path, sandbox_home: &Path, state: &SharedAppState) -> Result<Self, String> {
        let expected_snapshot_parent = sandbox_home
            .parent()
            .ok_or("cleanup_register_failed：沙箱 HOME 无父目录。")?
            .to_path_buf();
        let managed_id = format!(".one-click-rollback-{}", config::new_id());
        let root = expected_snapshot_parent.join(&managed_id);
        Ok(Self {
            config_dir: config_dir.to_path_buf(),
            expected_snapshot_parent,
            managed_id,
            root,
            expected_root_identity: None,
            state: state.clone(),
        })
    }

    fn bind_root_identity(&mut self, entry: &EntryStat) -> Result<(), String> {
        #[allow(clippy::useless_conversion)]
        let device = u64::try_from(entry.st_dev)
            .map_err(|_| self.register_error("事务快照 device 非法。"))?;
        let inode =
            inode_u64(entry.st_ino).ok_or_else(|| self.register_error("事务快照 inode 非法。"))?;
        if entry.st_mode & S_IFMT != S_IFDIR {
            return Err(self.register_error("事务快照不是目录。"));
        }
        self.expected_root_identity = Some((device, inode));
        Ok(())
    }

    fn register_error(&self, detail: &str) -> String {
        format!(
            "cleanup_register_failed：{detail}；recovery_path={}",
            self.root.display()
        )
    }
}

fn register_authority_cleanup(
    context: &AuthorityCleanupContext,
) -> Result<RegisteredAuthorityCleanup, String> {
    if context.root.parent() != Some(context.expected_snapshot_parent.as_path())
        || context.root.file_name().and_then(|name| name.to_str())
            != Some(context.managed_id.as_str())
        || !pending_cleanup_name_is_valid(&context.managed_id)
    {
        return Err(context.register_error("事务快照路径不在受管根内。"));
    }
    let parent = AuthorityTreeSnapshot::open_absolute_directory(&context.expected_snapshot_parent)
        .map_err(|_| context.register_error("事务快照父目录不可用。"))?;
    let root_name = AuthorityTreeSnapshot::destination_name(&context.root)
        .map_err(|_| context.register_error("事务快照名称非法。"))?;
    let root = AuthorityTreeSnapshot::open_directory_at(&parent, &root_name)
        .map_err(|_| context.register_error("事务快照不可用。"))?;
    let before = handle_metadata(&root).map_err(|_| context.register_error("事务快照不可用。"))?;
    let before_identity = crate::platform::identity_of_file(dir_file(&root))
        .map_err(|_| context.register_error("事务快照不可用。"))?;
    let before_entry = AuthorityTreeSnapshot::stat_destination_at(&parent, &root_name)
        .map_err(|_| context.register_error("事务快照不可用。"))?;
    let Some((expected_device, expected_inode)) = context.expected_root_identity else {
        return Err(context.register_error("事务快照创建身份缺失。"));
    };
    if !before.is_dir()
        || !crate::platform::file_owner_is_current(&before)
        || crate::platform::metadata_mode(&before) & 0o777 != 0o700
        || before_identity.dev != expected_device
        || before_identity.ino != expected_inode
        || !AuthorityTreeSnapshot::destination_entry_matches_file(&before_entry, dir_file(&root), S_IFDIR)
    {
        return Err(context.register_error("事务快照身份不安全。"));
    }
    let marker_name = std::ffi::CString::new(PENDING_CLEANUP_MARKER_FILE).unwrap();
    match AuthorityTreeSnapshot::stat_destination_at(&root, &marker_name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut marker = AuthorityTreeSnapshot::open_destination_at(
                &root,
                &marker_name,
                O_WRONLY | O_CREAT | O_EXCL,
                0o600,
            )
            .map_err(|_| context.register_error("无法创建事务快照 marker。"))?;
            std::io::Write::write_all(&mut marker, format!("{}\n", context.managed_id).as_bytes())
                .and_then(|_| apply_file_mode(&marker, 0o600))
                .and_then(|_| marker.sync_all())
                .map_err(|_| context.register_error("无法持久化事务快照 marker。"))?;
            let metadata = marker
                .metadata()
                .map_err(|_| context.register_error("无法复核事务快照 marker。"))?;
            if !metadata.is_file()
                || !crate::platform::file_owner_is_current(&metadata)
                || crate::platform::metadata_mode(&metadata) & 0o777 != 0o600
                || file_nlink(&marker).ok() != Some(1)
                || metadata.len() > 256
            {
                return Err(context.register_error("事务快照 marker 身份不安全。"));
            }
            handle_sync(&root)
                .and_then(|_| handle_sync(&parent))
                .map_err(|_| context.register_error("无法持久化事务快照目录。"))?;
        }
        Ok(_) => {
            let mut marker = AuthorityTreeSnapshot::open_destination_at(
                &root,
                &marker_name,
                O_RDONLY,
                0,
            )
            .map_err(|_| context.register_error("事务快照 marker 身份不安全。"))?;
            let metadata = marker
                .metadata()
                .map_err(|_| context.register_error("事务快照 marker 身份不安全。"))?;
            if !metadata.is_file()
                || !crate::platform::file_owner_is_current(&metadata)
                || crate::platform::metadata_mode(&metadata) & 0o777 != 0o600
                || file_nlink(&marker).ok() != Some(1)
                || metadata.len() > 256
            {
                return Err(context.register_error("事务快照 marker 身份不安全。"));
            }
            let mut bytes = Vec::new();
            std::io::Read::take(&mut marker, 257)
                .read_to_end(&mut bytes)
                .map_err(|_| context.register_error("无法读取事务快照 marker。"))?;
            if bytes != format!("{}\n", context.managed_id).as_bytes() {
                return Err(context.register_error("事务快照 marker 不匹配。"));
            }
        }
        Err(_) => return Err(context.register_error("无法检查事务快照 marker。")),
    }
    let after = handle_metadata(&root)
        .map_err(|_| context.register_error("无法复核事务快照。"))?;
    let after_identity = crate::platform::identity_of_file(dir_file(&root))
        .map_err(|_| context.register_error("无法复核事务快照。"))?;
    let after_entry = AuthorityTreeSnapshot::stat_destination_at(&parent, &root_name)
        .map_err(|_| context.register_error("无法复核事务快照。"))?;
    if after_identity.dev != before_identity.dev
        || after_identity.ino != before_identity.ino
        || !after.is_dir()
        || !crate::platform::file_owner_is_current(&after)
        || crate::platform::metadata_mode(&after) & 0o777 != 0o700
        || !AuthorityTreeSnapshot::destination_entry_matches_file(
            &after_entry,
            dir_file(&root),
            S_IFDIR,
        )
    {
        return Err(context.register_error("事务快照在注册期间发生变化。"));
    }
    let entry = PendingCleanupEntry {
        managed_id: context.managed_id.clone(),
        path: context.root.clone(),
        device: after_identity.dev,
        inode: after_identity.ino,
        marker: context.managed_id.clone(),
    };
    if !matches!(
        validate_pending_cleanup_entry(&entry, &context.expected_snapshot_parent),
        Ok(PendingCleanupTargetState::Present(ref current)) if current == &entry
    ) {
        return Err(context.register_error("事务快照持久化后身份复核失败。"));
    }
    #[cfg(test)]
    config::test_pending_cleanup_register_publish_attempt(test_pending_cleanup_identity(&entry))
        .map_err(|_| context.register_error("待清理事务清单 REGISTER 发布失败。"))?;
    let previous = config::read_pending_authority_cleanup_manifest(&context.config_dir)
        .map_err(|_| context.register_error("无法读取待清理事务清单。"))?;
    if let Some(bytes) = previous.as_deref() {
        let existing = parse_pending_cleanup_manifest(bytes)
            .map_err(|_| context.register_error("现有待清理事务清单非法。"))?;
        if !existing.entries.is_empty() && existing.entries != [entry.clone()] {
            return Err(context.register_error("已有不同的待清理事务快照。"));
        }
    }
    let manifest_raw = pending_cleanup_manifest_bytes(
        vec![entry.clone()],
        PendingCleanupDisposition::ActiveRecovery,
    )
    .map_err(|_| context.register_error("无法编码待清理事务清单。"))?;
    let publish = match previous.as_deref() {
        Some(expected) => config::write_pending_authority_cleanup_manifest(
            &context.config_dir,
            &manifest_raw,
            Some(expected),
        ),
        None => config::write_pending_authority_cleanup_manifest_if_absent(
            &context.config_dir,
            &manifest_raw,
        ),
    };
    publish.map_err(|_| context.register_error("无法原子提交待清理事务清单。"))?;
    let mut current = lock(&context.state);
    if !current
        .pending_authority_cleanup
        .iter()
        .any(|pending| pending == &context.root)
    {
        current.pending_authority_cleanup.push(context.root.clone());
    }
    Ok(RegisteredAuthorityCleanup {
        manifest_raw,
        entry,
    })
}

fn finalize_failed_authority_snapshot(
    context: &AuthorityCleanupContext,
    primary: String,
) -> String {
    let cleanup = register_authority_cleanup(context)
        .and_then(|ticket| prepare_registered_authority_cleanup(context, &ticket))
        .and_then(|ticket| finalize_registered_authority_cleanup(context, &ticket));
    match cleanup {
        Ok(()) => primary,
        Err(cleanup_error) => format!("{primary}；{cleanup_error}"),
    }
}

fn publish_pending_cleanup_clear(
    state: &SharedAppState,
    config_dir: &Path,
    manifest_raw: &[u8],
    entry: &PendingCleanupEntry,
    observe_recovery: bool,
) -> Result<(), String> {
    #[cfg(not(test))]
    let _ = observe_recovery;
    let empty = pending_cleanup_manifest_bytes(Vec::new(), PendingCleanupDisposition::CleanupOnly)?;
    config::write_pending_authority_cleanup_manifest(config_dir, &empty, Some(manifest_raw))
        .map_err(|_| {
            cleanup_required_error(
                "待清理事务快照已移除，但清单 CLEAR 未提交",
                &entry.path,
                "cleanup_clear_failed",
            )
        })?;
    #[cfg(test)]
    if observe_recovery {
        config::test_observe_pending_cleanup_clear_published();
    }
    lock(state)
        .pending_authority_cleanup
        .retain(|pending| pending != &entry.path);
    *PENDING_CLEANUP_CLEAR_RETRY
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
    Ok(())
}

fn retry_completed_pending_cleanup_clear(state: &SharedAppState) -> Result<bool, String> {
    let retry = PENDING_CLEANUP_CLEAR_RETRY
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let Some(retry) = retry else {
        return Ok(false);
    };
    let current = config::read_pending_authority_cleanup_manifest(&retry.config_dir)
        .map_err(|_| "cleanup_manifest_read_failed：无法读取待清理事务清单。")?;
    if current.as_deref() != Some(retry.manifest_raw.as_slice())
        || !matches!(
            inspect_pending_cleanup_target(&retry.entry),
            PendingCleanupTargetState::Missing
        )
    {
        *PENDING_CLEANUP_CLEAR_RETRY
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        return Ok(false);
    }
    publish_pending_cleanup_clear(
        state,
        &retry.config_dir,
        &retry.manifest_raw,
        &retry.entry,
        true,
    )?;
    Ok(true)
}

fn finalize_registered_authority_cleanup(
    context: &AuthorityCleanupContext,
    ticket: &RegisteredAuthorityCleanup,
) -> Result<(), String> {
    let manifest_raw = config::read_pending_authority_cleanup_manifest(&context.config_dir)
        .map_err(|_| "cleanup_manifest_read_failed：无法安全读取刚注册的待清理事务清单。")?
        .ok_or("cleanup_manifest_missing：刚注册的待清理事务清单不存在。")?;
    if manifest_raw != ticket.manifest_raw {
        return Err(
            "cleanup_manifest_causal_mismatch：刚注册的待清理事务清单字节票据不匹配。".into(),
        );
    }
    let manifest = parse_pending_cleanup_manifest(&manifest_raw)?;
    if manifest.entries.len() != 1 || manifest.entries.first() != Some(&ticket.entry) {
        return Err(
            "cleanup_manifest_causal_mismatch：刚注册的待清理事务清单因果票据不匹配。".into(),
        );
    }
    if pending_cleanup_requires_recovery(&manifest) {
        return Err(
            "cleanup_manifest_active_recovery：活动恢复快照未转换为 cleanup-only，拒绝删除。"
                .into(),
        );
    }
    match validate_pending_cleanup_entry(&ticket.entry, &context.expected_snapshot_parent)? {
        PendingCleanupTargetState::Present(actual) if actual == ticket.entry => {}
        _ => {
            return Err(
                "cleanup_identity_changed：刚注册的事务快照在删除前发生变化，已停止清理。".into(),
            )
        }
    }
    if remove_authority_snapshot_root_with_retry(&ticket.entry, &context.expected_snapshot_parent)
        .is_err()
    {
        return Err(cleanup_required_error(
            "one-click 事务快照仍无法清理",
            &ticket.entry.path,
            "cleanup_remove_failed",
        ));
    }
    if !matches!(
        inspect_pending_cleanup_target(&ticket.entry),
        PendingCleanupTargetState::Missing
    ) {
        return Err("cleanup_identity_changed：刚注册的事务快照删除后仍存在，已停止清理。".into());
    }
    publish_pending_cleanup_clear(
        &context.state,
        &context.config_dir,
        &manifest_raw,
        &ticket.entry,
        false,
    )?;
    Ok(())
}

fn prepare_registered_authority_cleanup(
    context: &AuthorityCleanupContext,
    ticket: &RegisteredAuthorityCleanup,
) -> Result<RegisteredAuthorityCleanup, String> {
    let current = config::read_pending_authority_cleanup_manifest(&context.config_dir)
        .map_err(|_| "cleanup_manifest_read_failed：无法读取活动恢复快照清单。")?
        .ok_or("cleanup_manifest_missing：活动恢复快照清单不存在。")?;
    if current != ticket.manifest_raw {
        return Err("cleanup_manifest_causal_mismatch：活动恢复快照清单字节票据不匹配。".into());
    }
    let manifest = parse_pending_cleanup_manifest(&current)?;
    if manifest.entries.len() != 1 || manifest.entries.first() != Some(&ticket.entry) {
        return Err("cleanup_manifest_causal_mismatch：活动恢复快照清单因果票据不匹配。".into());
    }
    let cleanup_only = pending_cleanup_manifest_bytes(
        vec![ticket.entry.clone()],
        PendingCleanupDisposition::CleanupOnly,
    )?;
    config::write_pending_authority_cleanup_manifest(
        &context.config_dir,
        &cleanup_only,
        Some(&current),
    )
    .map_err(|_| {
        cleanup_required_error(
            "无法把活动恢复快照原子转换为 cleanup-only",
            &ticket.entry.path,
            "cleanup_prepare_failed",
        )
    })?;
    Ok(RegisteredAuthorityCleanup {
        manifest_raw: cleanup_only,
        entry: ticket.entry.clone(),
    })
}

fn retry_pending_authority_cleanup(state: &SharedAppState) -> Result<(), String> {
    if retry_completed_pending_cleanup_clear(state)? {
        return Ok(());
    }
    let config_dir = config::default_dir();
    let Some(manifest_raw) = config::read_pending_authority_cleanup_manifest(&config_dir)
        .map_err(|_| "cleanup_manifest_read_failed：无法安全读取待清理事务清单。")?
    else {
        return Ok(());
    };
    let manifest = parse_pending_cleanup_manifest(&manifest_raw)?;
    if manifest.entries.is_empty() {
        lock(state).pending_authority_cleanup.clear();
        return Ok(());
    }
    let recovery_snapshot = pending_cleanup_requires_recovery(&manifest);
    let sandbox_home_path = sandbox_home();
    let expected_parent = sandbox_home_path
        .parent()
        .ok_or("cleanup_manifest_invalid：沙箱 HOME 无父目录。")?;
    let entry = manifest
        .entries
        .into_iter()
        .next()
        .ok_or("cleanup_manifest_invalid：待清理事务清单缺少条目。")?;
    let initial = validate_pending_cleanup_entry(&entry, expected_parent)?;
    #[cfg(test)]
    config::test_observe_pending_cleanup_manifest_validated(test_pending_cleanup_identity(&entry));
    {
        let mut current = lock(state);
        if !current
            .pending_authority_cleanup
            .iter()
            .any(|pending| pending == &entry.path)
        {
            current.pending_authority_cleanup.push(entry.path.clone());
        }
    }
    if recovery_snapshot {
        return Err(cleanup_required_error(
            "检测到中断的 one-click authority 事务；活动恢复快照尚未转换为 cleanup-only，已拒绝自动删除",
            &entry.path,
            "authority_snapshot_recovery_required",
        ));
    }
    let active_stage = config::load_from(&config_dir)
        .map_err(|error| format!("cleanup_manifest_read_failed：无法读取运行事务：{error}"))?
        .runtime_transaction
        .map(|journal| journal.stage);
    if active_stage
        .as_deref()
        .is_some_and(runtime_transaction_requires_snapshot_preservation)
    {
        return Err(cleanup_required_error(
            "检测到中断的 one-click authority 事务；已保留精确注册的私有快照，拒绝自动删除或把部分写入态当作新基线",
            &entry.path,
            "authority_snapshot_recovery_required",
        ));
    }
    #[cfg(test)]
    config::test_observe_pending_cleanup_initial_ticket(match &initial {
        PendingCleanupTargetState::Present(_) => {
            config::PendingCleanupInitialTicket::Present(test_pending_cleanup_identity(&entry))
        }
        PendingCleanupTargetState::Missing => {
            config::PendingCleanupInitialTicket::Missing(test_pending_cleanup_identity(&entry))
        }
        PendingCleanupTargetState::Unsafe => unreachable!(),
    });
    #[cfg(test)]
    config::test_pending_cleanup_race_hook()
        .map_err(|_| "cleanup_race_hook_failed：待清理事务快照复核失败。")?;
    let current = inspect_pending_cleanup_target(&entry);
    let completed = match (&initial, &current) {
        (PendingCleanupTargetState::Present(_), PendingCleanupTargetState::Present(actual))
            if actual == &entry =>
        {
            #[cfg(test)]
            config::test_observe_pending_cleanup_delete_attempt();
            if remove_authority_snapshot_root_with_retry(&entry, expected_parent).is_err() {
                #[cfg(test)]
                config::test_observe_pending_cleanup_completion(
                    config::PendingCleanupRemovalOutcome::Error,
                    config::PendingCleanupFinalState::Present(test_pending_cleanup_identity(
                        &entry,
                    )),
                );
                return Err(cleanup_required_error(
                    "待清理 one-click 事务快照仍无法清理",
                    &entry.path,
                    "cleanup_remove_failed",
                ));
            }
            matches!(
                inspect_pending_cleanup_target(&entry),
                PendingCleanupTargetState::Missing
            )
        }
        (PendingCleanupTargetState::Missing, PendingCleanupTargetState::Missing) => true,
        _ => false,
    };
    if !completed {
        #[cfg(test)]
        config::test_observe_pending_cleanup_completion(
            config::PendingCleanupRemovalOutcome::Error,
            match current {
                PendingCleanupTargetState::Missing => config::PendingCleanupFinalState::NotFound,
                PendingCleanupTargetState::Present(actual) => {
                    config::PendingCleanupFinalState::Present(test_pending_cleanup_identity(
                        &actual,
                    ))
                }
                PendingCleanupTargetState::Unsafe => config::PendingCleanupFinalState::Error,
            },
        );
        return Err(
            "cleanup_identity_changed：待清理事务快照在删除前后发生变化，已停止运行。".into(),
        );
    }
    #[cfg(test)]
    config::test_observe_pending_cleanup_completion(
        match initial {
            PendingCleanupTargetState::Present(_) => config::PendingCleanupRemovalOutcome::Removed,
            PendingCleanupTargetState::Missing => {
                config::PendingCleanupRemovalOutcome::AlreadyAbsent
            }
            PendingCleanupTargetState::Unsafe => unreachable!(),
        },
        config::PendingCleanupFinalState::NotFound,
    );
    *PENDING_CLEANUP_CLEAR_RETRY
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(PendingCleanupClearRetry {
        config_dir: config_dir.clone(),
        manifest_raw: manifest_raw.clone(),
        entry: entry.clone(),
    });
    publish_pending_cleanup_clear(state, &config_dir, &manifest_raw, &entry, true)?;
    Ok(())
}

#[derive(Default)]
struct AuthorityCopyBudget {
    entries: usize,
    bytes: u64,
    full_copy_bytes: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct AuthorityDirectoryEntryIdentity {
    name: std::ffi::OsString,
    kind: u8,
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl AuthorityTreeSnapshot {
    fn os_error_code(error: &std::io::Error) -> i32 {
        error.raw_os_error().unwrap_or(-1)
    }

    fn clone_regular_file_at(
        source: &std::fs::File,
        parent: &DirHandle,
        destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        #[cfg(test)]
        if let Some((_, errno)) = SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .authority_clone_errno
            .filter(|(thread, _)| *thread == std::thread::current().id())
        {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let result =
                unsafe { libc::fclonefileat(source.as_raw_fd(), parent.as_raw_fd(), destination_name.as_ptr(), 0) };
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        #[cfg(windows)]
        {
            // Windows 无 fclonefileat（macOS clonefile）：按设计回退到调用方的
            // 有界独立拷贝路径（普通 read/write 复制，语义等价 fs::copy）。
            let _ = (source, parent, destination_name);
            Err(std::io::Error::other("clonefile unsupported on windows"))
        }
    }

    fn open_destination_at(
        parent: &DirHandle,
        destination_name: &std::ffi::CStr,
        flags: i32,
        mode: ModeT,
    ) -> Result<std::fs::File, std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    destination_name.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    libc::c_uint::from(mode),
                )
            };
            if fd < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(unsafe { std::fs::File::from_raw_fd(fd) })
            }
        }
        #[cfg(windows)]
        {
            // Windows 无 openat：按“父目录锚定路径 + 名字”打开；custom_flags
            // 打开 reparse point 本身（不跟随），打开后复查并拒绝符号链接。
            use std::os::windows::fs::OpenOptionsExt;
            let path = dir_path(parent).join(destination_name.to_string_lossy().as_ref());
            let mut options = std::fs::OpenOptions::new();
            if flags & O_WRONLY == 0 {
                options.read(true);
            } else {
                options.write(true);
            }
            if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
                options.create_new(true);
            }
            // FILE_SHARE_DELETE：备份文件句柄存活期间必须允许祖先目录改名/
            // 删除（快照清理 = 改名为墓碑再删除），否则句柄会把整个回滚树
            // 锁死，restore 后的清理必然 ACCESS_DENIED。
            options.share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
            );
            options.custom_flags(crate::platform::no_follow_flags());
            let file = options.open(&path)?;
            if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "拒绝符号链接目标",
                ));
            }
            let _ = mode;
            Ok(file)
        }
    }

    fn open_directory_at(
        parent: &DirHandle,
        destination_name: &std::ffi::CStr,
    ) -> Result<DirHandle, std::io::Error> {
        #[cfg(unix)]
        {
            let file = Self::open_destination_at(
                parent,
                destination_name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            Ok(file)
        }
        #[cfg(windows)]
        {
            // Windows：目录句柄经平台原语打开（拒绝符号链接目录），并锚定完整路径。
            let path =
                crate::platform::extend_max_path(
                    &dir_path(parent).join(destination_name.to_string_lossy().as_ref()),
                );
            let file = crate::platform::open_dir(&path)?;
            Ok(DirHandle {
                file,
                path,
            })
        }
    }

    fn open_absolute_directory(path: &Path) -> Result<DirHandle, std::io::Error> {
        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory path must be absolute",
            ));
        }
        #[cfg(unix)]
        {
            let mut directory = {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open("/")?
            };
            for component in path.components() {
                match component {
                    std::path::Component::RootDir => {}
                    std::path::Component::Normal(name) => {
                        let name = cstring_from_os(name).map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "directory component contains NUL",
                            )
                        })?;
                        directory = Self::open_directory_at(&directory, &name)?;
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "directory path contains unsupported component",
                        ))
                    }
                }
            }
            Ok(directory)
        }
        #[cfg(windows)]
        {
            // Windows：std 无逐级 openat，直接以平台原语打开完整路径（内部
            // 拒绝符号链接目录）；路径锚定退化为路径访问，属已接受设计。
            let file = crate::platform::open_dir(path)?;
            Ok(DirHandle {
                file,
                path: path.to_path_buf(),
            })
        }
    }

    fn open_or_create_authority_snapshot_parent(
        config_dir: &Path,
        sandbox_home: &Path,
    ) -> Result<DirHandle, String> {
        let expected_parent = sandbox_home
            .parent()
            .ok_or("code=authority_snapshot_root_parent_missing")?;
        if sandbox_home != config_dir.join("sandbox").join("home") {
            return Err("code=authority_snapshot_root_parent_contract_failed".into());
        }
        let config_parent = Self::open_absolute_directory(config_dir).map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_open_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        let initial_config_parent_metadata = handle_metadata(&config_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_validate_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        if !initial_config_parent_metadata.is_dir()
            || !crate::platform::file_owner_is_current(&initial_config_parent_metadata)
        {
            return Err("code=authority_snapshot_config_parent_identity_failed".into());
        }
        apply_dir_mode(&config_parent, 0o700).map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_chmod_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        let config_parent_metadata = handle_metadata(&config_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_validate_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        if !config_parent_metadata.is_dir()
            || !crate::platform::file_owner_is_current(&config_parent_metadata)
            || crate::platform::metadata_mode(&config_parent_metadata) & 0o777 != 0o700
        {
            return Err("code=authority_snapshot_config_parent_identity_failed".into());
        }

        let parent_name = Self::destination_name(expected_parent)?;
        match Self::stat_destination_at(&config_parent, &parent_name) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match Self::mkdir_destination_at(&config_parent, &parent_name, 0o700) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(format!(
                            "code=authority_snapshot_root_parent_create_failed os_error={}",
                            Self::os_error_code(&error)
                        ))
                    }
                }
            }
            Err(error) => {
                return Err(format!(
                    "code=authority_snapshot_root_parent_entry_validate_failed os_error={}",
                    Self::os_error_code(&error)
                ))
            }
        }
        let parent_entry =
            Self::stat_destination_at(&config_parent, &parent_name).map_err(|error| {
                format!(
                    "code=authority_snapshot_root_parent_entry_validate_failed os_error={}",
                    Self::os_error_code(&error)
                )
            })?;
        #[cfg(test)]
        if let Some(barrier) = SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .snapshot_parent_barrier
            .as_ref()
            .filter(|(target, _)| target == expected_parent)
            .map(|(_, barrier)| barrier.clone())
        {
            std::fs::create_dir_all(&barrier).map_err(|error| {
                format!("test-only snapshot parent barrier create failed: {error}")
            })?;
            std::fs::write(barrier.join("ready"), b"ready\n").map_err(|error| {
                format!("test-only snapshot parent barrier arm failed: {error}")
            })?;
            let mut released = false;
            for _ in 0..200 {
                if barrier.join("release").is_file() {
                    released = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if !released {
                return Err("test-only snapshot parent barrier timed out".into());
            }
        }
        let snapshot_parent = Self::open_directory_at(&config_parent, &parent_name)
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_root_parent_open_failed os_error={}",
                    Self::os_error_code(&error)
                )
            })?;
        let initial_snapshot_parent_metadata =
            handle_metadata(&snapshot_parent).map_err(|error| {
                format!(
                    "code=authority_snapshot_root_parent_validate_failed os_error={}",
                    Self::os_error_code(&error)
                )
            })?;
        if !initial_snapshot_parent_metadata.is_dir()
            || !crate::platform::file_owner_is_current(&initial_snapshot_parent_metadata)
            || !Self::destination_entry_matches_file(
                &parent_entry,
                dir_file(&snapshot_parent),
                S_IFDIR,
            )
        {
            return Err("code=authority_snapshot_root_parent_identity_failed".into());
        }
        apply_dir_mode(&snapshot_parent, 0o700).map_err(|error| {
            format!(
                "code=authority_snapshot_root_parent_chmod_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        let snapshot_parent_metadata = handle_metadata(&snapshot_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_root_parent_validate_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        if !snapshot_parent_metadata.is_dir()
            || !crate::platform::file_owner_is_current(&snapshot_parent_metadata)
            || crate::platform::metadata_mode(&snapshot_parent_metadata) & 0o777 != 0o700
            || !Self::destination_entry_matches_file(
                &parent_entry,
                dir_file(&snapshot_parent),
                S_IFDIR,
            )
        {
            return Err("code=authority_snapshot_root_parent_identity_failed".into());
        }
        if !Self::absolute_directory_binding_matches(config_dir, &config_parent).map_err(
            |error| {
                format!(
                    "code=authority_snapshot_config_parent_revalidate_failed os_error={}",
                    Self::os_error_code(&error)
                )
            },
        )? {
            return Err("code=authority_snapshot_config_parent_rebound".into());
        }
        if !Self::absolute_directory_binding_matches(expected_parent, &snapshot_parent).map_err(
            |error| {
                format!(
                    "code=authority_snapshot_root_parent_revalidate_failed os_error={}",
                    Self::os_error_code(&error)
                )
            },
        )? {
            return Err("code=authority_snapshot_root_parent_rebound".into());
        }
        handle_sync(&snapshot_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_root_parent_sync_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        handle_sync(&config_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_sync_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        Ok(snapshot_parent)
    }

    fn absolute_directory_binding_matches(
        path: &Path,
        pinned: &DirHandle,
    ) -> Result<bool, std::io::Error> {
        let current = Self::open_absolute_directory(path)?;
        let expected_metadata = handle_metadata(pinned)?;
        let actual_metadata = handle_metadata(&current)?;
        let expected_identity = crate::platform::identity_of_file(dir_file(pinned))?;
        let actual_identity = crate::platform::identity_of_file(dir_file(&current))?;
        Ok(expected_metadata.is_dir()
            && actual_metadata.is_dir()
            && expected_identity.dev == actual_identity.dev
            && expected_identity.ino == actual_identity.ino
            && crate::platform::file_owner_is_current(&expected_metadata)
            && crate::platform::file_owner_is_current(&actual_metadata))
    }

    fn read_directory_names(
        directory: &DirHandle,
    ) -> Result<Vec<std::ffi::OsString>, std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let duplicate =
                unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if duplicate < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if unsafe { libc::lseek(duplicate, 0, libc::SEEK_SET) } < 0 {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(duplicate);
                }
                return Err(error);
            }
            let stream = unsafe { libc::fdopendir(duplicate) };
            if stream.is_null() {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(duplicate);
                }
                return Err(error);
            }
            let stream = AuthorityDirectoryStream(stream);
            let mut names = Vec::new();
            loop {
                unsafe {
                    *libc::__error() = 0;
                }
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error().unwrap_or(0) == 0 {
                        break;
                    }
                    return Err(error);
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                names.push(std::ffi::OsString::from_vec(name.to_vec()));
            }
            names.sort();
            Ok(names)
        }
        #[cfg(windows)]
        {
            // Windows：fdopendir/readdir 不可用，用 read_dir 枚举并排序（路径锚定退化）。
            let mut names = Vec::new();
            for entry in std::fs::read_dir(crate::platform::extend_max_path(dir_path(
                directory,
            )))? {
                let name = entry?.file_name();
                if name == std::ffi::OsStr::new(".") || name == std::ffi::OsStr::new("..") {
                    continue;
                }
                names.push(name);
            }
            names.sort();
            Ok(names)
        }
    }

    fn remove_tree_at(
        destination_parent: &DirHandle,
        destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        let entry = Self::stat_destination_at(destination_parent, destination_name)?;
        let kind = entry.st_mode & S_IFMT;
        if kind == S_IFDIR {
            let directory = Self::open_directory_at(destination_parent, destination_name)?;
            // 句柄仍可读取（错误即失败），身份校验经 destination_entry_matches_file。
            handle_metadata(&directory)?;
            if !Self::destination_entry_matches_file(&entry, dir_file(&directory), S_IFDIR) {
                return Err(std::io::Error::other("directory entry identity changed"));
            }
            for child in Self::read_directory_names(&directory)? {
                let child = cstring_from_os(&child).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "directory entry contains NUL",
                    )
                })?;
                Self::remove_tree_at(&directory, &child)?;
            }
            handle_sync(&directory)?;
            let final_entry = Self::stat_destination_at(destination_parent, destination_name)?;
            handle_metadata(&directory)?;
            if !Self::destination_entry_matches_file(&final_entry, dir_file(&directory), S_IFDIR) {
                return Err(std::io::Error::other(
                    "directory entry rebound before removal",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                let result = unsafe {
                    libc::unlinkat(
                        destination_parent.as_raw_fd(),
                        destination_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                };
                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            #[cfg(windows)]
            {
                // Windows 无 unlinkat(AT_REMOVEDIR)：子项已清空，按完整路径删除空目录。
                std::fs::remove_dir(crate::platform::extend_max_path(
                    &dir_path(destination_parent)
                        .join(destination_name.to_string_lossy().as_ref()),
                ))?;
            }
        } else if kind == S_IFREG || kind == S_IFLNK {
            Self::unlink_destination_at(destination_parent, destination_name)?;
        } else {
            return Err(std::io::Error::other(
                "refusing to remove special authority entry",
            ));
        }
        handle_sync(destination_parent)
    }

    fn mkdir_destination_at(
        parent: &DirHandle,
        destination_name: &std::ffi::CStr,
        mode: ModeT,
    ) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), destination_name.as_ptr(), mode) };
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        #[cfg(windows)]
        {
            // Windows 无 mkdirat：按完整路径创建目录；新目录默认 ACL 已仅当前
            // 用户可访问（等价 0700），mode 参数仅作占位。
            let _ = mode;
            std::fs::create_dir(dir_path(parent).join(destination_name.to_string_lossy().as_ref()))
        }
    }

    fn unlink_destination_at(
        parent: &DirHandle,
        destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let result = unsafe { libc::unlinkat(parent.as_raw_fd(), destination_name.as_ptr(), 0) };
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        #[cfg(windows)]
        {
            // Windows 无 unlinkat：按完整路径删除文件/符号链接。
            std::fs::remove_file(crate::platform::extend_max_path(
                &dir_path(parent).join(destination_name.to_string_lossy().as_ref()),
            ))
        }
    }

    fn destination_name(path: &Path) -> Result<std::ffi::CString, String> {
        let name = path
            .file_name()
            .ok_or("code=authority_snapshot_destination_name_missing")?;
        cstring_from_os(name)
            .map_err(|_| "code=authority_snapshot_destination_name_invalid".into())
    }

    fn cleanup_created_destination(
        destination_parent: &DirHandle,
        destination_name: &std::ffi::CStr,
        scope: AuthoritySnapshotScope,
        category: AuthoritySnapshotCategory,
    ) -> Result<(), String> {
        Self::unlink_destination_at(destination_parent, destination_name)
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_cleanup_unlink_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        handle_sync(destination_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_cleanup_sync_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })
    }

    fn stat_destination_at(
        destination_parent: &DirHandle,
        destination_name: &std::ffi::CStr,
    ) -> Result<EntryStat, std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
            let result = unsafe {
                libc::fstatat(
                    destination_parent.as_raw_fd(),
                    destination_name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                Ok(unsafe { stat.assume_init() })
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        #[cfg(windows)]
        {
            // Windows 无 fstatat：symlink_metadata + 平台身份原语合成 stat
            // （mode 为合成值，uid/gid 恒 0，其余字段语义一致）。
            let path =
                crate::platform::extend_max_path(
                    &dir_path(destination_parent)
                        .join(destination_name.to_string_lossy().as_ref()),
                );
            let metadata = std::fs::symlink_metadata(&path)?;
            let identity = crate::platform::identity_of_path(&path)?;
            Ok(entry_stat_from_metadata(&metadata, identity))
        }
    }

    fn destination_entry_matches_file(
        entry: &EntryStat,
        file: &std::fs::File,
        expected_kind: ModeT,
    ) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match file.metadata() {
                Ok(metadata) => {
                    u64::try_from(entry.st_dev).ok() == Some(metadata.dev())
                        && inode_u64(entry.st_ino) == Some(metadata.ino())
                        && entry.st_mode & S_IFMT == expected_kind
                }
                Err(_) => false,
            }
        }
        #[cfg(windows)]
        {
            match crate::platform::identity_of_file(file) {
                Ok(identity) => {
                    identity.dev == entry.st_dev
                        && identity.ino == entry.st_ino
                        && entry.st_mode & S_IFMT == expected_kind
                }
                Err(_) => false,
            }
        }
    }

    fn readlink_destination_at(
        destination_parent: &DirHandle,
        destination_name: &std::ffi::CStr,
        expected_len: usize,
    ) -> Result<Vec<u8>, std::io::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let mut bytes = vec![0u8; expected_len.saturating_add(1)];
            let length = unsafe {
                libc::readlinkat(
                    destination_parent.as_raw_fd(),
                    destination_name.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if length < 0 {
                return Err(std::io::Error::last_os_error());
            }
            bytes.truncate(length as usize);
            Ok(bytes)
        }
        #[cfg(windows)]
        {
            // Windows：fs::read_link 等价 readlinkat（按完整路径读 reparse point）。
            let target = std::fs::read_link(
                dir_path(destination_parent).join(destination_name.to_string_lossy().as_ref()),
            )?;
            let bytes = os_str_bytes(target.as_os_str())?;
            if bytes.len() > expected_len.saturating_add(1) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "符号链接目标长度变化",
                ));
            }
            Ok(bytes)
        }
    }

    fn category(
        scope: AuthoritySnapshotScope,
        root: &Path,
        current: &Path,
    ) -> AuthoritySnapshotCategory {
        if scope != AuthoritySnapshotScope::ScienceData {
            return AuthoritySnapshotCategory::Other;
        }
        let Ok(relative) = current.strip_prefix(root) else {
            return AuthoritySnapshotCategory::Other;
        };
        let components = relative
            .components()
            .filter_map(|component| component.as_os_str().to_str())
            .collect::<Vec<_>>();
        let Some(first) = components.first().copied() else {
            return AuthoritySnapshotCategory::Other;
        };
        if first == "conda" {
            return AuthoritySnapshotCategory::CondaCache;
        }
        if matches!(first, "runtime" | "seed-assets" | "r-libs" | "sbx-bind-src") {
            return AuthoritySnapshotCategory::ScienceRuntime;
        }
        if components
            .iter()
            .any(|component| matches!(*component, "skills" | "marketplace-plugins"))
        {
            return AuthoritySnapshotCategory::Skills;
        }
        if matches!(
            first,
            ".oauth-tokens"
                | ".key-backups"
                | "active-org.json"
                | "auth-owner.lock"
                | "encryption.key"
                | "mcp"
                | "orgs"
        ) {
            return AuthoritySnapshotCategory::OrgState;
        }
        AuthoritySnapshotCategory::Other
    }

    fn stat_entry_stable(initial: &EntryStat, final_entry: &EntryStat) -> bool {
        initial.st_dev == final_entry.st_dev
            && initial.st_ino == final_entry.st_ino
            && initial.st_mode == final_entry.st_mode
            && initial.st_uid == final_entry.st_uid
            && initial.st_gid == final_entry.st_gid
            && initial.st_nlink == final_entry.st_nlink
            && initial.st_size == final_entry.st_size
            && initial.st_mtime == final_entry.st_mtime
            && initial.st_mtime_nsec == final_entry.st_mtime_nsec
    }

    // mac 上 libc::stat 的 st_dev/st_size 非 u64；Windows 侧类型已是 u64（下同，不赘注）。
    #[allow(clippy::useless_conversion)]
    fn directory_manifest_at(
        directory: &DirHandle,
        names: &[std::ffi::OsString],
    ) -> Result<Vec<AuthorityDirectoryEntryIdentity>, String> {
        names
            .iter()
            .map(|name| {
                let name_c = cstring_from_os(name)
                    .map_err(|_| "code=authority_snapshot_source_name_invalid")?;
                let metadata = Self::stat_destination_at(directory, &name_c).map_err(|error| {
                    format!(
                        "code=authority_snapshot_directory_member_validate_failed os_error={}",
                        Self::os_error_code(&error)
                    )
                })?;
                let kind = match metadata.st_mode & S_IFMT {
                    S_IFREG => 1,
                    S_IFDIR => 2,
                    S_IFLNK => 3,
                    _ => 4,
                };
                Ok(AuthorityDirectoryEntryIdentity {
                    name: name.clone(),
                    kind,
                    device: u64::try_from(metadata.st_dev)
                        .map_err(|_| "code=authority_snapshot_source_device_invalid")?,
                    inode: inode_u64(metadata.st_ino)
                        .ok_or("code=authority_snapshot_source_inode_invalid")?,
                    size: u64::try_from(metadata.st_size)
                        .map_err(|_| "code=authority_snapshot_source_size_invalid")?,
                    mode: metadata.st_mode & 0o777,
                    modified_seconds: metadata.st_mtime,
                    modified_nanoseconds: metadata.st_mtime_nsec,
                })
            })
            .collect()
    }

    #[cfg(test)]
    // mac 快照机制的便捷包装；Windows 快照路径只走 _with_budget 变体，保留对照。
    #[allow(dead_code)]
    fn capture(source: PathBuf, backup: PathBuf) -> Result<Self, String> {
        Self::capture_scoped(AuthoritySnapshotScope::Test, source, backup)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn capture_scoped(
        scope: AuthoritySnapshotScope,
        source: PathBuf,
        backup: PathBuf,
    ) -> Result<Self, String> {
        let backup_parent = backup
            .parent()
            .ok_or("code=authority_snapshot_destination_parent_missing")?;
        let backup_parent_file = Self::open_absolute_directory(backup_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_destination_parent_open_failed scope={} os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        let backup_name = Self::destination_name(&backup)?;
        Self::capture_scoped_at(scope, source, backup, &backup_parent_file, &backup_name)
    }

    fn capture_scoped_at(
        scope: AuthoritySnapshotScope,
        source: PathBuf,
        backup: PathBuf,
        backup_parent: &DirHandle,
        backup_name: &std::ffi::CStr,
    ) -> Result<Self, String> {
        let mut budget = AuthorityCopyBudget::default();
        Self::capture_scoped_at_with_budget(
            scope,
            source,
            backup,
            backup_parent,
            backup_name,
            &mut budget,
        )
    }

    fn capture_scoped_at_with_budget(
        scope: AuthoritySnapshotScope,
        source: PathBuf,
        backup: PathBuf,
        backup_parent: &DirHandle,
        backup_name: &std::ffi::CStr,
        budget: &mut AuthorityCopyBudget,
    ) -> Result<Self, String> {
        let source_parent_path = source
            .parent()
            .ok_or("code=authority_snapshot_source_parent_missing")?;
        let source_parent = match Self::open_absolute_directory(source_parent_path) {
            Ok(parent) => parent,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    scope,
                    source,
                    backup,
                    existed: false,
                    source_parent: None,
                    source_name: None,
                    backup_identity: None,
                    backup_parent: None,
                    backup_name: None,
                })
            }
            Err(error) => {
                return Err(format!(
                    "code=authority_snapshot_source_parent_open_failed scope={} os_error={}",
                    scope.code(),
                    Self::os_error_code(&error)
                ))
            }
        };
        let source_name = Self::destination_name(&source)?;
        Self::capture_scoped_from_parent_with_budget(
            scope,
            source,
            backup,
            &source_parent,
            &source_name,
            backup_parent,
            backup_name,
            budget,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::useless_conversion)]
    fn capture_scoped_from_parent_with_budget(
        scope: AuthoritySnapshotScope,
        source: PathBuf,
        backup: PathBuf,
        source_parent: &DirHandle,
        source_name: &std::ffi::CStr,
        backup_parent: &DirHandle,
        backup_name: &std::ffi::CStr,
        budget: &mut AuthorityCopyBudget,
    ) -> Result<Self, String> {
        #[cfg(test)]
        if SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .capture_fail_source
            .as_ref()
            == Some(&source)
        {
            return Err(format!(
                "test-only authority snapshot capture failure for {}",
                source.display()
            ));
        }
        let source_parent_path = source
            .parent()
            .ok_or("code=authority_snapshot_source_parent_missing")?;
        let backup_identity = match Self::stat_destination_at(source_parent, source_name) {
            Ok(source_identity) => {
                if source_identity.st_mode & S_IFMT == S_IFLNK {
                    return Err(format!(
                        "code=authority_snapshot_root_symlink scope={} category=other",
                        scope.code()
                    ));
                }
                Self::copy_tree_from_at(
                    &source,
                    source_parent,
                    source_name,
                    backup_parent,
                    backup_name,
                    budget,
                    false,
                    scope,
                    &source,
                )?;
                let source_parent_still_bound =
                    Self::absolute_directory_binding_matches(
                        source_parent_path,
                        source_parent,
                    )
                    .map_err(|error| {
                        format!(
                            "code=authority_snapshot_source_parent_revalidate_failed scope={} os_error={}",
                            scope.code(),
                            Self::os_error_code(&error)
                        )
                    })?;
                if !source_parent_still_bound {
                    let primary = format!(
                        "code=authority_snapshot_source_parent_rebound scope={}",
                        scope.code()
                    );
                    return match Self::cleanup_created_destination(
                        backup_parent,
                        backup_name,
                        scope,
                        AuthoritySnapshotCategory::Other,
                    ) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(format!("{primary}; {cleanup}")),
                    };
                }
                let identity =
                    Self::stat_destination_at(backup_parent, backup_name)
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_root_entry_validate_failed scope={} os_error={}",
                                scope.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                Some((
                    u64::try_from(identity.st_dev)
                        .map_err(|_| "code=authority_snapshot_root_device_invalid")?,
                    inode_u64(identity.st_ino)
                        .ok_or("code=authority_snapshot_root_inode_invalid")?,
                    identity.st_mode & S_IFMT,
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                "code=authority_snapshot_root_metadata_failed scope={} category=other os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            ))
            }
        };
        let backup_parent_handle = if backup_identity.is_some() {
            Some(dir_try_clone(backup_parent).map_err(|error| {
                format!(
                    "code=authority_snapshot_backup_parent_pin_failed scope={} os_error={}",
                    scope.code(),
                    Self::os_error_code(&error)
                )
            })?)
        } else {
            None
        };
        let backup_name_handle = backup_identity.as_ref().map(|_| backup_name.to_owned());
        let source_parent_handle = dir_try_clone(source_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_source_parent_pin_failed scope={} os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        Ok(Self {
            scope,
            source,
            backup,
            existed: backup_identity.is_some(),
            source_parent: Some(source_parent_handle),
            source_name: Some(source_name.to_owned()),
            backup_identity,
            backup_parent: backup_parent_handle,
            backup_name: backup_name_handle,
        })
    }

    fn charge_entry(
        budget: &mut AuthorityCopyBudget,
        file_bytes: u64,
        scope: AuthoritySnapshotScope,
        category: AuthoritySnapshotCategory,
    ) -> Result<(), String> {
        budget.entries = budget.entries.checked_add(1).ok_or_else(|| {
            format!(
                "code=authority_snapshot_entry_overflow scope={} category={}",
                scope.code(),
                category.code()
            )
        })?;
        if budget.entries > MAX_AUTHORITY_SNAPSHOT_ENTRIES {
            return Err(format!(
                "code=authority_snapshot_entry_limit scope={} category={} observed_entries={} entry_limit={MAX_AUTHORITY_SNAPSHOT_ENTRIES}",
                scope.code(),
                category.code(),
                budget.entries
            ));
        }
        if file_bytes > MAX_AUTHORITY_SNAPSHOT_FILE_BYTES {
            return Err(format!(
                "code=authority_snapshot_file_limit scope={} category={} observed_bytes={file_bytes} file_limit={MAX_AUTHORITY_SNAPSHOT_FILE_BYTES}",
                scope.code(),
                category.code()
            ));
        }
        budget.bytes = budget.bytes.checked_add(file_bytes).ok_or_else(|| {
            format!(
                "code=authority_snapshot_total_overflow scope={} category={} observed_entries={}",
                scope.code(),
                category.code(),
                budget.entries
            )
        })?;
        if budget.bytes > MAX_AUTHORITY_SNAPSHOT_TOTAL_BYTES {
            return Err(format!(
                "code=authority_snapshot_total_limit scope={} category={} observed_total_bytes={} total_limit={MAX_AUTHORITY_SNAPSHOT_TOTAL_BYTES} observed_entries={}",
                scope.code(),
                category.code(),
                budget.bytes,
                budget.entries
            ));
        }
        Ok(())
    }

    fn charge_full_copy(
        budget: &mut AuthorityCopyBudget,
        file_bytes: u64,
        scope: AuthoritySnapshotScope,
        category: AuthoritySnapshotCategory,
        source_name: &std::ffi::CStr,
    ) -> Result<(), String> {
        if file_bytes > MAX_AUTHORITY_FULL_COPY_FILE_BYTES {
            return Err(format!(
                "code=authority_snapshot_clone_required scope={} category={} file={} observed_bytes={file_bytes} full_copy_file_limit={MAX_AUTHORITY_FULL_COPY_FILE_BYTES}",
                scope.code(),
                category.code(),
                source_name.to_string_lossy()
            ));
        }
        budget.full_copy_bytes =
            budget
                .full_copy_bytes
                .checked_add(file_bytes)
                .ok_or_else(|| {
                    format!(
                        "code=authority_snapshot_full_copy_overflow scope={} category={}",
                        scope.code(),
                        category.code()
                    )
                })?;
        if budget.full_copy_bytes > MAX_AUTHORITY_FULL_COPY_TOTAL_BYTES {
            return Err(format!(
                "code=authority_snapshot_clone_required scope={} category={} file={} observed_full_copy_bytes={} full_copy_total_limit={MAX_AUTHORITY_FULL_COPY_TOTAL_BYTES}",
                scope.code(),
                category.code(),
                source_name.to_string_lossy(),
                budget.full_copy_bytes
            ));
        }
        Ok(())
    }

    fn sync_snapshot_completion(
        backup_root: &DirHandle,
        snapshot_parent: &DirHandle,
    ) -> Result<(), std::io::Error> {
        #[cfg(test)]
        if SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .authority_completion_sync_failure
            .is_some_and(|thread| thread == std::thread::current().id())
        {
            #[cfg(unix)]
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
            #[cfg(windows)]
            return Err(std::io::Error::other("test-only completion sync failure"));
        }
        handle_sync(backup_root)?;
        handle_sync(snapshot_parent)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn copy_tree(
        source: &Path,
        backup: &Path,
        budget: &mut AuthorityCopyBudget,
        allow_symlink: bool,
        scope: AuthoritySnapshotScope,
        root: &Path,
    ) -> Result<(), String> {
        let parent = backup
            .parent()
            .ok_or("code=authority_snapshot_destination_parent_missing")?;
        let parent_file = Self::open_absolute_directory(parent).map_err(|error| {
            format!(
                "code=authority_snapshot_destination_parent_open_failed scope={} os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        let backup_name = Self::destination_name(backup)?;
        let source_parent_path = source
            .parent()
            .ok_or("code=authority_snapshot_source_parent_missing")?;
        let source_parent = Self::open_absolute_directory(source_parent_path).map_err(|error| {
            format!(
                "code=authority_snapshot_source_parent_open_failed scope={} os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        let source_name = Self::destination_name(source)?;
        Self::copy_tree_from_at(
            source,
            &source_parent,
            &source_name,
            &parent_file,
            &backup_name,
            budget,
            allow_symlink,
            scope,
            root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_tree_from_at(
        source_logical: &Path,
        source_parent: &DirHandle,
        source_name: &std::ffi::CStr,
        destination_parent: &DirHandle,
        destination_name: &std::ffi::CStr,
        budget: &mut AuthorityCopyBudget,
        allow_symlink: bool,
        scope: AuthoritySnapshotScope,
        root: &Path,
    ) -> Result<(), String> {
        let category = Self::category(scope, root, source_logical);
        let metadata = Self::stat_destination_at(source_parent, source_name).map_err(|error| {
            format!(
                "code=authority_snapshot_metadata_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let source_kind = metadata.st_mode & S_IFMT;
        if source_kind == S_IFLNK {
            if !allow_symlink {
                return Err(format!(
                    "code=authority_snapshot_root_symlink scope={} category={}",
                    scope.code(),
                    category.code()
                ));
            }
            let expected_len = usize::try_from(metadata.st_size).map_err(|_| {
                format!(
                    "code=authority_snapshot_symlink_size_invalid scope={} category={}",
                    scope.code(),
                    category.code()
                )
            })?;
            let target_bytes =
                Self::readlink_destination_at(source_parent, source_name, expected_len).map_err(
                    |error| {
                        format!(
                    "code=authority_snapshot_symlink_read_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
                    },
                )?;
            Self::charge_entry(budget, target_bytes.len() as u64, scope, category)?;
            let symlink_result: Result<(), std::io::Error> = {
                #[cfg(unix)]
                {
                    use std::os::fd::AsRawFd;
                    let target_name = std::ffi::CString::new(target_bytes.clone())
                        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
                    match target_name {
                        Ok(target_name) => unsafe {
                            libc::symlinkat(
                                target_name.as_ptr(),
                                destination_parent.as_raw_fd(),
                                destination_name.as_ptr(),
                            )
                        }
                        .map_err(|error| error),
                        Err(error) => Err(error),
                    }
                }
                #[cfg(windows)]
                (|| -> Result<(), std::io::Error> {
                    // Windows：std 符号链接创建（需开发者模式/管理员权限；失败即
                    // fail closed，目标内容不会被跟随或改动）。按目标类型选择
                    // symlink_dir/symlink_file（本工具链无通用 symlink 入口）。
                    let target_path = std::path::PathBuf::from(
                        String::from_utf8(target_bytes.clone())
                            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?,
                    );
                    let destination = dir_path(destination_parent)
                        .join(destination_name.to_string_lossy().as_ref());
                    if std::fs::metadata(&target_path)
                        .map(|metadata| metadata.is_dir())
                        .unwrap_or(false)
                    {
                        std::os::windows::fs::symlink_dir(&target_path, &destination)
                    } else {
                        std::os::windows::fs::symlink_file(&target_path, &destination)
                    }
                })()
            };
            if let Err(error) = symlink_result {
                return Err(format!(
                    "code=authority_snapshot_symlink_create_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                ));
            }
            let destination_identity =
                Self::stat_destination_at(destination_parent, destination_name)
                    .map_err(|error| {
                        format!(
                            "code=authority_snapshot_symlink_validate_failed scope={} category={} os_error={}",
                            scope.code(),
                            category.code(),
                            Self::os_error_code(&error)
                        )
                    });
            let snapshot_result = (|| -> Result<(), String> {
                let destination_identity = destination_identity?;
                if destination_identity.st_mode & S_IFMT != S_IFLNK {
                    return Err(format!(
                        "code=authority_snapshot_symlink_identity_failed scope={} category={}",
                        scope.code(),
                        category.code()
                    ));
                }
                let final_metadata =
                    Self::stat_destination_at(source_parent, source_name).map_err(
                        |error| {
                            format!(
                                "code=authority_snapshot_symlink_revalidate_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        },
                    )?;
                let final_target = Self::readlink_destination_at(
                    source_parent,
                    source_name,
                    target_bytes.len(),
                )
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_symlink_target_revalidate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                if !Self::stat_entry_stable(&metadata, &final_metadata)
                    || final_metadata.st_mode & S_IFMT != S_IFLNK
                    || final_target != target_bytes
                {
                    return Err(format!(
                        "code=authority_snapshot_symlink_changed scope={} category={}",
                        scope.code(),
                        category.code()
                    ));
                }
                let final_destination =
                    Self::stat_destination_at(destination_parent, destination_name)
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_symlink_entry_revalidate_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                let final_destination_target = Self::readlink_destination_at(
                    destination_parent,
                    destination_name,
                    target_bytes.len(),
                )
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_symlink_target_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                if final_destination.st_dev != destination_identity.st_dev
                    || final_destination.st_ino != destination_identity.st_ino
                    || final_destination.st_mode & S_IFMT != S_IFLNK
                    || final_destination_target != target_bytes
                {
                    return Err(format!(
                        "code=authority_snapshot_destination_rebound scope={} category={} kind=symlink",
                        scope.code(),
                        category.code()
                    ));
                }
                handle_sync(destination_parent).map_err(|error| {
                    format!(
                        "code=authority_snapshot_parent_sync_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })
            })();
            if let Err(primary) = snapshot_result {
                return match Self::cleanup_created_destination(
                    destination_parent,
                    destination_name,
                    scope,
                    category,
                ) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(format!("{primary}; {cleanup}")),
                };
            }
            return Ok(());
        }
        if source_kind == S_IFREG {
            #[allow(clippy::useless_conversion)]
            let source_size = u64::try_from(metadata.st_size).map_err(|_| {
                format!(
                    "code=authority_snapshot_source_size_invalid scope={} category={}",
                    scope.code(),
                    category.code()
                )
            })?;
            // Science 自有大内容（Electron 缓存、Agent 产物 CSV 等）：不复制、
            // 不恢复，原地保留。快照只保护小型权威状态（凭据/组织/技能）；
            // 大文件复制慢、受预算约束，且回滚本就不应触碰 Science 自管内容。
            // 恢复时只覆盖备份集内文件——缺备份的大文件原地原样保留。
            if source_size > MAX_AUTHORITY_SNAPSHOT_COPYABLE_FILE_BYTES {
                return Ok(());
            }
            let source_mode = metadata.st_mode & 0o777;
            Self::charge_entry(budget, source_size, scope, category)?;
            let mut input = Self::open_destination_at(source_parent, source_name, O_RDONLY, 0)
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_source_open_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
            let opened = input
                .metadata()
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_source_open_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
            if !opened.is_file()
                || !Self::destination_entry_matches_file(&metadata, &input, S_IFREG)
                || opened.len() != source_size
            {
                return Err(format!(
                    "code=authority_snapshot_source_changed scope={} category={} phase=open",
                    scope.code(),
                    category.code()
                ));
            }
            let clone_result =
                Self::clone_regular_file_at(&input, destination_parent, destination_name);
            let mut destination_created = clone_result.is_ok();
            let cloned = clone_result.is_ok();
            let snapshot_result = (|| -> Result<(), String> {
                let output = match clone_result {
                    Ok(()) => Self::open_destination_at(destination_parent, destination_name, O_RDONLY, 0)
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_clone_open_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        })?,
                    Err(clone_error) if clone_unsupported(&clone_error) => {
                        Self::charge_full_copy(budget, source_size, scope, category, source_name)?;
                        let mut output = Self::open_destination_at(
                            destination_parent,
                            destination_name,
                            O_WRONLY | O_CREAT | O_EXCL,
                            0o600,
                        )
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_copy_create_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                        destination_created = true;
                        #[cfg(test)]
                        if SANDBOX_SESSION_TEST_SEAMS
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .authority_fallback_fail_after_create
                            .is_some_and(|thread| thread == std::thread::current().id())
                        {
                            return Err(format!(
                                "code=authority_snapshot_copy_injected_failure scope={} category={}",
                                scope.code(),
                                category.code()
                            ));
                        }
                        let copied = std::io::copy(&mut input, &mut output).map_err(|error| {
                            format!(
                                "code=authority_snapshot_copy_failed scope={} category={} file={} os_error={}",
                                scope.code(),
                                category.code(),
                                destination_name.to_string_lossy(),
                                Self::os_error_code(&error)
                            )
                        })?;
                        if copied != source_size {
                            return Err(format!(
                                "code=authority_snapshot_source_changed scope={} category={} phase=copy",
                                scope.code(),
                                category.code()
                            ));
                        }
                        output
                    }
                    Err(clone_error) => {
                        return Err(format!(
                            "code=authority_snapshot_clone_failed scope={} category={} os_error={}",
                            scope.code(),
                            category.code(),
                            Self::os_error_code(&clone_error)
                        ))
                    }
                };
                apply_file_mode(&output, source_mode).map_err(|error| {
                    format!(
                        "code=authority_snapshot_chmod_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                let saved = output.metadata().map_err(|error| {
                    format!(
                        "code=authority_snapshot_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                let saved_identity = crate::platform::identity_of_file(&output).map_err(|error| {
                    format!(
                        "code=authority_snapshot_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                let opened_identity =
                    crate::platform::identity_of_file(&input).map_err(|error| {
                        format!(
                            "code=authority_snapshot_validate_failed scope={} category={} os_error={}",
                            scope.code(),
                            category.code(),
                            Self::os_error_code(&error)
                        )
                    })?;
                if !saved.is_file()
                    || (cloned && saved_identity.dev != opened_identity.dev)
                    || (saved_identity.dev == opened_identity.dev
                        && saved_identity.ino == opened_identity.ino)
                    || saved.len() != opened.len()
                    || crate::platform::metadata_mode(&saved) & 0o777 != source_mode
                {
                    return Err(format!(
                        "code=authority_snapshot_independence_failed scope={} category={}",
                        scope.code(),
                        category.code()
                    ));
                }
                let destination_entry =
                    Self::stat_destination_at(destination_parent, destination_name)
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_entry_revalidate_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                if !Self::destination_entry_matches_file(&destination_entry, &output, S_IFREG)
                {
                    return Err(format!(
                        "code=authority_snapshot_destination_rebound scope={} category={} kind=file",
                        scope.code(),
                        category.code()
                    ));
                }
                let final_entry =
                    Self::stat_destination_at(source_parent, source_name).map_err(
                        |error| {
                            format!(
                                "code=authority_snapshot_source_entry_revalidate_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        },
                    )?;
                let final_metadata = input.metadata().map_err(|error| {
                    format!(
                        "code=authority_snapshot_source_revalidate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                let final_source_identity =
                    crate::platform::identity_of_file(&input).map_err(|error| {
                        format!(
                            "code=authority_snapshot_source_revalidate_failed scope={} category={} os_error={}",
                            scope.code(),
                            category.code(),
                            Self::os_error_code(&error)
                        )
                    })?;
                if !Self::stat_entry_stable(&metadata, &final_entry)
                    || !Self::destination_entry_matches_file(&final_entry, &input, S_IFREG)
                    || final_source_identity.dev != opened_identity.dev
                    || final_source_identity.ino != opened_identity.ino
                    || final_metadata.len() != opened.len()
                    || crate::platform::metadata_mode(&final_metadata) & 0o777
                        != crate::platform::metadata_mode(&opened) & 0o777
                    || metadata_mtime_pair(&final_metadata) != metadata_mtime_pair(&opened)
                {
                    return Err(format!(
                        "code=authority_snapshot_source_changed scope={} category={} phase=revalidate",
                        scope.code(),
                        category.code()
                    ));
                }
                output.sync_all().map_err(|error| {
                    format!(
                        "code=authority_snapshot_sync_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                handle_sync(destination_parent).map_err(|error| {
                    format!(
                        "code=authority_snapshot_parent_sync_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                Ok(())
            })();
            if let Err(primary) = snapshot_result {
                if destination_created {
                    return match Self::cleanup_created_destination(
                        destination_parent,
                        destination_name,
                        scope,
                        category,
                    ) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(format!("{primary}; {cleanup}")),
                    };
                }
                return Err(primary);
            }
            return Ok(());
        }
        if source_kind != S_IFDIR {
            return Err(format!(
                "code=authority_snapshot_special_file scope={} category={}",
                scope.code(),
                category.code()
            ));
        }
        let source_directory =
            Self::open_directory_at(source_parent, source_name).map_err(
                |error| {
                    format!(
                        "code=authority_snapshot_directory_source_open_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                },
            )?;
        let source_directory_metadata = handle_metadata(&source_directory).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_source_validate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let source_directory_identity =
            crate::platform::identity_of_file(dir_file(&source_directory)).map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_source_validate_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        if !source_directory_metadata.is_dir()
            || !Self::destination_entry_matches_file(
                &metadata,
                dir_file(&source_directory),
                S_IFDIR,
            )
        {
            return Err(format!(
                "code=authority_snapshot_source_changed scope={} category={} phase=directory_open",
                scope.code(),
                category.code()
            ));
        }
        let source_mode = metadata.st_mode & 0o777;
        Self::charge_entry(budget, 0, scope, category)?;
        Self::mkdir_destination_at(destination_parent, destination_name, 0o700)
            .map_err(|error| {
                format!(
                "code=authority_snapshot_directory_create_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
            })?;
        let created_destination_entry =
            Self::stat_destination_at(destination_parent, destination_name)
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_directory_entry_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
        let destination_directory =
            Self::open_directory_at(destination_parent, destination_name).map_err(
                |error| {
                    format!(
                "code=authority_snapshot_directory_open_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
                },
            )?;
        apply_dir_mode(&destination_directory, 0o700).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_chmod_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let destination_metadata = handle_metadata(&destination_directory).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_validate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let destination_directory_identity =
            crate::platform::identity_of_file(dir_file(&destination_directory)).map_err(
                |error| {
                    format!(
                        "code=authority_snapshot_directory_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                },
            )?;
        if !destination_metadata.is_dir()
            || destination_metadata.file_type().is_symlink()
            || !crate::platform::file_owner_is_current(&destination_metadata)
            || (destination_directory_identity.dev == source_directory_identity.dev
                && destination_directory_identity.ino == source_directory_identity.ino)
            || !Self::destination_entry_matches_file(
                &created_destination_entry,
                dir_file(&destination_directory),
                S_IFDIR,
            )
        {
            return Err(format!(
                "code=authority_snapshot_directory_identity_failed scope={} category={}",
                scope.code(),
                category.code()
            ));
        }
        let children = Self::read_directory_names(&source_directory).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_enumerate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let initial_manifest = Self::directory_manifest_at(&source_directory, &children)?;
        #[cfg(test)]
        if let Some(barrier) = SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .directory_barrier
            .as_ref()
            .filter(|(target, _)| target == source_logical)
            .map(|(_, barrier)| barrier.clone())
        {
            std::fs::create_dir_all(&barrier)
                .map_err(|error| format!("test-only snapshot barrier create failed: {error}"))?;
            std::fs::write(barrier.join("ready"), b"ready\n")
                .map_err(|error| format!("test-only snapshot barrier arm failed: {error}"))?;
            let mut released = false;
            for _ in 0..200 {
                if barrier.join("release").is_file() {
                    released = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if !released {
                return Err("test-only authority snapshot barrier timed out".into());
            }
        }
        for child in &children {
            let child_name = cstring_from_os(child).map_err(|_| {
                format!(
                    "code=authority_snapshot_source_name_invalid scope={} category={}",
                    scope.code(),
                    category.code()
                )
            })?;
            let child_logical = source_logical.join(child);
            Self::copy_tree_from_at(
                &child_logical,
                &source_directory,
                &child_name,
                &destination_directory,
                &child_name,
                budget,
                true,
                scope,
                root,
            )?;
        }
        let final_children =
            Self::read_directory_names(&source_directory).map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_reenumerate_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        let final_manifest = Self::directory_manifest_at(&source_directory, &final_children)?;
        let final_entry =
            Self::stat_destination_at(source_parent, source_name).map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_source_entry_revalidate_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        let final_metadata = handle_metadata(&source_directory).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_source_revalidate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let final_opened_identity =
            crate::platform::identity_of_file(dir_file(&source_directory)).map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_source_revalidate_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        let membership_stable = initial_manifest == final_manifest && children == final_children;
        let entry_stable = Self::stat_entry_stable(&metadata, &final_entry);
        let binding_stable =
            Self::destination_entry_matches_file(&final_entry, dir_file(&source_directory), S_IFDIR);
        let opened_stable = final_opened_identity.dev == source_directory_identity.dev
            && final_opened_identity.ino == source_directory_identity.ino
            && crate::platform::file_owner_is_current(&final_metadata)
            && crate::platform::metadata_mode(&final_metadata) & 0o777
                == crate::platform::metadata_mode(&source_directory_metadata) & 0o777
            && metadata_mtime_pair(&final_metadata)
                == metadata_mtime_pair(&source_directory_metadata);
        if !membership_stable
            || !final_metadata.is_dir()
            || !entry_stable
            || !binding_stable
            || !opened_stable
        {
            let manifest_detail = initial_manifest
                .iter()
                .zip(&final_manifest)
                .enumerate()
                .find_map(|(index, (initial, final_entry))| {
                    (initial != final_entry).then(|| {
                        format!(
                            " first_mismatch_index={index} name_equal={} kind_equal={} device_equal={} inode_equal={} size_equal={} mode_equal={} mtime_equal={}",
                            initial.name == final_entry.name,
                            initial.kind == final_entry.kind,
                            initial.device == final_entry.device,
                            initial.inode == final_entry.inode,
                            initial.size == final_entry.size,
                            initial.mode == final_entry.mode,
                            initial.modified_seconds == final_entry.modified_seconds
                                && initial.modified_nanoseconds
                                    == final_entry.modified_nanoseconds
                        )
                    })
                })
                .unwrap_or_default();
            return Err(format!(
                "code=authority_snapshot_directory_changed scope={} category={} membership_stable={} entry_stable={} binding_stable={} opened_stable={} initial_entries={} final_entries={}{}",
                scope.code(),
                category.code(),
                membership_stable,
                entry_stable,
                binding_stable,
                opened_stable,
                initial_manifest.len(),
                final_manifest.len(),
                manifest_detail
            ));
        }
        apply_dir_mode(&destination_directory, source_mode).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_chmod_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        // 句柄仍可读取（错误即失败）；绑定校验经 destination_entry_matches_file。
        let final_destination_entry =
            Self::stat_destination_at(destination_parent, destination_name)
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_directory_entry_revalidate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
        handle_metadata(&destination_directory).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_validate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        if !Self::destination_entry_matches_file(
            &final_destination_entry,
            dir_file(&destination_directory),
            S_IFDIR,
        ) {
            return Err(format!(
                "code=authority_snapshot_destination_rebound scope={} category={} kind=directory",
                scope.code(),
                category.code()
            ));
        }
        handle_sync(&destination_directory).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_sync_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        handle_sync(destination_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_parent_sync_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        Ok(())
    }

    fn remove_current_at(
        scope: AuthoritySnapshotScope,
        parent: &DirHandle,
        name: &std::ffi::CStr,
    ) -> Result<(), String> {
        let metadata = match Self::stat_destination_at(parent, name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return handle_sync(parent).map_err(|sync_error| {
                    format!(
                        "code=authority_restore_parent_sync_failed scope={} os_error={}",
                        scope.code(),
                        Self::os_error_code(&sync_error)
                    )
                })
            }
            Err(error) => {
                return Err(format!(
                    "code=authority_restore_metadata_failed scope={} os_error={}",
                    scope.code(),
                    Self::os_error_code(&error)
                ))
            }
        };
        if metadata.st_mode & S_IFMT == S_IFLNK {
            return Err(format!(
                "code=authority_restore_root_symlink scope={}",
                scope.code()
            ));
        }
        let kind = metadata.st_mode & S_IFMT;
        if kind == S_IFDIR || kind == S_IFREG {
            Self::remove_tree_at(parent, name).map_err(|error| {
                format!(
                    "code=authority_restore_remove_failed scope={} os_error={}",
                    scope.code(),
                    Self::os_error_code(&error)
                )
            })
        } else {
            Err(format!(
                "code=authority_restore_special_file scope={}",
                scope.code()
            ))
        }
    }

    #[allow(clippy::useless_conversion)]
    fn validate_backup_identity(&self) -> Result<(), String> {
        let Some((expected_device, expected_inode, expected_kind)) = self.backup_identity else {
            return if self.existed {
                Err(format!(
                    "code=authority_restore_backup_identity_missing scope={}",
                    self.scope.code()
                ))
            } else {
                Ok(())
            };
        };
        let parent = self.backup_parent.as_ref().ok_or_else(|| {
            format!(
                "code=authority_restore_backup_parent_missing scope={}",
                self.scope.code()
            )
        })?;
        let name = self.backup_name.as_deref().ok_or_else(|| {
            format!(
                "code=authority_restore_backup_name_missing scope={}",
                self.scope.code()
            )
        })?;
        let parent_path = self
            .backup
            .parent()
            .ok_or("code=authority_restore_backup_parent_missing")?;
        if !Self::absolute_directory_binding_matches(parent_path, parent).map_err(|error| {
            format!(
                "code=authority_restore_backup_parent_revalidate_failed scope={} os_error={}",
                self.scope.code(),
                Self::os_error_code(&error)
            )
        })? {
            return Err(format!(
                "code=authority_restore_backup_parent_rebound scope={}",
                self.scope.code()
            ));
        }
        let current = Self::stat_destination_at(parent, name).map_err(|error| {
            format!(
                "code=authority_restore_backup_validate_failed scope={} os_error={}",
                self.scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        if u64::try_from(current.st_dev).ok() != Some(expected_device)
            || inode_u64(current.st_ino) != Some(expected_inode)
            || current.st_mode & S_IFMT != expected_kind
        {
            return Err(format!(
                "code=authority_restore_backup_identity_changed scope={}",
                self.scope.code()
            ));
        }
        Ok(())
    }

    // mac 回滚快照走恢复路径；Windows 失败回滚走删除路径，恢复实现保留对照。
    #[allow(dead_code)]
    fn restore(&mut self) -> Result<(), String> {
        self.validate_backup_identity()?;
        let parent_path = self.source.parent().ok_or("隔离 authority 没有父目录")?;
        let opened_parent;
        let parent = match self.source_parent.as_ref() {
            Some(parent) => {
                if !Self::absolute_directory_binding_matches(parent_path, parent).map_err(
                    |error| {
                        format!(
                            "code=authority_restore_parent_revalidate_failed scope={} os_error={}",
                            self.scope.code(),
                            Self::os_error_code(&error)
                        )
                    },
                )? {
                    return Err(format!(
                        "code=authority_restore_parent_rebound scope={}",
                        self.scope.code()
                    ));
                }
                parent
            }
            None => {
                opened_parent = match Self::open_absolute_directory(parent_path) {
                    Ok(parent) => parent,
                    Err(error) if !self.existed && error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(())
                    }
                    Err(error) => {
                        return Err(format!(
                            "code=authority_restore_parent_open_failed scope={} os_error={}",
                            self.scope.code(),
                            Self::os_error_code(&error)
                        ))
                    }
                };
                &opened_parent
            }
        };
        let computed_source_name;
        let source_name = match self.source_name.as_deref() {
            Some(name) => name,
            None => {
                computed_source_name = Self::destination_name(&self.source)?;
                &computed_source_name
            }
        };
        Self::remove_current_at(self.scope, parent, source_name)?;
        if self.existed {
            let mut budget = AuthorityCopyBudget::default();
            let backup_root = self.backup.clone();
            let backup_parent = self.backup_parent.as_ref().ok_or_else(|| {
                format!(
                    "code=authority_restore_backup_parent_missing scope={}",
                    self.scope.code()
                )
            })?;
            let backup_name = self.backup_name.as_deref().ok_or_else(|| {
                format!(
                    "code=authority_restore_backup_name_missing scope={}",
                    self.scope.code()
                )
            })?;
            Self::copy_tree_from_at(
                &self.backup,
                backup_parent,
                backup_name,
                parent,
                source_name,
                &mut budget,
                false,
                self.scope,
                &backup_root,
            )
            .map_err(|error| format!("无法恢复隔离 authority：{error}"))?;
            self.validate_backup_identity()?;
        }
        if !Self::absolute_directory_binding_matches(parent_path, parent).map_err(|error| {
            format!(
                "code=authority_restore_parent_revalidate_failed scope={} os_error={}",
                self.scope.code(),
                Self::os_error_code(&error)
            )
        })? {
            return Err(format!(
                "code=authority_restore_parent_rebound scope={}",
                self.scope.code()
            ));
        }
        Ok(())
    }
}

struct AppAuthoritySnapshot {
    proxy_present: bool,
    proxy_port: u16,
    secret: String,
    provider: String,
    gateway_kind: String,
    shim_mode: String,
    launch_id: String,
    key_fp: u64,
    gateway_launch_context: Option<crate::GatewayLaunchContext>,
    sandbox_present: bool,
    sandbox_port: u16,
    sandbox_url: Option<String>,
    science_runtime: Option<ScienceRuntimeIdentity>,
    science_confirmed_stopped: Option<ScienceRuntimeIdentity>,
    history_recovery: Option<HistoryRecoverySession>,
    pending_authority_cleanup: Vec<PathBuf>,
}

impl AppAuthoritySnapshot {
    fn capture(state: &SharedAppState) -> Self {
        let state = lock(state);
        Self {
            proxy_present: state.proxy.is_some(),
            proxy_port: state.proxy_port,
            secret: state.secret.clone(),
            provider: state.provider.clone(),
            gateway_kind: state.gateway_kind.clone(),
            shim_mode: state.shim_mode.clone(),
            launch_id: state.launch_id.clone(),
            key_fp: state.key_fp,
            gateway_launch_context: state.gateway_launch_context.clone(),
            sandbox_present: state.sandbox.is_some(),
            sandbox_port: state.sandbox_port,
            sandbox_url: state.sandbox_url.clone(),
            science_runtime: state.science_runtime.clone(),
            science_confirmed_stopped: state.science_confirmed_stopped.clone(),
            history_recovery: state.history_recovery.clone(),
            pending_authority_cleanup: state.pending_authority_cleanup.clone(),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn restore(&self, state: &SharedAppState, proxy_action: ProxyAction) -> Result<(), String> {
        let mut current = lock(state);
        if proxy_action == ProxyAction::Restarted {
            current.stop_proxy();
        }
        if current.sandbox.is_some() && !self.sandbox_present {
            return Err("late-failure 补偿发现未预期的 Science child，拒绝伪造恢复状态".into());
        }
        if self.proxy_present != current.proxy.is_some() {
            return Err("late-failure 补偿无法恢复先前 Gateway child 所有权".into());
        }
        current.proxy_port = self.proxy_port;
        current.secret = self.secret.clone();
        current.provider = self.provider.clone();
        current.gateway_kind = self.gateway_kind.clone();
        current.shim_mode = self.shim_mode.clone();
        current.launch_id = self.launch_id.clone();
        current.key_fp = self.key_fp;
        current.gateway_launch_context = self.gateway_launch_context.clone();
        current.sandbox_port = self.sandbox_port;
        current.sandbox_url = self.sandbox_url.clone();
        current.science_runtime = self.science_runtime.clone();
        current.science_confirmed_stopped = self.science_confirmed_stopped.clone();
        current.history_recovery = self.history_recovery.clone();
        current.pending_authority_cleanup = self.pending_authority_cleanup.clone();
        Ok(())
    }

    fn restore_with_gateway<R: Runtime>(
        &self,
        app: &tauri::AppHandle<R>,
        state: &SharedAppState,
        lifecycle: &lifecycle::Lifecycle,
        proxy_action: ProxyAction,
    ) -> Result<(), String> {
        if proxy_action == ProxyAction::Restarted {
            lock(state).stop_proxy();
        }
        if self.proxy_present {
            let context = self
                .gateway_launch_context
                .as_ref()
                .ok_or("late-failure 补偿缺少先前 Gateway 内存启动上下文")?;
            start_proxy_for(
                app,
                state,
                lifecycle,
                &context.profile,
                context.science_runtime.as_ref(),
                None,
            )
            .map_err(|error| format!("late-failure 补偿无法重启先前 Gateway：{error}"))?;
            if lock(state).proxy.is_none() {
                return Err("late-failure 补偿未恢复先前 Gateway child 所有权".into());
            }
        } else {
            let mut current = lock(state);
            if current.proxy.is_some() {
                return Err("late-failure 补偿发现未预期的 Gateway child".into());
            }
            current.proxy_port = self.proxy_port;
            current.secret = self.secret.clone();
            current.provider = self.provider.clone();
            current.gateway_kind = self.gateway_kind.clone();
            current.shim_mode = self.shim_mode.clone();
            current.launch_id = self.launch_id.clone();
            current.key_fp = self.key_fp;
            current.gateway_launch_context = self.gateway_launch_context.clone();
        }
        let mut current = lock(state);
        if current.sandbox.is_some() && !self.sandbox_present {
            return Err("late-failure 补偿发现未预期的 Science child，拒绝伪造恢复状态".into());
        }
        current.sandbox_port = self.sandbox_port;
        current.sandbox_url = self.sandbox_url.clone();
        current.science_runtime = self.science_runtime.clone();
        current.science_confirmed_stopped = self.science_confirmed_stopped.clone();
        current.history_recovery = self.history_recovery.clone();
        current.pending_authority_cleanup = self.pending_authority_cleanup.clone();
        Ok(())
    }
}

struct OneClickAuthoritySnapshot {
    backup_root: PathBuf,
    cleanup_context: AuthorityCleanupContext,
    cleanup_ticket: Option<RegisteredAuthorityCleanup>,
    trees: Vec<AuthorityTreeSnapshot>,
    science_root_path: PathBuf,
    science_root: Option<DirHandle>,
    science_opaque_bindings: [Option<(u64, u64)>; SCIENCE_OWNED_OPAQUE_ROOTS.len()],
    config: config::Config,
    app: AppAuthoritySnapshot,
    preserve_recovery: bool,
    cleanup_prepared: bool,
}

impl OneClickAuthoritySnapshot {
    fn science_opaque_root_bindings(
        root: Option<&DirHandle>,
    ) -> Result<[Option<(u64, u64)>; SCIENCE_OWNED_OPAQUE_ROOTS.len()], String> {
        let mut bindings = [None; SCIENCE_OWNED_OPAQUE_ROOTS.len()];
        let Some(root) = root else {
            return Ok(bindings);
        };
        for (index, entry) in SCIENCE_OWNED_OPAQUE_ROOTS.iter().enumerate() {
            let name = std::ffi::CString::new(*entry)
                .map_err(|_| "code=science_environment_root_name_invalid")?;
            match AuthorityTreeSnapshot::stat_destination_at(root, &name) {
                Ok(identity)
                    if identity.st_mode & S_IFMT == S_IFDIR
                        && identity.st_uid == current_uid()
                        && identity.st_mode & 0o022 == 0 =>
                {
                    #[allow(clippy::useless_conversion)]
                    let device = u64::try_from(identity.st_dev)
                        .map_err(|_| "code=science_environment_root_device_invalid")?;
                    let inode = inode_u64(identity.st_ino)
                        .ok_or("code=science_environment_root_inode_invalid")?;
                    bindings[index] = Some((device, inode));
                }
                Ok(_) => {
                    return Err(
                        "code=science_environment_root_identity_failed category=science_runtime"
                            .into(),
                    )
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "code=science_environment_root_validate_failed category=science_runtime os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    ))
                }
            }
        }
        Ok(bindings)
    }

    fn pin_science_root_and_validate_opaque_entries(
        auth_dir: &Path,
    ) -> Result<Option<DirHandle>, String> {
        let root = match AuthorityTreeSnapshot::open_absolute_directory(auth_dir) {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "code=science_authority_root_open_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ))
            }
        };
        let metadata = handle_metadata(&root).map_err(|error| {
            format!(
                "code=science_authority_root_validate_failed os_error={}",
                AuthorityTreeSnapshot::os_error_code(&error)
            )
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || !crate::platform::file_owner_is_current(&metadata)
            || crate::platform::metadata_mode(&metadata) & 0o022 != 0
        {
            return Err("code=science_authority_root_identity_failed".into());
        }
        Self::science_opaque_root_bindings(Some(&root))?;
        Ok(Some(root))
    }

    fn revalidate_science_root_binding(
        auth_dir: &Path,
        pinned: &Option<DirHandle>,
    ) -> Result<(), String> {
        let Some(pinned) = pinned.as_ref() else {
            return match AuthorityTreeSnapshot::open_absolute_directory(auth_dir) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Ok(_) => Err("code=science_authority_root_created_during_capture".into()),
                Err(error) => Err(format!(
                    "code=science_authority_root_revalidate_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )),
            };
        };
        let matches = AuthorityTreeSnapshot::absolute_directory_binding_matches(auth_dir, pinned)
            .map_err(|error| {
            format!(
                "code=science_authority_root_revalidate_failed os_error={}",
                AuthorityTreeSnapshot::os_error_code(&error)
            )
        })?;
        if matches {
            Ok(())
        } else {
            Err("code=science_authority_root_rebound".into())
        }
    }

    fn validate_science_restore_root(&self) -> Result<(), String> {
        let current = Self::pin_science_root_and_validate_opaque_entries(&self.science_root_path)?;
        if Self::science_opaque_root_bindings(current.as_ref())? != self.science_opaque_bindings {
            return Err("code=science_environment_root_rebound category=science_runtime".into());
        }
        match (self.science_root.as_ref(), current.as_ref()) {
            (Some(pinned), Some(_)) => {
                let matches = AuthorityTreeSnapshot::absolute_directory_binding_matches(
                    &self.science_root_path,
                    pinned,
                )
                .map_err(|error| {
                    format!(
                        "code=science_authority_restore_root_revalidate_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    )
                })?;
                if matches {
                    Ok(())
                } else {
                    Err("code=science_authority_restore_root_rebound".into())
                }
            }
            (Some(_), None) => Err("code=science_authority_restore_root_missing".into()),
            (None, _) => Ok(()),
        }
    }

    fn science_opaque_bindings_env(&self) -> String {
        SCIENCE_OWNED_OPAQUE_ROOTS
            .iter()
            .zip(self.science_opaque_bindings)
            .map(|(name, binding)| match binding {
                Some((device, inode)) => format!("{name}={device}:{inode}"),
                None => format!("{name}=absent"),
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    fn capture(
        config_dir: &Path,
        sandbox_home: &Path,
        auth_dir: &Path,
        config: &config::Config,
        state: &SharedAppState,
    ) -> Result<Self, String> {
        #[cfg(test)]
        {
            let capture_seam = SANDBOX_SESSION_TEST_SEAMS
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .one_click_capture
                .as_ref()
                .filter(|(target_dir, _, _, _, _)| target_dir == config_dir)
                .cloned();
            if let Some((_, observation, _, expected_prior_pid, expected_receipt)) =
                capture_seam.as_ref()
            {
                let listener_state = if proc::loopback_port_in_use(
                    config.sandbox_port,
                    operation::LOCAL_HEALTH_TIMEOUT_MS,
                ) {
                    "running"
                } else {
                    "stopped"
                };
                let prior_process = if crate::runtime::science::test_process_start_identity_for_pid(
                    *expected_prior_pid,
                )
                .is_some()
                {
                    "alive"
                } else {
                    "absent"
                };
                let prior_receipt = if expected_receipt.exists() {
                    "present"
                } else {
                    "absent"
                };
                std::fs::write(
                    observation,
                    format!(
                        "expected_prior_pid={expected_prior_pid}\nexpected_receipt={}\nlistener={listener_state}\nprior_process={prior_process}\nprior_receipt={prior_receipt}\n",
                        expected_receipt.display()
                    ),
                )
                .map_err(|error| {
                        format!("test-only authority snapshot observation failed: {error}")
                    })?;
            }
            if capture_seam.is_some_and(|(_, _, fail, _, _)| fail) {
                return Err("test-only one-click authority snapshot capture failure".into());
            }
        }
        let sandbox_dir = sandbox_home
            .parent()
            .ok_or("沙箱 HOME 无父目录，无法建立事务快照")?;
        let mut cleanup_context = AuthorityCleanupContext::new(config_dir, sandbox_home, state)?;
        let backup_root = cleanup_context.root.clone();
        let snapshot_parent = AuthorityTreeSnapshot::open_or_create_authority_snapshot_parent(
            config_dir,
            sandbox_home,
        )?;
        let backup_root_name = AuthorityTreeSnapshot::destination_name(&backup_root)?;
        AuthorityTreeSnapshot::mkdir_destination_at(&snapshot_parent, &backup_root_name, 0o700)
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_root_create_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
        let created_root_entry =
            AuthorityTreeSnapshot::stat_destination_at(&snapshot_parent, &backup_root_name)
                .map_err(|error| {
                    finalize_failed_authority_snapshot(
                        &cleanup_context,
                        format!(
                            "code=authority_snapshot_root_entry_validate_failed os_error={}",
                            AuthorityTreeSnapshot::os_error_code(&error)
                        ),
                    )
                })?;
        cleanup_context.bind_root_identity(&created_root_entry)?;
        let backup_root_file = match (|| -> Result<DirHandle, String> {
            let root = AuthorityTreeSnapshot::open_directory_at(&snapshot_parent, &backup_root_name)
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_root_open_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    )
                })?;
            apply_dir_mode(&root, 0o700).map_err(|error| {
                format!(
                    "code=authority_snapshot_root_chmod_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
            let metadata = handle_metadata(&root).map_err(|error| {
                format!(
                    "code=authority_snapshot_root_validate_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || !crate::platform::file_owner_is_current(&metadata)
                || crate::platform::metadata_mode(&metadata) & 0o777 != 0o700
                || !AuthorityTreeSnapshot::destination_entry_matches_file(
                    &created_root_entry,
                    dir_file(&root),
                    S_IFDIR,
                )
            {
                return Err("code=authority_snapshot_root_identity_failed".into());
            }
            handle_sync(&root).map_err(|error| {
                format!(
                    "code=authority_snapshot_root_sync_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
            handle_sync(&snapshot_parent).map_err(|error| {
                format!(
                    "code=authority_snapshot_root_parent_sync_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
            Ok(root)
        })() {
            Ok(root) => root,
            Err(error) => return Err(finalize_failed_authority_snapshot(&cleanup_context, error)),
        };
        let cleanup_ticket = match register_authority_cleanup(&cleanup_context) {
            Ok(ticket) => ticket,
            Err(error) => return Err(finalize_failed_authority_snapshot(&cleanup_context, error)),
        };
        let science_root = match Self::pin_science_root_and_validate_opaque_entries(auth_dir) {
            Ok(root) => root,
            Err(error) => return Err(finalize_failed_authority_snapshot(&cleanup_context, error)),
        };
        let science_opaque_bindings =
            match Self::science_opaque_root_bindings(science_root.as_ref()) {
                Ok(bindings) => bindings,
                Err(error) => {
                    return Err(finalize_failed_authority_snapshot(&cleanup_context, error))
                }
            };
        let science_backup = backup_root.join("0");
        let science_backup_name = AuthorityTreeSnapshot::destination_name(&science_backup)?;
        AuthorityTreeSnapshot::mkdir_destination_at(&backup_root_file, &science_backup_name, 0o700)
            .map_err(|error| {
                finalize_failed_authority_snapshot(
                    &cleanup_context,
                    format!(
                        "code=science_authority_projection_create_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    ),
                )
            })?;
        let science_backup_file = AuthorityTreeSnapshot::open_directory_at(
            &backup_root_file,
            &science_backup_name,
        )
        .map_err(|error| {
            finalize_failed_authority_snapshot(
                &cleanup_context,
                format!(
                    "code=science_authority_projection_open_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ),
            )
        })?;
        let mut trees = Vec::with_capacity(SCIENCE_PROTECTED_AUTHORITY_ENTRIES.len() + 3);
        let mut science_budget = AuthorityCopyBudget::default();
        for entry in SCIENCE_PROTECTED_AUTHORITY_ENTRIES {
            let source = auth_dir.join(entry);
            let backup = science_backup.join(entry);
            let source_name = AuthorityTreeSnapshot::destination_name(&source)?;
            let backup_name = AuthorityTreeSnapshot::destination_name(&backup)?;
            let capture = match science_root.as_ref() {
                Some(science_root) => {
                    AuthorityTreeSnapshot::capture_scoped_from_parent_with_budget(
                        AuthoritySnapshotScope::ScienceData,
                        source,
                        backup,
                        science_root,
                        &source_name,
                        &science_backup_file,
                        &backup_name,
                        &mut science_budget,
                    )
                }
                None => AuthorityTreeSnapshot::capture_scoped_at_with_budget(
                    AuthoritySnapshotScope::ScienceData,
                    source,
                    backup,
                    &science_backup_file,
                    &backup_name,
                    &mut science_budget,
                ),
            };
            match capture {
                Ok(snapshot) => trees.push(snapshot),
                Err(error) => {
                    let durability = handle_sync(&science_backup_file)
                        .and_then(|_| handle_sync(&backup_root_file))
                        .and_then(|_| handle_sync(&snapshot_parent));
                    let primary = match durability {
                        Ok(()) => error,
                        Err(sync_error) => format!(
                            "{error}; code=authority_snapshot_failure_sync_failed os_error={}",
                            AuthorityTreeSnapshot::os_error_code(&sync_error)
                        ),
                    };
                    return Err(finalize_failed_authority_snapshot(
                        &cleanup_context,
                        primary,
                    ));
                }
            }
        }
        if let Err(error) = Self::revalidate_science_root_binding(auth_dir, &science_root) {
            return Err(finalize_failed_authority_snapshot(&cleanup_context, error));
        }
        handle_sync(&science_backup_file)
            .and_then(|_| handle_sync(&backup_root_file))
            .map_err(|error| {
                finalize_failed_authority_snapshot(
                    &cleanup_context,
                    format!(
                        "code=science_authority_projection_sync_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    ),
                )
            })?;
        let sources = [
            (
                AuthoritySnapshotScope::SandboxState,
                sandbox_dir.join("state"),
            ),
            (
                AuthoritySnapshotScope::CsswitchRuntime,
                config_dir.join("runtime"),
            ),
            (
                AuthoritySnapshotScope::ManagedReceipt,
                config_dir.join("science-managed-launch.v1.json"),
            ),
        ];
        for (index, (scope, source)) in sources.into_iter().enumerate() {
            let index = index + 1;
            let backup = backup_root.join(index.to_string());
            let backup_name = AuthorityTreeSnapshot::destination_name(&backup)?;
            match AuthorityTreeSnapshot::capture_scoped_at(
                scope,
                source,
                backup,
                &backup_root_file,
                &backup_name,
            ) {
                Ok(snapshot) => trees.push(snapshot),
                Err(error) => {
                    let durability = handle_sync(&backup_root_file)
                        .and_then(|_| handle_sync(&snapshot_parent));
                    let primary = match durability {
                        Ok(()) => error,
                        Err(sync_error) => format!(
                            "{error}; code=authority_snapshot_failure_sync_failed os_error={}",
                            AuthorityTreeSnapshot::os_error_code(&sync_error)
                        ),
                    };
                    return Err(finalize_failed_authority_snapshot(
                        &cleanup_context,
                        primary,
                    ));
                }
            }
        }
        if !AuthorityTreeSnapshot::absolute_directory_binding_matches(
            &cleanup_context.expected_snapshot_parent,
            &snapshot_parent,
        )
        .map_err(|error| {
            finalize_failed_authority_snapshot(
                &cleanup_context,
                format!(
                    "code=authority_snapshot_root_parent_revalidate_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ),
            )
        })? {
            return Err(finalize_failed_authority_snapshot(
                &cleanup_context,
                "code=authority_snapshot_root_parent_rebound".into(),
            ));
        }
        // 句柄仍可读取（错误即失败）；绑定校验经 destination_entry_matches_file。
        handle_metadata(&backup_root_file).map_err(|error| {
            finalize_failed_authority_snapshot(
                &cleanup_context,
                format!(
                    "code=authority_snapshot_root_validate_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ),
            )
        })?;
        let final_root_entry =
            AuthorityTreeSnapshot::stat_destination_at(&snapshot_parent, &backup_root_name)
                .map_err(|error| {
                    finalize_failed_authority_snapshot(
                        &cleanup_context,
                        format!(
                            "code=authority_snapshot_root_entry_revalidate_failed os_error={}",
                            AuthorityTreeSnapshot::os_error_code(&error)
                        ),
                    )
                })?;
        if !AuthorityTreeSnapshot::destination_entry_matches_file(
            &final_root_entry,
            dir_file(&backup_root_file),
            S_IFDIR,
        ) {
            return Err(finalize_failed_authority_snapshot(
                &cleanup_context,
                "code=authority_snapshot_root_rebound".into(),
            ));
        }
        AuthorityTreeSnapshot::sync_snapshot_completion(&backup_root_file, &snapshot_parent)
            .map_err(|error| {
                finalize_failed_authority_snapshot(
                    &cleanup_context,
                    format!(
                        "code=authority_snapshot_completion_sync_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    ),
                )
            })?;
        Ok(Self {
            backup_root,
            cleanup_context,
            cleanup_ticket: Some(cleanup_ticket),
            trees,
            science_root_path: auth_dir.to_path_buf(),
            science_root,
            science_opaque_bindings,
            config: config.clone(),
            app: AppAuthoritySnapshot::capture(state),
            preserve_recovery: false,
            cleanup_prepared: false,
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn restore(
        &mut self,
        config_dir: &Path,
        state: &SharedAppState,
        proxy_action: ProxyAction,
    ) -> Result<(), String> {
        let mut errors = Vec::new();
        let science_restore_allowed = match self.validate_science_restore_root() {
            Ok(()) => true,
            Err(error) => {
                errors.push(error);
                false
            }
        };
        for tree in &mut self.trees {
            if tree.scope == AuthoritySnapshotScope::ScienceData && !science_restore_allowed {
                continue;
            }
            if let Err(error) = tree.restore() {
                errors.push(error);
            }
        }
        if let Err(error) =
            config::save_to(config_dir, &self.config).map_err(|error| error.to_string())
        {
            errors.push(error);
        }
        if let Err(error) = self.app.restore(state, proxy_action) {
            errors.push(error);
        }
        if errors.is_empty() {
            return self.cleanup_when_expendable();
        }
        self.preserve_recovery = true;
        Err(errors.join("; "))
    }

    fn restore_with_gateway<R: Runtime>(
        &mut self,
        app: &tauri::AppHandle<R>,
        config_dir: &Path,
        state: &SharedAppState,
        lifecycle: &lifecycle::Lifecycle,
        proxy_action: ProxyAction,
    ) -> Result<(), String> {
        if proxy_action == ProxyAction::Restarted {
            lock(state).stop_proxy();
        }
        let mut errors = Vec::new();
        let science_restore_allowed = match self.validate_science_restore_root() {
            Ok(()) => true,
            Err(error) => {
                errors.push(error);
                false
            }
        };
        for tree in &mut self.trees {
            if tree.scope == AuthoritySnapshotScope::ScienceData && !science_restore_allowed {
                continue;
            }
            if let Err(error) = tree.restore() {
                errors.push(error);
            }
        }
        if let Err(error) =
            config::save_to(config_dir, &self.config).map_err(|error| error.to_string())
        {
            errors.push(error);
        }
        if let Err(error) =
            self.app
                .restore_with_gateway(app, state, lifecycle, proxy_action)
        {
            errors.push(error);
        }
        #[cfg(test)]
        {
            let mut seams = SANDBOX_SESSION_TEST_SEAMS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(canary) = seams.rollback_diagnostic_canary.clone() {
                seams.rollback_diagnostic_snapshot = Some(self.backup_root.clone());
                errors.push(format!("test-only rollback diagnostic {canary}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            self.preserve_recovery = true;
            Err(errors.join("; "))
        }
    }

    fn cleanup_when_expendable(&mut self) -> Result<(), String> {
        self.preserve_recovery = true;
        if self.cleanup_ticket.is_none() {
            self.cleanup_ticket = Some(register_authority_cleanup(&self.cleanup_context)?);
        }
        let ticket = self
            .cleanup_ticket
            .as_ref()
            .ok_or("cleanup_register_failed：事务快照清理票据缺失。")?;
        let cleanup_ticket = prepare_registered_authority_cleanup(&self.cleanup_context, ticket)?;
        self.cleanup_ticket = Some(cleanup_ticket);
        let ticket = self
            .cleanup_ticket
            .as_ref()
            .ok_or("cleanup_register_failed：cleanup-only 票据缺失。")?;
        match finalize_registered_authority_cleanup(&self.cleanup_context, ticket) {
            Ok(()) => {
                self.preserve_recovery = false;
                self.cleanup_prepared = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn prepare_success(&mut self, value: &mut Value) -> Result<(), String> {
        match self.cleanup_when_expendable() {
            Ok(()) => Ok(()),
            Err(error) if error.contains("recovery_status=cleanup_required") => {
                self.preserve_recovery = true;
                self.cleanup_prepared = true;
                if let Some(object) = value.as_object_mut() {
                    object.insert("status".into(), Value::String("degraded".into()));
                    object.insert(
                        "recovery_status".into(),
                        Value::String("cleanup_required".into()),
                    );
                    object.insert(
                        "cleanup_recovery_path".into(),
                        Value::String(self.backup_root.to_string_lossy().into_owned()),
                    );
                    object.insert(
                        "cleanup_message".into(),
                        Value::String("one-click 已完成，但私有事务快照需要稍后安全清理。".into()),
                    );
                }
                Ok(())
            }
            Err(error) => {
                self.preserve_recovery = true;
                Err(error)
            }
        }
    }

    fn commit(&mut self) {
        if !self.cleanup_prepared {
            let _ = self.cleanup_when_expendable();
        }
    }
}

impl Drop for OneClickAuthoritySnapshot {
    fn drop(&mut self) {
        // Drop can run during panic unwinding after protected state changed.
        // Only explicit success or fully successful compensation may publish
        // ActiveRecovery -> CleanupOnly and remove the recovery snapshot.
        self.preserve_recovery = true;
    }
}

fn validate_system_ssh_wrapper_path<R: Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<PathBuf, String> {
    #[cfg(test)]
    let wrapper_override =
        std::env::var_os("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE").map(PathBuf::from);
    #[cfg(not(test))]
    let wrapper_override: Option<PathBuf> = None;
    let wrapper = match wrapper_override {
        Some(wrapper) => wrapper,
        None => {
            let root = asset_root(app).ok_or("打包的 CSSwitch SSH bridge 缺失")?;
            let scripts = root.join("scripts");
            let wrapper_dir = scripts.join("ssh-bridge");
            let wrapper = wrapper_dir.join("ssh");
            for path in [&root, &scripts, &wrapper_dir] {
                let metadata = std::fs::symlink_metadata(path)
                    .map_err(|_| "打包的 CSSwitch SSH bridge 缺失".to_string())?;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err("打包的 CSSwitch SSH bridge 不是安全的可执行文件".into());
                }
            }
            wrapper
        }
    };
    let metadata = std::fs::symlink_metadata(&wrapper)
        .map_err(|_| "打包的 CSSwitch SSH bridge 缺失".to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > 128 * 1024
        || !crate::platform::is_executable_file(&wrapper)
    {
        return Err("打包的 CSSwitch SSH bridge 不是安全的可执行文件".into());
    }
    Ok(wrapper)
}

fn validate_running_system_ssh_bridge<R: Runtime>(
    app: &tauri::AppHandle<R>,
    sandbox_home: &Path,
) -> Result<(), String> {
    let _validated_wrapper =
        crate::runtime::sandbox_session::validate_system_ssh_wrapper_path(app)?;
    let expected_hosts = crate::runtime::ssh_bridge::validate_science_ssh_bridge(sandbox_home)?;
    crate::runtime::settings::validate_managed_sandbox_ssh_stub(sandbox_home, &expected_hosts)?;
    Ok(())
}

fn prevalidate_one_click_system_ssh<R: Runtime>(
    app: &tauri::AppHandle<R>,
    cfg: &config::Config,
    sandbox_home: &Path,
) -> Result<Vec<String>, String> {
    let expected_hosts = crate::runtime::ssh_bridge::prevalidate_science_ssh_bridge(
        sandbox_home,
        cfg.reuse_system_ssh,
    )?;
    crate::runtime::settings::prevalidate_sandbox_ssh_stub(
        sandbox_home,
        &expected_hosts,
        cfg.reuse_system_ssh,
    )?;
    if cfg.reuse_system_ssh {
        let _validated_wrapper =
            crate::runtime::sandbox_session::validate_system_ssh_wrapper_path(app)?;
    }
    Ok(expected_hosts)
}

const SCIENCE_CANONICAL_ROLE_MODEL_IDS: [&str; 5] = [
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-opus-4-8",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
];



fn verify_gateway_model_catalog(
    port: u16,
    secret: &str,
    profile: &config::Profile,
) -> Result<(), String> {
    let timeout_ms = gateway_model_catalog_timeout_ms(profile);
    let (status, body) =
        proc::http_get_body_cancellable(port, Some(secret), "/v1/models", timeout_ms, None)
            .ok_or("gateway 模型目录探活无响应")?;
    if status != 200 {
        return Err(format!("gateway 模型目录探活返回 {status}"));
    }
    let value: Value = serde_json::from_str(&body).map_err(|_| "gateway 模型目录不是合法 JSON")?;
    let models = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or("gateway 模型目录缺少 data array")?;
    let mut ids = Vec::with_capacity(models.len());
    let mut unique = std::collections::BTreeSet::new();
    for model in models {
        let id = model
            .as_object()
            .and_then(|model| model.get("id"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or("gateway 模型目录包含 malformed id row")?;
        if !unique.insert(id) {
            return Err("gateway 模型目录包含 duplicate id".into());
        }
        ids.push(id);
    }
    let mut expected: std::collections::BTreeSet<&str> = profile
        .model_catalog
        .iter()
        .map(|route| route.selector_id.as_str())
        .collect();
    expected.extend(SCIENCE_CANONICAL_ROLE_MODEL_IDS);
    let actual: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    if actual != expected || ids.first().copied() != Some(profile.default_model_route_id.as_str()) {
        return Err("gateway 模型目录与已提交白名单/default selector 不一致".into());
    }
    Ok(())
}

fn gateway_model_catalog_timeout_ms(_profile: &config::Profile) -> u64 {
    operation::LOCAL_HEALTH_TIMEOUT_MS
}

fn verify_gateway_model_catalog_traced(
    trace: &OperationTrace,
    port: u16,
    secret: &str,
    profile: &config::Profile,
) -> Result<(), String> {
    trace.stage(
        OperationStage::CatalogVerify,
        format!(
            "start policy={:?} timeout_ms={}",
            profile.model_policy,
            gateway_model_catalog_timeout_ms(profile)
        ),
    );
    #[cfg(test)]
    if SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .catalog_failure_port
        == Some(port)
    {
        trace.stage(OperationStage::CatalogVerify, "outcome=test_error");
        trace.finish("error=test_catalog_verify_after_gateway_restart");
        return Err("test-only healthy reopen catalog failure after Gateway restart".into());
    }
    #[cfg(test)]
    if SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .catalog_bypass_port
        == Some(port)
    {
        trace.stage(OperationStage::CatalogVerify, "outcome=test_bypass");
        return Ok(());
    }
    match verify_gateway_model_catalog(port, secret, profile) {
        Ok(()) => {
            trace.stage(OperationStage::CatalogVerify, "outcome=ok");
            Ok(())
        }
        Err(error) => {
            trace.stage(OperationStage::CatalogVerify, "outcome=error");
            trace.finish("error=catalog_verify");
            Err(error)
        }
    }
}

fn configure_third_party_best_effort<R: Runtime>(
    app: &tauri::AppHandle<R>,
    status: RegistrationStatus,
    data_dir: &std::path::Path,
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    force: bool,
) -> RegistrationStatus {
    if !matches!(
        status,
        RegistrationStatus::Registered | RegistrationStatus::AlreadyRegistered
    ) {
        let _ = invalidate_route_configuration(data_dir);
        return status;
    }
    let Some(science_version) = runtime.version.as_deref() else {
        let _ = invalidate_route_configuration(data_dir);
        return RegistrationStatus::Warning(
            "Science 版本无法确认，未记录第三方能力配置状态".into(),
        );
    };
    let needs_configuration = force
        || matches!(status, RegistrationStatus::Registered)
        || match route_configuration_is_current(data_dir, science_version) {
            Ok(current) => !current,
            Err(error) => return RegistrationStatus::Warning(error),
        };
    if !needs_configuration {
        return status;
    }
    if let Err(error) = invalidate_route_configuration(data_dir) {
        return RegistrationStatus::Warning(error);
    }
    let control_url = sandbox_url(port, runtime);
    if let Err(error) = configure_third_party_after_science_start(app, &control_url) {
        return RegistrationStatus::Warning(error);
    }
    match mark_route_configuration_current(data_dir, science_version) {
        Ok(()) => status,
        Err(error) => RegistrationStatus::Warning(error),
    }
}

/// Explicit doctor action: bypass the version cache and route marker without
/// starting Science or the proxy solely for diagnostics.
pub(crate) fn force_third_party_reconcile<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
) -> Result<String, String> {
    let cfg = config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
    let data_dir = sandbox_data_dir();
    let (remembered_runtime, version_cache) = {
        let st = lock(state);
        (st.science_runtime.clone(), st.science_version_cache.clone())
    };

    let (science_state, running_runtime) = match remembered_runtime {
        Some(mut runtime) => {
            if !runtime_identity_is_current(&runtime) {
                invalidate_route_configuration(&data_dir)?;
                return Ok(
                    "Science 二进制文件已变化；已安排下次停止并启动后重新选择 runtime。".into(),
                );
            }
            let previous_version = runtime.version.clone();
            let refreshed = version_cache
                .force_refresh(&runtime.path)
                .ok_or("Science 版本强制复检失败")?;
            if previous_version
                .as_deref()
                .is_some_and(|version| version != refreshed)
            {
                invalidate_route_configuration(&data_dir)?;
                return Ok(
                    "Science 二进制版本已变化；已安排下次停止并启动后重新配置 Skill 路由。".into(),
                );
            }
            runtime.version = Some(refreshed);
            let science_state = probe_known_runtime(cfg.sandbox_port, &runtime);
            let running = (science_state == SandboxScienceState::RunningHealthy).then_some(runtime);
            (science_state, running)
        }
        None => {
            version_cache.clear();
            probe_sandbox_runtime_cached(cfg.sandbox_port, &version_cache)?
        }
    };

    if cfg.mode == "official" {
        return Ok("官方模式无需核验 CSSwitch 第三方 Skill 路由。".into());
    }
    match science_state {
        SandboxScienceState::Stopped => {
            invalidate_route_configuration(&data_dir)?;
            Ok("Science 未运行；已安排下次一键开始重新核验 Skill 路由。".into())
        }
        SandboxScienceState::Unknown => {
            invalidate_route_configuration(&data_dir)?;
            Err("无法确认 Science 实例身份；已使路由标记失效，未执行修复".into())
        }
        SandboxScienceState::RunningHealthy => {
            let runtime = running_runtime.ok_or("Science 运行身份缺失")?;
            let secret = { lock(state).secret.clone() };
            if secret.is_empty() {
                invalidate_route_configuration(&data_dir)?;
                return Ok("当前代理身份不可用；已安排下次一键开始重新核验 Skill 路由。".into());
            }
            let bridge_dir = skill_install_bridge_dir(&secret)?;
            let bridge_key = match current_skill_install_bridge_key() {
                Ok(path) => path,
                Err(error) => {
                    invalidate_route_configuration(&data_dir)?;
                    return Ok(format!(
                        "Skill bridge 尚未就绪；已安排下次一键开始重新核验：{error}"
                    ));
                }
            };
            let status = inspect_while_science_running(app, &data_dir, &bridge_dir, &bridge_key);
            let status = configure_third_party_best_effort(
                app,
                status,
                &data_dir,
                cfg.sandbox_port,
                &runtime,
                true,
            );
            {
                let mut st = lock(state);
                st.science_runtime = Some(runtime);
                st.science_confirmed_stopped = None;
            }
            match status {
                RegistrationStatus::AlreadyRegistered | RegistrationStatus::Registered => {
                    Ok("Skill 路由已强制核验并同步。".into())
                }
                RegistrationStatus::RestartRequired => {
                    Ok("Skill 路由文件需要重启 Science 后加载；状态标记已失效。".into())
                }
                RegistrationStatus::Warning(message) => {
                    Ok(format!("Skill 路由核验未完成：{message}"))
                }
            }
        }
    }
}

/// One-click session startup: active proxy, virtual login, sandbox, browser.
///
/// Callers must hold the command serializer lock.
pub(crate) fn one_click_login<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    runtime_choice: Option<&str>,
) -> Result<Value, String> {
    one_click_login_with_options(
        app,
        state,
        lifecycle,
        runtime_choice,
        true,
        None,
    )
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PriorScienceDisposition {
    #[default]
    RestartRequired,
    Restored,
    EnvironmentUncertain,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ReconcileScienceError {
    PriorScienceRestored { cause: String },
    EnvironmentUncertain { cause: String },
    RestartRequired { cause: String },
}

#[allow(dead_code)]
impl ReconcileScienceError {
    pub(crate) fn cause(&self) -> &str {
        match self {
            Self::PriorScienceRestored { cause }
            | Self::EnvironmentUncertain { cause }
            | Self::RestartRequired { cause } => cause,
        }
    }

    pub(crate) fn prior_science_restored(&self) -> bool {
        matches!(self, Self::PriorScienceRestored { .. })
    }

    pub(crate) fn environment_uncertain(&self) -> bool {
        matches!(self, Self::EnvironmentUncertain { .. })
    }
}

#[allow(dead_code)]
pub(crate) fn reconcile_science_for_active<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
) -> Result<Value, ReconcileScienceError> {
    let mut disposition = PriorScienceDisposition::RestartRequired;
    one_click_login_with_options(
        app,
        state,
        lifecycle,
        None,
        false,
        Some(&mut disposition),
    )
    .map_err(|cause| match disposition {
        PriorScienceDisposition::Restored => ReconcileScienceError::PriorScienceRestored { cause },
        PriorScienceDisposition::EnvironmentUncertain => {
            ReconcileScienceError::EnvironmentUncertain { cause }
        }
        PriorScienceDisposition::RestartRequired => {
            ReconcileScienceError::RestartRequired { cause }
        }
    })
}

/// Rollback-only recovery path. The persisted config is already the old,
/// authoritative profile. Do not trust its previous runtime binding to decide
/// reuse: a healthy process may actually have loaded the failed candidate
/// catalog. Stop only the exact in-memory Science identity and start the
/// committed chain again from a clean process.
#[allow(dead_code)]
pub(crate) fn force_restart_science_for_active<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
) -> Result<Value, String> {
    let cfg = config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
    let remembered = { lock(&state).science_runtime.clone() };
    match remembered {
        Some(runtime) => match probe_known_runtime(cfg.sandbox_port, &runtime) {
            SandboxScienceState::RunningHealthy => {
                let mut st = lock(&state);
                st.science_runtime = Some(runtime);
                stop_sandbox_state(&app, &mut st).map_err(|error| {
                    format!("回滚时停止候选 Science 失败，未猜测 PID 或按端口结束进程：{error}")
                })?;
            }
            SandboxScienceState::Stopped => {
                let mut st = lock(&state);
                st.science_confirmed_stopped = Some(runtime);
                st.science_runtime = None;
            }
            SandboxScienceState::Unknown => {
                return Err(
                    "回滚时 Science 可能正在运行，但身份无法确认；已拒绝猜测 PID 或按端口结束进程。"
                        .into(),
                );
            }
        },
        None if proc::loopback_port_in_use(
            cfg.sandbox_port,
            operation::LOCAL_HEALTH_TIMEOUT_MS,
        ) =>
        {
            return Err(
                "回滚时 Science 端口仍被占用，但没有可确认的 runtime 身份；已拒绝强制结束。".into(),
            );
        }
        None => {}
    }
    one_click_login_with_options(app, state, lifecycle, None, false, None)
}

fn advance_runtime_transaction(
    dir: &Path,
    active_profile_id: &str,
    previous_binding: Option<config::RuntimeBindingCommit>,
    stage: &str,
) -> Result<(), String> {
    config::update(dir, |current| match current.runtime_transaction.as_mut() {
        Some(journal) if journal.target_profile_id == active_profile_id => {
            journal.stage = stage.to_string();
        }
        _ => {
            current.runtime_transaction = Some(config::RuntimeTransactionJournal {
                transaction_id: config::new_id(),
                target_profile_id: active_profile_id.to_string(),
                stage: stage.to_string(),
                previous_binding: previous_binding.clone(),
                previous_gateway: None,
            });
        }
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

const SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX: &str = "start_science_environment_pending:";
const AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX: &str = "authority_snapshot_active:";
const LEGACY_SCIENCE_ENVIRONMENT_STAGE: &str = "start_science";
const LEGACY_SCIENCE_ENVIRONMENT_PENDING_STAGE: &str = "start_science_environment_pending";

pub(crate) fn interrupted_science_environment_runtime_id(stage: &str) -> Option<&str> {
    let runtime_id = stage
        .strip_prefix(SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX)
        .or_else(|| stage.strip_prefix(AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX))?;
    (runtime_id.len() == 64
        && runtime_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    .then_some(runtime_id)
}

pub(crate) fn runtime_transaction_requires_snapshot_preservation(stage: &str) -> bool {
    stage == LEGACY_SCIENCE_ENVIRONMENT_STAGE
        || stage == LEGACY_SCIENCE_ENVIRONMENT_PENDING_STAGE
        || stage.starts_with(SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX)
        || stage.starts_with(AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX)
}

fn validate_interrupted_science_transaction_entry(
    stage: Option<&str>,
    runtime_id: Option<&str>,
) -> Result<(), String> {
    if stage.is_some_and(runtime_transaction_requires_snapshot_preservation) && runtime_id.is_none()
    {
        return Err(
            "检测到旧版或无法识别的 Science 启动中断记录；无法证明当时使用的 runtime，已拒绝自动清理快照或再次启动；environment_uncertain；newer_runtime_required；recovery_status=manual_recovery_required"
                .into(),
        );
    }
    if stage.is_some_and(|stage| stage.starts_with(AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX)) {
        return Err(
            "检测到 authority 快照已登记但受保护状态写入未完成；已保留恢复快照并拒绝把部分写入态作为新基线；recovery_status=manual_recovery_required"
                .into(),
        );
    }
    Ok(())
}

fn validate_interrupted_science_environment_runtime(
    expected_runtime_id: Option<&str>,
    runtime: &ScienceRuntimeIdentity,
) -> Result<(), String> {
    let Some(expected_runtime_id) = expected_runtime_id else {
        return Ok(());
    };
    if runtime.environment_transaction_id() == expected_runtime_id {
        Ok(())
    } else {
        Err(
            "上次启动在 Science 环境暴露边界中断，当前 executable 与中断事务不一致；已拒绝自动启动旧版或其他 runtime；environment_uncertain；newer_runtime_required；recovery_status=manual_recovery_required"
                .into(),
        )
    }
}

#[derive(Clone)]
struct OneClickRollbackContext {
    proxy_action: ProxyAction,
    sandbox_port: u16,
    launch_runtime: ScienceRuntimeIdentity,
    launch_token: Option<ScienceManagedLaunchToken>,
    launch_attempted: bool,
    launch_confirmed_stopped: bool,
    candidate_stop_proof: ManagedScienceCandidateStopProof,
    ssh_stub_transaction: Option<crate::runtime::settings::ManagedSshStubTransaction>,
}

const SCIENCE_LAUNCH_ENVIRONMENT_EXPOSED_EXIT_CODE: i32 = 70;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ManagedScienceCandidateStopProof {
    #[default]
    NotRequired,
    ConfirmedStopped,
    Unproven,
}

struct ManagedScienceRestartError {
    message: String,
    candidate_stop_proof: ManagedScienceCandidateStopProof,
}

impl ManagedScienceRestartError {
    fn before_spawn(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            candidate_stop_proof: ManagedScienceCandidateStopProof::NotRequired,
        }
    }

    fn after_spawn_unproven(message: impl Into<String>) -> Self {
        Self {
            message: format!("{}；code=science_candidate_stop_unproven", message.into()),
            candidate_stop_proof: ManagedScienceCandidateStopProof::Unproven,
        }
    }

    fn after_exact_cleanup(message: impl Into<String>, cleanup: Result<(), String>) -> Self {
        match cleanup {
            Ok(()) => Self {
                message: message.into(),
                candidate_stop_proof: ManagedScienceCandidateStopProof::ConfirmedStopped,
            },
            Err(error) => {
                Self::after_spawn_unproven(format!("{}；candidate_cleanup={error}", message.into()))
            }
        }
    }
}

impl std::fmt::Display for ManagedScienceRestartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl From<String> for ManagedScienceRestartError {
    fn from(message: String) -> Self {
        Self::before_spawn(message)
    }
}

impl From<&str> for ManagedScienceRestartError {
    fn from(message: &str) -> Self {
        Self::before_spawn(message)
    }
}

struct OneClickFailure {
    message: String,
    rollback: OneClickRollbackContext,
}

// Science 0.1.25 gives boot quick_check a 300s query timeout. Its own warning
// says the subsequently unblocked migration can take about 30 minutes, so the
// recovery restart has a separate finite ceiling instead of the ordinary 8s
// launch budget.
const SCIENCE_DB_REVERIFY_BUDGET_MS: u64 = 305_000;
const SCIENCE_DB_RECOVERY_RESTART_BUDGET_MS: u64 = 30 * 60 * 1_000 + 10_000;
const SCIENCE_HEALTH_BOOTSTRAP_BUDGET_MS: u64 = 60_000;

fn science_db_reverify_budget_ms() -> u64 {
    #[cfg(test)]
    if let Ok(value) = std::env::var("CSSWITCH_TEST_DB_REVERIFY_BUDGET_MS") {
        if let Ok(value) = value.parse::<u64>() {
            return value.max(POLL_INTERVAL_MS);
        }
    }
    SCIENCE_DB_REVERIFY_BUDGET_MS
}

fn science_db_recovery_restart_budget_ms() -> u64 {
    #[cfg(test)]
    if let Ok(value) = std::env::var("CSSWITCH_TEST_DB_RECOVERY_RESTART_BUDGET_MS") {
        if let Ok(value) = value.parse::<u64>() {
            return value.max(POLL_INTERVAL_MS);
        }
    }
    SCIENCE_DB_RECOVERY_RESTART_BUDGET_MS
}

fn open_authenticated_science_health_session(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    token: &ScienceManagedLaunchToken,
    deadline: Instant,
) -> Result<ScienceHealthSession, String> {
    if !crate::runtime::science::managed_launch_token_is_current_for_runtime(token, runtime) {
        return Err("science_db_listener_identity_changed".into());
    }
    let context = runtime
        .skill_install_host_context(port)
        .map_err(|_| "science_api_health_control_context_invalid".to_string())?;
    let session = open_science_health_session_before(&context, deadline)
        .map_err(science_health_control_error)?;
    if !crate::runtime::science::managed_launch_token_is_current_for_runtime(token, runtime) {
        return Err("science_db_listener_identity_changed".into());
    }
    Ok(session)
}

fn science_health_control_error(error: csswitch_skill_install_core::AttachError) -> String {
    if error.retryable
        && matches!(
            error.code.as_str(),
            "SCIENCE_HEALTH_UNREACHABLE"
                | "SCIENCE_HEALTH_TIMEOUT"
                | "SCIENCE_CONTROL_TIMEOUT"
                | "SCIENCE_HEALTH_HTTP_STATUS"
        )
    {
        "science_api_health_unreachable".into()
    } else {
        format!("science_api_health_control_failed code={}", error.code)
    }
}

fn authenticated_science_db_health(
    session: &ScienceHealthSession,
    timeout: Duration,
) -> Result<proc::ScienceDbHealth, String> {
    let body = session
        .read_health_with_timeout(timeout)
        .map_err(science_health_control_error)?;
    let body =
        std::str::from_utf8(&body).map_err(|_| "science_api_health_malformed".to_string())?;
    proc::science_db_health_from_body(body)
}

fn wait_for_science_db_reverify(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    token: &ScienceManagedLaunchToken,
) -> Result<proc::ScienceDbHealth, String> {
    let deadline = Instant::now() + Duration::from_millis(science_db_reverify_budget_ms());
    let bootstrap_deadline =
        deadline.min(Instant::now() + Duration::from_millis(SCIENCE_HEALTH_BOOTSTRAP_BUDGET_MS));
    let session = loop {
        let remaining = bootstrap_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("science_api_health_bootstrap_timeout".into());
        }
        match open_authenticated_science_health_session(port, runtime, token, bootstrap_deadline) {
            Ok(session) => break session,
            Err(error)
                if error == "science_api_health_unreachable"
                    && Instant::now() < bootstrap_deadline =>
            {
                std::thread::sleep(
                    Duration::from_millis(POLL_INTERVAL_MS)
                        .min(bootstrap_deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("science_db_reverify_timeout".into());
        }
        if !crate::runtime::science::managed_launch_token_is_current_for_runtime(token, runtime) {
            return Err("science_db_listener_identity_changed".into());
        }
        match authenticated_science_db_health(&session, remaining.min(Duration::from_secs(5))) {
            Ok(state) => {
                if !crate::runtime::science::managed_launch_token_is_current_for_runtime(
                    token, runtime,
                ) {
                    return Err("science_db_listener_identity_changed".into());
                }
                match state {
                    proc::ScienceDbHealth::ReverifyPending if Instant::now() < deadline => {
                        std::thread::sleep(
                            Duration::from_millis(POLL_INTERVAL_MS)
                                .min(deadline.saturating_duration_since(Instant::now())),
                        );
                    }
                    proc::ScienceDbHealth::ReverifyPending => {
                        return Err("science_db_reverify_timeout".into())
                    }
                    other => return Ok(other),
                }
            }
            Err(error)
                if matches!(
                    error.as_str(),
                    "science_api_health_unreachable" | "science_api_health_incomplete"
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(
                    Duration::from_millis(POLL_INTERVAL_MS)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error)
                if matches!(
                    error.as_str(),
                    "science_api_health_unreachable" | "science_api_health_incomplete"
                ) =>
            {
                return Err("science_db_reverify_timeout".into())
            }
            Err(error) => return Err(error),
        }
    }
}

#[derive(Clone)]
struct PriorScienceContext {
    runtime: ScienceRuntimeIdentity,
    port: u16,
    launch_token: ScienceManagedLaunchToken,
}

enum AuthorityCaptureAfterQuiesceError {
    PriorScienceRestored(String),
    RestartRequired(String),
}

impl OneClickRollbackContext {
    fn failure(&self, message: impl Into<String>) -> OneClickFailure {
        OneClickFailure {
            message: message.into(),
            rollback: self.clone(),
        }
    }
}

#[allow(clippy::result_large_err)]
fn one_click_step<T, E: std::fmt::Display>(
    result: Result<T, E>,
    rollback: &OneClickRollbackContext,
) -> Result<T, OneClickFailure> {
    result.map_err(|error| rollback.failure(error.to_string()))
}

// ---------- 沙箱启动命令构造（跨平台：unix zsh 脚本 / Windows 原生 serve） ----------

/// 从代理 URL 提取 `host:port` 的端口（等价脚本的 _PROXY_HOSTPORT 解析）。
#[cfg(windows)]
fn windows_proxy_port(proxy_url: &str) -> Option<u16> {
    proxy_url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .and_then(|hostport| hostport.rsplit_once(':'))
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

/// 快速失败代理地址（等价脚本的 _FASTFAIL_PROXY：剥掉 scheme 与路径）。
#[cfg(windows)]
fn windows_fastfail_proxy(proxy_url: &str) -> String {
    let hostport = proxy_url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(proxy_url);
    format!("http://{hostport}")
}

/// 路径任一祖先（含自身）是符号链接即拒绝（等价脚本的 path_contains_symlink，
/// 逐级 symlink_metadata 检查；Windows 目录挂载点同样表现为 symlink）。
#[cfg(windows)]
fn windows_path_contains_symlink(path: &Path) -> bool {
    let mut current = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(_) => return false, // 缺失的尾部组件由调用方另行处理
        }
        if !current.pop() {
            return false;
        }
    }
}

/// 校验 Science opaque-root 启动绑定（等价 validate_science_opaque_bindings 的
/// 存在性/目录类型/dev:ino 身份部分；Windows 身份经平台原语获取）。
#[cfg(windows)]
fn windows_validate_opaque_bindings(data_dir: &Path, bindings: &str) -> Result<(), String> {
    for binding in bindings.split(';') {
        let Some((name, expected)) = binding.split_once('=') else {
            return Err("拒绝：Science opaque-root 启动绑定格式非法".into());
        };
        if !matches!(
            name,
            "conda" | "runtime" | "seed-assets" | "r-libs" | "sbx-bind-src"
        ) {
            return Err("拒绝：Science opaque-root 启动绑定名称非法".into());
        }
        let target = data_dir.join(name);
        if expected == "absent" {
            if target.symlink_metadata().is_ok() {
                return Err("拒绝：Science opaque root 在启动前出现".into());
            }
            continue;
        }
        let Some((device_text, inode_text)) = expected.split_once(':') else {
            return Err("拒绝：Science opaque-root 启动绑定格式非法".into());
        };
        let metadata = match std::fs::symlink_metadata(&target) {
            Ok(metadata) => metadata,
            Err(_) => return Err("拒绝：Science opaque root 在启动前被替换".into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("拒绝：Science opaque root 在启动前被替换".into());
        }
        match crate::platform::identity_of_path(&target) {
            Ok(identity) => {
                let device_ok = device_text
                    .parse::<u64>()
                    .map(|value| value == identity.dev)
                    .unwrap_or(false);
                let inode_ok = inode_text
                    .parse::<u64>()
                    .map(|value| value == identity.ino)
                    .unwrap_or(false);
                if !device_ok || !inode_ok {
                    return Err("拒绝：Science opaque root 启动绑定已变化".into());
                }
            }
            Err(_) => return Err("拒绝：Science opaque root 启动绑定已变化".into()),
        }
    }
    Ok(())
}

/// Windows 原生启动预检（等价脚本的铁律护栏）。返回 Some(原因) 时不得启动。
/// macOS keychain 与系统 SSH stub 部分在 Windows 上不存在：按
/// REUSE_SYSTEM_SSH=0 处理（不启用系统 SSH，也不需要钥匙串）。
#[cfg(windows)]
fn windows_sandbox_launch_refusal(
    port: u16,
    proxy_url: &str,
    opaque_bindings: Option<&str>,
    version_prechecked: bool,
) -> Option<String> {
    let sandbox_home = crate::runtime::science::sandbox_home();
    let data_dir = sandbox_home.join(".claude-science");
    // 铁律断言：绝不使用真实目录 / 真实端口。
    if port == 8765 {
        return Some("拒绝：端口 8765 是真实实例保留端口".into());
    }
    if port == u16::MAX {
        return Some("拒绝：Science 端口必须小于 65535，才能分配隔离预览端口".into());
    }
    let preview_port = port.wrapping_add(1);
    if preview_port == 8765 {
        return Some("拒绝：预览端口会命中真实实例保留端口 8765".into());
    }
    if windows_proxy_port(proxy_url) == Some(preview_port) {
        return Some(format!(
            "拒绝：预览端口 {preview_port} 与 CSSwitch Gateway 端口冲突"
        ));
    }
    // data-dir 的真实路径不得指向真实 Science 目录。
    if let Some(real_home) = crate::platform::home_dir() {
        let real_data_dir = real_home.join(".claude-science");
        if let (Ok(actual), Ok(real)) = (
            std::path::absolute(&data_dir),
            std::path::absolute(&real_data_dir),
        ) {
            if actual.to_string_lossy().to_ascii_lowercase()
                == real.to_string_lossy().to_ascii_lowercase()
            {
                return Some("拒绝：data-dir 的真实路径指向真实目录".into());
            }
        }
    }
    if windows_path_contains_symlink(&data_dir) {
        return Some("拒绝：Science data-dir 路径包含符号链接".into());
    }
    // opaque 绑定：版本已预检时必须提供，且逐项校验身份。
    match opaque_bindings {
        None | Some("") if version_prechecked => {
            return Some("拒绝：缺少 Science opaque-root 启动绑定".into());
        }
        Some(bindings) if !bindings.is_empty() => {
            if let Err(refusal) = windows_validate_opaque_bindings(&data_dir, bindings) {
                return Some(refusal);
            }
        }
        _ => {}
    }
    // data-dir 只承载持久化状态；由本启动器建立（等价脚本的 mkdir -p）。
    if let Err(error) = std::fs::create_dir_all(&data_dir) {
        return Some(format!("拒绝：无法创建隔离 Science data-dir：{error}"));
    }
    if windows_path_contains_symlink(&data_dir) {
        return Some("拒绝：Science data-dir 路径在初始化期间发生符号链接变化".into());
    }
    None
}

/// 脚本约定的退出码 70：证明启动已被尝试（环境可能已被触碰），桌面事务据此
/// 把候选停止证明降级为 unproven（launch_attempted=true）。
#[cfg(windows)]
fn windows_sweep_sandbox_leftovers() {
    use std::os::windows::process::CommandExt;
    // 杀残留 winsbx 容器进程与指向沙箱的孤儿 Science 实例。只动命令行
    // 里含 .csswitch 的进程，真实应用（无 --data-dir）不受影响。
    let kill = |name: &str| {
        let _ = Command::new("taskkill")
            .args(["/IM", name, "/F"])
            .creation_flags(0x0800_0000)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };
    kill("operon-winsbx.exe");
    kill("operon-winsbx-stdio-owner.exe");
    let script = "Get-CimInstance Win32_Process -Filter \"Name='claude-science.exe'\" | Where-Object { $_.CommandLine -match '.csswitch' } | Select-Object -ExpandProperty ProcessId";
    if let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .creation_flags(0x0800_0000)
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Ok(pid) = line.trim().parse::<u32>() {
                let _ = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .creation_flags(0x0800_0000)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(1_500));
}

/// 「全部停止」的深度清扫：先杀残留容器与孤儿 Science，再删除回滚快照目录。
/// 保守策略：存在 pending-authority-cleanup 清单时跳过快照删除（留给状态机
/// 处理），只报告未清理。返回给 UI 的人读摘要。
#[cfg(windows)]
pub(crate) fn deep_clean_sandbox_leftovers() -> String {
    windows_sweep_sandbox_leftovers();
    let mut removed = 0usize;
    let mut failed = Vec::new();
    let mut kept_manifest = false;
    let sandbox_root = match crate::runtime::science::sandbox_home().parent() {
        Some(parent) => parent.to_path_buf(),
        None => return "清扫：无法定位沙箱根目录".into(),
    };
    // 读失败按"状态未知"处理：跳过快照删除（保守），只清进程残留。
    if config::read_pending_authority_cleanup_manifest(&config::default_dir())
        .map_or(true, |manifest| manifest.is_some())
    {
        kept_manifest = true;
    }
    if !kept_manifest {
        if let Ok(entries) = std::fs::read_dir(&sandbox_root) {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str() else {
                    continue;
                };
                if !pending_cleanup_name_is_valid(name) {
                    continue;
                }
                let path = crate::platform::extend_max_path(&entry.path());
                let mut last_error = None;
                for _ in 0..3 {
                    match std::fs::remove_dir_all(&path) {
                        Ok(()) => {
                            removed += 1;
                            last_error = None;
                            break;
                        }
                        Err(error) => {
                            last_error = Some(error);
                            std::thread::sleep(std::time::Duration::from_millis(2_000));
                        }
                    }
                }
                if let Some(error) = last_error {
                    failed.push(format!("{name}（{error}）"));
                }
            }
        }
    }
    let mut summary = String::from("已清理残留的后台进程");
    if removed > 0 {
        summary.push_str(&format!("、残留启动备份×{removed}"));
    }
    if kept_manifest {
        summary.push_str("、有正在恢复中的记录，启动备份保留");
    }
    if !failed.is_empty() {
        summary.push_str(&format!("、部分清理失败：{}", failed.join("、")));
    }
    format!("已顺带{summary}")
}

#[cfg(not(windows))]
pub(crate) fn deep_clean_sandbox_leftovers() -> String {
    String::new()
}

fn windows_exit_code_70_command() -> Command {
    let mut command = Command::new("cmd");
    command.args(["/d", "/s", "/c", "exit", "70"]);
    crate::platform::configure_spawn(&mut command);
    command
}

/// 构造沙箱启动命令：unix 由 zsh 执行打包脚本（保持既有契约不变）；
/// Windows 无 zsh，直接构造 `science serve ... --detached` 原生命令，并注入
/// 隔离 HOME（HOME+USERPROFILE）与代理外联环境。
fn sandbox_launch_command(
    launch: &Path,
    port: u16,
    science_bin: &Path,
    proxy_url: &str,
) -> Command {
    #[cfg(unix)]
    {
        let mut command = Command::new("zsh");
        command
            .arg(launch)
            .arg("--port")
            .arg(port.to_string())
            .arg("--skip-oauth-forge");
        let _ = (science_bin, proxy_url);
        command
    }
    #[cfg(windows)]
    {
        // Windows 语义：护栏预检在 apply_sandbox_launch_guard 中完成；系统 SSH
        // 按未授权处理（不注入 SSH bridge PATH 与 CSSWITCH_SYSTEM_SSH_CONFIG）。
        let _ = launch;
        let sandbox_home = crate::runtime::science::sandbox_home();
        let data_dir = sandbox_home.join(".claude-science");
        // 同理：conda_home 的自动探测（USERPROFILE\.claude-science\conda）会
        // 落到沙箱内的空 conda；而 winsbx 设计上共享真实安装的 conda 环境
        // （ro-root 已授权）。经官方 config.toml [paths] 显式指向真实 conda。
        if let Some(real_home) = crate::platform::home_dir() {
            let conda_home = real_home.join(".claude-science").join("conda");
            if conda_home.is_dir() {
                let config_path = data_dir.join("config.toml");
                let content =
                    format!("[paths]\r\nconda_home = '{}'\r\n", conda_home.display());
                if std::fs::read_to_string(&config_path).unwrap_or_default() != content {
                    let _ = std::fs::write(&config_path, content);
                }
            }
        }
        let mut command = Command::new(science_bin);
        command
            .arg("serve")
            .arg("--data-dir")
            .arg(data_dir)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--sandbox-port")
            .arg(port.wrapping_add(1).to_string())
            .arg("--no-browser")
            .arg("--no-auto-update")
            .arg("--detached");
        // HOME 与 USERPROFILE 都指向沙箱：Windows 版 Science 的凭据目录按
        // USERPROFILE 推导（token 存 <auth_dir>/.oauth-tokens），保留真实
        // USERPROFILE 会让 daemon 读真实目录的空 token → UI 永远显示登录页。
        // 数据隔离由显式 --data-dir 双重保证；首次 provisioning 用真实环境
        // 预先完成（见 apply_sandbox_launch_guard），之后 serve 不再触网。
        command.env("HOME", &sandbox_home);
        command.env("USERPROFILE", &sandbox_home);
        // 沙箱化 USERPROFILE 后，已知目录（SHGetKnownFolderPath → 注册表
        // %USERPROFILE%\AppData\...）展开落到沙箱 home——目录不存在时
        // winsbx fence 会拒绝启动容器单元（Python/repl）。预建结构。
        for known in ["AppData\\Local", "AppData\\Roaming", "AppData\\LocalLow"] {
            let _ = std::fs::create_dir_all(sandbox_home.join(known));
        }
        command.env("ANTHROPIC_BASE_URL", proxy_url);
        // Windows 版 Science 的凭据解析第一优先级是环境变量
        // （ANTHROPIC_API_KEY → ANTHROPIC_AUTH_TOKEN，全无则报
        // "No credentials available" 并在 UI 显示登录页）；0.1.55 已不读
        // macOS 的 .oauth-tokens 布局，因此第三方模式在 Windows 上用占位
        // API key 让 daemon 视为「有凭据」。对上游的真实鉴权由网关完成
        // （路径密钥门禁 + 转发时替换为 provider key），该值对上游无意义。
        command.env("ANTHROPIC_API_KEY", "csswitch-managed-third-party");
        let fastfail = windows_fastfail_proxy(proxy_url);
        command
            .env("https_proxy", &fastfail)
            .env("HTTPS_PROXY", &fastfail)
            .env("no_proxy", "127.0.0.1,localhost,::1")
            .env("NO_PROXY", "127.0.0.1,localhost,::1");
        crate::platform::configure_spawn(&mut command);
        command
    }
}

/// 启动前护栏：unix 由 zsh 脚本自行校验（无操作）；Windows 执行原生预检 +
/// 首次启动前的原生沙箱 provisioning，失败时把启动命令替换为脚本约定的
/// 退出码 70 占位命令。
fn apply_sandbox_launch_guard(
    command: &mut Command,
    port: u16,
    proxy_url: &str,
    opaque_bindings: Option<&str>,
    version_prechecked: bool,
) {
    #[cfg(unix)]
    {
        let _ = (command, port, proxy_url, opaque_bindings, version_prechecked);
    }
    #[cfg(windows)]
    {
        // 原生沙箱 provisioning 必须用真实用户环境执行一次（读真实 AppData
        // 构建保护根表；serve 阶段的沙箱化 USERPROFILE 会让它报 fence I7）。
        // 完成态持久化后跳过。失败 → 明确的手动恢复指引 + exit 70。
        if let Some(program) = command.get_program().to_str().map(String::from) {
            let marker = crate::runtime::science::sandbox_home().join("sandbox-setup.done");
            if !marker.exists() {
                let science_bin = std::path::PathBuf::from(&program);
                if windows_ensure_sandbox_provisioned(&science_bin, &marker).is_err() {
                    // 详细原因已写入 sandbox-setup.last-error.txt。
                    *command = windows_exit_code_70_command();
                }
            }
        }
        if windows_sandbox_launch_refusal(port, proxy_url, opaque_bindings, version_prechecked)
            .is_some()
        {
            *command = windows_exit_code_70_command();
        }
    }
}

/// 用真实用户环境执行一次 `claude-science sandbox setup`（幂等；成功后写
/// 标记文件）。首次约 1-4 分钟（conda 只读根遍历），之后秒级 no-op。
fn windows_ensure_sandbox_provisioned(
    science_bin: &Path,
    marker: &Path,
) -> Result<(), String> {
    let data_dir = crate::runtime::science::sandbox_home().join(".claude-science");
    let error_file = crate::runtime::science::sandbox_home().join("sandbox-setup.last-error.txt");
    let data_dir_display = data_dir.display().to_string();
    let mut command = Command::new(science_bin);
    command
        .arg("sandbox")
        .arg("setup")
        .arg("--data-dir")
        .arg(&data_dir);
    crate::platform::configure_spawn(&mut command);
    let started = Instant::now();
    let failure = |detail: String| -> String {
        let _ = std::fs::write(&error_file, format!("{}\n", detail));
        detail
    };
    let output = command.output().map_err(|error| {
        failure(format!(
            "sandbox setup 启动失败：{error}；请手动执行 `claude-science sandbox setup --data-dir \"{data_dir_display}\"` 后重试"
        )
        .to_string())
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(failure(format!(
            "原生沙箱 provisioning 失败（exit {:?}，耗时 {:?}）：{}；请手动执行 `claude-science sandbox setup --data-dir \"{data_dir_display}\"`，或 `claude-science sandbox doctor` 诊断",
            output.status.code(),
            started.elapsed(),
            stderr.trim()
        )));
    }
    std::fs::write(
        marker,
        format!("provisioned_at={:?}\n", started.elapsed()),
    )
    .map_err(|error| format!("写 provisioning 标记失败：{error}"))?;
    Ok(())
}

/// 定位打包内的沙箱启动脚本：unix 必须存在（zsh 将执行它）；Windows 原生
/// 启动不使用脚本，只要求打包资源根可解析。
fn locate_sandbox_launch_asset(app_root: Option<PathBuf>) -> Result<PathBuf, String> {
    let root = app_root.ok_or(
        "找不到 scripts/launch-virtual-sandbox.sh（打包资源或仓库根均未命中）。".to_string(),
    )?;
    let launch = root.join("scripts/launch-virtual-sandbox.sh");
    #[cfg(unix)]
    if !launch.is_file() {
        return Err("找不到 scripts/launch-virtual-sandbox.sh。".into());
    }
    #[cfg(windows)]
    let _ = &launch;
    Ok(launch)
}

fn restart_prior_science<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    prior: &PriorScienceContext,
) -> Result<(), String> {
    restart_managed_science_with_budget(
        app,
        state,
        lifecycle,
        prior,
        operation::SANDBOX_HEALTH_BUDGET_MS,
    )
    .map_err(|error| error.to_string())
}

fn restart_managed_science_with_budget<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    _lifecycle: &lifecycle::Lifecycle,
    prior: &PriorScienceContext,
    health_budget_ms: u64,
) -> Result<(), ManagedScienceRestartError> {
    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|error| error.to_string())?;
    if cfg.sandbox_port != prior.port {
        return Err("恢复 prior Science 时沙箱端口已变化".into());
    }
    if !runtime_identity_is_current(&prior.runtime) {
        return Err("恢复 prior Science 时 runtime 身份已变化".into());
    }
    if proc::loopback_port_in_use(prior.port, operation::LOCAL_HEALTH_TIMEOUT_MS) {
        return Err("恢复 prior Science 前端口仍被占用；拒绝接管未知 listener".into());
    }
    let (proxy_port, secret) = {
        let current = lock(state);
        if current.proxy.is_some() {
            (current.proxy_port, current.secret.clone())
        } else {
            (cfg.proxy_port, cfg.secret.clone())
        }
    };
    let ssh_hosts = if cfg.reuse_system_ssh {
        crate::runtime::ssh_bridge::validate_science_ssh_bridge(&sandbox_home())?
    } else {
        Vec::new()
    };
    let launch = {
        #[cfg(unix)]
        {
            let root = asset_root(app).ok_or("恢复 prior Science 时找不到打包资源")?;
            let launch = root.join("scripts/launch-virtual-sandbox.sh");
            if !launch.is_file() {
                return Err("恢复 prior Science 时启动脚本缺失".into());
            }
            launch
        }
        #[cfg(windows)]
        {
            // Windows：原生启动不依赖 zsh 脚本，只要求打包资源根可解析。
            locate_sandbox_launch_asset(asset_root(app))?
        }
    };
    let logf = open_log("sandbox.log").map_err(|error| error.to_string())?;
    let logf2 = logf.try_clone().map_err(|error| error.to_string())?;
    let proxy_url = format!("http://127.0.0.1:{proxy_port}/{secret}");
    let deadline = Instant::now() + Duration::from_millis(health_budget_ms.max(POLL_INTERVAL_MS));
    let mut launch_command =
        sandbox_launch_command(&launch, prior.port, &prior.runtime.path, &proxy_url);
    launch_command
        .env("SANDBOX_HOME", sandbox_home())
        .env("SCIENCE_BIN", &prior.runtime.path)
        .env("CSSWITCH_RUNTIME_VERSION_PRECHECKED", "1")
        .env("CSSWITCH_PROXY_URL", &proxy_url)
        .env(
            "CSSWITCH_REUSE_SYSTEM_SSH",
            if cfg.reuse_system_ssh { "1" } else { "0" },
        )
        .env("CSSWITCH_SYSTEM_SSH_HOSTS", ssh_hosts.join(" "))
        .stdout(Stdio::from(logf))
        .stderr(Stdio::from(logf2));
    apply_sandbox_launch_guard(&mut launch_command, prior.port, &proxy_url, None, true);
    let mut launch_child = launch_command
        .spawn()
        .map_err(|error| {
            ManagedScienceRestartError::before_spawn(format!(
                "恢复 prior Science 启动失败：{error}"
            ))
        })?;
    let status = loop {
        match launch_child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(
                    Duration::from_millis(POLL_INTERVAL_MS)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Ok(None) => {
                let _ = launch_child.kill();
                let _ = launch_child.wait();
                return Err(ManagedScienceRestartError::after_spawn_unproven(
                    "恢复 prior Science 启动脚本超过 absolute deadline",
                ));
            }
            Err(error) => {
                let _ = launch_child.kill();
                let _ = launch_child.wait();
                return Err(ManagedScienceRestartError::after_spawn_unproven(format!(
                    "恢复 prior Science 启动脚本状态未知：{error}"
                )));
            }
        }
    };
    if !status.success() {
        return Err(ManagedScienceRestartError::after_spawn_unproven(format!(
            "恢复 prior Science 启动脚本非零退出（{:?}）",
            status.code()
        )));
    }
    let mut healthy = false;
    while Instant::now() < deadline {
        std::thread::sleep(
            Duration::from_millis(POLL_INTERVAL_MS)
                .min(deadline.saturating_duration_since(Instant::now())),
        );
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let probe_timeout_ms = operation::LOCAL_HEALTH_TIMEOUT_MS.min(
            u64::try_from(remaining.as_millis())
                .unwrap_or(u64::MAX)
                .max(1),
        );
        if proc::http_health(prior.port, None, probe_timeout_ms) {
            healthy = true;
            break;
        }
    }
    if !healthy
        || Instant::now() > deadline
        || !sandbox_listener_matches_runtime(prior.port, &prior.runtime)
    {
        return Err(ManagedScienceRestartError::after_spawn_unproven(
            "恢复 prior Science 后 listener 健康或 runtime 身份不一致",
        ));
    }
    let _candidate_token = crate::runtime::science::uncommitted_managed_science_launch_token(
        prior.port,
        &prior.runtime,
    )
    .ok_or_else(|| {
        ManagedScienceRestartError::after_spawn_unproven(
            "恢复 prior Science 后无法建立精确的未提交启动身份",
        )
    })?;
    #[cfg(test)]
    {
        let mut seams = SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if seams.prior_restart_post_spawn_failure_port == Some(prior.port) {
            let listener_pid = crate::runtime::science::test_unique_listener_pid(prior.port)
                .ok_or("test-only prior Science listener identity missing after verification")?;
            let process_start =
                crate::runtime::science::test_process_start_identity_for_pid(listener_pid)
                    .ok_or("test-only prior Science process-start identity missing")?;
            seams.prior_restart_post_spawn_identity = Some((listener_pid, process_start));
            drop(seams);
            let mut sandbox = None;
            let mut url = None;
            let cleanup = stop_sandbox_with_launch_token(
                app,
                &mut sandbox,
                &mut url,
                Some(&prior.runtime),
                Some(&_candidate_token),
            );
            return Err(ManagedScienceRestartError::after_exact_cleanup(
                "test-only prior Science post-spawn validation failure",
                cleanup,
            ));
        }
    }
    let token =
        match crate::runtime::science::record_managed_science_launch(prior.port, &prior.runtime) {
            Ok(token) => token,
            Err(error) => {
                let mut sandbox = None;
                let mut url = None;
                let token_present = error.token().is_some();
                let cleanup = stop_sandbox_with_launch_token(
                    app,
                    &mut sandbox,
                    &mut url,
                    Some(&prior.runtime),
                    error.token(),
                );
                let message = format!(
                    "恢复 prior Science 时 fresh managed receipt 提交失败：{}",
                    error.message()
                );
                return Err(if token_present {
                    ManagedScienceRestartError::after_exact_cleanup(message, cleanup)
                } else {
                    ManagedScienceRestartError::after_spawn_unproven(message)
                });
            }
        };
    if !crate::runtime::science::managed_launch_token_is_current_for_runtime(&token, &prior.runtime)
    {
        let mut sandbox = None;
        let mut url = None;
        let cleanup = stop_sandbox_with_launch_token(
            app,
            &mut sandbox,
            &mut url,
            Some(&prior.runtime),
            Some(&token),
        );
        return Err(ManagedScienceRestartError::after_exact_cleanup(
            "恢复 prior Science 后 fresh managed receipt 回读不一致",
            cleanup,
        ));
    }
    let url = sandbox_url(prior.port, &prior.runtime);
    let mut current = lock(state);
    current.sandbox_port = prior.port;
    current.sandbox_url = Some(url);
    current.science_runtime = Some(prior.runtime.clone());
    current.science_confirmed_stopped = None;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn capture_authority_after_science_quiesce<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    config_dir: &Path,
    sandbox_home: &Path,
    auth_dir: &Path,
    config: &config::Config,
    prior_science: Option<&PriorScienceContext>,
) -> Result<OneClickAuthoritySnapshot, AuthorityCaptureAfterQuiesceError> {
    match OneClickAuthoritySnapshot::capture(config_dir, sandbox_home, auth_dir, config, state) {
        Ok(snapshot) => Ok(snapshot),
        Err(capture_error) => {
            if let Some(prior) = prior_science {
                match restart_prior_science(app, state, lifecycle, prior) {
                    Ok(()) => Err(AuthorityCaptureAfterQuiesceError::PriorScienceRestored(
                        capture_error,
                    )),
                    Err(restart_error) => Err(AuthorityCaptureAfterQuiesceError::RestartRequired(
                        format!("{capture_error}；prior_science_restart={restart_error}"),
                    )),
                }
            } else {
                Err(AuthorityCaptureAfterQuiesceError::RestartRequired(
                    capture_error,
                ))
            }
        }
    }
}

fn mark_stop_old_science_transaction(
    dir: &Path,
    active_profile_id: &str,
    previous_binding: Option<config::RuntimeBindingCommit>,
) -> Result<(), String> {
    config::update(dir, |current| {
        current.runtime_transaction = Some(config::RuntimeTransactionJournal {
            transaction_id: config::new_id(),
            target_profile_id: active_profile_id.to_string(),
            stage: "stop_old_science".into(),
            previous_binding: previous_binding.clone(),
            previous_gateway: None,
        });
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn clear_runtime_transaction(dir: &Path) -> Result<(), String> {
    config::update(dir, |current| current.runtime_transaction = None)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn commit_runtime_binding(dir: &Path, binding: config::RuntimeBindingCommit) -> Result<(), String> {
    config::update(dir, |current| {
        current.runtime_binding = Some(binding.clone());
        current.runtime_transaction = None;
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn history_recovery_choices(
    candidates: Vec<oauth_forge::HistoryOrgCandidate>,
) -> Result<(Vec<HistoryRecoveryChoice>, Vec<Value>), String> {
    if candidates.len() > 64 {
        return Err("历史记录候选超过安全上限（64），已拒绝生成恢复会话".into());
    }
    let choices = candidates
        .into_iter()
        .map(|candidate| HistoryRecoveryChoice {
            reference: config::new_id(),
            candidate,
        })
        .collect::<Vec<_>>();
    let visible = choices
        .iter()
        .enumerate()
        .map(|(index, choice)| {
            let label = if index < 26 {
                format!("历史记录 {}", (b'A' + index as u8) as char)
            } else {
                format!("历史记录 {}", index + 1)
            };
            json!({
                "reference": choice.reference,
                "label": label
            })
        })
        .collect();
    Ok((choices, visible))
}

#[allow(clippy::too_many_arguments)]
fn compensate_one_click_failure<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    dir: &Path,
    trace: &OperationTrace,
    authority_snapshot: &mut OneClickAuthoritySnapshot,
    prior_science: Option<&PriorScienceContext>,
    failure: OneClickFailure,
    mut reconcile_disposition: Option<&mut PriorScienceDisposition>,
) -> Result<Value, String> {
    let environment_uncertain = failure.rollback.launch_attempted;
    let cross_runtime_environment = environment_uncertain
        && prior_science.is_some_and(|prior| prior.runtime != failure.rollback.launch_runtime);
    let cleanup = if failure.rollback.candidate_stop_proof
        == ManagedScienceCandidateStopProof::Unproven
    {
        Err("code=science_candidate_stop_unproven".into())
    } else if !failure.rollback.launch_attempted && failure.rollback.launch_token.is_none() {
        Ok(())
    } else if failure.rollback.launch_confirmed_stopped {
        let receipt = dir.join("science-managed-launch.v1.json");
        if proc::loopback_port_in_use(
            failure.rollback.sandbox_port,
            operation::LOCAL_HEALTH_TIMEOUT_MS,
        ) || failure
            .rollback
            .launch_token
            .as_ref()
            .is_some_and(crate::runtime::science::managed_launch_token_process_is_alive)
            || receipt.exists()
        {
            Err("DB recovery restart 前已停止的 Science 身份重新出现；拒绝恢复 authority".into())
        } else {
            Ok(())
        }
    } else {
        let mut current = lock(state);
        let AppState {
            sandbox,
            sandbox_url,
            ..
        } = &mut *current;
        let result = stop_sandbox_with_launch_token(
            app,
            sandbox,
            sandbox_url,
            Some(&failure.rollback.launch_runtime),
            failure.rollback.launch_token.as_ref(),
        );
        if result.is_ok() {
            current.science_runtime = None;
            current.science_confirmed_stopped = Some(failure.rollback.launch_runtime.clone());
        }
        result
    };
    if let Err(cleanup_error) = cleanup.as_ref() {
        if environment_uncertain {
            if let Some(disposition) = reconcile_disposition.as_deref_mut() {
                *disposition = PriorScienceDisposition::EnvironmentUncertain;
            }
        }
        authority_snapshot.preserve_recovery = true;
        trace.finish("error=compensation_restore_blocked_science_cleanup_unproven");
        let environment_codes = if cross_runtime_environment {
            "；environment_uncertain；newer_runtime_required"
        } else if environment_uncertain {
            "；environment_uncertain"
        } else {
            ""
        };
        return Err(cleanup_required_error(
            &format!(
                "{}；compensation_science_cleanup_failed；compensation_restore_blocked_science_candidate；{cleanup_error}{environment_codes}",
                failure.message,
            ),
            &authority_snapshot.backup_root,
            "science_candidate_stop_unproven",
        ));
    }
    let ssh_cleanup = match failure.rollback.ssh_stub_transaction.as_ref() {
        Some(transaction) => transaction.compensate(&sandbox_home()),
        None => crate::runtime::settings::remove_managed_sandbox_ssh_stub(&sandbox_home()),
    };
    let rollback = authority_snapshot.restore_with_gateway(
        app,
        dir,
        state,
        lifecycle,
        failure.rollback.proxy_action,
    );
    let prior_restart = if rollback.is_ok() && !cross_runtime_environment {
        prior_science.map(|prior| restart_prior_science(app, state, lifecycle, prior))
    } else {
        None
    };
    let authorities_restored = cleanup.is_ok()
        && ssh_cleanup.is_ok()
        && rollback.is_ok()
        && prior_restart.as_ref().is_none_or(Result::is_ok);
    let prior_science_restored = authorities_restored
        && prior_science.is_some()
        && prior_restart.as_ref().is_some_and(Result::is_ok);
    if let Some(disposition) = reconcile_disposition {
        if environment_uncertain {
            *disposition = PriorScienceDisposition::EnvironmentUncertain;
        } else if prior_science_restored {
            *disposition = PriorScienceDisposition::Restored;
        }
    }
    let snapshot_cleanup = if authorities_restored {
        Some(authority_snapshot.cleanup_when_expendable())
    } else {
        authority_snapshot.preserve_recovery = true;
        None
    };
    trace.finish(if authorities_restored && environment_uncertain {
        "error=one_click_transaction_compensated environment=uncertain"
    } else if authorities_restored {
        "error=one_click_transaction_compensated environment=not_exposed"
    } else {
        "error=one_click_compensation_incomplete"
    });
    let mut codes = Vec::new();
    if cleanup.is_err() {
        codes.push("compensation_science_cleanup_failed".to_string());
    }
    if ssh_cleanup.is_err() {
        codes.push("compensation_ssh_cleanup_failed".to_string());
    }
    if rollback.is_err() {
        codes.push("compensation_restore_failed".to_string());
    }
    if environment_uncertain {
        codes.push("environment_uncertain".to_string());
    }
    if cross_runtime_environment {
        codes.push("newer_runtime_required".to_string());
    }
    if let Some(Err(error)) = prior_restart {
        #[cfg(test)]
        if error.contains("test-only prior Science post-spawn validation failure") {
            codes.push("test-only prior Science post-spawn validation failure".to_string());
        } else {
            codes.push("compensation_prior_science_restart_failed".to_string());
        }
        #[cfg(not(test))]
        {
            let _ = error;
            codes.push("compensation_prior_science_restart_failed".to_string());
        }
    }
    if let Some(Err(error)) = snapshot_cleanup {
        if error.contains("recovery_status=cleanup_required") {
            codes.push(error);
        } else {
            codes.push("compensation_snapshot_register_failed".to_string());
        }
    }
    let suffix = (!codes.is_empty()).then(|| format!("；{}", codes.join("; ")));
    Err(format!("{}{}", failure.message, suffix.unwrap_or_default()))
}

#[allow(clippy::too_many_arguments)]
fn healthy_reopen_with_gateway_rollback<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    trace: &OperationTrace,
    dir: &Path,
    cfg: &config::Config,
    active_profile: &config::Profile,
    auth_dir: &Path,
    sport: u16,
    running_runtime: &ScienceRuntimeIdentity,
    open_surface: bool,
) -> Result<Value, String> {
    let app_snapshot = AppAuthoritySnapshot::capture(state);
    let prior_config = cfg.clone();
    let attempt = (|| -> Result<Value, String> {
        let (_pport, secret, proxy_action) = ensure_proxy(
            app,
            state,
            lifecycle,
            Some(running_runtime),
            Some(trace),
        )?;
        verify_gateway_model_catalog_traced(trace, cfg.proxy_port, &secret, active_profile)?;
        let installer_bridge = skill_install_bridge_dir(&secret)?;
        let refreshed_cfg = config::load_from(dir).map_err(|error| error.to_string())?;
        let committed = crate::runtime::provider::desired_runtime_binding(
            &refreshed_cfg,
            refreshed_cfg
                .active_profile()
                .ok_or("生效 profile 在启动期间消失")?,
            running_runtime,
        )?;
        config::update(dir, |config| {
            config.runtime_binding = Some(committed.clone());
            config.runtime_transaction = None;
        })
        .map_err(|error| error.to_string())?;
        let installer = match current_skill_install_bridge_key() {
            Ok(installer_key) => {
                inspect_while_science_running(app, auth_dir, &installer_bridge, &installer_key)
            }
            Err(error) => RegistrationStatus::Warning(error),
        };
        let installer = configure_third_party_best_effort(
            app,
            installer,
            auth_dir,
            sport,
            running_runtime,
            false,
        );
        let url = sandbox_url(sport, running_runtime);
        {
            let mut current = lock(state);
            current.sandbox_port = sport;
            current.sandbox_url = Some(url.clone());
            current.science_runtime = Some(running_runtime.clone());
            current.science_confirmed_stopped = None;
        }
        let base = match proxy_action {
            ProxyAction::Reused => "已在运行",
            ProxyAction::Restarted => "已用新配置重启代理，Science 沿用不变",
        };
        let (message, fallback_url) = if open_surface {
            match open_science_surface(app, &url) {
                Ok("webview") => (format!("{base}，已重新打开 Science 窗口。"), None),
                Ok(_) => (format!("{base}，已向系统浏览器发送打开请求。"), None),
                Err(_) => (
                    format!("{base}，服务已就绪；自动打开失败。"),
                    Some(url.clone()),
                ),
            }
        } else {
            (format!("{base}，Science 绑定保持不变。"), None)
        };
        let message = append_installer_note(message, &installer);
        trace.finish(format!(
            "ok action=reopened proxy_action={}",
            proxy_action.as_str()
        ));
        Ok(json!({
            "msg": message,
            "action": "reopened",
            "stage": "complete",
            "status": "ok",
            "recovery_status": "not_needed",
            "fallback_url": fallback_url,
            "external_skill_installer": installer_status_json(&installer)
        }))
    })();
    match attempt {
        Ok(value) => Ok(value),
        Err(primary) => {
            let mut recovery_errors = Vec::new();
            if let Err(error) =
                config::save_to(dir, &prior_config).map_err(|error| error.to_string())
            {
                recovery_errors.push(format!("config={error}"));
            }
            if let Err(error) = app_snapshot.restore_with_gateway(
                app,
                state,
                lifecycle,
                ProxyAction::Restarted,
            ) {
                recovery_errors.push(format!("gateway={error}"));
            }
            if recovery_errors.is_empty() {
                Err(primary)
            } else {
                Err(format!(
                    "{primary}；healthy_reopen_recovery={}",
                    recovery_errors.join("; ")
                ))
            }
        }
    }
}

#[allow(clippy::result_large_err)]
fn one_click_login_with_options<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    runtime_choice: Option<&str>,
    open_surface: bool,
    mut reconcile_disposition: Option<&mut PriorScienceDisposition>,
) -> Result<Value, String> {
    let trace = OperationTrace::start(OperationKind::OneClickLogin, "command=one_click_login");
    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|e| e.to_string())?;
    let interrupted_environment_stage = cfg
        .runtime_transaction
        .as_ref()
        .map(|journal| journal.stage.as_str());
    let interrupted_environment_runtime_id = cfg
        .runtime_transaction
        .as_ref()
        .and_then(|journal| interrupted_science_environment_runtime_id(&journal.stage));
    validate_interrupted_science_transaction_entry(
        interrupted_environment_stage,
        interrupted_environment_runtime_id,
    )?;
    let active_profile = cfg
        .active_profile()
        .ok_or("未配置生效 profile，请先在面板选择或新建一条配置。")?;
    // 仅做启动计划校验（无生效/不合法即失败）；结果不再被后续步骤使用。
    let _active_launch = crate::runtime::provider::resolve_launch_plan(active_profile)?;
    crate::runtime::settings::validate_runtime_ports(cfg.proxy_port, cfg.sandbox_port)?;
    let sport = cfg.sandbox_port;

    let sbx_home = sandbox_home();
    let auth_dir = sbx_home.join(".claude-science");
    let ssh_prevalidation =
        crate::runtime::sandbox_session::prevalidate_one_click_system_ssh(&app, &cfg, &sbx_home)?;
    let ssh_stub_transaction = cfg
        .reuse_system_ssh
        .then(|| {
            crate::runtime::settings::ManagedSshStubTransaction::capture(
                &sbx_home,
                &ssh_prevalidation,
            )
        })
        .transpose()?;
    retry_pending_authority_cleanup(&state)?;
    let version_cache = { lock(&state).science_version_cache.clone() };

    let (remembered_runtime, confirmed_stopped) = {
        let st = lock(&state);
        (
            st.science_runtime.clone(),
            st.science_confirmed_stopped.clone(),
        )
    };
    let (science_state, running_runtime) = match remembered_runtime {
        Some(runtime) => {
            let science_state = probe_known_runtime(sport, &runtime);
            let running_runtime =
                (science_state == SandboxScienceState::RunningHealthy).then_some(runtime);
            (science_state, running_runtime)
        }
        None if confirmed_stopped
            .as_ref()
            .is_some_and(|runtime| runtime.source != ScienceRuntimeSource::CachedOnce)
            && !proc::loopback_port_in_use(sport, 100) =>
        {
            (SandboxScienceState::Stopped, None)
        }
        None => probe_sandbox_runtime_cached(sport, &version_cache)?,
    };
    let mut running_runtime_to_stop = None;
    let launch_runtime: ScienceRuntimeIdentity = match science_state {
        SandboxScienceState::RunningHealthy => {
            let running_runtime =
                running_runtime.ok_or("Science 状态为运行中，但无法确认其 binary 身份")?;
            validate_interrupted_science_environment_runtime(
                interrupted_environment_runtime_id,
                &running_runtime,
            )?;
            let desired_binding = crate::runtime::provider::desired_runtime_binding(
                &cfg,
                active_profile,
                &running_runtime,
            )?;
            let science_binding_matches = !crate::runtime::provider::science_restart_required(
                cfg.runtime_binding.as_ref(),
                &desired_binding,
            );
            let login_intact =
                oauth_forge::login_intact(&auth_dir, "virtual@localhost.invalid", &sbx_home);
            if login_intact && science_binding_matches {
                if cfg.reuse_system_ssh {
                    validate_running_system_ssh_bridge(&app, &sbx_home)?;
                }
                oauth_forge::bootstrap_marker_for_intact_login(
                    &auth_dir,
                    "virtual@localhost.invalid",
                    &sbx_home,
                )
                .map_err(|error| format!("补齐历史恢复标记失败：{error}"))?;
                let mut reopened = healthy_reopen_with_gateway_rollback(
                    &app,
                    &state,
                    lifecycle,
                    &trace,
                    &dir,
                    &cfg,
                    active_profile,
                    &auth_dir,
                    sport,
                    &running_runtime,
                    open_surface,
                )?;
                if interrupted_environment_runtime_id.is_some() {
                    reopened["recovery_status"] = json!("environment_uncertain");
                    reopened["environment_status"] = json!("uncertain");
                }
                return Ok(reopened);
            }
            let prior_runtime = running_runtime.clone();
            let selected = if login_intact {
                running_runtime
            } else {
                select_science_runtime_cached(runtime_choice, &version_cache)?
            };
            running_runtime_to_stop = Some(prior_runtime);
            selected
        }
        SandboxScienceState::Stopped => {
            select_science_runtime_cached(runtime_choice, &version_cache)?
        }
        SandboxScienceState::Unknown => {
            trace.finish("error=sandbox_state_unknown_before_start");
            if interrupted_environment_runtime_id.is_some() {
                return Err(
                    "上次启动在 Science 环境暴露边界中断，且当前 listener/runtime 身份无法确认；已拒绝自动恢复；environment_uncertain；recovery_status=manual_recovery_required"
                        .into(),
                );
            }
            return Err(format!(
                "无法确认隔离 Science 状态（端口 {sport} 或 data-dir 状态不一致）。请先停止占用该端口的进程后重试。"
            ));
        }
    };
    validate_interrupted_science_environment_runtime(
        interrupted_environment_runtime_id,
        &launch_runtime,
    )?;
    let mut rollback_context = OneClickRollbackContext {
        proxy_action: ProxyAction::Reused,
        sandbox_port: sport,
        launch_runtime: launch_runtime.clone(),
        launch_token: None,
        launch_attempted: false,
        launch_confirmed_stopped: false,
        candidate_stop_proof: ManagedScienceCandidateStopProof::NotRequired,
        ssh_stub_transaction,
    };
    let prior_science = match running_runtime_to_stop.as_ref() {
        Some(runtime) => Some(PriorScienceContext {
            runtime: runtime.clone(),
            port: sport,
            launch_token: crate::runtime::science::managed_launch_token_for_runtime(sport, runtime)
                .ok_or("prior Science managed launch 身份无法确认，拒绝停止或快照")?,
        }),
        None => None,
    };
    if let Some(prior) = prior_science.as_ref() {
        {
            let mut current = lock(&state);
            let AppState {
                sandbox,
                sandbox_url,
                ..
            } = &mut *current;
            stop_sandbox_with_launch_token(
                &app,
                sandbox,
                sandbox_url,
                Some(&prior.runtime),
                Some(&prior.launch_token),
            )?;
            current.science_runtime = None;
            current.science_confirmed_stopped = Some(prior.runtime.clone());
        }
        let receipt = dir.join("science-managed-launch.v1.json");
        if proc::loopback_port_in_use(sport, operation::LOCAL_HEALTH_TIMEOUT_MS)
            || crate::runtime::science::managed_launch_token_process_is_alive(&prior.launch_token)
            || receipt.exists()
        {
            let restart = restart_prior_science(&app, &state, lifecycle, prior);
            return Err(format!(
                "prior Science 未完成 verified stop，拒绝建立 authority 快照；restart={restart:?}"
            ));
        }
    }
    let prior_science_for_compensation = prior_science.as_ref();
    // Windows：daemon 的优雅关闭可能留下孤儿容器/子进程（daemon 内部的
    // powershell 清扫在此环境会 EPERM），它们持有 data-dir 文件句柄，会让
    // 权限快照复制撞 os_error 33。快照前清扫一轮。
    #[cfg(windows)]
    windows_sweep_sandbox_leftovers();
    trace.stage(
        OperationStage::AuthoritySnapshot,
        "phase=capture_begin scope=protected_state",
    );
    let mut authority_snapshot = match capture_authority_after_science_quiesce(
        &app,
        &state,
        lifecycle,
        &dir,
        &sbx_home,
        &auth_dir,
        &cfg,
        prior_science_for_compensation,
    ) {
        Ok(snapshot) => {
            trace.stage(
                OperationStage::AuthoritySnapshot,
                "phase=capture_end outcome=ok",
            );
            snapshot
        }
        Err(AuthorityCaptureAfterQuiesceError::PriorScienceRestored(cause)) => {
            trace.stage(
                OperationStage::AuthoritySnapshot,
                "phase=capture_end outcome=error prior_science=restored",
            );
            if let Some(disposition) = reconcile_disposition.as_deref_mut() {
                *disposition = PriorScienceDisposition::Restored;
            }
            return Err(cause);
        }
        Err(AuthorityCaptureAfterQuiesceError::RestartRequired(cause)) => {
            trace.stage(
                OperationStage::AuthoritySnapshot,
                "phase=capture_end outcome=error prior_science=restart_required",
            );
            return Err(cause);
        }
    };
    let transaction_result = (|| -> Result<Value, OneClickFailure> {
        if running_runtime_to_stop.is_some() {
            one_click_step(
                mark_stop_old_science_transaction(
                    &dir,
                    &active_profile.id,
                    cfg.runtime_binding.clone(),
                ),
                &rollback_context,
            )?;
        }
        let transaction_cfg = one_click_step(config::load_from(&dir), &rollback_context)?;
        one_click_step(
            advance_runtime_transaction(
                &dir,
                &active_profile.id,
                transaction_cfg.runtime_binding.clone(),
                "start_gateway",
            ),
            &rollback_context,
        )?;
        let preview_port = match sport.checked_add(1) {
            Some(port) => port,
            None => {
                return Err(
                    rollback_context.failure("沙箱端口必须小于 65535，才能分配隔离预览端口。")
                )
            }
        };
        if proc::loopback_port_in_use(preview_port, operation::LOCAL_HEALTH_TIMEOUT_MS) {
            return Err(rollback_context.failure(format!(
                "隔离 Science 预览端口 {preview_port} 已被占用；未启动或结束任何占用者。请修改沙箱端口后重试。"
            )));
        }
        lock(&state).science_confirmed_stopped = None;
        one_click_step(
            authority_snapshot.validate_science_restore_root(),
            &rollback_context,
        )?;
        let authority_active_stage = format!(
            "{AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX}{}",
            launch_runtime.environment_transaction_id()
        );
        one_click_step(
            advance_runtime_transaction(
                &dir,
                &active_profile.id,
                transaction_cfg.runtime_binding.clone(),
                &authority_active_stage,
            ),
            &rollback_context,
        )?;

        trace.stage(OperationStage::SandboxLogin, "ensure_virtual_login");
        let (forged, login_action) = match oauth_forge::ensure_virtual_login(
            &auth_dir,
            "virtual@localhost.invalid",
            &sbx_home,
        ) {
            Ok(result) => result,
            Err(oauth_forge::EnsureVirtualLoginError::HistoryChoiceRequired(candidates)) => {
                let (choices, visible_choices) =
                    one_click_step(history_recovery_choices(candidates), &rollback_context)?;
                {
                    let mut app_state = lock(&state);
                    app_state.science_confirmed_stopped = Some(launch_runtime.clone());
                    app_state.history_recovery = Some(HistoryRecoverySession {
                        active_profile_id: active_profile.id.clone(),
                        sandbox_port: sport,
                        auth_dir: auth_dir.clone(),
                        sandbox_root: sbx_home.clone(),
                        choices,
                    });
                }
                one_click_step(clear_runtime_transaction(&dir), &rollback_context)?;
                trace.finish("attention=history_choice_required");
                let mut value = json!({
                    "msg": "检测到多份旧历史记录。请选择要恢复的一份；CSSwitch 不会删除其他记录。",
                    "action": "history_choice_required",
                    "stage": "history_recovery",
                    "status": "attention",
                    "recovery_status": "choice_required",
                    "choices": visible_choices,
                    "fallback_url": null
                });
                one_click_step(
                    authority_snapshot.prepare_success(&mut value),
                    &rollback_context,
                )?;
                return Ok(value);
            }
            Err(oauth_forge::EnsureVirtualLoginError::Message(message)) => {
                return Err(rollback_context.failure(format!("写虚拟登录失败：{message}")));
            }
        };
        let _validated_login_identity = (
            &forged.auth_dir,
            &forged.account_uuid,
            &forged.org_uuid,
            &forged.enc_file,
        );
        let launch = match locate_sandbox_launch_asset(asset_root(&app)) {
            Ok(launch) => launch,
            Err(message) => return Err(rollback_context.failure(message)),
        };
        #[cfg(test)]
        if let Some(hosts) = std::env::var_os("CSSWITCH_TEST_SSH_HOSTS_AFTER_CAPTURE") {
            let config = one_click_step(
                crate::runtime::settings::system_ssh_config_path(),
                &rollback_context,
            )?;
            one_click_step(
                std::fs::write(&config, format!("Host {}\n", hosts.to_string_lossy())),
                &rollback_context,
            )?;
            one_click_step(
                crate::platform::set_path_mode(&config, 0o600),
                &rollback_context,
            )?;
        }
        let ssh_hosts = if cfg.reuse_system_ssh {
            one_click_step(
                crate::runtime::ssh_bridge::prepare_science_ssh_bridge(&sbx_home),
                &rollback_context,
            )?
        } else {
            one_click_step(
                crate::runtime::ssh_bridge::revoke_science_ssh_bridge(&sbx_home),
                &rollback_context,
            )?;
            Vec::new()
        };
        if cfg.reuse_system_ssh {
            if let Some(transaction) = rollback_context.ssh_stub_transaction.as_ref() {
                one_click_step(
                    transaction.validate_prepared_hosts(&ssh_hosts),
                    &rollback_context,
                )?;
            }
        }
        let (pport, secret, proxy_action) = one_click_step(
            ensure_proxy(
                &app,
                &state,
                lifecycle,
                Some(&launch_runtime),
                Some(&trace),
            ),
            &rollback_context,
        )?;
        rollback_context.proxy_action = proxy_action;
        one_click_step(
            verify_gateway_model_catalog_traced(&trace, pport, &secret, active_profile),
            &rollback_context,
        )?;
        let environment_pending_stage = format!(
            "{SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX}{}",
            launch_runtime.environment_transaction_id()
        );
        one_click_step(
            advance_runtime_transaction(
                &dir,
                &active_profile.id,
                transaction_cfg.runtime_binding.clone(),
                &environment_pending_stage,
            ),
            &rollback_context,
        )?;
        let installer_bridge =
            one_click_step(skill_install_bridge_dir(&secret), &rollback_context)?;
        let installer = match current_skill_install_bridge_key() {
            Ok(installer_key) => {
                register_before_science_start(&app, &auth_dir, &installer_bridge, &installer_key)
            }
            Err(error) => RegistrationStatus::Warning(error),
        };
        let proxy_url = format!("http://127.0.0.1:{pport}/{secret}");
        let logf = match open_log("sandbox.log") {
            Ok(file) => file,
            Err(error) => return Err(rollback_context.failure(format!("建日志失败：{error}"))),
        };
        {
            use std::io::Write;
            let mut writer = &logf;
            let _ = writeln!(
                writer,
                "[oauth] 虚拟登录已就绪（Rust，零 node；action={:?}；isolated=true）",
                login_action
            );
        }
        let logf2 = one_click_step(logf.try_clone(), &rollback_context)?;
        trace.stage(OperationStage::SandboxLaunch, format!("port={sport}"));
        if !runtime_identity_is_current(&launch_runtime) {
            return Err(
                rollback_context.failure("Science runtime 在预检后发生变化；已拒绝启动，请重试")
            );
        }
        one_click_step(
            authority_snapshot.validate_science_restore_root(),
            &rollback_context,
        )?;
        #[cfg(test)]
        if let Some(foreign_stub) =
            std::env::var_os("CSSWITCH_TEST_SSH_LATE_FOREIGN_STUB").map(std::path::PathBuf::from)
        {
            let parent = match foreign_stub.parent() {
                Some(parent) => parent,
                None => {
                    return Err(rollback_context.failure("SSH late-failure test stub has no parent"))
                }
            };
            one_click_step(std::fs::create_dir_all(parent), &rollback_context)?;
            one_click_step(
                crate::platform::set_path_mode(parent, 0o700),
                &rollback_context,
            )?;
            let mut file = one_click_step(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&foreign_stub),
                &rollback_context,
            )?;
            one_click_step(
                crate::platform::make_file_private(&file),
                &rollback_context,
            )?;
            one_click_step(
                std::io::Write::write_all(&mut file, b"foreign-test-stub-must-survive\n"),
                &rollback_context,
            )?;
            one_click_step(file.sync_all(), &rollback_context)?;
        }
        one_click_step(
            authority_snapshot.validate_science_restore_root(),
            &rollback_context,
        )?;
        let mut launch_command =
            sandbox_launch_command(&launch, sport, &launch_runtime.path, &proxy_url);
        launch_command
            .env("SANDBOX_HOME", sandbox_home())
            .env("SCIENCE_BIN", &launch_runtime.path)
            .env("CSSWITCH_RUNTIME_VERSION_PRECHECKED", "1")
            .env(
                "CSSWITCH_SCIENCE_OPAQUE_BINDINGS",
                authority_snapshot.science_opaque_bindings_env(),
            )
            .env("CSSWITCH_PROXY_URL", &proxy_url)
            .env(
                "CSSWITCH_REUSE_SYSTEM_SSH",
                if cfg.reuse_system_ssh { "1" } else { "0" },
            )
            .env("CSSWITCH_SYSTEM_SSH_HOSTS", ssh_hosts.join(" "))
            .stdout(Stdio::from(logf))
            .stderr(Stdio::from(logf2));
        apply_sandbox_launch_guard(
            &mut launch_command,
            sport,
            &proxy_url,
            Some(&authority_snapshot.science_opaque_bindings_env()),
            true,
        );
        let launch_child = launch_command.spawn();
        let status = match launch_child {
            Ok(mut child) => match child.wait() {
                Ok(status) => status,
                Err(error) => {
                    rollback_context.launch_attempted = true;
                    rollback_context.candidate_stop_proof =
                        ManagedScienceCandidateStopProof::Unproven;
                    return Err(rollback_context.failure(format!(
                        "起沙箱状态未知：{error}；code=science_candidate_stop_unproven"
                    )));
                }
            },
            Err(error) => {
                return Err(rollback_context.failure(format!("起沙箱失败：{error}")));
            }
        };
        rollback_context.launch_attempted = status.success()
            || status.code() == Some(SCIENCE_LAUNCH_ENVIRONMENT_EXPOSED_EXIT_CODE)
            || status.code().is_none();
        if let Some(transaction) = rollback_context.ssh_stub_transaction.as_mut() {
            transaction.observe_after_launch(&sbx_home);
        }
        if !status.success() {
            let tail = redact(&tail_file(&log_path("sandbox.log"), 600), &secret);
            return Err(rollback_context.failure(format!("起沙箱脚本失败。\n{tail}")));
        }
        {
            let mut current = lock(&state);
            current.sandbox_port = sport;
            current.science_runtime = Some(launch_runtime.clone());
            current.science_confirmed_stopped = None;
        }
        let mut healthy = false;
        for _ in 0..(operation::SANDBOX_HEALTH_BUDGET_MS / POLL_INTERVAL_MS) {
            std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            if proc::http_health(sport, None, operation::LOCAL_HEALTH_TIMEOUT_MS) {
                healthy = true;
                break;
            }
        }
        trace.stage(
            OperationStage::SandboxHealth,
            if healthy { "ready" } else { "not_ready" },
        );
        if !healthy {
            let tail = redact(&tail_file(&log_path("sandbox.log"), 600), &secret);
            return Err(
                rollback_context.failure(format!("沙箱起后探活超时（端口 {sport}）。\n{tail}"))
            );
        }
        if !sandbox_listener_matches_runtime(sport, &launch_runtime) {
            return Err(rollback_context.failure(format!(
                "端口 {sport} 有服务响应，但按 data-dir 确认不是本沙箱 Science（疑似被其它服务占用）。"
            )));
        }
        match crate::runtime::science::record_managed_science_launch(sport, &launch_runtime) {
            Ok(token) => rollback_context.launch_token = Some(token),
            Err(error) => {
                rollback_context.launch_token = error.token().cloned();
                return Err(rollback_context.failure(format!(
                    "Science 已启动但受管启动身份无法安全提交：{}",
                    error.message()
                )));
            }
        }
        one_click_step(
            advance_runtime_transaction(
                &dir,
                &active_profile.id,
                transaction_cfg.runtime_binding.clone(),
                "wait_science_db_reverify",
            ),
            &rollback_context,
        )?;
        let first_token = match rollback_context.launch_token.clone() {
            Some(token) => token,
            None => {
                return Err(rollback_context.failure("Science DB 检查缺少受管启动身份"));
            }
        };
        match one_click_step(
            wait_for_science_db_reverify(sport, &launch_runtime, &first_token),
            &rollback_context,
        )? {
            proc::ScienceDbHealth::Ready => {}
            proc::ScienceDbHealth::ReverifyPending => unreachable!(),
            proc::ScienceDbHealth::RestartRequired => {
                {
                    let mut current = lock(&state);
                    let AppState {
                        sandbox,
                        sandbox_url,
                        ..
                    } = &mut *current;
                    one_click_step(
                        stop_sandbox_with_launch_token(
                            &app,
                            sandbox,
                            sandbox_url,
                            Some(&launch_runtime),
                            Some(&first_token),
                        ),
                        &rollback_context,
                    )?;
                    current.science_runtime = None;
                    current.science_confirmed_stopped = Some(launch_runtime.clone());
                }
                rollback_context.launch_confirmed_stopped = true;
                if proc::loopback_port_in_use(sport, operation::LOCAL_HEALTH_TIMEOUT_MS)
                    || crate::runtime::science::managed_launch_token_process_is_alive(&first_token)
                    || dir.join("science-managed-launch.v1.json").exists()
                {
                    return Err(rollback_context
                        .failure("Science DB recovery 的首次受管进程未完成 verified stop"));
                }
                one_click_step(
                    advance_runtime_transaction(
                        &dir,
                        &active_profile.id,
                        transaction_cfg.runtime_binding.clone(),
                        "restart_science_after_db_heal",
                    ),
                    &rollback_context,
                )?;
                let recovery = PriorScienceContext {
                    runtime: launch_runtime.clone(),
                    port: sport,
                    // restart_managed_science_with_budget does not consume the
                    // stopped token; retaining it gives compensation an exact
                    // absence proof until the fresh receipt is committed.
                    launch_token: first_token.clone(),
                };
                if let Err(error) = restart_managed_science_with_budget(
                    &app,
                    &state,
                    lifecycle,
                    &recovery,
                    science_db_recovery_restart_budget_ms(),
                ) {
                    rollback_context.candidate_stop_proof = error.candidate_stop_proof;
                    return Err(rollback_context.failure(error.to_string()));
                }
                let second_token = one_click_step(
                    crate::runtime::science::managed_launch_token_for_runtime(
                        sport,
                        &launch_runtime,
                    )
                    .ok_or("Science DB recovery restart 缺少 fresh managed receipt"),
                    &rollback_context,
                )?;
                rollback_context.launch_token = Some(second_token.clone());
                rollback_context.launch_confirmed_stopped = false;
                one_click_step(
                    advance_runtime_transaction(
                        &dir,
                        &active_profile.id,
                        transaction_cfg.runtime_binding.clone(),
                        "verify_science_db_after_restart",
                    ),
                    &rollback_context,
                )?;
                let second_state = one_click_step(
                    wait_for_science_db_reverify(sport, &launch_runtime, &second_token),
                    &rollback_context,
                )?;
                if !crate::runtime::science::managed_launch_token_is_current_for_runtime(
                    &second_token,
                    &launch_runtime,
                ) || second_state != proc::ScienceDbHealth::Ready
                {
                    return Err(rollback_context.failure(format!(
                        "Science DB recovery 的第二次启动未达到 clear/clear：{second_state:?}"
                    )));
                }
            }
        }
        one_click_step(
            advance_runtime_transaction(
                &dir,
                &active_profile.id,
                transaction_cfg.runtime_binding.clone(),
                "verify_science_catalog",
            ),
            &rollback_context,
        )?;
        let installer = configure_third_party_best_effort(
            &app,
            installer,
            &auth_dir,
            sport,
            &launch_runtime,
            false,
        );
        let url = sandbox_url(sport, &launch_runtime);
        {
            let mut current = lock(&state);
            current.sandbox_port = sport;
            current.sandbox_url = Some(url.clone());
            current.science_runtime = Some(launch_runtime.clone());
            current.science_confirmed_stopped = None;
        }
        let started = match login_action {
            oauth_forge::LoginAction::Created => "已启动",
            _ => "沙箱已重新启动，沿用原有对话",
        };
        let refreshed_cfg = one_click_step(config::load_from(&dir), &rollback_context)?;
        let refreshed_profile = match refreshed_cfg.active_profile() {
            Some(profile) => profile,
            None => return Err(rollback_context.failure("生效 profile 在启动期间消失")),
        };
        let committed = one_click_step(
            crate::runtime::provider::desired_runtime_binding(
                &refreshed_cfg,
                refreshed_profile,
                &launch_runtime,
            ),
            &rollback_context,
        )?;
        one_click_step(commit_runtime_binding(&dir, committed), &rollback_context)?;
        let (message, fallback_url) = if open_surface {
            match open_science_surface(&app, &url) {
                Ok("webview") => (format!("{started}，已打开 Science 窗口。"), None),
                Ok(_) => (format!("{started}，已向系统浏览器发送打开请求。"), None),
                Err(_) => (
                    format!("{started}，服务已就绪；自动打开失败。"),
                    Some(url.clone()),
                ),
            }
        } else {
            (format!("{started}，Science 已按新模型目录刷新。"), None)
        };
        let message = append_installer_note(message, &installer);
        trace.stage(OperationStage::OpenBrowser, "done");
        trace.finish(format!(
            "ok action=started proxy_action={}",
            proxy_action.as_str()
        ));
        let mut value = json!({
            "msg": message,
            "action": "started",
            "stage": "complete",
            "status": "ok",
            "recovery_status": "not_needed",
            "fallback_url": fallback_url,
            "external_skill_installer": installer_status_json(&installer)
        });
        if interrupted_environment_runtime_id.is_some() {
            value["recovery_status"] = json!("environment_uncertain");
            value["environment_status"] = json!("uncertain");
        }
        one_click_step(
            authority_snapshot.prepare_success(&mut value),
            &rollback_context,
        )?;
        Ok(value)
    })();
    match transaction_result {
        Ok(value) => {
            authority_snapshot.commit();
            Ok(value)
        }
        Err(failure) => compensate_one_click_failure(
            &app,
            &state,
            lifecycle,
            &dir,
            &trace,
            &mut authority_snapshot,
            prior_science_for_compensation,
            failure,
            reconcile_disposition,
        ),
    }
}

#[cfg(test)]
mod transaction_tests {
    // 跨平台测试共用的导入。
    use super::{
        advance_runtime_transaction, gateway_model_catalog_timeout_ms,
        interrupted_science_environment_runtime_id, prevalidate_one_click_system_ssh,
        runtime_transaction_requires_snapshot_preservation, science_health_control_error,
        validate_interrupted_science_transaction_entry, verify_gateway_model_catalog,
        OneClickAuthoritySnapshot, AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX,
        SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX,
    };
    // 仅被 unix 门控测试使用的导入（Windows 上不编译，避免未用告警）。
    #[cfg(unix)]
    use super::{
        cleanup_tombstone_path, clear_runtime_transaction,
        finalize_registered_authority_cleanup, parse_pending_cleanup_manifest,
        retry_pending_authority_cleanup, test_arm_authority_cleanup_parent_sync_failure,
        test_arm_authority_snapshot_capture_failure, test_arm_authority_snapshot_cleanup_fault,
        test_arm_authority_snapshot_clone_errno,
        test_arm_authority_snapshot_completion_sync_failure,
        test_arm_authority_snapshot_directory_barrier,
        test_arm_authority_snapshot_fallback_create_failure,
        test_arm_authority_snapshot_parent_barrier, AuthorityCopyBudget,
        AuthoritySnapshotCategory, AuthoritySnapshotScope, AuthorityTreeSnapshot,
        PendingCleanupEntry, RegisteredAuthorityCleanup, MAX_AUTHORITY_FULL_COPY_FILE_BYTES,
        MAX_AUTHORITY_FULL_COPY_TOTAL_BYTES, MAX_AUTHORITY_SNAPSHOT_ENTRIES,
        MAX_AUTHORITY_SNAPSHOT_FILE_BYTES, MAX_AUTHORITY_SNAPSHOT_TOTAL_BYTES,
        PENDING_CLEANUP_MARKER_FILE, SCIENCE_OWNED_OPAQUE_ROOTS,
    };
    use crate::config::{self, Config, RuntimeBindingCommit};
    use crate::provider_contracts::ModelPolicy;
    use crate::runtime::proxy::ProxyAction;
    use crate::{AppState, SharedAppState};
    use csswitch_skill_install_core::AttachError;
    #[cfg(unix)]
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct ScopedEnv {
        saved: Vec<(String, Option<std::ffi::OsString>)>,
    }

    impl ScopedEnv {
        fn new() -> Self {
            Self { saved: Vec::new() }
        }

        fn set(&mut self, key: &str, value: impl AsRef<std::ffi::OsStr>) {
            self.saved.push((key.to_string(), std::env::var_os(key)));
            std::env::set_var(key, value);
        }

        fn remove(&mut self, key: &str) {
            self.saved.push((key.to_string(), std::env::var_os(key)));
            std::env::remove_var(key);
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            for (key, value) in self.saved.iter().rev() {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn health_bootstrap_retries_only_explicit_transport_failures() {
        let transient = science_health_control_error(AttachError {
            code: "SCIENCE_HEALTH_UNREACHABLE".into(),
            message: "safe transport failure".into(),
            retryable: true,
            uncertain: false,
        });
        assert_eq!(transient, "science_api_health_unreachable");

        for code in [
            "SCIENCE_RUNTIME_CHANGED",
            "SCIENCE_CONTROL_FAILED",
            "SCIENCE_NOT_READY",
        ] {
            let hard_failure = science_health_control_error(AttachError {
                code: code.into(),
                message: "safe hard failure".into(),
                retryable: true,
                uncertain: false,
            });
            assert!(
                hard_failure.starts_with("science_api_health_control_failed"),
                "{code} must never enter the transient bootstrap retry lane"
            );
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[allow(dead_code)]
    struct TreeEntry {
        kind: &'static str,
        mode: u32,
        bytes: Vec<u8>,
    }

    fn isolated_tmpdir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "csswitch-sandbox-transaction-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path.canonicalize().unwrap()
    }

    /// 快照树比对夹具：依赖 POSIX symlink/mode 语义，仅 unix 可用。
    #[cfg(unix)]
    fn tree(root: &Path) -> BTreeMap<PathBuf, TreeEntry> {
        fn walk(root: &Path, current: &Path, entries: &mut BTreeMap<PathBuf, TreeEntry>) {
            let metadata = match fs::symlink_metadata(current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Err(error) => panic!("cannot inspect {}: {error}", current.display()),
            };
            let relative = current.strip_prefix(root).unwrap().to_path_buf();
            if metadata.file_type().is_symlink() {
                entries.insert(
                    relative,
                    TreeEntry {
                        kind: "symlink",
                        mode: metadata.permissions().mode() & 0o777,
                        bytes: fs::read_link(current)
                            .unwrap()
                            .as_os_str()
                            .as_encoded_bytes()
                            .to_vec(),
                    },
                );
            } else if metadata.is_file() {
                entries.insert(
                    relative,
                    TreeEntry {
                        kind: "file",
                        mode: metadata.permissions().mode() & 0o777,
                        bytes: fs::read(current).unwrap(),
                    },
                );
            } else {
                assert!(metadata.is_dir(), "fixture contains a special file");
                entries.insert(
                    relative,
                    TreeEntry {
                        kind: "dir",
                        mode: metadata.permissions().mode() & 0o777,
                        bytes: Vec::new(),
                    },
                );
                let mut children = fs::read_dir(current)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect::<Vec<_>>();
                children.sort();
                for child in children {
                    walk(root, &child, entries);
                }
            }
        }

        let mut entries = BTreeMap::new();
        walk(root, root, &mut entries);
        entries
    }

    // 依赖 POSIX symlink/dev/ino/clonefile errno 语义；Windows 走合成身份，不适用。
    #[cfg(unix)]
    #[test]
    fn authority_snapshot_uses_independent_inodes_and_restores_in_place_mutation() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut science_0125_budget = AuthorityCopyBudget::default();
        AuthorityTreeSnapshot::charge_entry(
            &mut science_0125_budget,
            187_050_734,
            AuthoritySnapshotScope::ScienceData,
            AuthoritySnapshotCategory::CondaCache,
        )
        .expect("observed Science 0.1.25 files below 512 MiB must remain snapshotable");
        let mut oversized_budget = AuthorityCopyBudget::default();
        let oversized = AuthorityTreeSnapshot::charge_entry(
            &mut oversized_budget,
            MAX_AUTHORITY_SNAPSHOT_FILE_BYTES + 1,
            AuthoritySnapshotScope::ScienceData,
            AuthoritySnapshotCategory::ScienceRuntime,
        )
        .expect_err("authority files above 512 MiB must remain fail-closed");
        assert!(oversized.contains("code=authority_snapshot_file_limit"));
        assert!(oversized.contains("scope=science_data"));
        assert!(oversized.contains("category=science_runtime"));
        assert!(!oversized.contains('/'));

        let mut total_budget = AuthorityCopyBudget::default();
        for _ in 0..16 {
            AuthorityTreeSnapshot::charge_entry(
                &mut total_budget,
                MAX_AUTHORITY_SNAPSHOT_FILE_BYTES,
                AuthoritySnapshotScope::ScienceData,
                AuthoritySnapshotCategory::ScienceRuntime,
            )
            .expect("exact 8 GiB logical authority boundary must pass");
        }
        assert_eq!(total_budget.bytes, MAX_AUTHORITY_SNAPSHOT_TOTAL_BYTES);
        let total_error = AuthorityTreeSnapshot::charge_entry(
            &mut total_budget,
            1,
            AuthoritySnapshotScope::ScienceData,
            AuthoritySnapshotCategory::Other,
        )
        .expect_err("logical authority above 8 GiB must fail closed");
        assert!(total_error.contains("code=authority_snapshot_total_limit"));

        let mut entry_budget = AuthorityCopyBudget::default();
        for _ in 0..MAX_AUTHORITY_SNAPSHOT_ENTRIES {
            AuthorityTreeSnapshot::charge_entry(
                &mut entry_budget,
                0,
                AuthoritySnapshotScope::Test,
                AuthoritySnapshotCategory::Other,
            )
            .expect("exact entry boundary must pass");
        }
        let entry_error = AuthorityTreeSnapshot::charge_entry(
            &mut entry_budget,
            0,
            AuthoritySnapshotScope::Test,
            AuthoritySnapshotCategory::Other,
        )
        .expect_err("entry boundary plus one must fail closed");
        assert!(entry_error.contains("code=authority_snapshot_entry_limit"));

        let mut overflow_budget = AuthorityCopyBudget {
            bytes: u64::MAX,
            ..AuthorityCopyBudget::default()
        };
        let overflow_error = AuthorityTreeSnapshot::charge_entry(
            &mut overflow_budget,
            1,
            AuthoritySnapshotScope::Test,
            AuthoritySnapshotCategory::Other,
        )
        .expect_err("logical byte addition overflow must fail closed");
        assert!(overflow_error.contains("code=authority_snapshot_total_overflow"));

        let mut fallback_budget = AuthorityCopyBudget::default();
        AuthorityTreeSnapshot::charge_full_copy(
            &mut fallback_budget,
            MAX_AUTHORITY_FULL_COPY_FILE_BYTES,
            AuthoritySnapshotScope::Test,
            AuthoritySnapshotCategory::Other,
            c"blob-0",
        )
        .expect("a single file at the full-copy file boundary must pass");
        assert_eq!(
            fallback_budget.full_copy_bytes,
            MAX_AUTHORITY_FULL_COPY_TOTAL_BYTES,
            "文件级上限对齐基础预算后，单文件即占满全量复制总量"
        );
        let fallback_total_error = AuthorityTreeSnapshot::charge_full_copy(
            &mut fallback_budget,
            1,
            AuthoritySnapshotScope::Test,
            AuthoritySnapshotCategory::Other,
            c"blob-overflow",
        )
        .expect_err("full-copy boundary plus one must require clone support");
        assert!(fallback_total_error.contains("code=authority_snapshot_clone_required"));
        let fallback_file_error = AuthorityTreeSnapshot::charge_full_copy(
            &mut AuthorityCopyBudget::default(),
            MAX_AUTHORITY_FULL_COPY_FILE_BYTES + 1,
            AuthoritySnapshotScope::Test,
            AuthoritySnapshotCategory::Other,
            c"blob-too-big",
        )
        .expect_err("large individual full copy must require clone support");
        assert!(fallback_file_error.contains("code=authority_snapshot_clone_required"));
        assert!(
            fallback_file_error.contains("blob-too-big"),
            "超限报错必须带文件名便于定位：{fallback_file_error}"
        );

        let tmp = isolated_tmpdir("independent-inodes");
        let source = tmp.join("authority");
        let backup = tmp.join("rollback/authority");
        fs::create_dir_all(source.join("nested/empty")).unwrap();
        fs::create_dir(tmp.join("rollback")).unwrap();
        fs::write(source.join("database.db"), b"prior-database-bytes\n").unwrap();
        fs::write(source.join("nested/state.json"), br#"{"prior":true}"#).unwrap();
        symlink("state.json", source.join("nested/state-link")).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            source.join("database.db"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::set_permissions(
            source.join("nested/state.json"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let before = tree(&source);

        let mut snapshot = AuthorityTreeSnapshot::capture(source.clone(), backup.clone()).unwrap();
        for relative in [Path::new("database.db"), Path::new("nested/state.json")] {
            let live = fs::metadata(source.join(relative)).unwrap();
            let saved = fs::metadata(backup.join(relative)).unwrap();
            assert_eq!(
                live.dev(),
                saved.dev(),
                "transaction snapshot must stay on the same isolated filesystem"
            );
            assert_ne!(
                live.ino(),
                saved.ino(),
                "transaction snapshot must never share a mutable inode with live authority"
            );
        }
        assert_eq!(tree(&backup), before);

        let mut database = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(source.join("database.db"))
            .unwrap();
        database.write_all(b"mutated-in-place\n").unwrap();
        database.sync_all().unwrap();
        fs::set_permissions(
            source.join("database.db"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::remove_file(source.join("nested/state.json")).unwrap();
        fs::remove_file(source.join("nested/state-link")).unwrap();
        symlink("new-authority", source.join("nested/state-link")).unwrap();
        fs::write(source.join("nested/new-authority"), b"must disappear\n").unwrap();
        fs::create_dir(source.join("new-directory")).unwrap();

        snapshot.restore().unwrap();
        assert_eq!(
            tree(&source),
            before,
            "restore must recover exact bytes, modes, empty directories, and object set"
        );
        let linked_target = tmp.join("linked-authority-target");
        let linked_source = tmp.join("linked-authority-root");
        fs::create_dir(&linked_target).unwrap();
        symlink(&linked_target, &linked_source).unwrap();
        let linked_error = AuthorityTreeSnapshot::capture(
            linked_source,
            tmp.join("rollback/linked-authority-root"),
        )
        .err()
        .expect("authority root symlinks must remain fail-closed");
        assert!(linked_error.contains("code=authority_snapshot_root_symlink"));

        let restore_source = tmp.join("restore-authority");
        let restore_backup = tmp.join("rollback/restore-authority");
        fs::create_dir(&restore_source).unwrap();
        fs::write(restore_source.join("state.json"), b"prior\n").unwrap();
        let mut restore_snapshot =
            AuthorityTreeSnapshot::capture(restore_source, restore_backup.clone()).unwrap();
        fs::remove_dir_all(&restore_backup).unwrap();
        symlink(&linked_target, &restore_backup).unwrap();
        let restore_error = restore_snapshot
            .restore()
            .expect_err("restore backup roots that become symlinks must remain fail-closed");
        assert!(
            restore_error.contains("code=authority_restore_backup_identity_changed")
                || restore_error.contains("code=authority_restore_backup_validate_failed")
        );

        for (label, errno) in [("enotsup", libc::ENOTSUP), ("exdev", libc::EXDEV)] {
            let fallback_source = tmp.join(format!("fallback-{label}"));
            let fallback_backup = tmp.join(format!("rollback/fallback-{label}"));
            fs::create_dir(&fallback_source).unwrap();
            fs::write(fallback_source.join("state"), b"fallback-bytes\n").unwrap();
            {
                let _clone_seam = test_arm_authority_snapshot_clone_errno(errno);
                AuthorityTreeSnapshot::capture(fallback_source.clone(), fallback_backup.clone())
                    .expect("ENOTSUP and EXDEV must use the bounded independent-copy fallback");
            }
            assert_eq!(
                fs::read(fallback_backup.join("state")).unwrap(),
                b"fallback-bytes\n"
            );
            let live = fs::metadata(fallback_source.join("state")).unwrap();
            let saved = fs::metadata(fallback_backup.join("state")).unwrap();
            assert!(
                live.dev() != saved.dev() || live.ino() != saved.ino(),
                "fallback must create an independent regular file"
            );
        }

        let unexpected_source = tmp.join("unexpected-clone-error");
        let unexpected_backup = tmp.join("rollback/unexpected-clone-error");
        fs::create_dir(&unexpected_source).unwrap();
        fs::write(unexpected_source.join("state"), b"unchanged\n").unwrap();
        {
            let _clone_seam = test_arm_authority_snapshot_clone_errno(libc::EIO);
            let error =
                AuthorityTreeSnapshot::capture(unexpected_source, unexpected_backup.clone())
                    .err()
                    .expect("unexpected clone errors must fail closed");
            assert!(error.contains("code=authority_snapshot_clone_failed"));
            assert!(error.contains("os_error=5"));
        }
        assert!(
            !unexpected_backup.join("state").exists(),
            "unexpected clone failure must not leave a destination file"
        );

        let injected_source = tmp.join("injected-fallback-failure");
        let injected_backup = tmp.join("rollback/injected-fallback-failure");
        fs::create_dir(&injected_source).unwrap();
        fs::write(injected_source.join("state"), b"unchanged\n").unwrap();
        {
            let _clone_seam = test_arm_authority_snapshot_clone_errno(libc::ENOTSUP);
            let _copy_seam = test_arm_authority_snapshot_fallback_create_failure();
            let error = AuthorityTreeSnapshot::capture(injected_source, injected_backup.clone())
                .err()
                .expect("fallback failure after create must fail closed");
            assert!(error.contains("code=authority_snapshot_copy_injected_failure"));
        }
        assert!(
            !injected_backup.join("state").exists(),
            "failed fallback must unlink the pinned destination entry"
        );

        let per_file_source = tmp.join("fallback-per-file-limit");
        let per_file_backup = tmp.join("rollback/fallback-per-file-limit");
        fs::create_dir(&per_file_source).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(per_file_source.join("large"))
            .unwrap()
            .set_len(MAX_AUTHORITY_FULL_COPY_FILE_BYTES + 1)
            .unwrap();
        {
            let _clone_seam = test_arm_authority_snapshot_clone_errno(libc::ENOTSUP);
            let error = AuthorityTreeSnapshot::capture(per_file_source, per_file_backup.clone())
                .err()
                .expect("fallback above the per-file copy budget must fail closed");
            assert!(error.contains("code=authority_snapshot_clone_required"));
        }
        assert!(!per_file_backup.join("large").exists());

        let aggregate_source = tmp.join("fallback-aggregate-limit");
        let aggregate_backup = tmp.join("rollback/fallback-aggregate-limit");
        fs::write(&aggregate_source, b"x").unwrap();
        let mut exhausted_budget = AuthorityCopyBudget {
            full_copy_bytes: MAX_AUTHORITY_FULL_COPY_TOTAL_BYTES,
            ..AuthorityCopyBudget::default()
        };
        {
            let _clone_seam = test_arm_authority_snapshot_clone_errno(libc::EXDEV);
            let error = AuthorityTreeSnapshot::copy_tree(
                &aggregate_source,
                &aggregate_backup,
                &mut exhausted_budget,
                false,
                AuthoritySnapshotScope::Test,
                &aggregate_source,
            )
            .expect_err("fallback aggregate budget plus one must fail closed");
            assert!(error.contains("code=authority_snapshot_clone_required"));
        }
        assert!(!aggregate_backup.exists());

        let fallback_restore_source = tmp.join("fallback-restore");
        let fallback_restore_backup = tmp.join("rollback/fallback-restore");
        fs::create_dir(&fallback_restore_source).unwrap();
        fs::write(fallback_restore_source.join("state"), b"prior\n").unwrap();
        let mut fallback_restore_snapshot = AuthorityTreeSnapshot::capture(
            fallback_restore_source.clone(),
            fallback_restore_backup,
        )
        .unwrap();
        fs::write(fallback_restore_source.join("state"), b"mutated\n").unwrap();
        {
            let _clone_seam = test_arm_authority_snapshot_clone_errno(libc::ENOTSUP);
            fallback_restore_snapshot
                .restore()
                .expect("restore must use the bounded independent-copy fallback");
        }
        assert_eq!(
            fs::read(fallback_restore_source.join("state")).unwrap(),
            b"prior\n"
        );

        let rebound_parent = tmp.join("restore-rebound-parent");
        let displaced_parent = tmp.join("restore-displaced-parent");
        let rebound_foreign = tmp.join("restore-foreign");
        let rebound_source = rebound_parent.join("authority");
        let rebound_backup = tmp.join("rollback/restore-rebound");
        let rebound_barrier = tmp.join("restore-rebound-barrier");
        fs::create_dir_all(&rebound_source).unwrap();
        fs::create_dir(&rebound_foreign).unwrap();
        fs::write(rebound_source.join("state"), b"prior-pinned\n").unwrap();
        let mut rebound_snapshot =
            AuthorityTreeSnapshot::capture(rebound_source.clone(), rebound_backup.clone()).unwrap();
        fs::write(rebound_source.join("state"), b"mutated\n").unwrap();
        let rebound_seam =
            test_arm_authority_snapshot_directory_barrier(rebound_backup, rebound_barrier.clone());
        let restore_worker = thread::spawn(move || rebound_snapshot.restore());
        for _ in 0..200 {
            if rebound_barrier.join("ready").is_file() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(rebound_barrier.join("ready").is_file());
        fs::rename(&rebound_parent, &displaced_parent).unwrap();
        symlink(&rebound_foreign, &rebound_parent).unwrap();
        fs::write(rebound_barrier.join("release"), b"release\n").unwrap();
        let restore_rebound_error = restore_worker
            .join()
            .unwrap()
            .expect_err("restore parent rebind must fail closed");
        drop(rebound_seam);
        assert!(
            restore_rebound_error.contains("code=authority_restore_parent_rebound")
                || restore_rebound_error
                    .contains("code=authority_restore_parent_revalidate_failed")
        );
        assert!(
            !rebound_foreign.join("authority").exists(),
            "restore must not write through a rebound parent symlink"
        );
        assert_eq!(
            fs::read(displaced_parent.join("authority/state")).unwrap(),
            b"prior-pinned\n"
        );

        let backup_parent_rebind_source = tmp.join("backup-parent-rebind-live");
        let backup_parent_rebind_parent = tmp.join("backup-parent-rebind-root");
        let backup_parent_displaced = tmp.join("backup-parent-rebind-displaced");
        let backup_parent_rebind_backup = backup_parent_rebind_parent.join("authority");
        fs::create_dir(&backup_parent_rebind_source).unwrap();
        fs::create_dir(&backup_parent_rebind_parent).unwrap();
        fs::write(
            backup_parent_rebind_source.join("state"),
            b"trusted-prior\n",
        )
        .unwrap();
        let mut backup_parent_rebind_snapshot = AuthorityTreeSnapshot::capture(
            backup_parent_rebind_source.clone(),
            backup_parent_rebind_backup.clone(),
        )
        .unwrap();
        fs::write(backup_parent_rebind_source.join("state"), b"live-mutated\n").unwrap();
        fs::rename(&backup_parent_rebind_parent, &backup_parent_displaced).unwrap();
        fs::create_dir_all(&backup_parent_rebind_backup).unwrap();
        fs::write(
            backup_parent_rebind_backup.join("state"),
            b"foreign-replacement\n",
        )
        .unwrap();
        let backup_parent_rebind_error = backup_parent_rebind_snapshot
            .restore()
            .expect_err("backup parent rebind must fail closed");
        assert!(
            backup_parent_rebind_error.contains("code=authority_restore_backup_parent_rebound")
                || backup_parent_rebind_error
                    .contains("code=authority_restore_backup_parent_revalidate_failed")
        );
        assert_eq!(
            fs::read(backup_parent_rebind_source.join("state")).unwrap(),
            b"live-mutated\n",
            "restore must not mutate live authority after backup parent rebind"
        );
        assert_eq!(
            fs::read(backup_parent_rebind_backup.join("state")).unwrap(),
            b"foreign-replacement\n",
            "restore must never read or mutate the replacement backup tree"
        );
        assert_eq!(
            fs::read(backup_parent_displaced.join("authority/state")).unwrap(),
            b"trusted-prior\n",
            "the pinned original backup must remain intact for diagnosis"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    // 依赖 dev/ino 独立性与 0600 权限设置（POSIX 语义）。
    #[cfg(unix)]
    #[test]
    fn authority_snapshot_accepts_observed_science_0125_tree_via_independent_clones() {
        // Installed 0.1.25 normal-HOME metadata-only observation after first-run
        // R/Conda setup: 75,588 entries, 4,386,369,604 logical bytes total, and
        // a 189,776,400-byte largest regular file. Keep the filesystem fixture sparse:
        // the regression is about bounded logical authority and independent
        // snapshot objects, not allocating GiBs in the test.
        const OBSERVED_ENTRIES: usize = 75_588;
        const OBSERVED_TOTAL_BYTES: u64 = 4_386_369_604;
        const OBSERVED_MAX_FILE_BYTES: u64 = 189_776_400;

        let mut observed_budget = AuthorityCopyBudget::default();
        let mut observed_remaining = OBSERVED_TOTAL_BYTES;
        for _ in 0..OBSERVED_ENTRIES {
            let bytes = if observed_remaining == 0 {
                0
            } else {
                OBSERVED_MAX_FILE_BYTES.min(observed_remaining)
            };
            observed_remaining -= bytes;
            AuthorityTreeSnapshot::charge_entry(
                &mut observed_budget,
                bytes,
                AuthoritySnapshotScope::ScienceData,
                AuthoritySnapshotCategory::CondaCache,
            )
            .expect("observed normal Science 0.1.25 authority budget must pass");
        }
        assert_eq!(observed_remaining, 0);
        assert_eq!(observed_budget.entries, OBSERVED_ENTRIES);
        assert_eq!(observed_budget.bytes, OBSERVED_TOTAL_BYTES);

        let tmp = isolated_tmpdir("science-0125-observed-authority");
        let source = tmp.join("authority");
        let backup = tmp.join("rollback/authority");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir(tmp.join("rollback")).unwrap();

        let mut remaining = OBSERVED_TOTAL_BYTES;
        let mut index = 0usize;
        while remaining > 0 {
            let size = remaining.min(OBSERVED_MAX_FILE_BYTES);
            let path = source.join(format!("payload-{index}"));
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.set_len(size).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            remaining -= size;
            index += 1;
        }

        let mut snapshot = AuthorityTreeSnapshot::capture(source.clone(), backup.clone())
            .expect("observed normal Science 0.1.25 authority must be snapshotable");
        for entry in fs::read_dir(&source).unwrap() {
            let entry = entry.unwrap();
            let live = fs::metadata(entry.path()).unwrap();
            let saved = fs::metadata(backup.join(entry.file_name())).unwrap();
            assert_eq!(live.len(), saved.len());
            assert_eq!(
                live.permissions().mode() & 0o777,
                saved.permissions().mode() & 0o777
            );
            assert_eq!(live.dev(), saved.dev());
            assert_ne!(live.ino(), saved.ino());
        }
        snapshot.restore().unwrap();
        let restored_total = fs::read_dir(&source)
            .unwrap()
            .map(|entry| fs::metadata(entry.unwrap().path()).unwrap().len())
            .sum::<u64>();
        assert_eq!(restored_total, OBSERVED_TOTAL_BYTES);
        let _ = fs::remove_dir_all(tmp);
    }

    // 使用 mkfifo 构造 special file（unix 专用）。
    #[cfg(unix)]
    #[test]
    fn authority_snapshot_limit_diagnostic_is_path_and_credential_free() {
        let tmp = isolated_tmpdir("authority-limit-redaction");
        let source = tmp.join("science-data");
        let backup = tmp.join("rollback/science-data");
        fs::create_dir_all(source.join("conda")).unwrap();
        fs::create_dir(tmp.join("rollback")).unwrap();
        let canary = "sk-private-canary-path-secret";
        let path = source.join("conda").join(canary);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(MAX_AUTHORITY_SNAPSHOT_FILE_BYTES + 1).unwrap();

        let error = AuthorityTreeSnapshot::capture_scoped(
            AuthoritySnapshotScope::ScienceData,
            source,
            backup,
        )
        .err()
        .expect("oversized Science authority must fail closed");
        assert!(error.contains("code=authority_snapshot_file_limit"));
        assert!(error.contains("scope=science_data"));
        assert!(error.contains("category=conda_cache"));
        assert!(!error.contains(canary));
        assert!(!error.contains(tmp.to_string_lossy().as_ref()));

        let special_source = tmp.join("special-science-data");
        let special_backup = tmp.join("rollback/special-science-data");
        fs::create_dir(&special_source).unwrap();
        let special_canary = "sk-private-special-file-canary";
        let socket_path = special_source.join(special_canary);
        let socket_path_raw =
            std::ffi::CString::new(socket_path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(socket_path_raw.as_ptr(), 0o600) }, 0);
        let special_error = AuthorityTreeSnapshot::capture_scoped(
            AuthoritySnapshotScope::ScienceData,
            special_source,
            special_backup,
        )
        .err()
        .expect("special authority files must fail closed");
        assert!(special_error.contains("code=authority_snapshot_special_file"));
        assert!(!special_error.contains(special_canary));
        assert!(!special_error.contains(tmp.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(tmp);
    }

    // 依赖 symlink 换绑与 0600/0700 权限夹具（POSIX 语义）。
    #[cfg(unix)]
    #[test]
    fn authority_snapshot_fails_closed_when_directory_membership_changes_mid_capture() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tmp = isolated_tmpdir("directory-membership-race");
        let source = tmp.join("authority");
        let backup = tmp.join("rollback/authority");
        let barrier = tmp.join("barrier");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir(tmp.join("rollback")).unwrap();
        fs::write(source.join("database.db"), b"prior-database\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            source.join("database.db"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let _seam = test_arm_authority_snapshot_directory_barrier(source.clone(), barrier.clone());

        let capture_source = source.clone();
        let capture_backup = backup.clone();
        let worker =
            thread::spawn(move || AuthorityTreeSnapshot::capture(capture_source, capture_backup));
        for _ in 0..200 {
            if barrier.join("ready").is_file() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            barrier.join("ready").is_file(),
            "test-only barrier must observe the directory enumeration boundary"
        );
        fs::write(source.join("database.db-wal"), b"concurrent-wal\n").unwrap();
        fs::set_permissions(
            source.join("database.db-wal"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(barrier.join("release"), b"release\n").unwrap();
        let capture = worker.join().unwrap();
        let accepted_torn_tree = capture.is_ok()
            && backup.join("database.db").is_file()
            && !backup.join("database.db-wal").exists();
        assert!(
            capture.is_err(),
            "authority snapshot must fail closed when a DB/WAL directory entry appears after enumeration; accepted_torn_tree={accepted_torn_tree}"
        );
        drop(_seam);

        let rebound_source = tmp.join("rebound-authority");
        let rebound_backup = tmp.join("rollback/rebound-authority");
        let displaced_backup = tmp.join("rollback/displaced-authority");
        let foreign = tmp.join("foreign-must-remain-empty");
        let rebound_barrier = tmp.join("rebound-barrier");
        fs::create_dir(&rebound_source).unwrap();
        fs::create_dir(&foreign).unwrap();
        fs::write(rebound_source.join("state"), b"must-stay-pinned\n").unwrap();
        let rebound_seam = test_arm_authority_snapshot_directory_barrier(
            rebound_source.clone(),
            rebound_barrier.clone(),
        );
        let rebound_worker = {
            let source = rebound_source.clone();
            let backup = rebound_backup.clone();
            thread::spawn(move || AuthorityTreeSnapshot::capture(source, backup))
        };
        for _ in 0..200 {
            if rebound_barrier.join("ready").is_file() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(rebound_barrier.join("ready").is_file());
        fs::rename(&rebound_backup, &displaced_backup).unwrap();
        symlink(&foreign, &rebound_backup).unwrap();
        fs::write(rebound_barrier.join("release"), b"release\n").unwrap();
        let rebound_error = rebound_worker
            .join()
            .unwrap()
            .err()
            .expect("destination entry rebind must fail closed");
        drop(rebound_seam);
        assert!(rebound_error.contains("code=authority_snapshot_destination_rebound"));
        assert!(
            !foreign.join("state").exists(),
            "dirfd-anchored copy must never write through a rebound destination symlink"
        );
        assert_eq!(
            fs::read(displaced_backup.join("state")).unwrap(),
            b"must-stay-pinned\n"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    // 断言 uid/0700 mode 真实值，并依赖 HOME 环境隔离（POSIX 语义）。
    #[cfg(unix)]
    #[test]
    fn fresh_authority_snapshot_parent_is_private_and_cleanup_safe() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut env = ScopedEnv::new();
        let tmp = isolated_tmpdir("fresh-authority-parent");
        let home = tmp.join("home");
        env.set("HOME", &home);
        let config_dir = config::default_dir();
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        assert!(
            !sandbox_home.parent().unwrap().exists(),
            "fixture must begin before the managed sandbox directory exists"
        );
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let mut snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .expect("fresh config must create a safe private snapshot parent");
        let parent = sandbox_home.parent().unwrap();
        let parent_metadata = fs::symlink_metadata(parent).unwrap();
        assert!(
            parent_metadata.is_dir()
                && !parent_metadata.file_type().is_symlink()
                && parent_metadata.uid() == unsafe { libc::geteuid() }
                && parent_metadata.permissions().mode() & 0o777 == 0o700,
            "fresh snapshot parent must be an owned private directory"
        );
        let backup_root = snapshot.backup_root.clone();
        let registered = config::read_pending_authority_cleanup_manifest(&config_dir)
            .unwrap()
            .unwrap();
        let registered: serde_json::Value = serde_json::from_slice(&registered).unwrap();
        assert_eq!(
            registered["entries"].as_array().map(Vec::len),
            Some(1),
            "a complete authority snapshot must be durably registered before protected writes"
        );
        let runtime_id = "b".repeat(64);
        advance_runtime_transaction(
            &config_dir,
            "snapshot-crash-fixture",
            None,
            &format!("{AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX}{runtime_id}"),
        )
        .unwrap();
        let retry_error = retry_pending_authority_cleanup(&state)
            .expect_err("an active authority transaction must preserve its recovery snapshot");
        assert!(
            retry_error.contains("code=authority_snapshot_recovery_required")
                && backup_root.is_dir(),
            "active crash recovery must preserve the exact registered root: {retry_error}"
        );
        clear_runtime_transaction(&config_dir).unwrap();
        snapshot
            .restore(&config_dir, &state, ProxyAction::Reused)
            .expect("fresh missing authority parents must already satisfy prior absence");
        let manifest = config::read_pending_authority_cleanup_manifest(&config_dir)
            .unwrap()
            .unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        assert!(
            parent.is_dir()
                && !sandbox_home.exists()
                && !backup_root.exists()
                && manifest["entries"].as_array().is_some_and(Vec::is_empty),
            "restore must retain the private sandbox parent, preserve prior HOME absence, and durably clear rollback state"
        );
        let panic_snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .unwrap();
        let panic_recovery_root = panic_snapshot.backup_root.clone();
        fs::create_dir_all(&auth_dir).unwrap();
        fs::set_permissions(&auth_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            auth_dir.join("active-org.json"),
            b"partial-protected-write\n",
        )
        .unwrap();
        advance_runtime_transaction(
            &config_dir,
            "snapshot-panic-fixture",
            None,
            &format!("{AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX}{runtime_id}"),
        )
        .unwrap();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held_snapshot = panic_snapshot;
            panic!("test-only panic after protected mutation");
        }));
        assert!(unwind.is_err());
        let panic_retry = retry_pending_authority_cleanup(&state)
            .expect_err("panic unwind must not convert ActiveRecovery to cleanup-only");
        assert!(
            panic_retry.contains("cleanup_code=authority_snapshot_recovery_required")
                && panic_retry.contains(&panic_recovery_root.to_string_lossy().to_string())
                && panic_recovery_root.is_dir(),
            "panic unwind must preserve the exact registered recovery root: {panic_retry}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    // 依赖 clonefile errno 注入夹具与 4 GiB 稀疏文件（unix 专用）。
    #[cfg(unix)]
    #[test]
    fn one_click_snapshot_does_not_descend_or_restore_science_owned_environment() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tmp = isolated_tmpdir("science-owned-environment-boundary");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let org_db = auth_dir.join("orgs/org-test/history.db");
        let conda_sentinel = auth_dir.join("conda/candidate-state");
        let unknown_sentinel = auth_dir.join("future-science-state/candidate-state");
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        fs::create_dir_all(org_db.parent().unwrap()).unwrap();
        fs::create_dir_all(conda_sentinel.parent().unwrap()).unwrap();
        fs::create_dir_all(unknown_sentinel.parent().unwrap()).unwrap();
        fs::write(
            auth_dir.join("active-org.json"),
            b"{\"org_uuid\":\"org-test\"}\n",
        )
        .unwrap();
        fs::write(&org_db, b"prior-history\n").unwrap();
        fs::write(&conda_sentinel, b"prior-environment\n").unwrap();
        fs::write(&unknown_sentinel, b"prior-unknown\n").unwrap();
        for root in SCIENCE_OWNED_OPAQUE_ROOTS {
            let sparse_path = auth_dir.join(root).join("large-environment");
            fs::create_dir_all(sparse_path.parent().unwrap()).unwrap();
            let sparse = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&sparse_path)
                .unwrap();
            sparse.set_len(4 * 1024 * 1024 * 1024).unwrap();
        }
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let _clone_fallback = test_arm_authority_snapshot_clone_errno(libc::ENOTSUP);

        let mut snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .expect("opaque Science environment must not enter snapshot copy budgets");
        fs::write(
            auth_dir.join("active-org.json"),
            b"{\"org_uuid\":\"candidate\"}\n",
        )
        .unwrap();
        fs::write(&org_db, b"candidate-history\n").unwrap();
        fs::write(&conda_sentinel, b"candidate-environment\n").unwrap();
        fs::write(&unknown_sentinel, b"candidate-unknown\n").unwrap();

        snapshot
            .restore(&config_dir, &state, ProxyAction::Reused)
            .expect("protected authority projection must restore independently");
        assert_eq!(
            fs::read(auth_dir.join("active-org.json")).unwrap(),
            b"{\"org_uuid\":\"org-test\"}\n"
        );
        assert_eq!(fs::read(&org_db).unwrap(), b"prior-history\n");
        assert_eq!(
            fs::read(&conda_sentinel).unwrap(),
            b"candidate-environment\n",
            "CSSwitch rollback must preserve Science-owned environment in place"
        );
        assert_eq!(fs::read(&unknown_sentinel).unwrap(), b"candidate-unknown\n");
        for root in SCIENCE_OWNED_OPAQUE_ROOTS {
            assert_eq!(
                fs::metadata(auth_dir.join(root).join("large-environment"))
                    .unwrap()
                    .len(),
                4 * 1024 * 1024 * 1024,
                "CSSwitch must neither copy nor delete opaque environment objects"
            );
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn one_click_snapshot_skips_science_owned_large_files() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tmp = isolated_tmpdir("large-science-owned-files");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        fs::create_dir_all(auth_dir.join("artifacts/proj")).unwrap();
        fs::write(
            auth_dir.join("active-org.json"),
            b"{\"org_uuid\":\"org-test\"}\n",
        )
        .unwrap();
        // 70 MB 稀疏文件（> 64 MiB 可复制上限）：代表 Agent 产物/Electron 级大内容。
        let big = auth_dir.join("artifacts/proj/v1_export.csv");
        let sparse = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&big)
            .unwrap();
        sparse.set_len(70 * 1024 * 1024).unwrap();
        drop(sparse);
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));

        let mut snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .expect("large science-owned files must not enter snapshot copy budgets");
        // 探针：capture 刚结束时回滚目录能否被改名？
        if let Some(tree) = snapshot.trees.first() {
            if let Some(backup) = &tree.backup_parent {
                if let Some(rollback_root) = backup.path.parent() {
                    let probe_to = rollback_root
                        .parent()
                        .unwrap()
                        .join("__rename_probe__");
                    match fs::rename(rollback_root, &probe_to) {
                        Ok(()) => {
                            eprintln!("[cleanup-diag] probe rename OK——回滚目录无句柄锁定");
                            fs::rename(&probe_to, rollback_root).unwrap();
                        }
                        Err(e) => {
                            eprintln!("[cleanup-diag] probe rename FAILED: {e}");
                        }
                    }
                }
            }
        }
        fs::write(
            auth_dir.join("active-org.json"),
            b"{\"org_uuid\":\"org-candidate\"}\n",
        )
        .unwrap();

        snapshot
            .restore(&config_dir, &state, ProxyAction::Reused)
            .expect("protected authority projection must restore independently");
        assert_eq!(
            fs::read(auth_dir.join("active-org.json")).unwrap(),
            b"{\"org_uuid\":\"org-test\"}\n",
            "小型权威状态必须正常备份并恢复"
        );
        assert_eq!(
            fs::metadata(&big).unwrap().len(),
            70 * 1024 * 1024,
            "Science 自有大文件必须原地保留（不复制、不删除、不回滚）"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    // 依赖 symlinkat 夹具（unix 专用）。
    #[cfg(unix)]
    #[test]
    fn one_click_snapshot_rejects_opaque_root_symlink_without_touching_target() {
        let tmp = isolated_tmpdir("science-owned-environment-symlink");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let foreign = tmp.join("foreign");
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        fs::create_dir_all(&auth_dir).unwrap();
        fs::create_dir(&foreign).unwrap();
        fs::write(foreign.join("canary"), b"must-not-change\n").unwrap();
        symlink(&foreign, auth_dir.join("conda")).unwrap();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));

        let error = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .err()
        .expect("opaque root symlink must fail closed");
        assert!(error.contains("code=science_environment_root_identity_failed"));
        assert_eq!(
            fs::read(foreign.join("canary")).unwrap(),
            b"must-not-change\n"
        );
        assert!(fs::symlink_metadata(auth_dir.join("conda"))
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(&tmp);
    }

    // 依赖 symlink 换绑（unix 专用）。
    #[cfg(unix)]
    #[test]
    fn one_click_snapshot_blocks_protected_restore_after_opaque_root_rebind() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tmp = isolated_tmpdir("science-owned-environment-restore-rebind");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let foreign = tmp.join("foreign");
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        fs::create_dir_all(auth_dir.join("conda")).unwrap();
        fs::create_dir(&foreign).unwrap();
        fs::write(auth_dir.join("active-org.json"), b"prior\n").unwrap();
        fs::write(foreign.join("canary"), b"must-not-change\n").unwrap();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));

        let mut snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .expect("safe top-level opaque directory must allow capture");
        fs::rename(auth_dir.join("conda"), auth_dir.join("conda-displaced")).unwrap();
        symlink(&foreign, auth_dir.join("conda")).unwrap();
        fs::write(auth_dir.join("active-org.json"), b"candidate\n").unwrap();

        let error = snapshot
            .restore(&config_dir, &state, ProxyAction::Reused)
            .expect_err("opaque-root rebind must block protected Science restore");
        assert!(error.contains("code=science_environment_root_identity_failed"));
        assert_eq!(
            fs::read(auth_dir.join("active-org.json")).unwrap(),
            b"candidate\n",
            "protected authority must not be restored after the root contract changes"
        );
        assert_eq!(
            fs::read(foreign.join("canary")).unwrap(),
            b"must-not-change\n"
        );
        drop(snapshot);
        let _ = fs::remove_dir_all(&tmp);

        let race_tmp = isolated_tmpdir("science-owned-environment-capture-rebind");
        let race_config_dir = race_tmp.join("config");
        let race_sandbox_home = race_config_dir.join("sandbox/home");
        let race_auth_dir = race_sandbox_home.join(".claude-science");
        let race_orgs = race_auth_dir.join("orgs");
        let displaced_auth = race_tmp.join("displaced-auth");
        let replacement_auth = race_tmp.join("replacement-auth");
        let barrier = race_tmp.join("barrier");
        let race_config = Config::default();
        config::save_to(&race_config_dir, &race_config).unwrap();
        fs::create_dir_all(race_orgs.join("org-test")).unwrap();
        fs::write(race_orgs.join("org-test/history.db"), b"captured-prior\n").unwrap();
        let race_state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let _barrier =
            test_arm_authority_snapshot_directory_barrier(race_orgs.clone(), barrier.clone());
        let worker_config_dir = race_config_dir.clone();
        let worker_sandbox_home = race_sandbox_home.clone();
        let worker_auth_dir = race_auth_dir.clone();
        let worker_state = race_state.clone();
        let worker = thread::spawn(move || {
            OneClickAuthoritySnapshot::capture(
                &worker_config_dir,
                &worker_sandbox_home,
                &worker_auth_dir,
                &race_config,
                &worker_state,
            )
        });
        for _ in 0..200 {
            if barrier.join("ready").is_file() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(barrier.join("ready").is_file());
        fs::rename(&race_auth_dir, &displaced_auth).unwrap();
        fs::create_dir_all(replacement_auth.join("orgs/org-test")).unwrap();
        fs::write(
            replacement_auth.join("orgs/org-test/replacement-canary"),
            b"replacement-must-not-be-read-or-changed\n",
        )
        .unwrap();
        fs::rename(&replacement_auth, &race_auth_dir).unwrap();
        fs::write(barrier.join("release"), b"release\n").unwrap();
        let capture_error = worker
            .join()
            .unwrap()
            .err()
            .expect("root rebind during capture must fail closed");
        assert!(
            capture_error.contains("code=science_authority_root_rebound")
                || capture_error.contains("code=authority_snapshot_source_parent_rebound"),
            "unexpected capture rebind refusal: {capture_error}"
        );
        assert_eq!(
            fs::read(race_auth_dir.join("orgs/org-test/replacement-canary")).unwrap(),
            b"replacement-must-not-be-read-or-changed\n"
        );
        let _ = fs::remove_dir_all(&race_tmp);
    }

    // 依赖 symlink（unix 专用）。
    #[cfg(unix)]
    #[test]
    fn fresh_authority_snapshot_parent_refuses_symlink_without_touching_target() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tmp = isolated_tmpdir("fresh-authority-parent-symlink");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let foreign = tmp.join("foreign");
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        fs::create_dir(&foreign).unwrap();
        fs::write(foreign.join("canary"), b"must-not-change\n").unwrap();
        symlink(&foreign, config_dir.join("sandbox")).unwrap();
        let foreign_before = tree(&foreign);
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let error = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .err()
        .expect("a symlinked snapshot parent must fail closed");
        assert!(
            error.contains("code=authority_snapshot_root_parent_open_failed"),
            "unexpected symlink refusal: {error}"
        );
        assert_eq!(
            tree(&foreign),
            foreign_before,
            "snapshot parent setup must not follow or mutate the symlink target"
        );
        assert!(
            fs::symlink_metadata(config_dir.join("sandbox"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the rejected symlink must remain untouched"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn fresh_authority_snapshot_parent_refuses_non_sandbox_contract() {
        let tmp = isolated_tmpdir("fresh-authority-parent-contract");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("foreign-child/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let error = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .err()
        .expect("only the exact config/sandbox/home layout may create a snapshot parent");
        assert_eq!(
            error, "code=authority_snapshot_root_parent_contract_failed",
            "unexpected non-sandbox contract refusal"
        );
        assert!(
            !config_dir.join("foreign-child").exists(),
            "contract refusal must not create or mutate an arbitrary config child"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    // 依赖 0700/0750 chmod 真实值比对（POSIX 语义）。
    #[cfg(unix)]
    #[test]
    fn fresh_authority_snapshot_parent_rebind_fails_before_mutating_replacement() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tmp = isolated_tmpdir("fresh-authority-parent-rebind");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let sandbox_parent = sandbox_home.parent().unwrap().to_path_buf();
        let displaced = tmp.join("displaced-sandbox");
        let replacement = tmp.join("replacement");
        let barrier = tmp.join("barrier");
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        fs::create_dir(&sandbox_parent).unwrap();
        fs::set_permissions(&sandbox_parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(replacement.join("canary"), b"must-not-change\n").unwrap();
        let replacement_before = tree(&replacement);
        let seam =
            test_arm_authority_snapshot_parent_barrier(sandbox_parent.clone(), barrier.clone());
        let worker = {
            let config_dir = config_dir.clone();
            let sandbox_home = sandbox_home.clone();
            let auth_dir = auth_dir.clone();
            let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
            thread::spawn(move || {
                OneClickAuthoritySnapshot::capture(
                    &config_dir,
                    &sandbox_home,
                    &auth_dir,
                    &config,
                    &state,
                )
            })
        };
        for _ in 0..200 {
            if barrier.join("ready").is_file() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(barrier.join("ready").is_file());
        fs::rename(&sandbox_parent, &displaced).unwrap();
        fs::rename(&replacement, &sandbox_parent).unwrap();
        fs::write(barrier.join("release"), b"release\n").unwrap();
        let error = worker
            .join()
            .unwrap()
            .err()
            .expect("snapshot parent replacement must fail closed");
        drop(seam);
        assert_eq!(
            error, "code=authority_snapshot_root_parent_identity_failed",
            "unexpected snapshot parent rebind failure"
        );
        assert_eq!(
            tree(&sandbox_parent),
            replacement_before,
            "identity refusal must occur before chmod or writes reach the replacement directory"
        );
        assert!(
            displaced.is_dir(),
            "the originally pinned sandbox directory must remain recoverable"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    // 依赖 0600 marker 权限与目录 fsync 错误注入（POSIX 语义）。
    #[cfg(unix)]
    #[test]
    fn one_shot_commit_cleanup_fault_is_retried_before_success() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tmp = isolated_tmpdir("commit-cleanup-once");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let cleanup_log = tmp.join("cleanup.log");
        fs::create_dir_all(&auth_dir).unwrap();
        fs::write(auth_dir.join("active-org.json"), b"private-authority\n").unwrap();
        fs::set_permissions(
            auth_dir.join("active-org.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let config = Config::default();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        {
            let _sync_seam = test_arm_authority_snapshot_completion_sync_failure();
            let error = OneClickAuthoritySnapshot::capture(
                &config_dir,
                &sandbox_home,
                &auth_dir,
                &config,
                &state,
            )
            .err()
            .expect("completion fsync failure must fail closed");
            assert!(
                error.contains("code=authority_snapshot_completion_sync_failed"),
                "unexpected completion-sync failure: {error}"
            );
        }
        let rollback_residue = fs::read_dir(sandbox_home.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".one-click-rollback-")
            });
        assert!(
            !rollback_residue,
            "completion fsync failure must register and finish rollback cleanup"
        );
        let mut cleanup_sync_snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .unwrap();
        let cleanup_sync_root = cleanup_sync_snapshot.backup_root.clone();
        let cleanup_sync_tombstone = cleanup_tombstone_path(&PendingCleanupEntry {
            managed_id: cleanup_sync_root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            path: cleanup_sync_root.clone(),
            device: 0,
            inode: 0,
            marker: String::new(),
        });
        {
            let _cleanup_sync_seam = test_arm_authority_cleanup_parent_sync_failure();
            let error = cleanup_sync_snapshot
                .cleanup_when_expendable()
                .expect_err("cleanup parent fsync failure must remain pending");
            assert!(error.contains("recovery_status=cleanup_required"));
            let manifest = config::read_pending_authority_cleanup_manifest(&config_dir)
                .unwrap()
                .unwrap();
            let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
            assert_eq!(manifest["entries"].as_array().map(Vec::len), Some(1));
            assert!(cleanup_sync_tombstone.is_dir());
        }
        fs::remove_file(cleanup_sync_tombstone.join(PENDING_CLEANUP_MARKER_FILE)).unwrap();
        let pending_raw = config::read_pending_authority_cleanup_manifest(&config_dir)
            .unwrap()
            .unwrap();
        let pending = parse_pending_cleanup_manifest(&pending_raw).unwrap();
        let retry_ticket = RegisteredAuthorityCleanup {
            manifest_raw: pending_raw,
            entry: pending.entries.into_iter().next().unwrap(),
        };
        finalize_registered_authority_cleanup(
            &cleanup_sync_snapshot.cleanup_context,
            &retry_ticket,
        )
        .unwrap();
        let cleared = config::read_pending_authority_cleanup_manifest(&config_dir)
            .unwrap()
            .unwrap();
        let cleared: serde_json::Value = serde_json::from_slice(&cleared).unwrap();
        assert_eq!(cleared["entries"].as_array().map(Vec::len), Some(0));
        cleanup_sync_snapshot.cleanup_prepared = true;
        cleanup_sync_snapshot.preserve_recovery = false;

        let mut rebound_cleanup_snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .unwrap();
        let rebound_root = rebound_cleanup_snapshot.backup_root.clone();
        let displaced_root = tmp.join("cleanup-register-displaced-root");
        fs::rename(&rebound_root, &displaced_root).unwrap();
        fs::create_dir(&rebound_root).unwrap();
        fs::set_permissions(&rebound_root, fs::Permissions::from_mode(0o700)).unwrap();
        let rebound_error = rebound_cleanup_snapshot
            .cleanup_when_expendable()
            .expect_err("registered cleanup ticket must reject a replacement root");
        assert!(
            rebound_error.contains("cleanup_manifest_identity_mismatch"),
            "unexpected registered-ticket identity refusal: {rebound_error}"
        );
        assert!(
            rebound_root.is_dir(),
            "replacement root must not be deleted"
        );
        assert!(
            displaced_root.is_dir(),
            "original rollback root must remain recoverable"
        );
        assert!(
            !rebound_root.join(PENDING_CLEANUP_MARKER_FILE).exists(),
            "replacement root must not receive a cleanup marker"
        );
        let rebound_manifest = config::read_pending_authority_cleanup_manifest(&config_dir)
            .unwrap()
            .unwrap();
        let rebound_manifest: serde_json::Value =
            serde_json::from_slice(&rebound_manifest).unwrap();
        assert_eq!(
            rebound_manifest["entries"].as_array().map(Vec::len),
            Some(1),
            "the exact pre-mutation cleanup ticket must remain registered"
        );
        fs::remove_dir(&rebound_root).unwrap();
        fs::rename(&displaced_root, &rebound_root).unwrap();
        rebound_cleanup_snapshot
            .cleanup_when_expendable()
            .expect("restored exact root identity must consume the registered ticket");

        let _seam =
            test_arm_authority_snapshot_cleanup_fault(tmp.clone(), "once", cleanup_log.clone());
        let mut snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .unwrap();
        let backup_root = snapshot.backup_root.clone();
        snapshot.commit();
        let cleanup_attempts = fs::read_to_string(&cleanup_log)
            .unwrap_or_default()
            .lines()
            .count();
        let root_removed_before_success = !backup_root.exists();
        if backup_root.exists() {
            fs::remove_dir_all(&backup_root).unwrap();
        }
        let _ = fs::remove_dir_all(&tmp);

        assert!(
            root_removed_before_success && cleanup_attempts >= 2,
            "one-shot cleanup fault must be retried before commit reports success: attempts={cleanup_attempts}, root_removed={root_removed_before_success}"
        );
    }

    #[test]
    fn pending_cleanup_observer_mapping_only_does_not_claim_durable_cleanup() {
        let managed_id = ".one-click-rollback-0123456789abcdef0123456789abcdef";
        let identity = config::PendingCleanupIdentity {
            managed_id: managed_id.to_string(),
            path: PathBuf::from("/synthetic/mapping-only").join(managed_id),
            device: 41,
            inode: 73,
            marker: managed_id.to_string(),
        };
        let different = config::PendingCleanupIdentity {
            inode: 74,
            ..identity.clone()
        };
        let _lifecycle = config::test_arm_pending_cleanup_lifecycle(None);
        config::test_observe_pending_cleanup_manifest_validated(identity.clone());

        config::test_observe_pending_cleanup_initial_ticket(
            config::PendingCleanupInitialTicket::Present(identity.clone()),
        );
        config::test_observe_pending_cleanup_completion(
            config::PendingCleanupRemovalOutcome::Removed,
            config::PendingCleanupFinalState::NotFound,
        );
        config::test_observe_pending_cleanup_initial_ticket(
            config::PendingCleanupInitialTicket::Missing(identity.clone()),
        );
        config::test_observe_pending_cleanup_completion(
            config::PendingCleanupRemovalOutcome::AlreadyAbsent,
            config::PendingCleanupFinalState::NotFound,
        );

        for (ticket, outcome, final_state) in [
            (
                config::PendingCleanupInitialTicket::Present(identity.clone()),
                config::PendingCleanupRemovalOutcome::AlreadyAbsent,
                config::PendingCleanupFinalState::NotFound,
            ),
            (
                config::PendingCleanupInitialTicket::Missing(identity.clone()),
                config::PendingCleanupRemovalOutcome::Removed,
                config::PendingCleanupFinalState::NotFound,
            ),
            (
                config::PendingCleanupInitialTicket::Present(identity.clone()),
                config::PendingCleanupRemovalOutcome::Error,
                config::PendingCleanupFinalState::Error,
            ),
            (
                config::PendingCleanupInitialTicket::Present(identity.clone()),
                config::PendingCleanupRemovalOutcome::Removed,
                config::PendingCleanupFinalState::Present(different.clone()),
            ),
        ] {
            config::test_observe_pending_cleanup_initial_ticket(ticket);
            config::test_observe_pending_cleanup_completion(outcome, final_state);
        }

        config::test_observe_pending_cleanup_initial_ticket(
            config::PendingCleanupInitialTicket::Present(identity.clone()),
        );
        config::test_observe_pending_cleanup_completion(
            config::PendingCleanupRemovalOutcome::Removed,
            config::PendingCleanupFinalState::NotFound,
        );
        let observation = config::test_pending_cleanup_lifecycle_observation();
        assert_eq!(
            observation.events,
            vec![
                config::PendingCleanupLifecycleEvent::Register(identity.clone()),
                config::PendingCleanupLifecycleEvent::Remove {
                    identity: identity.clone(),
                    not_found: false,
                },
                config::PendingCleanupLifecycleEvent::Remove {
                    identity: identity.clone(),
                    not_found: true,
                },
                config::PendingCleanupLifecycleEvent::Remove {
                    identity,
                    not_found: false,
                },
            ],
            "mapping-only seam self-test must preserve exact Present/Removed=false and Missing/AlreadyAbsent=true outcomes without deduplication"
        );
        assert_eq!(
            observation.causal_mismatch_count, 4,
            "Present+AlreadyAbsent, Missing+Removed, error, and final Present are causal mismatches and must emit zero Remove"
        );
        assert_eq!(observation.completion_count, 7);
    }

    // 依赖 0600 权限夹具（POSIX 语义）。
    #[cfg(unix)]
    #[test]
    fn partial_capture_cleanup_failure_returns_tracked_degraded_recovery() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let tmp = isolated_tmpdir("partial-capture-cleanup");
        let config_dir = tmp.join("config");
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let cleanup_log = tmp.join("cleanup.log");
        fs::create_dir_all(&auth_dir).unwrap();
        fs::write(auth_dir.join("active-org.json"), b"private-authority\n").unwrap();
        fs::set_permissions(
            auth_dir.join("active-org.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let config = Config::default();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let _capture_seam = test_arm_authority_snapshot_capture_failure(
            sandbox_home.parent().unwrap().join("state"),
        );
        let _cleanup_seam = test_arm_authority_snapshot_cleanup_fault(
            tmp.clone(),
            "persistent",
            cleanup_log.clone(),
        );
        let failure = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .err()
        .expect("partial capture fault must fail");
        let cleanup_line = fs::read_to_string(&cleanup_log)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        let backup_root = PathBuf::from(
            cleanup_line
                .split('\t')
                .nth(2)
                .expect("cleanup observation must track the exact root"),
        );
        let degraded_and_tracked = (failure.contains("cleanup_required")
            || failure.contains("degraded"))
            && failure.contains(&backup_root.to_string_lossy().to_string())
            && backup_root.exists();
        if backup_root.exists() {
            fs::remove_dir_all(&backup_root).unwrap();
        }
        let _ = fs::remove_dir_all(&tmp);

        assert!(
            degraded_and_tracked,
            "partial-capture cleanup failure must return explicit degraded cleanup_required state with the exact residual path: failure={failure:?}, root={}",
            backup_root.display()
        );
    }

    // 依赖 symlink 拒绝跟随与 0600/0700 权限夹具（POSIX 语义）。
    #[cfg(unix)]
    #[test]
    fn rollback_refusal_restores_independent_authorities_and_preserves_recovery_snapshot() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut env = ScopedEnv::new();
        let tmp = isolated_tmpdir("rollback-refusal");
        let home = tmp.join("home");
        env.set("HOME", &home);
        let config_dir = config::default_dir();
        let sandbox_home = config_dir.join("sandbox/home");
        let auth_dir = sandbox_home.join(".claude-science");
        let private_state = sandbox_home.parent().unwrap().join("state");
        let runtime_dir = config_dir.join("runtime");
        let receipt = config_dir.join("science-managed-launch.v1.json");
        fs::create_dir_all(&auth_dir).unwrap();
        fs::create_dir_all(&private_state).unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::set_permissions(&auth_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(auth_dir.join("active-org.json"), b"prior-auth\n").unwrap();
        fs::write(private_state.join("private.json"), b"prior-private\n").unwrap();
        fs::write(runtime_dir.join("bridge.key"), b"prior-runtime\n").unwrap();
        fs::write(&receipt, b"prior-receipt\n").unwrap();
        for path in [
            auth_dir.join("active-org.json"),
            private_state.join("private.json"),
            runtime_dir.join("bridge.key"),
            receipt.clone(),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = Config::default();
        config::save_to(&config_dir, &config).unwrap();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let mut snapshot = OneClickAuthoritySnapshot::capture(
            &config_dir,
            &sandbox_home,
            &auth_dir,
            &config,
            &state,
        )
        .unwrap();
        let backup_root = snapshot.backup_root.clone();
        let auth_before = tree(&auth_dir);
        let private_before = tree(&private_state);
        let runtime_before = tree(&runtime_dir);
        let receipt_before = tree(&receipt);
        let config_before = config::load_from(&config_dir).unwrap();

        fs::remove_dir_all(&auth_dir).unwrap();
        let foreign = tmp.join("foreign-target");
        fs::write(&foreign, b"foreign-must-not-change\n").unwrap();
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&foreign, &auth_dir).unwrap();
        fs::write(private_state.join("private.json"), b"mutated-private\n").unwrap();
        fs::write(runtime_dir.join("bridge.key"), b"mutated-runtime\n").unwrap();
        fs::write(&receipt, b"mutated-receipt\n").unwrap();
        config::update(&config_dir, |current| {
            current.proxy_port = 54321;
            current.secret = "candidate-config-secret".into();
            current.reuse_system_ssh = true;
        })
        .unwrap();
        {
            let mut app = state.lock().unwrap();
            app.proxy_port = 54321;
            app.secret = "candidate-app-secret".into();
            app.provider = "candidate-provider".into();
            app.gateway_kind = "candidate-gateway".into();
            app.shim_mode = "candidate-shim".into();
            app.launch_id = "candidate-launch".into();
            app.key_fp = 54321;
            app.sandbox_port = 54322;
            app.sandbox_url = Some("http://127.0.0.1:54322/candidate".into());
        }

        let error = snapshot
            .restore(&config_dir, &state, ProxyAction::Reused)
            .unwrap_err();
        let refused_without_following = (error
            .contains("code=science_authority_restore_root_revalidate_failed")
            || error.contains("code=science_authority_restore_root_rebound")
            || error.contains("code=science_authority_root_open_failed"))
            && fs::read(&foreign).unwrap() == b"foreign-must-not-change\n"
            && fs::symlink_metadata(&auth_dir)
                .unwrap()
                .file_type()
                .is_symlink();
        let independent_authorities_restored = tree(&private_state) == private_before
            && tree(&runtime_dir) == runtime_before
            && tree(&receipt) == receipt_before;
        let config_restored = config::load_from(&config_dir).unwrap() == config_before;
        let app_restored = {
            let app = state.lock().unwrap();
            app.proxy.is_none()
                && app.proxy_port == 0
                && app.secret.is_empty()
                && app.provider.is_empty()
                && app.gateway_kind.is_empty()
                && app.shim_mode.is_empty()
                && app.launch_id.is_empty()
                && app.key_fp == 0
                && app.sandbox.is_none()
                && app.sandbox_port == 0
                && app.sandbox_url.is_none()
        };
        drop(snapshot);
        let recovery_metadata = fs::symlink_metadata(&backup_root).ok();
        let recovery_root_preserved = recovery_metadata.as_ref().is_some_and(|metadata| {
            metadata.is_dir() && metadata.permissions().mode() & 0o777 == 0o700
        });
        let immutable_recovery_complete = tree(&backup_root.join("0")) == auth_before
            && tree(&backup_root.join("1")) == private_before
            && tree(&backup_root.join("2")) == runtime_before
            && tree(&backup_root.join("3")) == receipt_before;
        let recovery_has_no_symlink = tree(&backup_root)
            .values()
            .all(|entry| entry.kind != "symlink");
        let retry_error = retry_pending_authority_cleanup(&state)
            .expect_err("an incomplete compensation snapshot must never become cleanup-only");
        let recovery_survives_retry = retry_error
            .contains("cleanup_code=authority_snapshot_recovery_required")
            && backup_root.is_dir();
        assert!(
            refused_without_following
                && independent_authorities_restored
                && config_restored
                && app_restored
                && recovery_root_preserved
                && immutable_recovery_complete
                && recovery_has_no_symlink
                && recovery_survives_retry,
            "rollback refusal must aggregate safely: error={error}; independent={independent_authorities_restored}; config={config_restored}; app={app_restored}; recovery_root={recovery_root_preserved}; recovery_complete={immutable_recovery_complete}; no_symlink={recovery_has_no_symlink}; retry={retry_error}"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary optional SSH feature-off smoke; temp HOME only"]
    fn reuse_system_ssh_false_does_not_require_packaged_wrapper_or_system_home() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut env = ScopedEnv::new();
        let tmp = isolated_tmpdir("ssh-feature-off");
        let missing_wrapper = tmp.join("missing-wrapper");
        env.remove("HOME");
        env.set("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", &missing_wrapper);
        let cfg = Config {
            reuse_system_ssh: false,
            ..Default::default()
        };
        let sandbox_home = tmp.join("sandbox/home");
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let result = prevalidate_one_click_system_ssh(&app.handle().clone(), &cfg, &sandbox_home);
        assert!(
            result.is_ok(),
            "disabled SSH must not require HOME, system config, host parsing, or packaged wrapper: {result:?}"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    // 依赖 0500 只读拒绝写入与 0600/0700 夹具（POSIX 语义）。
    #[cfg(unix)]
    #[test]
    #[ignore = "explicit Acceptance-boundary SSH write-authority prevalidation; temp HOME only"]
    fn enabled_ssh_prevalidation_rejects_unwritable_science_authority() {
        let _env_lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut env = ScopedEnv::new();
        let tmp = isolated_tmpdir("ssh-unwritable-authority");
        let home = tmp.join("home");
        let sandbox_home = tmp.join("sandbox/home");
        let science_data = sandbox_home.join(".claude-science");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::write(home.join(".ssh/config"), b"Host isolated-test-host\n").unwrap();
        fs::set_permissions(home.join(".ssh/config"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::create_dir_all(&science_data).unwrap();
        fs::write(science_data.join("config.toml"), b"quiet_logs = true\n").unwrap();
        fs::set_permissions(
            science_data.join("config.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::set_permissions(&science_data, fs::Permissions::from_mode(0o500)).unwrap();
        let wrapper = tmp.join("ssh-wrapper");
        fs::write(&wrapper, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        env.set("HOME", &home);
        env.set("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", &wrapper);
        let cfg = Config {
            reuse_system_ssh: true,
            ..Default::default()
        };
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let system_before = tree(&home.join(".ssh"));
        let science_before = tree(&science_data);
        let sandbox_stub_before = tree(&sandbox_home.join(".ssh"));
        let result = prevalidate_one_click_system_ssh(&app.handle().clone(), &cfg, &sandbox_home);
        let system_after = tree(&home.join(".ssh"));
        let science_after = tree(&science_data);
        let sandbox_stub_after = tree(&sandbox_home.join(".ssh"));
        let probe_residue = fs::read_dir(&science_data)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| {
                let name = name.to_string_lossy();
                name.starts_with('.') && name.contains("tmp")
            })
            .collect::<Vec<_>>();
        fs::set_permissions(&science_data, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error == "隔离 Science SSH authority 不可写"),
            "enabled SSH must reject a statically unwritable bridge authority before OAuth or journal mutation"
        );
        assert_eq!(system_after, system_before);
        assert_eq!(science_after, science_before);
        assert_eq!(sandbox_stub_after, sandbox_stub_before);
        assert!(
            probe_residue.is_empty(),
            "read-only prevalidation must not create a write probe or temp residue"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    fn profile_with_policy(policy: ModelPolicy) -> config::Profile {
        config::Profile {
            model_policy: policy,
            ..Default::default()
        }
    }

    fn serve_models_after(
        delay: Duration,
        body: impl Into<String>,
    ) -> (u16, Arc<AtomicUsize>, thread::JoinHandle<()>) {
        let body = body.into();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_ne!(port, 8765);
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = requests.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /test-secret/v1/models HTTP/1.0\r\n"));
            server_requests.fetch_add(1, Ordering::SeqCst);
            thread::sleep(delay);
            write!(
                stream,
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        (port, requests, server)
    }

    #[test]
    fn gateway_catalog_timeout_is_uniform_across_model_policies() {
        // Codex 动态目录移除后，目录核验统一使用本地健康探测超时。
        assert_eq!(
            gateway_model_catalog_timeout_ms(&profile_with_policy(ModelPolicy::DynamicCatalog)),
            crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS
        );
        assert_eq!(
            gateway_model_catalog_timeout_ms(&profile_with_policy(ModelPolicy::SavedCatalog)),
            crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS
        );
    }

    #[test]
    fn gateway_catalog_rejects_malformed_or_duplicate_rows_without_filtering_them() {
        for body in [
            r#"{"data":[{"id":"claude-csswitch-relay-mock-1"},{}]}"#,
            r#"{"data":[{"id":"claude-csswitch-relay-mock-1"},{"id":7}]}"#,
            r#"{"data":[{"id":"claude-csswitch-relay-mock-1"},"ignored-before-flow3"]}"#,
            r#"{"data":[{"id":"claude-csswitch-relay-mock-1"},{"id":"claude-csswitch-relay-mock-1"}]}"#,
        ] {
            let (port, _requests, server) = serve_models_after(Duration::ZERO, body);
            let profile = profile_with_policy(ModelPolicy::SavedCatalog);
            let error = verify_gateway_model_catalog(port, "test-secret", &profile).unwrap_err();
            assert!(
                error.contains("malformed") || error.contains("duplicate"),
                "strict catalog parser must reject the exact malformed row: {error}"
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn saved_catalog_requires_exact_selectors_plus_science_canonical_roles() {
        let selector = "claude-csswitch-relay-mock-model-0123456789ab";
        let profile = config::Profile {
            model_policy: ModelPolicy::SavedCatalog,
            model_catalog: vec![crate::model_catalog::ModelRoute {
                selector_id: selector.into(),
                display_name: "Mock model".into(),
                upstream_model: "mock-model".into(),
                supports_tools: Some(true),
                ..Default::default()
            }],
            default_model_route_id: selector.into(),
            ..Default::default()
        };
        let body = r#"{"data":[
            {"id":"claude-csswitch-relay-mock-model-0123456789ab"},
            {"id":"claude-opus-5"},
            {"id":"claude-sonnet-5"},
            {"id":"claude-opus-4-8"},
            {"id":"claude-sonnet-4-6"},
            {"id":"claude-haiku-4-5-20251001"}
        ]}"#;
        let (port, _requests, server) = serve_models_after(Duration::ZERO, body);
        verify_gateway_model_catalog(port, "test-secret", &profile).unwrap();
        server.join().unwrap();

        let unknown = r#"{"data":[
            {"id":"claude-csswitch-relay-mock-model-0123456789ab"},
            {"id":"claude-opus-5"},
            {"id":"claude-sonnet-5"},
            {"id":"claude-opus-4-8"},
            {"id":"claude-sonnet-4-6"},
            {"id":"claude-haiku-4-5-20251001"},
            {"id":"claude-csswitch-stale-provider"}
        ]}"#;
        let (port, _requests, server) = serve_models_after(Duration::ZERO, unknown);
        let error = verify_gateway_model_catalog(port, "test-secret", &profile).unwrap_err();
        assert!(error.contains("白名单/default selector"));
        server.join().unwrap();
    }

    #[test]
    fn runtime_journal_advances_in_place_and_retargets_without_secrets() {
        let dir = std::env::temp_dir().join(format!(
            "csswitch-runtime-journal-{}-{}",
            std::process::id(),
            config::new_id()
        ));
        let previous = RuntimeBindingCommit {
            profile_id: "old".into(),
            route_fp: "route-fp".into(),
            catalog_fp: "catalog-fp".into(),
            binding_fp: "binding-fp".into(),
        };
        config::save_to(
            &dir,
            &Config {
                runtime_binding: Some(previous.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        advance_runtime_transaction(&dir, "new", Some(previous.clone()), "start_gateway").unwrap();
        let first = config::load_from(&dir)
            .unwrap()
            .runtime_transaction
            .unwrap();
        assert_eq!(first.target_profile_id, "new");
        assert_eq!(first.stage, "start_gateway");
        assert_eq!(first.previous_binding, Some(previous.clone()));

        let runtime_id = "a".repeat(64);
        let environment_stage = format!("{SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX}{runtime_id}");
        advance_runtime_transaction(&dir, "new", Some(previous.clone()), &environment_stage)
            .unwrap();
        let second = config::load_from(&dir)
            .unwrap()
            .runtime_transaction
            .unwrap();
        assert_eq!(second.transaction_id, first.transaction_id);
        assert_eq!(second.stage, environment_stage);
        assert_eq!(
            interrupted_science_environment_runtime_id(&second.stage),
            Some(runtime_id.as_str())
        );
        assert!(interrupted_science_environment_runtime_id(
            "start_science_environment_pending:not-a-fingerprint"
        )
        .is_none());
        assert!(
            runtime_transaction_requires_snapshot_preservation("start_science")
                && runtime_transaction_requires_snapshot_preservation(
                    "start_science_environment_pending"
                )
                && runtime_transaction_requires_snapshot_preservation(&environment_stage)
                && !runtime_transaction_requires_snapshot_preservation(
                    "recover_interrupted_gateway"
                ),
            "legacy and fingerprinted environment-exposure stages must fail closed"
        );
        for listener_state in [
            "stopped-no-gateway",
            "running-no-gateway",
            "stopped-managed-gateway",
            "running-managed-gateway",
        ] {
            let legacy =
                validate_interrupted_science_transaction_entry(Some("start_science"), None)
                    .expect_err(
                        "legacy 0.8.3 start_science must never authorize an automatic spawn",
                    );
            assert!(
                legacy.contains("environment_uncertain")
                    && legacy.contains("newer_runtime_required")
                    && legacy.contains("manual_recovery_required"),
                "legacy oracle {listener_state} must fail closed: {legacy}"
            );
        }
        let authority_stage = format!("{AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX}{runtime_id}");
        assert_eq!(
            interrupted_science_environment_runtime_id(&authority_stage),
            Some(runtime_id.as_str())
        );

        advance_runtime_transaction(&dir, "newer", Some(previous), "start_gateway").unwrap();
        let retargeted = config::load_from(&dir)
            .unwrap()
            .runtime_transaction
            .unwrap();
        assert_ne!(retargeted.transaction_id, second.transaction_id);
        assert_eq!(retargeted.target_profile_id, "newer");
        let encoded = serde_json::to_string(&retargeted).unwrap();
        assert!(!encoded.contains("api_key"));
        assert!(!encoded.contains("base_url"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn one_click_snapshot_has_one_commit_and_one_failure_compensation_funnel() {
        use syn::visit::{self, Visit};
        use syn::{Expr, ExprCall, ExprMethodCall, Item, ItemFn, Pat, Stmt};

        fn top_level<'a>(file: &'a syn::File, name: &str) -> Option<&'a ItemFn> {
            file.items.iter().find_map(|item| match item {
                Item::Fn(function) if function.sig.ident == name => Some(function),
                _ => None,
            })
        }

        fn local_name(local: &syn::Local) -> Option<&syn::Ident> {
            match &local.pat {
                Pat::Ident(ident) => Some(&ident.ident),
                Pat::Type(typed) => match &*typed.pat {
                    Pat::Ident(ident) => Some(&ident.ident),
                    _ => None,
                },
                _ => None,
            }
        }

        fn result_arm_name(pattern: &Pat) -> Option<&syn::Ident> {
            match pattern {
                Pat::TupleStruct(tuple) => tuple.path.segments.last().map(|segment| &segment.ident),
                Pat::Struct(structure) => {
                    structure.path.segments.last().map(|segment| &segment.ident)
                }
                Pat::Path(path) => path.path.segments.last().map(|segment| &segment.ident),
                Pat::Ident(ident) => ident
                    .subpat
                    .as_ref()
                    .and_then(|(_, pattern)| result_arm_name(pattern)),
                _ => None,
            }
        }

        fn peel_expr(mut expression: &Expr) -> &Expr {
            loop {
                expression = match expression {
                    Expr::Group(group) => &group.expr,
                    Expr::Paren(paren) => &paren.expr,
                    _ => return expression,
                };
            }
        }

        fn direct_call_name(expression: &Expr) -> Option<&syn::Ident> {
            let Expr::Call(call) = peel_expr(expression) else {
                return None;
            };
            let Expr::Path(path) = peel_expr(&call.func) else {
                return None;
            };
            path.path.segments.last().map(|segment| &segment.ident)
        }

        fn success_tail_is_infallible(expression: &Expr) -> bool {
            match peel_expr(expression) {
                Expr::Path(_) => true,
                Expr::Call(call)
                    if direct_call_name(expression).is_some_and(|name| name == "Ok")
                        && call.args.len() == 1 =>
                {
                    matches!(peel_expr(call.args.first().unwrap()), Expr::Path(_))
                }
                _ => false,
            }
        }

        #[derive(Default)]
        struct FlowFacts {
            calls: Vec<String>,
            methods: Vec<String>,
            tries: usize,
            closures: usize,
        }

        impl<'ast> Visit<'ast> for FlowFacts {
            fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
                if let Expr::Path(path) = &*expression.func {
                    if let Some(segment) = path.path.segments.last() {
                        self.calls.push(segment.ident.to_string());
                    }
                }
                visit::visit_expr_call(self, expression);
            }

            fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
                self.methods.push(expression.method.to_string());
                visit::visit_expr_method_call(self, expression);
            }

            fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
                self.tries += 1;
                visit::visit_expr_try(self, expression);
            }

            fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
                self.closures += 1;
                visit::visit_expr_closure(self, expression);
            }
        }

        #[derive(Debug, Default)]
        struct OuterFacts {
            calls: Vec<String>,
            methods: Vec<String>,
            tries: usize,
            returns: usize,
            assignments: usize,
            macros: usize,
            closures: usize,
        }

        impl<'ast> Visit<'ast> for OuterFacts {
            fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
                if let Expr::Path(path) = &*expression.func {
                    if let Some(segment) = path.path.segments.last() {
                        self.calls.push(segment.ident.to_string());
                    }
                }
                visit::visit_expr_call(self, expression);
            }

            fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
                self.methods.push(expression.method.to_string());
                visit::visit_expr_method_call(self, expression);
            }

            fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
                self.tries += 1;
                visit::visit_expr_try(self, expression);
            }

            fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
                self.returns += 1;
                visit::visit_expr_return(self, expression);
            }

            fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
                self.assignments += 1;
                visit::visit_expr_assign(self, expression);
            }

            fn visit_macro(&mut self, expression: &'ast syn::Macro) {
                self.macros += 1;
                visit::visit_macro(self, expression);
            }

            fn visit_expr_closure(&mut self, _expression: &'ast syn::ExprClosure) {
                self.closures += 1;
            }
            fn visit_item_fn(&mut self, _function: &'ast ItemFn) {}
        }

        #[derive(Default)]
        struct TransactionLocalCount(usize);

        impl<'ast> Visit<'ast> for TransactionLocalCount {
            fn visit_local(&mut self, local: &'ast syn::Local) {
                if local_name(local).is_some_and(|name| name == "transaction_result") {
                    self.0 += 1;
                }
                visit::visit_local(self, local);
            }
        }

        let source = include_str!("sandbox_session.rs");
        let product_source = &source[..source
            .find("#[cfg(test)]\nmod transaction_tests")
            .expect("product source must precede transaction tests")];
        let file = syn::parse_file(product_source).expect("product Rust source must parse");
        let one_click = top_level(&file, "one_click_login_with_options")
            .expect("one-click product function must remain module-level");
        let recovery_restart = top_level(&file, "restart_managed_science_with_budget")
            .expect("DB recovery restart must remain a module-level bounded helper");
        assert!(
            top_level(&file, "compensate_one_click_failure").is_some(),
            "one-click must expose one release-visible failure compensation helper"
        );
        let snapshot_index = one_click
            .block
            .stmts
            .iter()
            .position(|statement| {
                matches!(
                    statement,
                    Stmt::Local(local)
                        if local_name(local).is_some_and(|name| name == "authority_snapshot")
                )
            })
            .expect("one-click must capture authority_snapshot before mutation");
        assert_eq!(
            one_click.block.stmts.len(),
            snapshot_index + 3,
            "authority_snapshot must be followed by exactly transaction_result and its final match"
        );
        let transaction_index = snapshot_index + 1;
        let transaction_statement = &one_click.block.stmts[transaction_index];
        let transaction_local = match transaction_statement {
            Stmt::Local(local)
                if local_name(local).is_some_and(|name| name == "transaction_result") =>
            {
                local
            }
            _ => {
                panic!("authority_snapshot must be followed immediately by let transaction_result")
            }
        };
        let mut transaction_locals = TransactionLocalCount::default();
        transaction_locals.visit_item_fn(one_click);
        assert_eq!(
            transaction_locals.0, 1,
            "one-click must contain exactly one transaction_result local"
        );
        let initializer = transaction_local
            .init
            .as_ref()
            .expect("transaction_result must have an immediate closure initializer");
        let transaction_call = match peel_expr(&initializer.expr) {
            Expr::Call(call) => call,
            _ => panic!("transaction_result initializer must directly invoke a closure"),
        };
        assert!(
            transaction_call.args.is_empty(),
            "transaction_result closure invocation must have zero arguments"
        );
        let transaction_closure = match peel_expr(&transaction_call.func) {
            Expr::Closure(closure) => closure,
            _ => panic!("transaction_result initializer must be a directly invoked closure"),
        };
        assert!(
            transaction_closure.inputs.is_empty(),
            "transaction_result closure must accept zero arguments"
        );
        let mut transaction = FlowFacts::default();
        transaction.visit_stmt(transaction_statement);
        assert_eq!(
            transaction.closures, 1,
            "transaction_result must be produced by one bounded mutation closure"
        );
        for required in [
            "ensure_virtual_login",
            "prepare_science_ssh_bridge",
            "revoke_science_ssh_bridge",
            "ensure_proxy",
            "record_managed_science_launch",
        ] {
            assert!(
                transaction.calls.iter().any(|call| call == required),
                "the single mutation closure must own the {required} error edge"
            );
        }
        assert!(
            transaction.methods.iter().any(|method| method == "spawn")
                && transaction.methods.iter().any(|method| method == "wait")
                && !transaction.methods.iter().any(|method| method == "status"),
            "the single mutation closure must own explicit shell spawn/wait and distinguish spawn from wait failure"
        );
        assert!(
            transaction
                .methods
                .iter()
                .filter(|method| *method == "validate_science_restore_root")
                .count()
                >= 3,
            "one-click must revalidate exact Science/opaque-root bindings before protected writes and immediately before spawn"
        );
        let mut recovery_restart_flow = FlowFacts::default();
        recovery_restart_flow.visit_item_fn(recovery_restart);
        assert!(
            recovery_restart_flow
                .methods
                .iter()
                .any(|method| method == "spawn")
                && recovery_restart_flow
                    .methods
                    .iter()
                    .any(|method| method == "try_wait")
                && recovery_restart_flow
                    .methods
                    .iter()
                    .any(|method| method == "saturating_duration_since")
                && recovery_restart_flow
                    .calls
                    .iter()
                    .any(|call| call == "http_health")
                && !recovery_restart_flow
                    .methods
                    .iter()
                    .any(|method| method == "status"),
            "DB recovery restart must enforce one absolute deadline across explicit shell try_wait and remaining-time-capped health"
        );
        assert!(
            !transaction.methods.iter().any(|method| method == "commit")
                && !transaction
                    .calls
                    .iter()
                    .any(|call| call == "compensate_one_click_failure"),
            "transaction_result closure must neither commit nor compensate its own snapshot"
        );

        let final_statement = one_click
            .block
            .stmts
            .last()
            .expect("one-click must end in the transaction result match");
        let final_match = match final_statement {
            Stmt::Expr(Expr::Match(expression), _) => expression,
            _ => panic!("one-click must end with exactly one success/failure transaction match"),
        };
        assert!(
            matches!(
                &*final_match.expr,
                Expr::Path(path) if path.path.is_ident("transaction_result")
            ),
            "the final transaction match must consume transaction_result directly"
        );
        assert_eq!(
            final_match.arms.len(),
            2,
            "the final transaction match must contain only one success and one failure arm"
        );
        assert!(
            final_match.arms.iter().all(|arm| arm.guard.is_none()),
            "the final transaction match must not use guarded arms"
        );
        let success = final_match
            .arms
            .iter()
            .find(|arm| result_arm_name(&arm.pat).is_some_and(|name| name == "Ok"))
            .expect("the final transaction match must contain one Ok arm");
        let failure = final_match
            .arms
            .iter()
            .find(|arm| result_arm_name(&arm.pat).is_some_and(|name| name == "Err"))
            .expect("the final transaction match must contain one Err arm");
        let success_block = match peel_expr(&success.body) {
            Expr::Block(block) => &block.block,
            _ => panic!("Ok arm must be a block containing commit and an infallible tail"),
        };
        assert_eq!(
            success_block.stmts.len(),
            2,
            "Ok arm must contain only snapshot commit and an infallible success tail"
        );
        let direct_commit = match &success_block.stmts[0] {
            Stmt::Expr(Expr::MethodCall(call), Some(_)) => {
                call.method == "commit"
                    && call.args.is_empty()
                    && matches!(
                        peel_expr(&call.receiver),
                        Expr::Path(path) if path.path.is_ident("authority_snapshot")
                    )
            }
            _ => false,
        };
        assert!(
            direct_commit,
            "Ok arm must begin with the sole direct authority_snapshot.commit()"
        );
        assert!(
            matches!(
                &success_block.stmts[1],
                Stmt::Expr(tail, None) if success_tail_is_infallible(tail)
            ),
            "Ok arm must end with only an infallible path or Ok(path) tail"
        );

        let failure_expression = match peel_expr(&failure.body) {
            Expr::Block(block) if matches!(block.block.stmts.as_slice(), [Stmt::Expr(_, None)]) => {
                match &block.block.stmts[0] {
                    Stmt::Expr(expression, None) => expression,
                    _ => unreachable!(),
                }
            }
            expression => expression,
        };
        assert!(
            direct_call_name(failure_expression)
                .is_some_and(|name| name == "compensate_one_click_failure"),
            "Err arm must be exactly one direct compensate_one_click_failure call"
        );
        let Expr::Call(failure_call) = peel_expr(failure_expression) else {
            unreachable!()
        };
        let mut failure_arguments = OuterFacts::default();
        for argument in &failure_call.args {
            failure_arguments.visit_expr(argument);
        }
        assert!(
            failure_arguments.calls.is_empty()
                && failure_arguments.methods.is_empty()
                && failure_arguments.tries == 0
                && failure_arguments.returns == 0
                && failure_arguments.assignments == 0
                && failure_arguments.macros == 0
                && failure_arguments.closures == 0,
            "Err compensation arguments must be operation-free: {failure_arguments:?}"
        );

        let mut post_snapshot = FlowFacts::default();
        for statement in one_click.block.stmts.iter().skip(snapshot_index + 1) {
            post_snapshot.visit_stmt(statement);
        }
        assert_eq!(
            post_snapshot
                .methods
                .iter()
                .filter(|method| *method == "commit")
                .count(),
            1,
            "all post-snapshot AST must contain exactly one commit, solely in Ok"
        );
        assert_eq!(
            post_snapshot
                .calls
                .iter()
                .filter(|call| *call == "compensate_one_click_failure")
                .count(),
            1,
            "all post-snapshot AST must contain exactly one compensation call, solely in Err"
        );
    }

    #[test]
    fn ssh_wrapper_prevalidation_uses_the_running_runtime_validator_before_oauth() {
        use syn::visit::{self, Visit};
        use syn::{
            Attribute, Expr, ExprCall, ExprLit, GenericArgument, Item, ItemFn, Lit, Pat,
            PathArguments, Stmt, Type,
        };

        fn top_level<'a>(file: &'a syn::File, name: &str) -> &'a ItemFn {
            file.items
                .iter()
                .find_map(|item| match item {
                    Item::Fn(function) if function.sig.ident == name => Some(function),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing module-level product function {name}"))
        }

        fn is_cfg(attribute: &Attribute) -> bool {
            attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr")
        }

        fn cfg_tokens(attribute: &Attribute) -> String {
            attribute
                .meta
                .require_list()
                .map(|list| list.tokens.to_string())
                .unwrap_or_default()
        }

        fn reject_cfg(attributes: &[Attribute], label: &str) {
            assert!(
                !attributes.iter().any(is_cfg),
                "{label} must be present in every release build"
            );
        }

        #[derive(Default)]
        struct Facts {
            calls: Vec<String>,
            strings: Vec<String>,
            has_cfg: bool,
        }

        impl<'ast> Visit<'ast> for Facts {
            fn visit_attribute(&mut self, attribute: &'ast Attribute) {
                self.has_cfg |= is_cfg(attribute);
                visit::visit_attribute(self, attribute);
            }

            fn visit_expr_call(&mut self, call: &'ast ExprCall) {
                if let Expr::Path(path) = &*call.func {
                    if let Some(segment) = path.path.segments.last() {
                        self.calls.push(segment.ident.to_string());
                    }
                }
                visit::visit_expr_call(self, call);
            }

            fn visit_expr_lit(&mut self, literal: &'ast ExprLit) {
                if let Lit::Str(value) = &literal.lit {
                    self.strings.push(value.value());
                }
                visit::visit_expr_lit(self, literal);
            }

            fn visit_item_fn(&mut self, _function: &'ast ItemFn) {}
            fn visit_expr_closure(&mut self, _closure: &'ast syn::ExprClosure) {}
            fn visit_expr_async(&mut self, _expression: &'ast syn::ExprAsync) {}
        }

        fn statement_facts(statement: &Stmt) -> Facts {
            let mut facts = Facts::default();
            facts.visit_stmt(statement);
            facts
        }

        fn function_facts(function: &ItemFn) -> Facts {
            let mut facts = Facts::default();
            facts.visit_block(&function.block);
            facts
        }

        fn local_name(local: &syn::Local) -> Option<&syn::Ident> {
            match &local.pat {
                Pat::Ident(ident) => Some(&ident.ident),
                Pat::Type(typed) => match &*typed.pat {
                    Pat::Ident(ident) => Some(&ident.ident),
                    _ => None,
                },
                _ => None,
            }
        }

        fn peel_expression(mut expression: &Expr) -> &Expr {
            loop {
                expression = match expression {
                    Expr::Group(group) => &group.expr,
                    Expr::Paren(paren) => &paren.expr,
                    _ => return expression,
                };
            }
        }

        fn direct_zero_arg_closure_body(local: &syn::Local) -> Option<&syn::Block> {
            let initializer = local.init.as_ref()?;
            let Expr::Call(call) = peel_expression(&initializer.expr) else {
                return None;
            };
            if !call.args.is_empty() {
                return None;
            }
            let Expr::Closure(closure) = peel_expression(&call.func) else {
                return None;
            };
            closure.inputs.is_empty().then_some(&closure.body).and_then(
                |body| match peel_expression(body) {
                    Expr::Block(block) => Some(&block.block),
                    _ => None,
                },
            )
        }

        fn direct_call(expression: &Expr) -> Option<&ExprCall> {
            match expression {
                Expr::Call(call) => Some(call),
                Expr::Await(awaited) => direct_call(&awaited.base),
                Expr::Group(group) => direct_call(&group.expr),
                Expr::Paren(paren) => direct_call(&paren.expr),
                Expr::Try(tried) => direct_call(&tried.expr),
                _ => None,
            }
        }

        fn call_path(call: &ExprCall) -> Option<String> {
            let Expr::Path(path) = &*call.func else {
                return None;
            };
            Some(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            )
        }

        fn expression_path(expression: &Expr) -> Option<String> {
            let Expr::Path(path) = expression else {
                return None;
            };
            Some(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            )
        }

        fn statement_directly_calls(statement: &Stmt, expected: &str) -> bool {
            let expression = match statement {
                Stmt::Local(local) => local.init.as_ref().map(|init| &*init.expr),
                Stmt::Expr(expression, _) => Some(expression),
                _ => None,
            };
            expression
                .and_then(direct_call)
                .and_then(call_path)
                .as_deref()
                == Some(expected)
        }

        fn simple_argument_name(expression: &Expr) -> Option<String> {
            let expression = match expression {
                Expr::Reference(reference) => &*reference.expr,
                Expr::Group(group) => &*group.expr,
                Expr::Paren(paren) => &*paren.expr,
                expression => expression,
            };
            let Expr::Path(path) = expression else {
                return None;
            };
            (path.qself.is_none() && path.path.segments.len() == 1)
                .then(|| path.path.segments[0].ident.to_string())
        }

        fn statement_direct_call_arguments(statement: &Stmt) -> Option<Vec<String>> {
            let expression = match statement {
                Stmt::Local(local) => local.init.as_ref().map(|init| &*init.expr),
                Stmt::Expr(expression, _) => Some(expression),
                _ => None,
            }?;
            let call = direct_call(expression)?;
            call.args.iter().map(simple_argument_name).collect()
        }

        fn statement_propagates_direct_call(statement: &Stmt, expected: &str) -> bool {
            let expression = match statement {
                Stmt::Local(local) => local.init.as_ref().map(|init| &*init.expr),
                Stmt::Expr(expression, _) => Some(expression),
                _ => None,
            };
            let Some(Expr::Try(tried)) = expression else {
                return false;
            };
            let Expr::Call(call) = &*tried.expr else {
                return false;
            };
            call_path(call).as_deref() == Some(expected)
        }

        fn returns_result_pathbuf_string(function: &ItemFn) -> bool {
            let syn::ReturnType::Type(_, returned) = &function.sig.output else {
                return false;
            };
            let Type::Path(path) = &**returned else {
                return false;
            };
            let Some(result) = path.path.segments.last() else {
                return false;
            };
            if result.ident != "Result" {
                return false;
            }
            let PathArguments::AngleBracketed(arguments) = &result.arguments else {
                return false;
            };
            let types = arguments
                .args
                .iter()
                .filter_map(|argument| match argument {
                    GenericArgument::Type(Type::Path(path)) => path
                        .path
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            types == ["PathBuf", "String"]
        }

        #[derive(Default)]
        struct EarlyExitFacts {
            count: usize,
        }

        impl<'ast> Visit<'ast> for EarlyExitFacts {
            fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
                self.count += 1;
                visit::visit_expr_return(self, expression);
            }

            fn visit_expr_break(&mut self, expression: &'ast syn::ExprBreak) {
                self.count += 1;
                visit::visit_expr_break(self, expression);
            }

            fn visit_expr_continue(&mut self, expression: &'ast syn::ExprContinue) {
                self.count += 1;
                visit::visit_expr_continue(self, expression);
            }

            fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
                self.count += 1;
                visit::visit_expr_loop(self, expression);
            }

            fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
                self.count += 1;
                visit::visit_expr_while(self, expression);
            }

            fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
                self.count += 1;
                visit::visit_expr_for_loop(self, expression);
            }

            fn visit_expr_call(&mut self, call: &'ast ExprCall) {
                if call_path(call).is_some_and(|path| {
                    matches!(
                        path.rsplit("::").next(),
                        Some("exit" | "abort" | "abort_internal")
                    )
                }) {
                    self.count += 1;
                }
                visit::visit_expr_call(self, call);
            }

            fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
                if invocation.path.segments.last().is_some_and(|segment| {
                    matches!(
                        segment.ident.to_string().as_str(),
                        "panic" | "todo" | "unreachable"
                    )
                }) || token_stream_contains_any(
                    invocation.tokens.clone(),
                    &["return", "break", "continue"],
                ) {
                    self.count += 1;
                }
                visit::visit_macro(self, invocation);
            }
        }

        #[derive(Default)]
        struct ProductLiterals(Vec<String>);

        impl<'ast> Visit<'ast> for ProductLiterals {
            fn visit_expr_lit(&mut self, literal: &'ast ExprLit) {
                if let Lit::Str(value) = &literal.lit {
                    self.0.push(value.value());
                }
                visit::visit_expr_lit(self, literal);
            }
        }

        fn use_tree_contains_ident(tree: &syn::UseTree, expected: &str) -> bool {
            match tree {
                syn::UseTree::Path(path) => {
                    path.ident == expected || use_tree_contains_ident(&path.tree, expected)
                }
                syn::UseTree::Name(name) => name.ident == expected,
                syn::UseTree::Rename(rename) => rename.ident == expected,
                syn::UseTree::Group(group) => group
                    .items
                    .iter()
                    .any(|tree| use_tree_contains_ident(tree, expected)),
                syn::UseTree::Glob(_) => false,
            }
        }

        fn token_stream_contains_any(tokens: proc_macro2::TokenStream, expected: &[&str]) -> bool {
            tokens.into_iter().any(|token| match token {
                proc_macro2::TokenTree::Ident(ident) => {
                    expected.iter().any(|value| ident == *value)
                }
                proc_macro2::TokenTree::Group(group) => {
                    token_stream_contains_any(group.stream(), expected)
                }
                _ => false,
            })
        }

        #[derive(Default)]
        struct ForbiddenCfgMacros(usize);

        impl<'ast> Visit<'ast> for ForbiddenCfgMacros {
            fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
                if invocation
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "cfg")
                    || token_stream_contains_any(invocation.tokens.clone(), &["cfg"])
                {
                    self.0 += 1;
                }
                visit::visit_macro(self, invocation);
            }

            fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
                if use_tree_contains_ident(&item.tree, "cfg") {
                    self.0 += 1;
                }
                visit::visit_item_use(self, item);
            }
        }

        #[derive(Default)]
        struct ValidatorFacts {
            cfg_attributes: Vec<String>,
            environment_reads: Vec<String>,
            environment_paths: Vec<String>,
            environment_imports: usize,
        }

        #[derive(Default)]
        struct ProductEnvironmentFacts {
            environment_paths: Vec<String>,
            environment_imports: usize,
        }

        impl<'ast> Visit<'ast> for ProductEnvironmentFacts {
            fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
                let path = expression
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                let last = path.rsplit("::").next().unwrap_or_default();
                if path.split("::").any(|segment| segment == "env")
                    || matches!(last, "var" | "var_os" | "vars" | "vars_os")
                {
                    self.environment_paths.push(path);
                }
                visit::visit_expr_path(self, expression);
            }

            fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
                if use_tree_contains_ident(&item.tree, "env") {
                    self.environment_imports += 1;
                }
                visit::visit_item_use(self, item);
            }

            fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
                if token_stream_contains_any(
                    invocation.tokens.clone(),
                    &["env", "var", "var_os", "vars", "vars_os"],
                ) {
                    self.environment_imports += 1;
                }
                visit::visit_macro(self, invocation);
            }
        }

        impl<'ast> Visit<'ast> for ValidatorFacts {
            fn visit_attribute(&mut self, attribute: &'ast Attribute) {
                if is_cfg(attribute) {
                    self.cfg_attributes.push(cfg_tokens(attribute));
                }
                visit::visit_attribute(self, attribute);
            }

            fn visit_expr_call(&mut self, call: &'ast ExprCall) {
                if let Some(path) = call_path(call) {
                    let last = path.rsplit("::").next().unwrap_or_default();
                    if path.split("::").any(|segment| segment == "env")
                        || matches!(last, "var" | "var_os" | "vars" | "vars_os")
                    {
                        self.environment_reads.push(path);
                    }
                }
                visit::visit_expr_call(self, call);
            }

            fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
                let path = expression
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                let last = path.rsplit("::").next().unwrap_or_default();
                if path.split("::").any(|segment| segment == "env")
                    || matches!(last, "var" | "var_os" | "vars" | "vars_os")
                {
                    self.environment_paths.push(path);
                }
                visit::visit_expr_path(self, expression);
            }

            fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
                if use_tree_contains_ident(&item.tree, "env") {
                    self.environment_imports += 1;
                }
                visit::visit_item_use(self, item);
            }
        }

        #[derive(Default)]
        struct WrapperLocalCount(usize);

        impl<'ast> Visit<'ast> for WrapperLocalCount {
            fn visit_local(&mut self, local: &'ast syn::Local) {
                if local_name(local).is_some_and(|name| name == "wrapper_override") {
                    self.0 += 1;
                }
                visit::visit_local(self, local);
            }
        }

        #[derive(Default)]
        struct CfgAttributes(Vec<String>);

        impl<'ast> Visit<'ast> for CfgAttributes {
            fn visit_attribute(&mut self, attribute: &'ast Attribute) {
                if is_cfg(attribute) {
                    self.0.push(cfg_tokens(attribute));
                }
                visit::visit_attribute(self, attribute);
            }
        }

        fn exact_test_override(local: &syn::Local) -> bool {
            if local.attrs.len() != 1
                || !local.attrs[0].path().is_ident("cfg")
                || cfg_tokens(&local.attrs[0]) != "test"
                || !matches!(&local.pat, Pat::Ident(ident) if ident.ident == "wrapper_override")
            {
                return false;
            }
            let Some(initializer) = &local.init else {
                return false;
            };
            let Expr::MethodCall(mapped) = &*initializer.expr else {
                return false;
            };
            if mapped.method != "map" || mapped.args.len() != 1 {
                return false;
            }
            let Expr::Call(read) = &*mapped.receiver else {
                return false;
            };
            if call_path(read).as_deref() != Some("std::env::var_os") || read.args.len() != 1 {
                return false;
            }
            if !matches!(
                read.args.first(),
                Some(Expr::Lit(ExprLit {
                    lit: Lit::Str(value),
                    ..
                })) if value.value() == "CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE"
            ) {
                return false;
            }
            expression_path(mapped.args.first().unwrap()).as_deref() == Some("PathBuf::from")
        }

        fn option_pathbuf_type(pattern: &Pat) -> bool {
            let Pat::Type(typed) = pattern else {
                return false;
            };
            if !matches!(&*typed.pat, Pat::Ident(ident) if ident.ident == "wrapper_override") {
                return false;
            }
            let Type::Path(path) = &*typed.ty else {
                return false;
            };
            let Some(option) = path.path.segments.last() else {
                return false;
            };
            if option.ident != "Option" {
                return false;
            }
            let PathArguments::AngleBracketed(arguments) = &option.arguments else {
                return false;
            };
            matches!(
                arguments.args.first(),
                Some(GenericArgument::Type(Type::Path(inner)))
                    if inner.path.segments.last().is_some_and(|segment| segment.ident == "PathBuf")
            )
        }

        fn exact_release_override(local: &syn::Local) -> bool {
            if local.attrs.len() != 1
                || !local.attrs[0].path().is_ident("cfg")
                || cfg_tokens(&local.attrs[0]).replace(' ', "") != "not(test)"
                || !option_pathbuf_type(&local.pat)
            {
                return false;
            }
            let Some(initializer) = &local.init else {
                return false;
            };
            expression_path(&initializer.expr).as_deref() == Some("None")
        }

        let source = include_str!("sandbox_session.rs");
        let product_source = &source[..source
            .find("#[cfg(test)]\nmod transaction_tests")
            .expect("product source must precede transaction tests")];
        let file = syn::parse_file(product_source).expect("product Rust source must parse");
        let mut forbidden_cfg_macros = ForbiddenCfgMacros::default();
        forbidden_cfg_macros.visit_file(&file);
        assert_eq!(
            forbidden_cfg_macros.0, 0,
            "product SSH transaction source must not branch on cfg!(test)"
        );
        let validator = top_level(&file, "validate_system_ssh_wrapper_path");
        let running = top_level(&file, "validate_running_system_ssh_bridge");
        let prevalidation = top_level(&file, "prevalidate_one_click_system_ssh");
        let one_click = top_level(&file, "one_click_login_with_options");
        assert!(
            returns_result_pathbuf_string(validator),
            "shared wrapper validator must return Result<PathBuf, String>"
        );
        let mut product_environment = ProductEnvironmentFacts::default();
        product_environment.visit_file(&file);
        product_environment.environment_paths.sort();
        assert_eq!(
            product_environment.environment_imports, 0,
            "product SSH transaction source must not import or alias environment APIs"
        );
        assert_eq!(
            product_environment.environment_paths,
            [
                "std::env::var".to_string(),
                "std::env::var".to_string(),
                "std::env::var".to_string(),
                "std::env::var_os".to_string(),
                "std::env::var_os".to_string(),
                "std::env::var_os".to_string(),
            ],
            "product transaction source may reference only the existing spike seam, DB reverify/restart-budget seams, exact wrapper override, host-proof seam, and exact late-failure seam environment APIs"
        );

        for (name, function) in [
            ("shared wrapper validator", validator),
            ("running SSH validator", running),
            ("pre-OAuth SSH validator", prevalidation),
            ("one-click product path", one_click),
        ] {
            reject_cfg(&function.attrs, name);
        }

        {
            let (name, function) = ("running SSH validator", running);
            let facts = function_facts(function);
            assert!(
                !facts.has_cfg,
                "{name} must not contain cfg-gated call sites"
            );
        }
        let prevalidation_facts = function_facts(prevalidation);
        assert!(
            !prevalidation_facts.has_cfg,
            "pre-OAuth SSH validation must not contain cfg-gated call sites"
        );
        assert_eq!(
            prevalidation_facts
                .calls
                .iter()
                .filter(|call| *call == "validate_system_ssh_wrapper_path")
                .count(),
            1,
            "enabled pre-OAuth validation must use the same shared wrapper validator exactly once"
        );
        for required in [
            "prevalidate_science_ssh_bridge",
            "prevalidate_sandbox_ssh_stub",
        ] {
            assert!(
                prevalidation_facts.calls.iter().any(|call| call == required),
                "pre-OAuth validation must preserve disabled-mode read-only conflict validation via {required}"
            );
        }

        {
            let (name, function) = ("running SSH validator", running);
            let shared_call_positions = function
                .block
                .stmts
                .iter()
                .enumerate()
                .filter_map(|(index, statement)| {
                    statement_directly_calls(
                        statement,
                        "crate::runtime::sandbox_session::validate_system_ssh_wrapper_path",
                    )
                    .then_some(index)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                shared_call_positions,
                [0],
                "{name} must execute the shared wrapper validator exactly once as its first statement"
            );
            assert_eq!(
                statement_direct_call_arguments(&function.block.stmts[0]),
                Some(vec!["app".to_string()]),
                "{name} shared-validator call may receive only the simple app argument"
            );
            assert!(
                statement_propagates_direct_call(
                    &function.block.stmts[0],
                    "crate::runtime::sandbox_session::validate_system_ssh_wrapper_path",
                ),
                "{name} must propagate the shared-validator Result with an exact Try(Call)"
            );
            let mut call_exit = EarlyExitFacts::default();
            call_exit.visit_stmt(&function.block.stmts[0]);
            assert_eq!(
                call_exit.count, 0,
                "{name} shared-validator call statement must not hide early-exit control flow in its arguments"
            );
        }

        let prevalidate_statement = one_click
            .block
            .stmts
            .iter()
            .position(|statement| {
                matches!(statement, Stmt::Local(_))
                    && statement_directly_calls(
                        statement,
                        "crate::runtime::sandbox_session::prevalidate_one_click_system_ssh",
                    )
            })
            .expect("one-click must execute prevalidation in a top-level local statement");
        assert_eq!(
            one_click
                .block
                .stmts
                .iter()
                .filter(|statement| {
                    statement_directly_calls(
                        statement,
                        "crate::runtime::sandbox_session::prevalidate_one_click_system_ssh",
                    )
                })
                .count(),
            1,
            "one-click must execute exactly one direct prevalidation call"
        );
        assert_eq!(
            statement_direct_call_arguments(&one_click.block.stmts[prevalidate_statement]),
            Some(vec![
                "app".to_string(),
                "cfg".to_string(),
                "sbx_home".to_string(),
            ]),
            "one-click prevalidation may receive only simple app, cfg, and sbx_home arguments"
        );
        assert!(
            statement_propagates_direct_call(
                &one_click.block.stmts[prevalidate_statement],
                "crate::runtime::sandbox_session::prevalidate_one_click_system_ssh",
            ),
            "one-click must propagate the prevalidation Result with an exact Try(Call)"
        );
        let mut early_exit = EarlyExitFacts::default();
        for statement in &one_click.block.stmts[..prevalidate_statement] {
            early_exit.visit_stmt(statement);
        }
        early_exit.visit_stmt(&one_click.block.stmts[prevalidate_statement]);
        assert_eq!(
            early_exit.count, 0,
            "one-click prevalidation statement and its prefix must be reachable before explicit early-exit control flow"
        );
        let authority_snapshot_statement = one_click
            .block
            .stmts
            .iter()
            .position(|statement| {
                matches!(
                    statement,
                    Stmt::Local(local)
                        if local_name(local).is_some_and(|name| name == "authority_snapshot")
                )
            })
            .expect("one-click authority snapshot statement must exist");
        let transaction_statement = one_click
            .block
            .stmts
            .iter()
            .position(|statement| {
                matches!(
                    statement,
                    Stmt::Local(local)
                        if local_name(local).is_some_and(|name| name == "transaction_result")
                )
            })
            .expect("one-click transaction_result statement must exist");
        assert!(
            prevalidate_statement < authority_snapshot_statement
                && authority_snapshot_statement < transaction_statement,
            "SSH prevalidation must precede authority snapshot and the mutation transaction"
        );
        assert!(
            one_click.block.stmts[..transaction_statement]
                .iter()
                .all(|statement| !statement_facts(statement)
                    .calls
                    .iter()
                    .any(|call| call == "ensure_virtual_login")),
            "one-click must not execute OAuth mutation before transaction_result"
        );
        let transaction_local = match &one_click.block.stmts[transaction_statement] {
            Stmt::Local(local) => local,
            _ => unreachable!(),
        };
        let transaction_body = direct_zero_arg_closure_body(transaction_local)
            .expect("transaction_result must directly invoke one zero-argument closure block");
        let oauth_statements = transaction_body
            .stmts
            .iter()
            .enumerate()
            .filter(|(_, statement)| {
                statement_facts(statement)
                    .calls
                    .iter()
                    .any(|call| call == "ensure_virtual_login")
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(
            oauth_statements.len(),
            1,
            "transaction body must contain exactly one top-level OAuth mutation statement"
        );
        let mut one_click_cfg = CfgAttributes::default();
        one_click_cfg.visit_block(&one_click.block);
        assert_eq!(
            one_click_cfg.0,
            [
                "windows".to_string(),
                "test".to_string(),
                "test".to_string()
            ],
            "one-click may contain only the Windows sweep seam and the exact host-proof and late-failure cfg(test) seams"
        );
        let late_seam_statements = transaction_body
            .stmts
            .iter()
            .enumerate()
            .filter(|(_, statement)| {
                let facts = statement_facts(statement);
                facts.has_cfg
                    && facts
                        .strings
                        .iter()
                        .any(|value| value == "CSSWITCH_TEST_SSH_LATE_FOREIGN_STUB")
                    && matches!(
                        statement,
                        Stmt::Expr(Expr::If(expression), _)
                            if expression.attrs.len() == 1
                                && expression.attrs[0].path().is_ident("cfg")
                                && cfg_tokens(&expression.attrs[0]) == "test"
                    )
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(
            late_seam_statements.len(),
            1,
            "transaction body must contain exactly one top-level exact cfg(test) late-failure seam"
        );
        assert!(
            oauth_statements[0] < late_seam_statements[0],
            "the sole transaction cfg(test) seam must remain after OAuth mutation"
        );

        let wrapper_locals = validator
            .block
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Local(local)
                    if local_name(local).is_some_and(|name| name == "wrapper_override") =>
                {
                    Some(local)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut wrapper_local_count = WrapperLocalCount::default();
        wrapper_local_count.visit_block(&validator.block);
        assert_eq!(
            wrapper_local_count.0, 2,
            "shared validator must not hide extra wrapper_override locals in nested product code"
        );
        assert_eq!(
            wrapper_locals.len(),
            2,
            "shared validator must define test and release wrapper_override locals"
        );
        assert!(
            wrapper_locals.iter().any(|local| exact_test_override(local)),
            "test wrapper_override must be the sole cfg(test) var_os literal mapped through PathBuf::from"
        );
        assert!(
            wrapper_locals
                .iter()
                .any(|local| exact_release_override(local)),
            "release wrapper_override must be exactly cfg(not(test)) Option<PathBuf> = None"
        );
        let mut validator_facts = ValidatorFacts::default();
        validator_facts.visit_block(&validator.block);
        validator_facts.cfg_attributes.sort();
        assert_eq!(
            validator_facts.cfg_attributes,
            ["not (test)".to_string(), "test".to_string()],
            "shared validator may contain only the two exact wrapper_override cfg attributes"
        );
        assert_eq!(
            validator_facts.environment_reads,
            ["std::env::var_os".to_string()],
            "shared validator may perform only the guarded test var_os environment read"
        );
        assert_eq!(
            validator_facts.environment_paths,
            ["std::env::var_os".to_string()],
            "shared validator may reference only the guarded test var_os environment path"
        );
        assert_eq!(
            validator_facts.environment_imports, 0,
            "shared validator must not import or alias environment APIs"
        );
        let mut product_literals = ProductLiterals::default();
        product_literals.visit_file(&file);
        assert_eq!(
            product_literals
                .0
                .iter()
                .filter(|value| value.as_str() == "CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE")
                .count(),
            1,
            "the test wrapper environment variable may appear only in its guarded local"
        );
    }

    // 行为段依赖 POSIX 执行位/symlink 语义（0600 不可执行、symlink 拒绝等），
    // 仅 unix 可运行；AST 结构契约已在上方跨平台测试中覆盖。
    #[cfg(unix)]
    #[test]
    fn ssh_wrapper_prevalidation_unix_behavior_contract() {
        struct RestoreWrapperOverride(Option<std::ffi::OsString>);
        impl Drop for RestoreWrapperOverride {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", value),
                    None => std::env::remove_var("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE"),
                }
            }
        }

        use std::os::unix::fs::PermissionsExt;
        let _override_guard =
            RestoreWrapperOverride(std::env::var_os("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE"));
        let root = std::env::temp_dir().join(format!(
            "csswitch-shared-ssh-validator-{}-{}",
            std::process::id(),
            crate::config::new_id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let missing = root.join("missing-wrapper");
        std::env::set_var("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", &missing);
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        assert_eq!(
            super::validate_system_ssh_wrapper_path(app.handle()).unwrap_err(),
            "打包的 CSSwitch SSH bridge 缺失"
        );
        let wrapper = root.join("ssh");
        std::fs::write(&wrapper, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::env::set_var("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", &wrapper);
        assert_eq!(
            super::validate_system_ssh_wrapper_path(app.handle()).unwrap_err(),
            "打包的 CSSwitch SSH bridge 不是安全的可执行文件"
        );
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            super::validate_system_ssh_wrapper_path(app.handle()).unwrap(),
            wrapper
        );
        let wrapper_link = root.join("ssh-link");
        std::os::unix::fs::symlink(&wrapper, &wrapper_link).unwrap();
        std::env::set_var("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", &wrapper_link);
        assert_eq!(
            super::validate_system_ssh_wrapper_path(app.handle()).unwrap_err(),
            "打包的 CSSwitch SSH bridge 不是安全的可执行文件"
        );
        let wrapper_directory = root.join("ssh-directory");
        std::fs::create_dir(&wrapper_directory).unwrap();
        std::fs::set_permissions(&wrapper_directory, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::env::set_var("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", &wrapper_directory);
        assert_eq!(
            super::validate_system_ssh_wrapper_path(app.handle()).unwrap_err(),
            "打包的 CSSwitch SSH bridge 不是安全的可执行文件"
        );
        let oversized_wrapper = root.join("ssh-oversized");
        std::fs::write(&oversized_wrapper, vec![b'x'; 128 * 1024 + 1]).unwrap();
        std::fs::set_permissions(&oversized_wrapper, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::env::set_var("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", &oversized_wrapper);
        assert_eq!(
            super::validate_system_ssh_wrapper_path(app.handle()).unwrap_err(),
            "打包的 CSSwitch SSH bridge 不是安全的可执行文件"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
