use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::Runtime;

use crate::{config, proc};

use super::system::kill_child;
// asset_root 仅用于 unix 的停止脚本调用路径。
#[cfg(unix)]
use super::system::asset_root;

pub(crate) const SCIENCE_BIN: &str =
    "/Applications/Claude Science.app/Contents/Resources/bin/claude-science";
pub(crate) const SCIENCE_DOWNLOAD_URL: &str = "https://claude.com/download";
pub(crate) const CACHED_ONCE_CHOICE: &str = "cached_once";
// mac 官方 updater 快照信任链的标识/尺寸常量；Windows 上该链路设计性短路
// （无 codesign 可校验），故无调用方，保留以维持两端实现对照。
#[allow(dead_code)]
const OFFICIAL_UPDATED_RUNTIME_RELATIVE: &str = ".claude-science/bin/claude-science";
#[allow(dead_code)]
const OFFICIAL_UPDATED_SCIENCE_IDENTIFIERS: [&str; 2] =
    ["com.anthropic.operon", "com.anthropic.operon.cli"];
#[allow(dead_code)]
const OFFICIAL_SCIENCE_TEAM_ID: &str = "Q6L2SF6YDW";
#[allow(dead_code)]
const MIN_SCIENCE_BINARY_SIZE: u64 = 1024 * 1024;
#[allow(dead_code)]
const MAX_SCIENCE_BINARY_SIZE: u64 = 512 * 1024 * 1024;
const OFFICIAL_UPDATED_SNAPSHOT_DIR: &str = "runtime-snapshots/science";
const SCIENCE_VERSION_TIMEOUT: Duration = Duration::from_secs(15);
const MANAGED_LAUNCH_FILE: &str = "science-managed-launch.v1.json";
const MAX_MANAGED_LAUNCH_BYTES: u64 = 16 * 1024;
static SCIENCE_VERSION_OUTPUT_NONCE: AtomicU64 = AtomicU64::new(1);
#[cfg(test)]
static MANAGED_LAUNCH_LAST_READ_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScienceRuntimeSource {
    Explicit,
    OfficialUpdated,
    InstalledApp,
    CachedOnce,
}

impl ScienceRuntimeSource {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::OfficialUpdated => "official_updated",
            Self::InstalledApp => "installed_app",
            Self::CachedOnce => "cached_once",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScienceRuntimeIdentity {
    pub(crate) path: PathBuf,
    pub(crate) source: ScienceRuntimeSource,
    pub(crate) version: Option<String>,
    fingerprint: ScienceExecutableFingerprint,
}

impl ScienceRuntimeIdentity {
    pub(crate) fn environment_transaction_id(&self) -> String {
        fingerprint_sha256_hex(&self.fingerprint)
    }

    pub(crate) fn skill_install_host_context(
        &self,
        sandbox_port: u16,
    ) -> Result<csswitch_skill_install_core::ScienceHostContext, String> {
        let canonical = crate::platform::canonicalize(&self.path)
            .map_err(|_| "Science binary 不可用，无法启用 Skill attach control")?;
        if canonical != self.path {
            return Err("Science binary 不是 canonical path，无法启用 Skill attach control".into());
        }
        let version = self
            .version
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .ok_or("Science 版本未确认，无法启用 Skill attach control")?
            .clone();
        if !self.is_current() {
            return Err("Science binary 在选择后发生变化，无法启用 Skill attach control".into());
        }
        let fingerprint = &self.fingerprint;
        Ok(csswitch_skill_install_core::ScienceHostContext {
            binary: canonical,
            version,
            fingerprint: csswitch_skill_install_core::ScienceExecutableFingerprint {
                device: fingerprint.device,
                inode: fingerprint.inode,
                size: fingerprint.size,
                modified_seconds: fingerprint.modified_seconds,
                modified_nanoseconds: fingerprint.modified_nanoseconds,
                mode: fingerprint.mode,
                sha256: fingerprint_sha256_hex(fingerprint),
            },
            home: sandbox_home(),
            data_dir: sandbox_data_dir(),
            sandbox_port,
        })
    }

    pub(crate) fn is_current(&self) -> bool {
        science_executable_fingerprint(&self.path).as_ref() == Some(&self.fingerprint)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScienceExecutableFingerprint {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    mode: u32,
    sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ScienceManagedLaunchRecord {
    schema_version: u32,
    launch_id: String,
    port: u16,
    listener_pid: u32,
    process_start: String,
    runtime_path: PathBuf,
    runtime_device: u64,
    runtime_inode: u64,
    runtime_size: u64,
    runtime_modified_seconds: i64,
    runtime_modified_nanoseconds: i64,
    runtime_mode: u32,
    runtime_sha256: String,
    data_dir: PathBuf,
    data_dir_device: u64,
    data_dir_inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedLaunchFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    mode: u32,
    owner_is_current: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ScienceManagedLaunchToken {
    record: ScienceManagedLaunchRecord,
    receipt_file: Option<ManagedLaunchFileIdentity>,
}

#[cfg(test)]
static MANAGED_LAUNCH_COMMIT_FAILURE_ONCE_FIRED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, unix))]
pub(crate) fn test_reset_managed_launch_commit_failure_once() {
    MANAGED_LAUNCH_COMMIT_FAILURE_ONCE_FIRED.store(false, std::sync::atomic::Ordering::SeqCst);
}

#[derive(Debug)]
pub(crate) struct ScienceManagedLaunchCommitError {
    message: String,
    token: Option<ScienceManagedLaunchToken>,
}

impl ScienceManagedLaunchCommitError {
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn token(&self) -> Option<&ScienceManagedLaunchToken> {
        self.token.as_ref()
    }
}

#[derive(Clone, Debug)]
struct ScienceVersionCacheEntry {
    fingerprint: ScienceExecutableFingerprint,
    version: String,
}

/// Successful Science `--version` results, shared for one CSSwitch process.
///
/// The dedicated inner lock serializes only the rare version probe. It never
/// holds the broader AppState lock while launching an external process.
#[derive(Clone, Debug, Default)]
pub(crate) struct ScienceVersionCache {
    entries: Arc<Mutex<HashMap<PathBuf, ScienceVersionCacheEntry>>>,
}

impl ScienceVersionCache {
    fn version(&self, path: &Path) -> Option<String> {
        self.version_inner(path, false)
    }

    pub(crate) fn force_refresh(&self, path: &Path) -> Option<String> {
        self.version_inner(path, true)
    }

    fn version_inner(&self, path: &Path, force: bool) -> Option<String> {
        let mut force = force;
        for _ in 0..2 {
            let fingerprint = science_executable_fingerprint(path)?;
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if force {
                entries.remove(path);
                force = false;
            } else if let Some(entry) = entries.get(path) {
                if entry.fingerprint == fingerprint {
                    return Some(entry.version.clone());
                }
                entries.remove(path);
            }

            let version = safe_science_version(path)?;
            let Some(after) = science_executable_fingerprint(path) else {
                entries.remove(path);
                return None;
            };
            if after != fingerprint {
                entries.remove(path);
                continue;
            }
            entries.insert(
                path.to_path_buf(),
                ScienceVersionCacheEntry {
                    fingerprint,
                    version: version.clone(),
                },
            );
            return Some(version);
        }
        None
    }

    pub(crate) fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }
}

/// 沙箱可写工作目录（独立 HOME）：由构建变体配置根派生；正式构建为
/// `~/.csswitch/sandbox/home`，Acceptance 为 `~/.csswitch-acceptance/sandbox/home`。
pub(crate) fn sandbox_home() -> PathBuf {
    config::default_dir().join("sandbox").join("home")
}

/// CSSwitch 隔离 Science 的持久化 data-dir；其中的 Skill 内容由 Science 自身管理。
pub(crate) fn sandbox_data_dir() -> PathBuf {
    sandbox_home().join(".claude-science")
}

/// 端口变更是否需要拆掉现有链路（纯函数，P1-c）。代理/沙箱任一端口变了，正在跑的代理就绑在
/// 旧端口、正在跑的沙箱又把旧代理 URL 烘死了，二者与新配置不一致 → 拆掉逼下次「一键开始」按新端口重建。
pub(crate) fn settings_change_needs_teardown(
    old_proxy: u16,
    new_proxy: u16,
    old_sandbox: u16,
    new_sandbox: u16,
) -> bool {
    old_proxy != new_proxy || old_sandbox != new_sandbox
}

/// 从 `claude-science url` 的 stdout 里取**第一条**合法 http(s) URL。
pub(crate) fn first_http_url(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let t = line.trim();
        if t.starts_with("http://") || t.starts_with("https://") {
            let url = t.split_whitespace().next().unwrap_or(t);
            return Some(url.to_string());
        }
    }
    None
}

/// 以 no-follow 语义打开既有文件：unix 用 O_NOFOLLOW|O_CLOEXEC；Windows 用
/// FILE_FLAG_OPEN_REPARSE_POINT（不跟随 reparse point）。
fn open_no_follow(options: &mut OpenOptions, path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(crate::platform::no_follow_flags());
    }
    options.open(path)
}

/// create_new 且带 POSIX 私有 mode 的新文件：unix 真实设置 mode；Windows 无
/// POSIX mode，按平台语义只映射只读位（0o500 → 只读，0o600 → 可写）。
fn create_new_private_file(
    options: &mut OpenOptions,
    path: &Path,
    mode: u32,
) -> std::io::Result<File> {
    options.create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(crate::platform::no_follow_flags());
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    {
        // Windows 默认 ACL 已仅当前用户可访问；按语义映射只读位。
        crate::platform::set_path_mode(path, mode)?;
    }
    let _ = mode;
    Ok(file)
}

/// 修改时间稳定身份：unix 用 mtime/mtime_nsec；Windows 等价换算
/// `metadata.modified()`（同一文件内容不变则不变）。
fn modified_parts(metadata: &fs::Metadata) -> (i64, i64) {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| (duration.as_secs() as i64, duration.subsec_nanos() as i64))
        .unwrap_or((0, 0))
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        // Windows 的 Prefix(C:)/RootDir component 单独 stat 会失败，跳过
        // （它们不可能是符号链接）。
        if matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        ) {
            current.push(component.as_os_str());
            continue;
        }
        current.push(component.as_os_str());
        match current.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => return false,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    crate::platform::is_executable_file(path)
}

fn is_explicit_executable_file(path: &Path) -> bool {
    is_executable_file(path)
}

#[allow(dead_code)]
fn embedded_identity_metadata_matches(details: &str, identifier: &str, team_id: &str) -> bool {
    details
        .lines()
        .any(|line| line == format!("Identifier={identifier}"))
        && details
            .lines()
            .any(|line| line == format!("TeamIdentifier={team_id}"))
}

#[allow(dead_code)]
fn official_updated_embedded_identity_metadata_matches(details: &str) -> bool {
    OFFICIAL_UPDATED_SCIENCE_IDENTIFIERS
        .iter()
        .any(|identifier| {
            embedded_identity_metadata_matches(details, identifier, OFFICIAL_SCIENCE_TEAM_ID)
        })
}

#[allow(dead_code)]
fn official_updated_identity_metadata_matches(path: &Path) -> bool {
    #[cfg(windows)]
    {
        // Windows 没有 codesign：官方 updater 快照的信任路径在 Windows 上整体
        // 关闭（入口处短路返回 None），统一回退到已安装 App / 显式 SCIENCE_BIN。
        // 此处恒 false 保证任何残留调用不会把未经 codesign 校验的文件当作
        // 官方 updater 产物放行。
        let _ = path;
        false
    }
    #[cfg(unix)]
    {
        // Official updater executables observed in 0.1.25 use either
        // `com.anthropic.operon` or `com.anthropic.operon.cli`, including an updater
        // seeded byte-for-byte from the installed App.
        // Both currently fail strict cryptographic `codesign --verify`. Treat the
        // exact allowlisted fields only as format/identity guards; the local trust
        // boundary remains the fixed user-owned path plus SHA-256-bound runtime
        // identity below, not a claim of verified official provenance.
        let output = Command::new("/usr/bin/codesign")
            .args(["-d", "--verbose=4"])
            .arg(path)
            .stdout(Stdio::null())
            .output();
        let Ok(output) = output else {
            return false;
        };
        if !output.status.success() || output.stderr.len() > 64 * 1024 {
            return false;
        }
        let details = String::from_utf8_lossy(&output.stderr);
        official_updated_embedded_identity_metadata_matches(&details)
    }
}

/// 平台原生可执行格式校验：unix 校验 Mach-O magic；Windows 校验 PE 头。
#[allow(dead_code)]
fn file_is_native_binary(path: &Path) -> bool {
    #[cfg(unix)]
    {
        file_is_macho(path)
    }
    #[cfg(windows)]
    {
        file_is_pe(path)
    }
}

#[cfg(unix)]
fn file_is_macho(path: &Path) -> bool {
    let Ok(mut file) = open_no_follow(&mut OpenOptions::new().read(true), path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    )
}

/// PE 头校验：`MZ` DOS header + `e_lfanew`（DOS header 偏移 0x3C 的 u32）指向
/// `PE\0\0` 签名。
#[cfg(windows)]
#[allow(dead_code)]
fn file_is_pe(path: &Path) -> bool {
    let Ok(mut file) = open_no_follow(OpenOptions::new().read(true), path) else {
        return false;
    };
    let mut dos = [0u8; 64];
    if file.read_exact(&mut dos).is_err() {
        return false;
    }
    if &dos[0..2] != b"MZ" {
        return false;
    }
    let pe_offset = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as u64;
    // e_lfanew 必须落在 DOS header 之后、文件内合理范围内。
    if !(64..=16 * 1024 * 1024).contains(&pe_offset) {
        return false;
    }
    if file.seek(SeekFrom::Start(pe_offset)).is_err() {
        return false;
    }
    let mut signature = [0u8; 4];
    file.read_exact(&mut signature).is_ok() && &signature == b"PE\0\0"
}

#[allow(dead_code)]
fn official_updated_science_bin_for_home(
    home: &Path,
    verify_local_identity: bool,
) -> Option<PathBuf> {
    if !home.is_absolute() || crate::platform::canonicalize(home).ok().as_deref() != Some(home) {
        return None;
    }
    let science_dir = home.join(".claude-science");
    let bin_dir = science_dir.join("bin");
    let candidate = home.join(OFFICIAL_UPDATED_RUNTIME_RELATIVE);
    if !is_executable_file(&candidate) {
        return None;
    }
    for directory in [home, &science_dir, &bin_dir] {
        let metadata = directory.symlink_metadata().ok()?;
        if !metadata.file_type().is_dir()
            || !crate::platform::file_owner_is_current(&metadata)
            || crate::platform::metadata_mode(&metadata) & 0o022 != 0
        {
            return None;
        }
    }
    let metadata = candidate.symlink_metadata().ok()?;
    let mode = crate::platform::metadata_mode(&metadata);
    if !metadata.file_type().is_file()
        || !crate::platform::file_owner_is_current(&metadata)
        || mode & 0o111 == 0
        || mode & 0o022 != 0
    {
        return None;
    }
    if verify_local_identity
        && (!(MIN_SCIENCE_BINARY_SIZE..=MAX_SCIENCE_BINARY_SIZE).contains(&metadata.len())
            || !file_is_native_binary(&candidate)
            || !official_updated_identity_metadata_matches(&candidate))
    {
        return None;
    }
    Some(candidate)
}

fn fingerprint_sha256_hex(fingerprint: &ScienceExecutableFingerprint) -> String {
    fingerprint
        .sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[allow(dead_code)]
fn secure_runtime_snapshot_root(root: &Path) -> Result<PathBuf, String> {
    if !root.is_absolute() {
        return Err("Science runtime snapshot 目录不是绝对路径".into());
    }
    let mut cursor = Some(root);
    while let Some(path) = cursor {
        match path.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("Science runtime snapshot 目录路径包含 symlink，已拒绝使用".into())
            }
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err("Science runtime snapshot 目录路径包含非目录文件".into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("检查 Science runtime snapshot 目录失败：{error}")),
        }
        cursor = path.parent();
    }
    fs::create_dir_all(root)
        .map_err(|error| format!("创建 Science runtime snapshot 目录失败：{error}"))?;
    let canonical = crate::platform::canonicalize(root)
        .map_err(|error| format!("确认 Science runtime snapshot 目录失败：{error}"))?;
    if canonical != root {
        return Err("Science runtime snapshot 目录包含 symlink，已拒绝使用".into());
    }
    let metadata = root
        .symlink_metadata()
        .map_err(|error| format!("读取 Science runtime snapshot 目录失败：{error}"))?;
    if !metadata.file_type().is_dir() || !crate::platform::file_owner_is_current(&metadata) {
        return Err("Science runtime snapshot 目录属主或权限不安全".into());
    }
    crate::platform::set_path_mode(root, 0o700)
        .map_err(|error| format!("收紧 Science runtime snapshot 目录权限失败：{error}"))?;
    Ok(canonical)
}

#[allow(dead_code)]
fn official_updated_snapshot_from_process_paths(
    snapshot_root: &Path,
    process_paths: &[PathBuf],
    verify_local_identity: bool,
) -> Result<Option<PathBuf>, String> {
    let metadata = match snapshot_root.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取 Science runtime snapshot 目录失败：{error}")),
    };
    if !snapshot_root.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || !crate::platform::file_owner_is_current(&metadata)
        || crate::platform::metadata_mode(&metadata) & 0o022 != 0
        || crate::platform::canonicalize(snapshot_root).ok().as_deref() != Some(snapshot_root)
    {
        return Err("Science runtime snapshot 目录身份或权限不安全".into());
    }
    let mut matching = process_paths
        .iter()
        .filter(|path| path.parent() == Some(snapshot_root));
    let Some(path) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err("Science listener 映射到多个 runtime snapshot，已拒绝恢复".into());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Science runtime snapshot 文件名不可识别")?;
    let Some(expected_sha) = name.strip_prefix("claude-science-") else {
        return Err("Science listener executable 不是内容寻址 snapshot".into());
    };
    if expected_sha.len() != 64 || !expected_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Science runtime snapshot 文件名 SHA-256 非法".into());
    }
    let metadata = path
        .symlink_metadata()
        .map_err(|error| format!("读取 Science runtime snapshot 文件失败：{error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || !crate::platform::file_owner_is_current(&metadata)
        || crate::platform::metadata_mode(&metadata) & 0o111 == 0
        || crate::platform::metadata_mode(&metadata) & 0o022 != 0
        || !(MIN_SCIENCE_BINARY_SIZE..=MAX_SCIENCE_BINARY_SIZE).contains(&metadata.len())
        || crate::platform::canonicalize(path).ok().as_deref() != Some(path.as_path())
    {
        return Err("Science runtime snapshot 文件身份或权限不安全".into());
    }
    let fingerprint =
        science_executable_fingerprint(path).ok_or("Science runtime snapshot 内容无法确认")?;
    if fingerprint_sha256_hex(&fingerprint) != expected_sha.to_ascii_lowercase() {
        return Err("Science runtime snapshot 文件名与内容 SHA-256 不一致".into());
    }
    if verify_local_identity
        && (!file_is_native_binary(path) || !official_updated_identity_metadata_matches(path))
    {
        return Err("Science runtime snapshot 未通过 Mach-O/embedded metadata 复核".into());
    }
    Ok(Some(path.clone()))
}

fn official_updated_snapshot_for_listener(
    port: u16,
    snapshot_root: &Path,
    verify_local_identity: bool,
) -> Result<Option<PathBuf>, String> {
    #[cfg(windows)]
    {
        // Windows 没有 codesign：与 official_updated_science_bin 一致，updater
        // snapshot 的监听恢复信任路径整体关闭，不做快照恢复。
        let _ = (port, snapshot_root, verify_local_identity);
        Ok(None)
    }
    #[cfg(unix)]
    {
        let Some(pid) = unique_listener_pid(port) else {
            return Ok(None);
        };
        let Some(process_paths) = process_text_paths(pid) else {
            return Ok(None);
        };
        official_updated_snapshot_from_process_paths(
            snapshot_root,
            &process_paths,
            verify_local_identity,
        )
    }
}

#[allow(dead_code)]
fn official_updated_snapshot_for_home(
    home: &Path,
    snapshot_root: &Path,
    verify_local_identity: bool,
) -> Result<Option<PathBuf>, String> {
    let candidate = home.join(OFFICIAL_UPDATED_RUNTIME_RELATIVE);
    if !candidate.exists() {
        return Ok(None);
    }
    let candidate = official_updated_science_bin_for_home(home, false).ok_or(
        "检测到 updater Science executable，但固定路径、属主或权限校验未通过；已拒绝静默回退旧 App",
    )?;
    let mut source = open_no_follow(OpenOptions::new().read(true), &candidate)
        .map_err(|error| format!("打开 updater Science executable 失败：{error}"))?;
    let source_before = source
        .metadata()
        .map_err(|error| format!("读取 updater Science executable 失败：{error}"))?;
    let source_before_identity = crate::platform::identity_of_file(&source)
        .map_err(|error| format!("读取 updater Science executable 失败：{error}"))?;
    if !source_before.file_type().is_file()
        || !(MIN_SCIENCE_BINARY_SIZE..=MAX_SCIENCE_BINARY_SIZE).contains(&source_before.len())
    {
        return Err("updater Science executable 大小或文件类型不安全；已拒绝静默回退旧 App".into());
    }

    let snapshot_root = secure_runtime_snapshot_root(snapshot_root)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "系统时间异常，无法创建 Science runtime snapshot")?
        .as_nanos();
    let temporary = snapshot_root.join(format!(
        ".claude-science-{}-{nonce}.tmp",
        std::process::id()
    ));
    let result = (|| -> Result<PathBuf, String> {
        let mut output = create_new_private_file(
            OpenOptions::new().write(true),
            &temporary,
            0o500,
        )
        .map_err(|error| format!("创建 Science runtime snapshot 临时文件失败：{error}"))?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = source
                .read(&mut buffer)
                .map_err(|error| format!("读取 updater Science executable 失败：{error}"))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            output
                .write_all(&buffer[..count])
                .map_err(|error| format!("写入 Science runtime snapshot 失败：{error}"))?;
        }
        output
            .sync_all()
            .map_err(|error| format!("持久化 Science runtime snapshot 失败：{error}"))?;
        drop(output);

        let source_after = source
            .metadata()
            .map_err(|error| format!("复核 updater Science executable 失败：{error}"))?;
        let source_after_identity = crate::platform::identity_of_file(&source)
            .map_err(|error| format!("复核 updater Science executable 失败：{error}"))?;
        let current_identity = crate::platform::identity_of_path(&candidate)
            .map_err(|error| format!("复核 updater Science executable 路径失败：{error}"))?;
        if source_before_identity.dev != source_after_identity.dev
            || source_before_identity.ino != source_after_identity.ino
            || source_before.len() != source_after.len()
            || modified_parts(&source_before) != modified_parts(&source_after)
            || source_before_identity.mode != source_after_identity.mode
            || source_after_identity.dev != current_identity.dev
            || source_after_identity.ino != current_identity.ino
            || official_updated_science_bin_for_home(home, false).as_deref()
                != Some(candidate.as_path())
        {
            return Err("updater Science executable 在快照期间发生变化；已拒绝启动，请重试".into());
        }
        crate::platform::set_path_mode(&temporary, 0o500)
            .map_err(|error| format!("收紧 Science runtime snapshot 权限失败：{error}"))?;
        if verify_local_identity
            && (!file_is_native_binary(&temporary)
                || !official_updated_identity_metadata_matches(&temporary))
        {
            return Err(
                "updater Science executable 未通过 Mach-O/embedded metadata 本地校验；已拒绝静默回退旧 App"
                    .into(),
            );
        }

        let sha256: [u8; 32] = digest.finalize().into();
        let name: String = sha256.iter().map(|byte| format!("{byte:02x}")).collect();
        let snapshot = snapshot_root.join(format!("claude-science-{name}"));
        match fs::hard_link(&temporary, &snapshot) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!("提交 Science runtime snapshot 失败：{error}"));
            }
        }
        let fingerprint = science_executable_fingerprint(&snapshot)
            .ok_or("Science runtime snapshot 无法重新确认")?;
        if fingerprint.sha256 != sha256
            || fingerprint.size != source_after.len()
            || fingerprint.mode & 0o022 != 0
        {
            return Err("Science runtime snapshot 内容或权限与已验证候选不一致".into());
        }
        Ok(snapshot)
    })();
    let _ = fs::remove_file(&temporary);
    result.map(Some)
}

fn official_updated_science_bin() -> Result<Option<PathBuf>, String> {
    #[cfg(windows)]
    {
        // Windows 没有 codesign：官方 updater 快照信任路径整体关闭，
        // 回退到已安装 App / 显式 SCIENCE_BIN 路径（下载引导不变）。
        Ok(None)
    }
    #[cfg(unix)]
    {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(None);
        };
        let snapshot_root = config::default_dir().join(OFFICIAL_UPDATED_SNAPSHOT_DIR);
        official_updated_snapshot_for_home(&home, &snapshot_root, true)
    }
}

fn science_executable_fingerprint(path: &Path) -> Option<ScienceExecutableFingerprint> {
    if !is_executable_file(path) {
        return None;
    }
    let mut file = open_no_follow(OpenOptions::new().read(true), path).ok()?;
    let before = file.metadata().ok()?;
    if !before.file_type().is_file() {
        return None;
    }
    let before_identity = crate::platform::identity_of_file(&file).ok()?;
    #[cfg(unix)]
    if before_identity.mode & 0o111 == 0 {
        return None;
    }
    // Windows 无 POSIX exec 位：可执行性已由 is_executable_file 的扩展名校验保证。
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().ok()?;
    let after_identity = crate::platform::identity_of_file(&file).ok()?;
    let path_identity = crate::platform::identity_of_path(path).ok()?;
    if path_identity.dev != after_identity.dev
        || path_identity.ino != after_identity.ino
        || before_identity.dev != after_identity.dev
        || before_identity.ino != after_identity.ino
        || before.len() != after.len()
        || modified_parts(&before) != modified_parts(&after)
        || before_identity.mode != after_identity.mode
    {
        return None;
    }
    Some(ScienceExecutableFingerprint {
        device: after_identity.dev,
        inode: after_identity.ino,
        size: after.len(),
        modified_seconds: modified_parts(&after).0,
        modified_nanoseconds: modified_parts(&after).1,
        mode: after_identity.mode,
        sha256: digest.finalize().into(),
    })
}

fn cached_science_bin(data_dir: &Path) -> PathBuf {
    data_dir.join("bin").join("claude-science")
}

fn create_science_version_output() -> Option<(fs::File, PathBuf)> {
    for _ in 0..8 {
        let nonce = SCIENCE_VERSION_OUTPUT_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            ".csswitch-science-version-{}-{nonce}",
            std::process::id()
        ));
        match create_new_private_file(OpenOptions::new().read(true).write(true), &path, 0o600)
        {
            Ok(file) => return Some((file, path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

fn anchored_child_exited(pid: u32) -> Result<bool, i32> {
    // unix：waitid(WEXITED|WNOHANG|WNOWAIT) 观察但不收割，pid 继续锚定进程组；
    // Windows：OpenProcess + WaitForSingleObject(0) 非阻塞探测。
    crate::platform::process_has_exited(pid).map_err(|error| error.raw_os_error().unwrap_or(0))
}

fn kill_anchored_science_version_group(pid: u32, leader_exited: bool) -> bool {
    #[cfg(unix)]
    {
        let Ok(pgid) = i32::try_from(pid) else {
            return false;
        };
        // SAFETY: waitid(WNOWAIT) or a still-running direct child keeps pid/pgid
        // reserved for the process group created by configure_spawn.
        if unsafe { libc::kill(-pgid, libc::SIGKILL) } == 0 {
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::ESRCH) {
            return true;
        }
        // Darwin returns EPERM, rather than ESRCH, when the anchored process group
        // contains only the WNOWAIT zombie leader. A same-uid executable descendant
        // would make killpg succeed, so accept EPERM only after waitid confirmed the
        // leader's exit; never accept it on the timeout/live-leader path.
        cfg!(target_os = "macos") && leader_exited && errno == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        // Windows 无进程组：等价语义是终止整棵进程树；leader 已退出时树根可能
        // 已消失，kill_tree 内部有单进程兜底。
        let _ = leader_exited;
        crate::platform::kill_tree(pid).is_ok()
    }
}

fn wait_science_version_probe(mut child: Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match anchored_child_exited(child.id()) {
            Ok(true) => {
                let group_stopped = kill_anchored_science_version_group(child.id(), true);
                let status = child.wait().ok()?;
                return group_stopped.then_some(status);
            }
            Ok(false) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(false) => {
                if !kill_anchored_science_version_group(child.id(), false) {
                    let _ = child.kill();
                }
                let cleanup_deadline = Instant::now() + Duration::from_secs(1);
                while Instant::now() < cleanup_deadline {
                    match anchored_child_exited(child.id()) {
                        Ok(true) => {
                            let _ = child.wait();
                            return None;
                        }
                        Ok(false) => std::thread::sleep(Duration::from_millis(20)),
                        Err(_) => break,
                    }
                }
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return None;
            }
            Err(_) => return None,
        }
    }
}

fn safe_science_version_with_timeout(path: &Path, timeout: Duration) -> Option<String> {
    let (mut output_file, output_path) = create_science_version_output()?;
    let result = (|| {
        let stdout = output_file.try_clone().ok()?;
        let mut command = Command::new(path);
        command
            .arg("--version")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::null());
        crate::platform::env_isolated_home(&mut command, &sandbox_home());
        // unix：独立进程组（超时可整组回收）；Windows：CREATE_NO_WINDOW 防闪黑窗。
        crate::platform::configure_spawn(&mut command);
        #[cfg(unix)]
        {
            // SAFETY: setrlimit is async-signal-safe and the closure touches no
            // shared Rust state. The hard limit is inherited by descendants and
            // prevents a malformed version command from filling TMPDIR.
            use std::os::unix::process::CommandExt;
            unsafe {
                command.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 1025 as libc::rlim_t,
                        rlim_max: 1025 as libc::rlim_t,
                    };
                    if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
        }
        #[cfg(windows)]
        // Windows 无 setrlimit：版本输出已有读侧 take(1025) 硬上限，超量直接判废。
        {
            let _ = &mut command;
        }
        let child = command.spawn().ok()?;
        let status = wait_science_version_probe(child, timeout)?;
        if !status.success() {
            return None;
        }
        output_file.seek(SeekFrom::Start(0)).ok()?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut output_file)
            .take(1025)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 1024 {
            return None;
        }
        let value = String::from_utf8(bytes).ok()?;
        let value = value.lines().next()?.trim();
        if value.is_empty()
            || value.len() > 160
            || !value
                .bytes()
                .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte))
        {
            return None;
        }
        Some(value.to_string())
    })();
    drop(output_file);
    let _ = fs::remove_file(output_path);
    result
}

fn safe_science_version(path: &Path) -> Option<String> {
    safe_science_version_with_timeout(path, SCIENCE_VERSION_TIMEOUT)
}

fn runtime_identity(
    path: PathBuf,
    source: ScienceRuntimeSource,
    version_cache: &ScienceVersionCache,
) -> Option<ScienceRuntimeIdentity> {
    // Windows canonicalize 产生 \? 前缀；入口统一规范化（剥前缀），
    // 使身份路径与后续 canonical 比较同型。
    let path = crate::platform::canonicalize(&path).ok()?;
    for _ in 0..2 {
        let before = science_executable_fingerprint(&path)?;
        let version = version_cache.version(&path)?;
        let after = science_executable_fingerprint(&path)?;
        if before == after {
            return Some(ScienceRuntimeIdentity {
                path,
                source,
                version: Some(version),
                fingerprint: after,
            });
        }
        let _ = version_cache.force_refresh(&path);
    }
    None
}

pub(crate) fn runtime_identity_is_current(runtime: &ScienceRuntimeIdentity) -> bool {
    runtime.is_current()
}

fn explicit_science_bin() -> Result<Option<PathBuf>, String> {
    let Some(path) = std::env::var_os("SCIENCE_BIN").map(PathBuf::from) else {
        return Ok(None);
    };
    if !is_explicit_executable_file(&path) {
        return Err("显式 SCIENCE_BIN 不是安全的绝对可执行文件；已拒绝回退".into());
    }
    Ok(Some(path))
}

/// Windows 上已安装 Claude Science CLI 的候选路径（按探测顺序），每个候选
/// 都必须存在且经 `platform::is_executable_file` 校验。
#[cfg(windows)]
fn windows_installed_science_bin_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let local = PathBuf::from(local);
        // 官方 Windows 安装目录是不带空格的 ClaudeScience；带空格变体仅作兼容。
        candidates.push(
            local
                .join("Programs")
                .join("ClaudeScience")
                .join("claude-science.exe"),
        );
        candidates.push(
            local
                .join("Programs")
                .join("Claude Science")
                .join("claude-science.exe"),
        );
        candidates.push(local.join("AnthropicClaude").join("claude-science.exe"));
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        let program_files = PathBuf::from(program_files);
        candidates.push(
            program_files
                .join("ClaudeScience")
                .join("claude-science.exe"),
        );
        candidates.push(
            program_files
                .join("Claude Science")
                .join("claude-science.exe"),
        );
    }
    candidates
        .into_iter()
        .filter(|candidate| crate::platform::is_executable_file(candidate))
        .collect()
}

/// Windows 已安装 Science CLI：按候选顺序取第一个通过既有 `--version` 探测
/// 校验的候选；全部失败 → None（上层沿用原有"未安装"错误与下载页 URL）。
#[cfg(windows)]
fn windows_installed_science_bin(version_cache: &ScienceVersionCache) -> Option<PathBuf> {
    windows_installed_science_bin_candidates()
        .into_iter()
        .find(|candidate| version_cache.version(candidate).is_some())
}

/// 已安装 App 内置 Science CLI 路径：macOS 为固定 `.app` 内路径；Windows 为
/// 候选探测结果。找不到时返回 `SCIENCE_BIN` 占位路径——它不是 Windows 可执行
/// 文件，必然不通过校验，上层照常报告"未安装"并给出下载页 URL。
fn installed_app_science_bin(version_cache: &ScienceVersionCache) -> PathBuf {
    #[cfg(windows)]
    {
        windows_installed_science_bin(version_cache).unwrap_or_else(|| PathBuf::from(SCIENCE_BIN))
    }
    #[cfg(not(windows))]
    {
        let _ = version_cache;
        PathBuf::from(SCIENCE_BIN)
    }
}

#[cfg(test)]
// mac 侧 runtime 预检/状态机专用函数（脚本预检、status 分类、managed-launch
// 读取）；Windows 入口走已安装探测与 health 路径，保留以维持两端实现对照。
#[allow(dead_code)]
fn science_runtime_preflight_for_paths(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    app_bin: &Path,
) -> Result<Value, String> {
    science_runtime_preflight_for_paths_cached(
        data_dir,
        explicit_bin,
        None,
        app_bin,
        &ScienceVersionCache::default(),
    )
}

#[cfg(test)]
#[allow(dead_code)]
fn science_runtime_preflight_for_paths_with_updated(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    official_updated_bin: Option<&Path>,
    app_bin: &Path,
) -> Result<Value, String> {
    science_runtime_preflight_for_paths_cached(
        data_dir,
        explicit_bin,
        official_updated_bin,
        app_bin,
        &ScienceVersionCache::default(),
    )
}

fn science_runtime_preflight_for_paths_cached(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    official_updated_bin: Option<&Path>,
    app_bin: &Path,
    version_cache: &ScienceVersionCache,
) -> Result<Value, String> {
    if let Some(bin) = explicit_bin {
        if !is_explicit_executable_file(bin) {
            return Err("显式 SCIENCE_BIN 不是安全的绝对可执行文件；已拒绝回退".into());
        }
        let runtime = runtime_identity(
            bin.to_path_buf(),
            ScienceRuntimeSource::Explicit,
            version_cache,
        )
        .ok_or("显式 SCIENCE_BIN 未通过版本预检；已拒绝回退")?;
        return Ok(json!({
            "status": "installed_ready",
            "selected_source": runtime.source.code(),
            "selected_version": runtime.version,
            "cached_version": Value::Null,
            "download_url": SCIENCE_DOWNLOAD_URL,
        }));
    }
    if let Some(bin) = official_updated_bin {
        let runtime = runtime_identity(
            bin.to_path_buf(),
            ScienceRuntimeSource::OfficialUpdated,
            version_cache,
        )
        .ok_or("updater Science snapshot 未通过版本预检；已拒绝回退旧 App")?;
        return Ok(json!({
            "status": "installed_ready",
            "selected_source": runtime.source.code(),
            "selected_version": runtime.version,
            "cached_version": Value::Null,
            "download_url": SCIENCE_DOWNLOAD_URL,
        }));
    }
    if let Some(runtime) = runtime_identity(
        app_bin.to_path_buf(),
        ScienceRuntimeSource::InstalledApp,
        version_cache,
    ) {
        return Ok(json!({
            "status": "installed_ready",
            "selected_source": runtime.source.code(),
            "selected_version": runtime.version,
            "cached_version": Value::Null,
            "download_url": SCIENCE_DOWNLOAD_URL,
        }));
    }
    let cached = cached_science_bin(data_dir);
    let cached_version = version_cache.version(&cached);
    if let Some(version) = cached_version {
        return Ok(json!({
            "status": "cached_choice_required",
            "selected_source": Value::Null,
            "selected_version": Value::Null,
            "cached_version": version,
            "download_url": SCIENCE_DOWNLOAD_URL,
        }));
    }
    Ok(json!({
        "status": "missing",
        "selected_source": Value::Null,
        "selected_version": Value::Null,
        "cached_version": Value::Null,
        "download_url": SCIENCE_DOWNLOAD_URL,
    }))
}

pub(crate) fn science_runtime_preflight(
    version_cache: &ScienceVersionCache,
    _confirmed_stopped: Option<&ScienceRuntimeIdentity>,
) -> Result<Value, String> {
    if let Ok(cfg) = config::load_from(&config::default_dir()) {
        let (state, runtime) = probe_sandbox_runtime_cached(cfg.sandbox_port, version_cache)?;
        if state == SandboxScienceState::RunningHealthy {
            let runtime = runtime.ok_or("Science 状态为运行中，但无法确认其 binary 身份")?;
            return Ok(json!({
                "status": "installed_ready",
                "selected_source": runtime.source.code(),
                "selected_version": runtime.version,
                "cached_version": Value::Null,
                "download_url": SCIENCE_DOWNLOAD_URL,
            }));
        }
    }
    let data_dir = sandbox_data_dir();
    let explicit = explicit_science_bin()?;
    let official_updated = official_updated_science_bin()?;
    let app_bin = installed_app_science_bin(version_cache);
    science_runtime_preflight_for_paths_cached(
        &data_dir,
        explicit.as_deref(),
        official_updated.as_deref(),
        &app_bin,
        version_cache,
    )
}

#[cfg(test)]
fn select_science_runtime_for_paths(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    app_bin: &Path,
    choice: Option<&str>,
) -> Result<ScienceRuntimeIdentity, String> {
    select_science_runtime_for_paths_cached(
        data_dir,
        explicit_bin,
        None,
        app_bin,
        choice,
        &ScienceVersionCache::default(),
    )
}

#[cfg(test)]
#[allow(dead_code)]
fn select_science_runtime_for_paths_with_updated(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    official_updated_bin: Option<&Path>,
    app_bin: &Path,
    choice: Option<&str>,
) -> Result<ScienceRuntimeIdentity, String> {
    select_science_runtime_for_paths_cached(
        data_dir,
        explicit_bin,
        official_updated_bin,
        app_bin,
        choice,
        &ScienceVersionCache::default(),
    )
}

fn select_science_runtime_for_paths_cached(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    official_updated_bin: Option<&Path>,
    app_bin: &Path,
    choice: Option<&str>,
    version_cache: &ScienceVersionCache,
) -> Result<ScienceRuntimeIdentity, String> {
    if let Some(bin) = explicit_bin {
        if !is_explicit_executable_file(bin) {
            return Err("显式 SCIENCE_BIN 不是安全的绝对可执行文件；已拒绝回退".into());
        }
        return runtime_identity(
            bin.to_path_buf(),
            ScienceRuntimeSource::Explicit,
            version_cache,
        )
        .ok_or_else(|| "显式 SCIENCE_BIN 未通过版本预检；已拒绝回退".to_string());
    }
    if let Some(bin) = official_updated_bin {
        return runtime_identity(
            bin.to_path_buf(),
            ScienceRuntimeSource::OfficialUpdated,
            version_cache,
        )
        .ok_or_else(|| "updater Science snapshot 未通过版本预检；已拒绝回退旧 App".to_string());
    }
    if let Some(runtime) = runtime_identity(
        app_bin.to_path_buf(),
        ScienceRuntimeSource::InstalledApp,
        version_cache,
    ) {
        return Ok(runtime);
    }
    let cached = cached_science_bin(data_dir);
    let cached_version = version_cache.version(&cached);
    if choice == Some(CACHED_ONCE_CHOICE) {
        let _ = cached_version
            .ok_or("缓存 Science 版本无法确认；请安装或更新 Claude Science 后再试")?;
        return runtime_identity(cached, ScienceRuntimeSource::CachedOnce, version_cache)
            .ok_or("缓存 Science 文件在版本确认期间发生变化；已拒绝启动".into());
    }
    if cached_version.is_some() {
        return Err("SCIENCE_RUNTIME_CHOICE_REQUIRED：请明确选择仅本次使用缓存版本，或安装/更新 Claude Science".into());
    }
    Err("找不到可用的 Claude Science App；请先安装或更新 Claude Science".into())
}

pub(crate) fn select_science_runtime_cached(
    choice: Option<&str>,
    version_cache: &ScienceVersionCache,
) -> Result<ScienceRuntimeIdentity, String> {
    let data_dir = sandbox_data_dir();
    let explicit = explicit_science_bin()?;
    let official_updated = official_updated_science_bin()?;
    let app_bin = installed_app_science_bin(version_cache);
    select_science_runtime_for_paths_cached(
        &data_dir,
        explicit.as_deref(),
        official_updated.as_deref(),
        &app_bin,
        choice,
        version_cache,
    )
}

fn runtime_probe_candidates(
    port: u16,
    version_cache: &ScienceVersionCache,
) -> Result<Vec<ScienceRuntimeIdentity>, String> {
    if let Some(explicit) = explicit_science_bin()? {
        return Ok(
            runtime_identity(explicit, ScienceRuntimeSource::Explicit, version_cache)
                .into_iter()
                .collect(),
        );
    }
    let mut candidates = Vec::new();
    let snapshot_root = config::default_dir().join(OFFICIAL_UPDATED_SNAPSHOT_DIR);
    if let Some(snapshot) = official_updated_snapshot_for_listener(port, &snapshot_root, true)? {
        if let Some(runtime) = runtime_identity(
            snapshot,
            ScienceRuntimeSource::OfficialUpdated,
            version_cache,
        ) {
            candidates.push(runtime);
        }
    }
    let app = installed_app_science_bin(version_cache);
    if let Some(app) = runtime_identity(app, ScienceRuntimeSource::InstalledApp, version_cache) {
        candidates.push(app);
    }
    let cached = cached_science_bin(&sandbox_data_dir());
    if let Some(cached) = runtime_identity(cached, ScienceRuntimeSource::CachedOnce, version_cache)
    {
        candidates.push(cached);
    }
    Ok(candidates)
}

#[cfg(test)]
#[allow(dead_code)]
fn science_status_running(out: &Output) -> bool {
    out.status.success() && science_status_value(out) == Some(true)
}

fn science_status_value(out: &Output) -> Option<bool> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    for (idx, ch) in stdout.char_indices() {
        if ch != '{' {
            continue;
        }
        let mut stream =
            serde_json::Deserializer::from_str(&stdout[idx..]).into_iter::<serde_json::Value>();
        if let Some(Ok(value)) = stream.next() {
            if let Some(running) = value.get("running").and_then(|running| running.as_bool()) {
                return Some(running);
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(dead_code)]
fn trusted_science_status(out: &Output) -> Option<bool> {
    match science_status_value(out) {
        Some(false) => Some(false),
        Some(true) if out.status.success() => Some(true),
        _ => None,
    }
}

fn runtime_status_value(out: &Output) -> Option<bool> {
    match science_status_value(out) {
        Some(false) => Some(false),
        Some(true) if out.status.success() => Some(true),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SandboxScienceState {
    RunningHealthy,
    Stopped,
    Unknown,
}

#[cfg(test)]
#[allow(dead_code)]
fn classify_sandbox_state(
    status: Option<bool>,
    health_ready: bool,
    port_accepts_tcp: bool,
) -> SandboxScienceState {
    match status {
        Some(true) if health_ready => SandboxScienceState::RunningHealthy,
        Some(false) if !port_accepts_tcp => SandboxScienceState::Stopped,
        _ => SandboxScienceState::Unknown,
    }
}

fn classify_known_runtime_state(
    status: Option<bool>,
    health_ready: bool,
    port_accepts_tcp: bool,
    listener_matches_runtime: bool,
) -> SandboxScienceState {
    match status {
        Some(true) if health_ready && listener_matches_runtime => {
            SandboxScienceState::RunningHealthy
        }
        Some(false) if !port_accepts_tcp => SandboxScienceState::Stopped,
        _ => SandboxScienceState::Unknown,
    }
}

fn loopback_port_accepts_tcp(port: u16) -> bool {
    #[cfg(test)]
    if std::env::var_os("CSSWITCH_TEST_PORT_OBSERVATION_TARGET")
        .and_then(|value| value.to_string_lossy().parse::<u16>().ok())
        == Some(port)
    {
        if let Some(sequence_dir) = std::env::var_os("CSSWITCH_TEST_PORT_OBSERVATION_SEQUENCE_DIR")
            .map(PathBuf::from)
            .filter(|path| path.join("armed").is_file())
        {
            let false_marker = sequence_dir.join("observed-false");
            if OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&false_marker)
                .is_ok()
            {
                return false;
            }
            let replaced_marker = sequence_dir.join("receipt-replaced");
            if !replaced_marker.is_file() {
                let replacement =
                    std::env::var_os("CSSWITCH_TEST_PORT_OBSERVATION_REPLACEMENT_RECEIPT")
                        .map(PathBuf::from);
                let target =
                    std::env::var_os("CSSWITCH_TEST_PORT_OBSERVATION_RECEIPT").map(PathBuf::from);
                let replacement_result = (|| -> std::io::Result<()> {
                    let replacement = replacement.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "replacement receipt path is missing",
                        )
                    })?;
                    let target = target.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "managed receipt path is missing",
                        )
                    })?;
                    let bytes = fs::read(replacement)?;
                    let temp = sequence_dir.join("concurrent-receipt.tmp");
                    let mut file = create_new_private_file(
                        OpenOptions::new().write(true),
                        &temp,
                        0o600,
                    )?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    fs::rename(&temp, &target)?;
                    File::open(
                        target
                            .parent()
                            .ok_or_else(|| std::io::Error::other("receipt parent is missing"))?,
                    )?
                    .sync_all()?;
                    fs::write(&replaced_marker, b"replaced")
                })();
                if replacement_result.is_err() {
                    let _ = fs::write(sequence_dir.join("receipt-replacement-failed"), b"failed");
                }
            }
            let _ = fs::write(sequence_dir.join("observed-true"), b"true");
            return true;
        }
    }
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_ok()
}

#[allow(dead_code)]
fn parse_unique_listener_pid(stdout: &str) -> Option<u32> {
    let mut pids = stdout
        .lines()
        .map(str::trim)
        .filter(|pid| !pid.is_empty())
        .map(str::parse::<u32>);
    let pid = pids.next()?.ok()?;
    if pid <= 1 || pids.any(|other| other.ok() != Some(pid)) {
        return None;
    }
    Some(pid)
}

fn unique_listener_pid(port: u16) -> Option<u32> {
    // unix 走 lsof；Windows 走 netstat -ano（platform::listening_pids）。
    let pids = crate::platform::listening_pids(port).ok()?;
    let pid = pids.first().copied()?;
    if pid <= 1 || pids.iter().any(|other| *other != pid) {
        return None;
    }
    Some(pid)
}

fn managed_launch_path() -> PathBuf {
    config::default_dir().join(MANAGED_LAUNCH_FILE)
}

fn process_start_identity(pid: u32) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    #[cfg(test)]
    if std::env::var_os("CSSWITCH_TEST_PROCESS_START_DRIFT_PID")
        .and_then(|value| value.to_string_lossy().parse::<u32>().ok())
        == Some(pid)
        && std::env::var_os("CSSWITCH_TEST_PROCESS_START_DRIFT_MARKER")
            .is_some_and(|path| PathBuf::from(path).is_file())
    {
        return Some("Mon Jan  1 00:00:00 2001".into());
    }
    // unix 取 ps lstart；Windows 取 GetProcessTimes filetime 串。
    let identity = crate::platform::process_start_identity(pid)?;
    if identity.is_empty()
        || identity.len() > 128
        || !identity.is_ascii()
        || identity.lines().count() != 1
    {
        return None;
    }
    Some(identity)
}

fn data_dir_identity() -> Option<(PathBuf, u64, u64)> {
    let data_dir = crate::platform::canonicalize(&sandbox_data_dir()).ok()?;
    let metadata = data_dir.symlink_metadata().ok()?;
    let identity = crate::platform::identity_of_path(&data_dir).ok()?;
    if !metadata.file_type().is_dir()
        || !crate::platform::file_owner_is_current(&metadata)
        || crate::platform::metadata_mode(&metadata) & 0o022 != 0
    {
        return None;
    }
    Some((data_dir, identity.dev, identity.ino))
}

#[cfg(test)]
pub(crate) fn test_process_start_identity_for_pid(pid: u32) -> Option<String> {
    process_start_identity(pid)
}

#[cfg(test)]
pub(crate) fn test_unique_listener_pid(port: u16) -> Option<u32> {
    unique_listener_pid(port)
}

fn managed_launch_record_for(
    port: u16,
    listener_pid: u32,
    runtime: &ScienceRuntimeIdentity,
) -> Option<ScienceManagedLaunchRecord> {
    if !runtime.is_current() {
        return None;
    }
    let runtime_path = crate::platform::canonicalize(&runtime.path).ok()?;
    if runtime_path != runtime.path {
        return None;
    }
    let process_start = process_start_identity(listener_pid)?;
    let (data_dir, data_dir_device, data_dir_inode) = data_dir_identity()?;
    let fingerprint = &runtime.fingerprint;
    Some(ScienceManagedLaunchRecord {
        schema_version: 1,
        launch_id: config::new_id(),
        port,
        listener_pid,
        process_start,
        runtime_path,
        runtime_device: fingerprint.device,
        runtime_inode: fingerprint.inode,
        runtime_size: fingerprint.size,
        runtime_modified_seconds: fingerprint.modified_seconds,
        runtime_modified_nanoseconds: fingerprint.modified_nanoseconds,
        runtime_mode: fingerprint.mode,
        runtime_sha256: fingerprint_sha256_hex(fingerprint),
        data_dir,
        data_dir_device,
        data_dir_inode,
    })
}

fn record_matches_runtime(
    record: &ScienceManagedLaunchRecord,
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    let Some((data_dir, data_dir_device, data_dir_inode)) = data_dir_identity() else {
        return false;
    };
    let fingerprint = &runtime.fingerprint;
    record.schema_version == 1
        && record.launch_id.len() >= 16
        && record.launch_id.len() <= 128
        && record
            .launch_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && record.port == port
        && record.listener_pid > 1
        && record.runtime_path == runtime.path
        && record.runtime_device == fingerprint.device
        && record.runtime_inode == fingerprint.inode
        && record.runtime_size == fingerprint.size
        && record.runtime_modified_seconds == fingerprint.modified_seconds
        && record.runtime_modified_nanoseconds == fingerprint.modified_nanoseconds
        && record.runtime_mode == fingerprint.mode
        && record.runtime_sha256 == fingerprint_sha256_hex(fingerprint)
        && record.data_dir == data_dir
        && record.data_dir_device == data_dir_device
        && record.data_dir_inode == data_dir_inode
}

fn managed_launch_file_identity(
    identity: crate::platform::FileIdentity,
    metadata: &fs::Metadata,
) -> ManagedLaunchFileIdentity {
    let (modified_seconds, modified_nanoseconds) = modified_parts(metadata);
    ManagedLaunchFileIdentity {
        device: identity.dev,
        inode: identity.ino,
        size: metadata.len(),
        modified_seconds,
        modified_nanoseconds,
        mode: identity.mode,
        owner_is_current: crate::platform::file_owner_is_current(metadata),
    }
}

fn private_managed_launch_file(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && crate::platform::file_owner_is_current(metadata)
        && crate::platform::metadata_mode(metadata) & 0o077 == 0
        && metadata.len() > 0
        && metadata.len() <= MAX_MANAGED_LAUNCH_BYTES
}

fn read_managed_launch_snapshot_at(
    path: &Path,
) -> Option<(ScienceManagedLaunchRecord, ManagedLaunchFileIdentity)> {
    let parent = path.parent()?;
    let parent_metadata = parent.symlink_metadata().ok()?;
    if !parent_metadata.file_type().is_dir()
        || !crate::platform::file_owner_is_current(&parent_metadata)
        || crate::platform::metadata_mode(&parent_metadata) & 0o022 != 0
    {
        return None;
    }
    let metadata = path.symlink_metadata().ok()?;
    if !private_managed_launch_file(&metadata) {
        return None;
    }
    let path_identity = crate::platform::identity_of_path(path).ok()?;
    let expected_file = managed_launch_file_identity(path_identity, &metadata);
    let mut file = open_no_follow(OpenOptions::new().read(true), path).ok()?;
    let after = file.metadata().ok()?;
    let after_identity = crate::platform::identity_of_file(&file).ok()?;
    if !private_managed_launch_file(&after)
        || managed_launch_file_identity(after_identity, &after) != expected_file
    {
        return None;
    }
    #[cfg(test)]
    if let Some(barrier_dir) = std::env::var_os("CSSWITCH_TEST_MANAGED_LAUNCH_READ_BARRIER") {
        let barrier_dir = PathBuf::from(barrier_dir);
        fs::write(barrier_dir.join("ready"), b"ready").ok()?;
        let mut released = false;
        for _ in 0..500 {
            if barrier_dir.join("continue").is_file() {
                released = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !released {
            return None;
        }
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected_file.size.min(MAX_MANAGED_LAUNCH_BYTES + 1)).ok()?,
    );
    (&mut file)
        .take(MAX_MANAGED_LAUNCH_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    #[cfg(test)]
    MANAGED_LAUNCH_LAST_READ_BYTES.store(bytes.len() as u64, Ordering::SeqCst);
    let final_metadata = file.metadata().ok()?;
    let final_identity = crate::platform::identity_of_file(&file).ok()?;
    if !private_managed_launch_file(&final_metadata)
        || managed_launch_file_identity(final_identity, &final_metadata) != expected_file
        || bytes.len() as u64 != expected_file.size
        || bytes.len() as u64 > MAX_MANAGED_LAUNCH_BYTES
    {
        return None;
    }
    let record = serde_json::from_slice(&bytes).ok()?;
    Some((record, expected_file))
}

fn read_managed_launch_snapshot() -> Option<(ScienceManagedLaunchRecord, ManagedLaunchFileIdentity)>
{
    read_managed_launch_snapshot_at(&managed_launch_path())
}

#[cfg(test)]
#[allow(dead_code)]
fn read_managed_launch_record() -> Option<ScienceManagedLaunchRecord> {
    read_managed_launch_snapshot().map(|(record, _)| record)
}

fn write_managed_launch_record(record: &ScienceManagedLaunchRecord) -> Result<(), String> {
    let path = managed_launch_path();
    let parent = path
        .parent()
        .ok_or("Science managed launch 记录路径无父目录")?;
    let parent_metadata = parent
        .symlink_metadata()
        .map_err(|_| "Science managed launch 记录目录不可用")?;
    if !parent_metadata.file_type().is_dir()
        || !crate::platform::file_owner_is_current(&parent_metadata)
        || crate::platform::metadata_mode(&parent_metadata) & 0o022 != 0
    {
        return Err("Science managed launch 记录目录不安全".into());
    }
    if let Ok(metadata) = path.symlink_metadata() {
        if !metadata.file_type().is_file()
            || !crate::platform::file_owner_is_current(&metadata)
            || crate::platform::metadata_mode(&metadata) & 0o077 != 0
        {
            return Err("Science managed launch 记录不是安全私有普通文件".into());
        }
    }
    let bytes = serde_json::to_vec(record).map_err(|_| "Science managed launch 记录无法序列化")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANAGED_LAUNCH_BYTES {
        return Err("Science managed launch 记录大小非法".into());
    }
    let temp = parent.join(format!(".{MANAGED_LAUNCH_FILE}.{}.tmp", record.launch_id));
    let write_result = (|| -> Result<(), String> {
        let mut file = create_new_private_file(OpenOptions::new().write(true), &temp, 0o600)
            .map_err(|_| "无法创建 Science managed launch 临时记录")?;
        file.write_all(&bytes)
            .map_err(|_| "无法写入 Science managed launch 临时记录")?;
        file.sync_all()
            .map_err(|_| "无法持久化 Science managed launch 临时记录")?;
        fs::rename(&temp, &path).map_err(|_| "无法提交 Science managed launch 记录")?;
        crate::platform::sync_dir(parent)
            .map_err(|_| "无法持久化 Science managed launch 记录目录")?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

#[allow(clippy::result_large_err)]
pub(crate) fn record_managed_science_launch(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> Result<ScienceManagedLaunchToken, ScienceManagedLaunchCommitError> {
    let listener_pid =
        listener_runtime_pid(port, runtime).ok_or_else(|| ScienceManagedLaunchCommitError {
            message: "Science listener 身份在 managed launch 提交前无法确认".into(),
            token: None,
        })?;
    let record = managed_launch_record_for(port, listener_pid, runtime).ok_or_else(|| {
        ScienceManagedLaunchCommitError {
            message: "Science managed launch 身份无法建立".into(),
            token: None,
        }
    })?;
    let uncommitted_token = ScienceManagedLaunchToken {
        record: record.clone(),
        receipt_file: None,
    };
    #[cfg(test)]
    {
        let persistent = std::env::var_os("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE").is_some();
        let once = std::env::var_os("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE_ONCE").is_some()
            && !MANAGED_LAUNCH_COMMIT_FAILURE_ONCE_FIRED
                .swap(true, std::sync::atomic::Ordering::SeqCst);
        if persistent || once {
            if let Some(observation) =
                std::env::var_os("CSSWITCH_TEST_MANAGED_LAUNCH_FAILURE_PID_LOG")
            {
                let _ = std::fs::write(observation, format!("{listener_pid}\n"));
            }
            return Err(ScienceManagedLaunchCommitError {
                message: "test-only managed launch commit failure after listener identity".into(),
                token: Some(uncommitted_token),
            });
        }
    }
    if unique_listener_pid(port) != Some(listener_pid)
        || process_start_identity(listener_pid).as_deref() != Some(record.process_start.as_str())
    {
        return Err(ScienceManagedLaunchCommitError {
            message: "Science listener 在 managed launch 提交前发生变化".into(),
            token: Some(uncommitted_token),
        });
    }
    if let Err(message) = write_managed_launch_record(&record) {
        return Err(ScienceManagedLaunchCommitError {
            message,
            token: Some(uncommitted_token),
        });
    }
    managed_launch_token(port, runtime).ok_or_else(|| ScienceManagedLaunchCommitError {
        message: "Science managed launch 记录提交后回读不一致".into(),
        token: Some(uncommitted_token),
    })
}

/// Capture an exact, receipt-free stop token for a newly spawned Science
/// listener. This is only valid for the narrow post-spawn/pre-receipt window:
/// callers must either commit the managed receipt or use this token to stop
/// the same PID/process-start/runtime identity before returning.
pub(crate) fn uncommitted_managed_science_launch_token(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> Option<ScienceManagedLaunchToken> {
    let listener_pid = listener_runtime_pid(port, runtime)?;
    let record = managed_launch_record_for(port, listener_pid, runtime)?;
    let token = ScienceManagedLaunchToken {
        record,
        receipt_file: None,
    };
    managed_launch_token_is_current(&token, runtime).then_some(token)
}

fn managed_launch_token(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> Option<ScienceManagedLaunchToken> {
    if !runtime.is_current() {
        return None;
    }
    let (record, receipt_file) = read_managed_launch_snapshot()?;
    if !record_matches_runtime(&record, port, runtime) {
        return None;
    }
    let pid_before = unique_listener_pid(port);
    if pid_before != Some(record.listener_pid)
        || process_start_identity(record.listener_pid).as_deref()
            != Some(record.process_start.as_str())
        || listener_runtime_pid(port, runtime) != Some(record.listener_pid)
    {
        return None;
    }
    if unique_listener_pid(port) != Some(record.listener_pid)
        || process_start_identity(record.listener_pid).as_deref()
            != Some(record.process_start.as_str())
    {
        return None;
    }
    Some(ScienceManagedLaunchToken {
        record,
        receipt_file: Some(receipt_file),
    })
}

pub(crate) fn managed_launch_token_for_runtime(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> Option<ScienceManagedLaunchToken> {
    managed_launch_token(port, runtime)
}

pub(crate) fn managed_launch_token_process_is_alive(token: &ScienceManagedLaunchToken) -> bool {
    process_start_identity(token.record.listener_pid).as_deref()
        == Some(token.record.process_start.as_str())
}

fn managed_launch_identity_matches(port: u16, runtime: &ScienceRuntimeIdentity) -> bool {
    managed_launch_token(port, runtime).is_some()
}

fn managed_launch_token_is_current(
    token: &ScienceManagedLaunchToken,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    let record = &token.record;
    if !runtime.is_current()
        || !record_matches_runtime(record, record.port, runtime)
        || unique_listener_pid(record.port) != Some(record.listener_pid)
        || process_start_identity(record.listener_pid).as_deref()
            != Some(record.process_start.as_str())
        || listener_runtime_pid(record.port, runtime) != Some(record.listener_pid)
    {
        return false;
    }
    if let Some(expected_file) = token.receipt_file.as_ref() {
        let Some((current_record, current_file)) = read_managed_launch_snapshot() else {
            return false;
        };
        if current_record != *record || current_file != *expected_file {
            return false;
        }
    }
    unique_listener_pid(record.port) == Some(record.listener_pid)
        && process_start_identity(record.listener_pid).as_deref()
            == Some(record.process_start.as_str())
}

pub(crate) fn managed_launch_token_is_current_for_runtime(
    token: &ScienceManagedLaunchToken,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    managed_launch_token_is_current(token, runtime)
}

fn restore_unmatched_managed_launch_tombstone(tombstone: &Path, path: &Path) -> Result<(), String> {
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(test)]
            if let Some(barrier_dir) =
                std::env::var_os("CSSWITCH_TEST_TOMBSTONE_RESTORE_BARRIER").map(PathBuf::from)
            {
                fs::write(barrier_dir.join("ready"), b"ready")
                    .map_err(|_| "Science managed launch 测试恢复屏障不可用".to_string())?;
                let mut released = false;
                for _ in 0..500 {
                    if barrier_dir.join("continue").is_file() {
                        released = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !released {
                    return Err("Science managed launch 测试恢复屏障超时".into());
                }
            }
            match fs::hard_link(tombstone, path) {
                Ok(()) => {
                    fs::remove_file(tombstone)
                        .map_err(|_| "Science managed launch 记录已恢复但 tombstone 无法清理")?;
                    let parent = path.parent().ok_or("Science managed launch 恢复路径无父目录")?;
                    crate::platform::sync_dir(parent)
                        .map_err(|_| "Science managed launch 恢复目录无法持久化")?;
                    Ok(())
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(
                    "Science managed launch 原子 no-clobber 恢复冲突；新记录与旧 tombstone 均已保留"
                        .into(),
                ),
                Err(_) => Err("Science managed launch 记录变化且无法原位恢复".into()),
            }
        }
        Ok(_) => {
            Err("Science managed launch 记录变化且新记录已出现；旧记录保留在 tombstone".into())
        }
        Err(_) => Err("Science managed launch 记录变化且无法确认恢复目标".into()),
    }
}

fn clear_managed_launch_identity(
    token: &ScienceManagedLaunchToken,
    runtime: &ScienceRuntimeIdentity,
) -> Result<(), String> {
    let path = managed_launch_path();
    let Some((record, receipt_file)) = read_managed_launch_snapshot() else {
        return match path.symlink_metadata() {
            Ok(_) => Err("Science managed launch 记录无效，未删除".into()),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && token.receipt_file.is_none() =>
            {
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("Science managed launch 已提交记录在停止清理前消失".into())
            }
            Err(_) => Err("无法确认 Science managed launch 记录".into()),
        };
    };
    if record != token.record
        || token
            .receipt_file
            .as_ref()
            .is_some_and(|expected| expected != &receipt_file)
        || !record_matches_runtime(&record, token.record.port, runtime)
    {
        return Err("Science managed launch 记录与停止目标不匹配，未删除".into());
    }
    let parent = path.parent().ok_or("Science managed launch 路径无父目录")?;
    let tombstone = parent.join(format!(
        ".{MANAGED_LAUNCH_FILE}.{}.stopped",
        token.record.launch_id
    ));
    if tombstone.symlink_metadata().is_ok() {
        return Err("Science managed launch 清理 tombstone 已存在".into());
    }
    fs::rename(&path, &tombstone).map_err(|_| "无法冻结待清理 Science managed launch 记录")?;
    let moved = read_managed_launch_snapshot_at(&tombstone);
    if moved.as_ref() != Some(&(record, receipt_file)) {
        let restore = restore_unmatched_managed_launch_tombstone(&tombstone, &path);
        return Err(match restore {
            Ok(()) => "Science managed launch 记录在清理前变化；已恢复且拒绝删除".into(),
            Err(error) => error,
        });
    }
    fs::remove_file(&tombstone).map_err(|_| "无法清理 Science managed launch 记录")?;
    crate::platform::sync_dir(parent)
        .map_err(|_| "无法持久化 Science managed launch 清理")?;
    Ok(())
}

fn process_text_paths(pid: u32) -> Option<Vec<PathBuf>> {
    // unix 走 lsof txt；Windows 取 QueryFullProcessImageNameW 的主模块映像路径。
    crate::platform::process_text_paths(pid).map(|paths| {
        paths
            .into_iter()
            .filter_map(|path| crate::platform::canonicalize(&path).ok())
            .collect()
    })
}

fn listener_runtime_pid(port: u16, runtime: &ScienceRuntimeIdentity) -> Option<u32> {
    if !runtime.is_current() {
        return None;
    }
    let pid = unique_listener_pid(port)?;
    #[cfg(test)]
    {
        let pid_text = pid.to_string();
        if test_listener_marker_matches(&pid_text, runtime) {
            return Some(pid);
        }
    }
    let expected = crate::platform::canonicalize(&runtime.path).ok()?;
    process_text_paths(pid)?
        .into_iter()
        .any(|path| path == expected)
        .then_some(pid)
}

fn listener_uses_runtime(port: u16, runtime: &ScienceRuntimeIdentity) -> bool {
    listener_runtime_pid(port, runtime).is_some()
}

#[cfg(test)]
fn test_listener_marker_matches(pid: &str, runtime: &ScienceRuntimeIdentity) -> bool {
    if std::env::var("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY")
        .ok()
        .as_deref()
        != Some("1")
    {
        return false;
    }
    let Some(configured) = std::env::var_os("SCIENCE_BIN").map(PathBuf::from) else {
        return false;
    };
    if crate::platform::canonicalize(&configured).ok() != crate::platform::canonicalize(&runtime.path).ok() {
        return false;
    }
    std::fs::read_to_string(sandbox_data_dir().join("fake-science/pid"))
        .ok()
        .is_some_and(|recorded| recorded.trim() == pid)
}

/// Return the sandbox UI URL, falling back to the plain localhost port.
pub(crate) fn sandbox_url(port: u16, runtime: &ScienceRuntimeIdentity) -> String {
    let home = sandbox_home();
    let data_dir = sandbox_data_dir();
    if runtime.is_current() {
        let mut command = Command::new(&runtime.path);
        command.arg("url").arg("--data-dir").arg(&data_dir);
        crate::platform::env_isolated_home(&mut command, &home);
        crate::platform::hide_console(&mut command);
        if let Ok(out) = command.output() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(url) = first_http_url(&s) {
                return url;
            }
        }
    }
    format!("http://127.0.0.1:{port}")
}

fn runtime_status(runtime: &ScienceRuntimeIdentity) -> Option<bool> {
    if !runtime.is_current() {
        return None;
    }
    let mut command = Command::new(&runtime.path);
    command.arg("status").arg("--data-dir").arg(sandbox_data_dir());
    crate::platform::env_isolated_home(&mut command, &sandbox_home());
    crate::platform::hide_console(&mut command);
    let out = command.output().ok()?;
    // Some Science builds use a non-zero exit to mean "not running" while
    // still returning a valid {"running":false} payload. Accept only that
    // negative result; a non-zero positive or malformed response stays unknown.
    runtime_status_value(&out)
}

pub(crate) fn probe_known_runtime(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> SandboxScienceState {
    let status = runtime_status(runtime);
    let health_ready = proc::http_health(port, None, 400);
    let port_accepts_tcp = health_ready || loopback_port_accepts_tcp(port);
    let listener_matches_runtime = status == Some(true)
        && health_ready
        && listener_uses_runtime(port, runtime)
        && managed_launch_identity_matches(port, runtime);
    classify_known_runtime_state(
        status,
        health_ready,
        port_accepts_tcp,
        listener_matches_runtime,
    )
}

pub(crate) fn probe_sandbox_runtime(
    port: u16,
) -> Result<(SandboxScienceState, Option<ScienceRuntimeIdentity>), String> {
    probe_sandbox_runtime_cached(port, &ScienceVersionCache::default())
}

pub(crate) fn probe_sandbox_runtime_cached(
    port: u16,
    version_cache: &ScienceVersionCache,
) -> Result<(SandboxScienceState, Option<ScienceRuntimeIdentity>), String> {
    let health_ready = proc::http_health(port, None, 400);
    let port_accepts_tcp = health_ready || loopback_port_accepts_tcp(port);
    let candidates = runtime_probe_candidates(port, version_cache)?;
    let no_candidates = candidates.is_empty();
    let mut saw_stopped = false;
    let mut saw_running_unconfirmed = false;
    for runtime in candidates {
        match runtime_status(&runtime) {
            Some(true)
                if health_ready
                    && listener_uses_runtime(port, &runtime)
                    && managed_launch_identity_matches(port, &runtime) =>
            {
                return Ok((SandboxScienceState::RunningHealthy, Some(runtime)))
            }
            Some(true) => saw_running_unconfirmed = true,
            Some(false) => saw_stopped = true,
            None => {}
        }
    }
    if saw_running_unconfirmed {
        return Ok((SandboxScienceState::Unknown, None));
    }
    if !port_accepts_tcp && (saw_stopped || !sandbox_data_dir().exists()) {
        return Ok((SandboxScienceState::Stopped, None));
    }
    if !port_accepts_tcp && no_candidates {
        return Ok((SandboxScienceState::Stopped, None));
    }
    Ok((SandboxScienceState::Unknown, None))
}

fn stop_runtime_from_probe(
    state: SandboxScienceState,
    runtime: Option<ScienceRuntimeIdentity>,
) -> Result<Option<ScienceRuntimeIdentity>, String> {
    match (state, runtime) {
        (SandboxScienceState::Stopped, _) => Ok(None),
        (SandboxScienceState::RunningHealthy, Some(runtime)) => Ok(Some(runtime)),
        (SandboxScienceState::RunningHealthy, None) => {
            Err("Science 状态为运行中，但无法确认其 binary 身份；已拒绝按端口停止".into())
        }
        (SandboxScienceState::Unknown, _) => {
            Err("无法确认当前 Science daemon 使用的 binary；已拒绝按端口停止".into())
        }
    }
}

/// Check that the sandbox Science associated with our data-dir is running.
/// A naked `/health` response is not sufficient identity proof.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn sandbox_running_ours(port: u16, runtime: &ScienceRuntimeIdentity) -> bool {
    probe_known_runtime(port, runtime) == SandboxScienceState::RunningHealthy
}

/// The caller has just observed a healthy response and only needs to prove the
/// listener executable identity; avoid repeating status and health CLI work.
pub(crate) fn sandbox_listener_matches_runtime(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    listener_uses_runtime(port, runtime)
}

/// `scripts/stop-science-sandbox.sh` 的 Windows 原生等价实现：拒绝指向真实
/// data-dir 或含符号链接的路径，然后用隔离 HOME 调用
/// `<science> stop --data-dir <sandbox data-dir>`。返回 `Some` 表示停止未确认。
#[cfg(windows)]
fn windows_stop_science_cli(bin: &Path, home: &Path, data_dir: &Path) -> Option<String> {
    // data-dir 的真实路径不得指向真实实例的 data-dir（脚本同款防护）。
    if let Some(real) = crate::platform::home_dir().map(|user_home| user_home.join(".claude-science")) {
        if let (Ok(sandbox_real), Ok(real_real)) = (
            crate::platform::canonicalize(data_dir),
            crate::platform::canonicalize(&real),
        ) {
            if sandbox_real == real_real {
                return Some("拒绝：data-dir 的真实路径指向真实目录".into());
            }
        }
    }
    let mut probe = PathBuf::new();
    for component in data_dir.components() {
        if matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        ) {
            probe.push(component.as_os_str());
            continue;
        }
        probe.push(component.as_os_str());
        match probe.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Some("拒绝：Science data-dir 路径包含符号链接".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {}
        }
    }
    if !data_dir.is_dir() {
        // 沙箱不存在，无需停止（与脚本一致视为成功）。
        return None;
    }
    let mut command = Command::new(bin);
    command.arg("stop").arg("--data-dir").arg(data_dir);
    crate::platform::env_isolated_home(&mut command, home);
    crate::platform::configure_spawn(&mut command);
    command.stdout(Stdio::null()).stderr(Stdio::null());
    match command.status() {
        Ok(status) if status.success() => None,
        Ok(status) => Some(format!("停止沙箱命令非零退出（{:?}）。", status.code())),
        Err(error) => Some(format!("调用停止沙箱命令失败：{error}")),
    }
}

/// Stop the sandbox Science process and clear the in-memory sandbox URL.
///
/// Returns `Err` when the stop script is missing or exits non-zero, so callers
/// can report that Science may not have stopped cleanly.
pub(crate) fn stop_sandbox<R: Runtime>(
    app: &tauri::AppHandle<R>,
    sandbox: &mut Option<Child>,
    sandbox_url: &mut Option<String>,
    runtime: Option<&ScienceRuntimeIdentity>,
) -> Result<(), String> {
    stop_sandbox_with_launch_token(app, sandbox, sandbox_url, runtime, None)
}

pub(crate) fn stop_sandbox_with_launch_token<R: Runtime>(
    app: &tauri::AppHandle<R>,
    sandbox: &mut Option<Child>,
    sandbox_url: &mut Option<String>,
    runtime: Option<&ScienceRuntimeIdentity>,
    launch_token: Option<&ScienceManagedLaunchToken>,
) -> Result<(), String> {
    if !sandbox_data_dir().exists() {
        let sandbox_port = config::load_from(&config::default_dir())
            .map_err(|error| format!("读取 Science 端口配置失败：{error}"))?
            .sandbox_port;
        let first_port_observation = loopback_port_accepts_tcp(sandbox_port);
        let second_port_observation = if first_port_observation {
            true
        } else {
            std::thread::sleep(Duration::from_millis(20));
            loopback_port_accepts_tcp(sandbox_port)
        };
        if second_port_observation {
            return Err(
                "Science data-dir 已消失，但配置端口仍有监听；未发送信号且未确认停止。".into(),
            );
        }
        kill_child(sandbox);
        *sandbox_url = None;
        return Ok(());
    }
    let recovered;
    let runtime = match runtime {
        Some(runtime) => runtime,
        None => {
            let port = config::load_from(&config::default_dir())
                .map_err(|e| format!("读取 Science 端口配置失败：{e}"))?
                .sandbox_port;
            let (state, runtime) = probe_sandbox_runtime(port)?;
            let Some(runtime) = stop_runtime_from_probe(state, runtime)? else {
                kill_child(sandbox);
                *sandbox_url = None;
                return Ok(());
            };
            recovered = runtime;
            &recovered
        }
    };
    if !runtime.is_current() {
        return Err("Science binary 在选择后发生变化；已拒绝用不同文件控制现有 daemon".into());
    }
    let sandbox_port = config::load_from(&config::default_dir())
        .map_err(|error| format!("读取 Science 端口配置失败：{error}"))?
        .sandbox_port;
    let stop_token = match launch_token {
        Some(token) => token.clone(),
        None => managed_launch_token(sandbox_port, runtime)
            .ok_or("Science managed launch 身份无法确认；已拒绝调用 stop 或发送信号")?,
    };
    if stop_token.record.port != sandbox_port
        || !managed_launch_token_is_current(&stop_token, runtime)
    {
        return Err("Science managed launch 身份在停止前发生变化；未调用 stop 或发送信号".into());
    }
    // Windows 分支会用原生 stop 结果整体覆盖初始 None，属预期。
    #[cfg_attr(windows, allow(unused_assignments))]
    let mut err = None;
    #[cfg(unix)]
    match asset_root(app) {
        Some(root) => {
            let stop = root.join("scripts/stop-science-sandbox.sh");
            if stop.is_file() {
                let mut command = Command::new("zsh");
                command.arg(&stop).stdout(Stdio::null()).stderr(Stdio::null());
                command.env("SANDBOX_HOME", sandbox_home());
                command.env("SCIENCE_BIN", &runtime.path);
                match command.status() {
                    Ok(s) if s.success() => {}
                    Ok(s) => err = Some(format!("停止沙箱脚本非零退出（{:?}）。", s.code())),
                    Err(e) => err = Some(format!("调用停止沙箱脚本失败：{e}")),
                }
            } else {
                err = Some(
                    "找不到打包的停止脚本，无法确认沙箱已停止（沙箱可能仍在运行）。".to_string(),
                );
            }
        }
        None => {
            err = Some(
                "定位不到资源根，取不到停止脚本，无法确认沙箱已停止（沙箱可能仍在运行）。"
                    .to_string(),
            );
        }
    }
    #[cfg(windows)]
    {
        // Windows 没有 zsh：走 scripts/stop-science-sandbox.sh 的原生等价实现。
        let _ = app;
        err = windows_stop_science_cli(&runtime.path, &sandbox_home(), &sandbox_data_dir());
    }
    if err.is_none() && loopback_port_accepts_tcp(sandbox_port) {
        let pid = stop_token.record.listener_pid;
        if managed_launch_token_is_current(&stop_token, runtime) {
            // Some upstream Science builds return success and remove their
            // lockfile without terminating the daemon. The user requested
            // stop, so signal only the exact launch token whose listener,
            // process start, receipt, and canonical executable were proved
            // both before and after CLI.
            // unix: SIGTERM（PID > 1 且精确 listener 身份已在上文复核）；
            // Windows: TerminateProcess 等价。
            if crate::platform::terminate_pid(pid, true).is_err() {
                err = Some("Science stop 返回成功但精确 daemon 无法接收 TERM。".into());
            } else {
                for _ in 0..50 {
                    if !loopback_port_accepts_tcp(sandbox_port) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                if managed_launch_token_is_current(&stop_token, runtime) {
                    // 同一 launch token（含 process-start 身份）在 TERM 等待后
                    // 复核通过才升级为 SIGKILL / TerminateProcess。
                    let _ = crate::platform::terminate_pid(pid, false);
                    for _ in 0..20 {
                        if !loopback_port_accepts_tcp(sandbox_port) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                if loopback_port_accepts_tcp(sandbox_port) {
                    err = Some(
                        "Science stop 返回成功，但端口仍被占用；已拒绝把未知监听者当作停止成功。"
                            .into(),
                    );
                }
            }
        } else {
            err = Some(
                "Science stop 返回成功，但停止后的监听身份与启动记录不一致；未发送信号。".into(),
            );
        }
    }
    kill_child(sandbox);
    *sandbox_url = None;
    if err.is_none() {
        if loopback_port_accepts_tcp(sandbox_port) {
            err = Some(
                "Science stop 后配置端口重新出现监听；未确认停止且未清理 managed launch 记录。"
                    .into(),
            );
        } else if let Err(error) = clear_managed_launch_identity(&stop_token, runtime) {
            err = Some(error);
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::net::{TcpListener, TcpStream};
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(unix)]
    use std::process::{Command, ExitStatus, Output};
    #[cfg(unix)]
    use std::sync::atomic::Ordering;
    #[cfg(unix)]
    use std::time::Duration;

    // 跨平台测试共用。
    use super::{
        classify_known_runtime_state, fingerprint_sha256_hex, first_http_url,
        official_updated_embedded_identity_metadata_matches, parse_unique_listener_pid,
        sandbox_home, select_science_runtime_for_paths, settings_change_needs_teardown,
        stop_runtime_from_probe, SandboxScienceState, ScienceRuntimeSource,
    };
    // 依赖 POSIX（symlink/mode/sh 脚本/lsof 语义）的测试专用。
    #[cfg(unix)]
    use super::{
        classify_sandbox_state, managed_launch_path, official_updated_science_bin_for_home,
        official_updated_snapshot_for_home, official_updated_snapshot_from_process_paths,
        probe_sandbox_runtime_cached, read_managed_launch_record,
        restore_unmatched_managed_launch_tombstone, runtime_identity_is_current,
        runtime_status_value, safe_science_version_with_timeout, sandbox_running_ours,
        sandbox_url, science_executable_fingerprint, science_runtime_preflight_for_paths,
        science_runtime_preflight_for_paths_cached,
        science_runtime_preflight_for_paths_with_updated, science_status_running,
        secure_runtime_snapshot_root, select_science_runtime_for_paths_cached,
        select_science_runtime_for_paths_with_updated, trusted_science_status,
        MANAGED_LAUNCH_LAST_READ_BYTES, MAX_MANAGED_LAUNCH_BYTES, CACHED_ONCE_CHOICE,
        ScienceRuntimeIdentity, ScienceVersionCache,
    };

    #[test]
    fn official_updater_identity_parser_accepts_only_known_exact_variants() {
        let standalone = "Identifier=com.anthropic.operon\nTeamIdentifier=Q6L2SF6YDW\n";
        assert!(official_updated_embedded_identity_metadata_matches(
            standalone
        ));

        let dmg_seed = "Identifier=com.anthropic.operon.cli\nTeamIdentifier=Q6L2SF6YDW\n";
        assert!(official_updated_embedded_identity_metadata_matches(
            dmg_seed
        ));
        assert!(!official_updated_embedded_identity_metadata_matches(
            "Identifier=com.anthropic.operon.other\nTeamIdentifier=Q6L2SF6YDW\n",
        ));
        assert!(!official_updated_embedded_identity_metadata_matches(
            "Identifier=com.anthropic.operon\nTeamIdentifier=WRONG\n",
        ));
        assert!(!official_updated_embedded_identity_metadata_matches(
            "prefix-Identifier=com.anthropic.operon\nTeamIdentifier=Q6L2SF6YDW\n",
        ));
        assert!(!official_updated_embedded_identity_metadata_matches(
            "Identifier=com.anthropic.operon\nTeamIdentifier=Q6L2SF6YDW-suffix\n",
        ));
    }

    #[test]
    fn managed_launch_tombstone_restore_uses_no_clobber_primitive() {
        let source = include_str!("science.rs");
        let start = source
            .find("fn restore_unmatched_managed_launch_tombstone")
            .expect("managed launch tombstone restore implementation must exist");
        let remainder = &source[start..];
        let end = remainder
            .find("\nfn clear_managed_launch_identity")
            .expect("managed launch tombstone restore implementation must remain bounded");
        let implementation = &remainder[..end];

        assert!(
            implementation.contains("fs::hard_link(tombstone, path)"),
            "managed launch tombstone restore must use hard_link as its final atomic no-clobber destination commit"
        );
        assert!(
            !implementation.contains("rename("),
            "managed launch tombstone restore must not retain a check-then-overwriting-rename path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn managed_launch_tombstone_restore_is_atomic_no_clobber(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-managed-launch-restore-race")?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let tombstone = root.join("science-managed-launch.old.stopped");
        let receipt = root.join("science-managed-launch.v1.json");
        let old_receipt = b"old-private-managed-launch".to_vec();
        let new_receipt = b"new-concurrent-managed-launch".to_vec();
        fs::write(&tombstone, &old_receipt)?;
        fs::set_permissions(&tombstone, fs::Permissions::from_mode(0o600))?;
        let barrier = root.join("restore-barrier");
        fs::create_dir(&barrier)?;
        std::env::set_var("CSSWITCH_TEST_TOMBSTONE_RESTORE_BARRIER", &barrier);

        let receipt_for_writer = receipt.clone();
        let barrier_for_writer = barrier.clone();
        let new_receipt_for_writer = new_receipt.clone();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            for _ in 0..500 {
                if barrier_for_writer.join("ready").is_file() {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&receipt_for_writer)?;
                    file.write_all(&new_receipt_for_writer)?;
                    file.sync_all()?;
                    fs::write(barrier_for_writer.join("continue"), b"continue")?;
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tombstone restore never reached the deterministic race barrier",
            ))
        });

        let restore = restore_unmatched_managed_launch_tombstone(&tombstone, &receipt);
        writer
            .join()
            .map_err(|_| "managed launch race writer panicked")??;
        std::env::remove_var("CSSWITCH_TEST_TOMBSTONE_RESTORE_BARRIER");
        let receipt_after = fs::read(&receipt)?;
        let tombstone_after = fs::read(&tombstone).ok();
        fs::remove_dir_all(&root)?;

        assert_eq!(
            restore.as_ref().map_err(String::as_str),
            Err(
                "Science managed launch 原子 no-clobber 恢复冲突；新记录与旧 tombstone 均已保留"
            ),
            "atomic no-clobber restore must report the conflict from its final no-replace commit primitive, not from another check before an overwriting rename"
        );
        assert_eq!(
            receipt_after, new_receipt,
            "atomic no-clobber restore must preserve the concurrently committed receipt byte-for-byte"
        );
        assert_eq!(
            tombstone_after.as_deref(),
            Some(old_receipt.as_slice()),
            "atomic no-clobber restore must retain the old tombstone on conflict"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn managed_launch_receipt_growth_read_is_hard_bounded() -> Result<(), Box<dyn std::error::Error>>
    {
        const CHILD_ENV: &str = "CSSWITCH_TEST_MANAGED_LAUNCH_GROWTH_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let root = unique_temp_dir("science-managed-launch-growth")?;
            let home = root.join("home");
            fs::create_dir_all(&home)?;
            let output = Command::new(std::env::current_exe()?)
                .arg("--exact")
                .arg("runtime::science::tests::managed_launch_receipt_growth_read_is_hard_bounded")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .env("HOME", &home)
                .output()?;
            let _ = fs::remove_dir_all(&root);
            assert!(
                output.status.success(),
                "isolated bounded receipt oracle failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }

        let config_dir = crate::config::default_dir();
        fs::create_dir_all(&config_dir)?;
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700))?;
        let receipt = managed_launch_path();
        fs::write(&receipt, b"{}")?;
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600))?;
        let barrier = config_dir.join("managed-launch-read-barrier");
        fs::create_dir_all(&barrier)?;
        std::env::set_var("CSSWITCH_TEST_MANAGED_LAUNCH_READ_BARRIER", &barrier);
        MANAGED_LAUNCH_LAST_READ_BYTES.store(0, Ordering::SeqCst);

        let receipt_for_writer = receipt.clone();
        let barrier_for_writer = barrier.clone();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            for _ in 0..500 {
                if barrier_for_writer.join("ready").is_file() {
                    let mut file = OpenOptions::new().append(true).open(&receipt_for_writer)?;
                    file.write_all(&vec![b' '; 1024 * 1024])?;
                    file.sync_all()?;
                    fs::write(barrier_for_writer.join("continue"), b"continue")?;
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "managed launch reader never reached the deterministic barrier",
            ))
        });
        let _ = read_managed_launch_record();
        writer
            .join()
            .map_err(|_| "managed launch writer panicked")??;
        std::env::remove_var("CSSWITCH_TEST_MANAGED_LAUNCH_READ_BARRIER");
        let observed = MANAGED_LAUNCH_LAST_READ_BYTES.load(Ordering::SeqCst);
        assert!(
            observed <= MAX_MANAGED_LAUNCH_BYTES + 1,
            "managed launch reader consumed {observed} bytes after concurrent growth; hard cap is {}",
            MAX_MANAGED_LAUNCH_BYTES + 1
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn fresh_restart_rejects_listener_without_managed_launch_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const CHILD_ENV: &str = "CSSWITCH_TEST_SCIENCE_REATTACH_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let root = unique_temp_dir("science-unmanaged-reattach")?;
            let home = root.join("home");
            fs::create_dir_all(&home)?;
            let output = Command::new(std::env::current_exe()?)
                .arg("--exact")
                .arg("runtime::science::tests::fresh_restart_rejects_listener_without_managed_launch_identity")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .env("HOME", &home)
                .output()?;
            let _ = fs::remove_dir_all(&root);
            assert!(
                output.status.success(),
                "isolated reattach oracle failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }

        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or("isolated HOME is required")?;
        let bin = home.join("bin").join("claude-science");
        let data_dir = sandbox_home().join(".claude-science");
        let state_dir = data_dir.join("fake-science");
        fs::create_dir_all(bin.parent().ok_or("fake bin parent is required")?)?;
        fs::create_dir_all(&state_dir)?;
        fs::write(
            &bin,
            r#"#!/bin/sh
set -eu
cmd="${1:-}"
if [ "$#" -gt 0 ]; then shift; fi
if [ "$cmd" = "--version" ]; then
  echo "claude-science unmanaged-reattach-test"
  exit 0
fi
data_dir=""
port=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-dir) data_dir="$2"; shift 2 ;;
    --port) port="$2"; shift 2 ;;
    *) shift ;;
  esac
done
state="$data_dir/fake-science"
mkdir -p "$state"
case "$cmd" in
  serve)
    python3 - "$port" "$state/pid" >/dev/null 2>&1 <<'PY' &
import http.server
import os
import socketserver
import sys
port = int(sys.argv[1])
pidfile = sys.argv[2]
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        if self.path.startswith("/health"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()
socketserver.TCPServer.allow_reuse_address = True
with open(pidfile, "w", encoding="utf-8") as f:
    f.write(str(os.getpid()))
with socketserver.TCPServer(("127.0.0.1", port), Handler) as httpd:
    httpd.serve_forever()
PY
    ;;
  status)
    pid="$(cat "$state/pid" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo '{"running":true}'
    else
      echo '{"running":false}'
      exit 1
    fi
    ;;
  stop)
    pid="$(cat "$state/pid" 2>/dev/null || true)"
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
    rm -f "$state/pid"
    ;;
  *) exit 2 ;;
esac
"#,
        )?;
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700))?;
        let bin = crate::platform::canonicalize(&bin)?;
        std::env::set_var("SCIENCE_BIN", &bin);
        std::env::set_var("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");

        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let launch = Command::new(&bin)
            .arg("serve")
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--port")
            .arg(port.to_string())
            .status()?;
        assert!(launch.success());
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let observed = probe_sandbox_runtime_cached(port, &ScienceVersionCache::default())?;
        let listener_still_alive = TcpStream::connect(("127.0.0.1", port)).is_ok();
        let stopped = Command::new(&bin)
            .arg("stop")
            .arg("--data-dir")
            .arg(&data_dir)
            .status()?;
        assert!(stopped.success());

        assert_eq!(
            observed,
            (SandboxScienceState::Unknown, None),
            "a fresh Desktop state must not adopt a listener that has no persisted managed-launch identity"
        );
        assert!(
            listener_still_alive,
            "rejected adoption must not signal the unproven listener"
        );
        Ok(())
    }

    // ---------- P1-c: 端口变更是否需拆链路（纯函数，4 组合） ----------
    #[test]
    fn settings_teardown_when_any_port_changes() {
        assert!(
            !settings_change_needs_teardown(18991, 18991, 8990, 8990),
            "端口未变 → 不拆链路"
        );
        assert!(
            settings_change_needs_teardown(18991, 19000, 8990, 8990),
            "代理端口变 → 拆（旧代理绑旧端口、沙箱烘旧 URL）"
        );
        assert!(
            settings_change_needs_teardown(18991, 18991, 8990, 9000),
            "沙箱端口变 → 拆（旧沙箱在旧端口成孤儿）"
        );
        assert!(
            settings_change_needs_teardown(18991, 19000, 8990, 9000),
            "都变 → 拆"
        );
    }

    #[cfg(unix)]
    #[test]
    fn science_version_probe_times_out_and_reaps_its_child(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-version-timeout")?;
        let binary = root.join("hanging-science");
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then exec /bin/sleep 60; fi\nexit 0\n",
        )?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
        let started = std::time::Instant::now();
        assert_eq!(
            safe_science_version_with_timeout(&binary, std::time::Duration::from_millis(100)),
            None
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn science_version_probe_kills_descendant_before_it_can_act_after_return(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-version-descendant")?;
        let binary = root.join("forking-science");
        let started_marker = root.join("descendant-started");
        let late_marker = root.join("descendant-late");
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then\n  ( : > '{}'; /bin/sleep 1; : > '{}' ) &\n  while [ ! -f '{}' ]; do /bin/sleep 0.01; done\n  printf '%s\\n' 'descendant-safe-v1'\n  exit 0\nfi\nexit 0\n",
                started_marker.display(),
                late_marker.display(),
                started_marker.display()
            ),
        )?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
        let started = std::time::Instant::now();
        let version =
            safe_science_version_with_timeout(&binary, std::time::Duration::from_secs(15));
        assert_eq!(version.as_deref(), Some("descendant-safe-v1"));
        assert!(started.elapsed() < std::time::Duration::from_secs(17));
        assert!(
            started_marker.exists(),
            "the descendant must actually start"
        );
        std::thread::sleep(std::time::Duration::from_millis(1_200));
        assert!(
            !late_marker.exists(),
            "the descendant must not remain executable after the probe returns"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn science_version_probe_rejects_oversize_output() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-version-oversize")?;
        let binary = root.join("oversize-science");
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then printf '%s\\n' 'valid-first-line'; printf '%01030d' 0; exit 0; fi\nexit 0\n",
        )?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            safe_science_version_with_timeout(&binary, std::time::Duration::from_secs(2)),
            None,
            "a legal first line must not hide oversized trailing output"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn first_http_url_takes_only_first_valid_url() {
        let multi = "http://127.0.0.1:8990/setup?nonce=abc123\n\
                     This is a single-use link, expires in 60 seconds.";
        assert_eq!(
            first_http_url(multi).as_deref(),
            Some("http://127.0.0.1:8990/setup?nonce=abc123"),
        );
        let inline = "https://x.example/y?z=1  (single-use)";
        assert_eq!(
            first_http_url(inline).as_deref(),
            Some("https://x.example/y?z=1")
        );
        let lead = "Open this link in your browser:\nhttp://127.0.0.1:8990/a";
        assert_eq!(
            first_http_url(lead).as_deref(),
            Some("http://127.0.0.1:8990/a")
        );
        assert_eq!(first_http_url("no url here\nnor here"), None);
        assert_eq!(
            first_http_url("http://127.0.0.1:8990").as_deref(),
            Some("http://127.0.0.1:8990")
        );
    }

    #[test]
    fn listener_pid_parser_requires_one_safe_identity() {
        assert_eq!(parse_unique_listener_pid("preamble\n"), None);
        assert_eq!(parse_unique_listener_pid("1\n"), None);
        assert_eq!(parse_unique_listener_pid("42\n42\n"), Some(42));
        assert_eq!(parse_unique_listener_pid("42\n43\n"), None);
        assert_eq!(parse_unique_listener_pid("42\ninvalid\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn version_cache_is_shared_and_invalidates_when_binary_changes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-version-cache")?;
        let app_bin = root.join("claude-science");
        let count = root.join("version-count");
        write_counted_version_bin(&app_bin, &count, "claude-science cache-v1")?;
        let data_dir = root.join("data");
        fs::create_dir_all(&data_dir)?;
        let cache = ScienceVersionCache::default();

        let preflight =
            science_runtime_preflight_for_paths_cached(&data_dir, None, None, &app_bin, &cache)?;
        assert_eq!(preflight["selected_version"], "claude-science cache-v1");
        let selected =
            select_science_runtime_for_paths_cached(&data_dir, None, None, &app_bin, None, &cache)?;
        assert_eq!(selected.version.as_deref(), Some("claude-science cache-v1"));
        assert_eq!(fs::read_to_string(&count)?, "1");

        write_counted_version_bin(&app_bin, &count, "claude-science cache-version-two")?;
        let selected =
            select_science_runtime_for_paths_cached(&data_dir, None, None, &app_bin, None, &cache)?;
        assert_eq!(
            selected.version.as_deref(),
            Some("claude-science cache-version-two")
        );
        assert_eq!(fs::read_to_string(&count)?, "2");

        assert_eq!(
            cache.force_refresh(&app_bin).as_deref(),
            Some("claude-science cache-version-two")
        );
        assert_eq!(fs::read_to_string(&count)?, "3");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn science_status_running_accepts_compact_and_spaced_json() {
        assert!(science_status_running(&status_output(
            0,
            r#"{"running":true}"#
        )));
        assert!(science_status_running(&status_output(
            0,
            r#"{"running": true}"#
        )));
        assert!(!science_status_running(&status_output(
            0,
            r#"{"running":false}"#
        )));
        assert!(!science_status_running(&status_output(0, "running")));
        assert!(!science_status_running(&status_output(
            1,
            r#"{"running": true}"#
        )));
    }

    #[cfg(unix)]
    #[test]
    fn science_status_running_accepts_json_with_cli_text() {
        assert!(science_status_running(&status_output(
            0,
            "Claude Science status:\n{\"running\": true, \"port\": 8990}\nready"
        )));
        assert!(science_status_running(&status_output(
            0,
            "warning: {not-json}\n{\"state\":\"ok\"}\n{\"running\": true}"
        )));
        assert!(!science_status_running(&status_output(
            0,
            "warning\n{\"running\": false}\n{\"running\": true}"
        )));
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_state_classification_fails_closed_on_probe_disagreement() {
        assert_eq!(
            classify_sandbox_state(Some(true), true, true),
            SandboxScienceState::RunningHealthy
        );
        assert_eq!(
            classify_sandbox_state(Some(false), false, false),
            SandboxScienceState::Stopped
        );
        for state in [
            classify_sandbox_state(None, false, false),
            classify_sandbox_state(Some(true), false, true),
            classify_sandbox_state(Some(true), false, false),
            classify_sandbox_state(Some(false), true, true),
            classify_sandbox_state(Some(false), false, true),
        ] {
            assert_eq!(state, SandboxScienceState::Unknown);
        }
        assert_eq!(
            trusted_science_status(&status_output(1, r#"{"running":false}"#)),
            Some(false),
            "a stopped daemon may be reported with a non-zero CLI exit"
        );
    }

    #[test]
    fn stop_probe_is_idempotent_only_for_confirmed_stopped_state() {
        assert_eq!(
            stop_runtime_from_probe(SandboxScienceState::Stopped, None).unwrap(),
            None
        );
        assert!(stop_runtime_from_probe(SandboxScienceState::Unknown, None).is_err());
        assert!(stop_runtime_from_probe(SandboxScienceState::RunningHealthy, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn known_runtime_state_requires_listener_binary_match() {
        assert_eq!(
            classify_known_runtime_state(Some(true), true, true, true),
            SandboxScienceState::RunningHealthy
        );
        assert_eq!(
            classify_known_runtime_state(Some(true), true, true, false),
            SandboxScienceState::Unknown
        );
        assert_eq!(
            runtime_status_value(&status_output(1, r#"{"running":false}"#)),
            Some(false),
            "a selected runtime may report stopped with a non-zero CLI exit"
        );
        assert_eq!(
            runtime_status_value(&status_output(1, r#"{"running":true}"#)),
            None,
            "a non-zero positive status is never trusted"
        );
    }

    #[test]
    fn known_runtime_classifier_requires_listener_binary_identity() {
        assert_eq!(
            classify_known_runtime_state(Some(true), true, true, true),
            SandboxScienceState::RunningHealthy
        );
        assert_eq!(
            classify_known_runtime_state(Some(true), true, true, false),
            SandboxScienceState::Unknown
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_selection_requires_explicit_one_shot_cache_choice(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-bin-selection")?;
        let data_dir = root.join("home").join(".claude-science");
        let explicit_bin = root.join("explicit-claude-science");
        let cached_bin = data_dir.join("bin").join("claude-science");
        let app_bin = root.join("app-claude-science");

        write_fake_version_bin(&explicit_bin, 0o755, "fake-explicit-1")?;
        write_fake_version_bin(&cached_bin, 0o755, "fake-cache-1")?;
        write_fake_version_bin(&app_bin, 0o755, "fake-app-1")?;
        let preflight =
            science_runtime_preflight_for_paths(&data_dir, Some(&explicit_bin), &app_bin)?;
        assert_eq!(preflight["status"], "installed_ready");
        assert_eq!(preflight["selected_source"], "explicit");
        assert_eq!(preflight["selected_version"], "fake-explicit-1");
        assert_eq!(
            select_science_runtime_for_paths(
                &data_dir,
                Some(&explicit_bin),
                &app_bin,
                Some(CACHED_ONCE_CHOICE),
            )?
            .path,
            explicit_bin,
            "a valid explicit development override wins even if cache was authorized"
        );

        fs::set_permissions(&explicit_bin, fs::Permissions::from_mode(0o644))?;
        assert!(
            select_science_runtime_for_paths(&data_dir, Some(&explicit_bin), &app_bin, None)
                .is_err(),
            "an invalid explicit override must not fall through to sandbox or system Science"
        );

        let app =
            select_science_runtime_for_paths(&data_dir, None, &app_bin, Some(CACHED_ONCE_CHOICE))?;
        assert_eq!(
            app.path, app_bin,
            "the installed Science app always wins over an old cache"
        );
        assert_eq!(app.source, ScienceRuntimeSource::InstalledApp);
        assert_eq!(app.version.as_deref(), Some("fake-app-1"));

        let explicit_link = root.join("explicit-link");
        symlink(&app_bin, &explicit_link)?;
        assert!(
            select_science_runtime_for_paths(&data_dir, Some(&explicit_link), &app_bin, None)
                .is_err(),
            "an explicit symlink must fail closed"
        );

        let real_parent = root.join("real-parent");
        let linked_parent = root.join("linked-parent");
        let parent_bin = real_parent.join("claude-science");
        write_fake_version_bin(&parent_bin, 0o755, "fake-parent-1")?;
        symlink(&real_parent, &linked_parent)?;
        assert!(
            select_science_runtime_for_paths(
                &data_dir,
                Some(&linked_parent.join("claude-science")),
                &app_bin,
                None,
            )
            .is_err(),
            "an explicit path with a symlinked parent must fail closed"
        );

        write_fake_bin(&app_bin, 0o755)?;
        let failed_app_preflight = science_runtime_preflight_for_paths(&data_dir, None, &app_bin)?;
        assert_eq!(failed_app_preflight["status"], "cached_choice_required");
        assert!(
            select_science_runtime_for_paths(&data_dir, None, &app_bin, None)
                .expect_err("failed App preflight must offer, not implicitly use, cache")
                .contains("SCIENCE_RUNTIME_CHOICE_REQUIRED")
        );

        fs::set_permissions(&app_bin, fs::Permissions::from_mode(0o644))?;
        let preflight = science_runtime_preflight_for_paths(&data_dir, None, &app_bin)?;
        assert_eq!(preflight["status"], "cached_choice_required");
        assert_eq!(preflight["cached_version"], "fake-cache-1");
        let no_choice = select_science_runtime_for_paths(&data_dir, None, &app_bin, None)
            .expect_err("cache must not launch without one-shot authorization");
        assert!(no_choice.contains("SCIENCE_RUNTIME_CHOICE_REQUIRED"));
        let cached =
            select_science_runtime_for_paths(&data_dir, None, &app_bin, Some(CACHED_ONCE_CHOICE))?;
        assert_eq!(cached.path, cached_bin);
        assert_eq!(cached.source, ScienceRuntimeSource::CachedOnce);
        assert_eq!(cached.version.as_deref(), Some("fake-cache-1"));

        write_fake_bin(&cached_bin, 0o755)?;
        let preflight = science_runtime_preflight_for_paths(&data_dir, None, &app_bin)?;
        assert_eq!(preflight["status"], "missing");
        assert!(select_science_runtime_for_paths(
            &data_dir,
            None,
            &app_bin,
            Some(CACHED_ONCE_CHOICE),
        )
        .is_err());

        fs::set_permissions(&cached_bin, fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            science_runtime_preflight_for_paths(&data_dir, None, &app_bin)?["status"],
            "missing"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn locally_validated_updated_runtime_wins_over_app_and_is_fingerprint_bound(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-official-updated")?;
        let home = root.join("home");
        let data_dir = home.join(".csswitch/sandbox/home/.claude-science");
        let updated_bin = home.join(".claude-science/bin/claude-science");
        let app_bin = root.join("app-claude-science");
        let explicit_bin = root.join("explicit-claude-science");
        write_fake_version_bin(&updated_bin, 0o755, "fake-official-updated-v2")?;
        {
            let mut file = fs::OpenOptions::new().append(true).open(&updated_bin)?;
            file.write_all(b"\n#")?;
            file.write_all(&vec![b' '; super::MIN_SCIENCE_BINARY_SIZE as usize])?;
        }
        write_fake_version_bin(&app_bin, 0o755, "fake-app-v1")?;
        write_fake_version_bin(&explicit_bin, 0o755, "fake-explicit-v3")?;

        assert_eq!(
            official_updated_science_bin_for_home(&home, false).as_deref(),
            Some(updated_bin.as_path())
        );
        assert!(official_updated_science_bin_for_home(&home, true).is_none());

        let snapshot = official_updated_snapshot_for_home(
            &home,
            &root.join("runtime-snapshots/science"),
            false,
        )?
        .expect("updated snapshot");
        assert_ne!(snapshot, updated_bin);

        let preflight = science_runtime_preflight_for_paths_with_updated(
            &data_dir,
            None,
            Some(&snapshot),
            &app_bin,
        )
        .expect("the locally validated updater snapshot must pass preflight");
        assert_eq!(preflight["selected_source"], "official_updated");
        assert_eq!(preflight["selected_version"], "fake-official-updated-v2");

        let selected = select_science_runtime_for_paths_with_updated(
            &data_dir,
            None,
            Some(&snapshot),
            &app_bin,
            None,
        )
        .expect("the locally validated updater snapshot must be selected");
        assert_eq!(selected.path, snapshot);
        assert_eq!(selected.source, ScienceRuntimeSource::OfficialUpdated);
        assert!(runtime_identity_is_current(&selected));

        let explicit = select_science_runtime_for_paths_with_updated(
            &data_dir,
            Some(&explicit_bin),
            Some(&selected.path),
            &app_bin,
            None,
        )
        .expect("a valid explicit override must still take priority");
        assert_eq!(explicit.source, ScienceRuntimeSource::Explicit);

        write_fake_version_bin(&updated_bin, 0o755, "fake-official-updated-v3")?;
        assert!(
            runtime_identity_is_current(&selected),
            "an updater replacement must not change the running snapshot identity"
        );
        fs::set_permissions(&selected.path, fs::Permissions::from_mode(0o700))?;
        write_fake_version_bin(&selected.path, 0o755, "fake-snapshot-tampered")?;
        assert!(!runtime_identity_is_current(&selected));

        write_fake_bin(&selected.path, 0o755)?;
        let preflight_error = science_runtime_preflight_for_paths_with_updated(
            &data_dir,
            None,
            Some(&selected.path),
            &app_bin,
        )
        .expect_err("an invalid updater snapshot must not fall through to the App seed");
        assert!(preflight_error.contains("已拒绝回退旧 App"));
        let selection_error = select_science_runtime_for_paths_with_updated(
            &data_dir,
            None,
            Some(&selected.path),
            &app_bin,
            None,
        )
        .expect_err("an invalid updater snapshot must not select the App seed");
        assert!(selection_error.contains("已拒绝回退旧 App"));

        fs::set_permissions(
            home.join(".claude-science/bin"),
            fs::Permissions::from_mode(0o775),
        )?;
        assert!(official_updated_science_bin_for_home(&home, false).is_none());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn historical_updated_snapshots_remain_recoverable_after_source_replacement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-updated-snapshot-recovery")?;
        let home = root.join("home");
        let candidate = home.join(".claude-science/bin/claude-science");
        let snapshots = root.join("runtime-snapshots/science");
        write_padded_fake_version_bin(&candidate, "fake-updater-a")?;
        let snapshot_a =
            official_updated_snapshot_for_home(&home, &snapshots, false)?.expect("snapshot A");

        write_padded_fake_version_bin(&candidate, "fake-updater-b")?;
        let snapshot_b =
            official_updated_snapshot_for_home(&home, &snapshots, false)?.expect("snapshot B");
        assert_ne!(snapshot_a, snapshot_b);

        let unrelated = root.join("not-a-runtime");
        write_padded_fake_version_bin(&unrelated, "unrelated")?;
        assert_eq!(
            official_updated_snapshot_from_process_paths(
                &snapshots,
                &[unrelated, snapshot_a.clone()],
                false,
            )?,
            Some(snapshot_a),
            "recovery validates only the executable reported for the live listener"
        );
        assert_eq!(
            official_updated_snapshot_from_process_paths(
                &snapshots,
                std::slice::from_ref(&snapshot_b),
                false,
            )?,
            Some(snapshot_b)
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_root_symlink_is_rejected_without_mutating_target(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-snapshot-root-symlink")?;
        let target = root.join("target");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        let link = root.join("snapshot-root");
        symlink(&target, &link)?;

        assert!(secure_runtime_snapshot_root(&link).is_err());
        assert_eq!(
            fs::symlink_metadata(&target)?.permissions().mode() & 0o777,
            0o755
        );
        assert!(target.read_dir()?.next().is_none());

        let ancestor_target = root.join("ancestor-target");
        fs::create_dir(&ancestor_target)?;
        fs::set_permissions(&ancestor_target, fs::Permissions::from_mode(0o755))?;
        let linked_ancestor = root.join("linked-ancestor");
        symlink(&ancestor_target, &linked_ancestor)?;
        assert!(secure_runtime_snapshot_root(&linked_ancestor.join("science")).is_err());
        assert_eq!(
            fs::symlink_metadata(&ancestor_target)?.permissions().mode() & 0o777,
            0o755
        );
        assert!(ancestor_target.read_dir()?.next().is_none());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires CSSWITCH_REAL_SCIENCE_BIN plus expected version and SHA-256"]
    fn real_updated_runtime_candidate_is_eligible_without_reading_real_science_data(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source = std::env::var_os("CSSWITCH_REAL_SCIENCE_BIN")
            .map(std::path::PathBuf::from)
            .ok_or("CSSWITCH_REAL_SCIENCE_BIN is required")?;
        let expected_version = std::env::var("CSSWITCH_EXPECTED_SCIENCE_VERSION")?;
        let expected_sha256 = std::env::var("CSSWITCH_EXPECTED_SCIENCE_SHA256")?;
        let root = unique_temp_dir("science-real-updated")?;
        let home = root.join("home");
        let candidate = home.join(".claude-science/bin/claude-science");
        fs::create_dir_all(candidate.parent().expect("candidate parent"))?;
        fs::copy(&source, &candidate)?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))?;

        assert_eq!(
            official_updated_science_bin_for_home(&home, true).as_deref(),
            Some(candidate.as_path()),
            "the fixed updater executable should pass the same local identity guards used in production"
        );
        let snapshot = official_updated_snapshot_for_home(
            &home,
            &root.join("runtime-snapshots/science"),
            true,
        )?
        .expect("real updater snapshot");
        assert_ne!(snapshot, candidate);
        assert_eq!(fs::read(&snapshot)?, fs::read(&candidate)?);
        let expected_snapshot_name = format!("claude-science-{expected_sha256}");
        assert_eq!(
            snapshot.file_name().and_then(|name| name.to_str()),
            Some(expected_snapshot_name.as_str())
        );
        let isolated_home = root.join("isolated-home");
        fs::create_dir_all(&isolated_home)?;
        let output = std::process::Command::new(&snapshot)
            .arg("--version")
            .env("HOME", &isolated_home)
            .output()?;
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout)?.trim(),
            format!("claude-science {expected_version} (release, public)")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[ignore = "requires CSSWITCH_REAL_SCIENCE_APP_BIN plus expected version and SHA-256"]
    fn real_installed_app_seed_is_selected_without_mutating_data_dir(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app_bin = std::env::var_os("CSSWITCH_REAL_SCIENCE_APP_BIN")
            .map(std::path::PathBuf::from)
            .ok_or("CSSWITCH_REAL_SCIENCE_APP_BIN is required")?;
        let expected_version = std::env::var("CSSWITCH_EXPECTED_SCIENCE_VERSION")?;
        let expected_sha256 = std::env::var("CSSWITCH_EXPECTED_SCIENCE_SHA256")?;
        let root = unique_temp_dir("science-real-installed-app")?;
        let data_dir = root.join("home/.claude-science");
        fs::create_dir_all(&data_dir)?;
        let marker = data_dir.join("state-marker");
        fs::write(&marker, "keep-me")?;

        let selected = select_science_runtime_for_paths(&data_dir, None, &app_bin, None)?;
        assert_eq!(selected.source, ScienceRuntimeSource::InstalledApp);
        assert_eq!(selected.path, app_bin);
        let expected_version_output =
            format!("claude-science {expected_version} (release, public)");
        assert_eq!(
            selected.version.as_deref(),
            Some(expected_version_output.as_str())
        );
        assert_eq!(
            fingerprint_sha256_hex(&selected.fingerprint),
            expected_sha256
        );
        assert_eq!(fs::read_to_string(&marker)?, "keep-me");
        assert_eq!(data_dir.read_dir()?.count(), 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cached_runtime_symlink_is_never_offered_or_executed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-cache-symlink")?;
        let data_dir = root.join("home").join(".claude-science");
        let cached_bin = data_dir.join("bin").join("claude-science");
        let target = root.join("target-claude-science");
        let missing_app = root.join("missing-app-claude-science");
        write_fake_version_bin(&target, 0o755, "fake-target-1")?;
        fs::create_dir_all(cached_bin.parent().expect("cached parent"))?;
        symlink(&target, &cached_bin)?;

        let preflight = science_runtime_preflight_for_paths(&data_dir, None, &missing_app)?;
        assert_eq!(preflight["status"], "missing");
        assert!(select_science_runtime_for_paths(
            &data_dir,
            None,
            &missing_app,
            Some(CACHED_ONCE_CHOICE),
        )
        .is_err());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn replacing_installed_app_uses_new_version_without_mutating_cache_or_data_dir(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_temp_dir("science-app-upgrade")?;
        let data_dir = root.join("home").join(".claude-science");
        let cached_bin = data_dir.join("bin").join("claude-science");
        let app_bin = root.join("app-claude-science");
        let state_marker = data_dir.join("persistent-state.txt");
        write_fake_version_bin(&cached_bin, 0o755, "fake-cache-old")?;
        fs::write(&state_marker, "keep-me")?;
        let cached_before = fs::read(&cached_bin)?;

        write_fake_version_bin(&app_bin, 0o755, "fake-app-v1")?;
        let first = select_science_runtime_for_paths(&data_dir, None, &app_bin, None)?;
        assert_eq!(first.version.as_deref(), Some("fake-app-v1"));

        write_fake_version_bin(&app_bin, 0o755, "fake-app-v2")?;
        let second = select_science_runtime_for_paths(&data_dir, None, &app_bin, None)?;
        assert_eq!(second.version.as_deref(), Some("fake-app-v2"));
        assert_eq!(second.path, app_bin);
        assert_eq!(fs::read_to_string(&state_marker)?, "keep-me");
        assert_eq!(fs::read(&cached_bin)?, cached_before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn sandbox_home_is_writable_under_config_dir() {
        let h = sandbox_home();
        assert!(h.ends_with("sandbox/home"), "应以 sandbox/home 结尾：{h:?}");
        assert!(
            h.to_string_lossy().contains(".csswitch"),
            "应在 .csswitch 下：{h:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_url_falls_back_to_localhost_when_cli_absent() {
        let root = unique_temp_dir("science-url-fallback").unwrap();
        let bin = root.join("claude-science");
        write_fake_bin(&bin, 0o755).unwrap();
        let runtime = ScienceRuntimeIdentity {
            path: bin,
            source: ScienceRuntimeSource::InstalledApp,
            version: None,
            fingerprint: science_executable_fingerprint(&root.join("claude-science")).unwrap(),
        };
        assert_eq!(sandbox_url(8990, &runtime), "http://127.0.0.1:8990");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_identity_does_not_trust_health_when_cli_absent() {
        let root = unique_temp_dir("science-identity-fallback").unwrap();
        let bin = root.join("claude-science");
        write_fake_bin(&bin, 0o755).unwrap();
        let runtime = ScienceRuntimeIdentity {
            path: bin,
            source: ScienceRuntimeSource::InstalledApp,
            version: None,
            fingerprint: science_executable_fingerprint(&root.join("claude-science")).unwrap(),
        };
        assert!(!sandbox_running_ours(9, &runtime));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    fn status_output(code: i32, stdout: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn unique_temp_dir(name: &str) -> std::io::Result<std::path::PathBuf> {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "csswitch-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p)?;
        p.canonicalize()
    }

    #[cfg(unix)]
    fn write_fake_bin(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, "#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    #[cfg(unix)]
    fn write_padded_fake_version_bin(path: &std::path::Path, version: &str) -> std::io::Result<()> {
        write_fake_version_bin(path, 0o755, version)?;
        let mut file = fs::OpenOptions::new().append(true).open(path)?;
        file.write_all(b"\n#")?;
        file.write_all(&vec![b' '; super::MIN_SCIENCE_BINARY_SIZE as usize])?;
        Ok(())
    }

    #[cfg(unix)]
    fn write_fake_version_bin(
        path: &std::path::Path,
        mode: u32,
        version: &str,
    ) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            path,
            format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then printf '%s\\n' '{}'; exit 0; fi\nexit 0\n",
                version
            ),
        )?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    #[cfg(unix)]
    fn write_counted_version_bin(
        path: &std::path::Path,
        count: &std::path::Path,
        version: &str,
    ) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            path,
            format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then count=$(cat '{}' 2>/dev/null || echo 0); count=$((count + 1)); printf '%s' \"$count\" > '{}'; printf '%s\\n' '{}'; exit 0; fi\nexit 0\n",
                count.display(),
                count.display(),
                version
            ),
        )?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
    }
}
