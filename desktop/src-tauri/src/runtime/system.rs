use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use tauri::{Manager, Runtime};

use crate::config;

const OPERATION_LOG_MAX_BYTES: u64 = 1_048_576;
#[cfg(all(not(test), feature = "acceptance-build"))]
const ACCEPTANCE_OPEN_BIN_ENV: &str = "CSSWITCH_ACCEPTANCE_OPEN_BIN";
#[cfg(test)]
const TEST_OPEN_BIN_ENV: &str = "CSSWITCH_TEST_OPEN_BIN";

/// Locate the CSSwitch repository root containing the Rust gateway and scripts.
/// Prefer `CSSWITCH_REPO`; otherwise walk upwards from the executable path.
pub(crate) fn repo_root() -> Option<PathBuf> {
    let gateway_marker = Path::new("desktop/gateway/Cargo.toml");
    let script_marker = Path::new("scripts/doctor.sh");
    if let Some(r) = std::env::var_os("CSSWITCH_REPO") {
        if let Ok(p) = std::fs::canonicalize(PathBuf::from(r)) {
            if p.join(gateway_marker).is_file() && p.join(script_marker).is_file() {
                return Some(p);
            }
        }
    }
    // Only walk from the executable path. current_dir is intentionally ignored:
    // the launch directory can be influenced, and must not select a foreign
    // proxy script that receives provider keys through env.
    if let Ok(exe) = std::env::current_exe() {
        let mut dir: Option<&Path> = exe.parent();
        while let Some(d) = dir {
            if d.join(gateway_marker).is_file() && d.join(script_marker).is_file() {
                return Some(d.to_path_buf());
            }
            dir = d.parent();
        }
    }
    None
}

/// Locate the asset root containing packaged scripts.
/// Packaged apps use `Contents/Resources`; dev builds fall back to repo root.
pub(crate) fn asset_root<R: Runtime>(app: &tauri::AppHandle<R>) -> Option<PathBuf> {
    let marker = Path::new("scripts/doctor.sh");
    if let Ok(res) = app.path().resource_dir() {
        if res.join(marker).is_file() {
            return Some(res);
        }
    }
    repo_root()
}

pub(crate) fn log_path(name: &str) -> PathBuf {
    config::default_dir().join("logs").join(name)
}

/// Open/truncate a child-process log, ensuring parent dir is 0700 and file is 0600.
pub(crate) fn open_log(name: &str) -> std::io::Result<std::fs::File> {
    let p = log_path(name);
    if let Some(parent) = p.parent() {
        config::assert_not_symlink(parent)?;
        std::fs::create_dir_all(parent)?;
        let _ = crate::platform::make_dir_private(parent);
    }
    config::assert_not_symlink(&p)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(crate::platform::no_follow_flags());
    }
    let f = options.open(&p)?;
    // unix：显式 0600 兜底；Windows：确保未带只读位（默认 ACL 已私有）。
    let _ = crate::platform::set_path_mode(&p, 0o600);
    Ok(f)
}

/// Append a redaction-safe operation event to `operation.log`.
/// Callers must pass only coarse stage metadata, never keys, secrets, base URLs, or request bodies.
pub(crate) fn append_operation_log(line: &str) {
    let p = log_path("operation.log");
    let Some(parent) = p.parent() else {
        return;
    };
    if config::assert_not_symlink(parent).is_err() || config::assert_not_symlink(&p).is_err() {
        return;
    }
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let _ = crate::platform::make_dir_private(parent);
    rotate_operation_log_if_needed(&p, line.len() as u64 + 1);
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(crate::platform::no_follow_flags());
    }
    let mut f = match options.open(&p) {
        Ok(f) => f,
        Err(_) => return,
    };
    let _ = crate::platform::set_path_mode(&p, 0o600);
    let _ = writeln!(f, "{line}");
}

fn operation_log_archive_path(p: &Path) -> PathBuf {
    p.with_file_name("operation.log.1")
}

fn should_rotate_operation_log(current_bytes: u64, incoming_bytes: u64) -> bool {
    current_bytes.saturating_add(incoming_bytes) > OPERATION_LOG_MAX_BYTES
}

fn rotate_operation_log_if_needed(p: &Path, incoming_bytes: u64) {
    let Ok(md) = std::fs::metadata(p) else {
        return;
    };
    if !should_rotate_operation_log(md.len(), incoming_bytes) {
        return;
    }
    let archive = operation_log_archive_path(p);
    if config::assert_not_symlink(&archive).is_err() {
        return;
    }
    let _ = std::fs::remove_file(&archive);
    if std::fs::rename(p, &archive).is_ok() {
        let _ = crate::platform::set_path_mode(&archive, 0o600);
    }
}

/// Redact a path-secret before returning child-process log tails to the frontend.
pub(crate) fn redact(s: &str, secret: &str) -> String {
    if secret.is_empty() {
        s.to_string()
    } else {
        s.replace(secret, "****")
    }
}

pub(crate) fn tail_file(path: &Path, max: usize) -> String {
    match std::fs::read(path) {
        Ok(b) => {
            let start = b.len().saturating_sub(max);
            String::from_utf8_lossy(&b[start..]).trim().to_string()
        }
        Err(_) => String::new(),
    }
}

pub(crate) fn kill_child(slot: &mut Option<Child>) {
    if let Some(mut c) = slot.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// Resolve the browser opener. `None` means "use the system opener"
/// (`platform::open_url`: macOS `open`, Linux `xdg-open`, Windows ShellExecute).
/// Only an explicit test/Acceptance override returns a validated executable.
fn select_browser_open_binary(
    override_bin: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>, String> {
    let Some(raw) = override_bin else {
        return Ok(None);
    };
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err("Acceptance 测试 opener 必须是绝对路径".into());
    }
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|_| "Acceptance 测试 opener 不可访问".to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("Acceptance 测试 opener 必须是普通非符号链接文件".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err("Acceptance 测试 opener 不可执行".into());
        }
    }
    #[cfg(windows)]
    {
        if !crate::platform::is_executable_file(&path) {
            return Err("Acceptance 测试 opener 不可执行".into());
        }
    }
    Ok(Some(path))
}

fn browser_open_binary() -> Result<Option<PathBuf>, String> {
    #[cfg(test)]
    let override_bin = std::env::var_os(TEST_OPEN_BIN_ENV);
    #[cfg(all(not(test), feature = "acceptance-build"))]
    let override_bin = std::env::var_os(ACCEPTANCE_OPEN_BIN_ENV);
    #[cfg(all(not(test), not(feature = "acceptance-build")))]
    let override_bin = None;
    select_browser_open_binary(override_bin)
}

pub(crate) fn open_in_browser(url: &str) -> Result<(), String> {
    // Formal and manually launched Acceptance builds default to the fixed
    // system opener. Only an explicit test-only absolute executable override
    // can divert an Acceptance/test run into a fake evidence recorder.
    match browser_open_binary()? {
        Some(open_bin) => {
            let st = Command::new(&open_bin)
                .arg(url)
                .status()
                .map_err(|e| format!("打开浏览器失败：{e}"))?;
            if !st.success() {
                return Err(format!("open 非零退出（{:?}）", st.code()));
            }
            Ok(())
        }
        None => crate::platform::open_url(url).map_err(|e| format!("打开浏览器失败：{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        operation_log_archive_path, redact, select_browser_open_binary, should_rotate_operation_log,
    };
    use std::path::Path;

    #[test]
    fn browser_open_defaults_to_system_binary_and_rejects_relative_override() {
        // 无覆盖 → 走系统 opener（platform::open_url），不再指向固定路径。
        assert_eq!(select_browser_open_binary(None).unwrap(), None);
        assert!(select_browser_open_binary(Some("open".into())).is_err());
    }

    #[test]
    fn redact_replaces_nonempty_secret_only() {
        assert_eq!(redact("abc secret abc", "secret"), "abc **** abc");
        assert_eq!(redact("abc", ""), "abc");
    }

    #[test]
    fn operation_log_rotation_threshold_counts_incoming_line() {
        assert!(!should_rotate_operation_log(1_048_575, 1));
        assert!(should_rotate_operation_log(1_048_575, 2));
        assert!(should_rotate_operation_log(u64::MAX, 1));
    }

    #[test]
    fn operation_log_archive_is_single_sibling_file() {
        assert_eq!(
            operation_log_archive_path(Path::new("/tmp/operation.log")),
            Path::new("/tmp/operation.log.1")
        );
    }
}
