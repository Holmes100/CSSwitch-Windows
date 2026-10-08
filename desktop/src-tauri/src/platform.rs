//! 跨平台系统原语层。所有平台相关操作（HOME 解析、POSIX mode、文件身份、
//! no-follow 打开、flock、原子 no-replace rename、进程发现/终止、打开
//! URL/目录/文件管理器、子进程进程组）都必须经由本模块，禁止业务代码直接
//! 触碰 `std::os::unix` / `windows-sys`。
//!
//! Windows 语义映射（有意为之的弱化，其余语义保持一致）：
//!   - POSIX mode 不存在于 NTFS：`metadata_mode()` 合成 0o700（目录）/
//!     0o600（普通文件）/ 0o500（只读文件），使 `mode & 0o077 != 0` 类校验在
//!     Windows 上保持通过；`set_path_mode()` 只映射只读位。
//!   - O_NOFOLLOW → `FILE_FLAG_OPEN_REPARSE_POINT` + 打开后 `symlink_metadata`
//!     复查拒绝；目录句柄 → `FILE_FLAG_BACKUP_SEMANTICS`。
//!   - `flock` → `LockFileEx`（整文件、立即失败）。
//!   - rename-no-replace → `MoveFileExW` 不带 REPLACE（目标存在即失败，原子）。
//!   - dev/ino → `GetFileInformationByHandle` 的 (volume serial, file index)。
//!   - SIGTERM/SIGKILL → `TerminateProcess`；杀整树 → `taskkill /T /F`。

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 用户 HOME：unix 读 `HOME`；Windows 回退 `USERPROFILE`。
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|value| !value.as_os_str().is_empty())
}

/// 为子进程注入隔离 HOME。Windows 上只覆盖 `HOME`、保留真实 `USERPROFILE`：
/// Science 与原生 Windows API（SHGetKnownFolderPath、沙箱 fence、已知目录
/// 解析）依赖真实用户 profile，覆盖它会让 `url`/`status` 子进程失败（静默
/// 回退到无认证 URL）或沙箱 provisioning 报错。数据隔离由显式 `--data-dir`
/// 参数保证。
pub fn env_isolated_home(command: &mut Command, home: &Path) {
    command.env("HOME", home);
    #[cfg(windows)]
    let _ = home;
}

/// 配置受管子进程：unix 建独立进程组（便于整组终止）；Windows 加
/// CREATE_NO_WINDOW 防止 GUI 进程 spawn 控制台程序时闪黑窗。
pub fn configure_spawn(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
}

/// Windows：仅抑制子进程控制台（CREATE_NO_WINDOW），不改变 unix 行为。
/// GUI 主进程（windows_subsystem="windows"，无控制台）spawn console 子系统
/// 程序时若不加此标志，子进程会各自弹出黑色命令行框。
pub fn hide_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = command;
    }
}

// ---------- 文件身份与 mode ----------

/// dev/ino/nlink/mode 的跨平台等价物。比较相等即视为同一文件。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    /// 合成 mode（unix 为真实 mode & 0o7777；Windows 为合成值，见模块注释）。
    pub mode: u32,
}

/// 合成/读取 POSIX mode。Windows 上从只读位合成，保证 mode 校验语义可用。
pub fn metadata_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o7777
    }
    #[cfg(windows)]
    {
        let base = if metadata.is_dir() { 0o700 } else { 0o600 };
        if metadata.permissions().readonly() {
            base & !0o222
        } else {
            base
        }
    }
}

// Windows 上暂无调用方；作为轻量包装保留。
#[allow(dead_code)]
pub fn path_mode(path: &Path) -> io::Result<u32> {
    Ok(metadata_mode(&fs::symlink_metadata(path)?))
}

/// 近似 chmod：unix 真实设置；Windows 只映射只读位（写位全空 → 置只读）。
pub fn set_path_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let metadata = fs::symlink_metadata(path)?;
        let mut permissions = metadata.permissions();
        let readonly = mode & 0o200 == 0;
        if permissions.readonly() != readonly {
            permissions.set_readonly(readonly);
            fs::set_permissions(path, permissions)?;
        }
        Ok(())
    }
}

/// 新建文件用的 0600 权限对象（仅 unix 存在；Windows 用 [`make_file_private`]）。
#[cfg(unix)]
pub fn secure_file_permissions() -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    fs::Permissions::from_mode(0o600)
}

/// 目录 0700 权限对象（仅 unix 存在；Windows 用 [`make_dir_private`]）。
#[cfg(unix)]
pub fn secure_dir_permissions() -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    fs::Permissions::from_mode(0o700)
}

/// 把新建文件收紧为 0600 等价：unix chmod 0600；Windows 默认 ACL 已仅当前
/// 用户可读，只需确保未带只读位。
pub fn make_file_private(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        file.set_permissions(secure_file_permissions())
    }
    #[cfg(windows)]
    {
        let mut permissions = file.metadata()?.permissions();
        if permissions.readonly() {
            // 清只读位是本分支唯一目的（unix 走 chmod 分支），lint 的跨平台
            // 担忧在此不成立。
            #[allow(clippy::permissions_set_readonly_false)]
            {
                permissions.set_readonly(false);
            }
            file.set_permissions(permissions)?;
        }
        Ok(())
    }
}

/// 把目录收紧为 0700 等价：unix chmod 0700；Windows 默认 ACL 已私有，无需处理。
pub fn make_dir_private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, secure_dir_permissions())
    }
    #[cfg(windows)]
    {
        let _ = path;
        Ok(())
    }
}

/// 文件属主是否为当前用户。Windows 无 POSIX uid，恒真。
pub fn file_owner_is_current(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.uid() == unsafe { libc::geteuid() }
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        true
    }
}

pub fn identity_of_file(file: &File) -> io::Result<FileIdentity> {
    identity_from_file_and_mode(file, metadata_mode(&file.metadata()?))
}

pub fn identity_of_path(path: &Path) -> io::Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata_mode(&metadata);
    identity_from_path_and_mode(path, mode)
}

#[cfg(unix)]
fn identity_from_file_and_mode(file: &File, mode: u32) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        nlink: metadata.nlink(),
        mode,
    })
}

#[cfg(unix)]
fn identity_from_path_and_mode(path: &Path, mode: u32) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    Ok(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        nlink: metadata.nlink(),
        mode,
    })
}

#[cfg(windows)]
fn identity_from_file_and_mode(file: &File, mode: u32) -> io::Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    by_handle_identity(handle, mode)
}

#[cfg(windows)]
fn identity_from_path_and_mode(path: &Path, mode: u32) -> io::Result<FileIdentity> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() {
        return Ok(FileIdentity { dev: 0, ino: 0, nlink: 1, mode });
    }
    let identity = by_handle_identity(handle, mode);
    unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
    identity
}

#[cfg(windows)]
fn by_handle_identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
    mode: u32,
) -> io::Result<FileIdentity> {
    use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;
    let mut info = unsafe { std::mem::zeroed::<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        dev: info.dwVolumeSerialNumber as u64,
        ino: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        nlink: info.nNumberOfLinks as u64,
        mode,
    })
}

/// 目录 fsync。unix 打开只读目录 fd 即可 fsync；Windows 的
/// FlushFileBuffers 需要写权限，必须走 [`open_dir`] 的读写句柄。
pub fn sync_dir(path: &Path) -> io::Result<()> {
    open_dir(path)?.sync_all()
}

// ---------- 随机字节 ----------

/// 密码学安全随机字节。unix 读 `/dev/urandom`（保留原 fail-closed 语义）；
/// Windows 用 `BCryptGenRandom`（系统首选 RNG）。
pub fn rand_bytes(buffer: &mut [u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = File::open("/dev/urandom")?;
        f.read_exact(buffer)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::BCryptGenRandom;
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x2；hAlgorithm 为 NULL 时必须带此标志。
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if status < 0 {
            return Err(io::Error::other(format!("BCryptGenRandom 失败：0x{status:08x}")));
        }
        Ok(())
    }
}

// ---------- 打开语义 ----------

/// 规范化路径（解析符号链接与 `..`）。Windows 的 `Path::canonicalize` 返回
/// `\\?\C:\...` 扩展前缀形式，与普通形式路径比较永不相等；本助手剥离该前缀
/// （UNC 的 `\\?\UNC\server\share` 还原为 `\\server\share`），使返回值与
/// 常规构造的路径可比较。业务代码禁止直接调用 `Path::canonicalize` 做路径
/// 相等性判断。
pub fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    let canonical = path.canonicalize()?;
    #[cfg(windows)]
    {
        let text = canonical.as_os_str().to_string_lossy();
        if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
            return Ok(PathBuf::from(format!(r"\\{unc}")));
        }
        if let Some(stripped) = text.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(stripped.to_string()));
        }
    }
    Ok(canonical)
}

/// Windows 扩展长度路径（`\\?\` 前缀），绕过 MAX_PATH=260 限制；其它平台
/// 原样返回。输入须为绝对路径。深层快照树的删除必须走这里，否则刚好压线
/// 的路径会在改名（如加 `.deleting` 后缀）后越过 260 上限，报
/// ERROR_INVALID_HANDLE / ERROR_PATH_NOT_FOUND 等误导性错误。
pub fn extend_max_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.as_os_str().to_string_lossy();
        if text.starts_with(r"\\?\UNC\") || text.starts_with(r"\\?\") {
            return path.to_path_buf();
        }
        if let Some(unc) = text.strip_prefix(r"\\") {
            return PathBuf::from(format!(r"\\?\UNC\{unc}"));
        }
        PathBuf::from(format!(r"\\?\{text}"))
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

/// OpenOptions custom_flags：拒绝跟随符号链接 + 关闭时即释放（unix）。
#[cfg(unix)]
pub fn no_follow_flags() -> i32 {
    libc::O_NOFOLLOW | libc::O_CLOEXEC
}

/// Windows 等价：打开 reparse point 本身（不跟随）；调用方需以
/// `symlink_metadata` 复查后拒绝符号链接。
#[cfg(windows)]
pub fn no_follow_flags() -> u32 {
    windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT
}

/// 打开目录句柄（unix O_DIRECTORY；Windows FILE_FLAG_BACKUP_SEMANTICS），
/// 用于身份锚定与目录 fsync。目录是符号链接时拒绝。
pub fn open_dir(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // GENERIC_WRITE 是 FlushFileBuffers（目录 fsync 等价）的前提；
        // unix 上只读 fd fsync 目录合法，Windows 不是。
        // FILE_SHARE_DELETE：句柄存活期间必须允许后续对目录的改名/删除——
        // 权限快照的"改名为墓碑再删除"清理流程正依赖这一点（句柄由
        // AuthorityTreeSnapshot 持有直到 restore 结束）。
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
            )
            .custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                    | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            )
            .open(path)?;
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("拒绝符号链接目录：{}", path.display()),
            ));
        }
        Ok(file)
    }
}

// ---------- flock ----------

/// 独占、立即失败（LOCK_EX|LOCK_NB）的整文件锁。
// 运行时暂无调用方（跨平台测试在用），保留。
#[allow(dead_code)]
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        };
        use windows_sys::Win32::System::IO::OVERLAPPED;
        let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle() as _,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// 释放 [`lock_exclusive`]。
#[allow(dead_code)]
pub fn unlock(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
        use windows_sys::Win32::System::IO::OVERLAPPED;
        let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
        let ok = unsafe {
            UnlockFileEx(file.as_raw_handle() as _, 0, u32::MAX, u32::MAX, &mut overlapped)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

// ---------- 原子提交原语 ----------

/// no-replace 硬链接发布：目标已存在即失败（std 的 hard_link 在两个平台上
/// 都具有该语义：unix linkat EEXIST；Windows CreateHardLinkW ERROR_FILE_EXISTS）。
pub fn link_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::hard_link(from, to)
}

/// 原子 rename 且不覆盖已存在目标。
pub fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
        if fs::symlink_metadata(to).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("目标已存在：{}", to.display()),
            ));
        }
        let from_wide: Vec<u16> =
            from.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let to_wide: Vec<u16> = to.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let ok = unsafe {
            MoveFileExW(from_wide.as_ptr(), to_wide.as_ptr(), MOVEFILE_WRITE_THROUGH)
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(80) | Some(183)) {
                // 80 = ERROR_FILE_EXISTS, 183 = ERROR_ALREADY_EXISTS。
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, error));
            }
            return Err(error);
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        // unix rename(2) 会覆盖既有目标；先做 symlink_metadata 前置检查。
        // 目录场景无法 link+unlink，此窗口可接受（macos/linux 关键路径各自
        // 使用 renameatx_np / renameat2 的模块内实现不受影响）。
        if fs::symlink_metadata(to).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("目标已存在：{}", to.display()),
            ));
        }
        fs::rename(from, to)
    }
}

// ---------- 进程 ----------

/// 终止单个进程：unix SIGTERM（graceful）或 SIGKILL；Windows 一律 TerminateProcess。
pub fn terminate_pid(pid: u32, graceful: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        let signal = if graceful { libc::SIGTERM } else { libc::SIGKILL };
        if unsafe { libc::kill(pid as i32, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };
        let _ = graceful;
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let ok = unsafe { TerminateProcess(handle, 1) };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// 终止整棵进程树（版本探测子进程、沙箱 daemon 的兜底回收）。
pub fn kill_tree(pid: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        // 进程组 id == leader pid（configure_spawn 的 process_group(0)）。
        if unsafe { libc::kill(-(pid as i32), libc::SIGKILL) } == 0 {
            return Ok(());
        }
        terminate_pid(pid, false)
    }
    #[cfg(windows)]
    {
        // 根进程已退出（版本探测子进程的正常路径）→ 与 unix killpg 返回
        // ESRCH 同义：没有东西可杀即为成功。否则后续 taskkill/TerminateProcess
        // 都会因 pid 不存在而失败，把"干净退出"误判成清理失败。
        if process_has_exited(pid).unwrap_or(false) {
            return Ok(());
        }
        let mut command = Command::new("taskkill");
        command
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        configure_spawn(&mut command);
        let status = command.status()?;
        if status.success() {
            return Ok(());
        }
        // 树根可能刚退出（探测竞态）；单进程终止兜底，pid 已消失同样视为成功。
        match terminate_pid(pid, false) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(87) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// 非阻塞探测进程是否已退出（不收割）。
pub fn process_has_exited(pid: u32) -> io::Result<bool> {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            // 由 libc 提供；显式声明以使用 WNOWAIT（不收割）。
            fn waitid(
                idtype: libc::idtype_t,
                id: libc::id_t,
                infop: *mut libc::siginfo_t,
                options: libc::c_int,
            ) -> libc::c_int;
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(true);
        }
        if error.raw_os_error() == Some(libc::EINTR) {
            return Ok(false);
        }
        Err(error)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
        use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid)
        };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(87) {
                // ERROR_INVALID_PARAMETER：进程不存在 → 已退出。
                return Ok(true);
            }
            return Err(error);
        }
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        unsafe { CloseHandle(handle) };
        Ok(wait == WAIT_OBJECT_0)
    }
}

/// 监听指定 TCP 端口的进程 PID 列表（lsof / netstat 等价）。
pub fn listening_pids(port: u16) -> io::Result<Vec<u32>> {
    #[cfg(unix)]
    {
        let mut command = Command::new("/usr/sbin/lsof");
        command.args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"]);
        configure_spawn(&mut command);
        let output = command.output()?;
        if !output.status.success() {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(text
            .split_whitespace()
            .filter_map(|token| token.parse::<u32>().ok())
            .collect())
    }
    #[cfg(windows)]
    {
        let mut command = Command::new("netstat");
        command.args(["-ano", "-p", "tcp"]);
        configure_spawn(&mut command);
        let output = command.output()?;
        if !output.status.success() {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let needle = format!(":{port}");
        let mut pids = Vec::new();
        for line in text.lines() {
            let columns: Vec<&str> = line.split_whitespace().collect();
            // Proto  Local  Foreign  State  PID
            if columns.len() != 5 || !columns[0].eq_ignore_ascii_case("tcp") {
                continue;
            }
            if !columns[3].eq_ignore_ascii_case("LISTENING") {
                continue;
            }
            let local = columns[1];
            let hits_port = local
                .rsplit_once(':')
                .is_some_and(|(_, port_text)| port_text == port.to_string());
            let ends_with_port = local.ends_with(&needle);
            if hits_port || ends_with_port {
                if let Ok(pid) = columns[4].parse::<u32>() {
                    if !pids.contains(&pid) {
                        pids.push(pid);
                    }
                }
            }
        }
        Ok(pids)
    }
}

/// 进程可执行映像路径（unix 取 txt 文本路径；Windows 取主模块映像路径）。
pub fn process_text_paths(pid: u32) -> Option<Vec<PathBuf>> {
    #[cfg(unix)]
    {
        let mut command = Command::new("/usr/sbin/lsof");
        command.args(["-a", "-p", &pid.to_string(), "-d", "txt", "-Fn"]);
        configure_spawn(&mut command);
        let output = command.output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let paths: Vec<PathBuf> = text
            .lines()
            .filter_map(|line| line.strip_prefix('n'))
            .map(PathBuf::from)
            .collect();
        if paths.is_empty() {
            None
        } else {
            Some(paths)
        }
    }
    #[cfg(windows)]
    {
        process_image_path(pid).map(|path| vec![path])
    }
}

#[cfg(windows)]
fn process_image_path(pid: u32) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buffer = [0u16; 1024];
    let mut length = buffer.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut length)
    };
    unsafe { CloseHandle(handle) };
    if ok == 0 || length == 0 {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize])))
}

/// 稳定的「进程启动时刻」身份串（lstart 等价；仅要求同进程稳定、跨启动不同）。
pub fn process_start_identity(pid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let mut command = Command::new("/bin/ps");
        command.args(["-p", &pid.to_string(), "-o", "lstart="]);
        configure_spawn(&mut command);
        let output = command.output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let mut creation = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let ok = unsafe {
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
        };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return None;
        }
        // FILETIME：1601-01-01 起 100ns。同一进程启动后不变，可作身份。
        let ticks = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
        Some(format!("win-filetime-{ticks}"))
    }
}

// ---------- Shell / 桌面集成 ----------

/// 用系统默认浏览器打开 URL。
pub fn open_url(url: &str) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("/usr/bin/open");
        command.arg(url);
        configure_spawn(&mut command);
        command.status().map(|_| ())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        configure_spawn(&mut command);
        command.status().map(|_| ())
    }
    #[cfg(windows)]
    {
        shell_execute_open(url)
    }
}

/// 在文件管理器中显示文件/目录并选中。
// Windows 上 Skill 管理器的 reveal 链路未接线；两端实现完整，保留。
#[allow(dead_code)]
pub fn reveal_in_file_manager(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("/usr/bin/open");
        command.args(["-R", &path.display().to_string()]);
        configure_spawn(&mut command);
        command.status().map(|_| ())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let mut command = Command::new("xdg-open");
        command.arg(path.parent().unwrap_or(path));
        configure_spawn(&mut command);
        command.status().map(|_| ())
    }
    #[cfg(windows)]
    {
        let mut command = Command::new("explorer");
        // /select, 后必须直接跟路径（含逗号），explorer 自己解析。
        command.arg(format!("/select,{}", path.display()));
        configure_spawn(&mut command);
        // explorer 对已存在的目标也常返回非零码，不能据 status 判失败。
        command.status().map(|_| ())
    }
}

/// 用系统默认程序打开路径（目录 → 文件管理器）。
pub fn open_path(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("/usr/bin/open");
        command.arg(path);
        configure_spawn(&mut command);
        command.status().map(|_| ())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let mut command = Command::new("xdg-open");
        command.arg(path);
        configure_spawn(&mut command);
        command.status().map(|_| ())
    }
    #[cfg(windows)]
    {
        shell_execute_open(&path.display().to_string())
    }
}

#[cfg(windows)]
fn shell_execute_open(target: &str) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let wide: Vec<u16> = std::ffi::OsStr::new(target)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = "open\0".encode_utf16().collect();
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // SW_SHOWNORMAL
        )
    };
    // 返回值 > 32 表示成功。
    if result as usize > 32 {
        Ok(())
    } else {
        Err(io::Error::other(
            format!("ShellExecuteW 打开失败：{target}"),
        ))
    }
}

/// 判断路径是否为可直接执行的普通文件（不可为符号链接）。
pub fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(windows)]
    {
        matches!(
            path.extension()
                .and_then(|extension| extension.to_str())
                .map(|extension| extension.to_ascii_lowercase())
                .as_deref(),
            Some("exe" | "com" | "bat" | "cmd")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_dir_falls_back_to_userprofile() {
        // 两个环境变量至少存在其一（CI/桌面环境均成立）。
        let home = home_dir();
        assert!(home.is_some());
        assert!(home.unwrap().file_name().is_some());
    }

    #[test]
    fn identity_is_stable_across_two_opens() {
        let dir = std::env::temp_dir().join(format!("csswitch-platform-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("identity.bin");
        fs::write(&file, b"identity").unwrap();
        let first = identity_of_path(&file).unwrap();
        let second = identity_of_path(&file).unwrap();
        assert_eq!(first, second);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rename_no_replace_rejects_existing_target() {
        let dir = std::env::temp_dir().join(format!("csswitch-platform-r-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let from = dir.join("from.txt");
        let to = dir.join("to.txt");
        fs::write(&from, b"a").unwrap();
        fs::write(&to, b"b").unwrap();
        let error = rename_no_replace(&from, &to).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&to).unwrap(), b"b");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rename_no_replace_moves_when_target_absent() {
        let dir = std::env::temp_dir().join(format!("csswitch-platform-r2-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let from = dir.join("from.txt");
        let to = dir.join("to.txt");
        fs::write(&from, b"a").unwrap();
        rename_no_replace(&from, &to).unwrap();
        assert!(to.exists() && !from.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lock_exclusive_conflicts_and_unlocks() {
        let dir = std::env::temp_dir().join(format!("csswitch-platform-l-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lock.txt");
        let first = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .unwrap();
        let second = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .unwrap();
        lock_exclusive(&first).unwrap();
        assert!(lock_exclusive(&second).is_err());
        unlock(&first).unwrap();
        lock_exclusive(&second).unwrap();
        drop(first);
        drop(second);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn listening_pids_on_free_port_is_empty_or_ok() {
        // 只验证调用形态；端口 1 极少有监听者。
        assert!(listening_pids(1).is_ok());
    }

    #[test]
    fn open_dir_rejects_missing() {
        assert!(open_dir(Path::new("Z:/definitely/not/here")).is_err());
    }
}
