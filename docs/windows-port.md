# CSSwitch Windows 适配说明

本文档描述 v0.8.4 源码树的 Windows（x86_64-pc-windows-msvc）移植：范围、平台语义映射、构建方法与已知边界。

## 支持状态总览

| 能力 | Windows 状态 | 说明 |
| --- | --- | --- |
| 桌面 App（Tauri 2 + WebView2） | 可用 | UI、配置管理、profile CRUD 全功能。 |
| 第三方模型接入（Gateway 代理链路） | 可用 | Rust gateway 全量跨平台（含全部单测编译通过）。 |
| 隔离 Science 沙箱 | 可用（依赖 Science Windows 版） | 沙箱启动/停止已原生 Rust 化；前置条件是本机安装了提供 `claude-science.exe` 的官方 Claude Science。 |
| Claude Science 探测 | 已适配 | 按候选路径探测 `claude-science.exe`；未安装时引导下载页。 |
| 官方模式（打开真实 Science） | 已适配 | 直接启动探测到的可执行文件。 |
| Skill 导入/管理（本地包） | 可用 | skill-package crate 跨平台。 |
| Skill 通过 Science 安装（bridge） | 可用 | bridge 宿主与连接器注册均已移植 Windows；连接器（tool-results ro 根内 exe 副本）在真机 daemon 日志中多次 spawn + stdio 握手成功。端到端"对话安装一个真实 Skill"完整流程尚待一次实测。 |
| Codex 实验功能 | 已移除 | 应用层面已整体删除（gateway/桌面端/前端/配置 schema）；旧配置中的 Codex profile 与相关设置在加载时安全清除并提示。 |
| doctor 自检 | 已适配 | Windows 用原生只读检查替代 `scripts/doctor.sh`。 |
| 日志/文件管理器定位 | 已适配 | `explorer /select,`。 |

### 真机交付状态（2026-10-02）

一键开始全链路（沙箱准备 → 代登录虚拟账号 → attach → 打开 Science）已多次真机成功；chat、第三方模型链路、web_search、Science 内置文献类 MCP 连接器（复用官方应用自带 conda，`config.toml [paths] conda_home` 注入）均真机验证可用。Skill 安装桥连接器 `csswitch-skill-installer` 于 10-01/10-02 daemon 日志中多次 `connected via stdio`（tool-results ro 授权根内 exe 副本方案生效）。App 本体为 GUI 子系统（debug 构建也不弹控制台），所有受管子进程带 `CREATE_NO_WINDOW`。三个 crate 在 Windows 上 `cargo test` 全绿（src-tauri 295 / gateway 131 / skill-package 46），`cargo clippy --all-targets` 零警告。

## 平台语义映射（`desktop/src-tauri/src/platform.rs`）

所有平台原语集中在 `platform.rs`，业务代码不直接触碰 `std::os::unix` / `windows-sys`：

| Unix 语义 | Windows 实现 | 备注 |
| --- | --- | --- |
| `$HOME` | `HOME` → `USERPROFILE` 回退；子进程同时注入两者 | |
| POSIX mode（0600/0700 校验） | 合成 mode：目录 `0o700`、文件 `0o600`、只读文件 `0o500` | mode 校验逻辑保持通过；`chmod` 只映射只读位。 |
| dev/ino 文件身份 | `GetFileInformationByHandle`（volume serial + file index） | |
| `O_NOFOLLOW` | `FILE_FLAG_OPEN_REPARSE_POINT` + 打开后 `symlink_metadata` 复查拒绝 | std 无 openat，路径锚定的 TOCTOU 窗口是接受的弱化。 |
| 目录句柄（O_DIRECTORY） | `FILE_FLAG_BACKUP_SEMANTICS` | 支持 `sync_all`（FlushFileBuffers）。 |
| `flock(LOCK_EX\|LOCK_NB)` | `LockFileEx` 整文件、立即失败 | |
| rename 不覆盖 | `MoveFileExW` 不带 `MOVEFILE_REPLACE_EXISTING`（原子） | |
| 硬链接 no-clobber 发布 | `std::fs::hard_link`（`CreateHardLinkW` 天生 EEXIST） | |
| `killpg`/SIGKILL | `taskkill /T /F`，回退 `TerminateProcess` | |
| `waitid(WNOWAIT)` 存活探测 | `OpenProcess` + `WaitForSingleObject(0)` | |
| `lsof -iTCP:port -sTCP:LISTEN` | `netstat -ano` 解析 LISTENING | |
| `ps -o lstart=` 进程身份 | `GetProcessTimes` 创建时刻 FILETIME | 仅要求同进程稳定。 |
| `/dev/urandom` | `BCryptGenRandom`（系统首选 RNG） | fail-closed 语义保留。 |
| 目录 fsync（`File::open(dir).sync_all()`） | `platform::sync_dir`：读写句柄 `FlushFileBuffers` | Windows 上只读句柄调 FlushFileBuffers 会拒绝访问。 |
| 逐级前缀符号链接检查 | 跳过 `Prefix(C:)`/`RootDir` component | 盘符前缀单独 stat 会失败且不可能是符号链接。 |
| `/usr/bin/open`（URL/目录/Finder 定位） | `ShellExecuteW` / `explorer /select,` | |
| Mach-O 二进制校验 | PE 头校验（`MZ` + `PE\0\0`） | 见 runtime::science。 |
| codesign 身份校验（官方 updater 快照信任） | 关闭（返回不匹配） | Windows 无 codesign；回退 installed app / explicit 路径。 |
| `pre_exec(setrlimit)` 输出上限 | 省略（读侧已有上限兜底） | |
| zsh 生命周期脚本 | 原生 Rust 等价实现（沙箱启动/停止、doctor） | |

## Windows 构建方法

工具链：rustup（stable-x86_64-pc-windows-msvc，minimal profile 即可）+ Visual Studio Build Tools（含 MSVC 与 Windows SDK）。前端为静态文件（`frontendDist: "../src"`），无需 Node 工具链即可 `cargo check`；打包时需要 Node + `@tauri-apps/cli`。

```bat
cd desktop\src-tauri
cargo check --target x86_64-pc-windows-msvc --lib
set CSSWITCH_LINK_TEST_MANIFEST=1 && cargo test --target x86_64-pc-windows-msvc
npm install && npm run tauri build                          # 完整打包（msi/nsis）
```

测试构建注意：`cargo test` 需要 `CSSWITCH_LINK_TEST_MANIFEST=1`。lib 单元测试进程拿不到 Tauri 的 comctl32 v6 manifest，而本机 comctl32 5.82 缺少测试会加载的 `TaskDialogIndirect` 入口（0xc0000139）；该环境变量让 build.rs 注入 `/DELAYLOAD:comctl32.dll`，仅影响测试构建，普通构建不受影响。

已知构建环境问题：项目路径过长时，src-tauri 的 build.rs 会在自身 OUT_DIR 内嵌套构建 gateway sidecar，路径可能超过 Windows 260 字符上限（`link.exe LNK1104`）。用 `subst X: <项目根>` 后从 `X:\...` 构建即可避开；或启用系统长路径支持（`LongPathsEnabled`）。

分发打包注意：tauri 只打包 `desktop/src-tauri/binaries/` 里现成的 sidecar 副本，构建前先重建 gateway release 并复制为 `binaries/csswitch-gateway-x86_64-pc-windows-msvc.exe`；CLI 不带 `--target` 时产物落 `desktop/src-tauri/target/release/bundle/{nsis,msi}/`。安装包只含程序本体与静态前端，不含任何 API Key 或 provider 配置（全部在首次使用时于界面内填写、仅存本机 `~/.csswitch/config.json`）。

## 已知边界

- **Claude Science Windows 版本形态**：0.1.55 实测安装于 `%LOCALAPPDATA%\Programs\ClaudeScience`（目录名无空格）；探测候选按「无空格优先，带空格与 `AnthropicClaude` 兼容」排列，全部候选需通过 `--version` 探测（正常输出 `claude-science <ver> (release, public)`）才算可用。
- **`test/`、`scripts/*.sh`**：验收脚本体系仍为 bash/zsh（macOS CI 用途）；Windows 下以 `cargo test` 为准。
- **打包资源中的 shell 脚本与 ssh-bridge**：unix 专用，Windows 打包包含但运行时不使用。
- 0600/0700 权限模型在 NTFS 上由默认 ACL 与只读位近似（见上文映射表），敌手威胁模型按同用户会话内进程考虑。
