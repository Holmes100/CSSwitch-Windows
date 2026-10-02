#[cfg(not(windows))]
use std::process::Command;

use crate::provider_contracts::AuthMode;
use crate::runtime::provider::adapter_for_profile;
#[cfg(not(windows))]
use crate::runtime::system::asset_root;
use crate::runtime::system::open_in_browser;
use crate::{config, run_blocking, SharedAppState, SharedLifecycle};

#[tauri::command]
pub(crate) async fn run_doctor(
    app: tauri::AppHandle,
    state: tauri::State<'_, SharedAppState>,
    lifecycle: tauri::State<'_, SharedLifecycle>,
) -> Result<String, String> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking(move || {
        let mut output = run_doctor_inner_cmd(&app)?;
        let route = lifecycle.with_serialized(|| {
            crate::runtime::sandbox_session::force_third_party_reconcile(&app, &state)
        });
        output.push_str("\n[Skill 路由] ");
        match route {
            Ok(message) => output.push_str(&message),
            Err(error) => output.push_str(&format!("核验失败：{error}")),
        }
        Ok(output)
    })
    .await
}

fn run_doctor_inner_cmd(app: &tauri::AppHandle) -> Result<String, String> {
    let cfg = doctor_config_from(&config::default_dir())?;
    // 生效 profile 的展示名（template_id）+ adapter + 脱敏认证类型；无生效配置则留空。
    let (provider_label, adapter, auth_mode, has_key) = match cfg.active_profile() {
        Some(profile) => {
            let public = crate::runtime::provider::resolve_launch_plan(profile)
                .ok()
                .map(|plan| plan.public());
            let auth_mode = match public.as_ref().map(|view| view.auth_mode) {
                Some(AuthMode::ApiKey) => "api_key",
                Some(AuthMode::CsswitchOauth) => "csswitch_oauth",
                Some(AuthMode::None) => "none",
                None => "",
            };
            let has_key = public.as_ref().is_some_and(|view| {
                view.auth_mode == AuthMode::ApiKey && view.credential_configured
            });
            (
                profile.template_id.clone(),
                adapter_for_profile(profile),
                auth_mode,
                has_key,
            )
        }
        None => (String::new(), String::new(), "", false),
    };
    let text = doctor_head(app, &cfg, &provider_label, &adapter, auth_mode, has_key)?;
    Ok(text)
}

/// doctor 的平台头部：unix 走 scripts/doctor.sh（bash）；Windows 用等价的
/// 只读原生检查（绝不启动进程、不联网、不打印 key 值）。
fn doctor_head(
    app: &tauri::AppHandle,
    cfg: &config::Config,
    provider_label: &str,
    adapter: &str,
    auth_mode: &str,
    has_key: bool,
) -> Result<String, String> {
    #[cfg(windows)]
    {
        let _ = app;
        let mut text = String::new();
        text.push_str("CSSwitch doctor（只读诊断，不启动进程、不联网、绝不碰真实目录）\n");
        text.push_str(&format!(
            "生效来源={}  适配器={}  代理端口={}  沙箱端口={}\n",
            if provider_label.is_empty() { "（无）" } else { provider_label },
            if adapter.is_empty() { "（无）" } else { adapter },
            cfg.proxy_port,
            cfg.sandbox_port
        ));
        text.push_str("[依赖]\n");
        if let Some(gateway) = crate::runtime::proxy_lifecycle::gateway_bin_path(app) {
            if gateway.is_file() {
                text.push_str(&format!("  OK Rust gateway 可执行：{}\n", gateway.display()));
            } else {
                text.push_str("  警告 gateway 路径不可执行\n");
            }
        } else {
            text.push_str("  警告 未找到 Rust gateway sidecar\n");
        }
        text.push_str("[Science 二进制]\n");
        let science = windows_installed_science_bin();
        match &science {
            Some(path) => text.push_str(&format!("  OK 找到 {}\n", path.display())),
            None => text.push_str(
                "  警告 未找到 Science 二进制（一键开始需要）：请安装官方 Claude Science\n",
            ),
        }
        text.push_str("[生效配置]\n");
        if provider_label.is_empty() {
            text.push_str("  警告 当前没有「生效」配置（在面板点「设为当前」选一条）\n");
        } else if auth_mode == "csswitch_oauth" {
            text.push_str(&format!(
                "  OK 生效来源：{provider_label}（{adapter} 适配器）· CSSwitch 私有文件 OAuth\n"
            ));
        } else if auth_mode == "none" {
            text.push_str(&format!(
                "  OK 生效来源：{provider_label}（{adapter} 适配器）· 无需凭据\n"
            ));
        } else if has_key {
            text.push_str(&format!(
                "  OK 生效来源：{provider_label}（{adapter} 适配器）· API key 已配置（不回显）\n"
            ));
        } else {
            text.push_str(&format!(
                "  警告 生效来源 {provider_label} 缺少 API key\n"
            ));
        }
        text.push_str("[端口护栏]\n");
        if cfg.proxy_port == 8765 || cfg.sandbox_port == 8765 {
            text.push_str("  失败 端口命中真实实例保留端口 8765\n");
        } else {
            text.push_str("  OK 未命中保留端口 8765\n");
        }
        text.push_str("[配置目录]\n");
        let dir = config::default_dir();
        if dir.join("config.json").is_file() {
            text.push_str(&format!("  OK 配置存在：{}\n", dir.join("config.json").display()));
        } else {
            text.push_str("  警告 config.json 尚未创建（首次保存后生成）\n");
        }
        let _ = auth_mode;
        Ok(text)
    }
    #[cfg(not(windows))]
    {
        let root = asset_root(app).ok_or("找不到 scripts/doctor.sh（打包资源或仓库根均未命中）。")?;
        let doctor = root.join("scripts/doctor.sh");
        let mut cmd = Command::new("bash");
        // 多 profile：传 template_id + adapter + key 有无（布尔）。doctor 不再按 provider 名写死、
        // 不再去 shell 环境找 key（key 存 config.json）。绝不把真实 key 值传进其环境。
        cmd.arg(&doctor)
            .env("CSSWITCH_PROVIDER", provider_label)
            .env("CSSWITCH_ADAPTER", adapter)
            .env("CSSWITCH_AUTH_MODE", auth_mode)
            .env("CSSWITCH_KEY_PRESENT", if has_key { "1" } else { "0" })
            .env("CSSWITCH_PROXY_PORT", cfg.proxy_port.to_string())
            .env("CSSWITCH_SANDBOX_PORT", cfg.sandbox_port.to_string());
        if let Some(gateway) = crate::runtime::proxy_lifecycle::gateway_bin_path(app) {
            cmd.env("CSSWITCH_GATEWAY_BIN", gateway);
        }
        let out = cmd.output().map_err(|e| e.to_string())?;
        let mut text = String::from_utf8_lossy(&out.stdout).to_string();
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.trim().is_empty() {
            text.push_str("\n[stderr] ");
            text.push_str(err.trim());
        }
        Ok(text)
    }
}

/// Windows 上探测已安装的官方 Claude Science（与 runtime::science 的候选
/// 列表保持一致；找到探测函数后可直接复用）。
#[cfg(windows)]
fn windows_installed_science_bin() -> Option<std::path::PathBuf> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let local = std::path::PathBuf::from(local);
        // 官方 Windows 安装目录是不带空格的 ClaudeScience。
        candidates.push(local.join(r"Programs\ClaudeScience\claude-science.exe"));
        candidates.push(local.join(r"Programs\Claude Science\claude-science.exe"));
        candidates.push(local.join(r"AnthropicClaude\claude-science.exe"));
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        candidates.push(std::path::PathBuf::from(program_files.clone()).join(r"ClaudeScience\claude-science.exe"));
        candidates.push(std::path::PathBuf::from(program_files).join(r"Claude Science\claude-science.exe"));
    }
    candidates
        .into_iter()
        .find(|candidate| crate::platform::is_executable_file(candidate))
}

/// doctor 的共用尾部（Codex 实验段已随功能移除删除）。
fn doctor_config_from(dir: &std::path::Path) -> Result<config::Config, String> {
    config::load_from(dir).map_err(|e| format!("读取配置失败，无法运行自检：{e}"))
}

/// 当前 app 版本（供前端「检查更新」与页脚版本号用）。
#[tauri::command]
pub(crate) fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// 打开 GitHub Releases 页（检查更新时用系统浏览器打开，浏览器走用户自己的代理）。
#[tauri::command]
pub(crate) fn open_release_page() -> Result<(), String> {
    open_in_browser("https://github.com/SuperJJ007/CSSwitch/releases/latest")
}

/// 打开「报 bug」页（预填 bug 模板）；用系统浏览器，走用户自己的代理。
#[tauri::command]
pub(crate) fn report_bug() -> Result<(), String> {
    open_in_browser("https://github.com/SuperJJ007/CSSwitch/issues/new?template=bug_report.yml")
}

/// 在文件管理器里打开构建变体自己的日志目录，方便用户附到 bug 反馈里（先自查有无密钥）。
#[tauri::command]
pub(crate) fn open_logs() -> Result<(), String> {
    let dir = config::default_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    crate::platform::open_path(&dir).map_err(|e| format!("打开日志目录失败：{e}"))
}

/// 一键导出诊断包：收集应用日志、Science daemon 日志、脱敏后的 config 与版本
/// 信息，打成一个 zip 写到 ~/.csswitch/diagnostics/ 并在资源管理器中定位。
/// 目标：用户报问题时一键附包，不必到处找日志。密钥在导出前强制脱敏。
#[tauri::command]
pub(crate) fn export_diagnostics() -> Result<String, String> {
    let entries = collect_diagnostics_entries()?;
    let out_dir = config::default_dir().join("diagnostics");
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("创建诊断目录失败：{e}"))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let out = out_dir.join(format!("csswitch-diagnostics-{stamp}.zip"));
    write_diagnostics_zip(&out, &entries).map_err(|e| format!("写诊断包失败：{e}"))?;
    let _ = crate::platform::reveal_in_file_manager(&out);
    Ok(out.to_string_lossy().into_owned())
}

/// 单文件大小上限：诊断包不是全量备份，超限日志跳过（避免 zip 巨大）。
const DIAGNOSTICS_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

fn push_log_dir(entries: &mut Vec<(String, Vec<u8>)>, zip_prefix: &str, dir: &std::path::Path) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".log") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if meta.len() > DIAGNOSTICS_MAX_FILE_BYTES {
                continue;
            }
        }
        if let Ok(bytes) = std::fs::read(&path) {
            entries.push((format!("{zip_prefix}/{name}"), bytes));
        }
    }
}

/// config.json 脱敏：字段名含 key/token/secret/credential/password 的值整体
/// 替换为占位符（递归，含 profile/credential 嵌套）；其余结构原样保留。
fn redact_config_json(value: &mut serde_json::Value) {
    const SENSITIVE: &[&str] = &["key", "token", "secret", "credential", "password"];
    match value {
        serde_json::Value::Object(map) => {
            for (name, item) in map.iter_mut() {
                let lower = name.to_ascii_lowercase();
                if SENSITIVE.iter().any(|word| lower.contains(word)) {
                    *item = serde_json::Value::String("[已脱敏]".into());
                } else {
                    redact_config_json(item);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_config_json),
        _ => {}
    }
}

fn collect_diagnostics_entries() -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    push_log_dir(
        &mut entries,
        "logs",
        &config::default_dir().join("logs"),
    );
    push_log_dir(
        &mut entries,
        "science-logs",
        &crate::runtime::science::sandbox_data_dir().join("logs"),
    );

    let config_path = config::default_dir().join("config.json");
    if config_path.is_file() {
        let raw = std::fs::read(&config_path).map_err(|e| format!("读取 config 失败：{e}"))?;
        let mut value: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| format!("config 解析失败（原文件未改动）：{e}"))?;
        redact_config_json(&mut value);
        let pretty = serde_json::to_vec_pretty(&value)
            .map_err(|e| format!("脱敏 config 序列化失败：{e}"))?;
        entries.push(("config.redacted.json".into(), pretty));
    }

    entries.push(("info.txt".into(), build_diagnostics_info().into_bytes()));
    Ok(entries)
}

fn build_diagnostics_info() -> String {
    let mut info = String::new();
    info.push_str("CSSwitch 诊断包\n");
    info.push_str(&format!(
        "生成时间: {} (epoch 秒)\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ));
    info.push_str(&format!("App 版本: {}\n", app_version()));
    info.push_str(&format!("平台: {}\n", std::env::consts::OS));

    let mut command = std::process::Command::new("cmd");
    command.args(["/c", "ver"]);
    crate::platform::hide_console(&mut command);
    if let Ok(output) = command.output() {
        info.push_str(&format!(
            "Windows: {}\n",
            String::from_utf8_lossy(&output.stdout).trim()
        ));
    }

    // Science 版本探测：cfg 分支与 run_doctor 的候选逻辑保持一致（仅 Windows）。
    #[cfg(windows)]
    if let Some(science_bin) = windows_installed_science_bin() {
        let mut command = std::process::Command::new(&science_bin);
        command.arg("--version");
        crate::platform::hide_console(&mut command);
        match command.output() {
            Ok(output) => info.push_str(&format!(
                "Claude Science: {}\n",
                String::from_utf8_lossy(&output.stdout).trim()
            )),
            Err(error) => info.push_str(&format!("Claude Science: 探测失败（{error}）\n")),
        }
    }

    info.push_str(
        "说明: config.redacted.json 已脱敏；key/token/secret/credential/password 字段值替换为占位符。\n",
    );
    info
}

fn write_diagnostics_zip(
    out: &std::path::Path,
    entries: &[(String, Vec<u8>)],
) -> std::io::Result<()> {
    let file = std::fs::File::create(out)?;
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in entries {
        zip.start_file(name.as_str(), options)?;
        std::io::Write::write_all(&mut zip, bytes)?;
    }
    zip.finish()?;
    Ok(())
}

/// 修复中断的启动事务（一键开始报 manual_recovery_required 时的自助恢复路径）。
/// 与真机验证过的手工流程一致：
/// 1. config.json 的 runtime_transaction 置 null——serde_json::Value 往返对
///    u64 无损（事务里的 inode 大整数远超 JS 的 2^53，文本/JS 解析必坏），
///    写回前留滚动备份；
/// 2. pending-authority-cleanup 清单 disposition 翻转为 cleanup_only——纯字节
///    替换、其余字节不动，下次一键开始由状态机自己安全消化快照；
/// 3. 不直接删快照。修复后需完全退出并重开 CSSwitch（内存态仍持有旧事务）。
fn repair_interrupted_transaction_in(dir: &std::path::Path) -> Result<Vec<String>, String> {
    let mut steps = Vec::new();

    let config_path = dir.join("config.json");
    if config_path.is_file() {
        let raw = std::fs::read(&config_path).map_err(|e| format!("读取 config.json 失败：{e}"))?;
        let mut value: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("config.json 解析失败：{e}"))?;
        if value.get("runtime_transaction").is_some_and(|v| !v.is_null()) {
            value["runtime_transaction"] = serde_json::Value::Null;
            let _ = config::write_rolling_backup(dir);
            let serialized = serde_json::to_vec_pretty(&value)
                .map_err(|e| format!("config.json 序列化失败：{e}"))?;
            std::fs::write(&config_path, serialized)
                .map_err(|e| format!("写回 config.json 失败：{e}"))?;
            let handle = std::fs::OpenOptions::new()
                .write(true)
                .open(&config_path)
                .map_err(|e| format!("收紧 config.json 权限失败：{e}"))?;
            let _ = crate::platform::make_file_private(&handle);
            steps.push("runtime_transaction 已置 null".into());
        } else {
            steps.push("runtime_transaction 无需修复".into());
        }
    }

    let manifest_path = dir.join("pending-authority-cleanup.v1.json");
    if manifest_path.is_file() {
        let raw = std::fs::read(&manifest_path).map_err(|e| format!("读取清理清单失败：{e}"))?;
        let text =
            String::from_utf8(raw).map_err(|_| "清理清单编码异常，已拒绝处理".to_string())?;
        if text.contains("\"disposition\":\"active_recovery\"") {
            let flipped = text.replace(
                "\"disposition\":\"active_recovery\"",
                "\"disposition\":\"cleanup_only\"",
            );
            std::fs::write(&manifest_path, flipped.as_bytes())
                .map_err(|e| format!("写回清理清单失败：{e}"))?;
            steps.push("清理清单已翻转为 cleanup_only（下次一键开始由应用安全消化快照）".into());
        } else {
            steps.push("清理清单无需翻转".into());
        }
    }

    Ok(steps)
}

/// 修复成功的用户提示：只讲下一步动作，不出现机制术语（术语留在诊断包/日志里）。
fn repair_summary(steps: &[String]) -> String {
    if steps.is_empty() {
        return "未发现需要修复的内容。如果「一键开始」仍失败，请点「导出诊断包」发给我们。".into();
    }
    format!(
        "已清理上次启动的残留记录。\n下一步：① 完全退出 CSSwitch（托盘图标右键退出）② 重新打开 CSSwitch ③ 再点「一键开始」。\n如果再次失败，请点「导出诊断包」发给我们。"
    )
}

/// 「诊断与支持」页的一键修复入口。
#[tauri::command]
pub(crate) fn repair_interrupted_transaction() -> Result<String, String> {
    let steps = repair_interrupted_transaction_in(&config::default_dir())?;
    Ok(repair_summary(&steps))
}

#[cfg(test)]
mod tests {
    use super::doctor_config_from;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("csswitch-doctor-{name}-{nanos}"))
    }

    #[test]
    fn diagnostics_redaction_strips_sensitive_fields_recursively() {
        let mut value = serde_json::from_str(
            r#"{"profiles":[{"name":"p","key":"sk-SECRET","credential":{"token":"tok"}}],"note":"ok","money":42}"#,
        )
        .unwrap();
        super::redact_config_json(&mut value);
        let text = serde_json::to_string(&value).unwrap();
        assert!(!text.contains("sk-SECRET"), "key 值必须被脱敏：{text}");
        assert!(!text.contains("\"tok\""), "token 值必须被脱敏：{text}");
        assert!(text.contains("\"name\":\"p\""), "非敏感字段保留：{text}");
        assert!(text.contains("[已脱敏]"));
    }

    #[test]
    fn diagnostics_collection_pulls_only_log_files() {
        let root = tmpdir("collect");
        let logs = root.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("operation.log"), b"app-log").unwrap();
        fs::write(logs.join("note.txt"), b"not-a-log").unwrap();
        let mut entries = Vec::new();
        super::push_log_dir(&mut entries, "logs", &logs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "logs/operation.log");
        assert_eq!(entries[0].1, b"app-log");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn diagnostics_zip_writes_magic_header() {
        let dir = tmpdir("zip");
        fs::create_dir_all(&dir).unwrap();
        let out = dir.join("d.zip");
        super::write_diagnostics_zip(&out, &[("a.txt".into(), b"hello".to_vec())]).unwrap();
        let bytes = fs::read(&out).unwrap();
        assert!(bytes.starts_with(b"PK"), "zip 魔数缺失");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn repair_interrupted_transaction_nulls_field_and_flips_manifest() {
        let dir = tmpdir("repair");
        fs::create_dir_all(&dir).unwrap();
        // 大整数全部 > 2^53（JS 解析必丢精度的区间）、< u64::MAX（serde_json 无损区间）。
        fs::write(
            dir.join("config.json"),
            br#"{"schema_version":4,"profiles":[],"active_id":"","proxy_port":18991,"sandbox_port":8990,"runtime_transaction":{"dev":12345678901234567890,"inode":9876543210987654321},"keeper":17909179561234567890}"#,
        )
        .unwrap();
        fs::write(
            dir.join("pending-authority-cleanup.v1.json"),
            br#"{"schema_version":2,"disposition":"active_recovery","entries":[{"inode":11122233344455566677}]}"#,
        )
        .unwrap();

        let steps = super::repair_interrupted_transaction_in(&dir).unwrap();
        assert_eq!(steps.len(), 2, "{steps:?}");

        let fixed: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap();
        assert!(fixed.get("runtime_transaction").unwrap().is_null());
        assert_eq!(
            fixed["keeper"],
            serde_json::from_str::<serde_json::Value>("17909179561234567890").unwrap(),
            "无关字段的大整数必须无损保留"
        );
        let manifest_raw = fs::read_to_string(dir.join("pending-authority-cleanup.v1.json")).unwrap();
        assert!(manifest_raw.contains("\"disposition\":\"cleanup_only\""), "{manifest_raw}");
        assert!(manifest_raw.contains("11122233344455566677"), "清单大整数必须逐字节保留");

        // 幂等：再跑一遍全部变为"无需修复"。
        let again = super::repair_interrupted_transaction_in(&dir).unwrap();
        assert!(again.iter().all(|s| s.contains("无需")), "{again:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn repair_summary_is_user_friendly_and_free_of_mechanism_terms() {
        let s = super::repair_summary(&["runtime_transaction 已置 null".into()]);
        assert!(s.contains("已清理上次启动的残留记录"), "{s}");
        assert!(s.contains("完全退出"), "{s}");
        assert!(!s.contains("runtime_transaction"), "成功提示不应出现机制术语：{s}");
        let empty = super::repair_summary(&[]);
        assert!(empty.contains("未发现需要修复的内容"), "{empty}");
        assert!(empty.contains("导出诊断包"), "{empty}");
    }

    #[test]
    fn doctor_config_rejects_reserved_port_instead_of_defaulting() {
        let dir = tmpdir("reserved-port");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("config.json"),
            br#"{"schema_version":2,"profiles":[],"active_id":"","proxy_port":8765,"sandbox_port":8990}"#,
        )
        .unwrap();

        let err = doctor_config_from(&dir).unwrap_err();
        assert!(err.contains("读取配置失败"));
        assert!(err.contains("8765"));
    }
}
