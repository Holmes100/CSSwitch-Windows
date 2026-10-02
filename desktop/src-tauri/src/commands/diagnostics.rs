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
