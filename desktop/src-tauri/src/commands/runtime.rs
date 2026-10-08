#[cfg(not(windows))]
use std::path::Path;
use std::process::Command;

use serde::Deserialize;
use serde_json::{json, Value};
use tauri::State;

use crate::runtime::capability_catalog::diagnostics_for_profile;
use crate::runtime::diagnostics::{
    build_status_response, proxy_status_last_error, science_diagnostics, status_lights,
    ScienceDiagnosticsInput, StatusProbeInput,
};
use crate::runtime::operation::{self, OperationKind, OperationTrace};
use crate::runtime::profile::profile_capabilities;
use crate::runtime::provider::{
    current_shim_mode_for_adapter, gateway_kind_for_adapter, resolve_launch_plan,
    status_upstream_endpoint,
};
use crate::runtime::proxy_lifecycle::ensure_proxy;
use crate::runtime::science::{
    sandbox_listener_matches_runtime, sandbox_url, science_runtime_preflight as runtime_preflight,
    settings_change_needs_teardown, stop_sandbox, SCIENCE_DOWNLOAD_URL,
};
use crate::runtime::settings::{
    remove_managed_sandbox_ssh_stub, system_ssh_config_path, validate_runtime_ports,
};
use crate::runtime::ssh_bridge::{revoke_science_ssh_bridge, system_ssh_hosts};
use crate::runtime::system::open_in_browser;
use crate::{
    config, lock, proc, run_blocking, run_blocking_typed, AppState, SharedAppState, SharedLifecycle,
};

fn config_last_error_json(error: &dyn std::fmt::Display) -> serde_json::Value {
    json!({
        "type": "config_error",
        "message": error.to_string(),
    })
}

fn status_response_for_config_error(error: &dyn std::fmt::Display) -> serde_json::Value {
    build_status_response(
        status_lights(StatusProbeInput {
            proxy_ok: false,
            sandbox_ok: false,
            upstream_ok: false,
            upstream_applicable: true,
        }),
        serde_json::Value::Null,
        "",
        "off",
        diagnostics_for_profile(None, "off"),
        science_diagnostics(ScienceDiagnosticsInput {
            sandbox_port: 0,
            sandbox_ok: false,
        }),
        Some(config_last_error_json(error)),
    )
}

fn status_runtime_identity(
    adapter: &str,
    secret: &str,
    launched_gateway_kind: String,
    launched_shim_mode: String,
) -> (String, String, &'static str) {
    let current_shim_mode = current_shim_mode_for_adapter(adapter);
    let gateway_kind = if !launched_gateway_kind.is_empty() {
        launched_gateway_kind
    } else if !secret.is_empty() {
        String::new()
    } else {
        gateway_kind_for_adapter(adapter).to_string()
    };
    let runtime_shim_mode = if !launched_shim_mode.is_empty() {
        launched_shim_mode
    } else if !secret.is_empty() {
        String::new()
    } else {
        current_shim_mode.to_string()
    };
    (gateway_kind, runtime_shim_mode, current_shim_mode)
}

fn status_upstream_applicable(adapter: &str) -> bool {
    !adapter.is_empty()
}

pub(crate) fn stop_sandbox_state<R: tauri::Runtime>(
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

/// 切换运行模式（"proxy" 第三方 / "official" 官方）。切官方要先拆第三方链路成功再落盘。
#[tauri::command]
pub(crate) async fn set_mode(
    app: tauri::AppHandle,
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
    mode: String,
) -> Result<(), String> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking(move || set_mode_inner(app, state, lifecycle, mode)).await
}

fn set_mode_inner(
    app: tauri::AppHandle,
    state: SharedAppState,
    lifecycle: SharedLifecycle,
    mode: String,
) -> Result<(), String> {
    if mode != "proxy" && mode != "official" {
        return Err(format!("未知模式：{mode}（只支持 proxy / official）。"));
    }
    // 经串行器（修 P1-b）：切官方的「拆链路 + 落盘」必须与「一键开始」等互斥，否则一键起到一半时
    // 切官方会先停链路、一键随后又把沙箱/OAuth 起起来 → 显示官方却有第三方沙箱在跑。bump_generation
    // 作废任何在途启动，防被停后又拿旧配置写回运行态。
    lifecycle.with_serialized(|| {
        let dir = config::default_dir();
        if mode == "official" {
            lifecycle.bump_generation();
            let mut st = lock(&state);
            stop_sandbox_state(&app, &mut st).map_err(|e| {
                format!("停止沙箱失败，未切换到官方模式：{e}（真实实例 8765 未受影响）")
            })?;
            st.stop_proxy();
        }
        config::update(&dir, {
            let mode = mode.clone();
            move |c| c.mode = mode
        })
        .map_err(|e| e.to_string())?;
        {
            let mut app_state = lock(&state);
            app_state.history_recovery = None;
            app_state.boot_attention = None;
        }
        Ok(())
    })
}

/// 官方模式：干净地打开用户【真实】的 Claude Science（不碰/复制真实凭证，抹掉 ANTHROPIC_*）。
#[tauri::command]
pub(crate) fn open_official() -> Result<(), String> {
    #[cfg(windows)]
    {
        // Windows：定位已安装的 Science 可执行文件并直接启动；抹掉代理环境变量。
        if let Some(binary) = {
            let mut candidates: Vec<std::path::PathBuf> = Vec::new();
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                let local = std::path::PathBuf::from(local);
                // 官方 Windows 安装目录是不带空格的 ClaudeScience。
                candidates.push(local.join(r"Programs\ClaudeScience\claude-science.exe"));
                candidates.push(local.join(r"Programs\Claude Science\claude-science.exe"));
                candidates.push(local.join(r"AnthropicClaude\claude-science.exe"));
            }
            if let Some(program_files) = std::env::var_os("ProgramFiles") {
                candidates.push(
                    std::path::PathBuf::from(program_files.clone())
                        .join(r"ClaudeScience\claude-science.exe"),
                );
                candidates.push(
                    std::path::PathBuf::from(program_files)
                        .join(r"Claude Science\claude-science.exe"),
                );
            }
            candidates
                .into_iter()
                .find(|candidate| crate::platform::is_executable_file(candidate))
        } {
            let mut cmd = Command::new(&binary);
            cmd.env_remove("ANTHROPIC_BASE_URL")
                .env_remove("ANTHROPIC_API_KEY")
                .env_remove("ANTHROPIC_AUTH_TOKEN");
            crate::platform::hide_console(&mut cmd);
            return match cmd.status() {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("打开官方 Claude Science 失败：{e}")),
            };
        }
        Err("未能打开 Claude Science。请确认已安装官方 Claude Science。".into())
    }
    #[cfg(not(windows))]
    {
        let app_path = "/Applications/Claude Science.app";
        let mut cmd = Command::new("open");
        if Path::new(app_path).is_dir() {
            cmd.arg(app_path);
        } else {
            cmd.arg("-a").arg("Claude Science");
        }
        cmd.env_remove("ANTHROPIC_BASE_URL")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_AUTH_TOKEN");
        match cmd.status() {
            Ok(s) if s.success() => Ok(()),
            Ok(_) => Err("未能打开 Claude Science。请确认已安装官方 Claude Science。".into()),
            Err(e) => Err(format!("打开官方 Claude Science 失败：{e}")),
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct UiSettings {
    proxy_port: u16,
    sandbox_port: u16,
    #[serde(default)]
    reuse_system_ssh: bool,
}

/// 运行设置（端口 + 系统 SSH 配置授权；provider/连接改走 profile CRUD + set_active_profile）。
/// 经串行器（修 P1-c）：端口或 SSH 授权一旦变化，正在跑的沙箱都必须拆掉，
/// 与新端口不一致；此处把这条陈旧链路拆掉（只停我们的沙箱、绝不碰 8765），逼下次「一键开始」按新端口重建，
/// 杜绝「复用旧沙箱指向死端口、UI 却报沿用不变」。
#[tauri::command]
pub(crate) async fn set_settings(
    app: tauri::AppHandle,
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
    cfg: UiSettings,
) -> Result<(), String> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking(move || set_settings_inner(app, state, lifecycle, cfg)).await
}

fn set_settings_inner(
    app: tauri::AppHandle,
    state: SharedAppState,
    lifecycle: SharedLifecycle,
    cfg: UiSettings,
) -> Result<(), String> {
    validate_runtime_ports(cfg.proxy_port, cfg.sandbox_port)?;
    if cfg.reuse_system_ssh {
        system_ssh_config_path()?;
        system_ssh_hosts()?;
    }
    lifecycle.with_serialized(|| {
        let dir = config::default_dir();
        let old = config::load_from(&dir).map_err(|e| e.to_string())?;
        let teardown = settings_change_needs_teardown(
            old.proxy_port,
            cfg.proxy_port,
            old.sandbox_port,
            cfg.sandbox_port,
        ) || old.reuse_system_ssh != cfg.reuse_system_ssh;
        // 拆链路【先】于落盘，且停沙箱结果必须据实处理（修增量 P1）：停不掉就【不改端口】——
        // 否则会留下「config 已是新端口、旧沙箱仍在旧端口指向旧代理」的不一致态，下次一键还会复用这条死链路。
        // 保持端口不变则一切仍自洽（旧沙箱指旧代理端口、下次一键在旧端口重建代理，链路照通）。
        if teardown {
            let mut st = lock(&state);
            stop_sandbox_state(&app, &mut st).map_err(|e| {
                format!(
                    "设置未更改：无法停止仍使用旧端口或旧 SSH 授权的沙箱（{e}）。请手动停止沙箱或重启 app 后重试。（真实实例 8765 未受影响）"
                )
            })?;
            lifecycle.bump_generation(); // 停成功后作废在途启动
            st.stop_proxy();
        }
        if !cfg.reuse_system_ssh {
            revoke_science_ssh_bridge(&crate::runtime::science::sandbox_home())?;
            remove_managed_sandbox_ssh_stub(&crate::runtime::science::sandbox_home())?;
        }
        // 拆链路成功（或无需拆）→ 才落盘新端口，保证 config 与运行态一致。
        config::update(&dir, move |c| {
            c.proxy_port = cfg.proxy_port;
            c.sandbox_port = cfg.sandbox_port;
            c.reuse_system_ssh = cfg.reuse_system_ssh;
        })
        .map_err(|e| e.to_string())?;
        {
            let mut app_state = lock(&state);
            app_state.history_recovery = None;
            app_state.boot_attention = None;
        }
        Ok(())
    })
}

#[tauri::command]
pub(crate) async fn start_proxy<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking_typed(move || start_proxy_inner_cmd(app, state, lifecycle)).await
}

fn start_proxy_inner_cmd<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: SharedLifecycle,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let cfg = config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
    let active = cfg
        .active_profile()
        .ok_or("未配置生效 profile，请先在面板选择或新建一条配置。")?;
    let _adapter = resolve_launch_plan(active)?.adapter;
    // 经串行器：与切换/连接编辑/清 key/删/停等 ensure_proxy 竞争串行化，防陈旧读起旧配置代理
    // 又写回运行态（修 P1-a，比照 spec §8.1「ensure_proxy 都经一把 app 级 mutex」）。
    lifecycle.with_serialized(|| {
        let trace = OperationTrace::start(OperationKind::StartProxy, "command=start_proxy");
        let (port, _secret, _action) =
            ensure_proxy(&app, &state, lifecycle.as_ref(), None, Some(&trace))?;
        trace.finish(format!("ok port={port}"));
        Ok(json!({ "port": port }))
    })
}

#[derive(Deserialize)]
pub(crate) struct FetchModelsReq {
    /// 模板 id（决定 builtin / base_url 可编辑性 / 默认 base_url）。
    template_id: String,
    /// 编辑已存 profile 时的实际 api_format；为空则按模板默认值。
    #[serde(default)]
    api_format: Option<String>,
    /// 自定义模板时用户填的 base_url（不可编辑模板忽略）。
    #[serde(default)]
    base_url: String,
    /// 用户新填的 key；为空表示沿用 profile_id 已存的 key（后端不回传完整 key）。
    #[serde(default)]
    key: String,
    /// 编辑已存 profile 时传其 id（用于沿用已存 key）。
    #[serde(default)]
    profile_id: Option<String>,
}

/// 「获取可用模型」——纯 scratch 探测：只用临时代理探候选 base_url/key 的 /v1/models，
/// 绝不写 config、不改 AppState、不碰正在服务 Science 的正式代理。
#[tauri::command]
pub(crate) async fn fetch_models(
    app: tauri::AppHandle,
    req: FetchModelsReq,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    run_blocking_typed(
        move || -> Result<_, crate::commands::RuntimeCommandError> {
            let request = crate::runtime::model_discovery::ModelDiscoveryRequest {
                template_id: req.template_id,
                api_format: req.api_format,
                base_url: req.base_url,
                key: req.key,
                profile_id: req.profile_id,
            };
            let _adapter = crate::runtime::model_discovery::request_adapter(&request)?;
            Ok(crate::runtime::model_discovery::fetch_models(app, request)?)
        },
    )
    .await
}

#[tauri::command]
pub(crate) async fn stop_all(
    app: tauri::AppHandle,
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
) -> Result<String, String> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking(move || stop_all_inner_cmd(app, state, lifecycle)).await
}

fn stop_all_inner_cmd(
    app: tauri::AppHandle,
    state: SharedAppState,
    lifecycle: SharedLifecycle,
) -> Result<String, String> {
    lifecycle.with_serialized(|| {
        lifecycle.bump_generation(); // 作废任何在途启动（防被停后又拿旧 key 复活）
        let mut st = lock(&state);
        let mut sandbox_res = stop_sandbox_state(&app, &mut st);
        st.stop_proxy();
        // 兜底：受管身份无法确认（应用重开后遗留的 daemon）时，委托官方 CLI
        // 按 data-dir 停止——daemon 自身校验数据目录锁，安全且不触碰真实实例。
        if let Err(e) = &sandbox_res {
            if e.contains("managed launch 身份") {
                match crate::runtime::science::cli_stop_sandbox_daemon() {
                    Ok(()) => {
                        sandbox_res = Ok(());
                        st.science_runtime = None;
                    }
                    Err(cli_err) => {
                        sandbox_res = Err(format!("{e}；官方 CLI 停止也失败：{cli_err}"));
                    }
                }
            }
        }
        let summary = match &sandbox_res {
            Ok(()) => crate::runtime::sandbox_session::deep_clean_sandbox_leftovers(),
            Err(_) => String::new(),
        };
        sandbox_res
            .map(|()| summary)
            .map_err(|e| format!("代理已停；但{e}真实实例 8765 未受影响。"))
    })
}

#[tauri::command]
pub(crate) async fn one_click_login<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
    runtime_choice: Option<String>,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking_typed(move || one_click_login_cmd(app, state, lifecycle, runtime_choice)).await
}

#[derive(Clone, PartialEq)]
struct OneClickGatewayPreflightSnapshot {
    child_pid: u32,
    proxy_port: u16,
    secret: String,
    provider: String,
    gateway_kind: String,
    shim_mode: String,
    launch_id: String,
    key_fp: u64,
    launch_context: crate::GatewayLaunchContext,
}

impl OneClickGatewayPreflightSnapshot {
    fn capture(state: &SharedAppState) -> Result<Option<Self>, String> {
        let mut current = lock(state);
        let Some(child) = current.proxy.as_mut() else {
            return Ok(None);
        };
        if child
            .try_wait()
            .map_err(|_| {
                "gateway_identity_retry：无法确认先前 Gateway child 状态，请重试。".to_string()
            })?
            .is_some()
        {
            return Err(
                "gateway_identity_retry：先前 Gateway child 已退出，请先恢复运行态后重试。".into(),
            );
        }
        let child_pid = child.id();
        let launch_context = current.gateway_launch_context.clone().ok_or(
            "gateway_identity_retry：先前 Gateway 缺少完整启动上下文，请先恢复运行态后重试。",
        )?;
        Ok(Some(Self {
            child_pid,
            proxy_port: current.proxy_port,
            secret: current.secret.clone(),
            provider: current.provider.clone(),
            gateway_kind: current.gateway_kind.clone(),
            shim_mode: current.shim_mode.clone(),
            launch_id: current.launch_id.clone(),
            key_fp: current.key_fp,
            launch_context,
        }))
    }

    fn verify_unchanged(&self, state: &SharedAppState) -> Result<(), String> {
        let mut current = lock(state);
        let child_matches = match current.proxy.as_mut() {
            Some(child) if child.id() == self.child_pid => child
                .try_wait()
                .map_err(|_| {
                    "gateway_identity_retry：无法复核先前 Gateway child 状态，请重试。".to_string()
                })?
                .is_none(),
            _ => false,
        };
        let exact_context = child_matches
            && current.proxy_port == self.proxy_port
            && current.secret == self.secret
            && current.provider == self.provider
            && current.gateway_kind == self.gateway_kind
            && current.shim_mode == self.shim_mode
            && current.launch_id == self.launch_id
            && current.key_fp == self.key_fp
            && current.gateway_launch_context.as_ref() == Some(&self.launch_context);
        if exact_context {
            Ok(())
        } else {
            Err(
                "gateway_context_changed_retry：先前 Gateway 身份或完整启动上下文在认证检查期间发生变化，请重试。"
                    .into(),
            )
        }
    }
}

#[derive(Clone)]
struct OneClickCandidateConfigSnapshot {
    config: config::Config,
}

impl OneClickCandidateConfigSnapshot {
    fn capture(config: &config::Config) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn verify_unchanged(&self) -> Result<(), String> {
        let current = config::load_from(&config::default_dir())
            .map_err(|_| "config_changed_retry：无法复核候选启动配置，请重试。".to_string())?;
        if current == self.config {
            Ok(())
        } else {
            Err("config_changed_retry：候选启动配置在认证检查期间发生变化，请重试。".into())
        }
    }
}

pub(crate) fn one_click_login_cmd<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: SharedLifecycle,
    runtime_choice: Option<String>,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let cfg = match config::load_from(&config::default_dir()) {
        Ok(cfg) => cfg,
        Err(error) => return Ok(one_click_failure_value(error.to_string())),
    };
    let active = match cfg.active_profile() {
        Some(active) => active,
        None => {
            return Ok(one_click_failure_value(
                "未配置生效 profile，请先在面板选择或新建一条配置。".into(),
            ))
        }
    };
    let _adapter = match resolve_launch_plan(active) {
        Ok(plan) => plan.adapter,
        Err(message) => return Ok(one_click_failure_value(message)),
    };
    let candidate_config = OneClickCandidateConfigSnapshot::capture(&cfg);
    let prior_gateway = match OneClickGatewayPreflightSnapshot::capture(&state) {
        Ok(snapshot) => snapshot,
        Err(message) => return Ok(one_click_failure_value(message)),
    };
    match lifecycle.with_serialized(|| -> Result<_, String> {
        candidate_config.verify_unchanged()?;
        if let Some(prior_gateway) = prior_gateway.as_ref() {
            prior_gateway.verify_unchanged(&state)?;
        }
        crate::runtime::proxy_lifecycle::recover_interrupted_gateway(&app, &state)?;
        crate::runtime::sandbox_session::one_click_login(
            app,
            state,
            lifecycle.as_ref(),
            runtime_choice.as_deref(),
        )
    }) {
        Ok(value) => Ok(value),
        Err(message) => Ok(one_click_failure_value(message)),
    }
}

#[tauri::command]
pub(crate) async fn restore_history_choice(
    app: tauri::AppHandle,
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
    reference: String,
) -> Result<serde_json::Value, String> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking(move || {
        lifecycle.with_serialized(|| {
            let cfg = config::load_from(&config::default_dir()).map_err(|e| e.to_string())?;
            if cfg.mode != "proxy" {
                return Err("当前已不是第三方模型模式，本次历史恢复选择已作废".into());
            }
            if cfg.runtime_transaction.is_some() {
                return Err("当前有新的运行事务尚未完成，已拒绝覆盖其历史身份".into());
            }
            let active_profile_id = cfg
                .active_profile()
                .map(|profile| profile.id.clone())
                .ok_or("当前选择已变化，本次历史恢复选择已作废")?;
            let (auth_dir, sandbox_root, candidate, expected_port) = {
                let app_state = lock(&state);
                let session = app_state
                    .history_recovery
                    .as_ref()
                    .ok_or("历史恢复选择已过期，请重新点击一键开始")?;
                if session.active_profile_id != active_profile_id
                    || session.sandbox_port != cfg.sandbox_port
                {
                    return Err("当前配置或端口已变化，本次历史恢复选择已作废".into());
                }
                let choice = session
                    .choices
                    .iter()
                    .find(|choice| choice.reference == reference)
                    .ok_or("历史恢复引用无效或已过期")?;
                (
                    session.auth_dir.clone(),
                    session.sandbox_root.clone(),
                    choice.candidate.clone(),
                    session.sandbox_port,
                )
            };

            // A user may discover after opening Science that A/B was the wrong
            // history. Keep the one-shot mapping in memory for this app session,
            // but stop only the exact managed runtime before changing credentials.
            {
                let mut app_state = lock(&state);
                if app_state.science_runtime.is_some() {
                    stop_sandbox_state(&app, &mut app_state)?;
                } else if proc::loopback_port_in_use(
                    expected_port,
                    operation::LOCAL_HEALTH_TIMEOUT_MS,
                ) {
                    return Err("Science 端口被未知进程占用，已拒绝改写历史身份".into());
                }
            }
            let current_cfg =
                config::load_from(&config::default_dir()).map_err(|e| e.to_string())?;
            if current_cfg.mode != "proxy"
                || current_cfg.sandbox_port != expected_port
                || current_cfg.runtime_transaction.is_some()
                || current_cfg
                    .active_profile()
                    .map(|profile| profile.id.as_str())
                    != Some(active_profile_id.as_str())
            {
                return Err("运行配置或事务在恢复前已变化，本次选择已作废".into());
            }
            let _ = crate::oauth_forge::restore_history_choice(
                &auth_dir,
                "virtual@localhost.invalid",
                &sandbox_root,
                &candidate,
            )?;
            // Consume every old reference after a successful selection. Fresh
            // references preserve the in-session "choose again" escape hatch
            // without making an invoke token replayable.
            let refreshed_choices = {
                let mut app_state = lock(&state);
                app_state.boot_attention = None;
                let session = app_state
                    .history_recovery
                    .as_mut()
                    .ok_or("历史恢复会话已过期")?;
                session
                    .choices
                    .iter_mut()
                    .enumerate()
                    .map(|(index, choice)| {
                        choice.reference = config::new_id();
                        let label = if index < 26 {
                            format!("历史记录 {}", (b'A' + index as u8) as char)
                        } else {
                            format!("历史记录 {}", index + 1)
                        };
                        json!({"reference": choice.reference, "label": label})
                    })
                    .collect::<Vec<_>>()
            };
            Ok(json!({
                "status": "ok",
                "action": "history_choice_restored",
                "message": "已恢复所选历史记录；其他历史记录未被删除。",
                "choices": refreshed_choices
            }))
        })
    })
    .await
}

fn one_click_failure_value(message: String) -> serde_json::Value {
    let environment_uncertain = message.contains("environment_uncertain");
    let recovery_status = if environment_uncertain {
        "environment_uncertain"
    } else {
        config::load_from(&config::default_dir())
            .ok()
            .and_then(|cfg| cfg.runtime_transaction)
            .map(|_| "degraded")
            .unwrap_or("not_needed")
    };
    let stage = science_failure_stage(&message);
    json!({
        "action": "failed",
        "stage": stage,
        "status": "error",
        "recovery_status": recovery_status,
        "environment_status": if environment_uncertain { "uncertain" } else { "not_exposed" },
        "message": message,
        "fallback_url": null,
    })
}

fn science_failure_stage(message: &str) -> &'static str {
    if message.contains("停止旧进程") || message.contains("停止沙箱") {
        "science_stop"
    } else if message.contains("模型目录") || message.contains("selector") {
        "catalog_verify"
    } else if message.contains("代理") || message.contains("gateway") {
        "gateway_start"
    } else if message.contains("沙箱")
        || message.contains("Science")
        || message.contains("science_api_")
        || message.contains("science_db_")
    {
        "science_start"
    } else {
        "prepare"
    }
}

#[tauri::command]
pub(crate) async fn science_runtime_preflight(
    state: State<'_, SharedAppState>,
) -> Result<Value, String> {
    let (version_cache, confirmed_stopped) = {
        let st = lock(state.inner());
        (
            st.science_version_cache.clone(),
            st.science_confirmed_stopped.clone(),
        )
    };
    run_blocking(move || runtime_preflight(&version_cache, confirmed_stopped.as_ref())).await
}

#[tauri::command]
pub(crate) fn open_science_download_page() -> Result<(), String> {
    open_in_browser(SCIENCE_DOWNLOAD_URL)
}

#[tauri::command]
pub(crate) fn status(state: State<'_, SharedAppState>) -> serde_json::Value {
    // 只在锁内取值，锁外做短超时探活。这里是高频 UI 状态灯，
    // 不能反复调用外部 `claude-science status`，否则前端轮询会卡住主线程。
    // 沙箱强身份确认保留在 one_click_login 的启动/复用边界。
    let (
        pport,
        secret,
        sport,
        adapter,
        base_url,
        active_profile,
        catalog_profile,
        tracked_proxy_child_alive,
        launched_provider,
        launched_gateway_kind,
        launched_shim_mode,
        launched_launch_id,
        active_contract_id,
        active_contract_digest,
        science_runtime,
    ) = {
        let mut st = lock(state.inner());
        let cfg = match config::load_from(&config::default_dir()) {
            Ok(cfg) => cfg,
            Err(e) => return status_response_for_config_error(&e),
        };
        let pport = if st.proxy_port != 0 {
            st.proxy_port
        } else {
            cfg.proxy_port
        };
        let sport = if st.sandbox_port != 0 {
            st.sandbox_port
        } else {
            cfg.sandbox_port
        };
        let tracked_proxy_child_alive = proc::tracked_child_is_running(&mut st.proxy);
        // 上游灯读生效 profile 的 adapter/base_url；无生效配置 → 空（灯显黄，不误探）。
        let (
            adapter,
            base_url,
            active_contract_id,
            active_contract_digest,
            active_profile,
            catalog_profile,
        ) = match cfg.active_profile() {
            Some(p) => {
                let (adapter, endpoint, contract_id, contract_digest) = resolve_launch_plan(p)
                    .map(|plan| {
                        (
                            plan.adapter,
                            plan.endpoint,
                            plan.contract_id,
                            plan.contract_digest,
                        )
                    })
                    .unwrap_or_else(|_| {
                        (
                            "unsupported".to_string(),
                            String::new(),
                            String::new(),
                            String::new(),
                        )
                    });
                (
                    adapter,
                    endpoint,
                    contract_id,
                    contract_digest,
                    json!({
                        "id": p.id,
                        "name": p.name,
                        "template_id": p.template_id,
                        "api_format": p.api_format,
                        "model": p.model,
                        "capabilities": profile_capabilities(p),
                    }),
                    Some(p.clone()),
                )
            }
            None => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                serde_json::Value::Null,
                None,
            ),
        };
        (
            pport,
            st.secret.clone(),
            sport,
            adapter,
            base_url,
            active_profile,
            catalog_profile,
            tracked_proxy_child_alive,
            st.provider.clone(),
            st.gateway_kind.clone(),
            st.shim_mode.clone(),
            st.launch_id.clone(),
            active_contract_id,
            active_contract_digest,
            st.science_runtime.clone(),
        )
    };
    let diagnostic_override = std::env::var_os("CSSWITCH_UPSTREAM_URL");
    let upstream = status_upstream_endpoint(&adapter, &base_url, diagnostic_override.as_deref());
    let proxy_ok = tracked_proxy_child_alive
        && !secret.is_empty()
        && !launched_gateway_kind.is_empty()
        && !launched_provider.is_empty()
        && proc::http_health_gateway(
            pport,
            Some(&secret),
            operation::STATUS_HEALTH_TIMEOUT_MS,
            proc::GatewayHealthExpectation {
                gateway: &launched_gateway_kind,
                provider: Some(&launched_provider),
                shim: Some(launched_shim_mode.as_str()),
                launch_id: Some(launched_launch_id.as_str()),
                provider_contract_id: Some(active_contract_id.as_str()),
                provider_contract_digest: Some(active_contract_digest.as_str()),
            },
        );
    let last_error = proxy_status_last_error(!secret.is_empty(), proxy_ok, pport);
    let sandbox_ok = proc::http_health(sport, None, operation::STATUS_HEALTH_TIMEOUT_MS);
    let upstream_ok = upstream
        .as_ref()
        .map(|e| proc::tcp_reachable(&e.host, e.port, operation::STATUS_UPSTREAM_TIMEOUT_MS))
        .unwrap_or(false);
    let lights = status_lights(StatusProbeInput {
        proxy_ok,
        sandbox_ok,
        upstream_ok,
        upstream_applicable: status_upstream_applicable(&adapter),
    });
    let (gateway_kind, shim_mode, catalog_shim_mode) =
        status_runtime_identity(&adapter, &secret, launched_gateway_kind, launched_shim_mode);
    let mut science = science_diagnostics(ScienceDiagnosticsInput {
        sandbox_port: sport,
        sandbox_ok,
    });
    if let (Some(object), Some(runtime)) = (science.as_object_mut(), science_runtime) {
        object.insert(
            "runtime".into(),
            json!({
                "source": runtime.source.code(),
                "version": runtime.version,
            }),
        );
    }
    build_status_response(
        lights,
        active_profile,
        &gateway_kind,
        &shim_mode,
        diagnostics_for_profile(catalog_profile.as_ref(), catalog_shim_mode),
        science,
        last_error,
    )
}

#[tauri::command]
pub(crate) fn boot_error(state: State<'_, SharedAppState>) -> Option<String> {
    lock(state.inner()).boot_error.clone()
}

#[tauri::command]
pub(crate) fn boot_attention(state: State<'_, SharedAppState>) -> Option<serde_json::Value> {
    lock(state.inner()).boot_attention.take()
}

fn manual_open_result(url: String, result: Result<(), String>) -> serde_json::Value {
    match result {
        Ok(()) => json!({
            "status": "ok",
            "message": "已向默认浏览器发出打开 Science 的请求。",
            "fallback_url": null,
        }),
        Err(error) => json!({
            "status": "error",
            "message": format!("打开浏览器失败：{error}"),
            "fallback_url": url,
        }),
    }
}

fn open_url_inner(state: &SharedAppState) -> Result<serde_json::Value, String> {
    let (sandbox_port, runtime) = {
        let st = lock(state);
        let runtime = st
            .science_runtime
            .clone()
            .ok_or("隔离 Science 尚未运行，请先「一键开始」。")?;
        (st.sandbox_port, runtime)
    };
    if sandbox_port == 0 || !sandbox_listener_matches_runtime(sandbox_port, &runtime) {
        return Err("隔离 Science 尚未就绪，请重新点击「一键开始」。".into());
    }
    // Science 的控制地址可能是短期、一次性的。每次手动打开都重新获取，
    // 不复用 one-click 已消费的内存 URL。成功时不返回 URL；只有系统
    // opener 失败时才把同一次新 URL 交给 UI，供用户复制或再次打开。
    let url = sandbox_url(sandbox_port, &runtime);
    Ok(manual_open_result(url.clone(), open_in_browser(&url)))
}

#[tauri::command]
pub(crate) async fn open_url(
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
) -> Result<serde_json::Value, String> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking(move || lifecycle.with_serialized(|| open_url_inner(&state))).await
}

#[tauri::command]
pub(crate) async fn quit_app(
    app: tauri::AppHandle,
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
) -> Result<(), String> {
    let exit_app = app.clone();
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking(move || stop_all_inner_cmd(app, state, lifecycle)).await?;
    exit_app.exit(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        config_last_error_json, manual_open_result, science_failure_stage,
        status_response_for_config_error, status_runtime_identity, status_upstream_applicable,
    };
    use crate::{config, lock, runtime::science, AppState, SharedAppState};
    use std::{
        env, fs,
        net::TcpStream,
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    // 以下导入仅被 #[cfg(unix)] 门控的集成测试使用。
    #[cfg(unix)]
    use crate::{
        config::{Config, Profile},
        lifecycle,
        runtime::{proxy_lifecycle, sandbox_session},
    };
    #[cfg(unix)]
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        path::Path,
        sync::Mutex,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    // unix 专属 API（symlink/MetadataExt/PermissionsExt）：仅 unix 下编译；
    // 依赖它们的测试与 helper 已各自加 #[cfg(unix)] 门控。
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    #[cfg(unix)]
    use tauri::{Listener, Manager};

    #[test]
    fn config_last_error_json_preserves_typed_config_error() {
        let err = config_last_error_json(&"bad config");
        assert_eq!(
            err.get("type").and_then(|v| v.as_str()),
            Some("config_error")
        );
        assert_eq!(
            err.get("message").and_then(|v| v.as_str()),
            Some("bad config")
        );
    }

    #[test]
    fn status_response_for_config_error_is_fail_closed() {
        let v = status_response_for_config_error(&"bad config");
        assert_eq!(v["proxy"], "amber");
        assert_eq!(v["sandbox"], "amber");
        assert_eq!(v["upstream"], "amber");
        assert_eq!(v["active_profile"], serde_json::Value::Null);
        assert_eq!(v["science"]["sandbox"]["port"], 0);
        assert_eq!(v["last_error"]["type"], "config_error");
        assert_eq!(v["last_error"]["message"], "bad config");
    }

    #[test]
    fn upstream_applicability_is_provider_semantics_not_endpoint_parse_success() {
        assert!(!status_upstream_applicable(""));
        assert!(status_upstream_applicable("relay"));
        assert!(status_upstream_applicable("deepseek"));
    }

    #[test]
    fn status_runtime_identity_prefers_launched_identity_and_fail_closes_partial_launch() {
        let (gateway, shim, catalog_shim) =
            status_runtime_identity("deepseek", "", String::new(), String::new());
        assert_eq!(gateway, "rust");
        assert_eq!(shim, "rewrite");
        assert_eq!(catalog_shim, "rewrite");

        let (gateway, shim, catalog_shim) =
            status_runtime_identity("deepseek", "secret-present", "rust".into(), "off".into());
        assert_eq!(gateway, "rust");
        assert_eq!(shim, "off");
        assert_eq!(catalog_shim, "rewrite");

        let (gateway, shim, catalog_shim) =
            status_runtime_identity("deepseek", "secret-present", String::new(), String::new());
        assert_eq!(gateway, "");
        assert_eq!(shim, "");
        assert_eq!(catalog_shim, "rewrite");
    }

    #[test]
    fn science_operation_failures_have_stable_structured_stages() {
        assert_eq!(science_failure_stage("停止旧进程失败"), "science_stop");
        assert_eq!(science_failure_stage("代理探活失败"), "gateway_start");
        assert_eq!(science_failure_stage("模型目录不一致"), "catalog_verify");
        assert_eq!(
            science_failure_stage("gateway 模型目录探活无响应"),
            "catalog_verify"
        );
        assert_eq!(science_failure_stage("沙箱起后超时"), "science_start");
        assert_eq!(
            science_failure_stage("science_api_health_status_401"),
            "science_start"
        );
        assert_eq!(
            science_failure_stage("science_db_reverify_timeout"),
            "science_start"
        );
        assert_eq!(science_failure_stage("配置不可用"), "prepare");
    }

    #[test]
    fn manual_browser_failure_returns_the_same_fresh_url_for_copy_and_retry() {
        let url = "http://127.0.0.1:8990/?nonce=fresh".to_string();
        let failed = manual_open_result(url.clone(), Err("opener rejected".into()));
        assert_eq!(failed["status"], "error");
        assert_eq!(failed["fallback_url"], url);
        assert!(failed["message"]
            .as_str()
            .unwrap()
            .contains("打开浏览器失败"));

        let opened = manual_open_result(url, Ok(()));
        assert_eq!(opened["status"], "ok");
        assert!(opened["fallback_url"].is_null());
    }

    #[allow(dead_code)] // 仅被 #[cfg(unix)] 门控的集成测试使用
    struct EnvGuard {
        saved: Vec<(String, Option<std::ffi::OsString>)>,
    }

    #[allow(dead_code)] // 仅被 #[cfg(unix)] 门控的集成测试使用
    impl EnvGuard {
        fn new() -> Self {
            Self { saved: Vec::new() }
        }

        fn set(&mut self, key: &str, value: impl AsRef<std::ffi::OsStr>) {
            self.saved.push((key.to_string(), env::var_os(key)));
            env::set_var(key, value);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.iter().rev() {
                match value {
                    Some(v) => env::set_var(key, v),
                    None => env::remove_var(key),
                }
            }
        }
    }

    #[cfg(unix)]
    fn tmpdir(label: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("csswitch-{label}-{}-{now}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path.canonicalize().unwrap()
    }

    #[cfg(unix)]
    fn free_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_ne!(port, 8765);
        port
    }

    #[cfg(unix)]
    fn ssh_fixture_ports() -> (u16, u16) {
        for _ in 0..128 {
            let proxy_port = free_port();
            let sandbox_port = free_port();
            if matches!(sandbox_port, 8764 | 8765 | 65535) {
                continue;
            }
            let preview_port = sandbox_port + 1;
            if preview_port == 8765 || proxy_port == sandbox_port || proxy_port == preview_port {
                continue;
            }
            return (proxy_port, sandbox_port);
        }
        panic!("could not allocate a safe pairwise-distinct proxy/sandbox/preview port set");
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    fn write_test_bins(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        write_executable(
            &dir.join("open"),
            r#"#!/bin/sh
if [ -n "${CSSWITCH_FAKE_OPEN_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$CSSWITCH_FAKE_OPEN_LOG"
fi
if [ -n "${CSSWITCH_FAKE_OPEN_FAIL_ONCE_FILE:-}" ] && [ ! -e "$CSSWITCH_FAKE_OPEN_FAIL_ONCE_FILE" ]; then
  : > "$CSSWITCH_FAKE_OPEN_FAIL_ONCE_FILE"
  exit 1
fi
exit 0
"#,
        );
        write_executable(
            &dir.join("security"),
            r#"#!/bin/sh
exit 0
"#,
        );
        let science_bin = dir.join("claude-science");
        write_executable(
            &science_bin,
            r#"#!/bin/sh
set -eu
cmd="${1:-}"
if [ "$#" -gt 0 ]; then shift; fi
if [ -n "${CSSWITCH_FAKE_SCIENCE_CALL_LOG:-}" ]; then
  printf '%s\n' "$cmd" >> "$CSSWITCH_FAKE_SCIENCE_CALL_LOG"
fi
if [ "$cmd" = "--version" ]; then
  echo "claude-science 0.0.0-csswitch-test"
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
    count="$(cat "$state/serve-count" 2>/dev/null || echo 0)"
    count=$((count + 1))
    printf '%s' "$count" > "$state/serve-count"
    failure_control="$state/fail-after-inplace-mutation"
    if [ -f "$failure_control" ]; then
      mutation_file="$(/usr/bin/sed -n '1p' "$failure_control")"
      failure_marker="$(/usr/bin/sed -n '2p' "$failure_control")"
      printf '%s\n' "mutated-by-failing-science" > "$mutation_file"
      chmod 0644 "$mutation_file"
      if [ -n "$failure_marker" ]; then
        printf '%s\n' "serve-mutated-before-exit" > "$failure_marker"
      fi
      exit 23
    fi
    if [ "$count" -eq 2 ] && [ -n "${CSSWITCH_FAKE_SCIENCE_SECOND_BOOT_BLOCKS:-}" ]; then
      trap '' HUP
      printf '%s\n' "mutated-by-blocked-second-candidate" > "$CSSWITCH_FAKE_SCIENCE_UNBOUND_MUTATION"
      printf '%s' "$$" > "$CSSWITCH_FAKE_SCIENCE_UNBOUND_PID"
      while :; do sleep 60; done
    fi
    if [ "$count" -eq 2 ] && [ -n "${CSSWITCH_FAKE_SCIENCE_SECOND_BOOT_NO_LISTENER:-}" ]; then
      python3 - "$CSSWITCH_FAKE_SCIENCE_UNBOUND_PID" "$CSSWITCH_FAKE_SCIENCE_UNBOUND_MUTATION" >/dev/null 2>&1 <<'PY' &
import os
import sys
import time
pidfile = sys.argv[1]
mutation = sys.argv[2]
with open(mutation, "w", encoding="utf-8") as f:
    f.write("mutated-by-unbound-second-candidate\n")
with open(pidfile, "w", encoding="utf-8") as f:
    f.write(str(os.getpid()))
while True:
    time.sleep(60)
PY
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -s "$CSSWITCH_FAKE_SCIENCE_UNBOUND_PID" ] && break
        sleep 0.02
      done
      exit 0
    fi
    printf '%s' "$port" > "$state/port"
    python3 - "$port" "$state/pid" "$data_dir" "$count" >/dev/null 2>&1 <<'PY' &
import http.server
import os
import socketserver
import sys
import time
import urllib.parse
port = int(sys.argv[1])
pidfile = sys.argv[2]
data_dir = sys.argv[3]
generation = sys.argv[4]
origin = f"http://127.0.0.1:{port}"
auth_cookie = generation.zfill(64)
db_health = os.environ.get("CSSWITCH_FAKE_SCIENCE_DB_HEALTH", "clear")
verdict = os.path.join(data_dir, "fake-db-damage-verdict")
boot_skipped = db_health == "stateful" and os.path.exists(verdict)
class Handler(http.server.BaseHTTPRequestHandler):
    health_polls = 0
    def log_message(self, *args):
        pass
    def reject_auth(self):
        self.send_response(401)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"detail":"invalid bearer token"}')
    def do_POST(self):
        if self.path != "/api/auth/nonce":
            self.send_response(404)
            self.end_headers()
            return
        if self.headers.get("Origin") != origin:
            self.reject_auth()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.reject_auth()
            return
        if length <= 0 or length > 4096:
            self.reject_auth()
            return
        form = urllib.parse.parse_qs(
            self.rfile.read(length).decode("ascii"),
            keep_blank_values=True,
        )
        try:
            with open(os.path.join(data_dir, "fake-science", "url-nonce"), encoding="utf-8") as f:
                expected_nonce = f.read().strip()
        except OSError:
            self.reject_auth()
            return
        if form.get("nonce") != [expected_nonce] or form.get("dest") != ["/"]:
            self.reject_auth()
            return
        self.send_response(200)
        self.send_header(
            "Set-Cookie",
            f"operon_auth={auth_cookie}; Path=/; HttpOnly; SameSite=Strict",
        )
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def do_GET(self):
        if self.path.startswith("/api/health"):
            cookies = {}
            for item in self.headers.get("Cookie", "").split(";"):
                if "=" in item:
                    name, value = item.split("=", 1)
                    cookies[name.strip()] = value.strip()
            if self.headers.get("Origin") != origin or cookies.get("operon_auth") != auth_cookie:
                self.reject_auth()
                return
            if db_health == "stalled":
                time.sleep(2)
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            Handler.health_polls += 1
            if boot_skipped:
                if Handler.health_polls == 1:
                    self.wfile.write(b'{"db_corruption":{"flagged":true,"kind":"damage"},"db_migrations_skipped":true}')
                    return
                try:
                    os.unlink(verdict)
                except FileNotFoundError:
                    pass
                self.wfile.write(b'{"db_corruption":{"flagged":false,"kind":null},"db_migrations_skipped":true}')
            elif db_health == "skipped":
                self.wfile.write(b'{"db_corruption":{"flagged":false,"kind":null},"db_migrations_skipped":true}')
            elif db_health == "damage-reverify":
                self.wfile.write(b'{"db_corruption":{"flagged":true,"kind":"damage"},"db_migrations_skipped":true}')
            elif db_health == "damage":
                self.wfile.write(b'{"db_corruption":{"flagged":true,"kind":"damage"},"db_migrations_skipped":false}')
            elif db_health == "io-errors":
                self.wfile.write(b'{"db_corruption":{"flagged":true,"kind":"io_errors"},"db_migrations_skipped":false}')
            elif db_health == "missing-kind":
                self.wfile.write(b'{"db_corruption":{"flagged":true},"db_migrations_skipped":false}')
            else:
                self.wfile.write(b'{"db_corruption":{"flagged":false,"kind":null},"db_migrations_skipped":false}')
        elif self.path.startswith("/health"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fake science")
socketserver.TCPServer.allow_reuse_address = True
with open(pidfile, "w", encoding="utf-8") as f:
    f.write(str(os.getpid()))
with socketserver.TCPServer(("127.0.0.1", port), Handler) as httpd:
    httpd.serve_forever()
PY
    exit 0
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
  url)
    p="$(cat "$state/port")"
    count="$(cat "$state/url-count" 2>/dev/null || echo 0)"
    count=$((count + 1))
    printf '%s' "$count" > "$state/url-count"
    nonce="$(printf '%064x' "$count")"
    printf '%s' "$nonce" > "$state/url-nonce"
    echo "http://127.0.0.1:$p/?nonce=$nonce"
    ;;
  stop)
    if [ -n "${CSSWITCH_TEST_PORT_OBSERVATION_SEQUENCE_DIR:-}" ]; then
      mkdir -p "$CSSWITCH_TEST_PORT_OBSERVATION_SEQUENCE_DIR"
      : > "$CSSWITCH_TEST_PORT_OBSERVATION_SEQUENCE_DIR/armed"
      echo "stopped-with-false-then-true-port-observation"
      exit 0
    fi
    if [ -n "${CSSWITCH_TEST_PROCESS_START_DRIFT_MARKER:-}" ]; then
      : > "$CSSWITCH_TEST_PROCESS_START_DRIFT_MARKER"
      echo "stopped-with-identity-drift"
      exit 0
    fi
    pid="$(cat "$state/pid" 2>/dev/null || true)"
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
    rm -f "$state/pid"
    echo "stopped"
    ;;
  *)
    echo "unsupported fake science command: $cmd" >&2
    exit 2
    ;;
esac
"#,
        );
        science_bin
    }

    #[allow(dead_code)] // 仅被 #[cfg(unix)] 门控的集成测试使用
    struct MockUpstream {
        port: u16,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for MockUpstream {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(("127.0.0.1", self.port));
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    #[allow(dead_code)] // 仅被 #[cfg(unix)] 门控的集成测试使用
    struct RuntimeSmokeCleanup<R: tauri::Runtime> {
        handle: tauri::AppHandle<R>,
        state: SharedAppState,
        temp: PathBuf,
        sandbox_port: u16,
        proxy_port: u16,
        armed: bool,
    }

    #[allow(dead_code)] // 仅被 #[cfg(unix)] 门控的集成测试使用
    impl<R: tauri::Runtime> RuntimeSmokeCleanup<R> {
        fn new(
            handle: tauri::AppHandle<R>,
            state: SharedAppState,
            temp: PathBuf,
            sandbox_port: u16,
            proxy_port: u16,
        ) -> Self {
            Self {
                handle,
                state,
                temp,
                sandbox_port,
                proxy_port,
                armed: true,
            }
        }

        fn cleanup(&mut self) -> Result<(), String> {
            if !self.armed {
                return Ok(());
            }
            self.armed = false;
            let stop_result = {
                let mut st = lock(&self.state);
                let AppState {
                    sandbox,
                    sandbox_url,
                    science_runtime,
                    ..
                } = &mut *st;
                let runtime = science_runtime.clone();
                let result =
                    science::stop_sandbox(&self.handle, sandbox, sandbox_url, runtime.as_ref());
                st.stop_proxy();
                result
            };
            stop_result?;
            for (label, port) in [("Science", self.sandbox_port), ("Gateway", self.proxy_port)] {
                let mut closed = false;
                for _ in 0..50 {
                    if TcpStream::connect(("127.0.0.1", port)).is_err() {
                        closed = true;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                if !closed {
                    return Err(format!(
                        "{label} fixture port {port} remained reachable; preserved {}",
                        self.temp.display()
                    ));
                }
            }
            let managed_launch = self
                .temp
                .join("home")
                .join(config::CONFIG_DIR_NAME)
                .join("science-managed-launch.v1.json");
            if managed_launch.exists() {
                return Err(format!(
                    "confirmed Science stop left managed launch receipt {}; preserved {}",
                    managed_launch.display(),
                    self.temp.display()
                ));
            }
            fs::remove_dir_all(&self.temp)
                .map_err(|error| format!("failed to remove {}: {error}", self.temp.display()))
        }

        fn finish(mut self) -> Result<(), String> {
            self.cleanup()
        }
    }

    impl<R: tauri::Runtime> Drop for RuntimeSmokeCleanup<R> {
        fn drop(&mut self) {
            if let Err(error) = self.cleanup() {
                eprintln!("isolated runtime cleanup failed: {error}");
            }
        }
    }

    #[cfg(unix)]
    fn start_mock_upstream() -> MockUpstream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_ne!(port, 8765);
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0; 512];
                        let _ = stream.read(&mut buf);
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        MockUpstream {
            port,
            stop,
            worker: Some(worker),
        }
    }

    #[cfg(unix)]
    fn wait_http_health(port: u16) {
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("mock service on port {port} did not become reachable");
    }

    #[cfg(unix)]
    fn wait_http_unreachable(port: u16) {
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_err() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("mock service on port {port} remained reachable");
    }

    #[cfg(unix)]
    fn force_stop_isolated_listener(port: u16) {
        let Some(pid) = listener_pid_if_unique(port) else {
            return;
        };
        assert!(pid > 1, "isolated listener PID must be signal-safe");
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_err() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if listener_pid_if_unique(port) == Some(pid) {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
        wait_http_unreachable(port);
    }

    #[cfg(unix)]
    fn force_cleanup_isolated_fixture(
        state: &SharedAppState,
        temp: &Path,
        sandbox_port: u16,
        proxy_port: u16,
    ) {
        if let Some(mut proxy) = lock(state).proxy.take() {
            let _ = proxy.kill();
            let _ = proxy.wait();
        }
        force_stop_isolated_listener(sandbox_port);
        force_stop_isolated_listener(proxy_port);
        if temp.exists() {
            fs::remove_dir_all(temp).unwrap();
        }
    }

    #[cfg(unix)]
    fn start_managed_fake_science(
        fake_science: &Path,
        sandbox_home: &Path,
        science_data: &Path,
        sandbox_port: u16,
        runtime: &science::ScienceRuntimeIdentity,
    ) -> u32 {
        let status = std::process::Command::new(fake_science)
            .arg("serve")
            .arg("--port")
            .arg(sandbox_port.to_string())
            .arg("--data-dir")
            .arg(science_data)
            .env("HOME", sandbox_home)
            .status()
            .unwrap();
        assert!(status.success(), "managed fake Science must launch");
        wait_http_health(sandbox_port);
        let listener_pid = unique_listener_pid(sandbox_port);
        science::record_managed_science_launch(sandbox_port, runtime)
            .expect("managed fake Science must commit its initial receipt");
        listener_pid
    }

    #[cfg(unix)]
    fn call_count(path: &Path, command: &str) -> usize {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == command)
            .count()
    }

    #[cfg(unix)]
    fn invoke_json<W: AsRef<tauri::Webview<tauri::test::MockRuntime>>>(
        webview: &W,
        command: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        tauri::test::get_ipc_response(
            webview,
            tauri::webview::InvokeRequest {
                cmd: command.into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: "tauri://localhost".parse().unwrap(),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.into(),
            },
        )
        .and_then(|body| {
            body.deserialize::<serde_json::Value>()
                .map_err(|error| serde_json::Value::String(error.to_string()))
        })
        .map_err(|error| {
            error.as_str().map(str::to_string).unwrap_or_else(|| {
                let code = error
                    .get("code")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                let cause = error
                    .get("cause")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("none");
                format!("typed IPC error code={code} cause={cause}")
            })
        })
    }

    #[cfg(unix)]
    fn listener_pid_if_unique(port: u16) -> Option<u32> {
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
            .output()
            .expect("lsof should inspect the isolated listener");
        if !output.status.success() {
            return None;
        }
        let pids: Vec<u32> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::trim)
            .filter(|pid| !pid.is_empty())
            .map(|pid| pid.parse().unwrap())
            .collect();
        (pids.len() == 1).then(|| pids[0])
    }

    #[cfg(unix)]
    fn unique_listener_pid(port: u16) -> u32 {
        listener_pid_if_unique(port).expect("isolated port must have one listener")
    }

    #[cfg(unix)]
    fn process_start_identity_if_alive(pid: u32) -> Option<String> {
        let output = std::process::Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart="])
            .env_clear()
            .output()
            .expect("ps should inspect the isolated process");
        if !output.status.success() {
            return None;
        }
        assert!(output.stderr.is_empty());
        let identity = String::from_utf8(output.stdout).unwrap();
        let identity = identity.trim();
        (!identity.is_empty()).then(|| identity.to_string())
    }

    #[cfg(unix)]
    fn process_start_identity(pid: u32) -> String {
        process_start_identity_if_alive(pid).expect("isolated process must remain alive")
    }

    #[cfg(unix)]
    fn ssh_fixture_config(mock_upstream_port: u16, proxy_port: u16, sandbox_port: u16) -> Config {
        let route_id = "claude-csswitch-relay-ssh-transaction-0123456789ab";
        let profile = Profile {
            id: "ssh-transaction".into(),
            name: "SSH transaction fixture".into(),
            template_id: "custom".into(),
            category: "custom".into(),
            api_format: "anthropic".into(),
            base_url: format!("http://127.0.0.1:{mock_upstream_port}/anthropic"),
            api_key: "ssh-transaction-fake-key-never-log".into(),
            model: "mock-model".into(),
            model_catalog: vec![crate::model_catalog::ModelRoute {
                selector_id: route_id.into(),
                display_name: "Mock model".into(),
                upstream_model: "mock-model".into(),
                supports_tools: Some(true),
                ..Default::default()
            }],
            default_model_route_id: route_id.into(),
            role_bindings: crate::model_catalog::RoleBindings {
                sonnet: route_id.into(),
                opus: route_id.into(),
                haiku: route_id.into(),
                fable: route_id.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        Config {
            profiles: vec![profile],
            active_id: "ssh-transaction".into(),
            proxy_port,
            sandbox_port,
            reuse_system_ssh: true,
            ..Default::default()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[allow(dead_code)] // 仅被 #[cfg(unix)] 门控的集成测试使用
    struct AuthorityTreeEntry {
        kind: &'static str,
        mode: u32,
        bytes: Vec<u8>,
    }

    #[cfg(unix)]
    fn authority_tree(root: &Path) -> BTreeMap<PathBuf, AuthorityTreeEntry> {
        fn walk(root: &Path, current: &Path, result: &mut BTreeMap<PathBuf, AuthorityTreeEntry>) {
            let metadata = match fs::symlink_metadata(current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Err(error) => {
                    panic!(
                        "authority snapshot failed for {}: {error}",
                        current.display()
                    )
                }
            };
            let relative = current.strip_prefix(root).unwrap().to_path_buf();
            if metadata.file_type().is_symlink() {
                result.insert(
                    relative,
                    AuthorityTreeEntry {
                        kind: "symlink",
                        mode: metadata.permissions().mode() & 0o777,
                        bytes: fs::read_link(current)
                            .unwrap()
                            .as_os_str()
                            .as_encoded_bytes()
                            .to_vec(),
                    },
                );
                return;
            }
            if metadata.is_file() {
                result.insert(
                    relative,
                    AuthorityTreeEntry {
                        kind: "file",
                        mode: metadata.permissions().mode() & 0o777,
                        bytes: fs::read(current).unwrap(),
                    },
                );
                return;
            }
            assert!(
                metadata.is_dir(),
                "authority fixture contains a special file"
            );
            result.insert(
                relative,
                AuthorityTreeEntry {
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
                walk(root, &child, result);
            }
        }

        let mut result = BTreeMap::new();
        walk(root, root, &mut result);
        result
    }

    #[cfg(unix)]
    fn science_authority_projection(root: &Path) -> BTreeMap<PathBuf, AuthorityTreeEntry> {
        let mut result = BTreeMap::new();
        for entry in crate::runtime::sandbox_session::SCIENCE_PROTECTED_AUTHORITY_ENTRIES {
            for (relative, value) in authority_tree(&root.join(entry)) {
                let projected = if relative.as_os_str().is_empty() {
                    PathBuf::from(entry)
                } else {
                    PathBuf::from(entry).join(relative)
                };
                result.insert(projected, value);
            }
        }
        result
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[allow(dead_code)] // 仅被 #[cfg(unix)] 门控的集成测试使用
    struct AppAuthorityProjection {
        proxy_present: bool,
        proxy_port: u16,
        secret: String,
        provider: String,
        gateway_kind: String,
        shim_mode: String,
        launch_id: String,
        key_fp: u64,
        sandbox_present: bool,
        sandbox_port: u16,
        sandbox_url: Option<String>,
        science_runtime: Option<science::ScienceRuntimeIdentity>,
        science_confirmed_stopped: Option<science::ScienceRuntimeIdentity>,
        history_recovery_present: bool,
    }

    #[cfg(unix)]
    fn app_authority_projection(state: &SharedAppState) -> AppAuthorityProjection {
        let state = lock(state);
        AppAuthorityProjection {
            proxy_present: state.proxy.is_some(),
            proxy_port: state.proxy_port,
            secret: state.secret.clone(),
            provider: state.provider.clone(),
            gateway_kind: state.gateway_kind.clone(),
            shim_mode: state.shim_mode.clone(),
            launch_id: state.launch_id.clone(),
            key_fp: state.key_fp,
            sandbox_present: state.sandbox.is_some(),
            sandbox_port: state.sandbox_port,
            sandbox_url: state.sandbox_url.clone(),
            science_runtime: state.science_runtime.clone(),
            science_confirmed_stopped: state.science_confirmed_stopped.clone(),
            history_recovery_present: state.history_recovery.is_some(),
        }
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary SSH transaction smoke; temp HOME, fake OAuth, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_ssh_prevalidation_precedes_oauth_mutation() {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let requested_case = env::var("CSSWITCH_TEST_SSH_PREVALIDATION_CASE").unwrap_or_default();
        let cases = [
            ("missing-system-config", "无法读取已授权的 SSH config"),
            ("no-concrete-host", "没有可枚举的具体 Host alias"),
            (
                "oversized-system-config",
                "SSH config 不是普通文件或超过安全大小上限",
            ),
            (
                "foreign-sandbox-stub",
                "隔离 SSH config 不是 CSSwitch 管理的安全入口",
            ),
            (
                "symlink-sandbox-stub",
                "隔离 SSH config 不是 CSSwitch 管理的安全入口",
            ),
            (
                "conflicting-science-bridge",
                "隔离 Science ssh_hosts 在授权期间被外部修改",
            ),
            (
                "group-writable-science-authority",
                "隔离 Science SSH authority 不可写",
            ),
            (
                "other-writable-science-authority",
                "隔离 Science SSH authority 不可写",
            ),
            (
                "missing-packaged-wrapper",
                "打包的 CSSwitch SSH bridge 缺失",
            ),
            (
                "unsafe-packaged-wrapper",
                "打包的 CSSwitch SSH bridge 不是安全的可执行文件",
            ),
        ];
        assert!(
            requested_case.is_empty() || cases.iter().any(|(case, _)| *case == requested_case),
            "unknown SSH prevalidation case selector: {requested_case}"
        );
        let mut executed_cases = 0;
        for (case, expected_error) in cases {
            if !requested_case.is_empty() && requested_case != case {
                continue;
            }
            executed_cases += 1;
            let tmp = tmpdir(&format!("ssh-prevalidation-{case}"));
            let home = tmp.join("home");
            let bin_dir = tmp.join("bin");
            fs::create_dir_all(home.join(".ssh")).unwrap();
            if case != "missing-system-config" {
                if case == "oversized-system-config" {
                    fs::write(home.join(".ssh/config"), vec![b'x'; 256 * 1024 + 1]).unwrap();
                } else {
                    let body = if case == "no-concrete-host" {
                        "Host * !blocked\n"
                    } else {
                        "Host isolated-test-host\n"
                    };
                    fs::write(home.join(".ssh/config"), body).unwrap();
                }
                fs::set_permissions(home.join(".ssh/config"), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
            let mock_upstream = start_mock_upstream();
            let (proxy_port, sandbox_port) = ssh_fixture_ports();

            let mut env_guard = EnvGuard::new();
            env_guard.set("HOME", &home);
            env_guard.set("SCIENCE_BIN", &fake_science);
            env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
            env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
            env_guard.set(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                    bin_dir.to_string_lossy()
                ),
            );
            env_guard.set("CSSWITCH_REPO", &repository);
            if case == "missing-packaged-wrapper" {
                env_guard.set(
                    "CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE",
                    tmp.join("missing-wrapper"),
                );
            } else if case == "unsafe-packaged-wrapper" {
                let unsafe_wrapper = tmp.join("unsafe-wrapper");
                fs::write(&unsafe_wrapper, b"not executable\n").unwrap();
                fs::set_permissions(&unsafe_wrapper, fs::Permissions::from_mode(0o600)).unwrap();
                env_guard.set("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE", unsafe_wrapper);
            }

            let config_dir = config::default_dir();
            let before = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
            config::save_to(&config_dir, &before).unwrap();
            let sandbox_home = home
                .join(config::CONFIG_DIR_NAME)
                .join("sandbox")
                .join("home");
            let science_data = sandbox_home.join(".claude-science");
            let mut foreign_target = None;
            if case == "foreign-sandbox-stub" {
                fs::create_dir_all(sandbox_home.join(".ssh")).unwrap();
                fs::write(
                    sandbox_home.join(".ssh/config"),
                    b"foreign-prevalidation-stub\n",
                )
                .unwrap();
                fs::set_permissions(
                    sandbox_home.join(".ssh/config"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            } else if case == "symlink-sandbox-stub" {
                fs::create_dir_all(sandbox_home.join(".ssh")).unwrap();
                let target = tmp.join("foreign-stub-target");
                fs::write(&target, b"foreign-symlink-target\n").unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
                symlink(&target, sandbox_home.join(".ssh/config")).unwrap();
                foreign_target = Some(target);
            }
            if case == "conflicting-science-bridge" {
                fs::create_dir_all(&science_data).unwrap();
                fs::write(
                    science_data.join("config.toml"),
                    "ssh_hosts = [\"foreign-edit\"]\n",
                )
                .unwrap();
                fs::set_permissions(
                    science_data.join("config.toml"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                fs::write(
                    science_data.join("csswitch-ssh-bridge.v1.json"),
                    br#"{"schema_version":1,"original_ssh_hosts":null,"effective_ssh_hosts":["prior-managed"],"managed_hosts":["prior-managed"]}"#,
                )
                .unwrap();
                fs::set_permissions(
                    science_data.join("csswitch-ssh-bridge.v1.json"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            } else if matches!(
                case,
                "group-writable-science-authority" | "other-writable-science-authority"
            ) {
                fs::create_dir_all(&science_data).unwrap();
                fs::write(science_data.join("config.toml"), b"quiet_logs = true\n").unwrap();
                fs::set_permissions(
                    science_data.join("config.toml"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                let mode = if case == "group-writable-science-authority" {
                    0o720
                } else {
                    0o702
                };
                fs::set_permissions(&science_data, fs::Permissions::from_mode(mode)).unwrap();
            }
            let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
            let config_before = config::load_from(&config_dir).unwrap();
            let app_before = app_authority_projection(&state);
            let system_ssh_before = authority_tree(&home.join(".ssh"));
            let science_before = science_authority_projection(&science_data);
            let private_state_before =
                authority_tree(&sandbox_home.parent().unwrap().join("state"));
            let runtime_before = authority_tree(&config_dir.join("runtime"));
            let stub_before = authority_tree(&sandbox_home.join(".ssh"));
            let foreign_target_before = foreign_target
                .as_deref()
                .map(authority_tree)
                .unwrap_or_default();
            let receipt_before = authority_tree(&config_dir.join("science-managed-launch.v1.json"));
            let lifecycle = Arc::new(lifecycle::Lifecycle::new());
            let app = tauri::test::mock_builder()
                .manage(state.clone())
                .manage(lifecycle.clone())
                .build(tauri::test::mock_context(tauri::test::noop_assets()))
                .unwrap();
            let handle = app.handle().clone();
            let cleanup = RuntimeSmokeCleanup::new(
                handle.clone(),
                state.clone(),
                tmp.clone(),
                sandbox_port,
                proxy_port,
            );

            let result = sandbox_session::one_click_login(
                handle,
                state.clone(),
                lifecycle.as_ref(),
                None,
                None,
            );
            let exact_error = result
                .as_ref()
                .is_err_and(|error| error.contains(expected_error));
            let authorities_unchanged = config::load_from(&config_dir).unwrap() == config_before
                && app_authority_projection(&state) == app_before
                && authority_tree(&home.join(".ssh")) == system_ssh_before
                && science_authority_projection(&science_data) == science_before
                && authority_tree(&sandbox_home.parent().unwrap().join("state"))
                    == private_state_before
                && authority_tree(&config_dir.join("runtime")) == runtime_before
                && authority_tree(&sandbox_home.join(".ssh")) == stub_before
                && foreign_target
                    .as_deref()
                    .map(authority_tree)
                    .unwrap_or_default()
                    == foreign_target_before
                && authority_tree(&config_dir.join("science-managed-launch.v1.json"))
                    == receipt_before
                && TcpStream::connect(("127.0.0.1", proxy_port)).is_err()
                && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err();
            cleanup
                .finish()
                .expect("prevalidation failure fixture must leave no process residue");

            assert!(
                exact_error,
                "{case} must reach its exact SSH-specific prevalidation refusal; observed={result:?}"
            );
            assert!(
                authorities_unchanged,
                "{case} must be rejected before OAuth, profile, Gateway, Science, bridge, stub, installer, receipt, or journal authority changes"
            );
        }
        assert_eq!(
            executed_cases,
            if requested_case.is_empty() {
                cases.len()
            } else {
                1
            },
            "SSH prevalidation selector must execute the exact requested oracle set"
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary SSH transaction smoke; temp HOME, fake OAuth, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_ssh_late_failure_compensates_every_authority_and_retry_is_idempotent() {
        let oracle_first = env::var("CSSWITCH_TEST_SSH_ORACLE_FIRST").unwrap_or_default();
        let failure_edge = env::var("CSSWITCH_TEST_SSH_LATE_FAILURE_EDGE")
            .unwrap_or_else(|_| "foreign-stub".into());
        assert!(
            matches!(
                oracle_first.as_str(),
                "" | "oauth" | "gateway" | "gateway-child" | "journal" | "bridge"
            ),
            "unknown SSH late-failure oracle selector: {oracle_first}"
        );
        let owned_gateway_oracle = oracle_first == "gateway-child";
        assert!(
            matches!(
                failure_edge.as_str(),
                "foreign-stub"
                    | "spawn-error"
                    | "serve-mutates-then-exits"
                    | "host-proof-drift"
                    | "db-health-skipped"
                    | "db-health-recovery"
                    | "db-health-never-clears"
                    | "db-health-stalled"
                    | "db-health-io-errors"
                    | "db-health-missing-kind"
                    | "db-restart-no-listener"
                    | "db-restart-launch-blocks"
                    | "post-status-receipt"
            ),
            "unknown SSH late-failure edge selector: {failure_edge}"
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("ssh-late-failure");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::write(home.join(".ssh/config"), "Host isolated-test-host\n").unwrap();
        fs::set_permissions(home.join(".ssh/config"), fs::Permissions::from_mode(0o600)).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let open_log = tmp.join("open.log");
        let science_call_log = tmp.join("science-call.log");
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_FAKE_OPEN_LOG", &open_log);
        env_guard.set("CSSWITCH_FAKE_SCIENCE_CALL_LOG", &science_call_log);
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        let gateway_publish_log = tmp.join("gateway-publish.log");
        if owned_gateway_oracle {
            fs::write(&gateway_publish_log, b"").unwrap();
            fs::set_permissions(&gateway_publish_log, fs::Permissions::from_mode(0o600)).unwrap();
            env_guard.set("CSSWITCH_TEST_GATEWAY_PUBLISH_LOG", &gateway_publish_log);
        }
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut before = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        let operation_api_canary = format!("ssh-transaction-key-{}", config::new_id());
        before
            .profile_by_id_mut("ssh-transaction")
            .expect("candidate fixture profile must exist")
            .api_key = operation_api_canary.clone();
        let candidate_profile_id = before.active_id.clone();
        before.secret = config::new_id();
        before.runtime_transaction = Some(config::RuntimeTransactionJournal {
            transaction_id: "prior-ssh-transaction-journal".into(),
            target_profile_id: candidate_profile_id.clone(),
            stage: "prior-authority".into(),
            previous_binding: before.runtime_binding.clone(),
            previous_gateway: None,
        });
        config::save_to(&config_dir, &before).unwrap();
        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let science_data = sandbox_home.join(".claude-science");
        fs::create_dir_all(science_data.join("mcp")).unwrap();
        crate::oauth_forge::ensure_virtual_login(
            &science_data,
            "virtual@localhost.invalid",
            &sandbox_home,
        )
        .unwrap();
        fs::remove_file(science_data.join("active-org.json")).unwrap();
        fs::write(
            science_data.join("config.toml"),
            "quiet_logs = true\nssh_hosts = [\"prior-user-host\"]\n",
        )
        .unwrap();
        fs::set_permissions(
            science_data.join("config.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            science_data.join("mcp/local-mcp.json"),
            br#"{"servers":[]}"#,
        )
        .unwrap();
        fs::set_permissions(
            science_data.join("mcp/local-mcp.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            science_data.join(".csswitch-route-state.json"),
            br#"{"prior":"route-authority"}"#,
        )
        .unwrap();
        fs::set_permissions(
            science_data.join(".csswitch-route-state.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let installer_key = config_dir.join("runtime/skill-install-bridge.key");
        let installer_key_canary = format!("prior-installer-authority-{}", config::new_id());
        fs::create_dir_all(installer_key.parent().unwrap()).unwrap();
        fs::write(&installer_key, format!("{installer_key_canary}\n")).unwrap();
        fs::set_permissions(&installer_key, fs::Permissions::from_mode(0o600)).unwrap();
        let prior_runtime =
            science::select_science_runtime_cached(None, &science::ScienceVersionCache::default())
                .unwrap();
        let foreign_stub = sandbox_home.join(".ssh/config");
        let inplace_authority = science_data.join("orgs/csswitch-test/prior-inplace.db");
        fs::create_dir_all(inplace_authority.parent().unwrap()).unwrap();
        let failure_marker = tmp.join("serve-mutation-reached");
        let failure_control = science_data.join("fake-science/fail-after-inplace-mutation");
        let unbound_candidate_pid = tmp.join("unbound-second-candidate.pid");
        if failure_edge == "foreign-stub" {
            env_guard.set("CSSWITCH_TEST_SSH_LATE_FOREIGN_STUB", &foreign_stub);
        } else if failure_edge == "host-proof-drift" {
            env_guard.set("CSSWITCH_TEST_SSH_HOSTS_AFTER_CAPTURE", "drifted-test-host");
        } else if failure_edge == "db-health-skipped" {
            env_guard.set("CSSWITCH_FAKE_SCIENCE_DB_HEALTH", "skipped");
        } else if failure_edge == "db-health-recovery" {
            env_guard.set("CSSWITCH_FAKE_SCIENCE_DB_HEALTH", "stateful");
            fs::create_dir_all(&science_data).unwrap();
            fs::write(science_data.join("fake-db-damage-verdict"), b"flagged\n").unwrap();
        } else if failure_edge == "db-health-never-clears" {
            env_guard.set("CSSWITCH_FAKE_SCIENCE_DB_HEALTH", "damage-reverify");
            env_guard.set("CSSWITCH_TEST_DB_REVERIFY_BUDGET_MS", "250");
        } else if failure_edge == "db-health-stalled" {
            env_guard.set("CSSWITCH_FAKE_SCIENCE_DB_HEALTH", "stalled");
            env_guard.set("CSSWITCH_TEST_DB_REVERIFY_BUDGET_MS", "250");
        } else if failure_edge == "db-health-io-errors" {
            env_guard.set("CSSWITCH_FAKE_SCIENCE_DB_HEALTH", "io-errors");
        } else if failure_edge == "db-health-missing-kind" {
            env_guard.set("CSSWITCH_FAKE_SCIENCE_DB_HEALTH", "missing-kind");
        } else if matches!(
            failure_edge.as_str(),
            "db-restart-no-listener" | "db-restart-launch-blocks"
        ) {
            env_guard.set("CSSWITCH_FAKE_SCIENCE_DB_HEALTH", "stateful");
            if failure_edge == "db-restart-no-listener" {
                env_guard.set("CSSWITCH_FAKE_SCIENCE_SECOND_BOOT_NO_LISTENER", "1");
            } else {
                env_guard.set("CSSWITCH_FAKE_SCIENCE_SECOND_BOOT_BLOCKS", "1");
            }
            env_guard.set("CSSWITCH_FAKE_SCIENCE_UNBOUND_PID", &unbound_candidate_pid);
            env_guard.set("CSSWITCH_FAKE_SCIENCE_UNBOUND_MUTATION", &inplace_authority);
            env_guard.set("CSSWITCH_TEST_DB_RECOVERY_RESTART_BUDGET_MS", "250");
            fs::create_dir_all(&science_data).unwrap();
            fs::write(science_data.join("fake-db-damage-verdict"), b"flagged\n").unwrap();
            fs::write(&inplace_authority, b"prior-inplace-authority\n").unwrap();
        } else if failure_edge == "serve-mutates-then-exits" {
            fs::write(&inplace_authority, b"prior-inplace-authority\n").unwrap();
            fs::set_permissions(&inplace_authority, fs::Permissions::from_mode(0o600)).unwrap();
            fs::create_dir_all(failure_control.parent().unwrap()).unwrap();
            fs::write(
                &failure_control,
                format!(
                    "{}\n{}\n",
                    inplace_authority.display(),
                    failure_marker.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&failure_control, fs::Permissions::from_mode(0o600)).unwrap();
        } else if failure_edge == "post-status-receipt" {
            env_guard.set("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE", "1");
        }
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .invoke_handler(tauri::generate_handler![
                super::start_proxy,
                super::one_click_login,
                super::status,
                super::boot_error,
                super::boot_attention
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .unwrap();
        let event_sinks = Arc::new(Mutex::new(Vec::<String>::new()));
        for event_name in ["boot://failed", "boot://attention"] {
            let observed = event_sinks.clone();
            handle.listen_any(event_name, move |event| {
                observed
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(event.payload().to_string());
            });
        }
        let mut prior_gateway_health = None;
        let mut prior_gateway_pid = None;
        if owned_gateway_oracle {
            let prior_profile = before.active_profile().unwrap().clone();
            let (_, _, action) = proxy_lifecycle::start_proxy_for(
                &handle,
                &state,
                lifecycle.as_ref(),
                &prior_profile,
                None,
                None,
            )
            .unwrap();
            assert!(matches!(
                action,
                crate::runtime::proxy::ProxyAction::Restarted
            ));
            let mut authority = lock(&state);
            assert!(authority.proxy.is_some());
            prior_gateway_pid = authority.proxy.as_ref().map(std::process::Child::id);
            prior_gateway_health = crate::proc::http_gateway_health(
                authority.proxy_port,
                Some(&authority.secret),
                crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS,
            );
            assert!(prior_gateway_health.is_some());
            authority.sandbox_port = 43211;
            authority.sandbox_url = Some("http://127.0.0.1:43211/prior".into());
            authority.science_confirmed_stopped = Some(prior_runtime.clone());
            drop(authority);
        } else {
            let mut authority = lock(&state);
            authority.proxy_port = 43210;
            authority.secret = "prior-memory-secret".into();
            authority.provider = "prior-provider".into();
            authority.gateway_kind = "prior-gateway".into();
            authority.shim_mode = "prior-shim".into();
            authority.launch_id = "prior-launch-id".into();
            authority.key_fp = 4242;
            authority.sandbox_port = 43211;
            authority.sandbox_url = Some("http://127.0.0.1:43211/prior".into());
            authority.science_confirmed_stopped = Some(prior_runtime.clone());
        }
        let config_before = config::load_from(&config_dir).unwrap();
        let app_authority_before = app_authority_projection(&state);
        let system_ssh_before = authority_tree(&home.join(".ssh"));
        let science_authority_before = science_authority_projection(&science_data);
        let private_state_before = authority_tree(&sandbox_home.parent().unwrap().join("state"));
        let installer_key_before = authority_tree(&config_dir.join("runtime"));
        let managed_receipt = config_dir.join("science-managed-launch.v1.json");
        let managed_receipt_before = authority_tree(&managed_receipt);
        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );
        let _db_catalog_bypass = matches!(
            failure_edge.as_str(),
            "db-health-skipped"
                | "db-health-recovery"
                | "db-health-never-clears"
                | "db-health-stalled"
                | "db-health-io-errors"
                | "db-health-missing-kind"
                | "db-restart-no-listener"
                | "db-restart-launch-blocks"
        )
        .then(|| sandbox_session::test_arm_gateway_catalog_bypass(proxy_port));

        if failure_edge == "spawn-error" {
            env::set_var("PATH", bin_dir.as_os_str());
        }
        let operation_started = Instant::now();
        let failed = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let failure_surface = failed
            .as_ref()
            .err()
            .map(String::as_str)
            .unwrap_or_default();
        if failure_edge != "db-health-recovery" {
            let environment_was_exposed = !matches!(
                failure_edge.as_str(),
                "foreign-stub" | "spawn-error" | "host-proof-drift"
            );
            assert_eq!(
                failure_surface.contains("environment_uncertain"),
                environment_was_exposed,
                "the failure surface must distinguish pre-spawn rollback from a launch whose Science-owned environment may have changed: edge={failure_edge}, failure={failure_surface}"
            );
        }
        if failure_edge == "serve-mutates-then-exits" {
            assert!(
                failure_surface.contains("recovery_status=cleanup_required")
                    && failure_surface.contains("compensation_restore_blocked_science_candidate"),
                "a failed Science invocation without an exact managed identity must preserve the recovery snapshot and block protected-state restore: {failed:?}"
            );
            assert!(
                failure_marker.is_file()
                    && fs::read_to_string(&inplace_authority)
                        .is_ok_and(|bytes| bytes == "mutated-by-failing-science\n"),
                "the oracle must prove Science changed a protected org authority before failing"
            );
            assert_ne!(
                science_authority_projection(&science_data),
                science_authority_before,
                "protected authority must not be restored underneath an unproven candidate"
            );
            assert!(
                failure_surface.contains(".one-click-rollback-"),
                "manual recovery must retain a credential-free snapshot locator"
            );
            fs::remove_file(&failure_control).unwrap();
            cleanup.finish().expect("unproven candidate oracle cleanup");
            return;
        }
        if failure_edge == "db-health-recovery" {
            assert!(
                failed
                    .as_ref()
                    .is_ok_and(|value| value["action"] == "started"),
                "stateful 0.1.25 oracle must close in one operation: {failed:?}"
            );
            assert_eq!(
                fs::read_to_string(science_data.join("fake-science/serve-count")).unwrap(),
                "2",
                "recovery must use the initial boot plus exactly one managed restart"
            );
            assert!(
                !science_data.join("fake-db-damage-verdict").exists(),
                "the Science-owned cleared verdict must survive the managed restart"
            );
            env::remove_var("CSSWITCH_FAKE_SCIENCE_DB_HEALTH");
            cleanup.finish().expect("DB recovery oracle cleanup");
            return;
        }
        if failure_edge == "db-health-skipped" {
            assert!(
                failed
                    .as_ref()
                    .is_err_and(|error| { error.contains("第二次启动未达到 clear/clear") }),
                "a second boot that still reports migrations_skipped must fail closed: {failed:?}"
            );
            assert_eq!(
                fs::read_to_string(&science_call_log)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| *line == "serve")
                    .count(),
                2,
                "second-boot failure must consume the sole managed restart and never launch a third candidate"
            );
            assert_eq!(
                science_authority_projection(&science_data),
                science_authority_before,
                "second-boot failure must restore the complete pre-operation ScienceData tree, including OAuth, route/config, and the persisted verdict"
            );
            assert!(TcpStream::connect(("127.0.0.1", sandbox_port)).is_err());
            assert!(!config_dir.join("science-managed-launch.v1.json").exists());
            env::remove_var("CSSWITCH_FAKE_SCIENCE_DB_HEALTH");
            cleanup.finish().expect("DB second-boot failure cleanup");
            return;
        }
        if failure_edge == "db-health-never-clears" {
            assert!(
                failed
                    .as_ref()
                    .is_err_and(|error| error.contains("science_db_reverify_timeout")),
                "a verdict that never clears must stop at the bounded reverify deadline: {failed:?}"
            );
            assert_eq!(
                fs::read_to_string(&science_call_log)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| *line == "serve")
                    .count(),
                1,
                "reverify timeout must not consume the managed restart"
            );
            assert_eq!(
                science_authority_projection(&science_data),
                science_authority_before
            );
            assert!(TcpStream::connect(("127.0.0.1", sandbox_port)).is_err());
            assert!(!config_dir.join("science-managed-launch.v1.json").exists());
            env::remove_var("CSSWITCH_FAKE_SCIENCE_DB_HEALTH");
            env::remove_var("CSSWITCH_TEST_DB_REVERIFY_BUDGET_MS");
            cleanup.finish().expect("DB reverify-timeout cleanup");
            return;
        }
        if failure_edge == "db-health-stalled" {
            assert!(
                failed
                    .as_ref()
                    .is_err_and(|error| error.contains("science_db_reverify_timeout")),
                "a stalled authenticated health response must stop at the absolute reverify deadline: {failed:?}"
            );
            assert!(
                operation_started.elapsed() < Duration::from_millis(3_500),
                "the 250ms reverify budget must cap a stalled 2s health response in addition to the fixed launch/rollback work"
            );
            assert_eq!(
                fs::read_to_string(&science_call_log)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| *line == "serve")
                    .count(),
                1,
                "stalled health must not consume the managed restart"
            );
            assert_eq!(
                science_authority_projection(&science_data),
                science_authority_before
            );
            assert!(TcpStream::connect(("127.0.0.1", sandbox_port)).is_err());
            assert!(!config_dir.join("science-managed-launch.v1.json").exists());
            env::remove_var("CSSWITCH_FAKE_SCIENCE_DB_HEALTH");
            env::remove_var("CSSWITCH_TEST_DB_REVERIFY_BUDGET_MS");
            cleanup.finish().expect("DB stalled-health cleanup");
            return;
        }
        if failure_edge == "db-health-io-errors" {
            assert!(
                failed.as_ref().is_err_and(|error| {
                    error.contains("第二次启动未达到 clear/clear")
                }),
                "0.1.25 io_errors is a THIS-run wedge and must consume the sole restart immediately: {failed:?}"
            );
            assert_eq!(
                fs::read_to_string(&science_call_log)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| *line == "serve")
                    .count(),
                2,
                "io_errors must not enter the 305s damage reverify lane"
            );
            assert_eq!(
                science_authority_projection(&science_data),
                science_authority_before
            );
            assert!(TcpStream::connect(("127.0.0.1", sandbox_port)).is_err());
            assert!(!config_dir.join("science-managed-launch.v1.json").exists());
            env::remove_var("CSSWITCH_FAKE_SCIENCE_DB_HEALTH");
            cleanup.finish().expect("DB io_errors cleanup");
            return;
        }
        if failure_edge == "db-health-missing-kind" {
            assert!(
                failed.as_ref().is_err_and(
                    |error| error.contains("science_api_health_missing_db_corruption_kind")
                ),
                "flagged health without the 0.1.25 kind discriminant must fail closed: {failed:?}"
            );
            assert_eq!(
                fs::read_to_string(&science_call_log)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| *line == "serve")
                    .count(),
                1,
                "malformed health must not guess a recovery lane or consume the restart"
            );
            assert_eq!(
                science_authority_projection(&science_data),
                science_authority_before
            );
            assert!(TcpStream::connect(("127.0.0.1", sandbox_port)).is_err());
            assert!(!config_dir.join("science-managed-launch.v1.json").exists());
            env::remove_var("CSSWITCH_FAKE_SCIENCE_DB_HEALTH");
            cleanup.finish().expect("DB missing-kind cleanup");
            return;
        }
        if matches!(
            failure_edge.as_str(),
            "db-restart-no-listener" | "db-restart-launch-blocks"
        ) {
            assert!(
                failed.as_ref().is_err_and(|error| {
                    error.contains("code=science_candidate_stop_unproven")
                        && error.contains("compensation_restore_blocked_science_candidate")
                        && error.contains("recovery_status=cleanup_required")
                }),
                "a detached post-spawn/pre-receipt candidate must block authority restore with typed recovery: {failed:?}"
            );
            assert_eq!(
                fs::read_to_string(&science_call_log)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| *line == "serve")
                    .count(),
                2,
                "the unbound candidate must be the sole recovery restart"
            );
            if failure_edge == "db-restart-launch-blocks" {
                assert!(
                    operation_started.elapsed() < std::time::Duration::from_secs(5),
                    "the recovery deadline must include the launch script, not begin after blocking status"
                );
            }
            let unbound_pid = fs::read_to_string(&unbound_candidate_pid)
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap();
            assert!(unbound_pid > 1);
            assert!(
                process_start_identity_if_alive(unbound_pid).is_some(),
                "old-product red requires the unbound second candidate to remain alive"
            );
            let expected_mutation = if failure_edge == "db-restart-launch-blocks" {
                "mutated-by-blocked-second-candidate\n"
            } else {
                "mutated-by-unbound-second-candidate\n"
            };
            assert_eq!(
                fs::read_to_string(&inplace_authority).unwrap(),
                expected_mutation,
                "authority must not be restored underneath an unproven live candidate"
            );
            assert_ne!(
                science_authority_projection(&science_data),
                science_authority_before,
                "blocked restore must preserve the current authority plus the recovery snapshot"
            );
            assert!(TcpStream::connect(("127.0.0.1", sandbox_port)).is_err());
            assert!(!config_dir.join("science-managed-launch.v1.json").exists());
            unsafe {
                libc::kill(unbound_pid as i32, libc::SIGTERM);
            }
            for _ in 0..50 {
                if process_start_identity_if_alive(unbound_pid).is_none() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if process_start_identity_if_alive(unbound_pid).is_some() {
                unsafe {
                    libc::kill(unbound_pid as i32, libc::SIGKILL);
                }
            }
            assert!(
                process_start_identity_if_alive(unbound_pid).is_none(),
                "test must clean the intentionally unowned candidate"
            );
            env::remove_var("CSSWITCH_FAKE_SCIENCE_DB_HEALTH");
            env::remove_var("CSSWITCH_FAKE_SCIENCE_SECOND_BOOT_NO_LISTENER");
            env::remove_var("CSSWITCH_FAKE_SCIENCE_SECOND_BOOT_BLOCKS");
            env::remove_var("CSSWITCH_FAKE_SCIENCE_UNBOUND_PID");
            env::remove_var("CSSWITCH_FAKE_SCIENCE_UNBOUND_MUTATION");
            env::remove_var("CSSWITCH_TEST_DB_RECOVERY_RESTART_BUDGET_MS");
            cleanup.finish().expect("DB unbound-candidate cleanup");
            return;
        }
        let config_after_failure = config::load_from(&config_dir).unwrap();
        let app_authority_after_failure = app_authority_projection(&state);
        let (tracked_gateway_pid_after_failure, tracked_gateway_running_after_failure) = {
            let mut authority = lock(&state);
            match authority.proxy.as_mut() {
                Some(child) => (Some(child.id()), child.try_wait().unwrap().is_none()),
                None => (None, false),
            }
        };
        let gateway_health_after_failure = crate::proc::http_gateway_health(
            app_authority_after_failure.proxy_port,
            Some(&app_authority_after_failure.secret),
            crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS,
        );
        let gateway_publish_raw = fs::read_to_string(&gateway_publish_log).unwrap_or_default();
        let gateway_publishes = gateway_publish_raw
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_ascii_whitespace();
                Some((
                    fields.next()?.parse::<u32>().ok()?,
                    fields.next()?.to_string(),
                    fields.next()?.parse::<u64>().ok()?,
                    fields.next()?.parse::<u16>().ok()?,
                ))
            })
            .collect::<Vec<_>>();
        let gateway_publish_adapters = gateway_publish_raw
            .lines()
            .filter_map(|line| line.split_ascii_whitespace().nth(4).map(str::to_string))
            .collect::<Vec<_>>();
        let system_ssh_after_failure = authority_tree(&home.join(".ssh"));
        let science_authority_after_failure = science_authority_projection(&science_data);
        let private_state_after_failure =
            authority_tree(&sandbox_home.parent().unwrap().join("state"));
        let installer_key_after_failure = authority_tree(&config_dir.join("runtime"));
        let managed_receipt_after_failure = authority_tree(&managed_receipt);
        let science_calls_after_failure =
            fs::read_to_string(&science_call_log).unwrap_or_else(|_| "<missing>".into());
        let failure_marker_reached = failure_marker.is_file();
        let oauth_restored = science_authority_after_failure == science_authority_before
            && private_state_after_failure == private_state_before;
        let profile_restored = config_after_failure == config_before;
        let journal_restored =
            config_after_failure.runtime_transaction == config_before.runtime_transaction;
        let stable_app_authority_restored = app_authority_after_failure.proxy_port
            == app_authority_before.proxy_port
            && app_authority_after_failure.secret == app_authority_before.secret
            && app_authority_after_failure.provider == app_authority_before.provider
            && app_authority_after_failure.gateway_kind == app_authority_before.gateway_kind
            && app_authority_after_failure.shim_mode == app_authority_before.shim_mode
            && app_authority_after_failure.key_fp == app_authority_before.key_fp
            && app_authority_after_failure.sandbox_present == app_authority_before.sandbox_present
            && app_authority_after_failure.sandbox_port == app_authority_before.sandbox_port
            && app_authority_after_failure.sandbox_url == app_authority_before.sandbox_url
            && app_authority_after_failure.science_runtime == app_authority_before.science_runtime
            && app_authority_after_failure.science_confirmed_stopped
                == app_authority_before.science_confirmed_stopped
            && app_authority_after_failure.history_recovery_present
                == app_authority_before.history_recovery_present;
        let gateway_restored = if owned_gateway_oracle {
            let prior_health = prior_gateway_health.as_ref();
            let restored_health = gateway_health_after_failure.as_ref();
            let prior_publish = gateway_publishes.first();
            let candidate = gateway_publishes.get(1);
            let restored_publish = gateway_publishes.get(2);
            let expected_installer_token = proxy_lifecycle::test_skill_install_bridge_token(
                &app_authority_after_failure.secret,
                &app_authority_after_failure.launch_id,
            )
            .ok()
            .map(|token| format!("{token}\n").into_bytes());
            stable_app_authority_restored
                && app_authority_after_failure.proxy_present
                && !app_authority_after_failure.launch_id.is_empty()
                && tracked_gateway_running_after_failure
                && tracked_gateway_pid_after_failure == restored_publish.map(|publish| publish.0)
                && listener_pid_if_unique(proxy_port) == tracked_gateway_pid_after_failure
                && gateway_publishes.len() == 3
                && prior_publish.is_some_and(|prior| {
                    Some(prior.0) == prior_gateway_pid
                        && prior_health.is_some_and(|health| health.launch_id == prior.1)
                        && prior.3 == proxy_port
                })
                && candidate.is_some_and(|candidate| {
                    Some(candidate.0) != tracked_gateway_pid_after_failure
                        && Some(candidate.0) != prior_gateway_pid
                        && candidate.1 != app_authority_after_failure.launch_id
                        && candidate.3 == proxy_port
                        && process_start_identity_if_alive(candidate.0).is_none()
                })
                && restored_publish.is_some_and(|restored| {
                    Some(restored.0) != prior_gateway_pid
                        && restored.1 == app_authority_after_failure.launch_id
                        && restored.2 == app_authority_after_failure.key_fp
                        && restored.3 == app_authority_after_failure.proxy_port
                })
                && prior_gateway_pid.is_some()
                && prior_health
                    .zip(restored_health)
                    .is_some_and(|(prior, restored)| {
                        restored.gateway == prior.gateway
                            && restored.provider == prior.provider
                            && restored.shim == prior.shim
                            && restored.provider_contract_id == prior.provider_contract_id
                            && restored.provider_contract_digest == prior.provider_contract_digest
                            && restored.catalog_fp == prior.catalog_fp
                            && restored.intent == prior.intent
                            && restored.launch_id == app_authority_after_failure.launch_id
                    })
                && installer_key_after_failure
                    .get(&PathBuf::from("skill-install-bridge.key"))
                    .is_some_and(|entry| {
                        entry.kind == "file"
                            && entry.mode == 0o600
                            && Some(&entry.bytes) == expected_installer_token.as_ref()
                    })
        } else {
            app_authority_after_failure == app_authority_before
                && TcpStream::connect(("127.0.0.1", proxy_port)).is_err()
                && installer_key_after_failure == installer_key_before
        };
        let science_restored = stable_app_authority_restored
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err()
            && managed_receipt_after_failure == managed_receipt_before;
        let bridge_restored = science_authority_after_failure == science_authority_before;
        let foreign_stub_authority = fs::symlink_metadata(&foreign_stub)
            .ok()
            .filter(|metadata| metadata.file_type().is_file())
            .map(|metadata| {
                (
                    metadata.permissions().mode() & 0o777,
                    fs::read(&foreign_stub).unwrap(),
                )
            });
        let sandbox_ssh_after_failure = authority_tree(&sandbox_home.join(".ssh"));
        let expected_sandbox_ssh = BTreeMap::from([
            (
                PathBuf::new(),
                AuthorityTreeEntry {
                    kind: "dir",
                    mode: 0o700,
                    bytes: Vec::new(),
                },
            ),
            (
                PathBuf::from("config"),
                AuthorityTreeEntry {
                    kind: "file",
                    mode: 0o600,
                    bytes: b"foreign-test-stub-must-survive\n".to_vec(),
                },
            ),
        ]);

        if failure_edge == "foreign-stub" {
            env::remove_var("CSSWITCH_TEST_SSH_LATE_FOREIGN_STUB");
            fs::remove_file(&foreign_stub).unwrap();
        } else if failure_edge == "host-proof-drift" {
            env::remove_var("CSSWITCH_TEST_SSH_HOSTS_AFTER_CAPTURE");
        } else if failure_edge == "db-health-skipped" {
            env::remove_var("CSSWITCH_FAKE_SCIENCE_DB_HEALTH");
        } else if failure_edge == "spawn-error" {
            env::set_var(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                    bin_dir.to_string_lossy()
                ),
            );
        } else if failure_edge == "serve-mutates-then-exits" {
            fs::remove_file(&failure_control).unwrap();
        } else {
            env::remove_var("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE");
        }
        let retry =
            sandbox_session::one_click_login(handle, state.clone(), lifecycle.as_ref(), None, None);
        let retry_started_once = retry
            .as_ref()
            .is_ok_and(|value| value["action"] == "started")
            && fs::read_to_string(sandbox_home.join(".claude-science/fake-science/serve-count"))
                .ok()
                .as_deref()
                == Some(if failure_edge == "post-status-receipt" {
                    "2"
                } else {
                    "1"
                });
        let science_calls_after_retry =
            fs::read_to_string(&science_call_log).unwrap_or_else(|_| "<missing>".into());
        let serve_calls_after_failure = science_calls_after_failure
            .lines()
            .filter(|line| *line == "serve")
            .count();
        let serve_calls_after_retry = science_calls_after_retry
            .lines()
            .filter(|line| *line == "serve")
            .count();
        cleanup
            .finish()
            .expect("late-failure and retry fixtures must leave no process residue");

        if failure_edge == "foreign-stub" {
            assert!(
                failed.as_ref().is_err_and(|error| {
                    error.contains("起沙箱脚本失败")
                        && error.contains("隔离 SSH config 不是 CSSwitch 管理的安全入口")
                }),
                "late injection must reach the exact SSH launch-script foreign-stub refusal"
            );
            assert_eq!(
                foreign_stub_authority,
                Some((0o600, b"foreign-test-stub-must-survive\n".to_vec())),
                "late-failure compensation must preserve foreign SSH file kind, private mode, and exact bytes"
            );
            assert_eq!(
                sandbox_ssh_after_failure, expected_sandbox_ssh,
                "late-failure compensation must leave no extra file, symlink, or directory in the sandbox SSH authority"
            );
        } else if failure_edge == "host-proof-drift" {
            assert!(
                failed.as_ref().is_err_and(|error| {
                    error.contains("code=ssh_authority_changed_retry")
                        && !error.contains("起沙箱脚本失败")
                }),
                "host proof drift must fail before packaged zsh with a typed retry"
            );
            assert!(
                sandbox_ssh_after_failure.is_empty(),
                "host proof drift must not create or rewrite the sandbox SSH stub"
            );
            assert_eq!(
                serve_calls_after_failure, 0,
                "host proof drift must fail before fake Science serve"
            );
        } else if failure_edge == "db-health-skipped" {
            assert!(
                failed.as_ref().is_err_and(|error| {
                    error.contains("science_db_migrations_skipped_restart_required")
                }),
                "semantic DB health must reject a coarse /health 200"
            );
            assert_eq!(
                serve_calls_after_failure, 1,
                "fake Science must start before semantic DB health rejects readiness"
            );
            assert!(
                sandbox_ssh_after_failure.is_empty(),
                "DB readiness compensation must remove the managed sandbox SSH stub"
            );
        } else if failure_edge == "spawn-error" {
            let spawn_error_reached = failure_surface.contains("起沙箱失败");
            assert!(
                spawn_error_reached,
                "spawn-error fixture must reach the post-authority zsh spawn edge: spawn_error_reached={spawn_error_reached}"
            );
            assert!(
                sandbox_ssh_after_failure.is_empty(),
                "a shell spawn error must leave no sandbox SSH authority"
            );
        } else if failure_edge == "serve-mutates-then-exits" {
            let serve_failure_reached = failure_surface.contains("起沙箱脚本失败");
            assert!(
                serve_failure_reached,
                "failing Science must propagate the launch-script failure: serve_failure_reached={serve_failure_reached}"
            );
            assert!(
                failure_marker_reached,
                "fake Science must prove it mutated live authority before exiting: failure_marker_reached={failure_marker_reached}, science_serve_observed={}",
                science_calls_after_failure.lines().any(|line| line == "serve")
            );
            assert!(
                sandbox_ssh_after_failure.is_empty(),
                "failed Science cleanup must remove only the managed sandbox SSH stub"
            );
        } else {
            let post_status_failure_reached = failure_surface.contains("受管启动身份无法安全提交")
                && failure_surface.contains("test-only managed launch commit failure");
            assert!(
                post_status_failure_reached,
                "post-status fixture must fail only after healthy listener identity and before receipt commit: post_status_failure_reached={post_status_failure_reached}"
            );
            assert!(
                sandbox_ssh_after_failure.is_empty(),
                "post-status compensation must remove the managed sandbox SSH stub"
            );
        }
        if failure_edge == "host-proof-drift" {
            assert_ne!(
                system_ssh_after_failure, system_ssh_before,
                "the external test authority drift must remain external to CSSwitch rollback"
            );
            assert_eq!(
                system_ssh_after_failure
                    .get(&PathBuf::from("config"))
                    .map(|entry| entry.bytes.as_slice()),
                Some(b"Host drifted-test-host\n".as_slice())
            );
        } else {
            assert_eq!(
                system_ssh_after_failure, system_ssh_before,
                "late-failure compensation must not change the authorized system SSH source tree"
            );
        }
        if oracle_first == "gateway" {
            assert!(
                gateway_restored,
                "late SSH failure must restore Gateway authority"
            );
        } else if oracle_first == "journal" {
            assert!(
                journal_restored,
                "late SSH failure must restore the exact prior transaction journal"
            );
        } else if oracle_first == "bridge" {
            assert!(
                bridge_restored,
                "late SSH failure must restore managed bridge state and Science config"
            );
        } else {
            assert!(
                oauth_restored,
                "late SSH failure must restore the exact prior virtual OAuth authority"
            );
        }
        assert!(
            profile_restored,
            "late SSH failure must preserve the active profile"
        );
        if owned_gateway_oracle {
            let ownership_error_absent =
                !failure_surface.contains("无法恢复先前 Gateway child 所有权");
            assert!(
                ownership_error_absent,
                "rollback must restore a real prior Gateway instead of reporting lost child ownership: ownership_error_absent={ownership_error_absent}"
            );
        }
        assert!(
            gateway_restored,
            "late SSH failure must restore Gateway authority"
        );
        assert!(
            science_restored,
            "late SSH failure must restore Science authority"
        );
        assert!(
            bridge_restored,
            "late SSH failure must restore managed bridge state and Science config"
        );
        assert!(
            journal_restored,
            "late SSH failure must restore the exact prior transaction journal"
        );
        assert!(
            retry_started_once,
            "retry after exact compensation must be idempotent and start one Science"
        );
        assert_eq!(
            serve_calls_after_failure,
            usize::from(matches!(
                failure_edge.as_str(),
                "serve-mutates-then-exits" | "db-health-skipped" | "post-status-receipt"
            )),
            "authority-external call log must identify whether the failed attempt reached Science serve"
        );
        assert_eq!(
            serve_calls_after_retry,
            if matches!(
                failure_edge.as_str(),
                "serve-mutates-then-exits" | "db-health-skipped" | "post-status-receipt"
            ) {
                2
            } else {
                1
            },
            "authority-external call log must count the failed attempt and one clean retry"
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary prior Science rollback; temp HOME, managed fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_late_failure_restarts_prior_managed_science_with_fresh_receipt() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("prior-science-rollback");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let candidate_pid_log = tmp.join("candidate-science.pid");
        let snapshot_observation = tmp.join("snapshot-observation.log");

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        cfg.runtime_binding = None;
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let science_data = sandbox_home.join(".claude-science");
        fs::create_dir_all(&science_data).unwrap();
        crate::oauth_forge::ensure_virtual_login(
            &science_data,
            "virtual@localhost.invalid",
            &sandbox_home,
        )
        .unwrap();
        let prior_runtime =
            science::select_science_runtime_cached(None, &science::ScienceVersionCache::default())
                .unwrap();
        let prior_pid = start_managed_fake_science(
            &fake_science,
            &sandbox_home,
            &science_data,
            sandbox_port,
            &prior_runtime,
        );
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        {
            let mut authority = lock(&state);
            authority.sandbox_port = sandbox_port;
            authority.sandbox_url = Some(format!("http://127.0.0.1:{sandbox_port}/prior"));
            authority.science_runtime = Some(prior_runtime.clone());
            authority.science_confirmed_stopped = None;
        }
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();

        science::test_reset_managed_launch_commit_failure_once();
        env_guard.set("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE_ONCE", "1");
        env_guard.set(
            "CSSWITCH_TEST_MANAGED_LAUNCH_FAILURE_PID_LOG",
            &candidate_pid_log,
        );
        let receipt_path = config_dir.join("science-managed-launch.v1.json");
        let _snapshot_seam = sandbox_session::test_arm_one_click_snapshot_capture(
            config_dir.clone(),
            snapshot_observation.clone(),
            false,
            prior_pid,
            receipt_path.clone(),
        );
        let failed = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let candidate_pid = fs::read_to_string(&candidate_pid_log)
            .ok()
            .and_then(|pid| pid.trim().parse::<u32>().ok());
        let capture_observation = fs::read_to_string(&snapshot_observation).unwrap_or_default();
        let expected_capture_observation = format!(
            "expected_prior_pid={prior_pid}\nexpected_receipt={}\nlistener=stopped\nprior_process=absent\nprior_receipt=absent\n",
            receipt_path.display()
        );
        let restored_pid = listener_pid_if_unique(sandbox_port);
        let receipt = fs::read(&receipt_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        let receipt_pid = receipt
            .as_ref()
            .and_then(|value| value["listener_pid"].as_u64())
            .map(|pid| pid as u32);
        let receipt_port = receipt
            .as_ref()
            .and_then(|value| value["port"].as_u64())
            .map(|port| port as u16);
        let app_after = app_authority_projection(&state);
        let candidate_gone =
            candidate_pid.is_some_and(|pid| process_start_identity_if_alive(pid).is_none());
        let prior_pid_gone = process_start_identity_if_alive(prior_pid).is_none();
        let restored_healthy = restored_pid.is_some()
            && restored_pid != Some(prior_pid)
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_ok();
        let fresh_receipt = receipt_pid == restored_pid
            && receipt_port == Some(sandbox_port)
            && receipt_pid != Some(prior_pid);
        let app_consistent = app_after.science_runtime == Some(prior_runtime.clone())
            && app_after.science_confirmed_stopped.is_none()
            && app_after.sandbox_port == sandbox_port
            && app_after.sandbox_url.is_some();

        let safe_stop = {
            let mut authority = lock(&state);
            let runtime = authority.science_runtime.clone();
            let AppState {
                sandbox,
                sandbox_url,
                ..
            } = &mut *authority;
            science::stop_sandbox(&handle, sandbox, sandbox_url, runtime.as_ref())
        };
        let stopped_cleanly = safe_stop.is_ok()
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err()
            && !receipt_path.exists();
        force_cleanup_isolated_fixture(&state, &tmp, sandbox_port, proxy_port);

        assert!(
            failed
                .as_ref()
                .is_err_and(|error| { error.contains("test-only managed launch commit failure") }),
            "fixture must reach the post-status managed-receipt failure: {failed:?}"
        );
        assert!(
            restored_healthy
                && fresh_receipt
                && app_consistent
                && candidate_gone
                && prior_pid_gone
                && capture_observation == expected_capture_observation
                && stopped_cleanly,
            "late failure after stop-old must quiesce the exact prior process before capture, restart prior Science with a fresh receipt and exact ownership, and leave no orphan daemon: capture={capture_observation:?}, prior_pid={prior_pid}, candidate_pid={candidate_pid:?}, restored_pid={restored_pid:?}, receipt_pid={receipt_pid:?}, prior_gone={prior_pid_gone}, app={app_after:?}, safe_stop={safe_stop:?}"
        );
    }

    #[cfg(unix)]
    fn run_prior_restart_failure_oracle(oracle: &str) {
        assert!(
            matches!(oracle, "cleanup-degraded" | "post-spawn-failure"),
            "unknown prior restart failure oracle: {oracle}"
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir(&format!("prior-restart-{oracle}"));
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let candidate_pid_log = tmp.join("candidate-science.pid");
        let snapshot_observation = tmp.join("snapshot-observation.log");
        let cleanup_log = tmp.join("snapshot-cleanup.log");

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        cfg.runtime_binding = None;
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let science_data = sandbox_home.join(".claude-science");
        fs::create_dir_all(&science_data).unwrap();
        crate::oauth_forge::ensure_virtual_login(
            &science_data,
            "virtual@localhost.invalid",
            &sandbox_home,
        )
        .unwrap();
        let stable_authority = science_data.join("orgs/csswitch-test/stable-authority.db");
        fs::create_dir_all(stable_authority.parent().unwrap()).unwrap();
        fs::write(&stable_authority, b"stable-private-authority\n").unwrap();
        fs::set_permissions(&stable_authority, fs::Permissions::from_mode(0o600)).unwrap();
        let stable_before = fs::read(&stable_authority).unwrap();
        let prior_runtime =
            science::select_science_runtime_cached(None, &science::ScienceVersionCache::default())
                .unwrap();
        let prior_pid = start_managed_fake_science(
            &fake_science,
            &sandbox_home,
            &science_data,
            sandbox_port,
            &prior_runtime,
        );
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        {
            let mut authority = lock(&state);
            authority.sandbox_port = sandbox_port;
            authority.sandbox_url = Some(format!("http://127.0.0.1:{sandbox_port}/prior"));
            authority.science_runtime = Some(prior_runtime.clone());
            authority.science_confirmed_stopped = None;
        }
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let prior_profile = cfg.active_profile().unwrap().clone();
        let (_, _, prior_gateway_action) = proxy_lifecycle::start_proxy_for(
            &handle,
            &state,
            lifecycle.as_ref(),
            &prior_profile,
            Some(&prior_runtime),
            None,
        )
        .unwrap();
        assert!(matches!(
            prior_gateway_action,
            crate::runtime::proxy::ProxyAction::Restarted
        ));
        let prior_gateway_pid = lock(&state).proxy.as_ref().map(std::process::Child::id);
        let prior_gateway_health = crate::proc::http_gateway_health(
            proxy_port,
            Some(&lock(&state).secret),
            crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS,
        )
        .expect("prior Gateway must be healthy before the late failure");
        let config_before = config::load_from(&config_dir).unwrap();

        science::test_reset_managed_launch_commit_failure_once();
        env_guard.set("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE_ONCE", "1");
        env_guard.set(
            "CSSWITCH_TEST_MANAGED_LAUNCH_FAILURE_PID_LOG",
            &candidate_pid_log,
        );
        let receipt_path = config_dir.join("science-managed-launch.v1.json");
        let _snapshot_seam = sandbox_session::test_arm_one_click_snapshot_capture(
            config_dir.clone(),
            snapshot_observation.clone(),
            false,
            prior_pid,
            receipt_path.clone(),
        );
        let _cleanup_seam = (oracle == "cleanup-degraded").then(|| {
            sandbox_session::test_arm_authority_snapshot_cleanup_fault(
                tmp.clone(),
                "persistent",
                cleanup_log.clone(),
            )
        });
        let _restart_seam = (oracle == "post-spawn-failure")
            .then(|| sandbox_session::test_arm_prior_restart_post_spawn_failure(sandbox_port));

        let failed = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let candidate_pid = fs::read_to_string(&candidate_pid_log)
            .ok()
            .and_then(|pid| pid.trim().parse::<u32>().ok());
        let capture_observation = fs::read_to_string(&snapshot_observation).unwrap_or_default();
        let expected_capture_observation = format!(
            "expected_prior_pid={prior_pid}\nexpected_receipt={}\nlistener=stopped\nprior_process=absent\nprior_receipt=absent\n",
            receipt_path.display()
        );
        let listener_after_failure = listener_pid_if_unique(sandbox_port);
        let verified_restart_identity = sandbox_session::test_prior_restart_post_spawn_identity();
        let verified_restart_identity_absent =
            verified_restart_identity
                .as_ref()
                .is_some_and(|(pid, process_start)| {
                    listener_after_failure != Some(*pid)
                        && science::test_process_start_identity_for_pid(*pid).as_ref()
                            != Some(process_start)
                });
        let receipt = fs::read(&receipt_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        let receipt_pid = receipt
            .as_ref()
            .and_then(|value| value["listener_pid"].as_u64())
            .map(|pid| pid as u32);
        let app_after = app_authority_projection(&state);
        let candidate_gone =
            candidate_pid.is_some_and(|pid| process_start_identity_if_alive(pid).is_none());
        let prior_gone = process_start_identity_if_alive(prior_pid).is_none();
        let stable_file_restored = fs::read(&stable_authority)
            .is_ok_and(|bytes| bytes == stable_before)
            && fs::metadata(&stable_authority)
                .is_ok_and(|metadata| metadata.permissions().mode() & 0o777 == 0o600);
        let config_after = config::load_from(&config_dir).ok();
        let stable_authority_restored =
            stable_file_restored && config_after.as_ref() == Some(&config_before);
        let gateway_after = {
            let authority = lock(&state);
            crate::proc::http_gateway_health(
                authority.proxy_port,
                Some(&authority.secret),
                crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS,
            )
        };
        let gateway_restored = lock(&state).proxy.as_ref().map(std::process::Child::id)
            == prior_gateway_pid
            && gateway_after.as_ref().is_some_and(|health| {
                health.gateway == prior_gateway_health.gateway
                    && health.provider == prior_gateway_health.provider
                    && health.launch_id == prior_gateway_health.launch_id
            });
        let cleanup_line = fs::read_to_string(&cleanup_log)
            .unwrap_or_default()
            .lines()
            .last()
            .unwrap_or_default()
            .to_string();
        let cleanup_residual = cleanup_line
            .split('\t')
            .nth(2)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let cleanup_residual_private = cleanup_residual.as_ref().is_some_and(|path| {
            fs::symlink_metadata(path).is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.permissions().mode() & 0o777 == 0o700
            })
        });
        let cleanup_tracked = cleanup_residual.as_ref().is_some_and(|path| {
            lock(&state)
                .pending_authority_cleanup
                .iter()
                .any(|pending| pending == path)
        });
        let result_surface = match &failed {
            Ok(value) => value.to_string(),
            Err(error) => error.clone(),
        };

        let safe_stop = {
            let mut authority = lock(&state);
            let runtime = authority.science_runtime.clone();
            let AppState {
                sandbox,
                sandbox_url,
                ..
            } = &mut *authority;
            science::stop_sandbox(&handle, sandbox, sandbox_url, runtime.as_ref())
        };
        let listener_closed_after_safe_stop =
            TcpStream::connect(("127.0.0.1", sandbox_port)).is_err();
        force_cleanup_isolated_fixture(&state, &tmp, sandbox_port, proxy_port);

        assert!(
            failed
                .as_ref()
                .is_err_and(|error| { error.contains("test-only managed launch commit failure") }),
            "fixture must reach the post-status managed-receipt failure: {failed:?}"
        );
        assert_eq!(
            capture_observation, expected_capture_observation,
            "prior Science must be exactly quiesced before the authority snapshot"
        );
        assert!(
            stable_authority_restored && gateway_restored && candidate_gone && prior_gone,
            "authority and prior Gateway must restore before the prior Science recovery decision: stable={stable_authority_restored}, stable_file={stable_file_restored}, config_equal={}, gateway={gateway_restored}, candidate_gone={candidate_gone}, prior_gone={prior_gone}, gateway_health_present={}",
            config_after.as_ref() == Some(&config_before),
            gateway_after.is_some()
        );
        if oracle == "cleanup-degraded" {
            let prior_restarted = listener_after_failure.is_some()
                && listener_after_failure != Some(prior_pid)
                && receipt_pid == listener_after_failure
                && app_after.science_runtime.as_ref() == Some(&prior_runtime)
                && app_after.science_confirmed_stopped.is_none()
                && safe_stop.is_ok()
                && listener_closed_after_safe_stop;
            let degraded_surface =
                result_surface.contains("degraded") && result_surface.contains("cleanup_required");
            let cleanup_path_reported = cleanup_residual
                .as_ref()
                .is_some_and(|path| result_surface.contains(&path.to_string_lossy().to_string()));
            assert!(
                prior_restarted
                    && cleanup_residual_private
                    && cleanup_tracked
                    && degraded_surface
                    && cleanup_path_reported,
                "persistent snapshot cleanup failure after successful authority/Gateway restore must still restart prior Science with a fresh receipt and exact AppState, while returning explicit degraded/cleanup_required with one tracked private residual: listener_present={}, receipt_matches_listener={}, app_runtime_restored={}, app_confirmed_stopped={}, degraded_surface={degraded_surface}, cleanup_path_reported={cleanup_path_reported}, private={cleanup_residual_private}, tracked={cleanup_tracked}, safe_stop={safe_stop:?}",
                listener_after_failure.is_some(),
                receipt_pid == listener_after_failure,
                app_after.science_runtime.as_ref() == Some(&prior_runtime),
                app_after.science_confirmed_stopped.is_some()
            );
        } else {
            let honest_stopped = listener_after_failure.is_none()
                && !receipt_path.exists()
                && app_after.science_runtime.is_none()
                && app_after.science_confirmed_stopped.as_ref() == Some(&prior_runtime);
            assert!(
                failed.as_ref().is_err_and(|error| {
                    error.contains("test-only prior Science post-spawn validation failure")
                }) && verified_restart_identity_absent
                    && honest_stopped,
                "a post-spawn prior restart validation failure must clean the exact verified candidate PID/process-start identity and port, leave no receipt, and keep AppState honestly stopped: result={failed:?}, verified_identity_recorded={}, verified_identity_absent={verified_restart_identity_absent}, listener_present={}, receipt_present={}, app_runtime_present={}, app_confirmed_stopped={}",
                verified_restart_identity.is_some(),
                listener_after_failure.is_some(),
                receipt.is_some(),
                app_after.science_runtime.is_some(),
                app_after.science_confirmed_stopped.is_some()
            );
        }
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary prior Science cleanup degradation; temp HOME, managed fake Science, real local Gateway, and loopback only"]
    #[cfg(unix)]
    fn isolated_prior_science_restart_survives_snapshot_cleanup_degradation() {
        run_prior_restart_failure_oracle("cleanup-degraded");
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary prior Science restart cleanup; temp HOME, managed fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_prior_science_post_spawn_failure_cleans_candidate() {
        run_prior_restart_failure_oracle("post-spawn-failure");
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary snapshot quiesce rollback; temp HOME, managed fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_snapshot_failure_occurs_after_verified_stop_and_restarts_prior_science() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("snapshot-quiesce-rollback");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let snapshot_observation = tmp.join("snapshot-observation.log");

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        cfg.runtime_binding = None;
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let science_data = sandbox_home.join(".claude-science");
        fs::create_dir_all(&science_data).unwrap();
        crate::oauth_forge::ensure_virtual_login(
            &science_data,
            "virtual@localhost.invalid",
            &sandbox_home,
        )
        .unwrap();
        let stable_authority = science_data.join("orgs/csswitch-test/prior-authority.db");
        fs::create_dir_all(stable_authority.parent().unwrap()).unwrap();
        fs::write(&stable_authority, b"prior-authority-bytes\n").unwrap();
        fs::set_permissions(&stable_authority, fs::Permissions::from_mode(0o600)).unwrap();
        let stable_bytes_before = fs::read(&stable_authority).unwrap();
        let stable_mode_before = fs::metadata(&stable_authority)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let config_before = config::load_from(&config_dir).unwrap();
        let prior_runtime =
            science::select_science_runtime_cached(None, &science::ScienceVersionCache::default())
                .unwrap();
        let prior_pid = start_managed_fake_science(
            &fake_science,
            &sandbox_home,
            &science_data,
            sandbox_port,
            &prior_runtime,
        );
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        {
            let mut authority = lock(&state);
            authority.sandbox_port = sandbox_port;
            authority.sandbox_url = Some(format!("http://127.0.0.1:{sandbox_port}/prior"));
            authority.science_runtime = Some(prior_runtime.clone());
            authority.science_confirmed_stopped = None;
        }
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let receipt_path = config_dir.join("science-managed-launch.v1.json");
        let _snapshot_seam = sandbox_session::test_arm_one_click_snapshot_capture(
            config_dir.clone(),
            snapshot_observation.clone(),
            true,
            prior_pid,
            receipt_path.clone(),
        );

        let failed = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let observation = fs::read_to_string(&snapshot_observation).unwrap_or_default();
        let expected_observation = format!(
            "expected_prior_pid={prior_pid}\nexpected_receipt={}\nlistener=stopped\nprior_process=absent\nprior_receipt=absent\n",
            receipt_path.display()
        );
        let restored_pid = listener_pid_if_unique(sandbox_port);
        let receipt_pid = fs::read(&receipt_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value["listener_pid"].as_u64())
            .map(|pid| pid as u32);
        let app_after = app_authority_projection(&state);
        let stable_authority_unchanged = fs::read(&stable_authority).unwrap()
            == stable_bytes_before
            && fs::metadata(&stable_authority)
                .unwrap()
                .permissions()
                .mode()
                & 0o777
                == stable_mode_before
            && config::load_from(&config_dir).unwrap() == config_before;
        let restarted_after_quiesce = observation == expected_observation
            && restored_pid.is_some()
            && restored_pid != Some(prior_pid)
            && process_start_identity_if_alive(prior_pid).is_none()
            && receipt_pid == restored_pid
            && app_after.science_runtime == Some(prior_runtime.clone())
            && app_after.science_confirmed_stopped.is_none()
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_ok();
        let safe_stop = {
            let mut authority = lock(&state);
            let runtime = authority.science_runtime.clone();
            let AppState {
                sandbox,
                sandbox_url,
                ..
            } = &mut *authority;
            science::stop_sandbox(&handle, sandbox, sandbox_url, runtime.as_ref())
        };
        let stopped_cleanly = safe_stop.is_ok()
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err()
            && !receipt_path.exists();
        force_cleanup_isolated_fixture(&state, &tmp, sandbox_port, proxy_port);

        assert!(
            failed
                .as_ref()
                .is_err_and(|error| error
                    .contains("test-only one-click authority snapshot capture failure")),
            "fixture must reach the injected snapshot capture failure: {failed:?}"
        );
        assert!(
            restarted_after_quiesce && stable_authority_unchanged && stopped_cleanly,
            "snapshot failure must be observed only after verified stop with prior process and receipt absent, preserve stable authority, restart prior Science with fresh ownership, leave no orphan prior PID, and remain safely stoppable: observation={observation:?}, prior_pid={prior_pid}, restored_pid={restored_pid:?}, receipt_pid={receipt_pid:?}, app={app_after:?}, safe_stop={safe_stop:?}"
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary profile-switch snapshot rollback; temp HOME, managed fake Science, real local Gateway, and loopback only"]
    #[cfg(unix)]
    fn isolated_profile_switch_snapshot_failure_reuses_restored_prior_science() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("profile-switch-snapshot-rollback");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let snapshot_observation = tmp.join("snapshot-observation.log");

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        cfg.runtime_binding = None;
        let mut candidate = cfg.profiles[0].clone();
        candidate.id = "snapshot-failure-candidate".into();
        candidate.name = "Snapshot failure candidate".into();
        cfg.profiles.push(candidate.clone());
        config::save_to(&config_dir, &cfg).unwrap();
        let config_before = config::load_from(&config_dir).unwrap();

        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let science_data = sandbox_home.join(".claude-science");
        fs::create_dir_all(&science_data).unwrap();
        crate::oauth_forge::ensure_virtual_login(
            &science_data,
            "virtual@localhost.invalid",
            &sandbox_home,
        )
        .unwrap();
        let prior_runtime =
            science::select_science_runtime_cached(None, &science::ScienceVersionCache::default())
                .unwrap();
        let prior_pid = start_managed_fake_science(
            &fake_science,
            &sandbox_home,
            &science_data,
            sandbox_port,
            &prior_runtime,
        );
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        {
            let mut authority = lock(&state);
            authority.sandbox_port = sandbox_port;
            authority.sandbox_url = Some(format!("http://127.0.0.1:{sandbox_port}/prior"));
            authority.science_runtime = Some(prior_runtime.clone());
            authority.science_confirmed_stopped = None;
        }
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let receipt_path = config_dir.join("science-managed-launch.v1.json");
        let _snapshot_seam = sandbox_session::test_arm_one_click_snapshot_capture(
            config_dir.clone(),
            snapshot_observation,
            true,
            prior_pid,
            receipt_path.clone(),
        );

        let result = crate::runtime::profile_switch::set_active_profile_txn(
            &handle,
            &state,
            lifecycle.as_ref(),
            &candidate.id,
            false,
            None,
            None,
        )
        .expect("profile switch snapshot failure must return structured recovery evidence");
        let restored_pid = listener_pid_if_unique(sandbox_port);
        let receipt_pid = fs::read(&receipt_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value["listener_pid"].as_u64())
            .map(|pid| pid as u32);
        let app_after = app_authority_projection(&state);
        let config_after = config::load_from(&config_dir).unwrap();
        let mut normalized_config_before = config_before.clone();
        let mut normalized_config_after = config_after.clone();
        normalized_config_before.secret.clear();
        normalized_config_after.secret.clear();
        let restored_prior_healthy = restored_pid.is_some()
            && restored_pid != Some(prior_pid)
            && process_start_identity_if_alive(prior_pid).is_none()
            && receipt_pid == restored_pid
            && app_after.science_runtime == Some(prior_runtime.clone())
            && app_after.science_confirmed_stopped.is_none()
            && science::probe_known_runtime(sandbox_port, &prior_runtime)
                == science::SandboxScienceState::RunningHealthy;
        let safe_stop = {
            let mut authority = lock(&state);
            let runtime = authority.science_runtime.clone();
            let AppState {
                sandbox,
                sandbox_url,
                ..
            } = &mut *authority;
            science::stop_sandbox(&handle, sandbox, sandbox_url, runtime.as_ref())
        };
        let stopped_cleanly = safe_stop.is_ok()
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err()
            && !receipt_path.exists();
        force_cleanup_isolated_fixture(&state, &tmp, sandbox_port, proxy_port);

        assert_eq!(result["committed"], false);
        assert_eq!(result["stage"], "science_start");
        assert_eq!(result["status"], "error");
        assert_eq!(result["recovery_status"], "restored");
        assert!(
            result["message"].as_str().is_some_and(|message| message
                .contains("test-only one-click authority snapshot capture failure")),
            "structured result must retain the original capture cause: {result}"
        );
        assert_eq!(
            normalized_config_after, normalized_config_before,
            "failed profile switch must restore the prior profiles, active id, binding, and journal; the recovered proxy may rotate its local path secret"
        );
        assert!(
            restored_prior_healthy && stopped_cleanly,
            "profile-switch recovery must keep the already-restored prior Science instead of re-entering snapshot capture: prior_pid={prior_pid}, restored_pid={restored_pid:?}, receipt_pid={receipt_pid:?}, app={app_after:?}, safe_stop={safe_stop:?}, result={result}"
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary healthy reopen Gateway rollback; temp HOME, managed fake Science, real local Gateway, and loopback only"]
    #[cfg(unix)]
    fn isolated_healthy_reopen_catalog_failure_restores_prior_owned_gateway() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("healthy-reopen-gateway-rollback");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let gateway_publish_log = tmp.join("gateway-publish.log");
        fs::write(&gateway_publish_log, b"").unwrap();
        fs::set_permissions(&gateway_publish_log, fs::Permissions::from_mode(0o600)).unwrap();

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set("CSSWITCH_TEST_GATEWAY_PUBLISH_LOG", &gateway_publish_log);
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        cfg.secret = "22".repeat(32);
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let science_data = sandbox_home.join(".claude-science");
        fs::create_dir_all(&science_data).unwrap();
        crate::oauth_forge::ensure_virtual_login(
            &science_data,
            "virtual@localhost.invalid",
            &sandbox_home,
        )
        .unwrap();
        let prior_runtime =
            science::select_science_runtime_cached(None, &science::ScienceVersionCache::default())
                .unwrap();
        let committed_binding = crate::runtime::provider::desired_runtime_binding(
            &cfg,
            cfg.active_profile().unwrap(),
            &prior_runtime,
        )
        .unwrap();
        cfg.runtime_binding = Some(committed_binding);
        config::save_to(&config_dir, &cfg).unwrap();
        let prior_science_pid = start_managed_fake_science(
            &fake_science,
            &sandbox_home,
            &science_data,
            sandbox_port,
            &prior_runtime,
        );

        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        {
            let mut authority = lock(&state);
            authority.sandbox_port = sandbox_port;
            authority.sandbox_url = Some(format!("http://127.0.0.1:{sandbox_port}/prior"));
            authority.science_runtime = Some(prior_runtime.clone());
            authority.science_confirmed_stopped = None;
        }
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let mut prior_profile = cfg.active_profile().unwrap().clone();
        prior_profile.api_key = "prior-gateway-different-fake-key".into();
        let (_, _, prior_action) = proxy_lifecycle::start_proxy_for(
            &handle,
            &state,
            lifecycle.as_ref(),
            &prior_profile,
            Some(&prior_runtime),
            None,
        )
        .unwrap();
        assert!(matches!(
            prior_action,
            crate::runtime::proxy::ProxyAction::Restarted
        ));
        let prior_gateway_pid = lock(&state).proxy.as_ref().map(std::process::Child::id);
        let prior_gateway_health = crate::proc::http_gateway_health(
            proxy_port,
            Some(&lock(&state).secret),
            crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS,
        )
        .expect("prior Gateway must be healthy");
        let _catalog_seam = sandbox_session::test_arm_healthy_reopen_catalog_failure(proxy_port);

        let failed = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let publishes = fs::read_to_string(&gateway_publish_log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_ascii_whitespace();
                Some((
                    fields.next()?.parse::<u32>().ok()?,
                    fields.next()?.to_string(),
                    fields.next()?.parse::<u64>().ok()?,
                    fields.next()?.parse::<u16>().ok()?,
                ))
            })
            .collect::<Vec<_>>();
        let (
            tracked_gateway_pid,
            tracked_gateway_running,
            secret,
            launch_id,
            key_fp,
            launch_context_matches_prior,
        ) = {
            let mut authority = lock(&state);
            let running = authority
                .proxy
                .as_mut()
                .is_some_and(|child| child.try_wait().unwrap().is_none());
            let context_matches =
                authority
                    .gateway_launch_context
                    .as_ref()
                    .is_some_and(|context| {
                        context.profile == prior_profile
                            && context.science_runtime.as_ref() == Some(&prior_runtime)
                    });
            (
                authority.proxy.as_ref().map(std::process::Child::id),
                running,
                authority.secret.clone(),
                authority.launch_id.clone(),
                authority.key_fp,
                context_matches,
            )
        };
        let restored_gateway_health = crate::proc::http_gateway_health(
            proxy_port,
            Some(&secret),
            crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS,
        );
        let candidate_pid = publishes.get(1).map(|publish| publish.0);
        let restored_publish = publishes.get(2);
        let gateway_restored = publishes.len() == 3
            && prior_gateway_pid == publishes.first().map(|publish| publish.0)
            && candidate_pid.is_some_and(|pid| process_start_identity_if_alive(pid).is_none())
            && tracked_gateway_running
            && tracked_gateway_pid == restored_publish.map(|publish| publish.0)
            && restored_publish.is_some_and(|publish| {
                publish.1 == launch_id
                    && publish.2 == key_fp
                    && publish.3 == proxy_port
                    && publishes.first().is_some_and(|prior| publish.2 == prior.2)
                    && publishes
                        .get(1)
                        .is_some_and(|candidate| publish.2 != candidate.2)
            })
            && launch_context_matches_prior
            && restored_gateway_health.as_ref().is_some_and(|restored| {
                restored.gateway == prior_gateway_health.gateway
                    && restored.provider == prior_gateway_health.provider
                    && restored.shim == prior_gateway_health.shim
                    && restored.provider_contract_id == prior_gateway_health.provider_contract_id
                    && restored.provider_contract_digest
                        == prior_gateway_health.provider_contract_digest
                    && restored.catalog_fp == prior_gateway_health.catalog_fp
                    && restored.intent == prior_gateway_health.intent
                    && restored.launch_id == launch_id
            });
        let science_untouched = listener_pid_if_unique(sandbox_port) == Some(prior_science_pid)
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_ok();
        let safe_science_stop = {
            let mut authority = lock(&state);
            let runtime = authority.science_runtime.clone();
            let AppState {
                sandbox,
                sandbox_url,
                ..
            } = &mut *authority;
            science::stop_sandbox(&handle, sandbox, sandbox_url, runtime.as_ref())
        };
        force_cleanup_isolated_fixture(&state, &tmp, sandbox_port, proxy_port);

        assert!(
            failed
                .as_ref()
                .is_err_and(|error| { error.contains("test-only healthy reopen catalog failure") }),
            "fixture must fail only after the active Gateway restart: {failed:?}"
        );
        assert!(
            gateway_restored && science_untouched && safe_science_stop.is_ok(),
            "healthy reopen catalog failure must stop candidate and restart the exact prior owned Gateway, including prior key fingerprint and in-memory launch context, without snapshotting or restarting healthy Science: publishes={publishes:?}, prior_gateway_pid={prior_gateway_pid:?}, tracked={tracked_gateway_pid:?}, candidate={candidate_pid:?}, context_restored={launch_context_matches_prior}, health={restored_gateway_health:?}, science_pid={prior_science_pid}, safe_science_stop={safe_science_stop:?}"
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary optional SSH feature-off smoke; temp HOME, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_ssh_feature_off_ignores_missing_optional_wrapper_and_system_config() {
        let cleanup_oracle = env::var("CSSWITCH_TEST_COMMIT_CLEANUP_ORACLE").unwrap_or_default();
        assert!(
            matches!(cleanup_oracle.as_str(), "" | "once" | "persistent"),
            "unknown commit cleanup oracle: {cleanup_oracle}"
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("ssh-feature-off");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();

        let mut env_guard = EnvGuard::new();
        let cleanup_log = tmp.join("snapshot-cleanup.log");
        let _cleanup_seam = (!cleanup_oracle.is_empty()).then(|| {
            sandbox_session::test_arm_authority_snapshot_cleanup_fault(
                tmp.clone(),
                &cleanup_oracle,
                cleanup_log.clone(),
            )
        });
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE",
            tmp.join("missing-optional-wrapper"),
        );
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let sandbox_ssh = sandbox_home.join(".ssh");
        fs::create_dir_all(&sandbox_ssh).unwrap();
        fs::set_permissions(&sandbox_ssh, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            sandbox_ssh.join("known_hosts"),
            b"foreign-known-host-authority\n",
        )
        .unwrap();
        fs::set_permissions(
            sandbox_ssh.join("known_hosts"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let sandbox_ssh_before = authority_tree(&sandbox_ssh);
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );

        let started =
            sandbox_session::one_click_login(handle, state.clone(), lifecycle.as_ref(), None, None);
        let serve_count =
            fs::read_to_string(sandbox_home.join(".claude-science/fake-science/serve-count"));
        let committed = config::load_from(&config_dir).unwrap();
        let sandbox_ssh_after = authority_tree(&sandbox_ssh);
        let system_ssh_after = authority_tree(&home.join(".ssh"));
        let rollback_residue = fs::read_dir(sandbox_home.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".one-click-rollback-"))
            .collect::<Vec<_>>();
        let cleanup_observation = fs::read_to_string(&cleanup_log).unwrap_or_default();
        let tracked_residual = cleanup_observation
            .lines()
            .last()
            .and_then(|line| line.split('\t').nth(2))
            .unwrap_or_default()
            .to_string();
        cleanup
            .finish()
            .expect("feature-off fixture must leave no process residue");

        if cleanup_oracle == "persistent" {
            assert!(
                started.as_ref().is_ok_and(|value| {
                    value["status"] == "degraded"
                        && value["recovery_status"] == "cleanup_required"
                        && !tracked_residual.is_empty()
                        && value.to_string().contains(&tracked_residual)
                }) && rollback_residue.len() == 1,
                "persistent commit cleanup failure must return explicit degraded/cleanup_required status and track the exact residual: result={started:?}, residual={tracked_residual:?}, entries={rollback_residue:?}"
            );
            return;
        }
        assert!(
            started
                .as_ref()
                .is_ok_and(|value| value["action"] == "started"),
            "disabled optional SSH must not require HOME/.ssh/config or a packaged wrapper: {started:?}"
        );
        assert!(
            system_ssh_after.is_empty(),
            "feature-off flow must not create a system SSH authority"
        );
        assert_eq!(
            sandbox_ssh_after, sandbox_ssh_before,
            "feature-off flow must preserve foreign sandbox SSH files exactly"
        );
        assert_eq!(serve_count.unwrap(), "1");
        assert!(!committed.reuse_system_ssh);
        assert!(
            committed.runtime_transaction.is_none(),
            "successful feature-off start must commit and clear the journal"
        );
        assert!(
            rollback_residue.is_empty(),
            "successful feature-off start must not retain rollback residue"
        );
        if cleanup_oracle == "once" {
            assert!(
                cleanup_observation.lines().count() >= 2,
                "one-shot commit cleanup fault must be retried before ordinary success: {cleanup_observation:?}"
            );
        }
    }

    #[cfg(unix)]
    fn run_cleanup_recovery_oracle(oracle: &str) {
        assert!(
            matches!(
                oracle,
                "pending-notfound" | "durable-present" | "durable-missing"
            ),
            "unknown cleanup recovery oracle: {oracle}"
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir(&format!("cleanup-recovery-{oracle}"));
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let cleanup_log = tmp.join("snapshot-cleanup.log");

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE",
            tmp.join("missing-optional-wrapper"),
        );
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let mut cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );
        let cleanup_seam = sandbox_session::test_arm_authority_snapshot_cleanup_fault(
            tmp.clone(),
            "persistent",
            cleanup_log.clone(),
        );
        let first = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let cleanup_line = fs::read_to_string(&cleanup_log)
            .unwrap_or_default()
            .lines()
            .last()
            .unwrap_or_default()
            .to_string();
        let residual = PathBuf::from(
            cleanup_line
                .split('\t')
                .nth(2)
                .expect("persistent cleanup observation must expose the exact residual"),
        );
        assert!(
            first.as_ref().is_ok_and(|value| {
                value["status"] == "degraded"
                    && value["recovery_status"] == "cleanup_required"
                    && value.to_string().contains(&residual.to_string_lossy().to_string())
            }) && residual.is_dir()
                && lock(&state)
                    .pending_authority_cleanup
                    .iter()
                    .any(|pending| pending == &residual),
            "fixture must establish one explicit tracked persistent cleanup residual: first={first:?}, residual={}",
            residual.display()
        );

        let sandbox_parent = sandbox_home.parent().unwrap();
        let neighbor = sandbox_parent.join(".one-click-rollback-neighbor-must-survive");
        fs::create_dir(&neighbor).unwrap();
        fs::set_permissions(&neighbor, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(neighbor.join("sentinel"), b"unrelated-neighbor\n").unwrap();
        fs::set_permissions(neighbor.join("sentinel"), fs::Permissions::from_mode(0o600)).unwrap();
        let neighbor_before = authority_tree(&neighbor);

        let manifest_path = config_dir.join(config::PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE);
        let residual_metadata = fs::symlink_metadata(&residual).unwrap();
        let managed_id = residual
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let managed_suffix = managed_id
            .strip_prefix(".one-click-rollback-")
            .unwrap_or_default();
        let managed_id_valid = managed_suffix.len() == 32
            && managed_suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
        let manifest_raw = fs::read(&manifest_path).ok();
        let manifest_private_exact = manifest_raw.as_ref().is_some_and(|bytes| {
            let metadata = fs::symlink_metadata(&manifest_path).ok();
            let parent_metadata = manifest_path
                .parent()
                .and_then(|parent| fs::symlink_metadata(parent).ok());
            let parsed = serde_json::from_slice::<serde_json::Value>(bytes).ok();
            metadata.is_some_and(|metadata| {
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.permissions().mode() & 0o777 == 0o600
            }) && parent_metadata.is_some_and(|metadata| {
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.permissions().mode() & 0o777 == 0o700
            }) && parsed.is_some_and(|value| {
                value.as_object().is_some_and(|object| object.len() == 3)
                    && value["schema_version"] == 2
                    && value["disposition"] == "cleanup_only"
                    && value["entries"]
                        == serde_json::json!([{
                            "managed_id": managed_id,
                            "path": residual.to_string_lossy().to_string(),
                            "device": residual_metadata.dev(),
                            "inode": residual_metadata.ino(),
                            "marker": managed_id
                        }])
            }) && fs::read(residual.join(".csswitch-one-click-rollback.marker"))
                .is_ok_and(|bytes| bytes == format!("{managed_id}\n").as_bytes())
                && {
                    let raw = String::from_utf8_lossy(bytes);
                    raw.contains(&residual.to_string_lossy().to_string())
                        && !raw.contains("foreign-known-host-authority")
                        && !raw.contains("ssh-transaction-fake-key-never-log")
                        && (cfg.secret.is_empty() || !raw.contains(&cfg.secret))
                }
        });
        let lifecycle_identity = config::PendingCleanupIdentity {
            managed_id: managed_id.clone(),
            path: residual.clone(),
            device: residual_metadata.dev(),
            inode: residual_metadata.ino(),
            marker: managed_id.clone(),
        };
        if matches!(oracle, "pending-notfound" | "durable-missing") {
            fs::remove_dir_all(&residual).unwrap();
        }
        drop(cleanup_seam);
        let _lifecycle_observation = oracle
            .starts_with("durable-")
            .then(|| config::test_arm_pending_cleanup_lifecycle(None));

        let second_state = if oracle.starts_with("durable-") {
            let stop_result = {
                let mut authority = lock(&state);
                let runtime = authority.science_runtime.clone();
                let AppState {
                    sandbox,
                    sandbox_url,
                    ..
                } = &mut *authority;
                let result = science::stop_sandbox(&handle, sandbox, sandbox_url, runtime.as_ref());
                authority.stop_proxy();
                result
            };
            assert!(
                stop_result.is_ok()
                    && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err()
                    && TcpStream::connect(("127.0.0.1", proxy_port)).is_err(),
                "fixture must quiesce old AppState-owned processes before simulating restart: {stop_result:?}"
            );
            let restarted: SharedAppState = Arc::new(Mutex::new(AppState::default()));
            cleanup.state = restarted.clone();
            restarted
        } else {
            state.clone()
        };

        let second = sandbox_session::one_click_login(
            handle,
            second_state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let pending_cleared = lock(&second_state).pending_authority_cleanup.is_empty();
        let residual_removed = !residual.exists();
        let neighbor_untouched = authority_tree(&neighbor) == neighbor_before;
        let manifest_cleared = match fs::read(&manifest_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| value["entries"].as_array().cloned())
                .is_some_and(|entries| entries.is_empty()),
            _ => false,
        };
        let lifecycle_observation = config::test_pending_cleanup_lifecycle_observation();
        let lifecycle_order_exact = !oracle.starts_with("durable-")
            || lifecycle_observation.events
                == vec![
                    config::PendingCleanupLifecycleEvent::Register(lifecycle_identity.clone()),
                    config::PendingCleanupLifecycleEvent::Remove {
                        identity: lifecycle_identity,
                        not_found: oracle == "durable-missing",
                    },
                    config::PendingCleanupLifecycleEvent::Clear,
                ];
        let durable_boundaries_exact = !oracle.starts_with("durable-")
            || (lifecycle_observation.validated_loader_count == 1
                && lifecycle_observation.initial_ticket_count == 1
                && lifecycle_observation.race_hook_count == 1
                && lifecycle_observation.completion_count == 1
                && lifecycle_observation.causal_mismatch_count == 0
                && lifecycle_observation.delete_attempt_count
                    == usize::from(oracle == "durable-present"));
        cleanup
            .finish()
            .expect("cleanup recovery fixture must leave no process or temp residue");

        if oracle == "pending-notfound" {
            assert!(
                second.as_ref().is_ok()
                    && pending_cleared
                    && residual_removed
                    && neighbor_untouched,
                "an exact tracked cleanup root that is already NotFound must be removed from pending and one-click must continue without deleting a similarly named neighbor: second_ok={}, pending_cleared={pending_cleared}, residual_removed={residual_removed}, neighbor_untouched={neighbor_untouched}",
                second.is_ok()
            );
        } else {
            assert!(
                manifest_private_exact
                    && managed_id_valid
                    && second.as_ref().is_ok()
                    && pending_cleared
                    && residual_removed
                    && neighbor_untouched
                    && manifest_cleared
                    && lifecycle_order_exact
                    && durable_boundaries_exact,
                "durable cleanup manifest must be strictly validated by the fresh AppState loader, publish an explicit Present/Removed or Missing/AlreadyAbsent completion with final NotFound, preserve marker-bearing identity, and clear only after the passive lifecycle boundaries are reached: oracle={oracle}, managed_id_valid={managed_id_valid}, manifest_private_exact={manifest_private_exact}, second_ok={}, pending_cleared={pending_cleared}, residual_removed={residual_removed}, neighbor_untouched={neighbor_untouched}, manifest_cleared={manifest_cleared}, lifecycle_order_exact={lifecycle_order_exact}, durable_boundaries_exact={durable_boundaries_exact}, validated_loader_count={}, initial_ticket_count={}, race_hook_count={}, delete_attempt_count={}, completion_count={}, causal_mismatch_count={}",
                second.is_ok(),
                lifecycle_observation.validated_loader_count,
                lifecycle_observation.initial_ticket_count,
                lifecycle_observation.race_hook_count,
                lifecycle_observation.delete_attempt_count,
                lifecycle_observation.completion_count,
                lifecycle_observation.causal_mismatch_count
            );
        }
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary pending cleanup idempotence; temp HOME, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_pending_cleanup_not_found_is_idempotent_and_neighbor_safe() {
        run_cleanup_recovery_oracle("pending-notfound");
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary durable cleanup manifest; temp HOME, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_cleanup_manifest_survives_app_state_restart() {
        let case =
            env::var("CSSWITCH_TEST_DURABLE_CLEANUP_CASE").unwrap_or_else(|_| "present".into());
        assert!(
            matches!(case.as_str(), "present" | "missing"),
            "unknown durable cleanup case: {case}"
        );
        run_cleanup_recovery_oracle(&format!("durable-{case}"));
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary cleanup manifest race revalidation; temp HOME, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_cleanup_manifest_race_revalidates_before_delete() {
        let case = env::var("CSSWITCH_TEST_DURABLE_RACE_CASE")
            .unwrap_or_else(|_| "missing-recreated".into());
        assert!(
            matches!(case.as_str(), "missing-recreated" | "present-deleted"),
            "unknown durable cleanup race case: {case}"
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir(&format!("cleanup-manifest-race-{case}"));
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_parent = home.join(config::CONFIG_DIR_NAME).join("sandbox");
        fs::create_dir_all(&sandbox_parent).unwrap();
        let managed_id = ".one-click-rollback-abcdefabcdefabcdefabcdefabcdefab";
        let replacement_marker = "race-replacement-object-must-survive";
        let managed = sandbox_parent.join(managed_id);
        fs::create_dir(&managed).unwrap();
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).unwrap();
        let marker_path = managed.join(".csswitch-one-click-rollback.marker");
        fs::write(&marker_path, format!("{managed_id}\n")).unwrap();
        fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::symlink_metadata(&managed).unwrap();
        let manifest_path = config_dir.join(config::PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE);
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "entries": [{
                "managed_id": managed_id,
                "path": managed.to_string_lossy().to_string(),
                "device": metadata.dev(),
                "inode": metadata.ino(),
                "marker": managed_id
            }]
        }))
        .unwrap();
        fs::write(&manifest_path, &manifest_bytes).unwrap();
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        if case == "missing-recreated" {
            fs::remove_file(&marker_path).unwrap();
            fs::remove_dir(&managed).unwrap();
        }
        let neighbor = sandbox_parent.join(".one-click-rollback-race-neighbor");
        fs::create_dir(&neighbor).unwrap();
        fs::write(neighbor.join("sentinel"), b"race-neighbor\n").unwrap();
        let neighbor_before = authority_tree(&neighbor);

        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );
        let _lifecycle_observation = config::test_arm_pending_cleanup_lifecycle(None);
        config::test_configure_pending_cleanup_race(if case == "missing-recreated" {
            config::PendingCleanupRaceAction::Recreate {
                path: managed.clone(),
                marker: replacement_marker.to_string(),
            }
        } else {
            config::PendingCleanupRaceAction::Delete {
                path: managed.clone(),
            }
        });

        let result =
            sandbox_session::one_click_login(handle, state.clone(), lifecycle.as_ref(), None, None);
        let observation = config::test_pending_cleanup_lifecycle_observation();
        let zero_remove = observation
            .events
            .iter()
            .all(|event| !matches!(event, config::PendingCleanupLifecycleEvent::Remove { .. }));
        let boundary_exact = observation.validated_loader_count == 1
            && observation.initial_ticket_count == 1
            && observation.race_hook_count == 1
            && observation.delete_attempt_count == 0
            && observation.completion_count == 1
            && observation.causal_mismatch_count == 1;
        let fail_closed_before_runtime = result.is_err()
            && lock(&state).proxy.is_none()
            && lock(&state).sandbox.is_none()
            && TcpStream::connect(("127.0.0.1", proxy_port)).is_err()
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err();
        let race_effect_preserved = if case == "missing-recreated" {
            observation
                .race_identity
                .as_ref()
                .is_some_and(|race_identity| {
                    race_identity.path == managed
                        && race_identity.marker == replacement_marker
                        && race_identity.device == metadata.dev()
                        && (race_identity.inode != metadata.ino()
                            || race_identity.marker != managed_id)
                        && fs::symlink_metadata(&managed).is_ok_and(|current| {
                            current.dev() == race_identity.device
                                && current.ino() == race_identity.inode
                        })
                        && fs::read(&marker_path).is_ok_and(|bytes| {
                            bytes == format!("{replacement_marker}\n").as_bytes()
                        })
                })
        } else {
            !managed.exists()
        };
        let manifest_untouched =
            fs::read(&manifest_path).is_ok_and(|bytes| bytes == manifest_bytes);
        let neighbor_untouched = authority_tree(&neighbor) == neighbor_before;
        cleanup
            .finish()
            .expect("durable cleanup race fixture must leave no process or temp residue");

        assert!(
            boundary_exact
                && zero_remove
                && fail_closed_before_runtime
                && race_effect_preserved
                && manifest_untouched
                && neighbor_untouched,
            "fresh-AppState durable cleanup must reach the validated-loader/ticket/race/completion boundaries, revalidate after the race, never call path delete for a causal mismatch, emit zero Remove, preserve the replacement or hook-deleted state, and fail closed: case={case}, result_failed={}, validated_loader_count={}, initial_ticket_count={}, race_hook_count={}, delete_attempt_count={}, completion_count={}, causal_mismatch_count={}, events={}, race_identity_present={}, race_effect_preserved={race_effect_preserved}, manifest_untouched={manifest_untouched}, neighbor_untouched={neighbor_untouched}",
            result.is_err(),
            observation.validated_loader_count,
            observation.initial_ticket_count,
            observation.race_hook_count,
            observation.delete_attempt_count,
            observation.completion_count,
            observation.causal_mismatch_count,
            observation.events.len(),
            observation.race_identity.is_some()
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary manifest pre-rename crash consistency; temp HOME, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_cleanup_manifest_pre_rename_fault_is_crash_consistent() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("cleanup-manifest-pre-rename");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_parent = home.join(config::CONFIG_DIR_NAME).join("sandbox");
        fs::create_dir_all(&sandbox_parent).unwrap();
        fs::set_permissions(&sandbox_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let managed_id = ".one-click-rollback-0123456789abcdef0123456789abcdef";
        let residual = sandbox_parent.join(managed_id);
        fs::create_dir(&residual).unwrap();
        fs::set_permissions(&residual, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            residual.join(".csswitch-one-click-rollback.marker"),
            format!("{managed_id}\n"),
        )
        .unwrap();
        fs::set_permissions(
            residual.join(".csswitch-one-click-rollback.marker"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let residual_metadata = fs::symlink_metadata(&residual).unwrap();
        let lifecycle_identity = config::PendingCleanupIdentity {
            managed_id: managed_id.to_string(),
            path: residual.clone(),
            device: residual_metadata.dev(),
            inode: residual_metadata.ino(),
            marker: managed_id.to_string(),
        };
        let manifest_path = config_dir.join(config::PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE);
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "entries": [{
                "managed_id": managed_id,
                "path": residual.to_string_lossy().to_string(),
                "device": residual_metadata.dev(),
                "inode": residual_metadata.ino(),
                "marker": managed_id
            }]
        }))
        .unwrap();
        fs::write(&manifest_path, &manifest_bytes).unwrap();
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        let manifest_before = fs::symlink_metadata(&manifest_path).unwrap();
        let lookalike_temp =
            config_dir.join(".pending-authority-cleanup.v1.json.tmp-lookalike-sentinel");
        let lookalike_temp_bytes = b"foreign-lookalike-temp-must-survive\n".to_vec();
        fs::write(&lookalike_temp, &lookalike_temp_bytes).unwrap();
        fs::set_permissions(&lookalike_temp, fs::Permissions::from_mode(0o600)).unwrap();
        let lookalike_temp_before = fs::symlink_metadata(&lookalike_temp).unwrap();
        fs::remove_file(residual.join(".csswitch-one-click-rollback.marker")).unwrap();
        fs::remove_dir(&residual).unwrap();

        let neighbor = sandbox_parent.join(".one-click-rollback-lookalike");
        fs::create_dir(&neighbor).unwrap();
        fs::write(neighbor.join("foreign-marker"), b"foreign-neighbor\n").unwrap();
        let neighbor_before = authority_tree(&neighbor);

        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let mut cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );
        let (failpoint, observation) =
            config::test_arm_pending_manifest_pre_rename_failure(&config_dir).unwrap();
        let _lifecycle_observation = config::test_arm_pending_cleanup_lifecycle(Some(
            config::PendingCleanupPublishFault::Clear,
        ));
        let first = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let observed = observation
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let manifest_after_fault = fs::read(&manifest_path).ok();
        let manifest_metadata_after_fault = fs::symlink_metadata(&manifest_path).ok();
        let old_manifest_exact = manifest_after_fault.as_deref() == Some(manifest_bytes.as_slice())
            && manifest_metadata_after_fault
                .as_ref()
                .is_some_and(|metadata| {
                    metadata.permissions().mode() & 0o777 == 0o600
                        && metadata.dev() == manifest_before.dev()
                        && metadata.ino() == manifest_before.ino()
                });
        let owned_temp_observed_and_cleaned = observed.as_ref().is_some_and(|observation| {
            observation.target_path == manifest_path
                && observation.config_access_held
                && observation.temp_path.parent() == Some(config_dir.as_path())
                && observation
                    .temp_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".pending-authority-cleanup.v1.json.tmp-"))
                && observation.temp_device == manifest_before.dev()
                && observation.temp_inode > 0
                && !observation.temp_path.exists()
        });
        let no_temp_residue = fs::read_dir(&config_dir).unwrap().all(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_none_or(|name| {
                    name == ".pending-authority-cleanup.v1.json.tmp-lookalike-sentinel"
                        || !name.contains("pending-authority-cleanup.v1.json.tmp-")
                })
        });
        let lookalike_temp_unchanged = fs::read(&lookalike_temp)
            .is_ok_and(|bytes| bytes == lookalike_temp_bytes)
            && fs::symlink_metadata(&lookalike_temp).is_ok_and(|metadata| {
                metadata.permissions().mode() & 0o777 == 0o600
                    && metadata.dev() == lookalike_temp_before.dev()
                    && metadata.ino() == lookalike_temp_before.ino()
            });
        let first_stopped_before_runtime = lock(&state).proxy.is_none()
            && lock(&state).sandbox.is_none()
            && TcpStream::connect(("127.0.0.1", proxy_port)).is_err()
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err();
        let neighbor_after_fault = authority_tree(&neighbor) == neighbor_before;

        {
            let mut authority = lock(&state);
            let runtime = authority.science_runtime.clone();
            let AppState {
                sandbox,
                sandbox_url,
                ..
            } = &mut *authority;
            let _ = science::stop_sandbox(&handle, sandbox, sandbox_url, runtime.as_ref());
            authority.stop_proxy();
        }
        drop(failpoint);
        let fresh_state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        cleanup.state = fresh_state.clone();
        let second = sandbox_session::one_click_login(
            handle,
            fresh_state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let manifest_cleared = match fs::read(&manifest_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| value["entries"].as_array().cloned())
                .is_some_and(|entries| entries.is_empty()),
            _ => false,
        };
        let fresh_retry_continued = second
            .as_ref()
            .is_ok_and(|value| matches!(value["action"].as_str(), Some("started" | "reopened")));
        let neighbor_untouched = authority_tree(&neighbor) == neighbor_before;
        let lifecycle_observation = config::test_pending_cleanup_lifecycle_observation();
        let lifecycle_order_exact = lifecycle_observation.events
            == vec![
                config::PendingCleanupLifecycleEvent::Register(lifecycle_identity.clone()),
                config::PendingCleanupLifecycleEvent::Remove {
                    identity: lifecycle_identity,
                    not_found: true,
                },
                config::PendingCleanupLifecycleEvent::Clear,
            ];
        let lifecycle_boundaries_exact = lifecycle_observation.validated_loader_count == 1
            && lifecycle_observation.initial_ticket_count == 1
            && lifecycle_observation.race_hook_count == 1
            && lifecycle_observation.delete_attempt_count == 0
            && lifecycle_observation.completion_count == 1
            && lifecycle_observation.causal_mismatch_count == 0;
        cleanup
            .finish()
            .expect("manifest pre-rename fixture must leave no process or temp residue");

        assert!(
            first.is_err()
                && observed.is_some()
                && old_manifest_exact
                && owned_temp_observed_and_cleaned
                && no_temp_residue
                && lookalike_temp_unchanged
                && first_stopped_before_runtime
                && neighbor_after_fault
                && fresh_retry_continued
                && manifest_cleared
                && neighbor_untouched
                && lifecycle_order_exact
                && lifecycle_boundaries_exact,
            "pre-rename CLEAR fault must occur only after the fresh loader and explicit Missing/AlreadyAbsent completion boundaries, preserve the old private target byte/mode/inode-exactly, remove only its owned temp, and retain the lookalike: first_failed={}, failpoint_reached={}, old_manifest_exact={old_manifest_exact}, owned_temp_observed_and_cleaned={owned_temp_observed_and_cleaned}, no_temp_residue={no_temp_residue}, lookalike_temp_unchanged={lookalike_temp_unchanged}, first_stopped_before_runtime={first_stopped_before_runtime}, neighbor_after_fault={neighbor_after_fault}, fresh_retry_continued={fresh_retry_continued}, manifest_cleared={manifest_cleared}, neighbor_untouched={neighbor_untouched}, lifecycle_order_exact={lifecycle_order_exact}, lifecycle_boundaries_exact={lifecycle_boundaries_exact}, validated_loader_count={}, initial_ticket_count={}, race_hook_count={}, delete_attempt_count={}, completion_count={}, causal_mismatch_count={}",
            first.is_err(),
            observed.is_some(),
            lifecycle_observation.validated_loader_count,
            lifecycle_observation.initial_ticket_count,
            lifecycle_observation.race_hook_count,
            lifecycle_observation.delete_attempt_count,
            lifecycle_observation.completion_count,
            lifecycle_observation.causal_mismatch_count
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary durable REGISTER failure; temp HOME, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_cleanup_register_failure_never_enters_remove() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("cleanup-register-failure");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let cleanup_log = tmp.join("remove-attempt.log");
        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );
        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        config::save_to(&config_dir, &cfg).unwrap();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );
        let _remove_seam = sandbox_session::test_arm_authority_snapshot_cleanup_fault(
            tmp.clone(),
            "persistent",
            cleanup_log.clone(),
        );
        let _lifecycle_seam = config::test_arm_pending_cleanup_lifecycle(Some(
            config::PendingCleanupPublishFault::Register,
        ));
        let result =
            sandbox_session::one_click_login(handle, state.clone(), lifecycle.as_ref(), None, None);
        let lifecycle_observation = config::test_pending_cleanup_lifecycle_observation();
        let residual = lifecycle_observation
            .attempted_register
            .as_ref()
            .map(|identity| identity.path.clone());
        let remove_log_empty = fs::read_to_string(&cleanup_log)
            .unwrap_or_default()
            .is_empty();
        let residual_private = residual.as_ref().is_some_and(|path| path.is_dir());
        let register_failed_before_remove = result.is_err()
            && lifecycle_observation.attempted_register.is_some()
            && lifecycle_observation.events.is_empty()
            && lifecycle_observation.initial_ticket_count == 0
            && lifecycle_observation.completion_count == 0
            && remove_log_empty
            && residual_private
            && !config_dir
                .join(config::PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE)
                .exists();
        cleanup
            .finish()
            .expect("REGISTER failure fixture must leave no process residue");
        assert!(
            register_failed_before_remove,
            "a product-owned durable REGISTER attempt must fail at its explicit publish boundary, preserve the still-valuable private snapshot, and never enter ticket/completion/Remove/Clear: result_failed={}, attempted_register={}, durable_events={}, initial_ticket_count={}, completion_count={}, remove_log_empty={}, residual_private={}",
            result.is_err(),
            lifecycle_observation.attempted_register.is_some(),
            lifecycle_observation.events.len(),
            lifecycle_observation.initial_ticket_count,
            lifecycle_observation.completion_count,
            remove_log_empty,
            residual_private
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary unsafe cleanup manifest matrix; temp HOME, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_cleanup_manifest_rejects_unsafe_entries_before_runtime() {
        let case = env::var("CSSWITCH_TEST_UNSAFE_MANIFEST_CASE")
            .unwrap_or_else(|_| "invalid-managed-id".into());
        assert!(
            matches!(
                case.as_str(),
                "invalid-managed-id"
                    | "path-mismatch"
                    | "device-mismatch"
                    | "inode-mismatch"
                    | "marker-mismatch"
                    | "manifest-symlink"
                    | "extra-field"
            ),
            "unknown unsafe manifest case"
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir(&format!("unsafe-cleanup-manifest-{case}"));
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );
        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        config::save_to(&config_dir, &cfg).unwrap();
        let config_before = config::load_from(&config_dir).unwrap();
        let sandbox_parent = home.join(config::CONFIG_DIR_NAME).join("sandbox");
        fs::create_dir_all(&sandbox_parent).unwrap();
        let managed_id = ".one-click-rollback-fedcba9876543210fedcba9876543210";
        let managed = sandbox_parent.join(managed_id);
        fs::create_dir(&managed).unwrap();
        let marker = managed.join(".csswitch-one-click-rollback.marker");
        fs::write(&marker, format!("{managed_id}\n")).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::symlink_metadata(&managed).unwrap();
        let neighbor = sandbox_parent.join(".one-click-rollback-11111111111111111111111111111111");
        fs::create_dir(&neighbor).unwrap();
        fs::write(neighbor.join("sentinel"), b"neighbor\n").unwrap();
        let manifest_path = config_dir.join(config::PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE);
        let mut manifest = serde_json::json!({
            "schema_version": 1,
            "entries": [{
                "managed_id": managed_id,
                "path": managed.to_string_lossy().to_string(),
                "device": metadata.dev(),
                "inode": metadata.ino(),
                "marker": managed_id
            }]
        });
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        let predicate_vector = |path: &Path, target: &Path, expected_raw_path: &str| {
            let lstat = fs::symlink_metadata(path).ok();
            let parsed = fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
            let entry = parsed
                .as_ref()
                .and_then(|value| value["entries"].as_array())
                .and_then(|entries| entries.first());
            let target_metadata = fs::symlink_metadata(target).ok();
            let id = entry
                .and_then(|entry| entry["managed_id"].as_str())
                .unwrap_or_default();
            let marker_ticket = entry
                .and_then(|entry| entry["marker"].as_str())
                .unwrap_or_default();
            let suffix = id.strip_prefix(".one-click-rollback-").unwrap_or_default();
            [
                lstat.is_some_and(|metadata| {
                    metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.permissions().mode() & 0o777 == 0o600
                }),
                parsed.as_ref().is_some_and(|value| {
                    value.as_object().is_some_and(|object| {
                        object.len() == 2
                            && object.contains_key("schema_version")
                            && object.contains_key("entries")
                    }) && value["schema_version"] == 1
                        && value["entries"].as_array().is_some_and(|entries| {
                            entries.len() == 1
                                && entries[0].as_object().is_some_and(|object| {
                                    object.len() == 5
                                        && ["managed_id", "path", "device", "inode", "marker"]
                                            .iter()
                                            .all(|key| object.contains_key(*key))
                                        && entries[0]["managed_id"].is_string()
                                        && entries[0]["path"].is_string()
                                        && entries[0]["device"].as_u64().is_some()
                                        && entries[0]["inode"].as_u64().is_some()
                                        && entries[0]["marker"].is_string()
                                })
                        })
                }),
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                entry.and_then(|entry| entry["path"].as_str()) == Some(expected_raw_path),
                entry.and_then(|entry| entry["device"].as_u64())
                    == target_metadata.as_ref().map(MetadataExt::dev),
                entry.and_then(|entry| entry["inode"].as_u64())
                    == target_metadata.as_ref().map(MetadataExt::ino),
                target.file_name().and_then(|name| name.to_str()) == Some(id)
                    && marker_ticket == id
                    && fs::read(target.join(".csswitch-one-click-rollback.marker"))
                        .is_ok_and(|bytes| bytes == format!("{marker_ticket}\n").as_bytes()),
            ]
        };
        let baseline_vector =
            predicate_vector(&manifest_path, &managed, managed.to_string_lossy().as_ref());
        assert_eq!(
            baseline_vector, [true; 7],
            "unsafe matrix baseline E1/E2/P1/P2/P3/P4/P5 must all be true"
        );
        let mut predicate_target = managed.clone();
        let mut expected_raw_path = managed.to_string_lossy().into_owned();
        if case == "invalid-managed-id" {
            let invalid_id = ".one-click-rollback-not-32-lower-hex";
            predicate_target = sandbox_parent.join(invalid_id);
            fs::create_dir(&predicate_target).unwrap();
            fs::write(
                predicate_target.join(".csswitch-one-click-rollback.marker"),
                format!("{invalid_id}\n"),
            )
            .unwrap();
            let invalid_metadata = fs::symlink_metadata(&predicate_target).unwrap();
            expected_raw_path = predicate_target.to_string_lossy().into_owned();
            manifest["entries"][0] = serde_json::json!({
                "managed_id": invalid_id,
                "path": expected_raw_path,
                "device": invalid_metadata.dev(),
                "inode": invalid_metadata.ino(),
                "marker": invalid_id
            });
        } else if case == "path-mismatch" {
            manifest["entries"][0]["path"] =
                serde_json::json!(format!("{}/./{}", sandbox_parent.display(), managed_id));
        } else if case == "device-mismatch" {
            manifest["entries"][0]["device"] = serde_json::json!(metadata.dev() + 1);
        } else if case == "inode-mismatch" {
            manifest["entries"][0]["inode"] = serde_json::json!(metadata.ino() + 1);
        } else if case == "marker-mismatch" {
            fs::write(&marker, b"foreign-marker-authority\n").unwrap();
        } else if case == "extra-field" {
            manifest["unexpected"] = serde_json::json!(true);
        }
        let target_before = authority_tree(&predicate_target);
        let neighbor_before = authority_tree(&neighbor);
        let authority_before = authority_tree(&sandbox_parent);
        let mut symlink_target = None;
        if case == "manifest-symlink" {
            fs::remove_file(&manifest_path).unwrap();
            let foreign = tmp.join("foreign-manifest-target");
            fs::write(&foreign, serde_json::to_vec(&manifest).unwrap()).unwrap();
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
            let foreign_metadata = fs::symlink_metadata(&foreign).unwrap();
            symlink_target = Some((
                foreign.clone(),
                authority_tree(&foreign),
                (
                    foreign_metadata.dev(),
                    foreign_metadata.ino(),
                    foreign_metadata.permissions().mode() & 0o777,
                ),
            ));
            symlink(&foreign, &manifest_path).unwrap();
        } else {
            fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let post_vector = predicate_vector(&manifest_path, &predicate_target, &expected_raw_path);
        let expected_false = match case.as_str() {
            "manifest-symlink" => 0,
            "extra-field" => 1,
            "invalid-managed-id" => 2,
            "path-mismatch" => 3,
            "device-mismatch" => 4,
            "inode-mismatch" => 5,
            "marker-mismatch" => 6,
            _ => unreachable!(),
        };
        assert_eq!(
            post_vector
                .iter()
                .enumerate()
                .filter_map(|(index, valid)| (!valid).then_some(index))
                .collect::<Vec<_>>(),
            vec![expected_false],
            "each unsafe selector must make exactly one of E1/E2/P1/P2/P3/P4/P5 false"
        );
        let manifest_before = authority_tree(&manifest_path);
        let manifest_metadata_before = fs::symlink_metadata(&manifest_path).unwrap();
        let manifest_identity_before = (
            manifest_metadata_before.dev(),
            manifest_metadata_before.ino(),
            manifest_metadata_before.permissions().mode() & 0o777,
            manifest_metadata_before.file_type().is_symlink(),
        );

        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );
        let result =
            sandbox_session::one_click_login(handle, state.clone(), lifecycle.as_ref(), None, None);
        let rejected_before_runtime = result.is_err()
            && lock(&state).proxy.is_none()
            && lock(&state).sandbox.is_none()
            && TcpStream::connect(("127.0.0.1", proxy_port)).is_err()
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err();
        let config_unchanged =
            config::load_from(&config_dir).is_ok_and(|current| current == config_before);
        let authority_untouched = authority_tree(&sandbox_parent) == authority_before;
        let target_untouched = authority_tree(&predicate_target) == target_before;
        let neighbor_untouched = authority_tree(&neighbor) == neighbor_before;
        let manifest_untouched = authority_tree(&manifest_path) == manifest_before
            && fs::symlink_metadata(&manifest_path).is_ok_and(|metadata| {
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.permissions().mode() & 0o777,
                    metadata.file_type().is_symlink(),
                ) == manifest_identity_before
            });
        let symlink_target_untouched =
            symlink_target
                .as_ref()
                .is_none_or(|(path, before, identity)| {
                    authority_tree(path) == *before
                        && fs::symlink_metadata(path).is_ok_and(|metadata| {
                            (
                                metadata.dev(),
                                metadata.ino(),
                                metadata.permissions().mode() & 0o777,
                            ) == *identity
                        })
                });
        cleanup
            .finish()
            .expect("unsafe manifest fixture must leave no process or temp residue");
        assert!(
            rejected_before_runtime
                && config_unchanged
                && authority_untouched
                && target_untouched
                && neighbor_untouched
                && manifest_untouched
                && symlink_target_untouched,
            "each unsafe manifest case must vary only its named invalid dimension, fail closed before Gateway/Science, and preserve target, neighbor, config, manifest bytes/mode/device/inode or symlink authority, and symlink target exactly: case={case}, baseline_vector={baseline_vector:?}, post_vector={post_vector:?}, rejected_before_runtime={rejected_before_runtime}, config_unchanged={config_unchanged}, authority_untouched={authority_untouched}, target_untouched={target_untouched}, neighbor_untouched={neighbor_untouched}, manifest_untouched={manifest_untouched}, symlink_target_untouched={symlink_target_untouched}"
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary compensation diagnostic redaction; temp HOME, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_compensation_diagnostics_are_credential_free() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("compensation-diagnostic-redaction");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE_ONCE", "1");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );
        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        cfg.reuse_system_ssh = false;
        config::save_to(&config_dir, &cfg).unwrap();
        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        fs::create_dir_all(sandbox_home.join(".claude-science")).unwrap();
        crate::oauth_forge::ensure_virtual_login(
            &sandbox_home.join(".claude-science"),
            "virtual@localhost.invalid",
            &sandbox_home,
        )
        .unwrap();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );
        science::test_reset_managed_launch_commit_failure_once();
        let canary = format!("rollback-raw-canary-credential-{}", config::new_id());
        let _rollback_seam = sandbox_session::test_arm_rollback_diagnostic_canary(&canary);
        let _cleanup_lifecycle = config::test_arm_pending_cleanup_lifecycle(None);
        let result =
            sandbox_session::one_click_login(handle, state.clone(), lifecycle.as_ref(), None, None);
        let surface = match &result {
            Ok(value) => value.to_string(),
            Err(error) => error.clone(),
        };
        let target_failure_reached = surface.contains("test-only managed launch commit failure");
        let diagnostic_credential_free = !surface.contains(&canary);
        let valuable_snapshot = sandbox_session::test_rollback_diagnostic_snapshot();
        let cleanup_observation = config::test_pending_cleanup_lifecycle_observation();
        let failed_restore_preserved_unregistered_snapshot =
            valuable_snapshot.as_ref().is_some_and(|path| path.is_dir())
                && cleanup_observation.events.is_empty()
                && cleanup_observation.attempted_register.is_none()
                && cleanup_observation.initial_ticket_count == 0
                && cleanup_observation.completion_count == 0;
        cleanup
            .finish()
            .expect("diagnostic redaction fixture must leave no process or temp residue");
        assert!(
            target_failure_reached
                && diagnostic_credential_free
                && failed_restore_preserved_unregistered_snapshot,
            "compensation diagnostics may expose only a typed safe rollback code, never a raw nested error; a failed restore whose snapshot remains valuable must reach no durable cleanup boundary and emit no REGISTER/REMOVE/CLEAR: target_failure_reached={target_failure_reached}, diagnostic_credential_free={diagnostic_credential_free}, valuable_snapshot_present={}, cleanup_events={}, attempted_register={}, initial_ticket_count={}, completion_count={}",
            valuable_snapshot.is_some(),
            cleanup_observation.events.len(),
            cleanup_observation.attempted_register.is_some(),
            cleanup_observation.initial_ticket_count,
            cleanup_observation.completion_count
        );
    }

    #[allow(dead_code)] // 仅被 #[cfg(unix)] 门控的集成测试使用
    struct TestChild(std::process::Child);

    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(unix)]
    fn stop_test_sandbox<R: tauri::Runtime>(
        handle: &tauri::AppHandle<R>,
        state: &SharedAppState,
        sandbox_port: u16,
    ) {
        {
            let mut st = lock(state);
            let AppState {
                sandbox,
                sandbox_url,
                science_runtime,
                science_confirmed_stopped,
                ..
            } = &mut *st;
            let runtime = science_runtime.clone();
            assert!(science::stop_sandbox(handle, sandbox, sandbox_url, runtime.as_ref()).is_ok());
            *science_confirmed_stopped = runtime;
            *science_runtime = None;
        }
        wait_http_unreachable(sandbox_port);
    }

    #[cfg(unix)]
    fn kill_tracked_proxy(state: &SharedAppState, proxy_port: u16) {
        let mut proxy_child = {
            let mut st = lock(state);
            assert_eq!(st.proxy_port, proxy_port);
            assert!(!st.secret.is_empty());
            st.proxy.take().expect("proxy child should be tracked")
        };
        let _ = proxy_child.kill();
        let _ = proxy_child.wait();
        wait_http_unreachable(proxy_port);
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary runtime smoke; uses fake Science and local loopback ports"]
    #[cfg(unix)]
    fn isolated_one_click_reuse_status_smoke_with_fake_science() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("isolated-runtime-smoke");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let open_log = tmp.join("open.log");
        let science_call_log = tmp.join("science-call.log");
        let route_config_log = tmp.join("route-config.log");
        let mock_upstream = start_mock_upstream();
        let mock_upstream_port = mock_upstream.port;
        let proxy_port = free_port();
        let sandbox_port = free_port();
        assert_ne!(proxy_port, sandbox_port);

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_FAKE_OPEN_LOG", &open_log);
        env_guard.set("CSSWITCH_FAKE_SCIENCE_CALL_LOG", &science_call_log);
        env_guard.set("CSSWITCH_TEST_THIRD_PARTY_CONFIG_LOG", &route_config_log);
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let fake_key = "csswitch-isolated-fake-key-never-log";
        let profile = Profile {
            id: "mock-relay".into(),
            name: "Mock Relay".into(),
            template_id: "custom".into(),
            category: "custom".into(),
            api_format: "anthropic".into(),
            base_url: format!("http://127.0.0.1:{mock_upstream_port}/anthropic"),
            api_key: fake_key.into(),
            model: "mock-model".into(),
            model_catalog: vec![crate::model_catalog::ModelRoute {
                selector_id: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                display_name: "Mock model".into(),
                upstream_model: "mock-model".into(),
                supports_tools: Some(true),
                ..Default::default()
            }],
            default_model_route_id: "claude-csswitch-relay-mock-model-0123456789ab".into(),
            role_bindings: crate::model_catalog::RoleBindings {
                sonnet: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                opus: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                haiku: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                fable: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let cfg = Config {
            profiles: vec![profile],
            active_id: "mock-relay".into(),
            proxy_port,
            sandbox_port,
            ..Default::default()
        };
        let config_dir = config::default_dir();
        config::save_to(&config_dir, &cfg).unwrap();

        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();

        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );
        let first = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        )
        .expect("first one-click should start proxy and sandbox");
        assert_eq!(first["action"], "started");
        assert!(
            first.get("url").is_none(),
            "one-time URL must stay backend-only"
        );
        wait_http_health(sandbox_port);
        let fake_state_dir = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home")
            .join(".claude-science")
            .join("fake-science");
        let first_pid = fs::read_to_string(fake_state_dir.join("pid")).unwrap();
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("serve-count")).unwrap(),
            "1"
        );
        assert_eq!(call_count(&science_call_log, "--version"), 1);
        assert_eq!(call_count(&science_call_log, "status"), 1);
        assert_eq!(call_count(&science_call_log, "url"), 2);
        assert_eq!(call_count(&route_config_log, "configure-third-party"), 1);

        let second = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        )
        .expect("second one-click should reuse running sandbox");
        assert_eq!(second["action"], "reopened");
        assert!(
            second.get("url").is_none(),
            "one-time URL must stay backend-only"
        );
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("pid")).unwrap(),
            first_pid
        );
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("serve-count")).unwrap(),
            "1"
        );
        assert_eq!(call_count(&science_call_log, "--version"), 1);
        assert_eq!(call_count(&science_call_log, "status"), 2);
        assert_eq!(call_count(&science_call_log, "url"), 3);
        assert_eq!(call_count(&route_config_log, "configure-third-party"), 1);

        let managed_launch_path = config_dir.join("science-managed-launch.v1.json");
        let managed_launch_metadata = managed_launch_path
            .symlink_metadata()
            .expect("managed launch receipt should be committed after a verified start");
        assert!(managed_launch_metadata.file_type().is_file());
        assert_eq!(managed_launch_metadata.permissions().mode() & 0o077, 0);
        assert!(managed_launch_metadata.len() > 0);
        assert!(managed_launch_metadata.len() <= 16 * 1024);

        let version_before_fresh_probe = call_count(&science_call_log, "--version");
        let fresh_probe = science::probe_sandbox_runtime_cached(
            sandbox_port,
            &science::ScienceVersionCache::default(),
        )
        .expect("fresh Science probe should inspect only the isolated runtime candidates");
        assert_eq!(fresh_probe.0, science::SandboxScienceState::RunningHealthy);
        let reattached_runtime = fresh_probe
            .1
            .expect("managed receipt should recover the exact Science runtime");
        assert_eq!(reattached_runtime.path, fake_science);
        assert!(science::runtime_identity_is_current(&reattached_runtime));
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("pid")).unwrap(),
            first_pid
        );
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("serve-count")).unwrap(),
            "1"
        );
        assert_eq!(
            call_count(&science_call_log, "--version"),
            version_before_fresh_probe + 1,
            "fresh Science cache must revalidate the executable version exactly once"
        );
        assert_eq!(call_count(&science_call_log, "--version"), 2);
        assert_eq!(call_count(&science_call_log, "status"), 3);
        assert_eq!(call_count(&science_call_log, "url"), 3);
        assert_eq!(call_count(&route_config_log, "configure-third-party"), 1);

        super::open_url_inner(&state)
            .expect("first manual open should refresh the one-time Science URL");
        super::open_url_inner(&state)
            .expect("second manual open should refresh the one-time Science URL again");
        assert_eq!(call_count(&science_call_log, "url"), 5);
        let opened_urls: Vec<_> = fs::read_to_string(&open_log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert!(opened_urls.len() >= 4);
        assert!(opened_urls[opened_urls.len() - 2].ends_with("/?nonce=4"));
        assert!(opened_urls[opened_urls.len() - 1].ends_with("/?nonce=5"));
        assert_ne!(
            opened_urls[opened_urls.len() - 2],
            opened_urls[opened_urls.len() - 1]
        );

        let fail_once = tmp.join("open-failed-once");
        env_guard.set("CSSWITCH_FAKE_OPEN_FAIL_ONCE_FILE", &fail_once);
        let failed_open = super::open_url_inner(&state)
            .expect("manual opener failure should be a structured UI result");
        assert_eq!(failed_open["status"], "error");
        assert!(failed_open["fallback_url"]
            .as_str()
            .unwrap()
            .ends_with("/?nonce=6"));
        let retried_open = super::open_url_inner(&state)
            .expect("retry should fetch and submit another fresh Science URL");
        assert_eq!(retried_open["status"], "ok");
        assert!(retried_open["fallback_url"].is_null());
        assert_eq!(call_count(&science_call_log, "url"), 7);

        let route_check = lifecycle
            .with_serialized(|| sandbox_session::force_third_party_reconcile(&handle, &state));
        assert_eq!(route_check.as_deref(), Ok("Skill 路由已强制核验并同步。"));
        assert_eq!(call_count(&science_call_log, "--version"), 3);
        assert_eq!(call_count(&science_call_log, "status"), 4);
        assert_eq!(call_count(&science_call_log, "url"), 8);
        assert_eq!(call_count(&route_config_log, "configure-third-party"), 2);

        stop_test_sandbox(&handle, &state, sandbox_port);
        let mut cold_start_ms = Vec::new();
        for cycle in 0..5 {
            let status_before_preflight = call_count(&science_call_log, "status");
            let (version_cache, confirmed_stopped) = {
                let st = lock(&state);
                (
                    st.science_version_cache.clone(),
                    st.science_confirmed_stopped.clone(),
                )
            };
            let preflight =
                science::science_runtime_preflight(&version_cache, confirmed_stopped.as_ref())
                    .expect("explicit preflight should refresh the stopped runtime selection");
            assert_eq!(preflight["status"], "installed_ready");
            assert_eq!(
                call_count(&science_call_log, "status"),
                status_before_preflight + 1,
                "each explicit preflight should perform one bounded status probe"
            );
            let status_before_restart = call_count(&science_call_log, "status");
            let started_at = Instant::now();
            let restarted = sandbox_session::one_click_login(
                handle.clone(),
                state.clone(),
                lifecycle.as_ref(),
                None,
                None,
            )
            .expect("normal cold start should not re-probe or reconfigure");
            cold_start_ms.push(started_at.elapsed().as_millis());
            assert_eq!(restarted["action"], "started");
            assert_eq!(
                call_count(&science_call_log, "status"),
                status_before_restart,
                "confirmed-stop one-click should not repeat the explicit preflight probe"
            );
            if cycle < 4 {
                stop_test_sandbox(&handle, &state, sandbox_port);
            }
        }
        let mut sorted_cold_start_ms = cold_start_ms.clone();
        sorted_cold_start_ms.sort_unstable();
        eprintln!(
            "focused cold starts ms={cold_start_ms:?} median_ms={}",
            sorted_cold_start_ms[2]
        );
        assert_eq!(call_count(&science_call_log, "--version"), 3);
        assert_eq!(call_count(&science_call_log, "status"), 9);
        assert_eq!(call_count(&science_call_log, "url"), 13);
        assert_eq!(call_count(&route_config_log, "configure-third-party"), 2);
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("serve-count")).unwrap(),
            "6"
        );

        stop_test_sandbox(&handle, &state, sandbox_port);
        let upgraded_script = fs::read_to_string(&fake_science)
            .unwrap()
            .replace("0.0.0-csswitch-test", "0.0.1-csswitch-test");
        let upgraded_candidate = bin_dir.join("claude-science-upgraded");
        write_executable(&upgraded_candidate, &upgraded_script);
        fs::rename(&upgraded_candidate, &fake_science).unwrap();
        let (version_cache, confirmed_stopped) = {
            let st = lock(&state);
            (
                st.science_version_cache.clone(),
                st.science_confirmed_stopped.clone(),
            )
        };
        let status_before_upgrade_preflight = call_count(&science_call_log, "status");
        assert_eq!(
            science::science_runtime_preflight(&version_cache, confirmed_stopped.as_ref()).unwrap()
                ["status"],
            "installed_ready"
        );
        assert_eq!(
            call_count(&science_call_log, "status"),
            status_before_upgrade_preflight + 1,
            "binary replacement preflight should perform one bounded status probe"
        );
        let status_before_upgraded_start = call_count(&science_call_log, "status");
        let upgraded = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        )
        .expect("binary replacement should re-probe and reconcile once");
        assert_eq!(upgraded["action"], "started");
        assert_eq!(
            call_count(&science_call_log, "status"),
            status_before_upgraded_start,
            "confirmed-stop upgraded start should not repeat the explicit preflight probe"
        );
        assert_eq!(call_count(&science_call_log, "--version"), 4);
        assert_eq!(call_count(&science_call_log, "status"), 10);
        assert_eq!(call_count(&science_call_log, "url"), 15);
        assert_eq!(call_count(&route_config_log, "configure-third-party"), 3);
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("serve-count")).unwrap(),
            "7"
        );

        let status = super::status(app.state::<SharedAppState>());
        assert_eq!(status["proxy"], "green");
        assert_eq!(status["sandbox"], "green");
        assert_eq!(status["upstream"], "green");
        assert_eq!(status["active_profile"]["id"], "mock-relay");
        assert_eq!(status["science"]["sandbox"]["port"], sandbox_port);
        assert_eq!(status["science"]["schema_version"], 1);
        assert!(status["last_error"].is_null());

        let doctor = std::process::Command::new(root.join("scripts/doctor.sh"))
            .env("HOME", &home)
            .env("SCIENCE_BIN", &fake_science)
            .env("CSSWITCH_CONFIG", config_dir.join("config.json"))
            .env("CSSWITCH_PROXY_PORT", proxy_port.to_string())
            .env("CSSWITCH_SANDBOX_PORT", sandbox_port.to_string())
            .output()
            .expect("doctor should run");
        assert!(doctor.status.success());
        let doctor_out = String::from_utf8_lossy(&doctor.stdout);
        assert!(doctor_out.contains("真实 HOME 检查默认跳过"));
        assert!(!doctor_out.contains(&format!("{}/.claude-science", home.display())));

        let cfg_after = config::load_from(&config_dir).unwrap();
        let secret = cfg_after.secret;
        assert!(!secret.is_empty());
        let doctor_err = String::from_utf8_lossy(&doctor.stderr);
        assert!(!doctor_out.contains(fake_key));
        assert!(!doctor_out.contains(&secret));
        assert!(!doctor_err.contains(fake_key));
        assert!(!doctor_err.contains(&secret));
        assert!(!first.to_string().contains(fake_key));
        assert!(!first.to_string().contains(&secret));
        assert!(!second.to_string().contains(fake_key));
        assert!(!second.to_string().contains(&secret));
        let opened = fs::read_to_string(&open_log).unwrap_or_default();
        assert!(!opened.contains(fake_key));
        assert!(!opened.contains(&secret));
        for name in ["proxy.log", "sandbox.log", "operation.log"] {
            let body = fs::read_to_string(config_dir.join("logs").join(name))
                .unwrap_or_else(|e| panic!("expected {name} to exist: {e}"));
            assert!(!body.contains(fake_key), "{name} leaked fake key");
            assert!(!body.contains(&secret), "{name} leaked path secret");
        }

        let valid_receipt_bytes = fs::read(&managed_launch_path).unwrap();
        let valid_receipt: serde_json::Value =
            serde_json::from_slice(&valid_receipt_bytes).unwrap();
        let valid_receipt_metadata = managed_launch_path.symlink_metadata().unwrap();
        assert_eq!(
            valid_receipt_metadata.uid(),
            unsafe { libc::geteuid() },
            "managed launch receipt must be owned by the current user"
        );
        let listener_pid_before_rejection = fs::read_to_string(fake_state_dir.join("pid")).unwrap();
        let actual_listener_pid = unique_listener_pid(sandbox_port);
        assert_eq!(
            valid_receipt["listener_pid"].as_u64(),
            Some(actual_listener_pid as u64)
        );
        let actual_process_start = process_start_identity(actual_listener_pid);
        assert_eq!(
            valid_receipt["process_start"].as_str(),
            Some(actual_process_start.as_str())
        );
        let helper_process = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("controlled non-listener helper should start");
        let helper_pid = helper_process.id();
        let helper_process_start = process_start_identity(helper_pid);
        let _helper_process = TestChild(helper_process);
        let assert_receipt_rejected = |case: &str| {
            let version_before = call_count(&science_call_log, "--version");
            let status_before = call_count(&science_call_log, "status");
            let observed = science::probe_sandbox_runtime_cached(
                sandbox_port,
                &science::ScienceVersionCache::default(),
            )
            .unwrap_or_else(|error| panic!("{case} probe should classify safely: {error}"));
            assert_eq!(
                observed,
                (science::SandboxScienceState::Unknown, None),
                "{case} must reject the managed launch receipt"
            );
            assert_eq!(
                call_count(&science_call_log, "--version"),
                version_before + 1,
                "{case} must use a fresh executable identity"
            );
            assert_eq!(
                call_count(&science_call_log, "status"),
                status_before + 1,
                "{case} must use one bounded status probe"
            );
            assert_eq!(
                fs::read_to_string(fake_state_dir.join("pid")).unwrap(),
                listener_pid_before_rejection,
                "{case} must not signal the listener"
            );
            assert!(
                TcpStream::connect(("127.0.0.1", sandbox_port)).is_ok(),
                "{case} must leave the listener reachable"
            );
            assert_eq!(
                unique_listener_pid(sandbox_port),
                actual_listener_pid,
                "{case} must leave the same kernel listener PID"
            );
            assert_eq!(
                process_start_identity(actual_listener_pid),
                actual_process_start,
                "{case} must not replace or recycle the listener process"
            );
        };

        let mut receipt_mutants = Vec::new();
        for field in [
            "schema_version",
            "port",
            "runtime_device",
            "runtime_inode",
            "runtime_size",
            "runtime_modified_seconds",
            "runtime_modified_nanoseconds",
            "runtime_mode",
            "data_dir_device",
            "data_dir_inode",
        ] {
            let mut mutant = valid_receipt.clone();
            let value = mutant[field]
                .as_u64()
                .unwrap_or_else(|| panic!("{field} must be numeric"));
            let changed = if value == u64::MAX {
                value - 1
            } else {
                value + 1
            };
            mutant[field] = serde_json::Value::from(changed);
            receipt_mutants.push((field, mutant));
        }
        for field in ["runtime_path", "data_dir"] {
            let mut mutant = valid_receipt.clone();
            let value = mutant[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} must be a path string"));
            mutant[field] = serde_json::Value::from(format!("{value}.tampered"));
            receipt_mutants.push((field, mutant));
        }
        let mut listener_pid_mutant = valid_receipt.clone();
        listener_pid_mutant["listener_pid"] = serde_json::Value::from(helper_pid);
        listener_pid_mutant["process_start"] = serde_json::Value::from(helper_process_start);
        receipt_mutants.push(("non_listener_pid", listener_pid_mutant));
        let mut process_start_mutant = valid_receipt.clone();
        process_start_mutant["process_start"] = serde_json::Value::from(format!(
            "{} tampered",
            valid_receipt["process_start"].as_str().unwrap()
        ));
        receipt_mutants.push(("process_start", process_start_mutant));
        let mut fingerprint_mutant = valid_receipt.clone();
        fingerprint_mutant["runtime_sha256"] = serde_json::Value::from("00".repeat(32));
        receipt_mutants.push(("runtime_sha256", fingerprint_mutant));
        let mut unknown_field_mutant = valid_receipt.clone();
        unknown_field_mutant
            .as_object_mut()
            .unwrap()
            .insert("unexpected_field".into(), serde_json::Value::Bool(true));
        receipt_mutants.push(("unknown_field", unknown_field_mutant));

        for (case, mutant) in receipt_mutants {
            fs::write(&managed_launch_path, serde_json::to_vec(&mutant).unwrap()).unwrap();
            fs::set_permissions(&managed_launch_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_receipt_rejected(case);
            fs::write(&managed_launch_path, &valid_receipt_bytes).unwrap();
        }

        fs::set_permissions(&managed_launch_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_receipt_rejected("widened_mode");
        fs::set_permissions(&managed_launch_path, fs::Permissions::from_mode(0o600)).unwrap();

        let mut oversized_receipt = valid_receipt_bytes.clone();
        oversized_receipt.resize(16 * 1024 + 1, b' ');
        assert!(
            serde_json::from_slice::<serde_json::Value>(&oversized_receipt).is_ok(),
            "oversized receipt mutant must remain valid JSON"
        );
        fs::write(&managed_launch_path, oversized_receipt).unwrap();
        assert_receipt_rejected("oversized_receipt");
        fs::write(&managed_launch_path, &valid_receipt_bytes).unwrap();

        let symlink_target = config_dir.join("science-managed-launch-target.json");
        fs::write(&symlink_target, &valid_receipt_bytes).unwrap();
        fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&managed_launch_path).unwrap();
        symlink(&symlink_target, &managed_launch_path).unwrap();
        assert_receipt_rejected("symlink_receipt");
        fs::remove_file(&managed_launch_path).unwrap();
        fs::remove_file(&symlink_target).unwrap();
        fs::write(&managed_launch_path, &valid_receipt_bytes).unwrap();
        fs::set_permissions(&managed_launch_path, fs::Permissions::from_mode(0o600)).unwrap();

        fs::remove_file(&managed_launch_path)
            .expect("isolated managed launch receipt should be removable for rejection injection");
        let version_before_rejected_reattach = call_count(&science_call_log, "--version");
        let status_before_rejected_reattach = call_count(&science_call_log, "status");
        let rejected = science::probe_sandbox_runtime_cached(
            sandbox_port,
            &science::ScienceVersionCache::default(),
        )
        .expect("missing receipt should be a classified Science state");
        assert_eq!(
            rejected,
            (science::SandboxScienceState::Unknown, None),
            "fresh Science probe must reject a listener after its receipt is removed"
        );
        assert_eq!(
            call_count(&science_call_log, "--version"),
            version_before_rejected_reattach + 1,
            "receipt rejection must still revalidate the executable through a fresh cache"
        );
        assert_eq!(
            call_count(&science_call_log, "status"),
            status_before_rejected_reattach + 1
        );
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("pid")).unwrap(),
            listener_pid_before_rejection,
            "rejected adoption must not signal the unproven listener"
        );
        assert!(
            TcpStream::connect(("127.0.0.1", sandbox_port)).is_ok(),
            "rejected adoption must leave the unproven listener untouched"
        );
        assert_eq!(
            unique_listener_pid(sandbox_port),
            actual_listener_pid,
            "missing receipt rejection must leave the same kernel listener PID"
        );
        assert_eq!(
            process_start_identity(actual_listener_pid),
            actual_process_start,
            "missing receipt rejection must not recycle the listener process"
        );
        fs::write(&managed_launch_path, &valid_receipt_bytes).unwrap();
        fs::set_permissions(&managed_launch_path, fs::Permissions::from_mode(0o600)).unwrap();

        let drift_marker = tmp.join("process-start-drift");
        env_guard.set(
            "CSSWITCH_TEST_PROCESS_START_DRIFT_PID",
            actual_listener_pid.to_string(),
        );
        env_guard.set("CSSWITCH_TEST_PROCESS_START_DRIFT_MARKER", &drift_marker);
        let drift_stop = {
            let mut st = lock(&state);
            super::stop_sandbox_state(&handle, &mut st)
        };
        let listener_after_drift_stop = listener_pid_if_unique(sandbox_port);
        let receipt_preserved_after_drift = managed_launch_path.is_file();
        env::remove_var("CSSWITCH_TEST_PROCESS_START_DRIFT_PID");
        env::remove_var("CSSWITCH_TEST_PROCESS_START_DRIFT_MARKER");
        let process_start_after_drift_stop = process_start_identity_if_alive(actual_listener_pid);

        let (runtime_before_stop_oracles, url_before_stop_oracles) = {
            let st = lock(&state);
            (
                st.science_runtime
                    .clone()
                    .expect("failed drift stop must retain the exact runtime"),
                st.sandbox_url.clone(),
            )
        };
        let port_sequence = tmp.join("false-then-true-port-observation");
        fs::create_dir_all(&port_sequence).unwrap();
        let mut concurrent_receipt = valid_receipt.clone();
        concurrent_receipt["launch_id"] =
            serde_json::Value::from("concurrent-managed-launch-receipt-0001");
        let concurrent_receipt_bytes = serde_json::to_vec(&concurrent_receipt).unwrap();
        assert_ne!(
            concurrent_receipt_bytes, valid_receipt_bytes,
            "false-to-true oracle replacement receipt must have a distinct identity"
        );
        let concurrent_receipt_source = config_dir.join(".concurrent-managed-launch-receipt.json");
        fs::write(&concurrent_receipt_source, &concurrent_receipt_bytes).unwrap();
        fs::set_permissions(
            &concurrent_receipt_source,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        env_guard.set(
            "CSSWITCH_TEST_PORT_OBSERVATION_TARGET",
            sandbox_port.to_string(),
        );
        env_guard.set(
            "CSSWITCH_TEST_PORT_OBSERVATION_SEQUENCE_DIR",
            &port_sequence,
        );
        env_guard.set(
            "CSSWITCH_TEST_PORT_OBSERVATION_REPLACEMENT_RECEIPT",
            &concurrent_receipt_source,
        );
        env_guard.set(
            "CSSWITCH_TEST_PORT_OBSERVATION_RECEIPT",
            &managed_launch_path,
        );
        let false_then_true_stop = {
            let mut st = lock(&state);
            super::stop_sandbox_state(&handle, &mut st)
        };
        let (
            false_then_true_confirmed_stopped,
            false_then_true_runtime,
            false_then_true_receipt,
            false_then_true_listener,
            false_then_true_process_start,
        ) = {
            let st = lock(&state);
            (
                st.science_confirmed_stopped.clone(),
                st.science_runtime.clone(),
                fs::read(&managed_launch_path).ok(),
                listener_pid_if_unique(sandbox_port),
                process_start_identity_if_alive(actual_listener_pid),
            )
        };
        env::remove_var("CSSWITCH_TEST_PORT_OBSERVATION_TARGET");
        env::remove_var("CSSWITCH_TEST_PORT_OBSERVATION_SEQUENCE_DIR");
        env::remove_var("CSSWITCH_TEST_PORT_OBSERVATION_REPLACEMENT_RECEIPT");
        env::remove_var("CSSWITCH_TEST_PORT_OBSERVATION_RECEIPT");
        let complete_port_sequence = port_sequence.join("observed-false").is_file()
            && port_sequence.join("receipt-replaced").is_file()
            && port_sequence.join("observed-true").is_file()
            && !port_sequence.join("receipt-replacement-failed").is_file();
        {
            let mut st = lock(&state);
            st.science_confirmed_stopped = None;
            st.science_runtime = Some(runtime_before_stop_oracles.clone());
            st.sandbox_url = url_before_stop_oracles.clone();
        }

        let sandbox_data_dir = fake_state_dir
            .parent()
            .expect("fake Science state must have an isolated data-dir parent")
            .to_path_buf();
        let moved_data_dir = sandbox_data_dir.with_extension("missing-for-stop-oracle");
        fs::rename(&sandbox_data_dir, &moved_data_dir)
            .expect("isolated data-dir must be movable for the missing-dir stop oracle");
        let missing_data_dir_stop = {
            let mut st = lock(&state);
            super::stop_sandbox_state(&handle, &mut st)
        };
        let (missing_data_dir_confirmed_stopped, missing_data_dir_runtime) = {
            let st = lock(&state);
            (
                st.science_confirmed_stopped.clone(),
                st.science_runtime.clone(),
            )
        };
        let missing_data_dir_receipt = fs::read(&managed_launch_path).ok();
        let missing_data_dir_listener = listener_pid_if_unique(sandbox_port);
        let missing_data_dir_process_start = process_start_identity_if_alive(actual_listener_pid);
        fs::rename(&moved_data_dir, &sandbox_data_dir)
            .expect("isolated data-dir must be restored for bounded cleanup");
        {
            let mut st = lock(&state);
            st.science_confirmed_stopped = None;
            st.science_runtime = Some(runtime_before_stop_oracles.clone());
            st.sandbox_url = url_before_stop_oracles;
        }
        cleanup.finish().expect(
            "all isolated Science and Gateway fixtures must cleanly stop before oracle assertions",
        );

        assert!(
            complete_port_sequence,
            "false-to-true stop oracle must inject observed-false, replace the managed receipt, and then inject observed-true"
        );
        assert_eq!(
            false_then_true_receipt.as_deref(),
            Some(concurrent_receipt_bytes.as_slice()),
            "false-to-true stop oracle must observe the concurrently committed receipt before evaluating stop success"
        );
        if env::var("CSSWITCH_TEST_STOP_ORACLE_FIRST").ok().as_deref() == Some("missing-data-dir") {
            assert!(
                missing_data_dir_stop.is_err(),
                "stop must fail closed when the data-dir disappears while the exact managed listener remains"
            );
        }
        assert!(
            false_then_true_stop.is_err(),
            "stop must fail closed when configured-port observations change from false to true after the stop CLI"
        );
        assert!(
            false_then_true_confirmed_stopped.is_none()
                && false_then_true_runtime.as_ref() == Some(&runtime_before_stop_oracles),
            "false-to-true port observations must not publish a confirmed-stopped transition"
        );
        assert_eq!(
            false_then_true_listener,
            Some(actual_listener_pid),
            "false-to-true port observations must not signal or replace the managed listener"
        );
        assert_eq!(
            false_then_true_process_start,
            Some(actual_process_start.clone()),
            "false-to-true port observations must preserve the exact managed process identity"
        );

        assert!(
            missing_data_dir_stop.is_err(),
            "stop must fail closed when the data-dir disappears while the exact managed listener remains"
        );
        assert!(
            missing_data_dir_confirmed_stopped.is_none()
                && missing_data_dir_runtime.as_ref() == Some(&runtime_before_stop_oracles),
            "a missing data-dir with a live managed listener must not publish a confirmed-stopped transition"
        );
        assert_eq!(
            missing_data_dir_receipt.as_deref(),
            Some(concurrent_receipt_bytes.as_slice()),
            "a missing data-dir with a live managed listener must preserve the managed receipt"
        );
        assert_eq!(
            missing_data_dir_listener,
            Some(actual_listener_pid),
            "a missing data-dir stop must leave the exact managed listener untouched"
        );
        assert_eq!(
            missing_data_dir_process_start,
            Some(actual_process_start.clone()),
            "a missing data-dir stop must preserve the exact managed process identity"
        );

        assert!(
            drift_stop.is_err(),
            "stop must fail closed when process-start changes after the stop CLI"
        );
        assert_eq!(
            listener_after_drift_stop,
            Some(actual_listener_pid),
            "process-start drift must not signal or replace the listener"
        );
        assert_eq!(
            process_start_after_drift_stop,
            Some(actual_process_start),
            "process-start drift must leave the original listener alive"
        );
        assert!(
            receipt_preserved_after_drift,
            "failed stop must preserve the managed launch receipt for safe retry"
        );
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary recovery proof; uses fake Science and local loopback ports"]
    #[cfg(unix)]
    fn isolated_manual_actions_recover_dead_proxy_with_fake_science() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("isolated-recovery-proof");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        fs::create_dir_all(&home).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let open_log = tmp.join("open.log");
        let mock_upstream = start_mock_upstream();
        let mock_upstream_port = mock_upstream.port;
        let proxy_port = free_port();
        let sandbox_port = free_port();
        assert_ne!(proxy_port, sandbox_port);

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_FAKE_OPEN_LOG", &open_log);
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let fake_key = "csswitch-isolated-fake-key-never-log";
        let profile = Profile {
            id: "mock-relay".into(),
            name: "Mock Relay".into(),
            template_id: "custom".into(),
            category: "custom".into(),
            api_format: "anthropic".into(),
            base_url: format!("http://127.0.0.1:{mock_upstream_port}/anthropic"),
            api_key: fake_key.into(),
            model: "mock-model".into(),
            model_catalog: vec![crate::model_catalog::ModelRoute {
                selector_id: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                display_name: "Mock model".into(),
                upstream_model: "mock-model".into(),
                supports_tools: Some(true),
                ..Default::default()
            }],
            default_model_route_id: "claude-csswitch-relay-mock-model-0123456789ab".into(),
            role_bindings: crate::model_catalog::RoleBindings {
                sonnet: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                opus: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                haiku: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                fable: "claude-csswitch-relay-mock-model-0123456789ab".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let cfg = Config {
            profiles: vec![profile],
            active_id: "mock-relay".into(),
            proxy_port,
            sandbox_port,
            ..Default::default()
        };
        let config_dir = config::default_dir();
        config::save_to(&config_dir, &cfg).unwrap();

        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );

        let first = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        )
        .expect("first one-click should start proxy and sandbox");
        assert_eq!(first["action"], "started");
        assert!(
            first.get("url").is_none(),
            "one-time URL must stay backend-only"
        );
        wait_http_health(proxy_port);
        wait_http_health(sandbox_port);
        let fake_state_dir = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home")
            .join(".claude-science")
            .join("fake-science");
        let first_pid = fs::read_to_string(fake_state_dir.join("pid")).unwrap();

        kill_tracked_proxy(&state, proxy_port);

        let down_status = super::status(app.state::<SharedAppState>());
        assert_eq!(down_status["proxy"], "amber");
        assert_eq!(down_status["sandbox"], "green");
        assert_eq!(down_status["last_error"]["type"], "proxy_unhealthy");
        assert_eq!(
            down_status["last_error"]["message"],
            "代理进程不可达或已退出，请点击「一键开始」恢复。"
        );
        assert_eq!(down_status["last_error"]["port"], proxy_port);

        let start_proxy_recovered =
            super::start_proxy_inner_cmd(handle.clone(), state.clone(), lifecycle.clone())
                .expect("start_proxy should manually recover a dead proxy");
        assert_eq!(start_proxy_recovered["port"], proxy_port);
        wait_http_health(proxy_port);

        let start_proxy_status = super::status(app.state::<SharedAppState>());
        assert_eq!(start_proxy_status["proxy"], "green");
        assert_eq!(start_proxy_status["sandbox"], "green");
        assert_eq!(start_proxy_status["upstream"], "green");
        assert!(start_proxy_status["last_error"].is_null());

        kill_tracked_proxy(&state, proxy_port);
        let down_again_status = super::status(app.state::<SharedAppState>());
        assert_eq!(down_again_status["proxy"], "amber");
        assert_eq!(down_again_status["sandbox"], "green");
        assert_eq!(down_again_status["last_error"]["type"], "proxy_unhealthy");

        let recovered = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        )
        .expect("one-click should manually recover a dead proxy");
        assert_eq!(recovered["action"], "reopened");
        assert_eq!(recovered["stage"], "complete");
        assert_eq!(recovered["status"], "ok");
        assert_eq!(recovered["recovery_status"], "not_needed");
        assert_eq!(recovered["external_skill_installer"]["status"], "WARNING");
        assert!(
            recovered.get("url").is_none(),
            "one-time URL must stay backend-only"
        );
        wait_http_health(proxy_port);
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("pid")).unwrap(),
            first_pid
        );
        assert_eq!(
            fs::read_to_string(fake_state_dir.join("serve-count")).unwrap(),
            "1"
        );

        let recovered_status = super::status(app.state::<SharedAppState>());
        assert_eq!(recovered_status["proxy"], "green");
        assert_eq!(recovered_status["sandbox"], "green");
        assert_eq!(recovered_status["upstream"], "green");
        assert!(recovered_status["last_error"].is_null());

        let cfg_after = config::load_from(&config_dir).unwrap();
        let secret = cfg_after.secret;
        assert!(!secret.is_empty());
        assert!(!down_status.to_string().contains(fake_key));
        assert!(!down_status.to_string().contains(&secret));
        assert!(!recovered.to_string().contains(fake_key));
        assert!(!recovered.to_string().contains(&secret));
        assert!(!recovered_status.to_string().contains(fake_key));
        assert!(!recovered_status.to_string().contains(&secret));
        for name in ["proxy.log", "sandbox.log", "operation.log"] {
            let body = fs::read_to_string(config_dir.join("logs").join(name))
                .unwrap_or_else(|e| panic!("expected {name} to exist: {e}"));
            assert!(!body.contains(fake_key), "{name} leaked fake key");
            assert!(!body.contains(&secret), "{name} leaked path secret");
        }

        cleanup
            .finish()
            .expect("isolated recovery fixtures must cleanly stop");
    }

    #[test]
    #[ignore = "explicit Acceptance-boundary preexisting managed SSH stub rollback; temp HOME, fake OAuth, fake Science, and loopback only"]
    #[cfg(unix)]
    fn isolated_late_failure_preserves_preexisting_managed_stub_when_science_stopped() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let tmp = tmpdir("preexisting-managed-stub-late-failure");
        let home = tmp.join("home");
        let bin_dir = tmp.join("bin");
        let system_ssh = home.join(".ssh");
        let system_config = system_ssh.join("config");
        fs::create_dir_all(&system_ssh).unwrap();
        fs::write(&system_config, "Host isolated-test-host\n").unwrap();
        fs::set_permissions(&system_config, fs::Permissions::from_mode(0o600)).unwrap();
        let fake_science = write_test_bins(&bin_dir).canonicalize().unwrap();
        let mock_upstream = start_mock_upstream();
        let (proxy_port, sandbox_port) = ssh_fixture_ports();
        let science_call_log = tmp.join("science-call.log");
        let open_log = tmp.join("open.log");

        let mut env_guard = EnvGuard::new();
        env_guard.set("HOME", &home);
        env_guard.set("CSSWITCH_REPO", &root);
        env_guard.set("SCIENCE_BIN", &fake_science);
        env_guard.set("CSSWITCH_TEST_OPEN_BIN", bin_dir.join("open"));
        env_guard.set("CSSWITCH_FAKE_OPEN_LOG", &open_log);
        env_guard.set("CSSWITCH_FAKE_SCIENCE_CALL_LOG", &science_call_log);
        env_guard.set("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY", "1");
        env_guard.set("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0");
        env_guard.set(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                bin_dir.to_string_lossy()
            ),
        );

        let config_dir = config::default_dir();
        let mut cfg = ssh_fixture_config(mock_upstream.port, proxy_port, sandbox_port);
        let api_canary = format!("managed-stub-api-{}", config::new_id());
        cfg.profile_by_id_mut("ssh-transaction").unwrap().api_key = api_canary.clone();
        cfg.secret = config::new_id();
        cfg.runtime_transaction = Some(config::RuntimeTransactionJournal {
            transaction_id: "preexisting-stub-prior-journal".into(),
            target_profile_id: "ssh-transaction".into(),
            stage: "prior-authority".into(),
            previous_binding: cfg.runtime_binding.clone(),
            previous_gateway: None,
        });
        config::save_to(&config_dir, &cfg).unwrap();

        let sandbox_home = home
            .join(config::CONFIG_DIR_NAME)
            .join("sandbox")
            .join("home");
        let sandbox_ssh = sandbox_home.join(".ssh");
        let sandbox_stub = sandbox_ssh.join("config");
        let foreign_neighbor = sandbox_ssh.join("known_hosts");
        fs::create_dir_all(&sandbox_ssh).unwrap();
        fs::set_permissions(&sandbox_ssh, fs::Permissions::from_mode(0o700)).unwrap();
        let stub_bytes = format!(
            "# CSSwitch managed system SSH config bridge v2\nHost isolated-test-host\nInclude \"{}\"\n",
            system_config.display()
        )
        .into_bytes();
        fs::write(&sandbox_stub, &stub_bytes).unwrap();
        fs::set_permissions(&sandbox_stub, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&foreign_neighbor, b"foreign-neighbor-must-survive\n").unwrap();
        fs::set_permissions(&foreign_neighbor, fs::Permissions::from_mode(0o600)).unwrap();

        let science_data = sandbox_home.join(".claude-science");
        fs::create_dir_all(&science_data).unwrap();
        crate::oauth_forge::ensure_virtual_login(
            &science_data,
            "virtual@localhost.invalid",
            &sandbox_home,
        )
        .unwrap();
        fs::remove_file(science_data.join("active-org.json")).unwrap();
        fs::write(
            science_data.join("config.toml"),
            "quiet_logs = true\nssh_hosts = [\"prior-user-host\"]\n",
        )
        .unwrap();
        fs::set_permissions(
            science_data.join("config.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let inplace_authority = science_data.join("orgs/csswitch-test/prior-inplace.db");
        fs::create_dir_all(inplace_authority.parent().unwrap()).unwrap();
        fs::write(&inplace_authority, b"prior-inplace-authority\n").unwrap();
        fs::set_permissions(&inplace_authority, fs::Permissions::from_mode(0o600)).unwrap();
        let failure_marker = tmp.join("serve-mutation-reached");
        let failure_control = science_data.join("fake-science/fail-after-inplace-mutation");
        fs::create_dir_all(failure_control.parent().unwrap()).unwrap();
        fs::write(
            &failure_control,
            format!(
                "{}\n{}\n",
                inplace_authority.display(),
                failure_marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&failure_control, fs::Permissions::from_mode(0o600)).unwrap();

        let prior_runtime =
            science::select_science_runtime_cached(None, &science::ScienceVersionCache::default())
                .unwrap();
        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        {
            let mut authority = lock(&state);
            authority.sandbox_port = sandbox_port;
            authority.sandbox_url = None;
            authority.science_runtime = None;
            authority.science_confirmed_stopped = Some(prior_runtime.clone());
        }
        let lifecycle = Arc::new(lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let handle = app.handle().clone();
        let prior_explicitly_stopped = lock(&state).sandbox.is_none()
            && lock(&state).science_runtime.is_none()
            && lock(&state).science_confirmed_stopped.as_ref() == Some(&prior_runtime)
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err();

        let config_before = config::load_from(&config_dir).unwrap();
        let app_before = app_authority_projection(&state);
        let system_ssh_before = authority_tree(&system_ssh);
        let science_before = science_authority_projection(&science_data);
        let private_state = sandbox_home.parent().unwrap().join("state");
        let private_state_before = authority_tree(&private_state);
        let runtime_before = authority_tree(&config_dir.join("runtime"));
        let receipt = config_dir.join("science-managed-launch.v1.json");
        let receipt_before = authority_tree(&receipt);
        let stub_tree_before = authority_tree(&sandbox_ssh);
        let neighbor_before = authority_tree(&foreign_neighbor);
        let cleanup = RuntimeSmokeCleanup::new(
            handle.clone(),
            state.clone(),
            tmp.clone(),
            sandbox_port,
            proxy_port,
        );

        let failed = sandbox_session::one_click_login(
            handle.clone(),
            state.clone(),
            lifecycle.as_ref(),
            None,
            None,
        );
        let failure_surface = failed
            .as_ref()
            .err()
            .map(String::as_str)
            .unwrap_or_default()
            .to_string();
        let late_edge_reached = failure_marker.is_file()
            && failure_surface.contains("起沙箱脚本失败")
            && fs::read_to_string(&science_call_log)
                .unwrap_or_default()
                .lines()
                .any(|line| line == "serve");
        let stub_after_failure = authority_tree(&sandbox_ssh);
        let neighbor_after_failure = authority_tree(&foreign_neighbor);
        let config_after_failure = config::load_from(&config_dir).unwrap();
        let app_after_failure = app_authority_projection(&state);
        let all_authorities_restored = config_after_failure == config_before
            && config_after_failure.runtime_transaction == config_before.runtime_transaction
            && app_after_failure == app_before
            && authority_tree(&system_ssh) == system_ssh_before
            && science_authority_projection(&science_data) == science_before
            && authority_tree(&private_state) == private_state_before
            && authority_tree(&config_dir.join("runtime")) == runtime_before
            && authority_tree(&receipt) == receipt_before
            && TcpStream::connect(("127.0.0.1", proxy_port)).is_err()
            && TcpStream::connect(("127.0.0.1", sandbox_port)).is_err();
        let exact_stub_preserved = stub_after_failure == stub_tree_before
            && fs::read(&sandbox_stub).ok().as_deref() == Some(stub_bytes.as_slice())
            && fs::symlink_metadata(&sandbox_stub)
                .is_ok_and(|metadata| metadata.permissions().mode() & 0o777 == 0o600)
            && neighbor_after_failure == neighbor_before;

        fs::remove_file(&failure_control).unwrap();
        let retry =
            sandbox_session::one_click_login(handle, state.clone(), lifecycle.as_ref(), None, None);
        let retry_surface = retry
            .as_ref()
            .map(serde_json::Value::to_string)
            .unwrap_or_else(|error| error.clone());
        let retry_idempotent = retry.as_ref().is_ok_and(|value| {
            value["action"] == "started" && value["stage"] == "complete" && value["status"] == "ok"
        }) && fs::read_to_string(
            science_data.join("fake-science/serve-count"),
        )
        .ok()
        .as_deref()
            == Some("1")
            && fs::read_to_string(&science_call_log)
                .unwrap_or_default()
                .lines()
                .filter(|line| *line == "serve")
                .count()
                == 2
            && authority_tree(&sandbox_ssh) == stub_tree_before
            && authority_tree(&foreign_neighbor) == neighbor_before;
        let sinks_credential_free = [
            failure_surface.as_str(),
            retry_surface.as_str(),
            fs::read_to_string(&open_log).unwrap_or_default().as_str(),
        ]
        .iter()
        .all(|sink| !sink.contains(&api_canary) && !sink.contains(&config_before.secret));
        cleanup
            .finish()
            .expect("preexisting managed stub fixture must leave no process residue");

        assert!(
            prior_explicitly_stopped
                && late_edge_reached
                && all_authorities_restored
                && exact_stub_preserved
                && retry_idempotent
                && sinks_credential_free,
            "with prior Science explicitly stopped and an exact valid private V2 CSSwitch-managed SSH stub plus a foreign neighbor already present, a post-OAuth real Science late failure must preserve the exact stub bytes/mode/tree and neighbor, restore every profile/OAuth/Gateway/Science/journal authority, and allow one idempotent retry: prior_explicitly_stopped={prior_explicitly_stopped}, late_edge_reached={late_edge_reached}, all_authorities_restored={all_authorities_restored}, exact_stub_preserved={exact_stub_preserved}, retry_idempotent={retry_idempotent}, sinks_credential_free={sinks_credential_free}"
        );
    }
}
