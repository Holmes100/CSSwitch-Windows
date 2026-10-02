use std::path::Path;

use serde_json::json;
use tauri::State;

use crate::runtime::profile::{
    build_get_config, build_list_templates, build_preset_sync_preview, clear_profile_key_inner,
    create_profile_with_catalog_inner, delete_profile_inner, persist_profile_candidate_inner,
    update_profile_metadata_inner, CatalogEdit, ConnectionEdit,
};
use crate::runtime::profile_switch::scratch_validate_candidate;
use crate::runtime::provider::{reject_openai_custom_anthropic_base, resolve_launch_plan};
use crate::{config, lifecycle, lock, run_blocking_typed, SharedAppState, SharedLifecycle};

fn catalog_edit_from_parts(
    legacy_model_present: bool,
    model_catalog: Option<Vec<crate::model_catalog::ModelRoute>>,
    default_model_route_id: Option<String>,
    role_bindings: Option<crate::model_catalog::RoleBindings>,
) -> Result<Option<CatalogEdit>, String> {
    let catalog_edit = match (model_catalog, default_model_route_id, role_bindings) {
        (None, None, None) => None,
        (Some(routes), Some(default_model_route_id), Some(role_bindings)) => Some(CatalogEdit {
            routes,
            default_model_route_id,
            role_bindings,
        }),
        _ => {
            return Err("model_catalog 必须与 default_model_route_id/role_bindings 一起提交".into())
        }
    };
    if legacy_model_present && catalog_edit.is_some() {
        return Err("legacy model 与完整 model_catalog 不能同时提交".into());
    }
    Ok(catalog_edit)
}

fn require_preview_fingerprint(preview: &serde_json::Value, expected: &str) -> Result<(), String> {
    if preview
        .get("preview_fingerprint")
        .and_then(serde_json::Value::as_str)
        == Some(expected)
    {
        Ok(())
    } else {
        Err("推荐目录预览已过期；配置或内置推荐已变化，请重新预览后确认。".into())
    }
}

fn load_without_runtime_transaction(dir: &Path) -> Result<config::Config, String> {
    let cfg = config::load_from(dir).map_err(|error| error.to_string())?;
    config::require_no_runtime_transaction(&cfg)?;
    Ok(cfg)
}

#[tauri::command]
pub(crate) fn get_config() -> Result<serde_json::Value, String> {
    build_get_config(&config::default_dir())
}

/// 模板注册表交前端铺 UI（新建向导用）。
#[tauri::command]
pub(crate) fn list_templates() -> Result<Vec<serde_json::Value>, String> {
    Ok(build_list_templates())
}

#[tauri::command]
pub(crate) fn preview_profile_preset_sync(id: String) -> Result<serde_json::Value, String> {
    build_preset_sync_preview(&config::default_dir(), &id)
}

#[tauri::command]
pub(crate) async fn apply_profile_preset_sync(
    lifecycle: State<'_, SharedLifecycle>,
    id: String,
    expected_preview_fingerprint: String,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let lifecycle = lifecycle.inner().clone();
    run_blocking_typed(move || {
        lifecycle.with_serialized(|| {
            let dir = config::default_dir();
            load_without_runtime_transaction(&dir)?;
            let preview = build_preset_sync_preview(&dir, &id)?;
            require_preview_fingerprint(&preview, &expected_preview_fingerprint)
                .map_err(crate::commands::RuntimeCommandError::from)?;
            let edit = CatalogEdit {
                routes: serde_json::from_value(preview["model_catalog"].clone())
                    .map_err(|error| error.to_string())?,
                default_model_route_id: preview["default_model_route_id"]
                    .as_str()
                    .ok_or("推荐目录缺少默认 selector")?
                    .to_string(),
                role_bindings: serde_json::from_value(preview["role_bindings"].clone())
                    .map_err(|error| error.to_string())?,
            };
            let cfg = load_without_runtime_transaction(&dir)?;
            let mut candidate = cfg
                .profile_by_id(&id)
                .cloned()
                .ok_or_else(|| format!("找不到 profile：{id}"))?;
            ConnectionEdit::default()
                .with_catalog(Some(edit))
                .apply(&mut candidate)?;
            resolve_launch_plan(&candidate)?;
            persist_profile_candidate_inner(&dir, &id, &candidate)?;
            Ok(json!({
                "committed": true,
                "status": "ok",
                "stage": "complete",
                "recovery_status": "not_needed",
                "message": "已同步最新推荐；下次一键开始时核验并应用。",
            }))
        })
    })
    .await
}

// ---------- profile CRUD 命令（薄包装 *_inner，统一经串行器） ----------
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_profile(
    lifecycle: State<'_, SharedLifecycle>,
    template_id: String,
    name: String,
    key: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
    model_catalog: Option<Vec<crate::model_catalog::ModelRoute>>,
    default_model_route_id: Option<String>,
    role_bindings: Option<crate::model_catalog::RoleBindings>,
) -> Result<String, String> {
    let catalog_edit = catalog_edit_from_parts(
        model.is_some(),
        model_catalog,
        default_model_route_id,
        role_bindings,
    )?;
    lifecycle.with_serialized(|| {
        create_profile_with_catalog_inner(
            &config::default_dir(),
            &template_id,
            &name,
            key.as_deref(),
            base_url.as_deref(),
            model.as_deref(),
            catalog_edit,
        )
    })
}

#[tauri::command]
pub(crate) fn update_profile_metadata(
    lifecycle: State<'_, SharedLifecycle>,
    id: String,
    name: String,
    notes: Option<String>,
) -> Result<(), String> {
    lifecycle.with_serialized(|| {
        update_profile_metadata_inner(&config::default_dir(), &id, &name, notes.as_deref())
    })
}

/// 清 key：经串行器；若清的是【生效】profile → bump_generation 作废在途启动 + 停运行中代理
/// （不再拿旧 key 服务，比照 spec §8.2 运行态撤销）。
#[tauri::command]
pub(crate) fn clear_profile_key(
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
    id: String,
) -> Result<(), String> {
    clear_profile_key_cmd(
        &config::default_dir(),
        state.inner(),
        lifecycle.as_ref(),
        &id,
    )
}

/// 删 profile：经串行器；删的是【生效】profile → active 置空（inner 内）+ bump + 停代理。
#[tauri::command]
pub(crate) fn delete_profile(
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
    id: String,
) -> Result<(), String> {
    delete_profile_cmd(
        &config::default_dir(),
        state.inner(),
        lifecycle.as_ref(),
        &id,
    )
}

fn clear_profile_key_cmd(
    dir: &Path,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    id: &str,
) -> Result<(), String> {
    lifecycle.with_serialized(|| {
        let cfg = load_without_runtime_transaction(dir)?;
        let was_applied = cfg
            .runtime_binding
            .as_ref()
            .map(|binding| binding.profile_id.as_str())
            == Some(id);
        clear_profile_key_inner(dir, id)?;
        if was_applied {
            lifecycle.bump_generation();
            let mut st = lock(state);
            st.stop_proxy();
        }
        Ok(())
    })
}

fn delete_profile_cmd(
    dir: &Path,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    id: &str,
) -> Result<(), String> {
    lifecycle.with_serialized(|| {
        let cfg = load_without_runtime_transaction(dir)?;
        let was_applied = cfg
            .runtime_binding
            .as_ref()
            .map(|binding| binding.profile_id.as_str())
            == Some(id);
        delete_profile_inner(dir, id)?;
        if was_applied {
            lifecycle.bump_generation();
            let mut st = lock(state);
            st.stop_proxy();
        }
        Ok(())
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_profile_connection(
    app: tauri::AppHandle,
    lifecycle: State<'_, SharedLifecycle>,
    id: String,
    base_url: Option<String>,
    api_format: Option<String>,
    model: Option<String>,
    key: Option<String>,
    model_catalog: Option<Vec<crate::model_catalog::ModelRoute>>,
    default_model_route_id: Option<String>,
    role_bindings: Option<crate::model_catalog::RoleBindings>,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let lifecycle = lifecycle.inner().clone();
    run_blocking_typed(move || {
        update_profile_connection_inner_cmd(
            app,
            lifecycle,
            id,
            base_url,
            api_format,
            model,
            key,
            model_catalog,
            default_model_route_id,
            role_bindings,
        )
    })
    .await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn validate_profile_catalog_model(
    app: tauri::AppHandle,
    lifecycle: State<'_, SharedLifecycle>,
    id: String,
    model_reference: String,
    base_url: Option<String>,
    key: Option<String>,
    model_catalog: Vec<crate::model_catalog::ModelRoute>,
    role_bindings: crate::model_catalog::RoleBindings,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let lifecycle = lifecycle.inner().clone();
    run_blocking_typed(move || {
        lifecycle.with_serialized(|| {
            let cfg =
                config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
            let mut candidate = cfg
                .profile_by_id(&id)
                .cloned()
                .ok_or_else(|| format!("找不到 profile：{id}"))?;
            if candidate.model_policy != crate::provider_contracts::ModelPolicy::SavedCatalog {
                return Err(crate::commands::RuntimeCommandError::from(
                    "当前目录模式不支持静态逐模型验证".to_string(),
                ));
            }
            ConnectionEdit::new(base_url, None, None, key)
                .with_catalog(Some(CatalogEdit {
                    routes: model_catalog,
                    default_model_route_id: model_reference,
                    role_bindings,
                }))
                .apply(&mut candidate)?;
            let validated = scratch_validate_candidate(&app, &candidate)?;
            Ok(json!({
                "validated": validated,
                "status": if validated { "ok" } else { "unknown" },
                "message": if validated {
                    "该模型已通过隔离 scratch 请求验证。"
                } else {
                    "未能确认该模型；未修改配置。"
                },
            }))
        })
    })
    .await
}

#[allow(clippy::too_many_arguments)]
fn update_profile_connection_inner_cmd(
    app: tauri::AppHandle,
    lifecycle: SharedLifecycle,
    id: String,
    base_url: Option<String>,
    api_format: Option<String>,
    model: Option<String>,
    key: Option<String>,
    model_catalog: Option<Vec<crate::model_catalog::ModelRoute>>,
    default_model_route_id: Option<String>,
    role_bindings: Option<crate::model_catalog::RoleBindings>,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let catalog_edit = catalog_edit_from_parts(
        model.is_some(),
        model_catalog,
        default_model_route_id,
        role_bindings,
    )
    .map_err(crate::commands::RuntimeCommandError::from)?;
    lifecycle
        .with_serialized(|| -> Result<_, String> {
            let dir = config::default_dir();
            let cfg = load_without_runtime_transaction(&dir)?;
            // 未命中 id → Err（不静默 Ok）。
            let mut candidate = cfg
                .profile_by_id(&id)
                .cloned()
                .ok_or_else(|| format!("找不到 profile：{id}"))?;
            // 生效【后】的候选连接（None=不改则沿用旧值），active/非 active 共用一份。
            let edit = ConnectionEdit::new(
                base_url.clone(),
                api_format.clone(),
                model.clone(),
                key.clone(),
            )
            .with_catalog(catalog_edit.clone());
            edit.apply(&mut candidate)?;
            let resolved = resolve_launch_plan(&candidate)?;
            reject_openai_custom_anthropic_base(&resolved.adapter, &candidate.base_url)?;
            // 保存前守卫（修 P2）：relay/自定义端点清空 base_url → 不可用连接（激活必失败）。
            // 校验生效后的 base_url，空则拒绝落盘、绝不谎报「已保存」；native 走硬编码端点，空无妨。
            if resolved.endpoint_policy
                == crate::provider_contracts::EndpointPolicy::ProfileRequired
                && candidate.base_url.trim().is_empty()
            {
                return Err(
                    "中转 / 自定义端点必须填写连接地址（base_url），连接未保存。".to_string(),
                );
            }
            // 保存前守卫（修 #9 P1-a）：relay/自定义端点空 model → 无 force → 退回 passthrough（显示 claude）。
            if resolved.model_policy == crate::provider_contracts::ModelPolicy::SavedCatalog
                && candidate.model.trim().is_empty()
            {
                return Err("中转 / 自定义端点必须选择或填写一个模型，连接未保存。".to_string());
            }
            // Saving a connection never applies it. Scratch validation remains
            // isolated and one-click is the only runtime apply/start boundary.
            let validated = scratch_validate_candidate(&app, &candidate)?;
            persist_profile_candidate_inner(&dir, &id, &candidate)?;
            Ok(json!({
                "validated": validated,
                "committed": true,
                "status": "ok",
                "message": "已保存连接；下次一键开始时核验并应用。",
            }))
        })
        .map_err(crate::commands::RuntimeCommandError::from)
}

/// 只把 profile 设为当前选择；真正 apply/start 只发生在一键开始。
#[tauri::command]
pub(crate) async fn set_active_profile(
    state: State<'_, SharedAppState>,
    lifecycle: State<'_, SharedLifecycle>,
    id: String,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking_typed(move || set_active_profile_inner_cmd(state, lifecycle, id)).await
}

fn set_active_profile_inner_cmd(
    state: SharedAppState,
    lifecycle: SharedLifecycle,
    id: String,
) -> Result<serde_json::Value, crate::commands::RuntimeCommandError> {
    lifecycle
        .with_serialized(|| pin_active_profile_in_dir(&config::default_dir(), &state, &id))
        .map_err(crate::commands::RuntimeCommandError::from)
}

fn pin_active_profile_in_dir(
    dir: &Path,
    state: &SharedAppState,
    id: &str,
) -> Result<serde_json::Value, String> {
    let applied_profile_id = config::update_result(dir, |cfg| {
        config::require_no_runtime_transaction(cfg)?;
        let profile = cfg
            .profile_by_id(id)
            .ok_or_else(|| format!("找不到 profile：{id}"))?;
        // This is local structural validation only. It must not read auth,
        // probe upstreams, or mutate either managed runtime.
        resolve_launch_plan(profile)?;
        let applied = cfg
            .runtime_binding
            .as_ref()
            .map(|binding| binding.profile_id.clone());
        let changed = cfg.active_id != id;
        cfg.active_id = id.to_string();
        Ok((applied, changed))
    })?;

    let science_running = {
        let app_state = crate::lock(state);
        app_state.sandbox.is_some() || app_state.science_runtime.is_some()
    };
    let hint = if science_running {
        "已设为当前选择，待应用。当前运行链和 Science 会话保持不变；下次一键开始时核验并应用。"
    } else {
        "已设为当前选择，待应用。当前运行链保持不变；下次一键开始时核验并应用。"
    };
    Ok(json!({
        "committed": true,
        "status": "ok",
        "selected_profile_id": id,
        "applied_profile_id": applied_profile_id,
        "apply_state": "pending",
        "science_running": science_running,
        "hint": hint,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        catalog_edit_from_parts, clear_profile_key_cmd, delete_profile_cmd,
        persist_profile_candidate_inner, pin_active_profile_in_dir, require_preview_fingerprint,
    };
    use crate::{
        config::{self, Config, Profile, RuntimeBindingCommit, RuntimeTransactionJournal},
        lifecycle, lock, AppState, SharedAppState,
    };
    use std::{
        fs,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("csswitch-{name}-{n}"))
    }

    fn profile(id: &str, key: &str) -> Profile {
        let (model_catalog, default_model_route_id, role_bindings) =
            crate::model_catalog::new_profile_catalog("deepseek", "anthropic", None).unwrap();
        let model = model_catalog
            .iter()
            .find(|route| route.selector_id == default_model_route_id)
            .unwrap()
            .upstream_model
            .clone();
        Profile {
            id: id.into(),
            name: id.into(),
            template_id: "deepseek".into(),
            category: "cn_official".into(),
            api_format: "anthropic".into(),
            base_url: "https://api.deepseek.com/anthropic".into(),
            api_key: key.into(),
            model,
            model_catalog,
            default_model_route_id,
            role_bindings,
            model_policy: crate::provider_contracts::ModelPolicy::SavedCatalog,
            ..Default::default()
        }
    }

    fn state_with_proxy_identity() -> SharedAppState {
        let mut state = AppState::default();
        state.secret = "runtime-secret".into();
        state.provider = "deepseek".into();
        state.gateway_kind = "rust".into();
        state.shim_mode = "off".into();
        state.launch_id = "launch-current".into();
        state.key_fp = 42;
        Arc::new(Mutex::new(state))
    }

    fn binding(profile_id: &str) -> RuntimeBindingCommit {
        RuntimeBindingCommit {
            profile_id: profile_id.into(),
            route_fp: "route".into(),
            catalog_fp: "catalog".into(),
            binding_fp: "binding".into(),
        }
    }

    #[test]
    fn clear_active_profile_key_stops_runtime_proxy_identity() {
        let dir = tmpdir("clear-active-key");
        let cfg = Config {
            profiles: vec![profile("active", "sk-active")],
            active_id: "active".into(),
            runtime_binding: Some(binding("active")),
            ..Default::default()
        };
        config::save_to(&dir, &cfg).unwrap();
        let state = state_with_proxy_identity();
        let lifecycle = lifecycle::Lifecycle::new();
        let before = lifecycle.current_generation();

        clear_profile_key_cmd(&dir, &state, &lifecycle, "active").unwrap();

        let after = config::load_from(&dir).unwrap();
        assert_eq!(after.profile_by_id("active").unwrap().api_key, "");
        assert!(after.runtime_binding.is_none());
        assert!(lifecycle.current_generation() > before);
        let st = lock(&state);
        assert!(st.secret.is_empty());
        assert!(st.provider.is_empty());
        assert!(st.gateway_kind.is_empty());
        assert!(st.shim_mode.is_empty());
        assert!(st.launch_id.is_empty());
        assert_eq!(st.key_fp, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_non_active_profile_key_leaves_runtime_proxy_identity() {
        let dir = tmpdir("clear-non-active-key");
        let cfg = Config {
            profiles: vec![profile("active", "sk-active"), profile("other", "sk-other")],
            active_id: "other".into(),
            runtime_binding: Some(binding("active")),
            ..Default::default()
        };
        config::save_to(&dir, &cfg).unwrap();
        let state = state_with_proxy_identity();
        let lifecycle = lifecycle::Lifecycle::new();
        let before = lifecycle.current_generation();

        clear_profile_key_cmd(&dir, &state, &lifecycle, "other").unwrap();

        let after = config::load_from(&dir).unwrap();
        assert_eq!(after.profile_by_id("other").unwrap().api_key, "");
        assert_eq!(lifecycle.current_generation(), before);
        let st = lock(&state);
        assert_eq!(st.secret, "runtime-secret");
        assert_eq!(st.provider, "deepseek");
        assert_eq!(st.gateway_kind, "rust");
        assert_eq!(st.shim_mode, "off");
        assert_eq!(st.launch_id, "launch-current");
        assert_eq!(st.key_fp, 42);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_active_profile_stops_runtime_proxy_identity() {
        let dir = tmpdir("delete-active-profile");
        let cfg = Config {
            profiles: vec![profile("active", "sk-active")],
            active_id: "active".into(),
            runtime_binding: Some(binding("active")),
            ..Default::default()
        };
        config::save_to(&dir, &cfg).unwrap();
        let state = state_with_proxy_identity();
        let lifecycle = lifecycle::Lifecycle::new();
        let before = lifecycle.current_generation();

        delete_profile_cmd(&dir, &state, &lifecycle, "active").unwrap();

        let after = config::load_from(&dir).unwrap();
        assert!(after.active_id.is_empty());
        assert!(after.profile_by_id("active").is_none());
        assert!(after.runtime_binding.is_none());
        assert!(lifecycle.current_generation() > before);
        let st = lock(&state);
        assert!(st.secret.is_empty());
        assert!(st.provider.is_empty());
        assert!(st.gateway_kind.is_empty());
        assert!(st.shim_mode.is_empty());
        assert!(st.launch_id.is_empty());
        assert_eq!(st.key_fp, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pin_changes_only_active_id_and_preserves_applied_and_in_memory_runtime() {
        let dir = tmpdir("pin-only");
        let binding = binding("active");
        let cfg = Config {
            profiles: vec![profile("active", "sk-active"), profile("next", "sk-next")],
            active_id: "active".into(),
            runtime_binding: Some(binding.clone()),
            ..Default::default()
        };
        config::save_to(&dir, &cfg).unwrap();
        let state = state_with_proxy_identity();
        lock(&state).boot_attention = Some(serde_json::json!({"status": "keep"}));

        let result = pin_active_profile_in_dir(&dir, &state, "next").unwrap();

        let after = config::load_from(&dir).unwrap();
        let mut expected = cfg.clone();
        expected.active_id = "next".into();
        assert_eq!(after, expected);
        assert_eq!(after.runtime_binding, Some(binding));
        assert!(after.runtime_transaction.is_none());
        assert_eq!(result["selected_profile_id"], "next");
        assert_eq!(result["applied_profile_id"], "active");
        assert_eq!(result["apply_state"], "pending");
        assert_eq!(result["science_running"], false);
        let st = lock(&state);
        assert_eq!(st.secret, "runtime-secret");
        assert_eq!(st.provider, "deepseek");
        assert_eq!(st.gateway_kind, "rust");
        assert_eq!(st.launch_id, "launch-current");
        assert_eq!(
            st.boot_attention,
            Some(serde_json::json!({"status": "keep"}))
        );
        assert!(st.sandbox.is_none());
        assert!(st.science_runtime.is_none());
        drop(st);

        config::update(&dir, |cfg| {
            cfg.profile_by_id_mut("active").unwrap().api_key = "sk-edited".into();
        })
        .unwrap();
        let result = pin_active_profile_in_dir(&dir, &state, "active").unwrap();
        assert_eq!(result["selected_profile_id"], "active");
        assert_eq!(result["applied_profile_id"], "active");
        assert_eq!(result["apply_state"], "pending");
        assert_eq!(
            config::load_from(&dir)
                .unwrap()
                .profile_by_id("active")
                .unwrap()
                .api_key,
            "sk-edited"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_selected_and_applied_profiles_use_runtime_binding_truth() {
        let dir = tmpdir("delete-selected-vs-applied");
        let cfg = Config {
            profiles: vec![profile("applied", "sk-a"), profile("selected", "sk-b")],
            active_id: "selected".into(),
            runtime_binding: Some(binding("applied")),
            ..Default::default()
        };
        config::save_to(&dir, &cfg).unwrap();
        let state = state_with_proxy_identity();
        let lifecycle = lifecycle::Lifecycle::new();
        let before = lifecycle.current_generation();

        delete_profile_cmd(&dir, &state, &lifecycle, "selected").unwrap();
        let after_selected = config::load_from(&dir).unwrap();
        assert!(after_selected.active_id.is_empty());
        assert_eq!(
            after_selected
                .runtime_binding
                .as_ref()
                .map(|b| b.profile_id.as_str()),
            Some("applied")
        );
        assert_eq!(lifecycle.current_generation(), before);
        assert_eq!(lock(&state).launch_id, "launch-current");

        delete_profile_cmd(&dir, &state, &lifecycle, "applied").unwrap();
        let after_applied = config::load_from(&dir).unwrap();
        assert!(after_applied.runtime_binding.is_none());
        assert!(lifecycle.current_generation() > before);
        assert!(lock(&state).launch_id.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pin_rejects_transaction_unknown_disabled_and_invalid_without_writes() {
        for (label, cfg, id) in [
            (
                "transaction",
                Config {
                    profiles: vec![profile("active", "sk-active"), profile("next", "sk-next")],
                    active_id: "active".into(),
                    runtime_transaction: Some(RuntimeTransactionJournal {
                        transaction_id: "txn".into(),
                        target_profile_id: "next".into(),
                        stage: "prepare".into(),
                        previous_binding: None,
                        previous_gateway: None,
                    }),
                    ..Default::default()
                },
                "next",
            ),
            (
                "unknown",
                Config {
                    profiles: vec![profile("active", "sk-active")],
                    active_id: "active".into(),
                    ..Default::default()
                },
                "missing",
            ),
        ] {
            let dir = tmpdir(&format!("pin-reject-{label}"));
            config::save_to(&dir, &cfg).unwrap();
            let before = fs::read(dir.join("config.json")).unwrap();
            let state = state_with_proxy_identity();
            assert!(
                pin_active_profile_in_dir(&dir, &state, id).is_err(),
                "{label} must fail closed"
            );
            assert_eq!(
                fs::read(dir.join("config.json")).unwrap(),
                before,
                "{label}"
            );
            assert_eq!(config::load_from(&dir).unwrap(), cfg, "{label}");
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn transaction_journal_blocks_clear_delete_and_candidate_persist_without_side_effects() {
        let dir = tmpdir("profile-mutations-txn-guard");
        let journal = RuntimeTransactionJournal {
            transaction_id: "txn".into(),
            target_profile_id: "selected".into(),
            stage: "prepare".into(),
            previous_binding: Some(binding("applied")),
            previous_gateway: None,
        };
        let cfg = Config {
            profiles: vec![profile("applied", "sk-a"), profile("selected", "sk-b")],
            active_id: "selected".into(),
            runtime_binding: Some(binding("applied")),
            runtime_transaction: Some(journal),
            ..Default::default()
        };
        config::save_to(&dir, &cfg).unwrap();
        let backup_path = dir.join("config.json.bak");
        fs::write(&backup_path, b"unique-existing-backup").unwrap();
        let state = state_with_proxy_identity();
        let lifecycle = lifecycle::Lifecycle::new();
        let generation = lifecycle.current_generation();
        let before = fs::read(dir.join("config.json")).unwrap();
        let backup_before = fs::read(&backup_path).unwrap();

        for error in [
            clear_profile_key_cmd(&dir, &state, &lifecycle, "applied").unwrap_err(),
            delete_profile_cmd(&dir, &state, &lifecycle, "selected").unwrap_err(),
        ] {
            assert!(error.contains("code=runtime_transaction_in_progress"));
            assert_eq!(fs::read(dir.join("config.json")).unwrap(), before);
            assert_eq!(fs::read(&backup_path).unwrap(), backup_before);
            assert_eq!(lifecycle.current_generation(), generation);
            assert_eq!(lock(&state).launch_id, "launch-current");
        }

        let mut candidate = cfg.profile_by_id("selected").unwrap().clone();
        candidate.api_key = "sk-edited".into();
        let error = persist_profile_candidate_inner(&dir, "selected", &candidate).unwrap_err();
        assert!(error.contains("code=runtime_transaction_in_progress"));
        assert_eq!(fs::read(dir.join("config.json")).unwrap(), before);
        assert_eq!(fs::read(&backup_path).unwrap(), backup_before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pin_rejects_invalid_local_structure_without_rewriting_it() {
        let dir = tmpdir("pin-invalid-structure");
        let cfg = Config {
            profiles: vec![profile("invalid", "sk-invalid")],
            ..Default::default()
        };
        config::save_to(&dir, &cfg).unwrap();
        let path = dir.join("config.json");
        let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw["profiles"][0]["credential_ref"] = serde_json::json!("not-allowed");
        fs::write(&path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();
        let before = fs::read(&path).unwrap();
        let state = state_with_proxy_identity();

        assert!(pin_active_profile_in_dir(&dir, &state, "invalid").is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn catalog_edit_requires_all_three_fields_and_rejects_legacy_mix() {
        let route = crate::model_catalog::ModelRoute {
            selector_id: "claude-csswitch-test-model-123456789abc".into(),
            display_name: "Model".into(),
            upstream_model: "model-upstream".into(),
            supports_tools: Some(true),
            ..Default::default()
        };
        let roles = crate::model_catalog::RoleBindings {
            sonnet: route.selector_id.clone(),
            opus: route.selector_id.clone(),
            haiku: route.selector_id.clone(),
            fable: route.selector_id.clone(),
            ..Default::default()
        };
        assert!(catalog_edit_from_parts(false, None, None, None)
            .unwrap()
            .is_none());
        assert!(catalog_edit_from_parts(
            false,
            Some(vec![route.clone()]),
            Some(route.selector_id.clone()),
            Some(roles.clone()),
        )
        .unwrap()
        .is_some());
        assert!(catalog_edit_from_parts(false, Some(vec![route.clone()]), None, None).is_err());
        assert!(catalog_edit_from_parts(
            true,
            Some(vec![route]),
            Some("claude-csswitch-test-model-123456789abc".into()),
            Some(roles),
        )
        .is_err());
    }

    #[test]
    fn stale_preset_preview_fingerprint_is_rejected() {
        let preview = serde_json::json!({ "preview_fingerprint": "fingerprint-a" });
        assert!(require_preview_fingerprint(&preview, "fingerprint-a").is_ok());
        assert!(require_preview_fingerprint(&preview, "fingerprint-b").is_err());
        assert!(require_preview_fingerprint(&serde_json::json!({}), "fingerprint-a").is_err());
    }
}
