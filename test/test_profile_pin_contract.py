import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProfilePinContractTests(unittest.TestCase):
    def test_backend_pin_is_local_and_one_click_remains_the_apply_boundary(self):
        profiles = (ROOT / "desktop/src-tauri/src/commands/profiles.rs").read_text()
        session = (ROOT / "desktop/src-tauri/src/runtime/sandbox_session.rs").read_text()
        pin = profiles.split("fn pin_active_profile_in_dir(", 1)[1].split(
            "\n#[cfg(test)]", 1
        )[0]

        self.assertIn("config::update_result", pin)
        self.assertIn("cfg.active_id = id.to_string()", pin)
        self.assertIn("config::require_no_runtime_transaction(cfg)?", pin)
        config_source = (ROOT / "desktop/src-tauri/src/config.rs").read_text()
        self.assertIn("code=runtime_transaction_in_progress", config_source)
        self.assertIn("resolve_launch_plan(profile)?", pin)
        self.assertIn('"apply_state": "pending"', pin)
        for forbidden in (
            "prepare_provider_auth",
            "scratch_validate_candidate",
            "set_active_profile_txn",
            "start_proxy",
            "stop_proxy",
            "probe_",
            "runtime_binding =",
            "runtime_transaction =",
            "history_recovery",
            "boot_attention",
        ):
            self.assertNotIn(forbidden, pin)

        one_click = session.split("fn one_click_login_with_options", 1)[1]
        self.assertIn("commit_runtime_binding(&dir, committed)", one_click)
        preset = profiles.split("pub(crate) async fn apply_profile_preset_sync", 1)[1].split(
            "// ---------- profile CRUD", 1
        )[0]
        connection = profiles.split("fn update_profile_connection_inner_cmd", 1)[1].split(
            "/// 只把 profile", 1
        )[0]
        self.assertNotIn("set_active_profile_txn", preset + connection)
        self.assertNotIn("cfg.active_id == id", preset + connection)
        self.assertGreaterEqual(preset.count("load_without_runtime_transaction"), 2)
        self.assertLess(
            connection.index("load_without_runtime_transaction"),
            connection.index("prepare_provider_auth"),
        )
        self.assertGreaterEqual(connection.count("load_without_runtime_transaction"), 2)
        self.assertIn("config::require_no_runtime_transaction(cfg)?", profiles)

    def test_ui_activation_has_no_skip_path_and_reports_pending_selection(self):
        js = (ROOT / "desktop/src/main.js").read_text()
        activate = js.split("async function activate(id)", 1)[1].split(
            "\nfunction hideRuntimeChoice", 1
        )[0]
        boundary = js.split("async function checkOneClickBoundary()", 1)[1].split(
            "\nasync function runOneClick", 1
        )[0]

        self.assertIn('call("set_active_profile", { id })', activate)
        self.assertIn("当前选择", activate)
        self.assertIn("待一键开始应用", activate)
        self.assertNotIn("skipVerify", js)
        self.assertNotIn("can_skip", js)
        self.assertNotIn("pendingSkipActivateId", js)
        self.assertIn("当前选择", boundary)
        self.assertIn("当前选择 · 待一键开始应用", js)
        self.assertIn(">上次应用</span>", js)
        command = (ROOT / "desktop/src-tauri/src/commands/profiles.rs").read_text().split(
            "pub(crate) async fn set_active_profile(", 1
        )[1].split("\n}", 1)[0]
        self.assertNotIn("skip_verify", command)
        html = (ROOT / "desktop/src/index.html").read_text()
        self.assertNotIn("skipActivateBtn", html)

    def test_success_keeps_single_finally_busy_ownership_through_refresh(self):
        js = (ROOT / "desktop/src/main.js").read_text()
        run_one_click = js.split("async function runOneClick(runtimeChoice)", 1)[1].split(
            "\nasync function importLocalSkill", 1
        )[0]
        success = run_one_click.split("// 透传后端据实回传的 msg", 1)[1].split(
            "} catch (e)", 1
        )[0]

        self.assertNotIn("setBusy(false)", success)
        finally_block = run_one_click.split("} finally {", 1)[1]
        self.assertLess(finally_block.index("setBusy(false)"), finally_block.index("refreshIfLoaded"))
        self.assertIn("await skillPage?.refreshIfLoaded()", run_one_click)

    def test_skill_and_browser_warnings_preserve_runtime_success(self):
        session = (ROOT / "desktop/src-tauri/src/runtime/sandbox_session.rs").read_text()
        self.assertIn("configure_third_party_best_effort", session)
        self.assertIn("RegistrationStatus::Warning", session)
        self.assertIn("服务已就绪；自动打开失败。", session)
        self.assertIn('"status": "ok"', session)
        self.assertIn('"fallback_url": fallback_url', session)


if __name__ == "__main__":
    unittest.main()
