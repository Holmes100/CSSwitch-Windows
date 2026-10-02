import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../desktop/src/main.js", import.meta.url), "utf8");
const mockInvokeSource = source
  .split("function mockInvoke(cmd, args) {", 2)[1]
  .split("\nconst $ =", 1)[0];

function makeMock() {
  const context = {
    mockStore: {
      schema_version: 4,
      active_id: "a",
      applied_profile_id: "a",
      selection_pending: false,
      proxy_port: 18991,
      sandbox_port: 8990,
      reuse_system_ssh: false,
      experimental_codex_enabled: false,
      codex_network: {},
      codex_network_resolved: {},
      mode: "proxy",
      profiles: [
        { id: "a", name: "A", key: "masked-a" },
        { id: "b", name: "B", key: "masked-b" },
      ],
    },
    MOCK_TEMPLATES: [],
    PREVIEW_SLOW_ACTIVATION: false,
    PREVIEW_BROWSER_FAIL: false,
    PREVIEW_RUNTIME_CACHE: false,
    PREVIEW_CONFIG_REFRESH_FAIL: false,
    PREVIEW_CODEX_NETWORK: false,
    PREVIEW_CODEX_STALE: false,
    PREVIEW_CODEX: false,
    PREVIEW_SKILL_IMPORT_CANCEL: false,
    QUERY: new URLSearchParams(),
    mockImportedSkills: [],
    Promise,
  };
  vm.createContext(context);
  vm.runInContext(`function mockInvoke(cmd, args) {${mockInvokeSource}`, context);
  return context;
}

test("preview pin preserves applied binding until one-click succeeds", async () => {
  const context = makeMock();
  const pin = await context.mockInvoke("set_active_profile", { id: "b" });
  assert.equal(context.mockStore.active_id, "b");
  assert.equal(context.mockStore.applied_profile_id, "a");
  assert.equal(context.mockStore.selection_pending, true);
  assert.equal(pin.applied_profile_id, "a");
  assert.equal(pin.apply_state, "pending");

  await context.mockInvoke("one_click_login", {});
  assert.equal(context.mockStore.applied_profile_id, "b");
  assert.equal(context.mockStore.selection_pending, false);
  const config = await context.mockInvoke("get_config", {});
  assert.equal(config.active_id, "b");
  assert.equal(config.applied_profile_id, "b");
  assert.equal(config.selection_pending, false);
});

test("preview clear and delete remove applied truth only for the applied profile", async () => {
  const clearContext = makeMock();
  await clearContext.mockInvoke("clear_profile_key", { id: "a" });
  assert.equal(clearContext.mockStore.applied_profile_id, null);
  assert.equal(clearContext.mockStore.profiles[0].key, "");

  const deleteContext = makeMock();
  await deleteContext.mockInvoke("delete_profile", { id: "a" });
  assert.equal(deleteContext.mockStore.applied_profile_id, null);
  assert.equal(deleteContext.mockStore.active_id, "");
  assert.equal(deleteContext.mockStore.selection_pending, false);

  const nonAppliedClear = makeMock();
  await nonAppliedClear.mockInvoke("clear_profile_key", { id: "b" });
  assert.equal(nonAppliedClear.mockStore.applied_profile_id, "a");
  assert.equal(nonAppliedClear.mockStore.selection_pending, false);

  const nonAppliedDelete = makeMock();
  await nonAppliedDelete.mockInvoke("delete_profile", { id: "b" });
  assert.equal(nonAppliedDelete.mockStore.applied_profile_id, "a");
  assert.equal(nonAppliedDelete.mockStore.selection_pending, false);
});

test("preview selected edits and preset sync become pending without changing applied", async () => {
  const context = makeMock();
  await context.mockInvoke("update_profile_connection", { id: "a", baseUrl: "https://changed" });
  assert.equal(context.mockStore.applied_profile_id, "a");
  assert.equal(context.mockStore.selection_pending, true);

  context.mockStore.selection_pending = false;
  await context.mockInvoke("apply_profile_preset_sync", { id: "a" });
  assert.equal(context.mockStore.applied_profile_id, "a");
  assert.equal(context.mockStore.selection_pending, true);
});
