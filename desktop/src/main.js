import { RUNTIME_STATUS_LABELS, aggregateRuntimeStatus, normalizeRuntimeLight } from "./runtime-status-state.js";
import {
  buildSimpleModelSubmission,
  mergeCatalogCandidates,
  projectSimpleModelFields,
} from "./model-catalog-state.js";

// CSSwitch 桌面面板前端。只调用后端 Tauri command，绝不碰任何密钥落盘逻辑。
// 后端只把 key 的【掩码】回显给这里；完整 key 永不进前端。
//
// ── Tauri 参数键约定（务必遵守）──────────────────────────────────────────────
// 本项目所有命令都是裸 `#[tauri::command]`（无 rename_all）。tauri-macros 默认
// `ArgumentCase::Camel`，会把 Rust 蛇形【顶层参数名】转成 lowerCamelCase 交给 JS：
//   template_id→templateId、base_url→baseUrl、api_format→apiFormat。
// 所以 invoke 顶层 args 用【小驼峰】。而 serde 结构体入参（`req`=FetchModelsReq、
// `cfg`=UiSettings）内部字段按结构体字段名（蛇形）：proxy_port/sandbox_port、
// template_id/base_url/key/profile_id。核对表见任务报告。
//
// 预览兜底：在普通浏览器（没有 Tauri 后端）里打开时用 mockInvoke 返回假数据，
// 让界面能完整渲染。真实 app 里 window.__TAURI__ 存在，走真后端，此兜底不生效。
const PREVIEW = !window.__TAURI__;
const QUERY = new URLSearchParams(window.location.search);
const SKILLS_PREVIEW = PREVIEW && QUERY.get("page") === "skills";
const PROFILE_INTERACTIVE_PREVIEW = PREVIEW && QUERY.get("profile_preview") === "1";
const PREVIEW_SLOW_ACTIVATION = PREVIEW && QUERY.get("activation") === "slow";
const PREVIEW_RUNTIME_CACHE = PREVIEW && QUERY.get("runtime") === "cache";
const PREVIEW_BROWSER_FAIL = PREVIEW && QUERY.get("browser") === "fail";
const invoke = PREVIEW
  ? (cmd, args) => mockInvoke(cmd, args)
  : window.__TAURI__.core.invoke;

// ── 预览兜底 mock（仅浏览器预览用；node --check 只验语法，真实 app 走真后端） ──
const MOCK_DISCOVERABLE_CAPABILITIES = {
  auth_mode: "api_key", credential_source: "api_key",
  base_url_required: true, model_required: true,
  model_discovery: "openai_models_or_manual", supports_thinking_policy: false,
  thinking_policy: "", supports_tools_hint: "translated",
};
const MOCK_TEMPLATES = [
  { id: "deepseek", name: "DeepSeek", category: "cn_official", api_format: "anthropic", adapter: "deepseek", base_url: "https://api.deepseek.com/anthropic", base_url_editable: false, requires_model_override: false, builtin_models: ["claude-opus-4-8", "claude-haiku-4-5"], icon: "deepseek", icon_color: "#1E88E5", website_url: "https://platform.deepseek.com" },
  { id: "glm", name: "智谱 GLM", category: "cn_official", api_format: "anthropic", adapter: "relay", base_url: "https://open.bigmodel.cn/api/anthropic", base_url_editable: true, requires_model_override: true, builtin_models: ["glm-5.2", "glm-4.7", "glm-4.6", "glm-4.5-air"], icon: "glm", icon_color: "#2E6BE6", website_url: "https://open.bigmodel.cn" },
  { id: "xiaomi", name: "小米 MiMo", category: "cn_official", api_format: "anthropic", adapter: "relay", base_url: "https://api.xiaomimimo.com/anthropic", base_url_editable: true, requires_model_override: true, builtin_models: ["mimo-v2.5-pro"], icon: "xiaomi", icon_color: "#FF6900", website_url: "https://xiaomimimo.com" },
  { id: "siliconflow", name: "硅基流动", category: "cn_official", api_format: "anthropic", adapter: "relay", base_url: "https://api.siliconflow.cn", base_url_editable: true, requires_model_override: true, builtin_models: ["deepseek-ai/DeepSeek-V4-Pro", "deepseek-ai/DeepSeek-V4-Flash", "deepseek-ai/DeepSeek-V3.2", "zai-org/GLM-5.2"], icon: "siliconflow", icon_color: "#7C3AED", website_url: "https://siliconflow.cn" },
  { id: "kimi", name: "Kimi（Moonshot）", category: "cn_official", api_format: "anthropic", adapter: "relay", base_url: "https://api.moonshot.cn/anthropic", base_url_editable: true, requires_model_override: true, builtin_models: ["kimi-k3", "kimi-k2.7-code", "kimi-k2.7-code-highspeed", "kimi-k2.6"], icon: "kimi", icon_color: "#16182F", website_url: "https://platform.moonshot.cn" },
  { id: "minimax", name: "MiniMax", category: "cn_official", api_format: "anthropic", adapter: "relay", base_url: "https://api.minimaxi.com/anthropic", base_url_editable: true, requires_model_override: true, builtin_models: ["MiniMax-M3", "MiniMax-M2.7", "MiniMax-M2.7-highspeed"], icon: "minimax", icon_color: "#E1341E", website_url: "https://platform.minimaxi.com" },
  { id: "openrouter", name: "OpenRouter", category: "custom", api_format: "anthropic", adapter: "relay", base_url: "https://openrouter.ai/api", base_url_editable: true, requires_model_override: true, builtin_models: ["anthropic/claude-sonnet-5", "anthropic/claude-opus-4.8", "anthropic/claude-opus-4.8-fast"], icon: "openrouter", icon_color: "#6467F2", website_url: "https://openrouter.ai" },
  { id: "qwen", name: "通义千问", category: "cn_official", api_format: "openai_chat", adapter: "qwen", base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1", base_url_editable: false, requires_model_override: false, builtin_models: ["qwen3.7-max", "qwen-plus-latest", "qwen-turbo"], icon: "qwen", icon_color: "#615CED", website_url: "https://dashscope.aliyun.com" },
  { id: "opencode-go-openai", name: "OpenCode Go — OpenAI Chat", category: "official", api_format: "openai_chat", adapter: "openai-custom", base_url: "https://opencode.ai/zen/go/v1", base_url_editable: false, requires_model_override: true, builtin_models: [], icon: "custom", icon_color: "#111827", website_url: "https://opencode.ai/docs/zh-cn/go/", compatibility_notice: "0.8.1 limited：图片、厂商 reasoning、原生流式和结构化输出尚未通过兼容门禁。", capabilities: MOCK_DISCOVERABLE_CAPABILITIES },
  { id: "opencode-go-anthropic", name: "OpenCode Go — Anthropic Messages", category: "official", api_format: "anthropic", adapter: "relay", base_url: "https://opencode.ai/zen/go/v1", base_url_editable: false, requires_model_override: true, builtin_models: [], icon: "custom", icon_color: "#111827", website_url: "https://opencode.ai/docs/zh-cn/go/", compatibility_notice: "0.8.1 limited：图片、厂商 reasoning、原生流式和结构化输出尚未通过兼容门禁。", capabilities: { ...MOCK_DISCOVERABLE_CAPABILITIES, model_discovery: "anthropic_models_or_manual", supports_tools_hint: "passthrough" } },
  { id: "grok", name: "Grok（xAI）", category: "official", api_format: "openai_chat", adapter: "openai-custom", base_url: "https://api.x.ai/v1", base_url_editable: false, requires_model_override: true, builtin_models: [], icon: "custom", icon_color: "#111827", website_url: "https://docs.x.ai/developers/rest-api-reference/inference", compatibility_notice: "0.8.1 limited：图片、厂商 reasoning、原生流式和结构化输出尚未通过兼容门禁。", capabilities: MOCK_DISCOVERABLE_CAPABILITIES },
  { id: "gemini", name: "Gemini（OpenAI 兼容）", category: "official", api_format: "openai_chat", adapter: "openai-custom", base_url: "https://generativelanguage.googleapis.com/v1beta/openai", base_url_editable: false, requires_model_override: true, builtin_models: [], icon: "custom", icon_color: "#4285F4", website_url: "https://ai.google.dev/gemini-api/docs/openai", compatibility_notice: "0.8.1 limited：仅实现官方 OpenAI compatibility；图片、厂商 reasoning、原生流式和结构化输出尚未通过。", capabilities: MOCK_DISCOVERABLE_CAPABILITIES },
  { id: "custom-openai", name: "自定义 OpenAI", category: "custom", api_format: "openai_chat", adapter: "openai-custom", base_url: "", base_url_editable: true, requires_model_override: true, builtin_models: [], icon: "custom", icon_color: "#2563EB", website_url: "" },
  { id: "custom-openai-responses", name: "自定义 OpenAI Responses", category: "custom", api_format: "openai_responses", adapter: "openai-responses", base_url: "", base_url_editable: true, requires_model_override: true, builtin_models: [], icon: "custom", icon_color: "#0F766E", website_url: "" },
  { id: "custom", name: "自定义 Anthropic", category: "custom", api_format: "anthropic", adapter: "relay", base_url: "", base_url_editable: true, requires_model_override: true, builtin_models: [], icon: "custom", icon_color: "#6B7280", website_url: "" },
];
for (const template of MOCK_TEMPLATES) {
  if (!template.recommended_catalog && template.builtin_models?.length) {
    template.preset_catalog_id = template.id;
    template.model_catalog_source = "preset";
    template.recommended_catalog = template.builtin_models.map((id) => ({
      selector_id: "", display_name: id, upstream_model: id, supports_tools: null,
    }));
    template.recommended_default_model_route_id = template.builtin_models[0];
    template.recommended_role_bindings = {
      sonnet: template.builtin_models[0], opus: template.builtin_models[0],
      haiku: template.builtin_models.at(-1), fable: template.builtin_models[0],
    };
  }
}
const mockStore = {
  schema_version: 3,
  active_id: "",
  applied_profile_id: "",
  selection_pending: false,
  proxy_port: 18991,
  sandbox_port: 8990,
  reuse_system_ssh: false,
  mode: "proxy",
  // 打包交付不留任何演示 provider 配置（含虚构 key 占位）；mock 模式从空列表开始。
  profiles: [],
};
const MOCK_SKILLS = [
  { skill_id: "csswitch-external-skill-tools", display_name: "CSSwitch external Skill tools", description: "外部 Skill 安装与卸载的 CSSwitch 系统路由。", source_kind: "csswitch_system", bundle_name: null, attachment_state: "attached" },
  { skill_id: "internal-comms", display_name: "Internal communications", description: "从 GitHub 安装的团队沟通写作 Skill。", source_kind: "csswitch_github", bundle_name: null, attachment_state: "attached" },
  { skill_id: "research-workflow", display_name: "Research workflow", description: "从本地 Skill 包导入的研究流程。", source_kind: "csswitch_local", bundle_name: "research-kit", attachment_state: "detached" },
  { skill_id: "pdf", display_name: "PDF", description: "当前 Science 组织中发现的文档处理 Skill。", source_kind: "science_local", bundle_name: null, attachment_state: "attached" },
  { skill_id: "legacy-notes", display_name: "Legacy notes", description: "来源标记不完整，因此 CSSwitch 不推断分发方。", source_kind: "unverified", bundle_name: null, attachment_state: "detached" },
];
const mockImportedSkills = [];
function mockSkillListEnvelope() {
  const scenario = QUERY.get("skills") || "healthy";
  const stopped = scenario === "stopped";
  const unverified = scenario === "unverified";
  const empty = scenario === "empty";
  const items = empty ? [] : [...MOCK_SKILLS, ...mockImportedSkills].map((item) => ({
    ...item,
    attachment_state: stopped || unverified ? "unknown" : item.attachment_state,
  }));
  return {
    schema_version: 1,
    science_state: stopped ? "stopped" : unverified ? "unverified" : "running_healthy",
    active_org_state: "ready",
    attachment_readback: stopped ? "unavailable" : unverified ? "failed" : "verified",
    agent_name: "OPERON",
    items,
    warnings: scenario === "warning" ? [{ code: "SKILL_SOURCE_UNVERIFIED", skill_id: "legacy-notes", message: "一个 Skill 的来源标记无法验证" }] : [],
  };
}
function mockMask(k) { return k ? "••••" + String(k).slice(-4) : ""; }
function mockInvoke(cmd, args) {
  args = args || {};
  switch (cmd) {
    case "get_config":
      return Promise.resolve({
        schema_version: mockStore.schema_version, active_id: mockStore.active_id,
        applied_profile_id: mockStore.applied_profile_id,
        selection_pending: mockStore.selection_pending,
        proxy_port: mockStore.proxy_port, sandbox_port: mockStore.sandbox_port,
        reuse_system_ssh: mockStore.reuse_system_ssh,
        mode: mockStore.mode, templates: MOCK_TEMPLATES,
        profiles: mockStore.profiles.map((p) => {
          const template = MOCK_TEMPLATES.find((item) => item.id === p.template_id) || {};
          const modelCatalog = p.model_catalog || (template.recommended_catalog || []).map((route) => ({ ...route }));
          return {
            ...p,
            model_catalog: modelCatalog,
            model_count: modelCatalog.length,
            default_model_route_id: p.default_model_route_id || p.model || modelCatalog[0]?.upstream_model || "",
            role_bindings: p.role_bindings || { ...(template.recommended_role_bindings || {}) },
          };
        }),
      });
    case "list_templates":
      return Promise.resolve(MOCK_TEMPLATES);
    case "create_profile": {
      const t = MOCK_TEMPLATES.find((x) => x.id === args.templateId) || {};
      const id = "p-" + Math.random().toString(16).slice(2, 10);
      mockStore.profiles.push({
        id, name: args.name || t.name || "新配置", template_id: args.templateId,
        category: t.category || "custom", api_format: t.api_format || "anthropic",
        base_url: args.baseUrl || t.base_url || "", model: args.model || args.modelCatalog?.[0]?.upstream_model || "",
        model_catalog: (args.modelCatalog || t.recommended_catalog || []).map((route) => ({ ...route })),
        default_model_route_id: args.defaultModelRouteId || args.model || "",
        role_bindings: args.roleBindings || { ...(t.recommended_role_bindings || {}) },
        key: mockMask(args.key || ""), model_options: [...(t.builtin_models || [])], icon: t.icon, icon_color: t.icon_color,
        website_url: t.website_url, sort_index: mockStore.profiles.length + 1, notes: "",
      });
      return Promise.resolve(id);
    }
    case "update_profile_metadata": {
      const p = mockStore.profiles.find((x) => x.id === args.id);
      if (!p) return Promise.reject("找不到 profile：" + args.id);
      p.name = args.name; p.notes = args.notes || "";
      return Promise.resolve(null);
    }
    case "update_profile_connection": {
      const p = mockStore.profiles.find((x) => x.id === args.id);
      if (!p) return Promise.reject("找不到 profile：" + args.id);
      if (args.baseUrl != null) p.base_url = args.baseUrl;
      if (args.model != null) p.model = args.model;
      if (args.modelCatalog) {
        p.model_catalog = args.modelCatalog.map((route) => ({ ...route }));
        p.default_model_route_id = args.defaultModelRouteId;
        p.role_bindings = { ...args.roleBindings };
        const selected = p.model_catalog.find((route) => route.selector_id === args.defaultModelRouteId || route.upstream_model === args.defaultModelRouteId);
        p.model = selected?.upstream_model || p.model_catalog[0]?.upstream_model || "";
      }
      if (args.key) p.key = mockMask(args.key);
      if (mockStore.active_id === args.id) mockStore.selection_pending = true;
      return Promise.resolve({ validated: true });
    }
    case "clear_profile_key": {
      const p = mockStore.profiles.find((x) => x.id === args.id);
      if (p) p.key = "";
      if (mockStore.applied_profile_id === args.id) {
        mockStore.applied_profile_id = null;
        mockStore.selection_pending = !!mockStore.active_id;
      } else if (mockStore.active_id === args.id) {
        mockStore.selection_pending = true;
      }
      return Promise.resolve(null);
    }
    case "delete_profile":
      mockStore.profiles = mockStore.profiles.filter((x) => x.id !== args.id);
      if (mockStore.active_id === args.id) mockStore.active_id = "";
      if (mockStore.applied_profile_id === args.id) mockStore.applied_profile_id = null;
      mockStore.selection_pending = !!mockStore.active_id &&
        mockStore.active_id !== mockStore.applied_profile_id;
      return Promise.resolve(null);
    case "set_active_profile": {
      const p = mockStore.profiles.find((x) => x.id === args.id);
      if (!p) return Promise.reject("找不到 profile：" + args.id);
      const commit = () => {
        mockStore.active_id = args.id;
        mockStore.selection_pending = true;
        return {
          committed: true,
          status: "ok",
          selected_profile_id: args.id,
          applied_profile_id: mockStore.applied_profile_id,
          apply_state: "pending",
          science_running: false,
          hint: "（预览：已设为当前选择，待一键开始应用）",
        };
      };
      return PREVIEW_SLOW_ACTIVATION
        ? new Promise((resolve) => setTimeout(() => resolve(commit()), 1200))
        : Promise.resolve(commit());
    }
    case "fetch_models":
      if (args.req && args.req.template_id === "opencode-go-openai") {
        return Promise.resolve({ models: [{ id: "kimi-k3", display_name: "Kimi K3", supports_tools: true, origin: "discovered", availability: "available", route_known: true }, { id: "deepseek-v4-pro", display_name: "DeepSeek V4 Pro", supports_tools: true, origin: "discovered", availability: "available", route_known: true }], source: "live", error_kind: null, upstream_status: 200, filtered_unknown_count: 1, route_catalog: { schema_version: 1, transport: "openai_chat" } });
      }
      if (args.req && args.req.template_id === "opencode-go-anthropic") {
        return Promise.resolve({ models: [{ id: "minimax-m3", display_name: "MiniMax M3", supports_tools: true, origin: "discovered", availability: "available", route_known: true }, { id: "qwen3.7-max", display_name: "Qwen 3.7 Max", supports_tools: true, origin: "discovered", availability: "available", route_known: true }], source: "live", error_kind: null, upstream_status: 200, filtered_unknown_count: 1, route_catalog: { schema_version: 1, transport: "anthropic" } });
      }
      return Promise.resolve({ models: [{ id: "provider-model", display_name: "Provider model", supports_tools: true, origin: "discovered", availability: "available" }], source: "live", error_kind: null, upstream_status: 200 });
    case "preview_profile_preset_sync": {
      const p = mockStore.profiles.find((x) => x.id === args.id);
      const t = MOCK_TEMPLATES.find((x) => x.id === p?.template_id);
      if (!p || !t?.recommended_catalog) return Promise.reject("该配置没有推荐目录");
      return Promise.resolve({
        profile_id: p.id, preset_catalog_id: t.id,
        additions: t.recommended_catalog.map((r) => r.upstream_model).filter((id) => !(p.model_catalog || []).some((r) => r.upstream_model === id)),
        removals: (p.model_catalog || []).map((r) => r.upstream_model).filter((id) => !t.recommended_catalog.some((r) => r.upstream_model === id)),
        model_catalog: t.recommended_catalog.map((r) => ({ ...r })),
        default_model_route_id: t.recommended_default_model_route_id,
        role_bindings: { ...t.recommended_role_bindings },
        preview_fingerprint: "a".repeat(64), requires_confirmation: true,
      });
    }
    case "apply_profile_preset_sync":
      if (mockStore.active_id === args.id) mockStore.selection_pending = true;
      return Promise.resolve({ committed: true, status: "ok", message: "已同步最新推荐。" });
    case "validate_profile_catalog_model":
      return Promise.resolve({ validated: true, status: "ok", message: "该模型已通过隔离 scratch 请求验证。" });
    case "set_settings":
      if (args.cfg) {
        mockStore.proxy_port = args.cfg.proxy_port;
        mockStore.sandbox_port = args.cfg.sandbox_port;
        mockStore.reuse_system_ssh = !!args.cfg.reuse_system_ssh;
      }
      return Promise.resolve(null);
    case "set_mode":
      mockStore.mode = args.mode;
      return Promise.resolve(null);
    case "one_click_login":
      mockStore.applied_profile_id = mockStore.active_id || null;
      mockStore.selection_pending = false;
      return Promise.resolve(PREVIEW_BROWSER_FAIL
        ? {
            msg: "（预览模式：服务已就绪；自动打开失败。）",
            action: "started", stage: "complete", status: "ok", recovery_status: "not_needed",
            fallback_url: "http://127.0.0.1:8990/?nonce=preview-fallback",
          }
        : { msg: "（预览模式：假装已就绪）", action: "started", stage: "complete", status: "ok", recovery_status: "not_needed", fallback_url: null });
    case "science_runtime_preflight":
      return Promise.resolve(PREVIEW_RUNTIME_CACHE
        ? { status: "cached_choice_required", selected_source: null, selected_version: null, cached_version: "0.0.0-preview-cache", download_url: "https://claude.com/download" }
        : { status: "installed_ready", selected_source: "installed_app", selected_version: "0.0.0-preview", cached_version: null, download_url: "https://claude.com/download" });
    case "install_local_skill_package":
      if (!mockImportedSkills.some((item) => item.skill_id === "demo-reader")) {
        mockImportedSkills.push({ skill_id: "demo-reader", display_name: "Demo reader", description: "刚刚从本地包导入的示例 Skill。", source_kind: "csswitch_local", bundle_name: "demo-bundle", attachment_state: "attached" });
      }
      return Promise.resolve({ schema_version: 2, status: "BUNDLE_INSTALLED_ATTACHED", package_kind: "bundle", bundle_name: "demo-bundle", skill_names: ["demo-reader"], attach_verified: true, directory_commit: true, message: "bundle 文件已安装并绑定 OPERON。" });
    case "list_installed_skills":
      if (QUERY.get("skills") === "error") return Promise.reject("预览注入：Skill 列表读取失败");
      return Promise.resolve(mockSkillListEnvelope());
    case "open_science_download_page":
      return Promise.resolve(null);
    case "status":
      if (QUERY.get("status") === "error") return Promise.reject(new Error("预览注入：运行状态查询失败"));
      if (QUERY.get("status") === "partial") return Promise.resolve({ proxy: "green", sandbox: "green", upstream: "amber" });
      if (QUERY.get("status") === "stopped") return Promise.resolve({ proxy: "amber", sandbox: "amber", upstream: "amber" });
      return Promise.resolve({ proxy: "green", sandbox: "green", upstream: "green" });
    case "boot_error":
      return Promise.resolve(null);
    case "app_version":
      return Promise.resolve("0.0.0-preview");
    case "run_doctor":
      return Promise.resolve("（预览模式：后端未运行，这里是占位文本）");
    default:
      return Promise.resolve(null);
  }
}

const $ = (id) => document.getElementById(id);
const els = {};
let statusTimer = null;
let busy = false;
let busyOp = null;
let activationInFlight = false;
let activationOp = null;
let busyMsgTimers = [];
let browserOpenInFlight = false;
let doctorInFlight = false;
let statusRecoveryMsg = "";
let skillPage = null;
let runtimeChoiceActiveId = null;
let mode = "proxy"; // "proxy" 第三方 | "official" 官方
let officialRuntimeState = "gray";
// 当前配置快照（get_config 结果）。全 key 绝不在此，只有掩码。
let configState = { profiles: [], templates: [], active_id: "", applied_profile_id: null, selection_pending: false, proxy_port: 18991, sandbox_port: 8990, reuse_system_ssh: false };
let pendingConfirm = null;          // 危险操作（清 key / 删除）的「再点一次确认」态
let wizardCatalog = [];
let connectionCatalog = [];
let wizardDiscoveredCatalog = [];
let connectionDiscoveredCatalog = [];
let wizardRoleRefs = { quality: "", balanced: "", fast: "" };
let connectionRoleRefs = { quality: "", balanced: "", fast: "" };

const CAT_LABELS = { official: "官方", cn_official: "国内", custom: "自定义", experimental: "实验" };
const MODEL_FAMILY_ICONS = {
  anthropic: { file: "anthropic.svg", label: "Anthropic" },
  deepseek: { file: "deepseek.svg", label: "DeepSeek" },
  generic: { file: "generic.svg", label: "自定义模型" },
  glm: { file: "glm.svg", label: "智谱 GLM" },
  kimi: { file: "kimi.svg", label: "Kimi" },
  minimax: { file: "minimax.svg", label: "MiniMax" },
  openai: { file: "openai.svg", label: "OpenAI" },
  openrouter: { file: "openrouter.svg", label: "OpenRouter" },
  qwen: { file: "qwen.svg", label: "通义千问" },
  siliconflow: { file: "siliconflow.svg", label: "硅基流动" },
  xiaomi: { file: "xiaomi.svg", label: "小米 MiMo" },
};

function modelFamilyKey(profile = {}) {
  const templateId = String(profile.template_id || "").toLowerCase();
  const icon = String(profile.icon || "").toLowerCase();
  const direct = templateId || icon;
  if (direct === "custom-openai" || direct === "custom-openai-responses") return "openai";
  if (direct === "custom") {
    if (String(profile.api_format || "").startsWith("openai")) return "openai";
    if (String(profile.api_format || "") === "anthropic") return "anthropic";
  }
  if (MODEL_FAMILY_ICONS[direct]) return direct;
  if (MODEL_FAMILY_ICONS[icon]) return icon;

  const value = [profile.model, profile.name, profile.base_url, profile.website_url]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (/openrouter/.test(value)) return "openrouter";
  if (/siliconflow|siliconcloud/.test(value)) return "siliconflow";
  if (/deepseek/.test(value)) return "deepseek";
  if (/glm|zhipu|bigmodel|zai-org/.test(value)) return "glm";
  if (/kimi|moonshot/.test(value)) return "kimi";
  if (/minimax/.test(value)) return "minimax";
  if (/qwen|dashscope|tongyi/.test(value)) return "qwen";
  if (/mimo|xiaomi/.test(value)) return "xiaomi";
  if (/claude|anthropic/.test(value)) return "anthropic";
  if (/gpt|openai/.test(value)) return "openai";
  return "generic";
}

function modelFamilyMeta(profile = {}) {
  const key = modelFamilyKey(profile);
  const item = MODEL_FAMILY_ICONS[key] || MODEL_FAMILY_ICONS.generic;
  return { ...item, key, src: `/assets/model-icons/${item.file}` };
}

function updateModelIcon(image, profile) {
  if (!image) return;
  const meta = modelFamilyMeta(profile);
  image.src = meta.src;
  image.title = meta.label;
  image.dataset.modelFamily = meta.key;
}

function modelIconMarkup(profile) {
  const meta = modelFamilyMeta(profile);
  return `<img class="model-family-icon profile-model-icon" src="${meta.src}" alt="" aria-hidden="true" title="${escapeHtml(meta.label)}" data-model-family="${meta.key}" />`;
}
const PAGE_META = {
  switch: ["", "模型连接", ""],
  skills: ["", "Skill & MCP", ""],
  status: ["", "状态", ""],
  settings: ["", "设置", ""],
};

const THEME_STORAGE_KEY = "csswitch-theme";

function savedTheme() {
  try {
    return window.localStorage?.getItem(THEME_STORAGE_KEY) || "";
  } catch (_) {
    return "";
  }
}

function applyTheme(theme, { persist = true } = {}) {
  const value = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = value;
  if (els.themeBtn) els.themeBtn.textContent = value === "dark" ? "切换浅色主题" : "切换深色主题";
  if (persist) {
    try { window.localStorage?.setItem(THEME_STORAGE_KEY, value); } catch (_) {}
  }
}

function setPage(page) {
  if (page === "profiles") page = "switch";
  const meta = PAGE_META[page] || PAGE_META.switch;
  document.querySelectorAll("[data-page]").forEach((node) => node.classList.toggle("active", node.dataset.page === page));
  document.querySelectorAll("[data-page-target]").forEach((node) => node.classList.toggle("active", node.dataset.pageTarget === page));
  if (els.pageEyebrow) els.pageEyebrow.textContent = meta[0];
  if (els.pageTitle) els.pageTitle.textContent = meta[1];
  if (els.pageSubtitle) els.pageSubtitle.textContent = meta[2];
  if (page === "skills") skillPage?.ensureLoaded();
}

async function configureDesktopWindow() {
  if (PREVIEW) return;
  try {
    const appWindow = window.__TAURI__.window.getCurrentWindow();
    const LogicalSize = window.__TAURI__.dpi.LogicalSize;
    await appWindow.setMinSize(new LogicalSize(760, 520));
    await appWindow.setSize(new LogicalSize(920, 650.5));
  } catch (_) {
    // 某些受限 WebView 权限下不能改窗口尺寸；界面本身仍保持响应式。
  }
}

function renderCurrentSummary() {
  if (!els.currentProfileName) return;
  if (mode === "official") {
    updateModelIcon(els.currentProfileIcon, { template_id: "anthropic" });
    els.currentProfileName.textContent = "官方 Claude";
    els.currentProfileState.textContent = "官方模式";
    els.currentProfileState.className = "state-pill neutral";
    els.currentRouteMode.textContent = "由 Science 管理";
    els.currentProfileModel.textContent = "Claude Science";
    els.currentProfileMeta.textContent = "订阅与登录由 Claude Science 管理";
    return;
  }
  const profile = (configState.profiles || []).find((item) => item.id === configState.active_id);
  els.currentRouteMode.textContent = "CSSwitch 代理";
  if (!profile) {
    updateModelIcon(els.currentProfileIcon, {});
    els.currentProfileName.textContent = "尚未选择配置";
    els.currentProfileState.textContent = "等待选择";
    els.currentProfileState.className = "state-pill neutral";
    els.currentProfileModel.textContent = "未配置";
    els.currentProfileMeta.textContent = "从下方选择配置方案";
    return;
  }
  const hasKey = typeof profile.has_key === "boolean" ? profile.has_key : !!profile.key;
  updateModelIcon(els.currentProfileIcon, profile);
  els.currentProfileName.textContent = profile.name || "未命名配置";
  const pending = configState.selection_pending || configState.active_id !== configState.applied_profile_id;
  els.currentProfileState.textContent = pending
    ? "当前选择 · 待一键开始应用"
    : "当前选择 · 上次应用";
  els.currentProfileState.className = "state-pill neutral";
  els.currentProfileModel.textContent = modelSummary(profile);
  els.currentProfileMeta.textContent = profile.base_url || (hasKey ? "Key 已保存" : "未填写端点");
}

// ── 模型能力（纯函数，无 DOM）：native 映射 / relay 跟随 / relay 固定。──
const CAP = { NATIVE: "native", FOLLOW: "follow", FIXED: "fixed" };
function templateCaps(t) { return (t && t.capabilities) || {}; }
function hasCapField(t, field) {
  return !!(t && t.capabilities && Object.prototype.hasOwnProperty.call(t.capabilities, field));
}
function legacyNativeAdapterFallback(t) {
  return !!(t && !t.capabilities && (t.adapter === "deepseek" || t.adapter === "qwen"));
}
function modelCapability(t) {
  if (!t) return CAP.FIXED;                       // 未知模板：最保守，要求填模型
  const caps = templateCaps(t);
  if (caps.model_discovery === "builtin_static" && caps.model_required === false) return CAP.NATIVE;
  if (caps.model_required === false) return CAP.FOLLOW;
  if (hasCapField(t, "model_required")) return CAP.FIXED;
  if (legacyNativeAdapterFallback(t)) return CAP.NATIVE; // 仅兼容旧后端 / preview mock；S1 DTO 走 capabilities
  return t.requires_model_override ? CAP.FIXED : CAP.FOLLOW; // 兼容旧后端 / preview mock
}
function canFetchModels(t) {
  const discovery = templateCaps(t).model_discovery;
  return discovery === "anthropic_models_or_manual"
    || discovery === "openai_models_or_manual";
}
function modelRequired(t) {
  if (!t) return true;
  if (hasCapField(t, "model_required")) return !!templateCaps(t).model_required;
  return !!t.requires_model_override; // 兼容旧后端 / preview mock
}
function baseUrlRequired(t) {
  if (!t) return true;
  if (hasCapField(t, "base_url_required")) return !!templateCaps(t).base_url_required;
  return !!t.base_url_editable; // 兼容旧后端 / preview mock
}
function profileCapabilitySource(p, t) {
  if (!p || !p.capabilities) return t;
  return {
    ...(t || {}),
    ...p,
    builtin_models: (t && t.builtin_models) || [],
    base_url_editable: t ? t.base_url_editable : true,
    capabilities: p.capabilities,
  };
}
// 来源提示：据「地址是否可编辑 + 模型能力」生成，不能只看 category。
function sourceHint(t) {
  if (!t) return "选择来源后按提示填写。";
  // 真·自定义（可编辑且无预设地址）才叫「自定义端点」；预设虽可编辑但有官方默认，另行描述。
  if (t.base_url_editable && !t.base_url && t.api_format === "openai_chat") {
    return "自定义 OpenAI Chat Completions 兼容端点：填 base root、key 与模型名称，经代理转换协议。";
  }
  if (t.base_url_editable && !t.base_url && t.api_format === "openai_responses") {
    return "自定义 OpenAI Responses 兼容端点：填 base root、key 与模型名称，经代理转换协议。";
  }
  if (t.base_url_editable && !t.base_url) return "自定义 Anthropic 兼容端点：填写地址、key 和供应商提供的精确模型 ID。";
  const cap = modelCapability(t);
  if (cap === CAP.NATIVE) {
    // deepseek 是原生 Anthropic 透传；qwen 经代理做 Anthropic↔OpenAI 转换，别都叫「直连」。
    return t.api_format === "openai_chat" || t.api_format === "openai_responses"
      ? "官方端点（经代理转换协议）：填 API Key 即可，地址与推荐模型已内置。"
      : "官方原生端点（无需转换）：填 API Key 即可，地址与推荐模型已内置。";
  }
  // 预设地址可编辑：默认已填好官方地址，套餐/区域端点可改（如小米 token plan）。
  const addr = t.base_url_editable ? "地址已预填官方默认（套餐 / 区域端点可改）" : "地址已预设";
  if (cap === CAP.FOLLOW) return `填 API Key 即可，${addr}；模型可从推荐中选择或自由填写。`;
  return `填 API Key 和精确模型 ID，${addr}。`;
}
const MODEL_HINT = {
  native: "推荐模型只是初始建议；四个模型框都允许自由填写精确模型 ID。",
  follow: "可以选择推荐模型，也可以直接填写供应商或中转站提供的精确模型 ID。",
  fixed: "默认模型必填；质量、快速与 Fable 留空时自动继承。",
};
const PROXY_UNHEALTHY_MSG = "代理进程不可达或已退出，请点击「一键开始」恢复。";

// 静态 provider 展示四个自由模型输入。
function applyModelCapability(t, ui, currentModel) {
  const cap = modelCapability(t);
  const listId = ui.sel.getAttribute("list");
  const dl = listId && document.getElementById(listId);
  // 静态 provider 统一使用四个自由输入框；推荐项只作为 datalist 建议。
  ui.info.textContent = cap === CAP.NATIVE ? MODEL_HINT.native : "";
  ui.info.hidden = cap !== CAP.NATIVE;
  ui.sel.hidden = false;
  if (ui.fetchBtn) {
    const fetchable = canFetchModels(t);
    ui.fetchBtn.hidden = !fetchable;
    ui.fetchBtn.parentElement.hidden = !fetchable;
    ui.fetchBtn.textContent = "获取可用模型";
  }
  const builtin = ((t && t.builtin_models) || []).slice();
  if (currentModel && !builtin.includes(currentModel)) builtin.unshift(currentModel);
  const models = builtin.map((id) => ({ id, supports_tools: null }));
  renderModelOptions(ui.sel, models, "内置");
  ui.sel.value = currentModel || (builtin[0] || "");
  ui.hint.textContent = [MODEL_HINT.fixed, t && t.compatibility_notice]
    .filter(Boolean).join(" ");
  return cap;
}

function setMsg(text, kind) {
  // 去掉常驻「就绪。」：空消息或纯 idle 时整条反馈栏不占位，有真实反馈（结果/错误/自检）才冒出来。
  const t = text && text !== "就绪。" ? text : "";
  els.msg.textContent = t;
  els.msg.className = "msg" + (kind ? " " + kind : "");
  els.msg.parentElement.hidden = !t && (!els.browserFallback || els.browserFallback.hidden);
}

function setBrowserFallback(url) {
  const value = typeof url === "string" ? url.trim() : "";
  els.browserFallbackUrl.value = value;
  els.browserFallback.hidden = !value;
  els.msg.parentElement.hidden = !value && !els.msg.textContent;
}

function setLight(el, s) {
  const cls = { green: "g", amber: "a", red: "r", gray: "", unknown: "" }[normalizeRuntimeLight(s)];
  el.className = "lt" + (cls ? " " + cls : "");
  document.querySelectorAll('[data-mirror-light="' + el.id + '"]').forEach((node) => {
    node.className = "lt" + (cls ? " " + cls : "");
  });
}

function setStatusText(id, status) {
  const normalized = normalizeRuntimeLight(status);
  const node = $(id);
  if (node) node.textContent = RUNTIME_STATUS_LABELS[normalized];
  document.querySelectorAll('[data-mirror-text="' + id + '"]').forEach((mirror) => {
    mirror.textContent = RUNTIME_STATUS_LABELS[normalized];
  });
}

function proxyRecoveryMessage(status) {
  const err = status && status.last_error;
  if (err && err.type === "proxy_unhealthy") return err.message || PROXY_UNHEALTHY_MSG;
  return "";
}

function setStatusRecoveryMsg(text) {
  if (busy) return;
  const current = els.msg.textContent || "";
  if (text) {
    if (!current || current === statusRecoveryMsg) {
      setMsg(text, "err");
      statusRecoveryMsg = text;
    }
    return;
  }
  if (statusRecoveryMsg && current === statusRecoveryMsg) {
    setMsg("");
  }
  statusRecoveryMsg = "";
}

function clearBusyMsgTimers() {
  busyMsgTimers.forEach((t) => clearTimeout(t));
  busyMsgTimers = [];
}

function profileName(id) {
  const p = (configState.profiles || []).find((x) => x.id === id);
  return p ? p.name : id;
}

function syncProfileBusyState() {
  if (!els.profileList) return;
  els.profileList.querySelectorAll(".prow").forEach((row) => {
    const rowId = row.getAttribute("data-id");
    const isTarget = !!(
      (busyOp && busyOp.kind === "activate" && rowId === busyOp.id) ||
      (activationOp && activationOp.kind === "activate" && rowId === activationOp.id)
    );
    row.classList.toggle("pworking", isTarget);
    row.querySelectorAll("button[data-act]").forEach((btn) => {
      const act = btn.getAttribute("data-act");
      const permanentlyDisabled = btn.dataset.permanentlyDisabled === "true";
      btn.disabled = permanentlyDisabled || busy || (activationInFlight && act === "activate");
      if (act === "activate") {
        btn.textContent = isTarget ? "已提交" : "设为当前";
      }
    });
  });
}

function sameOp(a, b) {
  return !!(a && b && a.kind === b.kind && (a.id || "") === (b.id || ""));
}

function scheduleBusyMsg(ms, op, text) {
  const timer = setTimeout(() => {
    if (busy && sameOp(busyOp, op)) setMsg(text);
  }, ms);
  busyMsgTimers.push(timer);
}

function startFetchModelsFeedback(id) {
  clearBusyMsgTimers();
  setMsg("正在用候选地址和 Key 做隔离模型探测；不会修改当前配置或正式代理…");
  scheduleBusyMsg(12000, { kind: "fetchModels", id }, "仍在等待上游模型列表。探测结果只会成为可选项，不会自动写入配置。");
  scheduleBusyMsg(30000, { kind: "fetchModels", id }, "模型探测接近等待上限。失败后仍可在已选 transport 下手工填写精确模型 ID。");
}

function startActivateFeedback(id) {
  const name = profileName(id);
  setMsg("正在把「" + name + "」设为当前选择；不会启动或切换正在运行的服务。");
}

function startSaveConnectionFeedback(id, selected) {
  clearBusyMsgTimers();
  if (selected) {
    setMsg("正在保存当前选择的连接；当前运行链保持不变，下次一键开始时应用…");
    scheduleBusyMsg(4500, { kind: "saveConnection", id }, "仍在等待候选连接上游校验。当前运行链保持不变。");
    scheduleBusyMsg(18000, { kind: "saveConnection", id }, "上游校验接近等待上限。验证后只保存候选连接。");
    return;
  }
  setMsg("保存连接中：正在做候选上游校验；无法确认时会保存但标记为未校验…");
  scheduleBusyMsg(4500, { kind: "saveConnection", id }, "仍在等待候选连接校验。不会影响当前正在运行的代理。");
}

function startOneClickFeedback() {
  clearBusyMsgTimers();
  setMsg("一键开始：检查代理 → 保护凭据与历史 → 准备虚拟登录 → 启动/复用沙箱 → 探活…");
  scheduleBusyMsg(3500, { kind: "oneClick" }, "正在建立启动事务并保护凭据、组织历史和插件配置；不会复制 Science 的 Conda 或 Runtime 环境。");
  scheduleBusyMsg(9000, { kind: "oneClick" }, "仍在准备受保护状态或启动沙箱。完成后会自动打开 Science；失败会显示日志摘要。");
}

function startSwitchModeFeedback(targetMode) {
  clearBusyMsgTimers();
  const toOfficial = targetMode === "official";
  setMsg(toOfficial
    ? "正在切到官方模式：停止第三方代理/沙箱并保存模式…"
    : "正在切到第三方模式：保存模式，完成后可选择配置并一键开始…");
  scheduleBusyMsg(3500, { kind: "switchMode", id: targetMode }, toOfficial
    ? "仍在停止第三方链路。真实 Claude Science 实例不会被触碰。"
    : "仍在保存模式切换。当前不会自动启动第三方代理。");
}

function startPortSaveFeedback(changed) {
  clearBusyMsgTimers();
  if (changed) {
    setMsg("正在保存端口设置：端口变化会先重置当前代理/沙箱链路…");
    scheduleBusyMsg(3500, { kind: "ports" }, "仍在应用端口设置。若旧沙箱无法停止，端口会保持原值并显示错误。");
    return;
  }
  setMsg("正在保存端口设置…");
}

function startDoctorFeedback() {
  clearBusyMsgTimers();
  setMsg("自检中：正在运行本地诊断脚本…");
  scheduleBusyMsg(3500, { kind: "doctor" }, "自检仍在运行。它会检查本地依赖、端口、配置摘要和 CSSwitch 管理的 Skill 路由；不会读取真实 Science HOME，也不会传出、打印或展示完整 key。");
}

function setBusy(on, op) {
  busy = on;
  busyOp = on ? (op || { kind: "global" }) : null;
  const activationBusy = on && busyOp && busyOp.kind === "activate";
  if (!on) clearBusyMsgTimers();
  [
    els.oneClickBtn, els.stopBtn, els.importSkillBtn, els.newBtn,
    els.runtimeUseCacheBtn, els.runtimeDownloadBtn, els.runtimeChoiceCancelBtn,
    els.wizSaveBtn, els.wizFetchBtn, els.wizCancelBtn,
    els.connSaveBtn, els.connFetchBtn, els.connClearBtn, els.connCancelBtn,
    els.wizModel, els.wizRoleQuality, els.wizRoleFast, els.wizRoleFable,
    els.connModel, els.connRoleQuality, els.connRoleFast, els.connRoleFable,
    els.metaSaveBtn, els.metaCancelBtn,
    // 端口输入也纳入忙碌禁用：忙碌中改端口会与在途操作竞态（修 P1-c 前端侧）。
    els.proxyPort, els.sandboxPort, els.reuseSystemSsh,
  ].forEach((b) => b && (b.disabled = on));
  syncOpenBrowserControl();
  if (skillPage) skillPage.setGlobalBusy(on);
  if (els.doctorBtn) els.doctorBtn.disabled = on && !activationBusy;
  // 模式切换按钮同样禁用：忙碌中切官方会与「一键开始」竞态（修 P1-b 前端侧）。
  if (els.modeSeg) els.modeSeg.querySelectorAll(".seg-btn").forEach((b) => (b.disabled = on));
  syncProfileBusyState();
  // 松开忙碌时，把模型必填保存门控交回门（避免 setBusy(false) 覆盖门控）。
  if (!on) { refreshWizGate(); refreshConnGate(); }
  syncActivationControls();
}

function syncOpenBrowserControl() {
  if (!els.openBrowserBtn) return;
  els.openBrowserBtn.disabled = busy || browserOpenInFlight;
  els.openBrowserBtn.textContent = browserOpenInFlight ? "打开中…" : "浏览器打开";
}

function syncActivationControls() {
  const writeLocked = busy;
  [
    els.newBtn, els.proxyPort, els.sandboxPort, els.reuseSystemSsh,
    els.connClearBtn, els.metaSaveBtn,
  ].forEach((b) => b && (b.disabled = writeLocked));
  if (els.modeSeg) els.modeSeg.querySelectorAll(".seg-btn").forEach((b) => (b.disabled = writeLocked));
  if (els.oneClickBtn) els.oneClickBtn.disabled = busy || activationInFlight;
  if (els.runtimeUseCacheBtn) els.runtimeUseCacheBtn.disabled = busy || activationInFlight;
  if (els.reuseSystemSsh) els.reuseSystemSsh.disabled = busy || activationInFlight;
  syncProfileBusyState();
  refreshWizGate();
  refreshConnGate();
}

function setActivationInFlight(on, op) {
  activationInFlight = on;
  activationOp = on ? op : null;
  syncActivationControls();
}

async function call(cmd, args) {
  return await invoke(cmd, args);
}

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function tplById(id) {
  return (configState.templates || []).find((t) => t.id === id) || null;
}

// ── 视图切换：列表 / 新建向导 / 连接编辑 / 改名。一次只显示一个表单（列表隐去减少高度）。──
function showView(v) {
  els.connectionOverview.hidden = v !== "list";
  els.listSec.hidden = v !== "list";
  els.wizSec.hidden = v !== "wizard";
  els.connSec.hidden = v !== "conn";
  els.metaSec.hidden = v !== "meta";
  els.panel.classList.toggle("view-form", v !== "list");
  if (v !== "list") setPage("switch");
}
function cancelForm() { showView("list"); setPage("switch"); setMsg("就绪。"); }

// 危险操作「再点一次确认」（避免依赖 window.confirm，Tauri webview 里不可靠）。
function confirmAction(token, promptText, fn) {
  if (pendingConfirm && pendingConfirm.token === token) {
    clearTimeout(pendingConfirm.timer);
    pendingConfirm = null;
    fn();
    return;
  }
  if (pendingConfirm) clearTimeout(pendingConfirm.timer);
  pendingConfirm = {
    token,
    timer: setTimeout(() => { pendingConfirm = null; setMsg("已取消。"); }, 4000),
  };
  setMsg(promptText + " —— 再点一次同一按钮确认（4 秒内）。", "err");
}

function runtimeCommandErrorText(error) {
  if (typeof error === "string") return error;
  if (error instanceof Error && typeof error.message === "string") return error.message;
  return "后端返回了无法识别的错误。";
}

// ── 加载配置 + 渲染列表 ──
async function loadConfig(options) {
  const opts = options || {};
  try {
    const cfg = await call("get_config");
    configState.profiles = cfg.profiles || [];
    configState.templates = cfg.templates || [];
    configState.active_id = cfg.active_id || "";
    configState.applied_profile_id = cfg.applied_profile_id || null;
    configState.selection_pending = !!cfg.selection_pending;
    configState.proxy_port = cfg.proxy_port ?? 18991;
    configState.sandbox_port = cfg.sandbox_port ?? 8990;
    configState.reuse_system_ssh = !!cfg.reuse_system_ssh;
    els.proxyPort.value = configState.proxy_port;
    els.sandboxPort.value = configState.sandbox_port;
    els.reuseSystemSsh.checked = configState.reuse_system_ssh;
    applyMode(cfg.mode === "official" ? "official" : "proxy");
    renderList();
    showView("list");
    // 一次性迁移提示（#9 甲）：后端 get_config 读后已清盘，只会出现一次。
    if (cfg.pending_notice) setMsg(cfg.pending_notice, "ok");
  } catch (e) {
    setMsg("读取配置失败：" + e, "err");
    if (opts.throwOnError) throw e;
    return false;
  }
  return true;
}

// 列表优先展示默认 route；静态目录未配置时明确提示。
function modelSummary(p) {
  const route = (p.model_catalog || []).find((item) =>
    item.selector_id === p.default_model_route_id || item.upstream_model === p.model
  );
  if (route) return route.display_name || route.upstream_model;
  if (p.model) return p.model;
  return "目录未配置";
}

function profileModelOptions(p) {
  const template = tplById(p.template_id);
  const catalogModels = (p.model_catalog || []).map((route) => route.upstream_model);
  const available = catalogModels.length
    ? catalogModels
    : (p.model_options || []).length
    ? p.model_options
    : ((template && template.builtin_models) || []);
  const candidates = [p.model, ...available]
    .filter(Boolean);
  return [...new Set(candidates)];
}

function profileModelControl(p) {
  const model = p.model || "";
  if (!PROFILE_INTERACTIVE_PREVIEW) {
    const count = Number.isFinite(p.model_count) ? p.model_count : (p.model_catalog || []).length;
    const primary = modelSummary(p);
    const details = count ? `${count} 个可用模型` : "动态目录";
    return `<strong class="profile-model-text" title="${escapeHtml(primary)}">${escapeHtml(primary)}</strong><span class="profile-model-meta">${escapeHtml(details)}</span>`;
  }
  const options = profileModelOptions(p);
  return `<select class="profile-model-select" data-profile-model="${escapeHtml(p.id)}" aria-label="${escapeHtml(p.name)} 的模型">
    ${options.map((value) => `<option value="${escapeHtml(value)}"${value === model ? " selected" : ""}>${escapeHtml(value)}</option>`).join("")}
  </select>`;
}

function renderList() {
  const list = els.profileList;
  const ps = configState.profiles || [];
  renderCurrentSummary();
  if (!ps.length) {
    list.innerHTML = '<div class="empty">还没有配置。使用“新建配置”添加一条第三方来源。</div>';
    return;
  }
  const header = `<div class="profile-list-head" aria-hidden="true"><span>配置</span><span>模型 / 目录</span><span>凭据</span><span>操作</span></div>`;
  list.innerHTML = header + ps.map((p) => {
    const active = p.id === configState.active_id;
    const hasKey = typeof p.has_key === "boolean" ? p.has_key : !!p.key;
    const credential = hasKey ? escapeHtml(p.key_masked || p.key || "已保存") : "未填写";
    const editAction = '<button class="abtn" data-act="editconn">编辑</button>';
    return (
      '<div class="prow' + (active ? " pactive" : "") + '" data-id="' + escapeHtml(p.id) + '">' +
        '<div class="profile-identity">' +
          '<div class="prow-top">' +
            modelIconMarkup(p) +
            '<span class="pname">' + escapeHtml(p.name) + "</span>" +
            (active ? '<span class="badge on">当前选择</span>' : "") +
            (p.id === configState.applied_profile_id ? '<span class="badge">上次应用</span>' : "") +
          "</div>" +
        "</div>" +
        '<div class="profile-model-cell">' + profileModelControl(p) + "</div>" +
        '<div class="profile-key-cell"><strong>' + credential + "</strong></div>" +
        '<div class="prow-acts">' +
          (active ? "" : '<button class="abtn prim" data-act="activate">设为当前</button>') +
          editAction +
          '<details class="profile-more"><summary>更多</summary><div class="profile-menu">' +
            '<button class="abtn" data-act="editmeta">名称与备注</button>' +
            '<button class="abtn" data-act="clearkey">清除 Key</button>' +
            '<button class="abtn danger" data-act="delete">删除配置</button>' +
          "</div></details>" +
        "</div>" +
      "</div>"
    );
  }).join("");
  syncProfileBusyState();
}

// ── 模式（第三方 / 官方）──
function applyMode(m) {
  const nextMode = m === "official" ? "official" : "proxy";
  if (nextMode !== mode && nextMode === "official") officialRuntimeState = "gray";
  mode = nextMode;
  els.panel.classList.toggle("mode-official", mode === "official");
  els.modeSeg.querySelectorAll(".seg-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.mode === mode)
  );
  els.oneClickBtn.textContent =
    mode === "official" ? "打开官方 Claude Science" : "一键开始";
  renderCurrentSummary();
}

async function switchMode(m) {
  if (m === mode) return;
  if (busy) return; // 忙碌中不切模式（防与「一键开始」竞态；按钮亦已禁用，此为双保险）。修 P1-b
  skillPage?.invalidate();
  setBusy(true, { kind: "switchMode", id: m });
  startSwitchModeFeedback(m);
  try {
    await call("set_mode", { mode: m });
  } catch (e) {
    setMsg("切换模式失败：" + e, "err");
    setBusy(false);
    await skillPage?.refreshIfLoaded();
    return;
  }
  applyMode(m);
  hideHistoryRecovery();
  setBusy(false);
  showView("list");
  setMsg(
    mode === "official"
      ? "已切到官方模式：第三方代理/沙箱已停，点上方按钮打开你真实的 Claude Science。"
      : "已切到第三方模式：选一条配置「设为当前」后点「一键开始」。"
  );
  await refreshStatus();
  await skillPage?.refreshIfLoaded();
}

async function openOfficial() {
  setBusy(true);
  setMsg("正在打开官方 Claude Science…");
  try {
    await call("open_official");
    officialRuntimeState = "gray";
    els.brandDot.className = "dot gray";
    setMsg("已发起打开官方 Claude Science；运行、登录与订阅状态由 Science 管理。", "ok");
  } catch (e) {
    officialRuntimeState = "gray";
    els.brandDot.className = "dot gray";
    setMsg("打开失败：" + e, "err");
  } finally {
    setBusy(false);
  }
}

// hero 按钮按当前模式分派。
async function heroClick() {
  if (mode === "official") await openOfficial();
  else await oneClick();
}

// ── 运行设置（端口 + 系统 SSH 配置授权；不含 provider/连接）──
async function persistRuntimeSettings() {
  if (busy) return; // 忙碌中不改端口（防与在途操作竞态；输入亦已禁用，此为双保险）。修 P1-c
  skillPage?.invalidate();
  const p = parseInt(els.proxyPort.value, 10) || 18991;
  const s = parseInt(els.sandboxPort.value, 10) || 8990;
  const reuseSystemSsh = !!els.reuseSystemSsh.checked;
  const portsChanged = p !== configState.proxy_port || s !== configState.sandbox_port;
  const sshChanged = reuseSystemSsh !== configState.reuse_system_ssh;
  const changed = portsChanged || sshChanged;
  // 本次端口提交全程置忙：仅靠开头的 `if (busy) return` 只挡「已在忙时进入」，挡不住本函数在途
  // 时其它操作（切模式/一键/连接编辑）启动。置忙 + 禁用控件才能保证操作顺序符合用户预期。修 GPT 三轮 P2
  setBusy(true, { kind: "ports" });
  startPortSaveFeedback(changed);
  try {
    await call("set_settings", { cfg: { proxy_port: p, sandbox_port: s, reuse_system_ssh: reuseSystemSsh } });
    configState.proxy_port = p;
    configState.sandbox_port = s;
    configState.reuse_system_ssh = reuseSystemSsh;
    // set_settings invalidates backend history-recovery references even when
    // the submitted values are unchanged, so never leave stale buttons visible.
    hideHistoryRecovery();
    // 后端在端口变化时会拆掉旧代理/沙箱（否则会复用指向旧端口的死链路），如实告知需重开。修 P1-c
    if (changed) {
      setMsg(sshChanged
        ? "SSH 授权设置已保存。正在运行的代理/沙箱已重置，请重新「一键开始」。"
        : "端口已保存。改端口会重置正在运行的代理/沙箱，请重新「一键开始」。", "ok");
      await refreshStatus();
      await skillPage?.refreshIfLoaded();
    } else {
      setMsg("端口未变化。", "ok");
    }
  } catch (e) {
    // 出错＝端口未落盘（校验不过 / 停旧沙箱失败）：把输入框还原成实际生效值，避免显示未保存的数字。
    els.proxyPort.value = configState.proxy_port;
    els.sandboxPort.value = configState.sandbox_port;
    els.reuseSystemSsh.checked = configState.reuse_system_ssh;
    setMsg(String(e), "err");
  } finally {
    setBusy(false);
    await skillPage?.refreshIfLoaded();
  }
}

// ── 模型候选渲染：填进 input 关联的 <datalist>，并按 supports_tools 标注。──
// input 的值由调用方另设，用户可自由编辑精确 upstream ID。
function renderModelOptions(sel, models, sourceLabel) {
  const listId = sel.getAttribute("list");
  const dl = listId && document.getElementById(listId);
  if (!dl) return;
  dl.innerHTML = "";
  for (const m of models || []) {
    const o = document.createElement("option");
    o.value = m.id;
    const tag = m.supports_tools === true ? " ·工具✓" : m.supports_tools === false ? " ·无工具" : "";
    const src = sourceLabel ? " [" + sourceLabel + "]" : "";
    const display = m.display_name && m.display_name !== m.id ? m.display_name + " · " : "";
    o.label = display + m.id + tag + src;
    dl.appendChild(o);
  }
}

const MODEL_SOURCE_LABELS = {
  live: "实时", "fresh-cache": "新鲜缓存", "revalidated-cache": "已重新验证缓存",
  "stale-cache": "过期缓存", builtin: "内置", unsupported: "内置", protocol: "协议不兼容",
};

function modelSourceLabel(source) {
  return MODEL_SOURCE_LABELS[source] || "未验证";
}

function editorState(kind) {
  const wizard = kind === "wizard";
  return {
    model: wizard ? els.wizModel : els.connModel,
    staticRoot: wizard ? els.wizStaticCatalog : els.connStaticCatalog,
    warning: wizard ? els.wizCatalogWarning : els.connCatalogWarning,
    quality: wizard ? els.wizRoleQuality : els.connRoleQuality,
    fast: wizard ? els.wizRoleFast : els.connRoleFast,
    fable: wizard ? els.wizRoleFable : els.connRoleFable,
    get catalog() { return wizard ? wizardCatalog : connectionCatalog; },
    set catalog(value) { if (wizard) wizardCatalog = value; else connectionCatalog = value; },
    get discovered() { return wizard ? wizardDiscoveredCatalog : connectionDiscoveredCatalog; },
    set discovered(value) { if (wizard) wizardDiscoveredCatalog = value; else connectionDiscoveredCatalog = value; },
    get refs() { return wizard ? wizardRoleRefs : connectionRoleRefs; },
    set refs(value) { if (wizard) wizardRoleRefs = value; else connectionRoleRefs = value; },
  };
}

function selectedReference(route) {
  return route.selector_id || route.upstream_model;
}

function roleReferences(bindings, fallback, defaultReference = fallback) {
  const roles = bindings || {};
  return {
    default: defaultReference || fallback || "",
    balanced: roles.sonnet || defaultReference || fallback || "",
    quality: roles.opus || roles.fable || fallback || "",
    fast: roles.haiku || fallback || "",
    fable: roles.fable || roles.opus || fallback || "",
  };
}

function initializeCatalogEditor(kind, routes, defaultRef, bindings) {
  const editor = editorState(kind);
  editor.discovered = [];
  editor.catalog = mergeCatalogCandidates([], (routes || []).map((route) => ({ ...route, enabled: true })), { enableNew: true });
  const fallback = defaultRef || selectedReference(editor.catalog[0] || {});
  editor.refs = roleReferences(bindings, fallback, defaultRef || fallback);
  const fields = projectSimpleModelFields(editor.catalog, editor.refs.default, bindings);
  editor.model.value = fields.default_model;
  editor.quality.value = fields.quality_model;
  editor.fast.value = fields.fast_model;
  editor.fable.value = fields.fable_model;
  renderModelOptions(editor.model, editor.catalog.map((item) => ({
    id: item.upstream_model,
    supports_tools: item.supports_tools,
  })), "推荐");
  const preservesLegacyBalanced = kind === "connection" && editor.refs.balanced !== editor.refs.default;
  editor.warning.textContent = preservesLegacyBalanced
    ? "这个旧配置曾单独保存均衡映射：不修改默认模型时会原样保留；修改默认模型后，均衡会随默认更新。"
    : "可以选择推荐模型，也可以直接填写供应商或中转站提供的精确模型 ID。";
}

function catalogSubmission(kind) {
  const editor = editorState(kind);
  return buildSimpleModelSubmission({
    default_model: editor.model.value,
    quality_model: editor.quality.value,
    fast_model: editor.fast.value,
    fable_model: editor.fable.value,
  }, {
    existing_routes: editor.catalog,
    candidate_routes: editor.discovered,
    existing_references: editor.refs,
    preserve_existing_sonnet: kind === "connection",
    prune_replaced_bindings: kind === "connection",
  });
}

function renderStaticCatalogDiscovery(kind, r) {
  const editor = editorState(kind);
  const models = (r && r.models) || [];
  editor.discovered = mergeCatalogCandidates([], models, { enableNew: false });
  const suggestions = mergeCatalogCandidates(editor.catalog, editor.discovered, { enableNew: false });
  renderModelOptions(editor.model, suggestions.map((item) => ({
    id: item.upstream_model,
    display_name: item.display_name,
    supports_tools: item.supports_tools,
  })), modelSourceLabel(r && r.source));
  const meta = kind === "wizard" ? els.wizCatalogMeta : els.connCatalogMeta;
  const filtered = Number(r && r.filtered_unknown_count) || 0;
  const transport = r && r.route_catalog && r.route_catalog.transport;
  meta.textContent = modelSourceLabel(r && r.source) + " · " + models.length + " 个候选"
    + (transport ? " · " + transport : "")
    + (filtered ? " · 已按官方协议表过滤 " + filtered + " 个" : "");
  if (r && r.error_kind === "protocol") {
    setMsg("模型列表响应与当前协议不兼容；探测未写入配置，仍可在明确 transport 下手工填写精确模型 ID。", "err");
  } else if (r && r.error_kind === "network") {
    setMsg("模型探测暂时不可达；探测未写入配置，仍可手工填写精确模型 ID并保存。", "err");
  } else {
    setMsg("已读取 " + models.length + " 个候选模型。只有你在四个模型框中明确选择的 ID 才会保存；探测本身未修改配置。", "ok");
  }
}

function catalogRolesChanged(kind) {
  if (kind === "wizard") refreshWizGate(); else refreshConnGate();
}

// ── C2：新建向导 ──
function openWizard() {
  renderTemplateChips();
  const first = (configState.templates || [])[0];
  selectWizTemplate(first ? first.id : "");
  showView("wizard");
  setMsg("选择来源，按提示填写连接信息后创建。");
}

function renderTemplateChips() {
  els.wizTemplateChips.innerHTML = (configState.templates || []).map((t) => {
    const dot = t.icon_color ? ' style="background:' + escapeHtml(t.icon_color) + '"' : "";
    const cat = CAT_LABELS[t.category] || t.category || "";
    return (
      '<button type="button" class="chip" aria-pressed="false" data-tid="' + escapeHtml(t.id) + '">' +
        '<span class="chip-dot"' + dot + "></span>" +
        '<span class="chip-name">' + escapeHtml(t.name) + "</span>" +
        '<span class="chip-cat">' + escapeHtml(cat) + "</span>" +
      "</button>"
    );
  }).join("");
}

function selectWizTemplate(id) {
  els.wizTemplate.value = id;
  els.wizTemplateChips.querySelectorAll(".chip").forEach((c) => {
    const on = c.getAttribute("data-tid") === id;
    c.classList.toggle("sel", on);
    c.setAttribute("aria-pressed", on ? "true" : "false");
  });
  onWizTemplate();
}

function onWizTemplate() {
  const t = tplById(els.wizTemplate.value);
  if (!t) return;
  els.wizName.value = t.name;
  // 把「新建不自动生效」放进顶部常驻提示（默认窗口下反馈区首屏可能在折叠线下，见 #6）。
  els.wizTplHint.textContent = sourceHint(t) + " 新建后先设为当前选择，再点「一键开始」应用。";
  els.wizCatalogMeta.textContent = "尚未探测模型。";
  if (t.base_url_editable) {
    // 预设：预填官方默认地址（仍可改到套餐 / 区域端点）；真·自定义：留空 + 占位提示。
    els.wizBase.value = t.base_url || "";
    els.wizBase.readOnly = false;
    els.wizBase.placeholder = t.api_format === "openai_chat" || t.api_format === "openai_responses"
      ? "https://open.bigmodel.cn/api/paas/v4"
      : "https://your-relay/claude";
    els.wizBaseHint.textContent = t.base_url
      ? "官方默认地址，可改到 token 套餐 / 区域端点（如小米 token plan）。"
      : (t.api_format === "openai_chat"
        ? "OpenAI 兼容 base root，代理自动补 /chat/completions 与 /models。"
        : t.api_format === "openai_responses"
        ? "OpenAI 兼容 base root，代理自动补 /responses 与 /models。"
          : "自定义端点根地址（自动补 /v1/messages）。");
  } else {
    els.wizBase.value = t.base_url;
    els.wizBase.readOnly = true;
    els.wizBaseHint.textContent = "模板地址已填好（只读）。";
  }
  applyModelCapability(t, {
    info: els.wizModelInfo, sel: els.wizModel, hint: els.wizModelHint, fetchBtn: els.wizFetchBtn,
  }, "");
  const recommended = (t.recommended_catalog || (t.builtin_models || []).map((id) => ({
    selector_id: "", display_name: id, upstream_model: id,
    supports_tools: null, origin: "preset", availability: "unknown",
  }))).map((route) => ({ origin: "preset", availability: "unknown", ...route }));
  const defaultReference = t.recommended_default_model_route_id || recommended[0]?.selector_id || recommended[0]?.upstream_model || "";
  initializeCatalogEditor("wizard", recommended, defaultReference, t.recommended_role_bindings);
  refreshWizGate();
  setMsg("选择来源，按提示填写连接信息后创建。");
}

function refreshWizGate() {
  const t = tplById(els.wizTemplate ? els.wizTemplate.value : "");
  let invalidCatalog = false;
  if (t) {
    try { catalogSubmission("wizard"); } catch (_) { invalidCatalog = true; }
  }
  els.wizSaveBtn.disabled = busy || !t || invalidCatalog;
}

function openaiCustomAnthropicBaseMessage(t, base) {
  if (t && (t.id === "custom-openai" || t.id === "custom-openai-responses") && (base || "").trim().toLowerCase().includes("/anthropic")) {
    return "这个地址看起来是 Anthropic 兼容端点。请改选「自定义 Anthropic」，或填写 OpenAI 兼容 base root（如 https://api.moonshot.cn/v1）。";
  }
  return "";
}

async function wizFetch() {
  const t = tplById(els.wizTemplate.value);
  if (!t || !canFetchModels(t)) return;
  setBusy(true, { kind: "fetchModels", id: "wizard" });
  startFetchModelsFeedback("wizard");
  try {
    const r = await call("fetch_models", { req: {
      template_id: t.id,
      api_format: t.api_format || "",
      base_url: els.wizBase.value.trim(),
      key: els.wizKey.value.trim(),
    } });
    renderStaticCatalogDiscovery("wizard", r);
  } catch (e) {
    setMsg("获取模型失败：" + runtimeCommandErrorText(e), "err");
  } finally {
    setBusy(false);
    refreshWizGate();
  }
}

async function wizSave() {
  const t = tplById(els.wizTemplate.value);
  if (!t) { setMsg("模板未加载。", "err"); return; }
  const name = els.wizName.value.trim() || t.name;
  let catalogPayload;
  try { catalogPayload = catalogSubmission("wizard"); }
  catch (error) { setMsg(String(error.message || error), "err"); return; }
  const args = { templateId: t.id, name, key: els.wizKey.value.trim() };
  if (catalogPayload) {
    args.modelCatalog = catalogPayload.model_catalog;
    args.defaultModelRouteId = catalogPayload.default_model_route_id;
    args.roleBindings = catalogPayload.role_bindings;
  }
  if (t.base_url_editable) {
    const base = els.wizBase.value.trim();
    if (baseUrlRequired(t) && !base) { setMsg("请先填写 base_url。", "err"); return; }
    const baseErr = openaiCustomAnthropicBaseMessage(t, base);
    if (baseErr) { setMsg(baseErr, "err"); return; }
    args.baseUrl = base;
  }
  setBusy(true);
  setMsg("创建中…");
  try {
    await call("create_profile", args);
    els.wizKey.value = "";
    await loadConfig();
    setMsg("已创建「" + name + "」。请设为当前选择，再点「一键开始」应用。", "ok");
  } catch (e) {
    setMsg("创建失败：" + e, "err");
  } finally {
    setBusy(false);
  }
}

// ── C3：连接编辑（base_url/model/key）+ 清 key ──
function currentConn() {
  const id = els.connSec.dataset.id;
  return (configState.profiles || []).find((x) => x.id === id) || null;
}

function openConn(id) {
  const p = (configState.profiles || []).find((x) => x.id === id);
  if (!p) return;
  const t = tplById(p.template_id);
  const capSrc = profileCapabilitySource(p, t);
  const editable = t ? t.base_url_editable : true;
  const selected = id === configState.active_id;
  els.connSec.dataset.id = id;
  els.connTitle.textContent = "编辑连接 · " + p.name + (selected ? "（当前选择）" : "");
  els.connCatalogMeta.textContent = "尚未探测模型。";
  els.connBase.value = p.base_url || (t ? t.base_url : "");
  els.connBase.readOnly = !editable;
  els.connBase.placeholder = capSrc && (capSrc.api_format === "openai_chat" || capSrc.api_format === "openai_responses")
    ? "https://open.bigmodel.cn/api/paas/v4"
    : "https://your-relay/claude";
  els.connBaseHint.textContent = editable
    ? (t && t.base_url
        ? "官方默认地址，可改到 token 套餐 / 区域端点。"
        : (capSrc && capSrc.api_format === "openai_chat"
          ? "OpenAI 兼容 base root，代理自动补 /chat/completions。"
          : capSrc && capSrc.api_format === "openai_responses"
          ? "OpenAI 兼容 base root，代理自动补 /responses。"
          : "自定义端点根地址。"))
    : (modelCapability(capSrc) === CAP.NATIVE
        ? "模板地址（只读）；模型名称可从推荐中选择或自由填写。"
        : "模板地址（只读）。模型名称可自由填写。");
  applyModelCapability(capSrc, {
    info: els.connModelInfo, sel: els.connModel, hint: els.connModelHint, fetchBtn: els.connFetchBtn,
  }, p.model || "");
  initializeCatalogEditor(
    "connection",
    (p.model_catalog || []).map((route) => ({
      origin: (t?.recommended_catalog || []).some((recommended) => recommended.upstream_model === route.upstream_model) ? "preset" : "manual",
      availability: "unknown",
      ...route,
    })),
    p.default_model_route_id || p.model,
    p.role_bindings
  );
  els.connKey.value = "";
  els.connKey.placeholder = p.key ? "已存：" + p.key + "（留空＝不改）" : "粘贴 key（只存本地）";
  showView("conn");
  refreshConnGate();
  setMsg(selected
    ? "编辑当前选择：保存只更新候选连接；当前运行链保持不变，下次一键开始时核验并应用。"
    : "编辑连接后点「保存连接」。");
}

function refreshConnGate() {
  const p = currentConn();
  let invalidCatalog = false;
  if (p) {
    try { catalogSubmission("connection"); } catch (_) { invalidCatalog = true; }
  }
  els.connSaveBtn.disabled = busy || !p || invalidCatalog;
}

async function connFetch() {
  const p = currentConn();
  if (!p) return;
  const t = tplById(p.template_id);
  const capSrc = p.capabilities ? p : t;
  if (!canFetchModels(capSrc)) return;
  setBusy(true, { kind: "fetchModels", id: p.id });
  startFetchModelsFeedback(p.id);
  try {
    const r = await call("fetch_models", {
      req: {
        template_id: p.template_id,
        api_format: p.api_format || (t ? t.api_format : ""),
        base_url: els.connBase.value.trim(),
        key: els.connKey.value.trim(),
        profile_id: p.id,
      },
    });
    renderStaticCatalogDiscovery("connection", r);
  } catch (e) {
    setMsg("获取模型失败：" + runtimeCommandErrorText(e), "err");
  } finally {
    setBusy(false);
    refreshConnGate();
  }
}

async function connSave() {
  const p = currentConn();
  if (!p) { setMsg("配置不存在。", "err"); return; }
  const t = tplById(p.template_id);
  const capSrc = profileCapabilitySource(p, t);
  let catalogPayload;
  try { catalogPayload = catalogSubmission("connection"); }
  catch (error) { setMsg(String(error.message || error), "err"); return; }
  const editable = t ? t.base_url_editable : true;
  const base = editable ? els.connBase.value.trim() : (t ? t.base_url : els.connBase.value.trim());
  // base_url 是否必填由后端 capabilities 决定；旧后端无字段时才按可编辑地址保守兜底。
  if (baseUrlRequired(capSrc) && !base) { setMsg("中转 / 自定义端点必须填写连接地址（base_url）。", "err"); return; }
  const baseErr = openaiCustomAnthropicBaseMessage(t, base);
  if (baseErr) { setMsg(baseErr, "err"); return; }
  const selected = p.id === configState.active_id;
  // key 留空＝不改；目录三件套必须一起提交，避免漏字段被解释为重置默认/roles。
  const args = {
    id: p.id,
    baseUrl: base,
    key: els.connKey.value.trim(),
    modelCatalog: catalogPayload.model_catalog,
    defaultModelRouteId: catalogPayload.default_model_route_id,
    roleBindings: catalogPayload.role_bindings,
  };
  setBusy(true, { kind: "saveConnection", id: p.id });
  startSaveConnectionFeedback(p.id, selected);
  try {
    const r = await call("update_profile_connection", args);
    els.connKey.value = "";
    await loadConfig();
    if (r && (r.status === "error" || r.committed === false)) {
      const recovery = r.recovery_status === "degraded" ? "；恢复也未完全成功，请先全部停止后检查" : r.recovery_status === "restored" ? "；旧配置已恢复" : "";
      setMsg((r.message || "连接未应用") + recovery + "（阶段：" + (r.stage || "unknown") + "）", "err");
    } else if (selected) {
      setMsg((r && (r.message || r.hint)) || "已保存连接；当前运行链保持不变，下次一键开始时应用。", "ok");
    } else if (r && r.validated) {
      setMsg("已保存连接（已通过上游校验）。", "ok");
    } else {
      setMsg("已保存连接（未能连通上游校验；下次一键开始时会再验并应用）。", "ok");
    }
  } catch (e) {
    // 后端错误文案已如实说明回滚/代理状态（可能是「已回滚到原配置」或「回滚未成功：代理当前已停」），
    // 前端不再盲目追加「仍在用原配置运行」，避免与「代理已停」相互矛盾。修 GPT 三轮 P2
    setMsg("连接未保存：" + runtimeCommandErrorText(e), "err");
  } finally {
    setBusy(false);
    await refreshStatus();
    await skillPage?.refreshIfLoaded();
  }
}

// 清 key（行内 / 连接表单都可触发）：二次确认后 clear_profile_key。
function clearKey(id) {
  const p = (configState.profiles || []).find((x) => x.id === id);
  const nm = p ? p.name : id;
  confirmAction("clearkey:" + id, "将清除「" + nm + "」的 API key（需重填才能用）", () => doClearKey(id));
}
async function doClearKey(id) {
  const wasSelected = id === configState.active_id;
  const wasApplied = id === configState.applied_profile_id;
  setBusy(true);
  setMsg("清除 key 中…");
  try {
    await call("clear_profile_key", { id });
    await loadConfig();
    setMsg(
      wasApplied
        ? "已清除 key（该配置属于上次提交的运行绑定，代理已停止；请重新填写并一键开始）。"
        : wasSelected
        ? "已清除当前选择的 key；当前运行链保持不变，重新填写后再一键开始。"
        : "已清除 key。",
      "ok"
    );
  } catch (e) {
    setMsg("清除失败：" + e, "err");
  } finally {
    setBusy(false);
    await refreshStatus();
  }
}

// ── C4：改名/备注 + 删除 + 设为当前 ──
function openMeta(id) {
  const p = (configState.profiles || []).find((x) => x.id === id);
  if (!p) return;
  els.metaSec.dataset.id = id;
  els.metaName.value = p.name;
  els.metaNotes.value = p.notes || "";
  showView("meta");
  setMsg("改名 / 备注不影响运行中的代理。");
}
async function metaSave() {
  const id = els.metaSec.dataset.id;
  const name = els.metaName.value.trim();
  if (!name) { setMsg("名称不能为空。", "err"); return; }
  const notes = els.metaNotes.value.trim();
  setBusy(true);
  setMsg("保存中…");
  try {
    await call("update_profile_metadata", { id, name, notes });
    await loadConfig();
    setMsg("已保存。", "ok");
  } catch (e) {
    setMsg("保存失败：" + e, "err");
  } finally {
    setBusy(false);
  }
}

function del(id) {
  const p = (configState.profiles || []).find((x) => x.id === id);
  const nm = p ? p.name : id;
  confirmAction("delete:" + id, "将删除配置「" + nm + "」", () => doDelete(id));
}
async function doDelete(id) {
  const wasSelected = id === configState.active_id;
  const wasApplied = id === configState.applied_profile_id;
  setBusy(true);
  setMsg("删除中…");
  try {
    await call("delete_profile", { id });
    await loadConfig();
    setMsg(
      wasApplied
        ? "已删除上次提交的运行绑定配置，相关代理已停止。"
        : wasSelected
        ? "已删除当前选择，请重新选择一条并「设为当前」。"
        : "已删除。",
      "ok"
    );
  } catch (e) {
    setMsg("删除失败：" + e, "err");
  } finally {
    setBusy(false);
    await refreshStatus();
  }
}

// 设为当前只保存选择；真正 apply/start 的唯一边界是一键开始。
async function activate(id) {
  if (activationInFlight) {
    setMsg("当前选择仍在保存。请稍后再提交另一条配置。");
    return;
  }
  setActivationInFlight(true, { kind: "activate", id });
  startActivateFeedback(id);
  try {
    const r = await call("set_active_profile", { id });
    if (r && r.committed) {
      hideHistoryRecovery();
      await loadConfig();
      if (r.apply_state === "pending") {
        configState.selection_pending = true;
        renderList();
      }
      setMsg(r.hint || "已设为当前选择，待一键开始应用。", "ok");
    } else {
      await loadConfig();
      setMsg((r && (r.message || r.hint)) || "当前选择未更改。", "err");
    }
  } catch (e) {
    await loadConfig();
    setMsg("设为当前失败：" + runtimeCommandErrorText(e), "err");
  } finally {
    setActivationInFlight(false);
    await refreshStatus();
  }
}

function hideRuntimeChoice() {
  els.runtimeChoiceSec.hidden = true;
  els.runtimeChoiceText.textContent = "";
  runtimeChoiceActiveId = null;
}

function showRuntimeChoice(preflight) {
  const cachedVersion = preflight && preflight.cached_version;
  const canUseCache = preflight && preflight.status === "cached_choice_required" && !!cachedVersion;
  els.runtimeUseCacheBtn.hidden = !canUseCache;
  els.runtimeChoiceText.textContent = canUseCache
    ? "未找到通过安全预检的 Claude Science App。发现可确认版本的历史缓存：" + cachedVersion + "。你可以仅本次使用它，或前往官方页面安装 / 更新 Science。此选择不会保存。"
    : "未找到通过安全预检的 Claude Science App，历史缓存也无法确认版本。请先从官方页面安装 / 更新 Science。";
  els.runtimeChoiceSec.hidden = false;
  runtimeChoiceActiveId = configState.active_id || null;
}

function hideHistoryRecovery() {
  els.historyRecoverySec.hidden = true;
  els.historyRecoveryText.textContent = "";
  els.historyRecoveryChoices.replaceChildren();
}

function showHistoryRecovery(result) {
  const choices = Array.isArray(result && result.choices) ? result.choices : [];
  els.historyRecoveryChoices.replaceChildren();
  choices.forEach((choice) => {
    if (!choice || typeof choice.reference !== "string" || !choice.reference) return;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn primary";
    button.dataset.historyReference = choice.reference;
    button.textContent = typeof choice.label === "string" && choice.label
      ? choice.label
      : "历史记录";
    els.historyRecoveryChoices.appendChild(button);
  });
  els.historyRecoveryText.textContent =
    "检测到多份 v0.8.0 遗留历史。请选择要恢复的一份；CSSwitch 不会读取对话内容，也不会删除其他记录。若打开后发现选错，可在本次应用运行期间返回这里改选。";
  els.historyRecoverySec.hidden = false;
}

async function restoreHistoryChoice(reference) {
  if (!reference || busy) return;
  setBusy(true, { kind: "historyRecovery" });
  setMsg("正在重新核验并恢复所选历史记录…");
  let restored = false;
  try {
    const result = await call("restore_history_choice", { reference });
    if (result && Array.isArray(result.choices)) showHistoryRecovery(result);
    setMsg(result && result.message || "已恢复所选历史记录。", "ok");
    restored = true;
  } catch (e) {
    setMsg("恢复历史记录失败：" + e, "err");
  } finally {
    setBusy(false);
  }
  if (restored) await runOneClick(null);
}

async function checkOneClickBoundary() {
  if (activationInFlight) {
    setMsg("当前选择仍在保存。请等待完成后再一键开始。", "err");
    return false;
  }
  if (!configState.active_id) {
    setMsg("还没有「当前选择」的配置。请先点「新建配置」或在列表点「设为当前」选一条，再一键开始。", "err");
    return false;
  }
  return true;
}

async function runOneClick(runtimeChoice) {
  if (runtimeChoice) {
    if (!runtimeChoiceActiveId || runtimeChoiceActiveId !== configState.active_id) {
      hideRuntimeChoice();
      setMsg("当前选择已变化，本次缓存运行选择已作废。请重新点击「一键开始」。", "err");
      return;
    }
  }
  if (!(await checkOneClickBoundary())) return;
  skillPage?.invalidate();
  hideRuntimeChoice();
  setBusy(true, { kind: "oneClick" });
  setBrowserFallback("");
  startOneClickFeedback();
  try {
    const r = await call("one_click_login", { runtimeChoice: runtimeChoice || null });
    if (r && r.status === "attention" && r.action === "history_choice_required") {
      showHistoryRecovery(r);
      setMsg(r.msg || "请选择要恢复的历史记录。", "err");
      await refreshStatus();
      return;
    }
    if (r && r.status === "error") {
      const recovery = r.recovery_status === "degraded"
        ? "；刷新未完成，安全事务记录已保留，可修正问题后重试"
        : "";
      setMsg((r.message || "一键开始未完成") + recovery + "（阶段：" + (r.stage || "unknown") + "）", "err");
      setBrowserFallback(r.fallback_url);
      await refreshStatus();
      return;
    }
    // 透传后端据实回传的 msg（已重开 / 已用新配置重启 / 沿用原对话 / 已启动 / 打开失败请手动打开）。
    const message = r.msg || "已就绪，正在打开面板…";
    if (!els.historyRecoverySec.hidden) {
      els.historyRecoveryText.textContent =
        "已打开所选历史。如果内容不对，可在本次应用运行期间选择另一份；切换前 CSSwitch 会先安全停止隔离 Science。";
    }
    setMsg(message, "ok");
    setBrowserFallback(r.fallback_url);
    configState.selection_pending = false;
    configState.applied_profile_id = configState.active_id || null;
    renderList();
    await refreshStatus();
  } catch (e) {
    setMsg("一键开始失败：" + runtimeCommandErrorText(e), "err");
  } finally {
    setBusy(false);
    await skillPage?.refreshIfLoaded();
  }
}

async function importLocalSkill() {
  if (busy) return;
  setBusy(true, { kind: "importSkill" });
  setMsg("正在选择并校验 Skill 包…");
  try {
    const result = await call("install_local_skill_package");
    if (result.status === "CANCELLED") {
      setMsg("已取消导入 Skill 包。");
    } else if (result.status === "INSTALLED_ATTACHED_VERIFY_REQUIRED") {
      setMsg("文件已安装并绑定 OPERON。请在 Science 中让 Agent 调用 skill(" + result.skill_name + ") 验证当前会话加载。", "ok");
    } else if (result.status === "BUNDLE_INSTALLED_ATTACHED") {
      const names = Array.isArray(result.skill_names) ? result.skill_names : [];
      const summary = names.slice(0, 4).join("、") + (names.length > 4 ? " 等" : "");
      setMsg("已安装并绑定 " + names.length + " 个 Skill" + (summary ? "：" + summary : "") + "。", "ok");
    } else {
      setMsg((result.message || "Skill 包导入未完成") + " [" + result.status + "]", "err");
    }
    if (result && result.directory_commit === true && skillPage) {
      await skillPage.refresh();
    }
  } catch (e) {
    setMsg("导入 Skill 包失败：" + e, "err");
    await skillPage?.refreshIfLoaded();
  } finally {
    setBusy(false);
  }
}

// ── 一键开始：先确认本次实际 Science runtime，再进入原启动链路。──
async function oneClick() {
  if (!(await checkOneClickBoundary())) return;
  setBusy(true, { kind: "oneClick" });
  setMsg("正在确认本次使用的 Claude Science…");
  try {
    const preflight = await call("science_runtime_preflight");
    if (preflight && preflight.status === "installed_ready") {
      setBusy(false);
      await runOneClick(null);
      return;
    }
    showRuntimeChoice(preflight || { status: "missing" });
    setMsg(preflight && preflight.status === "cached_choice_required"
      ? "Claude Science App 不可用或未通过预检。请选择是否仅本次使用已确认版本的缓存。"
      : "Claude Science App 不可用或未通过预检，且没有可安全启动的缓存版本。", "err");
  } catch (e) {
    setMsg("Science 运行环境检查失败：" + e, "err");
  } finally {
    setBusy(false);
  }
}

async function openScienceDownload() {
  try {
    await call("open_science_download_page");
    setMsg("已打开 Claude 官方下载页。安装完成后请再次点击「一键开始」。");
  } catch (e) {
    setMsg("打开 Claude 官方下载页失败：" + e, "err");
  }
}

function cancelRuntimeChoice() {
  hideRuntimeChoice();
  setMsg("已取消，本次没有启动 Claude Science。");
}

async function stopAll() {
  skillPage?.invalidate();
  setBusy(true);
  setMsg("停止中…");
  try {
    const summary = await call("stop_all");
    setMsg("已停止代理与沙箱。" + (summary ? summary : ""), "ok");
    await refreshStatus();
  } catch (e) {
    setMsg("停止失败：" + e, "err");
  } finally {
    setBusy(false);
    await skillPage?.refreshIfLoaded();
  }
}

async function openBrowser() {
  if (busy || browserOpenInFlight) return;
  browserOpenInFlight = true;
  syncOpenBrowserControl();
  setMsg("正在获取新的 Science 地址并交给默认浏览器打开…");
  try {
    const result = await call("open_url");
    if (result && result.status === "error") {
      setBrowserFallback(result.fallback_url);
      setMsg(result.message || "打开浏览器失败；请复制 URL 手动打开。", "err");
    } else {
      setBrowserFallback("");
      setMsg((result && result.message) || "已向默认浏览器发出打开 Science 的请求；若窗口没有切到前台，请从 Dock 或其他桌面切回默认浏览器。", "ok");
    }
  } catch (e) {
    setMsg("打开浏览器失败：" + e, "err");
  } finally {
    browserOpenInFlight = false;
    syncOpenBrowserControl();
  }
}

async function runDoctor() {
  const activationBusy = activationInFlight || (busy && busyOp && busyOp.kind === "activate");
  if (doctorInFlight || (busy && !activationBusy)) return;
  doctorInFlight = true;
  if (els.doctorBtn) els.doctorBtn.disabled = true;
  if (activationBusy) {
    setMsg("自检中：配置后台应用仍在继续。完成后会核验 CSSwitch 管理的 Skill 路由。");
  } else {
    setBusy(true, { kind: "doctor" });
    startDoctorFeedback();
  }
  try {
    const out = await call("run_doctor");
    setMsg(out, out.includes("失败 0") ? "ok" : null);
  } catch (e) {
    setMsg("自检失败：" + e, "err");
  } finally {
    doctorInFlight = false;
    if (els.doctorBtn) els.doctorBtn.disabled = busy && busyOp && busyOp.kind !== "activate";
    if (!activationBusy) setBusy(false);
  }
}

// 简单 semver 比较：a 是否比 b 新。
function isNewer(a, b) {
  const pa = String(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x > y;
  }
  return false;
}

async function checkUpdate() {
  setMsg("检查更新中…");
  let cur = "";
  try { cur = await call("app_version"); } catch (e) {}
  try {
    const resp = await fetch(
      "https://api.github.com/repos/SuperJJ007/CSSwitch/releases/latest",
      { headers: { Accept: "application/vnd.github+json" } }
    );
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    const latest = (data.tag_name || "").replace(/^v/, "");
    if (!latest) throw new Error("无版本信息");
    if (isNewer(latest, cur)) {
      setMsg("发现新版本 v" + latest + "（当前 v" + cur + "）。正在打开下载页…", "ok");
      try { await call("open_release_page"); } catch (_) {}
    } else {
      setMsg("已是最新版本（v" + cur + "）。", "ok");
    }
  } catch (e) {
    setMsg("无法自动检查更新（多为网络或代理限制）。已打开 Releases 页，请手动查看。", "err");
    try { await call("open_release_page"); } catch (_) {}
  }
}

async function refreshStatus() {
  try {
    const s = await call("status");
    setLight(els.ltProxy, s.proxy);
    setLight(els.ltSandbox, s.sandbox);
    setLight(els.ltUpstream, s.upstream);
    setStatusText("proxyStateText", s.proxy);
    setStatusText("sandboxStateText", s.sandbox);
    setStatusText("upstreamStateText", s.upstream);
    els.brandDot.className = "dot " + aggregateRuntimeStatus(s, { mode, officialState: officialRuntimeState });
    setStatusRecoveryMsg(proxyRecoveryMessage(s));
  } catch (e) {
    [els.ltProxy, els.ltSandbox, els.ltUpstream].forEach((l) => setLight(l, "unknown"));
    ["proxyStateText", "sandboxStateText", "upstreamStateText"].forEach((id) => setStatusText(id, "unknown"));
    els.brandDot.className = "dot gray";
  }
}

function wire() {
  [
    "oneClickBtn", "stopBtn", "importSkillBtn", "refreshSkillsBtn", "ltProxy", "ltSandbox", "ltUpstream",
    "runtimeChoiceSec", "runtimeChoiceText", "runtimeUseCacheBtn", "runtimeDownloadBtn", "runtimeChoiceCancelBtn",
    "historyRecoverySec", "historyRecoveryText", "historyRecoveryChoices", "historyRecoveryCancelBtn",
    "msg", "browserFallback", "browserFallbackUrl", "browserFallbackCopyBtn", "browserFallbackRetryBtn", "brandDot", "openBrowserBtn", "doctorBtn", "updateBtn", "verLabel",
    "reportBtn", "logsBtn", "exportDiagBtn", "quitBtn", "modeSeg", "proxyPort", "sandboxPort", "reuseSystemSsh", "advSec",
    "connectionOverview", "listSec", "profileList", "newBtn",
    "wizSec", "wizTemplate", "wizTemplateChips", "wizTplLabel", "wizTplHint", "wizName", "wizBaseGroup", "wizBase", "wizBaseHint",
    "wizModelGroup", "wizModelLabel", "wizFetchBtn", "wizModelInfo", "wizModel", "wizModelHint", "wizCatalogMeta", "wizStaticCatalog", "wizRoleQuality", "wizRoleFast", "wizRoleFable", "wizCatalogWarning", "wizKeyGroup", "wizKey", "wizSaveBtn", "wizCancelBtn",
    "connSec", "connTitle", "connBaseGroup", "connBase", "connBaseHint", "connFetchBtn",
    "connModelGroup", "connModelLabel", "connModelInfo", "connModel", "connModelHint", "connCatalogMeta", "connStaticCatalog", "connRoleQuality", "connRoleFast", "connRoleFable", "connCatalogWarning", "connKeyGroup", "connKey", "connSaveBtn", "connClearBtn", "connCancelBtn",
    "metaSec", "metaName", "metaNotes", "metaSaveBtn", "metaCancelBtn",
    "themeBtn", "pageEyebrow", "pageTitle", "pageSubtitle",
    "currentProfileIcon", "currentProfileName", "currentProfileState", "currentRouteMode", "currentProfileModel", "currentProfileMeta",
    "proxyStateText", "sandboxStateText", "upstreamStateText",
  ].forEach((id) => (els[id] = $(id)));
  els.panel = document.querySelector(".panel");

  document.querySelectorAll("[data-page-target]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.pageTarget === "switch") showView("list");
      setPage(button.dataset.pageTarget);
    });
  });
  applyTheme(savedTheme() || document.documentElement.dataset.theme || "light", { persist: false });
  els.themeBtn.addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));

  els.modeSeg.querySelectorAll(".seg-btn").forEach((b) =>
    b.addEventListener("click", () => switchMode(b.dataset.mode))
  );

  els.proxyPort.addEventListener("change", persistRuntimeSettings);
  els.sandboxPort.addEventListener("change", persistRuntimeSettings);
  els.reuseSystemSsh.addEventListener("change", persistRuntimeSettings);

  // 列表行内操作（事件委托；忙碌时忽略）。
  els.profileList.addEventListener("click", (e) => {
    if (busy) return;
    const btn = e.target.closest("[data-act]");
    const row = e.target.closest("[data-id]");
    if (!btn || !row || btn.disabled || btn.dataset.permanentlyDisabled === "true") return;
    const id = row.getAttribute("data-id");
    const act = btn.getAttribute("data-act");
    if (act === "activate") activate(id);
    else if (act === "editconn") openConn(id);
    else if (act === "editmeta") openMeta(id);
    else if (act === "clearkey") clearKey(id);
    else if (act === "delete") del(id);
  });

  // 浏览器交互预览可单独启用模型下拉；真实 App 始终使用后端已保存模型。
  els.profileList.addEventListener("change", (e) => {
    const select = e.target.closest("[data-profile-model]");
    if (!select || !PROFILE_INTERACTIVE_PREVIEW) return;
    const id = select.getAttribute("data-profile-model");
    const model = select.value;
    const profile = (configState.profiles || []).find((item) => item.id === id);
    const stored = (mockStore.profiles || []).find((item) => item.id === id);
    if (!profile || !stored) return;
    profile.model = model;
    stored.model = model;
    renderList();
    setMsg(`预览：已将「${profile.name}」的模型设为 ${model}。`, "ok");
  });

  els.newBtn.addEventListener("click", openWizard);
  els.wizTemplateChips.addEventListener("click", (e) => {
    if (busy) return;
    const chip = e.target.closest(".chip");
    if (chip) selectWizTemplate(chip.getAttribute("data-tid"));
  });
  [els.wizModel, els.wizRoleQuality, els.wizRoleFast, els.wizRoleFable]
    .forEach((input) => input.addEventListener("input", () => catalogRolesChanged("wizard")));
  els.wizFetchBtn.addEventListener("click", wizFetch);
  els.wizSaveBtn.addEventListener("click", wizSave);
  els.wizCancelBtn.addEventListener("click", cancelForm);

  [els.connModel, els.connRoleQuality, els.connRoleFast, els.connRoleFable]
    .forEach((input) => input.addEventListener("input", () => catalogRolesChanged("connection")));
  els.connFetchBtn.addEventListener("click", connFetch);
  els.connSaveBtn.addEventListener("click", connSave);
  els.connClearBtn.addEventListener("click", () => clearKey(els.connSec.dataset.id));
  els.connCancelBtn.addEventListener("click", cancelForm);

  els.metaSaveBtn.addEventListener("click", metaSave);
  els.metaCancelBtn.addEventListener("click", cancelForm);

  els.oneClickBtn.addEventListener("click", heroClick);
  els.runtimeUseCacheBtn.addEventListener("click", () => runOneClick("cached_once"));
  els.runtimeDownloadBtn.addEventListener("click", openScienceDownload);
  els.runtimeChoiceCancelBtn.addEventListener("click", cancelRuntimeChoice);
  els.historyRecoveryChoices.addEventListener("click", (event) => {
    const button = event.target.closest("[data-history-reference]");
    if (button) restoreHistoryChoice(button.dataset.historyReference);
  });
  els.historyRecoveryCancelBtn.addEventListener("click", hideHistoryRecovery);
  els.stopBtn.addEventListener("click", stopAll);
  els.importSkillBtn.addEventListener("click", importLocalSkill);
  els.openBrowserBtn.addEventListener("click", openBrowser);
  els.browserFallbackRetryBtn.addEventListener("click", openBrowser);
  els.browserFallbackCopyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(els.browserFallbackUrl.value);
      setMsg("Science URL 已复制。", "ok");
    } catch (_) {
      els.browserFallbackUrl.select();
      setMsg("无法自动写入剪贴板；已选中 URL，请手动复制。", "err");
    }
  });
  els.doctorBtn.addEventListener("click", runDoctor);
  els.updateBtn.addEventListener("click", checkUpdate);
  els.reportBtn.addEventListener("click", () =>
    call("report_bug").catch((e) => setMsg("打开反馈页失败：" + e, "err"))
  );
  els.logsBtn.addEventListener("click", () =>
    call("open_logs").catch((e) => setMsg("打开日志失败：" + e, "err"))
  );
  els.exportDiagBtn.addEventListener("click", async () => {
    els.exportDiagBtn.disabled = true;
    setMsg("正在打包诊断日志（自动脱敏 API Key）…");
    try {
      const path = await call("export_diagnostics");
      setMsg("诊断包已导出（已自动脱敏，可直接发给支持渠道）：" + path);
    } catch (e) {
      setMsg("导出诊断包失败：" + e, "err");
    } finally {
      els.exportDiagBtn.disabled = false;
    }
  });
  els.quitBtn.addEventListener("click", () => {
    setBusy(true);
    setMsg("正在停止代理与隔离 Science…");
    call("quit_app").catch((e) => {
      setBusy(false);
      setMsg("退出失败：" + e + "请先使用“全部停止”重试。", "err");
    });
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  wire();
  await configureDesktopWindow();
  try {
    const { mountSkillPage } = await import("./skill-page.js");
    skillPage = mountSkillPage($("skillPageRoot"), {
      call,
      refreshButton: els.refreshSkillsBtn,
      importButton: els.importSkillBtn,
    });
  } catch (e) {
    $("skillPageRoot").innerHTML = '<div class="skill-loading">Skill 页面载入失败：' + escapeHtml(e) + "</div>";
  }
  setPage(SKILLS_PREVIEW ? "skills" : "switch");
  await loadConfig();
  if (!PREVIEW && window.__TAURI__.event) {
    try {
      await Promise.all([
        window.__TAURI__.event.listen("boot://failed", (e) => {
          setMsg("自动启动未成功：" + (e.payload || "未知原因") + "\n可检查配置后点「一键开始」重试。", "err");
          refreshStatus();
        }),
        window.__TAURI__.event.listen("boot://attention", (e) => {
          if (e.payload && e.payload.action === "history_choice_required") {
            showHistoryRecovery(e.payload);
            setMsg(e.payload.msg || "自动启动需要先选择要恢复的历史记录。", "err");
          }
          refreshStatus();
        }),
      ]);
    } catch (e) {
      setMsg("无法订阅自动启动状态：" + e, "err");
    }
  }
  try {
    const bootError = await call("boot_error");
    if (bootError) setMsg("自动启动未成功：" + bootError + "\n可检查配置后点「一键开始」重试。", "err");
  } catch (e) {}
  try {
    const attention = await call("boot_attention");
    if (attention && attention.action === "history_choice_required") {
      showHistoryRecovery(attention);
      setMsg(attention.msg || "自动启动需要先选择要恢复的历史记录。", "err");
    }
  } catch (e) {}
  try { els.verLabel.textContent = "v" + (await call("app_version")); } catch (e) {}
  await refreshStatus();
  if (!PREVIEW) statusTimer = setInterval(refreshStatus, 2500);
});
