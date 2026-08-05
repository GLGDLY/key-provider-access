(() => {
  "use strict";

  const PATHS = {
    status: "/v0/management/plugins/key-model-access/status",
    policies: "/v0/management/plugins/key-model-access/policies",
    reload: "/v0/management/plugins/key-model-access/reload",
    apiKeys: "/v0/management/api-keys"
  };

  const icons = {
    eye: '<svg viewBox="0 0 24 24"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>',
    eyeOff: '<svg viewBox="0 0 24 24"><path d="m3 3 18 18M10.6 6.1A10.5 10.5 0 0 1 12 6c6 0 9.5 6 9.5 6a16 16 0 0 1-2.1 2.8M6.2 6.2C3.8 8 2.5 12 2.5 12s3.5 6 9.5 6c1.2 0 2.3-.2 3.3-.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>',
    search: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>',
    overview: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg>',
    key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M15 12v2"/></svg>',
    refresh: '<svg viewBox="0 0 24 24"><path d="M20 6v5h-5M4 18v-5h5"/><path d="M6.1 8.2A7 7 0 0 1 18.8 9M17.9 15.8A7 7 0 0 1 5.2 15"/></svg>',
    file: '<svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></svg>',
    save: '<svg viewBox="0 0 24 24"><path d="M5 4h12l2 2v14H5z"/><path d="M8 4v6h8V4M8 20v-6h8v6"/></svg>',
    sun: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.5"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    moon: '<svg viewBox="0 0 24 24"><path d="M20 15.2A8 8 0 0 1 8.8 4 8.2 8.2 0 1 0 20 15.2Z"/></svg>',
    logout: '<svg viewBox="0 0 24 24"><path d="M10 5H5v14h5M14 8l4 4-4 4M8 12h10"/></svg>',
    close: '<svg viewBox="0 0 24 24"><path d="m7 7 10 10M17 7 7 17"/></svg>',
    warning: '<svg viewBox="0 0 24 24"><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4M12 16.5h.01"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>',
    spinner: '<svg class="spinner" viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-9 9"/><path d="M3 12a9 9 0 0 1 9-9" opacity=".35"/></svg>'
  };

  const state = {
    token: "",
    status: null,
    keys: [],
    stalePolicies: [],
    revision: 0,
    selectedIndex: -1,
    dirty: false,
    busy: false,
    search: ""
  };

  const $ = (selector) => document.querySelector(selector);
  const authGate = $("#authGate");
  const app = $("#app");
  const editor = $("#editor");
  const nav = $("#policyNav");
  const saveButton = $("#saveButton");
  const reloadButton = $("#reloadButton");
  const refreshDataButton = $("#refreshDataButton");
  const healthBadge = $("#healthBadge");
  let navFrame = 0;

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
    })[character]);
  }

  function normalizeModels(value) {
    if (!Array.isArray(value)) return [];
    return [...new Set(value.map((model) => String(model).trim()).filter(Boolean))];
  }

  function normalizePolicyDocument(raw) {
    if (!raw || typeof raw !== "object" || raw.version !== 2 || !Array.isArray(raw.policies)) {
      throw new Error("插件返回了无效的 v2 策略文档。");
    }
    const seen = new Set();
    const policies = raw.policies.map((item, index) => {
      if (!item || typeof item !== "object") throw new Error(`策略 ${index + 1} 格式无效。`);
      const scope = typeof item.caller_scope === "string" ? item.caller_scope.trim().toLowerCase() : "";
      if (!/^[0-9a-f]{64}$/.test(scope)) throw new Error(`策略 ${index + 1} 的 caller scope 无效。`);
      if (seen.has(scope)) throw new Error(`策略 ${index + 1} 的 caller scope 重复。`);
      seen.add(scope);
      for (const field of ["allow_models", "deny_models"]) {
        if (!Array.isArray(item[field]) || item[field].some((model) => typeof model !== "string" || !model.trim())) {
          throw new Error(`策略 ${index + 1} 的 ${field} 无效。`);
        }
      }
      return {
        caller_scope: scope,
        allow_models: normalizeModels(item.allow_models),
        deny_models: normalizeModels(item.deny_models)
      };
    });
    return { version: 2, policies };
  }

  function shortFingerprint(scope) {
    return `${scope.slice(0, 10)}…${scope.slice(-6)}`;
  }

  function keyLabel(index) {
    return `CPA API Key ${String(index + 1).padStart(2, "0")}`;
  }

  async function api(path, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const timeout = options.timeout || (method === "GET" ? 12000 : 20000);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, {
        ...options,
        method,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${state.token}`,
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...(options.headers || {})
        },
        cache: "no-store"
      });
      let payload = null;
      try { payload = await response.json(); } catch (_) { payload = null; }
      if (!response.ok) {
        const detail = payload && (payload.error?.message || payload.error);
        const error = new Error(detail ? String(detail) : `请求失败（HTTP ${response.status}）`);
        error.status = response.status;
        throw error;
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") {
        const timeoutError = new Error(method === "GET" ? "CPA 响应超时，请检查服务状态。" : "操作响应超时，提交结果尚未确认。");
        timeoutError.code = "timeout";
        throw timeoutError;
      }
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function sha256Hex(value) {
    const bytes = new TextEncoder().encode(value);
    if (window.crypto?.subtle) {
      const digest = await window.crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    // SubtleCrypto is unavailable on plain HTTP origins other than localhost.
    // Keep remote CPA panels functional without sending raw API keys elsewhere.
    return sha256FallbackHex(bytes);
  }

  function sha256FallbackHex(bytes) {
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const stateWords = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLength);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const bitLength = bytes.length * 8;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(paddedLength - 4, bitLength >>> 0, false);
    const words = new Uint32Array(64);
    const rotateRight = (word, count) => (word >>> count) | (word << (32 - count));

    for (let offset = 0; offset < paddedLength; offset += 64) {
      for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(offset + index * 4, false);
      for (let index = 16; index < 64; index += 1) {
        const left = words[index - 15];
        const right = words[index - 2];
        const sigma0 = rotateRight(left, 7) ^ rotateRight(left, 18) ^ (left >>> 3);
        const sigma1 = rotateRight(right, 17) ^ rotateRight(right, 19) ^ (right >>> 10);
        words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = stateWords;
      for (let index = 0; index < 64; index += 1) {
        const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
        const choose = (e & f) ^ (~e & g);
        const temp1 = (h + sum1 + choose + constants[index] + words[index]) >>> 0;
        const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (sum0 + majority) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      stateWords[0] = (stateWords[0] + a) >>> 0;
      stateWords[1] = (stateWords[1] + b) >>> 0;
      stateWords[2] = (stateWords[2] + c) >>> 0;
      stateWords[3] = (stateWords[3] + d) >>> 0;
      stateWords[4] = (stateWords[4] + e) >>> 0;
      stateWords[5] = (stateWords[5] + f) >>> 0;
      stateWords[6] = (stateWords[6] + g) >>> 0;
      stateWords[7] = (stateWords[7] + h) >>> 0;
    }
    return stateWords.map((word) => word.toString(16).padStart(8, "0")).join("");
  }

  async function fetchCurrentKeys() {
    const payload = await api(PATHS.apiKeys, { method: "GET" });
    const values = Array.isArray(payload?.["api-keys"]) ? payload["api-keys"] : null;
    if (!values) throw new Error("CPA 返回了无法识别的 API Key 列表。");

    const temporaryValues = values.slice();
    const normalizedValues = temporaryValues.map((value) => String(value).trim()).filter(Boolean);
    try {
      const scopes = await Promise.all(normalizedValues.map((value) =>
        sha256Hex(`cli-proxy-api:caller-scope:v1\0${value}`)
      ));
      const seen = new Set();
      return scopes.filter((scope) => {
        if (seen.has(scope)) return false;
        seen.add(scope);
        return true;
      }).map((scope) => ({
        scope,
        fingerprint: shortFingerprint(scope),
        mask: "••••••••••••",
        allow_models: [],
        deny_models: []
      }));
    } finally {
      normalizedValues.fill("");
      temporaryValues.fill("");
      values.fill("");
    }
  }

  async function fetchRemoteData() {
    // Verify Management authentication once before issuing the remaining reads.
    const status = await api(PATHS.status, { method: "GET" });
    const [policies, keys] = await Promise.all([
      api(PATHS.policies, { method: "GET" }),
      fetchCurrentKeys()
    ]);
    return { status, policies, keys };
  }

  function applyPolicyDocument(rawDocument) {
    const documentValue = normalizePolicyDocument(rawDocument);
    const byScope = new Map(documentValue.policies.map((policy) => [policy.caller_scope, policy]));
    const currentScopes = new Set(state.keys.map((key) => key.scope));

    state.keys = state.keys.map((key) => {
      const policy = byScope.get(key.scope);
      return {
        ...key,
        allow_models: policy ? [...policy.allow_models] : [],
        deny_models: policy ? [...policy.deny_models] : []
      };
    });
    state.stalePolicies = documentValue.policies
      .filter((policy) => !currentScopes.has(policy.caller_scope))
      .map((policy) => ({ ...policy, allow_models: [...policy.allow_models], deny_models: [...policy.deny_models] }));
  }

  function installRemoteData(remote, preferredScope = "") {
    state.status = remote.status;
    state.keys = remote.keys;
    applyPolicyDocument(remote.policies?.policy);
    state.revision = Number(remote.policies?.revision ?? remote.status?.revision ?? 0);
    state.dirty = false;
    state.selectedIndex = preferredScope ? state.keys.findIndex((key) => key.scope === preferredScope) : -1;
  }

  async function connect(token) {
    state.token = token.trim();
    if (!state.token) return;
    setAuthBusy(true);
    $("#authError").textContent = "";
    try {
      const remote = await fetchRemoteData();
      installRemoteData(remote);
      $("#managementKey").value = "";
      authGate.hidden = true;
      app.hidden = false;
      renderAll();
      showToast("已安全连接到 CPA", "success");
    } catch (error) {
      state.token = "";
      $("#authError").textContent = error.status === 401 ? "Management Key 无效，请重新输入。" : error.message;
      $("#managementKey").focus();
    } finally {
      setAuthBusy(false);
    }
  }

  function disconnect() {
    if (state.dirty && !window.confirm("有尚未保存的模型规则。确定断开并放弃这些修改吗？")) return;
    state.token = "";
    state.status = null;
    state.keys = [];
    state.stalePolicies = [];
    state.revision = 0;
    state.selectedIndex = -1;
    state.dirty = false;
    $("#managementKey").value = "";
    app.hidden = true;
    authGate.hidden = false;
    $("#managementKey").focus();
  }

  function setAuthBusy(busy) {
    const button = $("#connectButton");
    button.disabled = busy;
    button.innerHTML = busy ? `${icons.spinner}<span>正在验证</span>` : "<span>连接到 CPA</span>";
  }

  function setBusy(busy, action = "") {
    state.busy = busy;
    $("#workspace").inert = busy;
    $("#disconnectButton").disabled = busy;
    refreshDataButton.disabled = busy;
    saveButton.disabled = busy || !state.dirty;
    reloadButton.disabled = busy || !state.status?.persistent_updates;
    saveButton.innerHTML = action === "save" && busy
      ? `${icons.spinner}<span class="label-long">正在保存</span>`
      : `${icons.save}<span class="label-long">${state.dirty ? "保存修改" : "已保存"}</span>`;
    reloadButton.innerHTML = action === "reload" && busy
      ? `${icons.spinner}<span class="label-long">正在重载</span>`
      : `${icons.file}<span class="label-long">从文件重载</span>`;
    refreshDataButton.innerHTML = action === "refresh" && busy
      ? icons.spinner
      : icons.refresh;
  }

  function markDirty() {
    state.dirty = true;
    syncHeader();
  }

  function renderAll() {
    renderNav();
    renderEditor();
    syncHeader();
    syncPersistence();
  }

  function syncHeader() {
    const healthy = state.status && !state.status.last_error;
    const warning = state.status?.last_error;
    healthBadge.innerHTML = `<span class="status-dot ${warning ? "warning" : healthy ? "" : "error"}"></span><span>${escapeHTML(warning ? "策略警告" : healthy ? `Schema v${state.status.schema_version || 2}` : "未连接")}</span>`;
    healthBadge.title = warning ? state.status.last_error : "插件运行正常";
    saveButton.disabled = state.busy || !state.dirty;
    reloadButton.disabled = state.busy || !state.status?.persistent_updates;
    reloadButton.title = state.status?.persistent_updates ? "从策略文件重载" : "未配置 policy_file，无法从文件重载";
    saveButton.innerHTML = `${icons.save}<span class="label-long">${state.dirty ? "保存修改" : "已保存"}</span>`;
    $("#policyCount").textContent = `${state.keys.length} 个当前 Key`;
  }

  function syncPersistence() {
    const notice = $("#persistenceNotice");
    if (!state.status) return;
    if (state.status.persistent_updates) {
      notice.className = "persistence-notice";
      notice.textContent = `策略保存到 ${state.status.policy_file}`;
    } else {
      notice.className = "persistence-notice warning";
      notice.textContent = "当前为内存模式；插件重载后修改会丢失。请配置 policy_file。";
    }
  }

  function scheduleNavRender() {
    if (navFrame) return;
    navFrame = requestAnimationFrame(() => {
      navFrame = 0;
      renderNav();
    });
  }

  function renderNav() {
    const query = state.search.trim().toLowerCase();
    const visible = state.keys.map((key, index) => ({ key, index })).filter(({ key, index }) =>
      !query || key.fingerprint.toLowerCase().includes(query) || keyLabel(index).toLowerCase().includes(query)
    );
    nav.innerHTML = `
      <button class="nav-item" type="button" data-select="overview" aria-current="${state.selectedIndex < 0 ? "page" : "false"}">
        <span class="nav-icon">${icons.overview}</span>
        <span class="nav-copy"><strong>权限概览</strong><span>认证由 CPA 管理</span></span>
      </button>
      <p class="nav-group-label">当前 CPA API Keys</p>
      ${visible.length ? visible.map(({ key, index }) => `
        <button class="nav-item" type="button" data-select="key" data-index="${index}" aria-current="${state.selectedIndex === index ? "page" : "false"}">
          <span class="nav-icon key">${icons.key}</span>
          <span class="nav-copy"><strong>${key.mask}</strong><span>SHA-256 ${escapeHTML(key.fingerprint)}</span></span>
        </button>`).join("") : `<p class="empty-nav">${query ? "没有匹配的 Key" : "CPA 当前没有 API Key"}</p>`}
    `;
  }

  function renderEditor() {
    if (state.selectedIndex >= 0 && state.keys[state.selectedIndex]) {
      renderKeyEditor(state.keys[state.selectedIndex], state.selectedIndex);
      return;
    }
    state.selectedIndex = -1;
    renderOverview();
  }

  function hasRules(key) {
    return key.allow_models.length > 0 || key.deny_models.length > 0;
  }

  function renderOverview() {
    const configured = state.keys.filter(hasRules).length;
    const defaults = state.keys.length - configured;
    const staleCount = state.stalePolicies.length;
    const statusWarning = state.status?.last_error
      ? `<div class="notice">${icons.warning}<span><strong>最近一次配置存在问题：</strong> ${escapeHTML(state.status.last_error)}。当前仍在使用最后一个有效策略。</span></div>`
      : "";
    const staleWarning = staleCount
      ? `<div class="notice">${icons.warning}<span><strong>${staleCount} 条失效策略：</strong>这些 caller scope 不对应 CPA 当前 Key。保存时会原样保留，不会静默删除；请在确认旧 Key 已永久移除后通过策略文件处理。</span></div>`
      : "";

    editor.innerHTML = `
      <header class="editor-head">
        <div class="editor-title-wrap">
          <p class="editor-kicker">Access overview</p>
          <h1>模型权限概览</h1>
          <p class="editor-subtitle">API Key 的创建、删除和生命周期完全由 CPA 管理；此页面只为现有 Key 配置模型规则。</p>
        </div>
      </header>
      ${statusWarning}
      ${staleWarning}
      <section class="overview-grid" aria-label="权限统计">
        ${statCard("当前 CPA Key", state.keys.length, "只读同步")}
        ${statCard("已配置", configured, "含 allow 或 deny")}
        ${statCard("默认允许", defaults, "没有模型规则")}
        ${statCard("失效策略", staleCount, "保存时仍保留", staleCount > 0)}
      </section>
      <section class="card">
        <div class="card-head"><h2>认证边界</h2><p>Key 身份与模型授权相互分离。</p></div>
        <div class="info-callout">
          <span class="callout-icon">${icons.key}</span>
          <div><strong>认证由 CPA 内置 API Keys 管理</strong><p>插件仅接收 CPA 提供的 caller scope，并据此执行 allow_models 与 deny_models。未配置策略或规则为空时，默认允许全部模型。</p></div>
        </div>
      </section>
      <section class="card">
        <div class="card-head"><h2>运行状态</h2><p>来自当前 CPA 插件实例。</p></div>
        ${statusRow("认证模式", displayAuthMode(state.status?.auth_mode))}
        ${statusRow("身份来源", state.status?.identity_source || "—")}
        ${statusRow("未配置 Key", state.status?.unconfigured_key_action === "allow" ? "允许全部模型" : state.status?.unconfigured_key_action || "—")}
        ${statusRow("后端策略数", state.status?.policy_count ?? "—")}
        ${statusRow("策略版本", `rev-${state.revision}`)}
        ${statusRow("策略来源", state.status?.source || "—")}
        ${statusRow("最后更新", formatDate(state.status?.updated_at))}
      </section>`;
  }

  function statCard(label, value, note, warning = false) {
    return `<article class="stat-card ${warning ? "warning" : ""}"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong><small>${escapeHTML(note)}</small></article>`;
  }

  function displayAuthMode(value) {
    return value === "cpa_builtin_api_keys" ? "CPA 内置 API Keys" : value || "—";
  }

  function statusRow(label, value) {
    return `<div class="setting-row"><div class="setting-copy"><strong>${escapeHTML(label)}</strong></div><div class="setting-control mono">${escapeHTML(value)}</div></div>`;
  }

  function renderKeyEditor(key, index) {
    const empty = !hasRules(key);
    editor.innerHTML = `
      <header class="editor-head">
        <div class="editor-title-wrap">
          <p class="editor-kicker">Existing CPA key</p>
          <h1>${escapeHTML(keyLabel(index))}</h1>
          <p class="editor-subtitle key-summary"><span>${key.mask}</span><span class="mono">SHA-256 ${escapeHTML(key.fingerprint)}</span></p>
        </div>
      </header>
      ${empty ? `<div class="default-notice">${icons.check}<span><strong>当前默认允许全部模型。</strong>添加 allow 或 deny 规则后才会为此 Key 写入策略。</span></div>` : ""}
      <section class="card">
        <div class="card-head"><h2>模型规则</h2><p>deny 优先于 allow；支持 * 和 ? 通配符。规则全部清空后恢复默认允许。</p></div>
        ${tagEditor("allow_models", "允许模型", "有 allow 时，仅允许命中的模型", key.allow_models, false)}
        ${tagEditor("deny_models", "拒绝模型", "命中后始终拒绝", key.deny_models, true)}
      </section>
      <div class="privacy-note">页面仅保留由 CPA Key 计算出的 caller scope；原始 Key 不会写入 DOM、浏览器存储或 URL。</div>`;
    editor.dataset.keyIndex = String(index);
  }

  function tagEditor(kind, title, description, models, deny) {
    return `<div class="tag-editor">
      <div class="tag-head"><strong>${escapeHTML(title)}</strong><span>${escapeHTML(description)}</span></div>
      <div class="chips">${models.length ? models.map((model, modelIndex) => `<span class="chip ${deny ? "deny" : ""}">${escapeHTML(model)}<button class="chip-remove" type="button" data-action="remove-model" data-kind="${kind}" data-model-index="${modelIndex}" aria-label="移除此模型规则">${icons.close}</button></span>`).join("") : '<span class="empty-chips">暂无规则</span>'}</div>
      <div class="tag-input-row"><input id="${kind}Input" class="mono" autocomplete="off" spellcheck="false" placeholder="输入模型或通配符，按 Enter"><button class="button secondary" type="button" data-action="add-model" data-kind="${kind}">添加规则</button></div>
    </div>`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function selectedKey() {
    return state.selectedIndex >= 0 ? state.keys[state.selectedIndex] : null;
  }

  function addModels(kind) {
    if (state.busy) return;
    const key = selectedKey();
    const input = $(`#${kind}Input`);
    if (!key || !input || (kind !== "allow_models" && kind !== "deny_models")) return;
    const additions = input.value.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    if (!additions.length) return;
    key[kind] = [...new Set([...key[kind], ...additions])];
    markDirty();
    renderEditor();
    requestAnimationFrame(() => $(`#${kind}Input`)?.focus());
  }

  function serializablePolicy() {
    const active = state.keys.filter(hasRules).map((key) => ({
      caller_scope: key.scope,
      allow_models: [...key.allow_models],
      deny_models: [...key.deny_models]
    }));
    const stale = state.stalePolicies.map((policy) => ({
      caller_scope: policy.caller_scope,
      allow_models: [...policy.allow_models],
      deny_models: [...policy.deny_models]
    }));
    return { version: 2, policies: [...active, ...stale] };
  }

  function scopeSet(keys) {
    return new Set(keys.map((key) => key.scope));
  }

  function setsEqual(left, right) {
    if (left.size !== right.size) return false;
    for (const value of left) if (!right.has(value)) return false;
    return true;
  }

  async function save() {
    if (!state.dirty || state.busy) return;
    const expectedRevision = state.revision;
    const submittedPolicy = serializablePolicy();
    setBusy(true, "save");
    try {
      const latestKeys = await fetchCurrentKeys();
      if (!setsEqual(scopeSet(state.keys), scopeSet(latestKeys))) {
        const changed = new Error("CPA API Key 列表已变化；为避免策略错配，保存已中止。请刷新数据后重新检查规则。");
        changed.code = "key_set_changed";
        throw changed;
      }

      const response = await api(PATHS.policies, {
        method: "PUT",
        headers: { "If-Match": `"rev-${expectedRevision}"` },
        body: JSON.stringify(submittedPolicy)
      });
      let keySetChangedAfterSave = false;
      let postSaveCheckError = null;
      try {
        const keysAfterSave = await fetchCurrentKeys();
        keySetChangedAfterSave = !setsEqual(scopeSet(state.keys), scopeSet(keysAfterSave));
        if (keySetChangedAfterSave) state.keys = keysAfterSave;
      } catch (verificationError) {
        postSaveCheckError = verificationError;
      }
      applyPolicyDocument(response?.policy || submittedPolicy);
      state.revision = Number(response?.revision ?? expectedRevision + 1);
      state.dirty = false;
      renderAll();
      if (keySetChangedAfterSave) {
        showToast("策略已保存，但 CPA Key 列表在保存期间发生变化；新 Key 当前默认允许全部模型，请立即检查。", "error");
      } else if (postSaveCheckError) {
        showToast(`策略已保存，但无法复核 CPA Key 列表：${postSaveCheckError.message}`, "error");
      } else {
        showToast(response?.persistent ? "策略已保存并持久化" : "策略已保存到内存", "success");
      }
      try {
        state.status = await api(PATHS.status, { method: "GET" });
        syncHeader();
        syncPersistence();
      } catch (refreshError) {
        showToast(`策略已保存，但状态刷新失败：${refreshError.message}`, "error");
      }
    } catch (error) {
      if (error.code === "timeout") {
        const confirmed = await confirmTimedOutSave(submittedPolicy, expectedRevision);
        showToast(confirmed ? "保存响应超时，但已重新读取并确认提交成功" : "保存结果无法确认；本地修改已保留，请刷新后核对。", confirmed ? "success" : "error");
      } else if (error.code === "key_set_changed") {
        showToast(error.message, "error", "刷新数据", refreshData);
      } else if (error.status === 412) {
        showToast("策略已被其他管理员或配置重载修改。请刷新数据后再保存。", "error", "刷新数据", refreshData);
      } else {
        showToast(error.message, "error");
      }
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function confirmTimedOutSave(submittedPolicy, expectedRevision) {
    try {
      const policies = await api(PATHS.policies, { method: "GET" });
      const remoteRevision = Number(policies?.revision ?? 0);
      if (remoteRevision <= expectedRevision || !policiesEquivalent(submittedPolicy, policies?.policy)) return false;
      applyPolicyDocument(policies.policy);
      state.revision = remoteRevision;
      state.dirty = false;
      try { state.status = await api(PATHS.status, { method: "GET" }); } catch (_) { /* policy confirmation is sufficient */ }
      renderAll();
      return true;
    } catch (_) {
      return false;
    }
  }

  function policiesEquivalent(leftRaw, rightRaw) {
    const canonical = (raw) => normalizePolicyDocument(raw).policies.map((policy) => ({
      caller_scope: policy.caller_scope,
      allow_models: [...policy.allow_models].sort(),
      deny_models: [...policy.deny_models].sort()
    })).sort((left, right) => left.caller_scope.localeCompare(right.caller_scope));
    return JSON.stringify(canonical(leftRaw)) === JSON.stringify(canonical(rightRaw));
  }

  async function refreshData() {
    if (state.busy) return;
    if (state.dirty && !window.confirm("刷新会放弃尚未保存的模型规则。是否继续？")) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "refresh");
    try {
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast("已刷新 CPA Key 与策略", "success");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function reload() {
    if (state.busy || !state.status?.persistent_updates) return;
    if (state.dirty && !window.confirm("从策略文件重载会放弃尚未保存的模型规则。是否继续？")) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "reload");
    let reloaded = false;
    try {
      await api(PATHS.reload, { method: "POST" });
      reloaded = true;
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast("已从策略文件重载", "success");
    } catch (error) {
      showToast(reloaded ? `策略已重载，但界面刷新失败：${error.message}` : error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  function showToast(message, type = "success", actionLabel = "", action = null) {
    const toast = document.createElement("div");
    toast.className = `toast ${type} enter`;
    toast.innerHTML = `${type === "error" ? icons.warning : icons.check}<span>${escapeHTML(message)}</span>${actionLabel ? `<button type="button">${escapeHTML(actionLabel)}</button>` : ""}`;
    $("#toastRegion").appendChild(toast);
    const button = toast.querySelector("button");
    let timer = window.setTimeout(remove, actionLabel ? 7000 : 3600);
    if (button) button.addEventListener("click", () => { window.clearTimeout(timer); action?.(); remove(); });
    requestAnimationFrame(() => toast.classList.remove("enter"));
    function remove() {
      if (!toast.isConnected) return;
      toast.classList.add("exit");
      window.setTimeout(() => toast.remove(), 190);
    }
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("key-model-access-theme", theme);
    $("#themeButton").innerHTML = theme === "dark" ? icons.sun : icons.moon;
    $("#themeButton").title = theme === "dark" ? "切换到浅色" : "切换到深色";
  }

  function initializeChrome() {
    $("#toggleSecret").innerHTML = icons.eye;
    $("#searchIcon").innerHTML = icons.search;
    refreshDataButton.innerHTML = icons.refresh;
    reloadButton.innerHTML = `${icons.file}<span class="label-long">从文件重载</span>`;
    saveButton.innerHTML = `${icons.save}<span class="label-long">已保存</span>`;
    $("#disconnectButton").innerHTML = icons.logout;
    const stored = localStorage.getItem("key-model-access-theme");
    const preferred = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    applyTheme(stored === "dark" || stored === "light" ? stored : preferred);
  }

  $("#authForm").addEventListener("submit", (event) => {
    event.preventDefault();
    connect($("#managementKey").value);
  });

  $("#toggleSecret").addEventListener("click", () => {
    const input = $("#managementKey");
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    $("#toggleSecret").innerHTML = showing ? icons.eye : icons.eyeOff;
    $("#toggleSecret").setAttribute("aria-label", showing ? "显示密钥" : "隐藏密钥");
  });

  $("#themeButton").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
  $("#disconnectButton").addEventListener("click", disconnect);
  refreshDataButton.addEventListener("click", refreshData);
  saveButton.addEventListener("click", save);
  reloadButton.addEventListener("click", reload);
  $("#searchInput").addEventListener("input", (event) => { state.search = event.target.value; scheduleNavRender(); });

  nav.addEventListener("click", (event) => {
    if (state.busy) return;
    const item = event.target.closest("[data-select]");
    if (!item) return;
    state.selectedIndex = item.dataset.select === "overview" ? -1 : Number(item.dataset.index);
    renderNav();
    renderEditor();
  });

  editor.addEventListener("click", (event) => {
    if (state.busy) return;
    const target = event.target.closest("button");
    if (!target) return;
    const action = target.dataset.action;
    if (action === "add-model") addModels(target.dataset.kind);
    else if (action === "remove-model") {
      const key = selectedKey();
      const kind = target.dataset.kind;
      if (!key || (kind !== "allow_models" && kind !== "deny_models")) return;
      key[kind].splice(Number(target.dataset.modelIndex), 1);
      markDirty();
      renderEditor();
    }
  });

  editor.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || !event.target.id?.endsWith("_modelsInput")) return;
    event.preventDefault();
    addModels(event.target.id.replace("Input", ""));
  });

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s" && !app.hidden) {
      event.preventDefault();
      save();
    }
  });

  window.addEventListener("beforeunload", (event) => {
    if (!state.dirty) return;
    event.preventDefault();
    event.returnValue = "";
  });

  initializeChrome();
})();
