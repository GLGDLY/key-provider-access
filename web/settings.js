(() => {
  "use strict";

  const PATHS = {
    status: "/v0/management/plugins/key-model-access/status",
    policies: "/v0/management/plugins/key-model-access/policies",
    reload: "/v0/management/plugins/key-model-access/reload"
  };

  const icons = {
    eye: '<svg viewBox="0 0 24 24"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>',
    eyeOff: '<svg viewBox="0 0 24 24"><path d="m3 3 18 18M10.6 6.1A10.5 10.5 0 0 1 12 6c6 0 9.5 6 9.5 6a16 16 0 0 1-2.1 2.8M6.2 6.2C3.8 8 2.5 12 2.5 12s3.5 6 9.5 6c1.2 0 2.3-.2 3.3-.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>',
    plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
    search: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>',
    sliders: '<svg viewBox="0 0 24 24"><path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/></svg>',
    key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M15 12v2"/></svg>',
    refresh: '<svg viewBox="0 0 24 24"><path d="M20 6v5h-5M4 18v-5h5"/><path d="M6.1 8.2A7 7 0 0 1 18.8 9M17.9 15.8A7 7 0 0 1 5.2 15"/></svg>',
    save: '<svg viewBox="0 0 24 24"><path d="M5 4h12l2 2v14H5z"/><path d="M8 4v6h8V4M8 20v-6h8v6"/></svg>',
    sun: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.5"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    moon: '<svg viewBox="0 0 24 24"><path d="M20 15.2A8 8 0 0 1 8.8 4 8.2 8.2 0 1 0 20 15.2Z"/></svg>',
    logout: '<svg viewBox="0 0 24 24"><path d="M10 5H5v14h5M14 8l4 4-4 4M8 12h10"/></svg>',
    close: '<svg viewBox="0 0 24 24"><path d="m7 7 10 10M17 7 7 17"/></svg>',
    copy: '<svg viewBox="0 0 24 24"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>',
    trash: '<svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5"/></svg>',
    warning: '<svg viewBox="0 0 24 24"><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4M12 16.5h.01"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>',
    spinner: '<svg class="spinner" viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-9 9"/><path d="M3 12a9 9 0 0 1 9-9" opacity=".35"/></svg>'
  };

  const state = {
    token: "",
    status: null,
    policy: null,
    revision: 0,
    selection: { type: "global", index: -1 },
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
  const healthBadge = $("#healthBadge");
  let navFrame = 0;

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
    })[character]);
  }

  function normalizePolicy(raw) {
    const policy = raw && typeof raw === "object" ? raw : {};
    return {
      version: 1,
      default_action: policy.default_action === "allow" ? "allow" : "deny",
      models_endpoint: policy.models_endpoint === "deny" ? "deny" : "allow",
      allow_query_keys: policy.allow_query_keys !== false,
      keys: Array.isArray(policy.keys) ? policy.keys.map((item) => ({
        id: String(item.id || ""),
        enabled: item.enabled !== false,
        key_sha256: String(item.key_sha256 || ""),
        allow_models: Array.isArray(item.allow_models) ? [...item.allow_models] : [],
        deny_models: Array.isArray(item.deny_models) ? [...item.deny_models] : [],
        _credential: ""
      })) : []
    };
  }

  function fingerprint(hash) {
    if (!hash) return "尚未设置凭据";
    return `${hash.slice(0, 8)}…${hash.slice(-6)}`;
  }

  async function api(path, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const timeout = options.timeout || (method === "GET" ? 12000 : 20000);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, {
        ...options,
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
        const message = payload && (payload.error?.message || payload.error)
          ? (payload.error?.message || payload.error)
          : `请求失败（HTTP ${response.status}）`;
        const error = new Error(message);
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

  async function connect(token) {
    state.token = token.trim();
    if (!state.token) return;
    setAuthBusy(true);
    $("#authError").textContent = "";
    try {
      // Verify once first: CPA rate-limits repeated Management authentication failures.
      const status = await api(PATHS.status);
      const policies = await api(PATHS.policies);
      state.status = status;
      state.policy = normalizePolicy(policies.policy);
      state.revision = Number(policies.revision ?? status.revision ?? 0);
      state.dirty = false;
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
    if (state.dirty && !window.confirm("有尚未保存的修改。确定断开并放弃这些修改吗？")) return;
    state.token = "";
    state.status = null;
    state.policy = null;
    state.revision = 0;
    state.dirty = false;
    state.selection = { type: "global", index: -1 };
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
    saveButton.disabled = busy || !state.dirty;
    reloadButton.disabled = busy || !state.status?.persistent_updates;
    if (action === "save" && busy) saveButton.innerHTML = `${icons.spinner}<span class="label-long">正在保存</span>`;
    else saveButton.innerHTML = `${icons.save}<span class="label-long">保存修改</span>`;
    if (action === "reload" && busy) reloadButton.innerHTML = `${icons.spinner}<span class="label-long">正在重载</span>`;
    else reloadButton.innerHTML = `${icons.refresh}<span class="label-long">从文件重载</span>`;
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
    const warning = state.status && state.status.last_error;
    healthBadge.innerHTML = `<span class="status-dot ${warning ? "warning" : healthy ? "" : "error"}"></span><span>${escapeHTML(warning ? "策略警告" : healthy ? `Schema ${state.status.host_schema_version}` : "未连接")}</span>`;
    healthBadge.title = warning ? state.status.last_error : "插件运行正常";
    saveButton.disabled = state.busy || !state.dirty;
    reloadButton.disabled = state.busy || !state.status?.persistent_updates;
    reloadButton.title = state.status?.persistent_updates ? "从策略文件重载" : "未配置 policy_file，无法从文件重载";
    saveButton.innerHTML = `${icons.save}<span class="label-long">${state.dirty ? "保存修改" : "已保存"}</span>`;
    $("#policyCount").textContent = `${state.policy?.keys.length || 0} 个 Key`;
  }

  function syncPersistence() {
    const notice = $("#persistenceNotice");
    if (!state.status) return;
    if (state.status.persistent_updates) {
      notice.className = "persistence-notice";
      notice.textContent = `保存到 ${state.status.policy_file}`;
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
    if (!state.policy) return;
    const query = state.search.trim().toLowerCase();
    const keyItems = state.policy.keys.map((key, index) => ({ key, index }))
      .filter(({ key }) => !query || key.id.toLowerCase().includes(query) || key.key_sha256.toLowerCase().includes(query));
    const globalSelected = state.selection.type === "global";
    nav.innerHTML = `
      <button class="nav-item" type="button" data-select="global" aria-current="${globalSelected ? "page" : "false"}">
        <span class="nav-icon">${icons.sliders}</span>
        <span class="nav-copy"><strong>全局策略</strong><span>${escapeHTML(state.policy.default_action)} · models ${escapeHTML(state.policy.models_endpoint)}</span></span>
      </button>
      <p class="nav-group-label">API Keys</p>
      ${keyItems.length ? keyItems.map(({ key, index }) => `
        <button class="nav-item" type="button" data-select="key" data-index="${index}" aria-current="${state.selection.type === "key" && state.selection.index === index ? "page" : "false"}">
          <span class="nav-icon key">${icons.key}</span>
          <span class="nav-copy"><strong>${escapeHTML(key.id || "未命名 Key")}</strong><span>${escapeHTML(fingerprint(key.key_sha256))}</span></span>
          <span class="nav-state ${key.enabled ? "" : "off"}" title="${key.enabled ? "已启用" : "已停用"}"></span>
        </button>`).join("") : `<p class="empty-nav">${query ? "没有匹配的 Key" : "尚未添加 API Key"}</p>`}
    `;
  }

  function renderEditor() {
    if (!state.policy) return;
    if (state.selection.type === "key") {
      const key = state.policy.keys[state.selection.index];
      if (key) {
        renderKeyEditor(key, state.selection.index);
        return;
      }
      state.selection = { type: "global", index: -1 };
    }
    renderGlobalEditor();
  }

  function segment(name, value, first, second) {
    return `<div class="segment" role="group" aria-label="${escapeHTML(name)}">
      <button type="button" data-setting="${escapeHTML(name)}" data-value="${first.value}" aria-pressed="${value === first.value}">${first.label}</button>
      <button type="button" data-setting="${escapeHTML(name)}" data-value="${second.value}" aria-pressed="${value === second.value}">${second.label}</button>
    </div>`;
  }

  function renderGlobalEditor() {
    const policy = state.policy;
    const statusWarning = state.status?.last_error ? `<div class="notice">${icons.warning}<span><strong>最近一次配置存在问题：</strong> ${escapeHTML(state.status.last_error)}。当前仍在使用最后一个有效策略。</span></div>` : "";
    editor.innerHTML = `
      <header class="editor-head">
        <div class="editor-title-wrap">
          <p class="editor-kicker">Policy defaults</p>
          <h1>全局策略</h1>
          <p class="editor-subtitle">设置未匹配模型的默认行为，以及客户端发现模型和传递 Key 的方式。</p>
        </div>
      </header>
      ${statusWarning}
      <section class="card">
        <div class="card-head"><h2>默认访问行为</h2><p>每个 Key 的 allow 与 deny 规则会覆盖这里的默认值。</p></div>
        <div class="setting-row">
          <div class="setting-copy"><strong>未匹配模型</strong><span>推荐拒绝，只开放明确列出的模型。</span></div>
          <div class="setting-control">${segment("default_action", policy.default_action, { value: "deny", label: "拒绝" }, { value: "allow", label: "允许" })}</div>
        </div>
        <div class="setting-row">
          <div class="setting-copy"><strong>/v1/models 端点</strong><span>CPA 只能返回全局列表，无法按 Key 过滤。</span></div>
          <div class="setting-control">${segment("models_endpoint", policy.models_endpoint, { value: "deny", label: "拒绝" }, { value: "allow", label: "允许" })}</div>
        </div>
        <div class="setting-row">
          <div class="setting-copy"><strong>查询参数 Key</strong><span>接受 ?key= 和 ?auth_token=；Header 始终可用。</span></div>
          <label class="toggle" aria-label="允许查询参数 Key"><input id="allowQueryKeys" type="checkbox" ${policy.allow_query_keys ? "checked" : ""}><span class="toggle-track"></span></label>
        </div>
      </section>
      <div class="notice">${icons.warning}<span><strong>模型列表说明：</strong>即使允许 /v1/models，客户端看到的也是 CPA 全局模型列表；实际调用仍按每个 Key 的策略严格校验。</span></div>
      <section class="card">
        <div class="card-head"><h2>运行状态</h2><p>来自当前 CPA 插件实例。</p></div>
        ${statusRow("插件版本", `v${state.status?.version || "—"}`)}
        ${statusRow("RPC Schema", `${state.status?.host_schema_version || "—"} / 要求 ${state.status?.schema_version || 2}`)}
        ${statusRow("策略版本", `rev-${state.revision}`)}
        ${statusRow("策略来源", state.status?.source || "—")}
        ${statusRow("最后更新", formatDate(state.status?.updated_at))}
      </section>`;
  }

  function statusRow(label, value) {
    return `<div class="setting-row"><div class="setting-copy"><strong>${escapeHTML(label)}</strong></div><div class="setting-control mono">${escapeHTML(value)}</div></div>`;
  }

  function renderKeyEditor(key, index) {
    const hasHash = Boolean(key.key_sha256);
    editor.innerHTML = `
      <header class="editor-head">
        <div class="editor-title-wrap">
          <p class="editor-kicker">API key policy</p>
          <h1>${escapeHTML(key.id || "未命名 Key")}</h1>
          <p class="editor-subtitle mono">${escapeHTML(fingerprint(key.key_sha256))}</p>
        </div>
        <label class="toggle" aria-label="启用此 Key"><input id="keyEnabled" type="checkbox" ${key.enabled ? "checked" : ""}><span class="toggle-track"></span></label>
      </header>
      <section class="card">
        <div class="card-head"><h2>身份与凭据</h2><p>明文 Key 只会在当前页面内存中短暂存在，保存后服务端仅返回 SHA-256。</p></div>
        <div class="form-grid">
          <div class="form-field">
            <label class="field-label" for="keyId">标识名称</label>
            <input id="keyId" value="${escapeHTML(key.id)}" autocomplete="off" spellcheck="false" placeholder="例如 team-a">
            <small>用于日志和管理，不会作为客户端凭据。</small>
          </div>
          <div class="form-field">
            <label class="field-label" for="credential">${hasHash ? "替换 API Key" : "API Key"}</label>
            <input id="credential" type="password" value="${escapeHTML(key._credential || "")}" autocomplete="new-password" spellcheck="false" placeholder="${hasHash ? "留空以保留当前 Key" : "输入新的客户端 Key"}">
            <small>${hasHash ? `当前指纹：${escapeHTML(fingerprint(key.key_sha256))}` : "保存前必须设置凭据。"}</small>
          </div>
          ${hasHash ? `<div class="form-field full"><label class="field-label" for="keyHash">SHA-256</label><div class="input-action"><input id="keyHash" class="mono" value="${escapeHTML(key.key_sha256)}" readonly><button class="icon-button" type="button" data-action="copy-hash" aria-label="复制 SHA-256" title="复制 SHA-256">${icons.copy}</button></div></div>` : ""}
        </div>
      </section>
      <section class="card">
        <div class="card-head"><h2>模型规则</h2><p>deny 优先级高于 allow；支持 * 和 ? 通配符。</p></div>
        ${tagEditor("allow_models", "允许模型", "命中后允许调用", key.allow_models, false)}
        ${tagEditor("deny_models", "拒绝模型", "命中后始终拒绝", key.deny_models, true)}
      </section>
      <section class="card">
        <div class="danger-zone">
          <div><strong>删除此 Key</strong><span>保存前可以撤销，保存后该凭据立即失效。</span></div>
          <button class="button danger" type="button" data-action="delete-key">${icons.trash}<span>删除 Key</span></button>
        </div>
      </section>`;
    editor.dataset.keyIndex = String(index);
  }

  function tagEditor(kind, title, description, models, deny) {
    return `<div class="tag-editor">
      <div class="tag-head"><strong>${escapeHTML(title)}</strong><span>${escapeHTML(description)}</span></div>
      <div class="chips">${models.length ? models.map((model, modelIndex) => `<span class="chip ${deny ? "deny" : ""}">${escapeHTML(model)}<button class="chip-remove" type="button" data-action="remove-model" data-kind="${kind}" data-model-index="${modelIndex}" aria-label="移除 ${escapeHTML(model)}">${icons.close}</button></span>`).join("") : '<span class="empty-chips">暂无规则</span>'}</div>
      <div class="tag-input-row"><input id="${kind}Input" class="mono" autocomplete="off" spellcheck="false" placeholder="输入模型或通配符，按 Enter"><button class="button secondary" type="button" data-action="add-model" data-kind="${kind}">添加</button></div>
    </div>`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function addKey() {
    if (state.busy) return;
    let number = state.policy.keys.length + 1;
    let id = `key-${number}`;
    const ids = new Set(state.policy.keys.map((key) => key.id));
    while (ids.has(id)) id = `key-${++number}`;
    state.policy.keys.push({ id, enabled: true, key_sha256: "", allow_models: [], deny_models: [], _credential: "" });
    state.selection = { type: "key", index: state.policy.keys.length - 1 };
    state.search = "";
    $("#searchInput").value = "";
    markDirty();
    renderAll();
    requestAnimationFrame(() => $("#credential")?.focus());
  }

  function selectedKey() {
    return state.selection.type === "key" ? state.policy.keys[state.selection.index] : null;
  }

  function addModels(kind) {
    if (state.busy) return;
    const key = selectedKey();
    const input = $(`#${kind}Input`);
    if (!key || !input) return;
    const additions = input.value.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    if (!additions.length) return;
    const existing = new Set(key[kind]);
    additions.forEach((model) => existing.add(model));
    key[kind] = [...existing];
    markDirty();
    renderEditor();
    requestAnimationFrame(() => $(`#${kind}Input`)?.focus());
  }

  function deleteKey() {
    if (state.busy) return;
    const index = state.selection.index;
    const removed = state.policy.keys.splice(index, 1)[0];
    if (!removed) return;
    state.selection = { type: "global", index: -1 };
    markDirty();
    renderAll();
    showToast(`已移除 ${removed.id || "未命名 Key"}`, "success", "撤销", () => {
      state.policy.keys.splice(Math.min(index, state.policy.keys.length), 0, removed);
      state.selection = { type: "key", index: Math.min(index, state.policy.keys.length - 1) };
      markDirty();
      renderAll();
    });
  }

  function validatePolicy() {
    const ids = new Set();
    for (const [index, key] of state.policy.keys.entries()) {
      key.id = key.id.trim();
      if (!key.id) return `第 ${index + 1} 个 Key 缺少标识名称。`;
      if (ids.has(key.id)) return `标识名称“${key.id}”重复。`;
      ids.add(key.id);
      if (!key.key_sha256 && !key._credential?.trim()) return `Key“${key.id}”尚未设置客户端凭据。`;
    }
    return "";
  }

  function serializablePolicy() {
    return {
      version: 1,
      default_action: state.policy.default_action,
      models_endpoint: state.policy.models_endpoint,
      allow_query_keys: state.policy.allow_query_keys,
      keys: state.policy.keys.map((key) => {
        const output = {
          id: key.id.trim(),
          enabled: key.enabled !== false,
          allow_models: [...key.allow_models],
          deny_models: [...key.deny_models]
        };
        if (key._credential?.trim()) output.key = key._credential.trim();
        else output.key_sha256 = key.key_sha256;
        return output;
      })
    };
  }

  async function save() {
    if (!state.dirty || state.busy) return;
    const validationError = validatePolicy();
    if (validationError) {
      showToast(validationError, "error");
      return;
    }
    const expectedRevision = state.revision;
    const submittedPolicy = serializablePolicy();
    setBusy(true, "save");
    try {
      const response = await api(PATHS.policies, {
        method: "PUT",
        headers: { "If-Match": `"rev-${expectedRevision}"` },
        body: JSON.stringify(submittedPolicy)
      });
      state.policy = normalizePolicy(response.policy);
      state.revision = Number(response.revision ?? expectedRevision + 1);
      state.dirty = false;
      if (state.selection.type === "key" && !state.policy.keys[state.selection.index]) state.selection = { type: "global", index: -1 };
      renderAll();
      showToast(response.persistent ? "策略已保存并持久化" : "策略已保存到内存", "success");
      try {
        state.status = await api(PATHS.status);
        syncHeader();
        syncPersistence();
      } catch (refreshError) {
        showToast(`策略已保存，但状态刷新失败：${refreshError.message}`, "error");
      }
    } catch (error) {
      if (error.code === "timeout") {
        const confirmed = await confirmTimedOutSave(submittedPolicy, expectedRevision);
        if (confirmed) showToast("保存响应超时，但已重新读取并确认提交成功", "success");
        else showToast("保存结果无法确认；本地修改已保留，请重新加载后核对。", "error");
      } else if (error.status === 412) {
        showToast("策略已被其他管理员或配置重载修改。请先重新加载再保存。", "error");
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
      const policies = await api(PATHS.policies);
      const remoteRevision = Number(policies.revision ?? 0);
      if (remoteRevision <= expectedRevision || !(await policiesEquivalent(submittedPolicy, policies.policy))) return false;
      state.policy = normalizePolicy(policies.policy);
      state.revision = remoteRevision;
      state.dirty = false;
      try { state.status = await api(PATHS.status); } catch (_) { /* policy confirmation is sufficient */ }
      renderAll();
      return true;
    } catch (_) {
      return false;
    }
  }

  async function policiesEquivalent(submitted, remoteRaw) {
    const remote = normalizePolicy(remoteRaw);
    if (submitted.default_action !== remote.default_action || submitted.models_endpoint !== remote.models_endpoint || submitted.allow_query_keys !== remote.allow_query_keys || submitted.keys.length !== remote.keys.length) return false;
    for (let index = 0; index < submitted.keys.length; index += 1) {
      const left = submitted.keys[index];
      const right = remote.keys[index];
      const expectedHash = left.key ? await sha256Hex(left.key) : left.key_sha256;
      if (left.id !== right.id || left.enabled !== right.enabled || expectedHash !== right.key_sha256) return false;
      if (JSON.stringify([...left.allow_models].sort()) !== JSON.stringify([...right.allow_models].sort())) return false;
      if (JSON.stringify([...left.deny_models].sort()) !== JSON.stringify([...right.deny_models].sort())) return false;
    }
    return true;
  }

  async function sha256Hex(value) {
    const bytes = new TextEncoder().encode(value.trim());
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async function reload() {
    if (state.busy || !state.status?.persistent_updates) return;
    if (state.dirty && !window.confirm("从策略文件重载会放弃尚未保存的修改。是否继续？")) return;
    setBusy(true, "reload");
    let reloaded = false;
    try {
      const response = await api(PATHS.reload, { method: "POST" });
      reloaded = true;
      state.revision = Number(response.revision ?? state.revision + 1);
      state.dirty = false;
      const policies = await api(PATHS.policies);
      state.status = await api(PATHS.status);
      state.policy = normalizePolicy(policies.policy);
      state.revision = Number(policies.revision ?? state.revision);
      state.selection = { type: "global", index: -1 };
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
    let timer = window.setTimeout(remove, actionLabel ? 6000 : 3600);
    if (button) button.addEventListener("click", () => { window.clearTimeout(timer); action?.(); remove(); });
    requestAnimationFrame(() => toast.classList.remove("enter"));
    function remove() {
      if (!toast.isConnected) return;
      toast.classList.add("exit");
      window.setTimeout(() => toast.remove(), 190);
    }
  }

  async function copyHash() {
    const key = selectedKey();
    if (!key?.key_sha256) return;
    try {
      await navigator.clipboard.writeText(key.key_sha256);
      showToast("SHA-256 已复制", "success");
    } catch (_) {
      const input = $("#keyHash");
      input?.select();
      showToast("请使用系统复制命令", "error");
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
    $("#addKeyButton").innerHTML = icons.plus;
    $("#searchIcon").innerHTML = icons.search;
    $("#reloadButton").innerHTML = `${icons.refresh}<span class="label-long">从文件重载</span>`;
    $("#saveButton").innerHTML = `${icons.save}<span class="label-long">已保存</span>`;
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
  $("#addKeyButton").addEventListener("click", addKey);
  saveButton.addEventListener("click", save);
  reloadButton.addEventListener("click", reload);
  $("#searchInput").addEventListener("input", (event) => { state.search = event.target.value; scheduleNavRender(); });

  nav.addEventListener("click", (event) => {
    if (state.busy) return;
    const item = event.target.closest("[data-select]");
    if (!item) return;
    state.selection = item.dataset.select === "global"
      ? { type: "global", index: -1 }
      : { type: "key", index: Number(item.dataset.index) };
    renderNav();
    renderEditor();
  });

  editor.addEventListener("click", (event) => {
    if (state.busy) return;
    const target = event.target.closest("button");
    if (!target) return;
    if (target.dataset.setting) {
      state.policy[target.dataset.setting] = target.dataset.value;
      markDirty();
      renderEditor();
      renderNav();
      return;
    }
    const action = target.dataset.action;
    if (action === "add-model") addModels(target.dataset.kind);
    else if (action === "remove-model") {
      const key = selectedKey();
      if (!key) return;
      key[target.dataset.kind].splice(Number(target.dataset.modelIndex), 1);
      markDirty();
      renderEditor();
    } else if (action === "delete-key") deleteKey();
    else if (action === "copy-hash") copyHash();
  });

  editor.addEventListener("input", (event) => {
    if (state.busy) return;
    const key = selectedKey();
    if (!key) return;
    if (event.target.id === "keyId") {
      key.id = event.target.value;
      markDirty();
      scheduleNavRender();
      editor.querySelector("h1").textContent = key.id || "未命名 Key";
    } else if (event.target.id === "credential") {
      key._credential = event.target.value;
      markDirty();
    }
  });

  editor.addEventListener("change", (event) => {
    if (state.busy) return;
    if (event.target.id === "allowQueryKeys") {
      state.policy.allow_query_keys = event.target.checked;
      markDirty();
    } else if (event.target.id === "keyEnabled") {
      const key = selectedKey();
      if (!key) return;
      key.enabled = event.target.checked;
      markDirty();
      renderNav();
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
