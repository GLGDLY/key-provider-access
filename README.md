# CPA Key Model Access 插件

一个 CLIProxyAPI（CPA）原生动态库插件，用于为**每个下游 API Key**配置可调用的模型。

## 功能

- 独占前端认证：未知或已禁用的 Key 无法绕过插件回退到 CPA 内置 `api-keys`。
- 每个 Key 支持 `allow_models`、`deny_models`，支持 `*` 和 `?` 通配符。
- `deny_models` 优先于 `allow_models`；都未匹配时使用全局 `default_action`。
- 支持以下 Key 来源：
  - `Authorization: Bearer <key>`
  - `X-Api-Key: <key>`
  - `X-Goog-Api-Key: <key>`
  - `?key=`、`?auth_token=`（可关闭）
- 同时在前端认证和 CPA 的请求执行拦截阶段校验模型，未授权请求不会到达上游。
- 特别覆盖不进入通用请求拦截链的 Codex Live 路由：顶层/`session.model`、multipart `session` 与默认 `gpt-live-1-codex`。
- 提供浏览器 Web 设置界面，以及受 CPA Management Key 保护的查询、整体替换、重载 API。
- Web UI 支持明暗主题、移动端布局、Key CRUD、模型标签、撤销删除和并发修改保护。
- 策略持久化时只保存 API Key 的 SHA-256，不保存明文。
- 所有配置写事务串行化；无效热更新保留最后一个有效快照，首次无效配置则以 deny-all 注册，避免回退到内置认证。

## 重要限制：`/v1/models`

CPA 当前插件 API **不能修改内置 `/v1/models` handler 的响应**。因此本插件不能让 Key A 和 Key B 在标准 `/v1/models` 中看到不同列表，只能通过 `models_endpoint: allow|deny` 对该端点整体允许或拒绝。

即使 `models_endpoint: allow` 返回全局模型列表，实际模型请求仍会严格执行每 Key 权限。若客户端必须看到过滤后的标准模型列表，需要在 CPA 前增加反向代理，或修改 CPA 核心以增加 models-list filter hook。

## 兼容性

- CLIProxyAPI **v7.2.103 或更新版本**。
- 插件 RPC schema 2（用于拦截器主动返回 `403`）。旧 schema 宿主上插件会以独占 deny-all 模式注册并在状态 API 中报告错误，不会降级为不安全的部分执行。
- 支持 CPA 动态插件的 CGO 构建。可通过任一 Management API 响应头 `X-CPA-SUPPORT-PLUGIN: 1` 确认二进制支持插件。

> 本插件声明 `frontend_auth_provider_exclusive: true`。启用后，它会成为唯一的下游认证来源，CPA 顶层 `api-keys` 不再参与认证。请先在插件策略中配置至少一个可用 Key，避免锁死 API。

## 构建

需要 Go、C 编译器和 `CGO_ENABLED=1`：

```bash
make test
make build
make package
```

以 macOS arm64 和默认版本为例，会生成：

```text
dist/key-model-access.dylib
dist/key-model-access_0.2.0_darwin_arm64.zip
dist/key-model-access_0.2.0_darwin_arm64.zip.sha256
```

动态库扩展名：

- macOS：`key-model-access.dylib`
- Linux / FreeBSD：`key-model-access.so`
- Windows：`key-model-access.dll`

可以覆盖目标平台、输出目录和写入插件的运行时版本：

```bash
make build GOOS=darwin GOARCH=arm64 BUILD_DIR=/path/to/plugins/darwin/arm64
make package VERSION=0.2.0
```

Go 的 `c-shared` 产物必须在目标系统上构建；不能仅设置 `GOOS` 进行普通交叉编译。

## GitHub 发布

发布流程与插件商店产物格式由 [`.github/workflows/build.yml`](./.github/workflows/build.yml) 自动完成。Pull Request 和手动运行会执行测试并构建产物；推送 `v*` 标签还会创建对应的 GitHub Release。

每个 Release 包含以下平台的 zip：

- Linux：amd64、arm64
- macOS：amd64、arm64
- Windows：amd64、arm64
- FreeBSD：amd64

产物命名为：

```text
key-model-access_<version>_<goos>_<goarch>.zip
checksums.txt
```

每个 zip 的根目录只包含对应平台的动态库，`checksums.txt` 使用 `sha256sum` 格式。创建发布：

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

本地可生成当前平台的压缩包和聚合校验文件：

```bash
make checksums VERSION=0.2.0
```

## 安装

自动安装到本机平台目录：

```bash
make install CPA_DIR=/path/to/CLIProxyAPI
```

或手动复制到：

```text
<CPA>/plugins/<GOOS>/<GOARCH>/key-model-access.<ext>
```

动态库的基础 ID 必须是 `key-model-access`，并与 `plugins.configs.key-model-access` 一致；也可使用 CPA 官方支持的 `key-model-access-v<version>.<ext>` 版本后缀。

将 [`config.example.yaml`](./config.example.yaml) 中的配置合并到 CPA 的 `config.yaml`：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-model-access:
      enabled: true
      priority: 100
      policy_file: "config/key-model-access-policies.yaml"
      default_action: deny
      models_endpoint: allow
      allow_query_keys: true
      keys:
        - id: bootstrap-admin
          key: "replace-with-a-real-api-key"
          allow_models: ["*"]
```

`policy_file` 相对路径以 CPA 的工作目录为准。文件不存在时先使用内联 `keys`；文件创建后，它成为权威策略来源。

Docker 部署还要持久化动态库和策略文件，例如：

```yaml
volumes:
  - ./plugins:/CLIProxyAPI/plugins
  - ./config:/CLIProxyAPI/config
```

必须挂载整个策略目录，而不是单独 bind mount 策略文件；Management API 通过同目录临时文件 + rename 原子替换，单文件 bind mount 通常不允许该操作。

## Web 设置界面

插件启用后访问：

```text
http://<CPA_HOST>:<CPA_PORT>/v0/resource/plugins/key-model-access/settings
```

页面也会以“模型权限”资源注册到支持插件菜单的 CPA 管理界面。静态页面本身不需要认证且不包含任何策略数据；打开后需要输入 CPA `remote-management.secret-key`，页面再通过同源 Management API 加载和保存策略。

界面提供：

- 全局 `default_action`、`models_endpoint` 和查询参数 Key 开关。
- 新增、停用、重命名和删除 API Key。
- 输入明文新 Key；保存后界面只接收并显示 SHA-256 指纹。
- 以标签方式编辑 `allow_models` / `deny_models` 通配符规则。
- 从 `policy_file` 重载、内存模式警告、错误状态与策略来源展示。
- 基于 revision/`If-Match` 的并发保护；其他管理员或配置重载已修改策略时返回 `412`，避免静默覆盖。
- 自动明暗主题、响应式移动布局、键盘 `⌘/Ctrl + S` 保存和 reduced-motion 支持。

安全边界：

- Management Key 只保存在当前页面 JavaScript 内存中，不写入 Local Storage、Session Storage、URL 或 DOM；成功连接后输入框立即清空。
- 页面使用每次请求随机 nonce 的 CSP、`frame-ancestors 'self'`、`X-Frame-Options: SAMEORIGIN`、`form-action 'none'` 和 `no-store`；仅允许同源 CPA 管理界面嵌入。
- 页面刷新或断开连接后必须重新输入 Management Key。
- 未配置 `policy_file` 时可以编辑，但保存仅作用于内存；界面会持续显示警告并禁用文件重载。

## 策略格式

参见 [`policies.example.yaml`](./policies.example.yaml)：

```yaml
version: 1
default_action: deny
models_endpoint: allow
allow_query_keys: true
keys:
  - id: team-a
    enabled: true
    key_sha256: "<64位 SHA-256 hex>"
    allow_models:
      - "gpt-5*"
      - "claude-sonnet-*"
    deny_models:
      - "*-preview"
```

生成 Key 哈希（不要带换行）：

```bash
printf %s "$KEY" | shasum -a 256
# Linux 也可使用：printf %s "$KEY" | sha256sum
```

匹配规则：

1. 命中任意 `deny_models`：拒绝。
2. 否则命中任意 `allow_models`：允许。
3. 否则使用 `default_action`。
4. `*` 可跨越 `/`，例如 `openai/*`；`?` 匹配一个字符。
5. 模型检查以客户端请求的模型名为准，优先使用 CPA 的 `RequestedModel`。
6. Codex Live 未显式传模型时按 CPA 默认值 `gpt-live-1-codex` 检查。
7. 不带模型的 `alpha/search` 无法确定实际权限：仅 `allow_models: ["*"]` 且无 deny 规则（或 `default_action: allow` 且无 deny 规则）的真正全模型 Key 可使用，受限 Key fail closed。
8. Live sideband 路由只携带服务器端 call ID，插件 API 不提供该会话绑定的模型；为避免跨 Key 接管，只有上述真正全模型 Key 可建立 sideband 连接。受限 Key 即使允许某个 Live 模型也会被拒绝 sideband，这是 CPA 当前 hook 的限制。

配置中可以临时使用 `key: "明文"`。插件只在内存中计算哈希；通过 Management API 保存时会删除明文并持久化 `key_sha256`。但 CPA 主配置本身不会被插件重写，因此生产配置仍建议直接使用 `key_sha256`。

## Management API

以下路由由 CPA 的 Management Key 保护：

| 方法 | 路径 | 用途 |
|---|---|---|
| `GET` | `/v0/management/plugins/key-model-access/status` | 状态和策略来源 |
| `GET` | `/v0/management/plugins/key-model-access/policies` | 获取脱敏后的完整策略 |
| `PUT` | `/v0/management/plugins/key-model-access/policies` | 原子替换全部策略 |
| `POST` | `/v0/management/plugins/key-model-access/reload` | 从 `policy_file` 重新读取 |

`GET policies` 响应包含 `revision` 和 `ETag: "rev-N"`。Web UI 保存时发送对应的 `If-Match`；自行调用 API 时也建议携带此 Header，以避免覆盖其他管理员的修改。为兼容旧客户端，不带 `If-Match` 的 PUT 仍可使用。

查询：

```bash
export CPA_URL=http://127.0.0.1:8317
export CPA_MANAGEMENT_KEY='your-management-key'

curl -sS \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_URL/v0/management/plugins/key-model-access/status"
```

整体替换策略（请求体为 JSON；可以传 `key`，响应及持久化文件只返回哈希）：

```bash
curl -sS -X PUT \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  -H 'Content-Type: application/json' \
  "$CPA_URL/v0/management/plugins/key-model-access/policies" \
  --data-binary @- <<'JSON'
{
  "version": 1,
  "default_action": "deny",
  "models_endpoint": "allow",
  "allow_query_keys": true,
  "keys": [
    {
      "id": "team-a",
      "key": "replace-with-real-key",
      "allow_models": ["gpt-5*", "claude-sonnet-*"],
      "deny_models": ["*-preview"]
    }
  ]
}
JSON
```

若配置了 `policy_file`，`PUT` 使用同目录临时文件、文件与目录 `fsync` 和重命名进行原子持久化，权限为 `0600`；未配置时只更新内存，并在下次插件重载后丢失。YAML 配置采用严格字段校验，拼写错误会在状态 API 的 `last_error` 中显示，而不会静默扩大权限。

## 验证

查看 CPA 已注册插件：

```bash
curl -sS \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  "$CPA_URL/v0/management/plugins"
```

模型授权测试：

```bash
# 允许的模型
curl -i "$CPA_URL/v1/chat/completions" \
  -H 'Authorization: Bearer your-client-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}'

# 不允许的模型不会到达上游；根据拦截阶段返回 401 或结构化 403。
curl -i "$CPA_URL/v1/chat/completions" \
  -H 'Authorization: Bearer your-client-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"not-allowed","messages":[{"role":"user","content":"hi"}]}'
```

本地质量检查：

```bash
make check   # gofmt + go vet + go test -race
make build
```

## 安全说明

- 原生插件与 CPA 同进程运行，只安装可信构建产物。
- API Key 经过 `strings.TrimSpace` 后计算 SHA-256；生成哈希时也不要带换行。
- Management API 响应设置 `Cache-Control: no-store`，不会返回明文 Key。
- `policy_file` 建议放在只有 CPA 进程用户可访问的位置，并纳入备份和容器持久化。
- 若策略文件损坏或热重载配置无效，插件保留最后一个有效策略；若启动时没有任何有效策略，则独占认证 deny-all。可通过状态 API 的 `last_error` 排查。
- 禁用或删除某个 Key 后，后续请求立即失效；当前已在上游执行中的请求不会被中断。

## 官方资料

实现依据：

- https://help.router-for.me/cn/plugin/development
- https://help.router-for.me/cn/plugin/frontend-auth-provider
- https://help.router-for.me/cn/plugin/frontend-auth-exclusive
- https://help.router-for.me/cn/plugin/request-interceptor
- https://help.router-for.me/cn/plugin/management-api
- https://github.com/router-for-me/CLIProxyAPI/tree/main/examples/plugin
