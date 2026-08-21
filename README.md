# CPA Key Provider Access

`key-provider-access` is a local CLIProxyAPI plugin derived from the layout and management UI of `key-model-access` v0.1.3. It keeps CPA's built-in downstream API-key authentication and applies a per-key allow/deny policy to upstream credential profiles instead of model names.

Profiles include both OAuth credentials and API-key-backed providers. Policies store CPA's stable auth IDs, never OAuth tokens or upstream API keys.

## Behavior

- CPA authenticates a downstream key and supplies `Metadata.caller_scope`.
- A key without a policy may use every eligible upstream profile.
- `deny_profiles` wins over `allow_profiles`.
- A non-empty `allow_profiles` list is a whitelist.
- An empty `allow_profiles` list allows every profile not matched by `deny_profiles`.
- `*` matches any number of characters and `?` matches one character.
- The scheduler chooses only among allowed candidates and round-robins eligible candidates.
- The after-auth interceptor verifies the selected auth ID before an upstream executor receives the request.
- Missing identity, missing selected-auth metadata, or invalid policy state fails closed whenever policies exist.

The scheduler receives CPA's currently eligible, highest-priority candidate tier. An allow list cannot promote a lower CPA priority tier that the host did not offer. CPA Home mode currently bypasses plugin schedulers; the after-auth check still prevents a disallowed profile from being used, but it cannot reroute that request.

Only one scheduler plugin is active in CPA (the highest-priority enabled scheduler). Configure plugin priorities deliberately if another scheduler plugin is enabled.

## Configuration

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-provider-access:
      enabled: true
      priority: 100
      version: 2
      policies: []
```

The Web UI is available at:

```text
/v0/resource/plugins/key-provider-access/settings
```

It reuses the same-origin CPAMC management session, reads downstream CPA keys to derive caller scopes, and builds a profile catalog from CPA's read-only auth/config management endpoints. Provider secrets are used only transiently to reproduce CPA's stable auth IDs and are not written to plugin state, DOM, browser storage, or URLs.

The panel identifies each downstream key with a masked head-and-tail display; the middle of the full key remains hidden. Full downstream keys are not persisted.

On first use, the UI creates `plugins/key-provider-access/config.toml` and patches only this plugin's `policy_file` setting. Policy updates use revision ETags and atomic file replacement.

## Policy schema

```toml
version = 2

[[policies]]
caller_scope = "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
allow_profiles = ["codex:apikey:abc123def456", "oauth-profile-id"]
deny_profiles = ["*-retired"]
```

Use the Web UI to derive caller scopes and choose current profile IDs. Do not put raw downstream keys, OAuth material, or provider API keys in policy files.

## Build and test

```bash
make check
make build
```

The Linux amd64 output is `dist/key-provider-access.so`. Install it as `plugins/linux/amd64/key-provider-access-v0.1.0.so` (or the unsuffixed name) and enable the matching `key-provider-access` config entry.

## Management API

- `GET /v0/management/plugins/key-provider-access/status`
- `GET/PUT /v0/management/plugins/key-provider-access/policies`
- `POST /v0/management/plugins/key-provider-access/reload`
- `POST /v0/management/plugins/key-provider-access/initialize-storage`

All routes use CPA management authentication. Status output never includes caller scopes or credentials.
