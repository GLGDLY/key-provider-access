package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func installDummyPluginBinary(t *testing.T, pluginsDir string) {
	t.Helper()
	extension := ".so"
	if runtime.GOOS == "darwin" {
		extension = ".dylib"
	} else if runtime.GOOS == "windows" {
		extension = ".dll"
	}
	platformDir := filepath.Join(pluginsDir, runtime.GOOS, runtime.GOARCH)
	if err := os.MkdirAll(platformDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(platformDir, pluginID+extension), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
}

const (
	scopeA = "c411112d71a0f4c7059026c25e281d0b46347a2173a1663735d758cd57c37bcb"
	scopeB = "d12018bebe927aab9ddea942e2b50535d414754a13f3e8ad87e00569eaa1bcf9"
)

func TestCallerScopeMatchesCPAFixedVector(t *testing.T) {
	if got := callerScope("  secret-a  "); got != scopeA {
		t.Fatalf("callerScope() = %q, want CPA vector %q", got, scopeA)
	}
}

func TestCompileDocumentV2Semantics(t *testing.T) {
	document := policyDocument{Version: 2, Policies: []policyConfig{
		{CallerScope: strings.ToUpper(scopeA), AllowProfiles: []string{"gpt-*", "gpt-*"}, DenyProfiles: []string{"gpt-danger"}},
		{CallerScope: scopeB, DenyProfiles: []string{"private-*"}},
	}}
	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		t.Fatalf("compileDocument() error = %v", err)
	}
	if sanitized.Policies[0].CallerScope != scopeA {
		t.Fatalf("caller_scope was not normalized: %q", sanitized.Policies[0].CallerScope)
	}
	first := snapshot.ByCallerScope[scopeA]
	for profile, want := range map[string]bool{
		"gpt-5":      true,
		"gpt-danger": false,
		"claude":     false,
	} {
		if got := policyAllows(first, profile); got != want {
			t.Errorf("first policyAllows(%q) = %v, want %v", profile, got, want)
		}
	}
	second := snapshot.ByCallerScope[scopeB]
	if !policyAllows(second, "gpt-5") || policyAllows(second, "private-profile") {
		t.Fatal("empty allow_profiles did not allow all profiles except deny_profiles")
	}
}

func TestCompileDocumentRejectsV1InvalidScopeAndDuplicates(t *testing.T) {
	if _, _, err := compileDocument(policyDocument{Version: 1}); err == nil || !strings.Contains(err.Error(), "only version 2") {
		t.Fatalf("v1 error = %v", err)
	}
	if _, _, err := compileDocument(policyDocument{Version: 2, Policies: []policyConfig{{CallerScope: "not-a-scope"}}}); err == nil {
		t.Fatal("invalid caller_scope was accepted")
	}
	if _, _, err := compileDocument(policyDocument{Version: 2, Policies: []policyConfig{{CallerScope: scopeA}, {CallerScope: scopeA}}}); err == nil || !strings.Contains(err.Error(), "duplicate caller_scope") {
		t.Fatalf("duplicate error = %v", err)
	}
	for _, policy := range []policyConfig{
		{CallerScope: scopeA, AllowProfiles: []string{" "}},
		{CallerScope: scopeA, DenyProfiles: []string{"\t"}},
	} {
		if _, _, err := compileDocument(policyDocument{Version: 2, Policies: []policyConfig{policy}}); err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Fatalf("blank profile pattern error = %v", err)
		}
	}
}

func TestSchedulerSelectsOnlyAllowedProfiles(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{
		CallerScope:   scopeA,
		AllowProfiles: []string{"codex:oauth-*", "claude:apikey:*"},
		DenyProfiles:  []string{"*-blocked"},
	}}})
	request := schedulerPickRequest{
		Provider: "mixed",
		Model:    "shared-model",
		Options:  schedulerOptions{Metadata: map[string]any{"caller_scope": scopeA}},
		Candidates: []schedulerAuthCandidate{
			{ID: "gemini:oauth-a", Provider: "gemini"},
			{ID: "codex:oauth-a", Provider: "codex"},
			{ID: "codex:oauth-blocked", Provider: "codex"},
			{ID: "claude:apikey:abc123", Provider: "claude"},
		},
	}
	want := map[string]bool{"codex:oauth-a": true, "claude:apikey:abc123": true}
	for index := 0; index < 4; index++ {
		rawRequest, _ := json.Marshal(request)
		rawResponse, err := pickProfile(rawRequest)
		if err != nil {
			t.Fatal(err)
		}
		var response schedulerPickResponse
		unwrapEnvelope(t, rawResponse, &response)
		if !response.Handled || !want[response.AuthID] {
			t.Fatalf("scheduler response = %#v", response)
		}
	}
}

func TestSchedulerUnconfiguredKeyFallsBackAndConfiguredKeyFailsClosed(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{
		CallerScope: scopeA, DenyProfiles: []string{"*"},
	}}})
	request := schedulerPickRequest{
		Provider:   "codex",
		Options:    schedulerOptions{Metadata: map[string]any{"caller_scope": scopeB}},
		Candidates: []schedulerAuthCandidate{{ID: "codex:oauth-a", Provider: "codex"}},
	}
	rawRequest, _ := json.Marshal(request)
	rawResponse, err := pickProfile(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	var fallback schedulerPickResponse
	unwrapEnvelope(t, rawResponse, &fallback)
	if fallback.Handled {
		t.Fatalf("unconfigured key response = %#v", fallback)
	}

	request.Options.Metadata["caller_scope"] = scopeA
	rawRequest, _ = json.Marshal(request)
	rawResponse, err = pickProfile(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	var wrapped envelope
	if err := json.Unmarshal(rawResponse, &wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped.OK || wrapped.Error == nil || wrapped.Error.Code != "profile_access_denied" || wrapped.Error.HTTPStatus != http.StatusForbidden {
		t.Fatalf("configured denied response = %#v", wrapped)
	}
}

func TestInterceptorUsesOnlyCallerScopeMetadata(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{
		CallerScope: scopeA, AllowProfiles: []string{"gpt-*"},
	}}})

	allowed := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "gpt-5"}})
	if allowed.Terminate {
		t.Fatalf("allowed response = %#v", allowed)
	}
	denied := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "claude-sonnet"}})
	if !denied.Terminate || denied.StatusCode != http.StatusForbidden {
		t.Fatalf("denied response = %#v", denied)
	}
	if strings.Contains(string(denied.ResponseBody), scopeA) {
		t.Fatalf("403 leaked caller_scope: %s", denied.ResponseBody)
	}

	// Even a valid raw key in a header cannot replace missing CPA metadata.
	headerOnly := callIntercept(t, requestInterceptRequest{
		Headers: http.Header{"Authorization": {"Bearer secret-a"}},
	})
	if !headerOnly.Terminate || headerOnly.StatusCode != http.StatusForbidden {
		t.Fatalf("header fallback was used: %#v", headerOnly)
	}
}

func TestInterceptorIdentityAndUnconfiguredKeyRules(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{CallerScope: scopeA, DenyProfiles: []string{"blocked"}}}})

	if response := callIntercept(t, requestInterceptRequest{}); !response.Terminate {
		t.Fatal("missing caller_scope was allowed while policies exist")
	}
	for _, invalidScope := range []any{"short", strings.Repeat("z", 64), 42} {
		if response := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": invalidScope, "selected_auth_id": "anything"}}); !response.Terminate {
			t.Fatalf("invalid caller_scope %#v was allowed while policies exist", invalidScope)
		}
	}
	if response := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeB, "selected_auth_id": "blocked"}}); response.Terminate {
		t.Fatalf("unconfigured caller_scope was denied: %#v", response)
	}
	if response := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA}}); !response.Terminate {
		t.Fatal("configured caller_scope with an unavailable profile was allowed")
	}

	installTestPolicy(t, policyDocument{Version: 2})
	if response := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"selected_auth_id": "anything"}}); response.Terminate {
		t.Fatalf("missing caller_scope was denied with no configured policies: %#v", response)
	}
}

func TestInitialInvalidConfigurationBlocksAll(t *testing.T) {
	globalState.clear()
	t.Cleanup(globalState.clear)
	raw, _ := json.Marshal(lifecycleRequest{SchemaVersion: 2, ConfigYAML: []byte("version: 1\npolicies: []\n")})
	if err := configure(raw); err != nil {
		t.Fatalf("configure() error = %v", err)
	}
	response := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeB, "selected_auth_id": "gpt-5"}})
	if !response.Terminate || response.StatusCode != http.StatusForbidden {
		t.Fatalf("initial invalid configuration did not block all: %#v", response)
	}
	_, snapshot, _, _, _, lastError := globalState.current()
	if !snapshot.BlockAll || !strings.Contains(lastError, "only version 2") {
		t.Fatalf("snapshot=%#v lastError=%q", snapshot, lastError)
	}
}

func TestConfigurePreservesLastValidPolicyOnInvalidReload(t *testing.T) {
	globalState.clear()
	t.Cleanup(globalState.clear)
	valid, _ := json.Marshal(lifecycleRequest{SchemaVersion: 2, ConfigYAML: []byte("enabled: true\npriority: 10\nstore: memory\nversion: 2\npolicies:\n  - caller_scope: " + scopeA + "\n    allow_profiles: [gpt-*]\n    deny_profiles: []\n")})
	if err := configure(valid); err != nil {
		t.Fatal(err)
	}
	invalid, _ := json.Marshal(lifecycleRequest{SchemaVersion: 2, ConfigYAML: []byte("version: 2\nunknown_field: true\n")})
	if err := configure(invalid); err != nil {
		t.Fatalf("invalid reconfigure should retain the snapshot: %v", err)
	}
	if response := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "claude"}}); !response.Terminate {
		t.Fatal("last valid restrictive policy was not preserved")
	}
	if response := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "gpt-5"}}); response.Terminate {
		t.Fatal("last valid allow policy was not preserved")
	}
	_, _, _, _, _, lastError := globalState.current()
	if !strings.Contains(lastError, "unknown_field") {
		t.Fatalf("last error = %q", lastError)
	}
}

func TestConfiguredMissingPolicyFileFailsClosed(t *testing.T) {
	globalState.clear()
	t.Cleanup(globalState.clear)
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	raw, _ := json.Marshal(lifecycleRequest{SchemaVersion: 2, ConfigYAML: []byte("policy_file: " + missing + "\n")})
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	_, snapshot, _, _, _, lastError := globalState.current()
	if !snapshot.BlockAll || !strings.Contains(lastError, "open policy file") {
		t.Fatalf("snapshot=%#v lastError=%q", snapshot, lastError)
	}
}

func TestPolicyFileIsStrictV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nunknown: true\npolicies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown field error = %v", err)
	}
	if err := os.WriteFile(path, []byte("version: 1\npolicies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := readPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := compileDocument(document); err == nil || !strings.Contains(err.Error(), "only version 2") {
		t.Fatalf("v1 compile error = %v", err)
	}
}

func TestTOMLPolicyFileRoundTripAndStrictFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	document := policyDocument{Version: 2, Policies: []policyConfig{{
		CallerScope:   scopeA,
		AllowProfiles: []string{"gpt-*"},
		DenyProfiles:  []string{"*-preview"},
	}}}
	if err := writePolicyFile(path, document); err != nil {
		t.Fatalf("writePolicyFile() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "[[policies]]") || !strings.Contains(string(raw), `caller_scope = "`+scopeA+`"`) {
		t.Fatalf("unexpected TOML policy:\n%s", raw)
	}
	loaded, err := readPolicyFile(path)
	if err != nil {
		t.Fatalf("readPolicyFile() error = %v", err)
	}
	if len(loaded.Policies) != 1 || loaded.Policies[0].CallerScope != scopeA {
		t.Fatalf("loaded TOML policy = %#v", loaded)
	}
	if err := os.WriteFile(path, []byte("version = 2\nunknown = true\npolicies = []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "unknown TOML fields") {
		t.Fatalf("unknown TOML field error = %v", err)
	}
}

func TestManagementInitializeStorageCreatesPluginTOMLWithoutMutatingRuntime(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{
		CallerScope:   scopeA,
		AllowProfiles: []string{"gpt-*"},
	}}})
	pluginsDir := t.TempDir()
	installDummyPluginBinary(t, pluginsDir)
	body, _ := json.Marshal(map[string]string{"plugins_dir": pluginsDir})
	raw, err := managementInitializeStorage(body)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeManagementResponse(t, raw)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("initialize status = %d body = %s", response.StatusCode, response.Body)
	}
	var payload struct {
		Created    bool   `json:"created"`
		PolicyFile string `json:"policy_file"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	expectedPath := filepath.Join(pluginsDir, pluginID, "config.toml")
	if !payload.Created || payload.PolicyFile != expectedPath {
		t.Fatalf("initialize payload = %#v, want path %q", payload, expectedPath)
	}
	document, err := readPolicyFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Policies) != 1 || document.Policies[0].CallerScope != scopeA {
		t.Fatalf("initialized document = %#v", document)
	}
	cfg, _, _, _, _, _ := globalState.current()
	if cfg.PolicyFile != "" {
		t.Fatalf("initializer mutated runtime policy_file before host config PATCH: %q", cfg.PolicyFile)
	}

	raw, err = managementInitializeStorage(body)
	if err != nil {
		t.Fatal(err)
	}
	response = decodeManagementResponse(t, raw)
	if response.StatusCode != http.StatusOK || strings.Contains(string(response.Body), `"created":true`) {
		t.Fatalf("second initialize response = %d %s", response.StatusCode, response.Body)
	}
}

func TestManagementInitializeStorageRejectsUnverifiedDirectory(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2})
	body, _ := json.Marshal(map[string]string{"plugins_dir": t.TempDir()})
	raw, err := managementInitializeStorage(body)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeManagementResponse(t, raw)
	if response.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(response.Body), "installed key-provider-access binary") {
		t.Fatalf("unverified plugins_dir response = %d %s", response.StatusCode, response.Body)
	}
}

func TestManagementInitializeStorageDoesNotOverwriteInvalidExistingFile(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2})
	pluginsDir := t.TempDir()
	installDummyPluginBinary(t, pluginsDir)
	policyDir := filepath.Join(pluginsDir, pluginID)
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policyDir, "config.toml")
	original := []byte("version = 1\npolicies = []\n")
	if err := os.WriteFile(policyPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"plugins_dir": pluginsDir})
	raw, err := managementInitializeStorage(body)
	if err != nil {
		t.Fatal(err)
	}
	response := decodeManagementResponse(t, raw)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("initialize status = %d body = %s", response.StatusCode, response.Body)
	}
	persisted, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(persisted) != string(original) {
		t.Fatalf("invalid existing file was overwritten:\n%s", persisted)
	}
}

func TestManagementPUTRejectsLegacyIdentityFields(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2})
	for _, forbidden := range []string{"key", "key_sha256", "id", "enabled"} {
		body := []byte(`{"version":2,"policies":[{"caller_scope":"` + scopeA + `","allow_profiles":[],"deny_profiles":[],"` + forbidden + `":"value"}]}`)
		raw, err := managementReplacePolicies(body, "")
		if err != nil {
			t.Fatal(err)
		}
		response := decodeManagementResponse(t, raw)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("field %q status = %d body = %s", forbidden, response.StatusCode, response.Body)
		}
	}
}

func TestManagementPersistenceAndGETUseOnlyV2Schema(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	installTestPolicy(t, policyDocument{Version: 2})
	cfg, snapshot, _, _, _, _ := globalState.current()
	cfg.PolicyFile = policyPath
	globalState.replace(cfg, snapshot, "test")

	body := []byte(`{"version":2,"policies":[{"caller_scope":"` + scopeA + `","allow_profiles":["gpt-*"],"deny_profiles":[]}]}`)
	raw, err := managementReplacePolicies(body, "")
	if err != nil {
		t.Fatal(err)
	}
	if response := decodeManagementResponse(t, raw); response.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d body = %s", response.StatusCode, response.Body)
	}
	persisted, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"key:", "key_sha256:", "id:", "enabled:"} {
		if strings.Contains(string(persisted), forbidden) {
			t.Fatalf("persisted policy contains %q:\n%s", forbidden, persisted)
		}
	}
	if !strings.Contains(string(persisted), "version: 2") || !strings.Contains(string(persisted), "caller_scope:") {
		t.Fatalf("unexpected persisted document:\n%s", persisted)
	}

	raw, err = managementPolicies()
	if err != nil {
		t.Fatal(err)
	}
	response := decodeManagementResponse(t, raw)
	for _, forbidden := range []string{`"key":`, `"key_sha256":`, `"id":`, `"enabled":`} {
		if strings.Contains(string(response.Body), forbidden) {
			t.Fatalf("GET policy contains forbidden field %s: %s", forbidden, response.Body)
		}
	}
	if strings.Contains(string(response.Body), `"allow_profiles":null`) || strings.Contains(string(response.Body), `"deny_profiles":null`) {
		t.Fatalf("GET policy returned null profile arrays: %s", response.Body)
	}
	var payload struct {
		Policy map[string]json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Policy) != 2 || payload.Policy["version"] == nil || payload.Policy["policies"] == nil {
		t.Fatalf("GET policy schema = %#v", payload.Policy)
	}
}

func TestManagementReloadKeepsLastValidSnapshotOnInvalidFile(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policies.yaml")
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{
		CallerScope: scopeA, AllowProfiles: []string{"gpt-*"},
	}}})
	cfg, snapshot, _, _, _, _ := globalState.current()
	cfg.PolicyFile = policyPath
	globalState.replace(cfg, snapshot, "test")
	if err := os.WriteFile(policyPath, []byte("version: 1\npolicies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := managementReload()
	if err != nil {
		t.Fatal(err)
	}
	response := decodeManagementResponse(t, raw)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("reload status = %d body = %s", response.StatusCode, response.Body)
	}
	if result := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "claude"}}); !result.Terminate {
		t.Fatal("invalid reload replaced the last valid snapshot")
	}
	_, _, _, _, _, lastError := globalState.current()
	if !strings.Contains(lastError, "only version 2") {
		t.Fatalf("last error = %q", lastError)
	}
}

func TestConcurrentManagementUpdatesKeepDiskAndMemoryConsistent(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policies.yaml")
	installTestPolicy(t, policyDocument{Version: 2})
	cfg, snapshot, _, _, _, _ := globalState.current()
	cfg.PolicyFile = policyPath
	globalState.replace(cfg, snapshot, "test")

	bodies := [][]byte{
		[]byte(`{"version":2,"policies":[{"caller_scope":"` + scopeA + `","allow_profiles":["gpt-*"],"deny_profiles":[]}]}`),
		[]byte(`{"version":2,"policies":[{"caller_scope":"` + scopeB + `","allow_profiles":["claude-*"],"deny_profiles":[]}]}`),
	}
	var wait sync.WaitGroup
	for _, body := range bodies {
		body := body
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := managementReplacePolicies(body, ""); err != nil {
				t.Errorf("managementReplacePolicies() error = %v", err)
			}
		}()
	}
	wait.Wait()

	diskDocument, err := readPolicyFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	diskSnapshot, _, err := compileDocument(diskDocument)
	if err != nil {
		t.Fatal(err)
	}
	_, memorySnapshot, _, _, _, _ := globalState.current()
	if len(diskSnapshot.ByCallerScope) != 1 || len(memorySnapshot.ByCallerScope) != 1 {
		t.Fatalf("disk policies = %d, memory policies = %d", len(diskSnapshot.ByCallerScope), len(memorySnapshot.ByCallerScope))
	}
	for scope := range diskSnapshot.ByCallerScope {
		if _, exists := memorySnapshot.ByCallerScope[scope]; !exists {
			t.Fatalf("disk and memory differ: disk caller_scope %s", scope)
		}
	}
}

func TestStatusReportsBuiltinAuthenticationContract(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{CallerScope: scopeA}}})
	raw, err := managementStatus()
	if err != nil {
		t.Fatal(err)
	}
	response := decodeManagementResponse(t, raw)
	var status map[string]any
	if err := json.Unmarshal(response.Body, &status); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"auth_mode":               "cpa_builtin_api_keys",
		"identity_source":         "Metadata.caller_scope",
		"unconfigured_key_action": "allow",
	} {
		if status[field] != want {
			t.Errorf("status[%q] = %#v, want %q", field, status[field], want)
		}
	}
	if status["policy_count"] != float64(1) {
		t.Fatalf("policy_count = %#v", status["policy_count"])
	}
}

func TestRegistrationHasNoFrontendAuthCapabilityOrMethod(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2})
	globalState.setHostSchema(2)
	raw, err := json.Marshal(pluginRegistration().Capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "frontend_auth") {
		t.Fatalf("registration still advertises frontend auth: %s", raw)
	}
	if !pluginRegistration().Capabilities.Scheduler {
		t.Fatal("registration does not advertise scheduler capability")
	}
	response, err := handleMethod("frontend_auth.authenticate", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var wrapped envelope
	if err := json.Unmarshal(response, &wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped.OK || wrapped.Error == nil || wrapped.Error.Code != "unknown_method" {
		t.Fatalf("frontend auth method response = %#v", wrapped)
	}
}

func installTestPolicy(t *testing.T, document policyDocument) {
	t.Helper()
	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		t.Fatalf("compile test policy: %v", err)
	}
	cfg := pluginConfig{Version: sanitized.Version, Policies: clonePolicyConfigs(sanitized.Policies)}
	globalState.replace(cfg, snapshot, "test")
	t.Cleanup(globalState.clear)
}

func callIntercept(t *testing.T, request requestInterceptRequest) requestInterceptResponse {
	t.Helper()
	rawRequest, _ := json.Marshal(request)
	rawResponse, err := interceptRequest(rawRequest, true)
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	var response requestInterceptResponse
	unwrapEnvelope(t, rawResponse, &response)
	return response
}

func decodeManagementResponse(t *testing.T, raw []byte) managementResponse {
	t.Helper()
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	return response
}

func unwrapEnvelope(t *testing.T, raw []byte, target any) {
	t.Helper()
	var wrapped envelope
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if !wrapped.OK {
		t.Fatalf("envelope error: %#v", wrapped.Error)
	}
	if err := json.Unmarshal(wrapped.Result, target); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
}
