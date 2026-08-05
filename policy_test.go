package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCompileDocumentHashesPlainKeysAndAppliesDenyPrecedence(t *testing.T) {
	document := policyDocument{
		Version:       1,
		DefaultAction: "deny",
		Keys: []keyConfig{{
			ID:          "team-a",
			Key:         "secret-a",
			AllowModels: []string{"gpt-*", "provider/*"},
			DenyModels:  []string{"gpt-danger"},
		}},
	}
	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		t.Fatalf("compileDocument() error = %v", err)
	}
	if sanitized.Keys[0].Key != "" {
		t.Fatal("plain key was retained in sanitized policy")
	}
	if sanitized.Keys[0].KeySHA256 != hashKey("secret-a") {
		t.Fatalf("key hash = %q", sanitized.Keys[0].KeySHA256)
	}
	policy := snapshot.ByHash[hashKey("secret-a")]
	for model, want := range map[string]bool{
		"gpt-5":          true,
		"gpt-danger":     false,
		"provider/model": true,
		"claude-sonnet":  false,
	} {
		if got := policyAllows(snapshot, policy, model); got != want {
			t.Errorf("policyAllows(%q) = %v, want %v", model, got, want)
		}
	}
}

func TestCompileDocumentRejectsDuplicateHashes(t *testing.T) {
	_, _, err := compileDocument(policyDocument{Version: 1, Keys: []keyConfig{
		{ID: "one", Key: "same"},
		{ID: "two", KeySHA256: hashKey("same")},
	}})
	if err == nil || !strings.Contains(err.Error(), "duplicate key_sha256") {
		t.Fatalf("error = %v, want duplicate hash error", err)
	}
}

func TestExtractAPIKeySources(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		query   url.Values
		allow   bool
		want    string
	}{
		{name: "bearer", headers: http.Header{"Authorization": {"Bearer abc"}}, want: "abc"},
		{name: "x api key", headers: http.Header{"X-Api-Key": {"xyz"}}, want: "xyz"},
		{name: "google", headers: http.Header{"X-Goog-Api-Key": {"goog"}}, want: "goog"},
		{name: "query", query: url.Values{"key": {"query"}}, allow: true, want: "query"},
		{name: "query disabled", query: url.Values{"key": {"query"}}, want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := extractAPIKey(test.headers, test.query, test.allow)
			if got != test.want {
				t.Fatalf("extractAPIKey() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestExtractModelFromJSONAndGeminiPath(t *testing.T) {
	if got := extractModel("/v1/chat/completions", nil, []byte(`{"model":"gpt-5"}`)); got != "gpt-5" {
		t.Fatalf("JSON model = %q", got)
	}
	if got := extractModel("/v1beta/models/gemini-2.5-pro:generateContent", nil, nil); got != "gemini-2.5-pro" {
		t.Fatalf("Gemini path model = %q", got)
	}
}

func TestExtractModelFromLiveMultipartAndDefault(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormField("session")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(`{"model":"gpt-live-custom"}`))
	_ = writer.Close()
	headers := http.Header{"Content-Type": {writer.FormDataContentType()}}
	if got := extractModel("/v1/live", headers, body.Bytes()); got != "gpt-live-custom" {
		t.Fatalf("multipart live model = %q", got)
	}
	if got := extractModel("/v1/realtime/calls", http.Header{"Content-Type": {"application/sdp"}}, []byte("v=0")); got != "gpt-live-1-codex" {
		t.Fatalf("default live model = %q", got)
	}
}

func TestLiveMultipartUsesFinalSessionAndSupportsLargeParts(t *testing.T) {
	var duplicate bytes.Buffer
	writer := multipart.NewWriter(&duplicate)
	for _, model := range []string{"allowed", "denied"} {
		part, _ := writer.CreateFormField("session")
		_, _ = part.Write([]byte(`{"model":"` + model + `"}`))
	}
	_ = writer.Close()
	headers := http.Header{"Content-Type": {writer.FormDataContentType()}}
	if got := extractModel("/v1/live", headers, duplicate.Bytes()); got != "denied" {
		t.Fatalf("final multipart session model = %q", got)
	}

	var large bytes.Buffer
	largeWriter := multipart.NewWriter(&large)
	part, _ := largeWriter.CreateFormField("session")
	payload := `{"model":"large-denied","padding":"` + strings.Repeat("x", (3<<20)) + `"}`
	_, _ = part.Write([]byte(payload))
	_ = largeWriter.Close()
	largeHeaders := http.Header{"Content-Type": {largeWriter.FormDataContentType()}}
	if got := extractModel("/v1/live", largeHeaders, large.Bytes()); got != "large-denied" {
		t.Fatalf("large multipart session model = %q", got)
	}
}

func TestAlphaSearchUsesOnlyTopLevelModel(t *testing.T) {
	body := []byte(`{"model":"denied","session":{"model":"allowed"}}`)
	if got := extractModel("/v1/alpha/search", http.Header{"Content-Type": {"application/json"}}, body); got != "denied" {
		t.Fatalf("alpha search model = %q", got)
	}
}

func TestAuthenticateEnforcesPerKeyModels(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 1, DefaultAction: "deny", Keys: []keyConfig{{
		ID: "team-a", Key: "secret-a", AllowModels: []string{"gpt-*"},
	}}})

	allowed := callAuthenticate(t, frontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer secret-a"}},
		Body:    []byte(`{"model":"gpt-5"}`),
	})
	if !allowed.Authenticated || allowed.Metadata["key_id"] != "team-a" {
		t.Fatalf("allowed response = %#v", allowed)
	}
	denied := callAuthenticate(t, frontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer secret-a"}},
		Body:    []byte(`{"model":"claude-sonnet"}`),
	})
	if denied.Authenticated {
		t.Fatalf("denied response = %#v", denied)
	}
	unknown := callAuthenticate(t, frontendAuthRequest{
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Authorization": {"Bearer unknown"}},
		Body:    []byte(`{"model":"gpt-5"}`),
	})
	if unknown.Authenticated {
		t.Fatalf("unknown-key response = %#v", unknown)
	}
}

func TestAuthenticateBlocksLiveModelsThatBypassRequestInterceptor(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 1, DefaultAction: "deny", Keys: []keyConfig{{
		ID: "team-a", Key: "secret-a", AllowModels: []string{"gpt-5"},
	}}})
	for _, request := range []frontendAuthRequest{
		{
			Path: "/v1/live", Headers: http.Header{"Authorization": {"Bearer secret-a"}, "Content-Type": {"application/json"}},
			Body: []byte(`{"session":{"model":"gpt-live-custom"}}`),
		},
		{
			Path: "/v1/realtime/calls", Headers: http.Header{"Authorization": {"Bearer secret-a"}, "Content-Type": {"application/sdp"}},
			Body: []byte("v=0"),
		},
	} {
		if response := callAuthenticate(t, request); response.Authenticated {
			t.Fatalf("live request was authenticated: %#v", request)
		}
	}
}

func TestAuthenticateLiveSidebandFailsClosedForRestrictedKeys(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 1, DefaultAction: "deny", Keys: []keyConfig{
		{ID: "restricted", Key: "restricted-key", AllowModels: []string{"gpt-live-1-codex"}},
		{ID: "admin", Key: "admin-key", AllowModels: []string{"*"}},
	}})
	for _, path := range []string{"/v1/live/call-1", "/v1/realtime/calls/call-1", "/v1/realtime"} {
		restricted := callAuthenticate(t, frontendAuthRequest{Path: path, Headers: http.Header{"Authorization": {"Bearer restricted-key"}}})
		if restricted.Authenticated {
			t.Fatalf("restricted key authenticated for sideband %s", path)
		}
		admin := callAuthenticate(t, frontendAuthRequest{Path: path, Headers: http.Header{"Authorization": {"Bearer admin-key"}}})
		if !admin.Authenticated {
			t.Fatalf("unrestricted key denied for sideband %s", path)
		}
	}
}

func TestAlphaSearchWithoutModelRequiresUnrestrictedPolicy(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 1, DefaultAction: "deny", Keys: []keyConfig{
		{ID: "restricted", Key: "restricted-key", AllowModels: []string{"gpt-*"}},
		{ID: "admin", Key: "admin-key", AllowModels: []string{"*"}},
	}})
	request := func(key string) frontendAuthRequest {
		return frontendAuthRequest{Path: "/v1/alpha/search", Headers: http.Header{"Authorization": {"Bearer " + key}}, Body: []byte(`{"query":"test"}`)}
	}
	if callAuthenticate(t, request("restricted-key")).Authenticated {
		t.Fatal("restricted key authenticated for model-less alpha search")
	}
	if !callAuthenticate(t, request("admin-key")).Authenticated {
		t.Fatal("unrestricted key denied for model-less alpha search")
	}
}

func TestAuthenticateCanDenyModelsList(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 1, ModelsEndpoint: "deny", Keys: []keyConfig{{
		ID: "team-a", Key: "secret-a", AllowModels: []string{"*"},
	}}})
	response := callAuthenticate(t, frontendAuthRequest{
		Path: "/v1/models", Headers: http.Header{"X-Api-Key": {"secret-a"}},
	})
	if response.Authenticated {
		t.Fatalf("models list response = %#v", response)
	}
}

func TestCallerScopeMatchesCPAFixedVector(t *testing.T) {
	const want = "3394aaad3539fa0c62135da7b4685c8550686b33cccf7399c940c0a6f1f3faac"
	if got := callerScope(principalForHash(hashKey("secret-a"))); got != want {
		t.Fatalf("callerScope() = %q, want CPA vector %q", got, want)
	}
}

func TestInterceptorUsesCallerScopeAndReturns403(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 1, DefaultAction: "deny", Keys: []keyConfig{{
		ID: "team-a", Key: "secret-a", AllowModels: []string{"gpt-*"},
	}}})
	keyHash := hashKey("secret-a")
	response := callIntercept(t, requestInterceptRequest{
		RequestedModel: "claude-sonnet",
		Metadata:       map[string]any{"caller_scope": callerScope(principalForHash(keyHash))},
	})
	if !response.Terminate || response.StatusCode != http.StatusForbidden {
		t.Fatalf("interceptor response = %#v", response)
	}
	if !strings.Contains(string(response.ResponseBody), "model_access_denied") {
		t.Fatalf("response body = %s", response.ResponseBody)
	}
}

func TestManagementReplacePersistsOnlyHashes(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	installTestPolicy(t, policyDocument{Version: 1})
	cfg, snapshot, _, _, _, _ := globalState.current()
	cfg.PolicyFile = policyPath
	globalState.replace(cfg, snapshot, "test")

	body := []byte(`{"version":1,"default_action":"deny","keys":[{"id":"team-a","key":"do-not-persist","allow_models":["gpt-*"]}]}`)
	raw, err := managementReplacePolicies(body, "")
	if err != nil {
		t.Fatalf("managementReplacePolicies() error = %v", err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.StatusCode, response.Body)
	}
	persisted, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if strings.Contains(string(persisted), "do-not-persist") {
		t.Fatalf("plain key leaked to policy file:\n%s", persisted)
	}
	if !strings.Contains(string(persisted), hashKey("do-not-persist")) {
		t.Fatalf("policy file does not contain hash:\n%s", persisted)
	}
}

func TestPolicyFileRejectsUnknownYAMLFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nmodels_endpont: allow\nkeys: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "models_endpont") {
		t.Fatalf("readPolicyFile() error = %v", err)
	}
}

func TestConcurrentManagementUpdatesKeepDiskAndMemoryConsistent(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	installTestPolicy(t, policyDocument{Version: 1})
	cfg, snapshot, _, _, _, _ := globalState.current()
	cfg.PolicyFile = policyPath
	globalState.replace(cfg, snapshot, "test")

	bodies := [][]byte{
		[]byte(`{"version":1,"keys":[{"id":"one","key":"secret-one","allow_models":["gpt-*"]}]}`),
		[]byte(`{"version":1,"keys":[{"id":"two","key":"secret-two","allow_models":["claude-*"]}]}`),
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
	if len(diskSnapshot.ByHash) != 1 || len(memorySnapshot.ByHash) != 1 {
		t.Fatalf("disk policies = %d, memory policies = %d", len(diskSnapshot.ByHash), len(memorySnapshot.ByHash))
	}
	for hash := range diskSnapshot.ByHash {
		if _, exists := memorySnapshot.ByHash[hash]; !exists {
			t.Fatalf("disk and memory differ: disk hash %s", hash)
		}
	}
}

func TestConfigureLegacySchemaRegistersFailClosed(t *testing.T) {
	globalState.clear()
	t.Cleanup(globalState.clear)
	raw, _ := json.Marshal(lifecycleRequest{SchemaVersion: 1, ConfigYAML: []byte("keys:\n  - id: old\n    key: old-secret\n    allow_models: ['*']\n")})
	if err := configure(raw); err != nil {
		t.Fatalf("configure() error = %v", err)
	}
	response := callAuthenticate(t, frontendAuthRequest{
		Path: "/v1/chat/completions", Headers: http.Header{"Authorization": {"Bearer old-secret"}}, Body: []byte(`{"model":"gpt-5"}`),
	})
	if response.Authenticated {
		t.Fatal("legacy host schema did not fail closed")
	}
	registration := pluginRegistration()
	if registration.SchemaVersion != 1 || registration.Capabilities.RequestInterceptor {
		t.Fatalf("legacy registration = %#v", registration)
	}
}

func TestConfigurePreservesLastValidPolicyOnInvalidYAML(t *testing.T) {
	globalState.clear()
	t.Cleanup(globalState.clear)
	valid, _ := json.Marshal(lifecycleRequest{SchemaVersion: 2, ConfigYAML: []byte("keys:\n  - id: good\n    key: secret\n    allow_models: ['gpt-*']\n")})
	if err := configure(valid); err != nil {
		t.Fatal(err)
	}
	invalid, _ := json.Marshal(lifecycleRequest{SchemaVersion: 2, ConfigYAML: []byte("models_endpont: allow\n")})
	if err := configure(invalid); err != nil {
		t.Fatalf("invalid reconfigure should preserve and register: %v", err)
	}
	response := callAuthenticate(t, frontendAuthRequest{
		Path: "/v1/chat/completions", Headers: http.Header{"Authorization": {"Bearer secret"}}, Body: []byte(`{"model":"gpt-5"}`),
	})
	if !response.Authenticated {
		t.Fatal("last valid policy was not preserved")
	}
	_, _, _, _, _, lastError := globalState.current()
	if !strings.Contains(lastError, "models_endpont") {
		t.Fatalf("last error = %q", lastError)
	}
}

func installTestPolicy(t *testing.T, document policyDocument) {
	t.Helper()
	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		t.Fatalf("compile test policy: %v", err)
	}
	cfg := pluginConfig{
		DefaultAction:  sanitized.DefaultAction,
		ModelsEndpoint: sanitized.ModelsEndpoint,
		AllowQueryKeys: sanitized.AllowQueryKeys,
		Keys:           sanitized.Keys,
	}
	globalState.replace(cfg, snapshot, "test")
	t.Cleanup(globalState.clear)
}

func callAuthenticate(t *testing.T, request frontendAuthRequest) frontendAuthResponse {
	t.Helper()
	rawRequest, _ := json.Marshal(request)
	rawResponse, err := authenticate(rawRequest)
	if err != nil {
		t.Fatalf("authenticate() error = %v", err)
	}
	var response frontendAuthResponse
	unwrapEnvelope(t, rawResponse, &response)
	return response
}

func callIntercept(t *testing.T, request requestInterceptRequest) requestInterceptResponse {
	t.Helper()
	rawRequest, _ := json.Marshal(request)
	rawResponse, err := interceptRequest(rawRequest)
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	var response requestInterceptResponse
	unwrapEnvelope(t, rawResponse, &response)
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
