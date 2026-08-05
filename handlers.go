package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	policiesPath         = "/v0/management/plugins/key-model-access/policies"
	statusPath           = "/v0/management/plugins/key-model-access/status"
	reloadPath           = "/v0/management/plugins/key-model-access/reload"
	settingsResourcePath = "/v0/resource/plugins/key-model-access/settings"
)

func authenticate(raw []byte) ([]byte, error) {
	var req frontendAuthRequest
	if err := decodeJSON(raw, &req); err != nil {
		return okEnvelope(frontendAuthResponse{Authenticated: false})
	}
	_, snapshot, _, _, hostSchema, _ := globalState.current()
	if hostSchema > 0 && hostSchema < schemaVersion {
		return okEnvelope(frontendAuthResponse{Authenticated: false})
	}
	key, source := extractAPIKey(req.Headers, req.Query, snapshot.AllowQueryKeys)
	if key == "" {
		return okEnvelope(frontendAuthResponse{Authenticated: false})
	}
	policy, exists := snapshot.ByHash[hashKey(key)]
	if !exists {
		return okEnvelope(frontendAuthResponse{Authenticated: false})
	}

	if isModelsListPath(req.Path) && snapshot.ModelsEndpoint == "deny" {
		return okEnvelope(frontendAuthResponse{Authenticated: false})
	}
	// CPA's Live sideband handshake carries only a call ID; the plugin API does
	// not expose the model bound to that server-side session. Restricted keys
	// therefore fail closed, while genuinely unrestricted keys may connect.
	if isLiveSidebandPath(req.Path) && !policyAllowsAllModels(snapshot, policy) {
		return okEnvelope(frontendAuthResponse{Authenticated: false})
	}
	// Enforce as early as possible. The request interceptor repeats this check with
	// CPA's authoritative RequestedModel to cover protocols not parsed here.
	model := extractModel(req.Path, req.Headers, req.Body)
	if model != "" && !policyAllows(snapshot, policy, model) {
		return okEnvelope(frontendAuthResponse{Authenticated: false})
	}
	if model == "" && isDirectModelRoute(req.Path) && !policyAllowsAllModels(snapshot, policy) {
		return okEnvelope(frontendAuthResponse{Authenticated: false})
	}
	return okEnvelope(frontendAuthResponse{
		Authenticated: true,
		Principal:     principalForHash(policy.KeySHA256),
		Metadata: map[string]string{
			"key_id": policy.ID,
			"source": source,
		},
	})
}

func interceptRequest(raw []byte) ([]byte, error) {
	var req requestInterceptRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	model := strings.TrimSpace(req.RequestedModel)
	if model == "" {
		model = strings.TrimSpace(req.Model)
	}
	if model == "" {
		return okEnvelope(requestInterceptResponse{})
	}

	_, snapshot, _, _, _, _ := globalState.current()
	policy, found := policyFromInterceptRequest(snapshot, req)
	if !found {
		return terminatedPolicyResponse(http.StatusForbidden, "model access identity is unavailable", model, "")
	}
	if !policyAllows(snapshot, policy, model) {
		return terminatedPolicyResponse(http.StatusForbidden, "model is not allowed for this API key", model, policy.ID)
	}
	return okEnvelope(requestInterceptResponse{})
}

func policyFromInterceptRequest(snapshot policySnapshot, req requestInterceptRequest) (runtimePolicy, bool) {
	if scope, ok := req.Metadata["caller_scope"].(string); ok {
		if policy, exists := snapshot.ByCallerScope[strings.TrimSpace(scope)]; exists {
			return policy, true
		}
	}
	key, _ := extractAPIKey(req.Headers, nil, false)
	if key == "" {
		return runtimePolicy{}, false
	}
	policy, exists := snapshot.ByHash[hashKey(key)]
	return policy, exists
}

func terminatedPolicyResponse(status int, message, model, keyID string) ([]byte, error) {
	errorObject := map[string]any{
		"error": map[string]any{
			"type":    "model_access_denied",
			"message": message,
			"model":   model,
		},
	}
	if keyID != "" {
		errorObject["error"].(map[string]any)["key_id"] = keyID
	}
	body, err := json.Marshal(errorObject)
	if err != nil {
		return nil, err
	}
	return okEnvelope(requestInterceptResponse{
		Terminate:       true,
		StatusCode:      status,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		ResponseBody:    body,
	})
}

func managementRegistration() managementRegistrationResponse {
	return managementRegistrationResponse{
		Routes: []managementRoute{
			{Method: http.MethodGet, Path: statusPath, Description: "Show key-model-access status without exposing API keys."},
			{Method: http.MethodGet, Path: policiesPath, Description: "List sanitized per-key model policies."},
			{Method: http.MethodPut, Path: policiesPath, Description: "Replace all per-key model policies."},
			{Method: http.MethodPost, Path: reloadPath, Description: "Reload policies from policy_file."},
		},
		Resources: []resourceRoute{{
			Path:        "/settings",
			Menu:        "模型权限",
			Description: "Manage per-key model access policies in a browser.",
		}},
	}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req managementRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	path := strings.TrimRight(strings.TrimSpace(req.Path), "/")
	switch {
	case method == http.MethodGet && path == settingsResourcePath:
		return settingsPage()
	case method == http.MethodGet && path == statusPath:
		return managementStatus()
	case method == http.MethodGet && path == policiesPath:
		return managementPolicies()
	case method == http.MethodPut && path == policiesPath:
		return managementReplacePolicies(req.Body, req.Headers.Get("If-Match"))
	case method == http.MethodPost && path == reloadPath:
		return managementReload()
	default:
		return managementJSON(http.StatusNotFound, map[string]any{"error": "management route not found"})
	}
}

func managementStatus() ([]byte, error) {
	cfg, snapshot, source, updatedAt, hostSchema, lastError, revision := globalState.currentWithRevision()
	return managementJSON(http.StatusOK, map[string]any{
		"plugin":              pluginID,
		"version":             pluginVersion,
		"schema_version":      schemaVersion,
		"host_schema_version": hostSchema,
		"last_error":          lastError,
		"policy_count":        len(snapshot.ByHash),
		"revision":            revision,
		"default_action":      snapshot.DefaultAction,
		"models_endpoint":     snapshot.ModelsEndpoint,
		"allow_query_keys":    snapshot.AllowQueryKeys,
		"policy_file":         cfg.PolicyFile,
		"persistent_updates":  cfg.PolicyFile != "",
		"source":              source,
		"updated_at":          formattedTime(updatedAt),
		"models_list_note":    "/v1/models is global in CPA; plugins can allow or deny it but cannot filter it per API key.",
	})
}

func managementPolicies() ([]byte, error) {
	cfg, snapshot, source, updatedAt, _, _, revision := globalState.currentWithRevision()
	document := documentFromConfig(cfg)
	document.DefaultAction = snapshot.DefaultAction
	document.ModelsEndpoint = snapshot.ModelsEndpoint
	document.AllowQueryKeys = boolPointer(snapshot.AllowQueryKeys)
	for index := range document.Keys {
		document.Keys[index].Key = ""
	}
	return managementJSONWithHeaders(http.StatusOK, map[string]any{
		"policy":     document,
		"revision":   revision,
		"source":     source,
		"updated_at": formattedTime(updatedAt),
	}, http.Header{"ETag": []string{etagForRevision(revision)}})
}

func managementReplacePolicies(body []byte, ifMatch string) ([]byte, error) {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	if strings.TrimSpace(ifMatch) != "" {
		expected, err := parseRevisionETag(ifMatch)
		if err != nil {
			return managementJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		}
		current := globalState.policyRevision()
		if expected != current {
			return managementJSON(http.StatusPreconditionFailed, map[string]any{
				"error":            "policy changed since it was loaded; reload before saving",
				"current_revision": current,
			})
		}
	}

	if len(body) == 0 || len(body) > maxPolicyFileSize {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("policy body must be between 1 and %d bytes", maxPolicyFileSize)})
	}
	var document policyDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "invalid policy JSON: " + err.Error()})
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
	}
	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
	}

	cfg, _, _, _, _, _ := globalState.current()
	if cfg.PolicyFile != "" {
		if err := writePolicyFile(cfg.PolicyFile, sanitized); err != nil {
			return managementJSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
	}
	cfg.DefaultAction = sanitized.DefaultAction
	cfg.ModelsEndpoint = sanitized.ModelsEndpoint
	cfg.AllowQueryKeys = sanitized.AllowQueryKeys
	cfg.Keys = sanitized.Keys
	source := "Management API (memory only)"
	if cfg.PolicyFile != "" {
		source = cfg.PolicyFile
	}
	globalState.replace(cfg, snapshot, source)
	revision := globalState.policyRevision()
	return managementJSONWithHeaders(http.StatusOK, map[string]any{
		"ok":           true,
		"policy_count": len(snapshot.ByHash),
		"persistent":   cfg.PolicyFile != "",
		"revision":     revision,
		"policy":       sanitized,
	}, http.Header{"ETag": []string{etagForRevision(revision)}})
}

func managementReload() ([]byte, error) {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	cfg, _, _, _, _, _ := globalState.current()
	if cfg.PolicyFile == "" {
		return managementJSON(http.StatusConflict, map[string]any{"error": "policy_file is not configured"})
	}
	document, err := readPolicyFile(cfg.PolicyFile)
	if err != nil {
		return managementJSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
	}
	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
	}
	cfg.DefaultAction = sanitized.DefaultAction
	cfg.ModelsEndpoint = sanitized.ModelsEndpoint
	cfg.AllowQueryKeys = sanitized.AllowQueryKeys
	cfg.Keys = sanitized.Keys
	globalState.replace(cfg, snapshot, cfg.PolicyFile)
	return managementJSON(http.StatusOK, map[string]any{
		"ok": true, "policy_count": len(snapshot.ByHash), "revision": globalState.policyRevision(),
	})
}

func managementJSON(status int, value any) ([]byte, error) {
	return managementJSONWithHeaders(status, value, nil)
}

func managementJSONWithHeaders(status int, value any, extra http.Header) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	headers := http.Header{"Content-Type": []string{"application/json; charset=utf-8"}, "Cache-Control": []string{"no-store"}}
	for name, values := range extra {
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	return okEnvelope(managementResponse{StatusCode: status, Headers: headers, Body: body})
}

func etagForRevision(revision uint64) string {
	return fmt.Sprintf("\"rev-%d\"", revision)
}

func parseRevisionETag(value string) (uint64, error) {
	value = strings.Trim(strings.TrimSpace(value), "\"")
	value = strings.TrimPrefix(value, "rev-")
	if value == "" {
		return 0, fmt.Errorf("If-Match must contain a policy revision ETag")
	}
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid policy revision ETag")
	}
	return revision, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return fmt.Errorf("policy body must contain one JSON object")
}

func formattedTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
