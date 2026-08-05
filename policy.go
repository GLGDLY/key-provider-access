package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const maxPolicyFileSize = 2 << 20

type pluginConfig struct {
	Enabled        *bool       `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Priority       int         `json:"priority,omitempty" yaml:"priority,omitempty"`
	Store          any         `json:"store,omitempty" yaml:"store,omitempty"`
	PolicyFile     string      `json:"policy_file" yaml:"policy_file"`
	DefaultAction  string      `json:"default_action" yaml:"default_action"`
	ModelsEndpoint string      `json:"models_endpoint" yaml:"models_endpoint"`
	AllowQueryKeys *bool       `json:"allow_query_keys" yaml:"allow_query_keys"`
	Keys           []keyConfig `json:"keys" yaml:"keys"`
}

type policyDocument struct {
	Version        int         `json:"version" yaml:"version"`
	DefaultAction  string      `json:"default_action" yaml:"default_action"`
	ModelsEndpoint string      `json:"models_endpoint" yaml:"models_endpoint"`
	AllowQueryKeys *bool       `json:"allow_query_keys,omitempty" yaml:"allow_query_keys,omitempty"`
	Keys           []keyConfig `json:"keys" yaml:"keys"`
}

type keyConfig struct {
	ID          string   `json:"id" yaml:"id"`
	Enabled     *bool    `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Key         string   `json:"key,omitempty" yaml:"key,omitempty"`
	KeySHA256   string   `json:"key_sha256,omitempty" yaml:"key_sha256,omitempty"`
	AllowModels []string `json:"allow_models" yaml:"allow_models"`
	DenyModels  []string `json:"deny_models,omitempty" yaml:"deny_models,omitempty"`
}

type runtimePolicy struct {
	ID          string
	KeySHA256   string
	AllowModels []string
	DenyModels  []string
}

type policySnapshot struct {
	DefaultAction  string
	ModelsEndpoint string
	AllowQueryKeys bool
	ByHash         map[string]runtimePolicy
	ByCallerScope  map[string]runtimePolicy
}

type state struct {
	mu             sync.RWMutex
	config         pluginConfig
	snapshot       policySnapshot
	source         string
	updatedAt      time.Time
	hostSchema     uint32
	hasValidPolicy bool
	lastError      string
	revision       uint64
}

var (
	globalState = state{snapshot: emptySnapshot()}
	mutationMu  sync.Mutex
)

func emptySnapshot() policySnapshot {
	return policySnapshot{
		DefaultAction:  "deny",
		ModelsEndpoint: "allow",
		AllowQueryKeys: true,
		ByHash:         make(map[string]runtimePolicy),
		ByCallerScope:  make(map[string]runtimePolicy),
	}
}

func (s *state) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = pluginConfig{}
	s.snapshot = emptySnapshot()
	s.source = ""
	s.updatedAt = time.Time{}
	s.hostSchema = 0
	s.hasValidPolicy = false
	s.lastError = ""
	s.revision = 0
}

func (s *state) current() (pluginConfig, policySnapshot, string, time.Time, uint32, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.snapshot, s.source, s.updatedAt, s.hostSchema, s.lastError
}

func (s *state) currentWithRevision() (pluginConfig, policySnapshot, string, time.Time, uint32, string, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.snapshot, s.source, s.updatedAt, s.hostSchema, s.lastError, s.revision
}

func (s *state) replace(cfg pluginConfig, snapshot policySnapshot, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
	s.snapshot = snapshot
	s.source = source
	s.updatedAt = time.Now().UTC()
	s.hasValidPolicy = true
	s.lastError = ""
	s.revision++
}

func (s *state) policyRevision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

func (s *state) setHostSchema(schema uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSchema = schema
}

func (s *state) failClosedOrPreserve(cfg pluginConfig, schema uint32, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSchema = schema
	s.lastError = cause.Error()
	if schema >= schemaVersion && s.hasValidPolicy {
		return
	}
	s.config = cfg
	s.snapshot = emptySnapshot()
	s.snapshot.ModelsEndpoint = "deny"
	s.source = "fail-closed: " + cause.Error()
	s.updatedAt = time.Now().UTC()
	s.hasValidPolicy = false
	s.revision++
}

func configure(raw []byte) error {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	var req lifecycleRequest
	if err := decodeJSON(raw, &req); err != nil {
		return err
	}
	cfg := pluginConfig{DefaultAction: "deny", ModelsEndpoint: "allow"}
	allowQuery := true
	cfg.AllowQueryKeys = &allowQuery
	if req.SchemaVersion < schemaVersion {
		globalState.failClosedOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("%s requires CPA plugin RPC schema 2 or newer (CPA v7.2.103+)", pluginID))
		return nil
	}
	if len(req.ConfigYAML) > 0 {
		if err := decodeStrictYAML(req.ConfigYAML, &cfg); err != nil {
			globalState.failClosedOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("decode plugin config: %w", err))
			return nil
		}
	}
	cfg.PolicyFile = strings.TrimSpace(cfg.PolicyFile)

	document := documentFromConfig(cfg)
	source := "inline config"
	if cfg.PolicyFile != "" {
		loaded, err := readPolicyFile(cfg.PolicyFile)
		switch {
		case err == nil:
			document = loaded
			source = cfg.PolicyFile
		case errors.Is(err, os.ErrNotExist):
			source = "inline config (policy file not found: " + cfg.PolicyFile + ")"
		default:
			globalState.failClosedOrPreserve(cfg, req.SchemaVersion, err)
			return nil
		}
	}

	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		globalState.failClosedOrPreserve(cfg, req.SchemaVersion, err)
		return nil
	}
	cfg.DefaultAction = sanitized.DefaultAction
	cfg.ModelsEndpoint = sanitized.ModelsEndpoint
	cfg.AllowQueryKeys = sanitized.AllowQueryKeys
	cfg.Keys = sanitized.Keys
	globalState.setHostSchema(req.SchemaVersion)
	globalState.replace(cfg, snapshot, source)
	return nil
}

func documentFromConfig(cfg pluginConfig) policyDocument {
	return policyDocument{
		Version:        1,
		DefaultAction:  cfg.DefaultAction,
		ModelsEndpoint: cfg.ModelsEndpoint,
		AllowQueryKeys: cfg.AllowQueryKeys,
		Keys:           cfg.Keys,
	}
}

func readPolicyFile(path string) (policyDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return policyDocument{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return policyDocument{}, fmt.Errorf("stat policy file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return policyDocument{}, fmt.Errorf("policy file %q is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return policyDocument{}, fmt.Errorf("read policy file %q: %w", path, err)
	}
	if len(raw) > maxPolicyFileSize {
		return policyDocument{}, fmt.Errorf("policy file %q exceeds %d bytes", path, maxPolicyFileSize)
	}
	var document policyDocument
	if err := decodeStrictYAML(raw, &document); err != nil {
		return policyDocument{}, fmt.Errorf("decode policy file %q: %w", path, err)
	}
	return document, nil
}

func decodeStrictYAML(raw []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("multiple YAML documents are not allowed")
}

func compileDocument(document policyDocument) (policySnapshot, policyDocument, error) {
	if document.Version == 0 {
		document.Version = 1
	}
	if document.Version != 1 {
		return policySnapshot{}, policyDocument{}, fmt.Errorf("unsupported policy version %d", document.Version)
	}
	document.DefaultAction = normalizeAction(document.DefaultAction, "deny")
	if document.DefaultAction != "allow" && document.DefaultAction != "deny" {
		return policySnapshot{}, policyDocument{}, fmt.Errorf("default_action must be allow or deny")
	}
	document.ModelsEndpoint = normalizeAction(document.ModelsEndpoint, "allow")
	if document.ModelsEndpoint != "allow" && document.ModelsEndpoint != "deny" {
		return policySnapshot{}, policyDocument{}, fmt.Errorf("models_endpoint must be allow or deny")
	}
	allowQuery := true
	if document.AllowQueryKeys != nil {
		allowQuery = *document.AllowQueryKeys
	}
	document.AllowQueryKeys = boolPointer(allowQuery)

	snapshot := policySnapshot{
		DefaultAction:  document.DefaultAction,
		ModelsEndpoint: document.ModelsEndpoint,
		AllowQueryKeys: allowQuery,
		ByHash:         make(map[string]runtimePolicy),
		ByCallerScope:  make(map[string]runtimePolicy),
	}

	ids := make(map[string]struct{}, len(document.Keys))
	for index := range document.Keys {
		item := &document.Keys[index]
		enabled := item.Enabled == nil || *item.Enabled
		item.Enabled = boolPointer(enabled)
		item.ID = strings.TrimSpace(item.ID)
		item.Key = strings.TrimSpace(item.Key)
		item.KeySHA256 = strings.ToLower(strings.TrimSpace(item.KeySHA256))
		if item.Key != "" {
			calculated := hashKey(item.Key)
			if item.KeySHA256 != "" && item.KeySHA256 != calculated {
				return policySnapshot{}, policyDocument{}, fmt.Errorf("keys[%d] key and key_sha256 do not match", index)
			}
			item.KeySHA256 = calculated
			item.Key = ""
		}
		if !validSHA256(item.KeySHA256) {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("keys[%d].key_sha256 must be 64 lowercase or uppercase hex characters", index)
		}
		if item.ID == "" {
			item.ID = "key-" + item.KeySHA256[:12]
		}
		if _, exists := ids[item.ID]; exists {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("duplicate key id %q", item.ID)
		}
		ids[item.ID] = struct{}{}
		if _, exists := snapshot.ByHash[item.KeySHA256]; exists {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("duplicate key_sha256 for id %q", item.ID)
		}
		item.AllowModels = normalizePatterns(item.AllowModels)
		item.DenyModels = normalizePatterns(item.DenyModels)
		if !enabled {
			continue
		}
		policy := runtimePolicy{
			ID: item.ID, KeySHA256: item.KeySHA256,
			AllowModels: append([]string(nil), item.AllowModels...),
			DenyModels:  append([]string(nil), item.DenyModels...),
		}
		snapshot.ByHash[item.KeySHA256] = policy
		snapshot.ByCallerScope[callerScope(principalForHash(item.KeySHA256))] = policy
	}
	return snapshot, document, nil
}

func normalizeAction(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func normalizePatterns(patterns []string) []string {
	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func principalForHash(keyHash string) string {
	return pluginID + ":" + keyHash
}

func callerScope(principal string) string {
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + strings.TrimSpace(principal)))
	return hex.EncodeToString(sum[:])
}

func boolPointer(value bool) *bool { return &value }

func policyAllows(snapshot policySnapshot, policy runtimePolicy, model string) bool {
	model = strings.TrimSpace(model)
	for _, pattern := range policy.DenyModels {
		if wildcardMatch(pattern, model) {
			return false
		}
	}
	for _, pattern := range policy.AllowModels {
		if wildcardMatch(pattern, model) {
			return true
		}
	}
	return snapshot.DefaultAction == "allow"
}

func policyAllowsAllModels(snapshot policySnapshot, policy runtimePolicy) bool {
	if len(policy.DenyModels) != 0 {
		return false
	}
	if snapshot.DefaultAction == "allow" {
		return true
	}
	for _, pattern := range policy.AllowModels {
		if pattern == "*" {
			return true
		}
	}
	return false
}

// wildcardMatch supports shell-style '*' and '?' while allowing '*' to cross '/'.
func wildcardMatch(pattern, value string) bool {
	patternRunes, valueRunes := []rune(pattern), []rune(value)
	p, v, star, checkpoint := 0, 0, -1, 0
	for v < len(valueRunes) {
		if p < len(patternRunes) && (patternRunes[p] == '?' || patternRunes[p] == valueRunes[v]) {
			p++
			v++
			continue
		}
		if p < len(patternRunes) && patternRunes[p] == '*' {
			star = p
			p++
			checkpoint = v
			continue
		}
		if star >= 0 {
			p = star + 1
			checkpoint++
			v = checkpoint
			continue
		}
		return false
	}
	for p < len(patternRunes) && patternRunes[p] == '*' {
		p++
	}
	return p == len(patternRunes)
}

func extractAPIKey(headers http.Header, query url.Values, allowQuery bool) (string, string) {
	for _, value := range headers.Values("Authorization") {
		parts := strings.Fields(value)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1]), "authorization"
		}
	}
	for _, name := range []string{"X-Goog-Api-Key", "X-Api-Key"} {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			return value, strings.ToLower(name)
		}
	}
	if allowQuery {
		for _, name := range []string{"key", "auth_token"} {
			if value := strings.TrimSpace(query.Get(name)); value != "" {
				return value, "query-" + name
			}
		}
	}
	return "", ""
}

func extractModel(path string, headers http.Header, body []byte) string {
	if isLiveBootstrapPath(path) {
		if model := liveModelFromJSON(body); model != "" {
			return model
		}
		if model := modelFromLiveMultipart(headers.Get("Content-Type"), body); model != "" {
			return model
		}
		// This is CPA's current default for JSON, SDP, plain text, and multipart
		// live bootstrap requests that omit session.model.
		return "gpt-live-1-codex"
	}
	if model := topLevelModelFromJSON(body); model != "" {
		return model
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for index := 0; index+1 < len(parts); index++ {
		if !strings.EqualFold(parts[index], "models") {
			continue
		}
		model := strings.TrimSpace(strings.SplitN(parts[index+1], ":", 2)[0])
		if decoded, err := url.PathUnescape(model); err == nil {
			model = decoded
		}
		return model
	}
	return ""
}

func topLevelModelFromJSON(body []byte) string {
	if len(body) == 0 || !json.Valid(body) {
		return ""
	}
	var payload struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	return strings.TrimSpace(payload.Model)
}

func liveModelFromJSON(body []byte) string {
	if len(body) == 0 || !json.Valid(body) {
		return ""
	}
	var payload struct {
		Model   string `json:"model"`
		Session struct {
			Model string `json:"model"`
		} `json:"session"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	if model := strings.TrimSpace(payload.Session.Model); model != "" {
		return model
	}
	return strings.TrimSpace(payload.Model)
}

func modelFromLiveMultipart(contentType string, body []byte) string {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") || strings.TrimSpace(params["boundary"]) == "" {
		return ""
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	model := ""
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return model
		}
		if err != nil {
			return ""
		}
		partBody, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil {
			return ""
		}
		if part.FormName() == "session" {
			// CPA processes all fields and the final session field wins.
			model = topLevelModelFromJSON(partBody)
		}
	}
}

func normalizedRequestPath(path string) string {
	return "/" + strings.Trim(strings.TrimSpace(path), "/")
}

func isLiveBootstrapPath(path string) bool {
	cleaned := normalizedRequestPath(path)
	return cleaned == "/v1/live" || cleaned == "/v1/realtime/calls"
}

func isLiveSidebandPath(path string) bool {
	cleaned := normalizedRequestPath(path)
	if cleaned == "/v1/realtime" {
		return true
	}
	for _, prefix := range []string{"/v1/live/", "/v1/realtime/calls/"} {
		if suffix := strings.TrimPrefix(cleaned, prefix); suffix != cleaned && suffix != "" && !strings.Contains(suffix, "/") {
			return true
		}
	}
	return false
}

func isDirectModelRoute(path string) bool {
	cleaned := normalizedRequestPath(path)
	return isLiveBootstrapPath(cleaned) || cleaned == "/v1/alpha/search" || cleaned == "/backend-api/codex/alpha/search"
}

func isModelsListPath(path string) bool {
	cleaned := normalizedRequestPath(path)
	return cleaned == "/v1/models" || cleaned == "/v1beta/models" || cleaned == "/models"
}

func writePolicyFile(path string, document policyDocument) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("policy_file is not configured")
	}
	raw, err := yaml.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode policy file: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create policy directory: %w", err)
		}
	}
	temporary, err := os.CreateTemp(dir, ".key-model-access-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary policy file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary policy file: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary policy file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary policy file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary policy file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace policy file: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("open policy directory for sync: %w", err)
		}
		errSync := directory.Sync()
		errClose := directory.Close()
		if errSync != nil {
			return fmt.Errorf("sync policy directory: %w", errSync)
		}
		if errClose != nil {
			return fmt.Errorf("close policy directory: %w", errClose)
		}
	}
	return nil
}
