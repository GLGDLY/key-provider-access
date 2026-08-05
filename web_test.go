package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestManagementRegistrationIncludesSettingsResource(t *testing.T) {
	registration := managementRegistration()
	if len(registration.Resources) != 1 {
		t.Fatalf("resources = %#v", registration.Resources)
	}
	resource := registration.Resources[0]
	if resource.Path != "/settings" || resource.Menu == "" {
		t.Fatalf("settings resource = %#v", resource)
	}
}

func TestSettingsPageEmbedsAssetsWithNonceCSP(t *testing.T) {
	raw, err := settingsPage()
	if err != nil {
		t.Fatalf("settingsPage() error = %v", err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	body := string(response.Body)
	for _, marker := range []string{"{{NONCE}}", "{{CSS}}", "{{JS}}"} {
		if strings.Contains(body, marker) {
			t.Fatalf("settings page retains template marker %s", marker)
		}
	}
	for _, expected := range []string{"id=\"authGate\"", "id=\"policyNav\"", "const PATHS", ":root"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("settings page missing %q", expected)
		}
	}

	csp := response.Headers.Get("Content-Security-Policy")
	match := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(csp)
	if len(match) != 2 || match[1] == "" {
		t.Fatalf("CSP nonce missing: %q", csp)
	}
	if !strings.Contains(body, `nonce="`+match[1]+`"`) {
		t.Fatal("CSP nonce does not match embedded assets")
	}
	if !strings.Contains(csp, "form-action 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP is not fail-closed: %q", csp)
	}
	if response.Headers.Get("Cache-Control") != "no-store" || response.Headers.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers = %#v", response.Headers)
	}
}

func TestHandleManagementServesSettingsResource(t *testing.T) {
	request, _ := json.Marshal(managementRequest{Method: http.MethodGet, Path: settingsResourcePath})
	raw, err := handleManagement(request)
	if err != nil {
		t.Fatalf("handleManagement() error = %v", err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Headers.Get("Content-Type"), "text/html") {
		t.Fatalf("settings response = %#v", response)
	}
}

func TestManagementPoliciesNeverExposePlainKeys(t *testing.T) {
	globalState.clear()
	t.Cleanup(globalState.clear)
	cfg := pluginConfig{DefaultAction: "deny", ModelsEndpoint: "deny", Keys: []keyConfig{{ID: "unsafe", Key: "must-not-leak"}}}
	globalState.failClosedOrPreserve(cfg, schemaVersion, errTestPolicy)

	raw, err := managementPolicies()
	if err != nil {
		t.Fatalf("managementPolicies() error = %v", err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if strings.Contains(string(response.Body), "must-not-leak") {
		t.Fatalf("plain key leaked: %s", response.Body)
	}
}

func TestPolicyRevisionRejectsStaleWrites(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 1, Keys: []keyConfig{{ID: "first", Key: "first-secret", AllowModels: []string{"*"}}}})
	initialRevision := globalState.policyRevision()
	body := []byte(`{"version":1,"default_action":"deny","keys":[{"id":"second","key":"second-secret","allow_models":["gpt-*"]}]}`)

	raw, err := managementReplacePolicies(body, etagForRevision(initialRevision))
	if err != nil {
		t.Fatalf("matching revision update error = %v", err)
	}
	var updated managementResponse
	unwrapEnvelope(t, raw, &updated)
	if updated.StatusCode != http.StatusOK || globalState.policyRevision() <= initialRevision {
		t.Fatalf("matching revision response = %#v", updated)
	}

	raw, err = managementReplacePolicies(body, etagForRevision(initialRevision))
	if err != nil {
		t.Fatalf("stale revision call error = %v", err)
	}
	var stale managementResponse
	unwrapEnvelope(t, raw, &stale)
	if stale.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale revision status = %d body = %s", stale.StatusCode, stale.Body)
	}
}

var errTestPolicy = &testPolicyError{}

type testPolicyError struct{}

func (*testPolicyError) Error() string { return "test invalid policy" }
