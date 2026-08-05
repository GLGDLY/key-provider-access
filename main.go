package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    void* ptr;
    size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
    uint32_t abi_version;
    void* host_ctx;
    cliproxy_host_call_fn call;
    cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
    uint32_t abi_version;
    cliproxy_plugin_call_fn call;
    cliproxy_plugin_free_fn free_buffer;
    cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(_ *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(abiVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required", 0))
		return 1
	}

	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, err := handleMethod(C.GoString(method), requestBytes)
	if err != nil {
		writeResponse(response, errorEnvelope("plugin_error", err.Error(), 0))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	globalState.clear()
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case methodPluginRegister, methodPluginReconfigure:
		if err := configure(request); err != nil {
			return nil, err
		}
		return okEnvelope(pluginRegistration())
	case methodFrontendAuthIdentifier:
		return okEnvelope(identifierResponse{Identifier: pluginID})
	case methodFrontendAuthAuthenticate:
		return authenticate(request)
	case methodRequestInterceptBefore, methodRequestInterceptAfter:
		return interceptRequest(request)
	case methodManagementRegister:
		return okEnvelope(managementRegistration())
	case methodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method, 0), nil
	}
}

func pluginRegistration() registration {
	_, _, _, _, hostSchema, _ := globalState.current()
	registrationSchema := hostSchema
	if registrationSchema == 0 || registrationSchema > schemaVersion {
		registrationSchema = schemaVersion
	}
	return registration{
		SchemaVersion: registrationSchema,
		Metadata: metadata{
			Name:             "Key Model Access",
			Version:          pluginVersion,
			Author:           "router-for-me community",
			GitHubRepository: "https://github.com/router-for-me/CLIProxyAPI",
			Logo:             "",
			ConfigFields: []configField{
				{Name: "policy_file", Type: "string", Description: "Optional YAML policy file used for persistent Management API updates."},
				{Name: "default_action", Type: "enum", EnumValues: []string{"deny", "allow"}, Description: "Action for models not matched by allow_models or deny_models."},
				{Name: "models_endpoint", Type: "enum", EnumValues: []string{"allow", "deny"}, Description: "Allow or deny the global /v1/models endpoint. Per-key filtering is not available in the CPA plugin API."},
				{Name: "allow_query_keys", Type: "boolean", Description: "Accept API keys from the key and auth_token query parameters."},
				{Name: "keys", Type: "array", Description: "Per-key model policies. Plain keys are hashed in memory; key_sha256 is preferred."},
			},
		},
		Capabilities: capabilities{
			FrontendAuthProvider:          true,
			FrontendAuthProviderExclusive: true,
			RequestInterceptor:            hostSchema >= schemaVersion,
			ManagementAPI:                 true,
		},
	}
}

func okEnvelope(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string, status int) []byte {
	raw, err := json.Marshal(envelope{OK: false, Error: &envelopeError{
		Code: code, Message: message, HTTPStatus: status,
	}})
	if err != nil {
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"encode error"}}`)
	}
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func decodeJSON(raw []byte, target any) error {
	if len(raw) == 0 {
		return fmt.Errorf("request body is required")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	return nil
}
