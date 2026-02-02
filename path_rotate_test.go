package solacevaultplugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func setupRotationTest(t *testing.T) (logical.Backend, logical.Storage, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply><execute-result code="ok"/></rpc-reply>`))
	}))

	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create broker pointing to test server
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/brokers/test-broker",
		Storage:   storage,
		Data: map[string]interface{}{
			"semp_url":       server.URL,
			"admin_username": "admin",
			"admin_password": "secret",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create broker: err=%v, resp=%v", err, resp)
	}

	// Create role
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":       "test-broker",
			"cli_username": "monitor",
		},
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create role: err=%v, resp=%v", err, resp)
	}

	return b, storage, server
}

func TestPathRotate_Success(t *testing.T) {
	b, storage, server := setupRotationTest(t)
	defer server.Close()
	ctx := context.Background()

	// Rotate
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate: err=%v, resp=%v", err, resp)
	}

	// Verify password was stored
	role, err := getRole(ctx, storage, "test-role")
	if err != nil {
		t.Fatalf("getRole: %v", err)
	}
	if role.Password == "" {
		t.Error("password should be set after rotation")
	}
	if role.LastRotated.IsZero() {
		t.Error("last_rotated should be set after rotation")
	}
}

func TestPathRotate_RoleNotFound(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/nonexistent",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error response for nonexistent role")
	}
}

func TestPathRotate_SEMPFailure_SanitizedError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply><execute-result code="fail"/><parse-error>Internal broker error at host-xyz-123</parse-error></rpc-reply>`))
	}))
	defer server.Close()

	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create broker pointing to failing SEMP server
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/brokers/test-broker",
		Storage:   storage,
		Data: map[string]interface{}{
			"semp_url":       server.URL,
			"admin_username": "admin",
			"admin_password": "secret",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create broker: err=%v, resp=%v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":       "test-broker",
			"cli_username": "monitor",
		},
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create role: err=%v, resp=%v", err, resp)
	}

	// Rotate — should fail with sanitized error
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("expected logical error response, got Go error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for SEMP failure")
	}

	// Verify the error message does not contain broker internals
	errMsg := resp.Data["error"].(string)
	if strings.Contains(errMsg, "host-xyz-123") {
		t.Errorf("error response should not contain broker internals, got: %s", errMsg)
	}
	if strings.Contains(errMsg, "Internal broker error") {
		t.Errorf("error response should not contain SEMP error details, got: %s", errMsg)
	}

	// Verify password was NOT stored (rotation safety)
	role, err := getRole(ctx, storage, "test-role")
	if err != nil {
		t.Fatalf("getRole: %v", err)
	}
	if role.Password != "" {
		t.Error("password should not be stored after failed rotation")
	}
}

func TestPathRotate_BrokerNotFound(t *testing.T) {
	_, storage := getTestBackend(t)
	ctx := context.Background()

	// Write role directly to storage referencing a non-existent broker
	role := &RoleEntry{
		Broker:      "nonexistent-broker",
		CLIUsername: "test",
	}
	if err := putRole(ctx, storage, "orphan-role", role); err != nil {
		t.Fatalf("putRole: %v", err)
	}

	b, _ := getTestBackend(t)
	// Try to rotate using the same storage
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/orphan-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error response for orphaned role")
	}
}

func TestPathRotate_RateLimited(t *testing.T) {
	b, storage, server := setupRotationTest(t)
	defer server.Close()
	ctx := context.Background()

	// First rotation should succeed
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("first rotate: err=%v, resp=%v", err, resp)
	}

	// Immediate second rotation should be rate-limited
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error response for rate-limited rotation")
	}
}
