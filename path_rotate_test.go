package solacevaultplugin

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestPathRotate_BrokerNotFound(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create a role referencing a broker, then delete the broker
	writeBroker(t, b, storage, "temp-broker")

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/orphan-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":       "temp-broker",
			"cli_username": "test",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create role: err=%v, resp=%v", err, resp)
	}

	// Delete broker
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/brokers/temp-broker",
		Storage:   storage,
	}
	b.HandleRequest(ctx, req)

	// Try to rotate
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/orphan-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error response for orphaned role")
	}
}
