package solacevaultplugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathCreds_ReadAfterRotation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply><execute-result code="ok"/></rpc-reply>`))
	}))
	defer server.Close()

	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Setup broker and role
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
	b.HandleRequest(ctx, req)

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":       "test-broker",
			"cli_username": "monitor",
		},
	}
	b.HandleRequest(ctx, req)

	// Rotate first
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/test-role",
		Storage:   storage,
	}
	b.HandleRequest(ctx, req)

	// Read creds
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || resp == nil {
		t.Fatalf("read creds: err=%v, resp=%v", err, resp)
	}
	if resp.Data["cli_username"] != "monitor" {
		t.Errorf("cli_username = %v, want monitor", resp.Data["cli_username"])
	}
	if resp.Data["password"] == nil || resp.Data["password"] == "" {
		t.Error("password should be set")
	}
	if resp.Data["broker"] != "test-broker" {
		t.Errorf("broker = %v, want test-broker", resp.Data["broker"])
	}
	if resp.Data["last_rotated"] == nil {
		t.Error("last_rotated should be set")
	}
}

func TestPathCreds_NoPasswordYet(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	writeBroker(t, b, storage, "test-broker")

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":       "test-broker",
			"cli_username": "monitor",
		},
	}
	b.HandleRequest(ctx, req)

	// Read creds before rotation
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error when password has not been rotated yet")
	}
}

func TestPathCreds_RoleNotFound(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nonexistent",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error for nonexistent role")
	}
}
