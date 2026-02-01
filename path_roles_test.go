package solacevaultplugin

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func writeBroker(t *testing.T, b logical.Backend, storage logical.Storage, name string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/brokers/" + name,
		Storage:   storage,
		Data: map[string]interface{}{
			"semp_url":       "https://broker:8080",
			"admin_username": "admin",
			"admin_password": "secret",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("writeBroker: err=%v, resp=%v", err, resp)
	}
}

func TestPathRoles_WriteReadDeleteList(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create a broker first
	writeBroker(t, b, storage, "test-broker")

	// Write role
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":          "test-broker",
			"cli_username":    "monitor",
			"rotation_period": 86400,
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write: err=%v, resp=%v", err, resp)
	}

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || resp == nil {
		t.Fatalf("read: err=%v, resp=%v", err, resp)
	}
	if resp.Data["broker"] != "test-broker" {
		t.Errorf("broker = %v, want test-broker", resp.Data["broker"])
	}
	if resp.Data["cli_username"] != "monitor" {
		t.Errorf("cli_username = %v, want monitor", resp.Data["cli_username"])
	}
	if resp.Data["rotation_period"] != 86400 {
		t.Errorf("rotation_period = %v, want 86400", resp.Data["rotation_period"])
	}

	// List roles
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || resp == nil {
		t.Fatalf("list: err=%v, resp=%v", err, resp)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "test-role" {
		t.Errorf("list keys = %v, want [test-role]", keys)
	}

	// Delete role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("delete: err=%v, resp=%v", err, resp)
	}

	// Verify deleted
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("read after delete: err=%v", err)
	}
	if resp != nil {
		t.Error("expected nil response after delete")
	}
}

func TestPathRoles_BrokerNotFound(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":       "nonexistent",
			"cli_username": "test",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error response for nonexistent broker")
	}
}
