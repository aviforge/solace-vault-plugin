package solacevaultplugin

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return b, config.StorageView
}

func TestPathConfigBrokers_WriteReadDeleteList(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Write broker config
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/brokers/test-broker",
		Storage:   storage,
		Data: map[string]interface{}{
			"semp_url":        "https://broker:8080",
			"admin_username":  "admin",
			"admin_password":  "secret",
			"semp_version":    "soltr/10_4",
			"tls_skip_verify": true,
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write: err=%v, resp=%v", err, resp)
	}

	// Read broker config
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/brokers/test-broker",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || resp == nil {
		t.Fatalf("read: err=%v, resp=%v", err, resp)
	}
	if resp.Data["semp_url"] != "https://broker:8080" {
		t.Errorf("semp_url = %v, want https://broker:8080", resp.Data["semp_url"])
	}
	if resp.Data["admin_username"] != "admin" {
		t.Errorf("admin_username = %v, want admin", resp.Data["admin_username"])
	}
	if _, exists := resp.Data["admin_password"]; exists {
		t.Error("admin_password should not be returned on read")
	}

	// List brokers
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "config/brokers/",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || resp == nil {
		t.Fatalf("list: err=%v, resp=%v", err, resp)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "test-broker" {
		t.Errorf("list keys = %v, want [test-broker]", keys)
	}

	// Delete broker
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/brokers/test-broker",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("delete: err=%v, resp=%v", err, resp)
	}

	// Verify deleted
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/brokers/test-broker",
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

func TestPathConfigBrokers_ValidationErrors(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/brokers/bad",
		Storage:   storage,
		Data: map[string]interface{}{
			"semp_url":       "",
			"admin_username": "admin",
			"admin_password": "secret",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error response for empty semp_url")
	}
}
