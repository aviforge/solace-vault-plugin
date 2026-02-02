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
			"password_length": 25,
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
	if resp.Data["password_length"] != 25 {
		t.Errorf("password_length = %v, want 25", resp.Data["password_length"])
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

func TestPathRoles_PasswordLengthValidation(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	writeBroker(t, b, storage, "test-broker")

	tests := []struct {
		name           string
		roleSuffix     string
		passwordLength int
		wantError      bool
	}{
		{"below minimum rejected", "below-min", 15, true},
		{"minimum accepted", "min", 16, false},
		{"default accepted", "default", 25, false},
		{"maximum accepted", "max", 128, false},
		{"above maximum rejected", "above-max", 129, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "roles/len-test-" + tt.roleSuffix,
				Storage:   storage,
				Data: map[string]interface{}{
					"broker":          "test-broker",
					"cli_username":    "test",
					"password_length": tt.passwordLength,
				},
			}
			resp, err := b.HandleRequest(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantError {
				if resp == nil || !resp.IsError() {
					t.Errorf("expected error for password_length=%d, got success", tt.passwordLength)
				}
			} else {
				if resp != nil && resp.IsError() {
					t.Errorf("expected success for password_length=%d, got error: %v", tt.passwordLength, resp.Data["error"])
				}
			}
		})
	}

	// Verify omitted password_length defaults to 25
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/len-test-omitted",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":       "test-broker",
			"cli_username": "test",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write with omitted password_length: err=%v, resp=%v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/len-test-omitted",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || resp == nil {
		t.Fatalf("read: err=%v, resp=%v", err, resp)
	}
	if resp.Data["password_length"] != defaultPasswordLength {
		t.Errorf("password_length = %v, want %d (default)", resp.Data["password_length"], defaultPasswordLength)
	}
}
