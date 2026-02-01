package solacevaultplugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestPeriodicFunc_RotatesDueRoles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply><execute-result code="ok"/></rpc-reply>`))
	}))
	defer server.Close()

	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create broker
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

	// Create role with 1-second rotation period
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/fast-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":          "test-broker",
			"cli_username":    "monitor",
			"rotation_period": 1,
		},
	}
	b.HandleRequest(ctx, req)

	// Do initial rotation
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/fast-role",
		Storage:   storage,
	}
	b.HandleRequest(ctx, req)

	// Get password after initial rotation
	role, _ := getRole(ctx, storage, "fast-role")
	firstPassword := role.Password

	// Backdate last_rotated to trigger periodic rotation
	role.LastRotated = time.Now().Add(-2 * time.Second)
	putRole(ctx, storage, "fast-role", role)

	// Run periodic function
	periodicReq := &logical.Request{Storage: storage}
	err := b.(*solaceBackend).periodicFunc(ctx, periodicReq)
	if err != nil {
		t.Fatalf("periodicFunc: %v", err)
	}

	// Verify password changed
	role, _ = getRole(ctx, storage, "fast-role")
	if role.Password == firstPassword {
		t.Error("password should have changed after periodic rotation")
	}
}

func TestPeriodicFunc_SkipsNotDueRoles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply><execute-result code="ok"/></rpc-reply>`))
	}))
	defer server.Close()

	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create broker
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

	// Create role with 1-hour rotation
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/slow-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":          "test-broker",
			"cli_username":    "monitor",
			"rotation_period": 3600,
		},
	}
	b.HandleRequest(ctx, req)

	// Do initial rotation
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "rotate-role/slow-role",
		Storage:   storage,
	}
	b.HandleRequest(ctx, req)

	role, _ := getRole(ctx, storage, "slow-role")
	firstPassword := role.Password

	// Run periodic — should NOT rotate (not due yet)
	periodicReq := &logical.Request{Storage: storage}
	err := b.(*solaceBackend).periodicFunc(ctx, periodicReq)
	if err != nil {
		t.Fatalf("periodicFunc: %v", err)
	}

	role, _ = getRole(ctx, storage, "slow-role")
	if role.Password != firstPassword {
		t.Error("password should NOT have changed — not due for rotation")
	}
}

func TestPeriodicFunc_SkipsNoRotationPeriod(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	writeBroker(t, b, storage, "test-broker")

	// Create role with no rotation_period
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/manual-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"broker":       "test-broker",
			"cli_username": "monitor",
		},
	}
	b.HandleRequest(ctx, req)

	// Run periodic — should not error
	periodicReq := &logical.Request{Storage: storage}
	err := b.(*solaceBackend).periodicFunc(ctx, periodicReq)
	if err != nil {
		t.Fatalf("periodicFunc: %v", err)
	}
}
