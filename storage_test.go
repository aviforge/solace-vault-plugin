package solacevaultplugin

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBrokerStorage(t *testing.T) {
	ctx := context.Background()
	s := &logical.InmemStorage{}

	config := &BrokerConfig{
		SEMPURL:       "https://broker:8080",
		AdminUsername: "admin",
		AdminPassword: "secret",
		SEMPVersion:   "soltr/10_4",
	}
	if err := putBroker(ctx, s, "test-broker", config); err != nil {
		t.Fatalf("putBroker: %v", err)
	}

	got, err := getBroker(ctx, s, "test-broker")
	if err != nil {
		t.Fatalf("getBroker: %v", err)
	}
	if got.SEMPURL != config.SEMPURL {
		t.Errorf("SEMPURL = %q, want %q", got.SEMPURL, config.SEMPURL)
	}
	if got.AdminUsername != config.AdminUsername {
		t.Errorf("AdminUsername = %q, want %q", got.AdminUsername, config.AdminUsername)
	}

	names, err := listBrokers(ctx, s)
	if err != nil {
		t.Fatalf("listBrokers: %v", err)
	}
	if len(names) != 1 || names[0] != "test-broker" {
		t.Errorf("listBrokers = %v, want [test-broker]", names)
	}

	if err := deleteBroker(ctx, s, "test-broker"); err != nil {
		t.Fatalf("deleteBroker: %v", err)
	}
	got, err = getBroker(ctx, s, "test-broker")
	if err != nil {
		t.Fatalf("getBroker after delete: %v", err)
	}
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestRoleStorage(t *testing.T) {
	ctx := context.Background()
	s := &logical.InmemStorage{}

	role := &RoleEntry{
		Broker:         "test-broker",
		CLIUsername:    "monitor",
		RotationPeriod: 24 * time.Hour,
	}
	if err := putRole(ctx, s, "test-role", role); err != nil {
		t.Fatalf("putRole: %v", err)
	}

	got, err := getRole(ctx, s, "test-role")
	if err != nil {
		t.Fatalf("getRole: %v", err)
	}
	if got.Broker != role.Broker {
		t.Errorf("Broker = %q, want %q", got.Broker, role.Broker)
	}
	if got.CLIUsername != role.CLIUsername {
		t.Errorf("CLIUsername = %q, want %q", got.CLIUsername, role.CLIUsername)
	}

	names, err := listRoles(ctx, s)
	if err != nil {
		t.Fatalf("listRoles: %v", err)
	}
	if len(names) != 1 || names[0] != "test-role" {
		t.Errorf("listRoles = %v, want [test-role]", names)
	}
}
