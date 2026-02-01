# Solace Vault Plugin Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a HashiCorp Vault secrets engine plugin that rotates Solace PubSub+ CLI user passwords via SEMP v1 XML API.

**Architecture:** Go-based Vault secrets engine using the `hashicorp/vault/sdk` framework. Multi-broker support with static role password rotation. SEMP v1 XML over HTTP for broker communication.

**Tech Stack:** Go, HashiCorp Vault SDK (`github.com/hashicorp/vault/sdk`), `encoding/xml`, `net/http`

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `cmd/solace-vault-plugin/main.go`
- Create: `Makefile`

**Step 1: Initialize Go module**

Run: `cd /home/avi/solace-vault-plugin && go mod init github.com/solace-vault-plugin`
Expected: `go.mod` created

**Step 2: Create main.go**

Create `cmd/solace-vault-plugin/main.go`:

```go
package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	solacevaultplugin "github.com/solace-vault-plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: solacevaultplugin.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
```

**Step 3: Create Makefile**

Create `Makefile`:

```makefile
PLUGIN_NAME := solace-vault-plugin
PLUGIN_DIR := bin

.PHONY: build clean test fmt

build:
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

clean:
	rm -rf $(PLUGIN_DIR)

test:
	go test -v -race ./...

fmt:
	go fmt ./...
```

**Step 4: Create a stub backend.go so the module compiles**

Create `backend.go`:

```go
package solacevaultplugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = "The Solace secrets engine rotates CLI user passwords on Solace PubSub+ brokers."

type solaceBackend struct {
	*framework.Backend
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *solaceBackend {
	b := &solaceBackend{}

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/brokers/*",
				"roles/*",
			},
		},
		Paths: framework.PathAppend(),
	}

	return b
}
```

**Step 5: Fetch dependencies**

Run: `cd /home/avi/solace-vault-plugin && go mod tidy`
Expected: `go.sum` generated, vault SDK downloaded

**Step 6: Verify it compiles**

Run: `cd /home/avi/solace-vault-plugin && go build ./...`
Expected: Clean build, no errors

**Step 7: Commit**

```bash
cd /home/avi/solace-vault-plugin && git init && git add -A && git commit -m "feat: project scaffolding with stub backend"
```

---

### Task 2: Types and Storage Helpers

**Files:**
- Create: `types.go`
- Create: `storage.go`
- Create: `storage_test.go`

**Step 1: Create types.go**

Create `types.go`:

```go
package solacevaultplugin

import "time"

// BrokerConfig holds connection details for a Solace broker's SEMP v1 interface.
type BrokerConfig struct {
	SEMPURL       string `json:"semp_url"`
	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`
	SEMPVersion   string `json:"semp_version,omitempty"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
}

// RoleEntry maps a Vault role to a CLI user on a Solace broker.
type RoleEntry struct {
	Broker         string        `json:"broker"`
	CLIUsername    string        `json:"cli_username"`
	RotationPeriod time.Duration `json:"rotation_period,omitempty"`
	Password       string        `json:"password,omitempty"`
	LastRotated    time.Time     `json:"last_rotated,omitempty"`
}
```

**Step 2: Create storage.go**

Create `storage.go`:

```go
package solacevaultplugin

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	brokerStoragePrefix = "config/brokers/"
	roleStoragePrefix   = "roles/"
)

func getEntry[T any](ctx context.Context, s logical.Storage, path string) (*T, error) {
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var result T
	if err := json.Unmarshal(entry.Value, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func putEntry(ctx context.Context, s logical.Storage, path string, data interface{}) error {
	entry, err := logical.StorageEntryJSON(path, data)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func getBroker(ctx context.Context, s logical.Storage, name string) (*BrokerConfig, error) {
	return getEntry[BrokerConfig](ctx, s, brokerStoragePrefix+name)
}

func putBroker(ctx context.Context, s logical.Storage, name string, config *BrokerConfig) error {
	return putEntry(ctx, s, brokerStoragePrefix+name, config)
}

func deleteBroker(ctx context.Context, s logical.Storage, name string) error {
	return s.Delete(ctx, brokerStoragePrefix+name)
}

func listBrokers(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, brokerStoragePrefix)
}

func getRole(ctx context.Context, s logical.Storage, name string) (*RoleEntry, error) {
	return getEntry[RoleEntry](ctx, s, roleStoragePrefix+name)
}

func putRole(ctx context.Context, s logical.Storage, name string, role *RoleEntry) error {
	return putEntry(ctx, s, roleStoragePrefix+name, role)
}

func deleteRole(ctx context.Context, s logical.Storage, name string) error {
	return s.Delete(ctx, roleStoragePrefix+name)
}

func listRoles(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, roleStoragePrefix)
}
```

**Step 3: Write storage_test.go**

Create `storage_test.go`:

```go
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

	// Put and get
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

	// List
	names, err := listBrokers(ctx, s)
	if err != nil {
		t.Fatalf("listBrokers: %v", err)
	}
	if len(names) != 1 || names[0] != "test-broker" {
		t.Errorf("listBrokers = %v, want [test-broker]", names)
	}

	// Delete
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
```

**Step 4: Run tests**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestBrokerStorage -run TestRoleStorage ./...`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add types.go storage.go storage_test.go && git commit -m "feat: types and storage helpers with tests"
```

---

### Task 3: Broker Config CRUD Paths

**Files:**
- Create: `path_config_brokers.go`
- Create: `path_config_brokers_test.go`
- Modify: `backend.go`

**Step 1: Create path_config_brokers.go**

Create `path_config_brokers.go`:

```go
package solacevaultplugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfigBrokers(b *solaceBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config/brokers/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the broker configuration.",
					Required:    true,
				},
				"semp_url": {
					Type:        framework.TypeString,
					Description: "SEMP v1 endpoint URL, e.g., https://broker:8080",
					Required:    true,
				},
				"admin_username": {
					Type:        framework.TypeString,
					Description: "Admin username for SEMP authentication.",
					Required:    true,
				},
				"admin_password": {
					Type:        framework.TypeString,
					Description: "Admin password for SEMP authentication.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"semp_version": {
					Type:        framework.TypeString,
					Description: "SEMP schema version string, e.g., soltr/10_4. Optional.",
				},
				"tls_skip_verify": {
					Type:        framework.TypeBool,
					Description: "Skip TLS certificate verification. Do not use in production.",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigBrokersWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigBrokersWrite,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigBrokersRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigBrokersDelete,
				},
			},
			ExistenceCheck:  b.pathConfigBrokersExistenceCheck,
			HelpSynopsis:    "Configure a Solace broker connection.",
			HelpDescription: "Configure connection details for a Solace PubSub+ broker's SEMP v1 management interface.",
		},
		{
			Pattern: "config/brokers/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathConfigBrokersList,
				},
			},
			HelpSynopsis:    "List configured Solace brokers.",
			HelpDescription: "List the names of all configured Solace broker connections.",
		},
	}
}

func (b *solaceBackend) pathConfigBrokersExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	broker, err := getBroker(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return broker != nil, nil
}

func (b *solaceBackend) pathConfigBrokersWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	config := &BrokerConfig{
		SEMPURL:       d.Get("semp_url").(string),
		AdminUsername: d.Get("admin_username").(string),
		AdminPassword: d.Get("admin_password").(string),
	}

	if v, ok := d.GetOk("semp_version"); ok {
		config.SEMPVersion = v.(string)
	}
	if v, ok := d.GetOk("tls_skip_verify"); ok {
		config.TLSSkipVerify = v.(bool)
	}

	if config.SEMPURL == "" {
		return logical.ErrorResponse("semp_url is required"), nil
	}
	if config.AdminUsername == "" {
		return logical.ErrorResponse("admin_username is required"), nil
	}
	if config.AdminPassword == "" {
		return logical.ErrorResponse("admin_password is required"), nil
	}

	if err := putBroker(ctx, req.Storage, name, config); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *solaceBackend) pathConfigBrokersRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	config, err := getBroker(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"semp_url":        config.SEMPURL,
			"admin_username":  config.AdminUsername,
			"semp_version":    config.SEMPVersion,
			"tls_skip_verify": config.TLSSkipVerify,
		},
	}, nil
}

func (b *solaceBackend) pathConfigBrokersDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	if err := deleteBroker(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *solaceBackend) pathConfigBrokersList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	brokers, err := listBrokers(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(brokers), nil
}
```

**Step 2: Register paths in backend.go**

Modify `backend.go` — replace `Paths: framework.PathAppend(),` with:

```go
		Paths: framework.PathAppend(
			pathConfigBrokers(b),
		),
```

**Step 3: Write path_config_brokers_test.go**

Create `path_config_brokers_test.go`:

```go
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
```

**Step 4: Run tests**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestPathConfigBrokers ./...`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add path_config_brokers.go path_config_brokers_test.go backend.go && git commit -m "feat: broker config CRUD paths with tests"
```

---

### Task 4: Role CRUD Paths

**Files:**
- Create: `path_roles.go`
- Create: `path_roles_test.go`
- Modify: `backend.go`

**Step 1: Create path_roles.go**

Create `path_roles.go`:

```go
package solacevaultplugin

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRoles(b *solaceBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
					Required:    true,
				},
				"broker": {
					Type:        framework.TypeString,
					Description: "Name of the broker configuration to use.",
					Required:    true,
				},
				"cli_username": {
					Type:        framework.TypeString,
					Description: "CLI username on the Solace broker.",
					Required:    true,
				},
				"rotation_period": {
					Type:        framework.TypeDurationSecond,
					Description: "How often to rotate the password, in seconds. 0 disables automatic rotation.",
					Default:     0,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck:  b.pathRolesExistenceCheck,
			HelpSynopsis:    "Manage roles that map to Solace CLI users.",
			HelpDescription: "Create, read, update, or delete a role that maps to a CLI user account on a Solace broker.",
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    "List configured roles.",
			HelpDescription: "List the names of all configured roles.",
		},
	}
}

func (b *solaceBackend) pathRolesExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *solaceBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	broker := d.Get("broker").(string)
	cliUsername := d.Get("cli_username").(string)
	rotationPeriodSec := d.Get("rotation_period").(int)

	if broker == "" {
		return logical.ErrorResponse("broker is required"), nil
	}
	if cliUsername == "" {
		return logical.ErrorResponse("cli_username is required"), nil
	}

	// Verify the referenced broker exists
	brokerConfig, err := getBroker(ctx, req.Storage, broker)
	if err != nil {
		return nil, err
	}
	if brokerConfig == nil {
		return logical.ErrorResponse("broker %q not found", broker), nil
	}

	// Preserve existing password and last_rotated if updating
	existing, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	role := &RoleEntry{
		Broker:         broker,
		CLIUsername:    cliUsername,
		RotationPeriod: time.Duration(rotationPeriodSec) * time.Second,
	}

	if existing != nil {
		role.Password = existing.Password
		role.LastRotated = existing.LastRotated
	}

	if err := putRole(ctx, req.Storage, name, role); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *solaceBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"broker":          role.Broker,
		"cli_username":    role.CLIUsername,
		"rotation_period": int(role.RotationPeriod.Seconds()),
	}
	if !role.LastRotated.IsZero() {
		data["last_rotated"] = role.LastRotated.Format(time.RFC3339)
	}

	return &logical.Response{Data: data}, nil
}

func (b *solaceBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	if err := deleteRole(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *solaceBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := listRoles(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}
```

**Step 2: Register paths in backend.go**

Modify `backend.go` — update `Paths` to:

```go
		Paths: framework.PathAppend(
			pathConfigBrokers(b),
			pathRoles(b),
		),
```

**Step 3: Write path_roles_test.go**

Create `path_roles_test.go`:

```go
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
```

**Step 4: Run tests**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestPathRoles ./...`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add path_roles.go path_roles_test.go backend.go && git commit -m "feat: role CRUD paths with tests"
```

---

### Task 5: Password Generator

**Files:**
- Create: `password.go`
- Create: `password_test.go`

**Step 1: Write password_test.go first (TDD)**

Create `password_test.go`:

```go
package solacevaultplugin

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	pw, err := generatePassword(32)
	if err != nil {
		t.Fatalf("generatePassword: %v", err)
	}
	if len(pw) != 32 {
		t.Errorf("len = %d, want 32", len(pw))
	}

	// Verify no excluded characters
	excluded := `:()";'<>,` + "`\\*&|"
	for _, c := range pw {
		if strings.ContainsRune(excluded, c) {
			t.Errorf("password contains excluded character: %c", c)
		}
	}
}

func TestGeneratePassword_Uniqueness(t *testing.T) {
	pw1, _ := generatePassword(32)
	pw2, _ := generatePassword(32)
	if pw1 == pw2 {
		t.Error("two generated passwords should not be identical")
	}
}

func TestGeneratePassword_MaxLength(t *testing.T) {
	pw, err := generatePassword(128)
	if err != nil {
		t.Fatalf("generatePassword(128): %v", err)
	}
	if len(pw) != 128 {
		t.Errorf("len = %d, want 128", len(pw))
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestGeneratePassword ./...`
Expected: FAIL — `generatePassword` undefined

**Step 3: Write password.go**

Create `password.go`:

```go
package solacevaultplugin

import (
	"crypto/rand"
	"math/big"
)

// Solace password constraints: max 128 chars, excludes :()";'<>,`\*&|
const passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^-_=+.~"

func generatePassword(length int) (string, error) {
	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(passwordCharset)))

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = passwordCharset[idx.Int64()]
	}

	return string(result), nil
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestGeneratePassword ./...`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add password.go password_test.go && git commit -m "feat: password generator with Solace constraints"
```

---

### Task 6: SEMP v1 Client

**Files:**
- Create: `semp_client.go`
- Create: `semp_client_test.go`

**Step 1: Write semp_client_test.go first (TDD)**

Create `semp_client_test.go`:

```go
package solacevaultplugin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSEMPClient_ChangePassword_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "adminpass" {
			t.Errorf("bad auth: user=%q pass=%q ok=%v", user, pass, ok)
		}

		// Verify POST to /SEMP
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/SEMP" {
			t.Errorf("path = %q, want /SEMP", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply>
			<execute-result code="ok"/>
		</rpc-reply>`))
	}))
	defer server.Close()

	client := &SEMPClient{
		SEMPURL:       server.URL,
		AdminUsername: "admin",
		AdminPassword: "adminpass",
		SEMPVersion:   "soltr/10_4",
		HTTPClient:    server.Client(),
	}

	err := client.ChangePassword("testuser", "newpassword")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
}

func TestSEMPClient_ChangePassword_SEMPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<rpc-reply>
			<execute-result code="fail"/>
			<parse-error>Invalid username</parse-error>
		</rpc-reply>`))
	}))
	defer server.Close()

	client := &SEMPClient{
		SEMPURL:       server.URL,
		AdminUsername: "admin",
		AdminPassword: "adminpass",
		HTTPClient:    server.Client(),
	}

	err := client.ChangePassword("testuser", "newpassword")
	if err == nil {
		t.Fatal("expected error for SEMP failure")
	}
}

func TestSEMPClient_ChangePassword_HTTPError(t *testing.T) {
	client := &SEMPClient{
		SEMPURL:       "http://127.0.0.1:1",
		AdminUsername: "admin",
		AdminPassword: "adminpass",
		HTTPClient:    http.DefaultClient,
	}

	err := client.ChangePassword("testuser", "newpassword")
	if err == nil {
		t.Fatal("expected error for unreachable broker")
	}
}

func TestBuildChangePasswordXML(t *testing.T) {
	xml := buildChangePasswordXML("soltr/10_4", "myuser", "mypass")
	expected := `<rpc semp-version="soltr/10_4"><username><name>myuser</name><change-password><password>mypass</password></change-password></username></rpc>`
	if xml != expected {
		t.Errorf("got:\n%s\nwant:\n%s", xml, expected)
	}
}

func TestBuildChangePasswordXML_NoVersion(t *testing.T) {
	xml := buildChangePasswordXML("", "myuser", "mypass")
	expected := `<rpc><username><name>myuser</name><change-password><password>mypass</password></change-password></username></rpc>`
	if xml != expected {
		t.Errorf("got:\n%s\nwant:\n%s", xml, expected)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run "TestSEMPClient|TestBuild" ./...`
Expected: FAIL — types undefined

**Step 3: Write semp_client.go**

Create `semp_client.go`:

```go
package solacevaultplugin

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SEMPClient communicates with a Solace broker via SEMP v1 XML.
type SEMPClient struct {
	SEMPURL       string
	AdminUsername string
	AdminPassword string
	SEMPVersion   string
	TLSSkipVerify bool
	HTTPClient    *http.Client
}

type sempReply struct {
	XMLName       xml.Name          `xml:"rpc-reply"`
	ExecuteResult sempExecuteResult `xml:"execute-result"`
	ParseError    string            `xml:"parse-error"`
}

type sempExecuteResult struct {
	Code string `xml:"code,attr"`
}

// NewSEMPClient creates a client from a BrokerConfig.
func NewSEMPClient(config *BrokerConfig) *SEMPClient {
	httpClient := &http.Client{Timeout: 30 * time.Second}

	if config.TLSSkipVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &SEMPClient{
		SEMPURL:       config.SEMPURL,
		AdminUsername: config.AdminUsername,
		AdminPassword: config.AdminPassword,
		SEMPVersion:   config.SEMPVersion,
		TLSSkipVerify: config.TLSSkipVerify,
		HTTPClient:    httpClient,
	}
}

// ChangePassword changes a CLI user's password on the broker via SEMP v1.
func (c *SEMPClient) ChangePassword(cliUsername, newPassword string) error {
	body := buildChangePasswordXML(c.SEMPVersion, cliUsername, newPassword)

	req, err := http.NewRequest(http.MethodPost, c.SEMPURL+"/SEMP", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")
	req.SetBasicAuth(c.AdminUsername, c.AdminPassword)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("SEMP request to %s failed: %w", c.SEMPURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading SEMP response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SEMP returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var reply sempReply
	if err := xml.Unmarshal(respBody, &reply); err != nil {
		return fmt.Errorf("parsing SEMP response: %w", err)
	}

	if reply.ExecuteResult.Code != "ok" {
		errMsg := reply.ParseError
		if errMsg == "" {
			errMsg = fmt.Sprintf("execute-result code=%q", reply.ExecuteResult.Code)
		}
		return fmt.Errorf("SEMP command failed: %s", errMsg)
	}

	return nil
}

func buildChangePasswordXML(sempVersion, username, password string) string {
	var b strings.Builder
	if sempVersion != "" {
		fmt.Fprintf(&b, `<rpc semp-version="%s">`, sempVersion)
	} else {
		b.WriteString(`<rpc>`)
	}
	fmt.Fprintf(&b, `<username><name>%s</name><change-password><password>%s</password></change-password></username>`, username, password)
	b.WriteString(`</rpc>`)
	return b.String()
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run "TestSEMPClient|TestBuild" ./...`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add semp_client.go semp_client_test.go && git commit -m "feat: SEMP v1 client with tests"
```

---

### Task 7: Rotate Path (On-Demand Rotation)

**Files:**
- Create: `path_rotate.go`
- Create: `path_rotate_test.go`
- Modify: `backend.go`

**Step 1: Write path_rotate_test.go first (TDD)**

Create `path_rotate_test.go`:

```go
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestPathRotate ./...`
Expected: FAIL — path not registered

**Step 3: Write path_rotate.go**

Create `path_rotate.go`:

```go
package solacevaultplugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const defaultPasswordLength = 32

func pathRotateRole(b *solaceBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role to rotate.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRotateRoleWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRotateRoleWrite,
				},
			},
			HelpSynopsis:    "Rotate the password for a Solace CLI user.",
			HelpDescription: "Triggers an immediate password rotation for the CLI user associated with the named role.",
		},
	}
}

func (b *solaceBackend) pathRotateRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	return b.rotateRole(ctx, req.Storage, name)
}

func (b *solaceBackend) rotateRole(ctx context.Context, s logical.Storage, name string) (*logical.Response, error) {
	role, err := getRole(ctx, s, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", name), nil
	}

	brokerConfig, err := getBroker(ctx, s, role.Broker)
	if err != nil {
		return nil, err
	}
	if brokerConfig == nil {
		return logical.ErrorResponse("broker %q not found for role %q", role.Broker, name), nil
	}

	newPassword, err := generatePassword(defaultPasswordLength)
	if err != nil {
		return nil, fmt.Errorf("generating password: %w", err)
	}

	client := NewSEMPClient(brokerConfig)
	if err := client.ChangePassword(role.CLIUsername, newPassword); err != nil {
		return nil, fmt.Errorf("rotating password for %q on broker %q: %w", role.CLIUsername, role.Broker, err)
	}

	role.Password = newPassword
	role.LastRotated = time.Now().UTC()

	if err := putRole(ctx, s, name, role); err != nil {
		return nil, fmt.Errorf("storing rotated password: %w", err)
	}

	return nil, nil
}
```

**Step 4: Register paths in backend.go**

Modify `backend.go` — update `Paths` to:

```go
		Paths: framework.PathAppend(
			pathConfigBrokers(b),
			pathRoles(b),
			pathRotateRole(b),
		),
```

**Step 5: Run tests to verify they pass**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestPathRotate ./...`
Expected: PASS

**Step 6: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add path_rotate.go path_rotate_test.go backend.go && git commit -m "feat: on-demand password rotation with tests"
```

---

### Task 8: Credentials Read Path

**Files:**
- Create: `path_creds.go`
- Create: `path_creds_test.go`
- Modify: `backend.go`

**Step 1: Write path_creds_test.go first (TDD)**

Create `path_creds_test.go`:

```go
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestPathCreds ./...`
Expected: FAIL — path not registered

**Step 3: Write path_creds.go**

Create `path_creds.go`:

```go
package solacevaultplugin

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreds(b *solaceBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathCredsRead,
				},
			},
			HelpSynopsis:    "Read current credentials for a Solace CLI user.",
			HelpDescription: "Returns the current username and password for the CLI user associated with the named role.",
		},
	}
}

func (b *solaceBackend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", name), nil
	}

	if role.Password == "" {
		return logical.ErrorResponse("password for role %q has not been rotated yet; run rotate-role/%s first", name, name), nil
	}

	data := map[string]interface{}{
		"cli_username": role.CLIUsername,
		"password":     role.Password,
		"broker":       role.Broker,
	}
	if !role.LastRotated.IsZero() {
		data["last_rotated"] = role.LastRotated.Format(time.RFC3339)
	}

	return &logical.Response{Data: data}, nil
}
```

**Step 4: Register paths in backend.go**

Modify `backend.go` — update `Paths` to:

```go
		Paths: framework.PathAppend(
			pathConfigBrokers(b),
			pathRoles(b),
			pathRotateRole(b),
			pathCreds(b),
		),
```

**Step 5: Run tests to verify they pass**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestPathCreds ./...`
Expected: PASS

**Step 6: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add path_creds.go path_creds_test.go backend.go && git commit -m "feat: credentials read path with tests"
```

---

### Task 9: Periodic Rotation

**Files:**
- Modify: `backend.go`
- Create: `backend_test.go`

**Step 1: Write backend_test.go first (TDD)**

Create `backend_test.go`:

```go
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestPeriodicFunc ./...`
Expected: FAIL — `periodicFunc` undefined

**Step 3: Add periodicFunc to backend.go**

Modify `backend.go` to add the periodic function and register it. The full updated `backend.go`:

```go
package solacevaultplugin

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = "The Solace secrets engine rotates CLI user passwords on Solace PubSub+ brokers."

type solaceBackend struct {
	*framework.Backend
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *solaceBackend {
	b := &solaceBackend{}

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/brokers/*",
				"roles/*",
			},
		},
		Paths: framework.PathAppend(
			pathConfigBrokers(b),
			pathRoles(b),
			pathRotateRole(b),
			pathCreds(b),
		),
		PeriodicFunc: b.periodicFunc,
	}

	return b
}

func (b *solaceBackend) periodicFunc(ctx context.Context, req *logical.Request) error {
	logger := b.Logger()

	roleNames, err := listRoles(ctx, req.Storage)
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	for _, name := range roleNames {
		role, err := getRole(ctx, req.Storage, name)
		if err != nil {
			logger.Error("periodic: failed to read role", "role", name, "error", err)
			continue
		}
		if role == nil {
			continue
		}

		// Skip roles without automatic rotation
		if role.RotationPeriod == 0 {
			continue
		}

		// Skip roles that haven't been rotated yet (need initial manual rotation)
		if role.LastRotated.IsZero() {
			continue
		}

		// Skip roles not yet due for rotation
		if now.Before(role.LastRotated.Add(role.RotationPeriod)) {
			continue
		}

		logger.Info("periodic: rotating role", "role", name, "cli_username", role.CLIUsername, "broker", role.Broker)

		resp, err := b.rotateRole(ctx, req.Storage, name)
		if err != nil {
			logger.Error("periodic: rotation failed", "role", name, "error", err)
			continue
		}
		if resp != nil && resp.IsError() {
			logger.Error("periodic: rotation returned error", "role", name, "error", resp.Data["error"])
			continue
		}

		logger.Info("periodic: rotation complete", "role", name)
	}

	return nil
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/avi/solace-vault-plugin && go test -v -run TestPeriodicFunc ./...`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add backend.go backend_test.go && git commit -m "feat: periodic password rotation with tests"
```

---

### Task 10: Full Test Suite and Build Verification

**Files:**
- No new files

**Step 1: Run entire test suite**

Run: `cd /home/avi/solace-vault-plugin && go test -v -race ./...`
Expected: All tests PASS, no race conditions

**Step 2: Run go vet**

Run: `cd /home/avi/solace-vault-plugin && go vet ./...`
Expected: No issues

**Step 3: Build the plugin binary**

Run: `cd /home/avi/solace-vault-plugin && make build`
Expected: Binary at `bin/solace-vault-plugin`

**Step 4: Verify binary runs**

Run: `cd /home/avi/solace-vault-plugin && ./bin/solace-vault-plugin --help 2>&1 || true`
Expected: Plugin output (it will error without Vault, which is expected)

**Step 5: Commit**

```bash
cd /home/avi/solace-vault-plugin && git add -A && git commit -m "chore: verify full build and test suite"
```

---

## Summary

| Task | Component | Key Deliverable |
|------|-----------|-----------------|
| 1 | Scaffolding | `go.mod`, `main.go`, `Makefile`, stub `backend.go` |
| 2 | Types + Storage | `types.go`, `storage.go` with generic helpers |
| 3 | Broker Config | CRUD + List paths for broker connections |
| 4 | Roles | CRUD + List paths for static roles |
| 5 | Password Gen | Crypto-random with Solace character constraints |
| 6 | SEMP Client | XML build/parse, HTTP POST, error handling |
| 7 | Rotation | On-demand `rotate-role/` path |
| 8 | Credentials | Read-only `creds/` path |
| 9 | Periodic | `PeriodicFunc` for automatic scheduled rotation |
| 10 | Verification | Full test suite, race detection, build |
