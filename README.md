# Solace Vault Plugin

A HashiCorp Vault secrets engine plugin that manages password rotation for Solace PubSub+ CLI (management) user accounts. Passwords are rotated on-demand or on a schedule, and propagated to the target broker via the SEMP v1 XML API.

## Features

- **Multi-broker support** — manage CLI users across dev, staging, prod, and regional brokers from a single Vault instance
- **On-demand rotation** — trigger immediate password rotation via the Vault CLI or HTTP API
- **Automatic rotation** — configure a `rotation_period` per role for scheduled rotation
- **Encrypted storage** — broker admin passwords and role credentials are sealed/wrapped at rest by Vault
- **Configurable password length** — set `password_length` per role (16–128 characters, default 25)
- **Safe rotation** — new passwords are only stored in Vault after the broker confirms the change succeeded

## Prerequisites

- [HashiCorp Vault](https://www.vaultproject.io/) (1.12+)
- [Go](https://go.dev/) (1.25+) for building from source
- A Solace PubSub+ broker with SEMP v1 enabled

## Build

```bash
make build
```

This produces `bin/solace-vault-plugin`.

## Register and Enable

```bash
# Calculate the SHA256 of the plugin binary
SHA256=$(shasum -a 256 bin/solace-vault-plugin | cut -d' ' -f1)

# Register the plugin with Vault
vault plugin register -sha256=$SHA256 secret solace-vault-plugin

# Enable the secrets engine at a path
vault secrets enable -path=solace solace-vault-plugin
```

## Quick Start

A complete walkthrough from building the plugin to reading rotated credentials.

### 1. Build and Start Vault with the Plugin

```bash
# Build the plugin
make build

# Start a Vault dev server with a plugin directory
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin &

# Authenticate
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

# Register and enable the secrets engine
vault secrets enable -path=solace solace-vault-plugin
```

For production deployments, register the plugin with its SHA256 hash:

```bash
SHA256=$(shasum -a 256 bin/solace-vault-plugin | cut -d' ' -f1)
vault plugin register -sha256=$SHA256 secret solace-vault-plugin
vault secrets enable -path=solace solace-vault-plugin
```

### 2. Configure a Broker

Point the plugin at a Solace PubSub+ broker's SEMP v1 management interface.

**Vault CLI:**

```bash
vault write solace/config/brokers/prod-east \
  semp_url="https://broker-prod-east:8080" \
  admin_username="admin" \
  admin_password="admin-secret" \
  semp_version="soltr/10_4"
```

**HTTP API:**

```bash
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST \
  -d '{"semp_url":"https://broker-prod-east:8080","admin_username":"admin","admin_password":"admin-secret","semp_version":"soltr/10_4"}' \
  $VAULT_ADDR/v1/solace/config/brokers/prod-east
```

You can configure multiple brokers for different environments:

```bash
vault write solace/config/brokers/dev \
  semp_url="http://dev-broker:8080" \
  admin_username="admin" \
  admin_password="dev-pass" \
  tls_skip_verify=true

vault write solace/config/brokers/prod-west \
  semp_url="https://broker-prod-west:8080" \
  admin_username="admin" \
  admin_password="prod-west-secret" \
  semp_version="soltr/10_4"
```

Verify the config (admin password is always redacted):

**Vault CLI:**

```bash
vault read solace/config/brokers/prod-east
vault list solace/config/brokers
```

**HTTP API:**

```bash
# Read a broker
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/solace/config/brokers/prod-east | jq .data

# List all brokers
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -X LIST \
  $VAULT_ADDR/v1/solace/config/brokers | jq .data.keys

# Delete a broker
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -X DELETE \
  $VAULT_ADDR/v1/solace/config/brokers/prod-east
```

### 3. Create Roles

A role maps a Vault name to a CLI user account on a broker. The CLI user must already exist on the broker — the plugin manages its password, not its lifecycle.

**Vault CLI:**

```bash
# Role with automatic daily rotation
vault write solace/roles/monitoring-user \
  broker="prod-east" \
  cli_username="monitor" \
  rotation_period="24h"

# Role with manual rotation only (rotation_period=0 or omitted)
vault write solace/roles/backup-user \
  broker="prod-east" \
  cli_username="backup"

# Role with a custom password length (64 characters)
vault write solace/roles/monitoring-user-west \
  broker="prod-west" \
  cli_username="monitor" \
  rotation_period="24h" \
  password_length=64
```

**HTTP API:**

```bash
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST \
  -d '{"broker":"prod-east","cli_username":"monitor","rotation_period":86400,"password_length":64}' \
  $VAULT_ADDR/v1/solace/roles/monitoring-user
```

Note: `rotation_period` is specified in seconds over the HTTP API (86400 = 24h). `password_length` is optional and defaults to 25.

```bash
# List roles
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -X LIST \
  $VAULT_ADDR/v1/solace/roles | jq .data.keys

# Read a role
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/solace/roles/monitoring-user | jq .data

# Delete a role
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -X DELETE \
  $VAULT_ADDR/v1/solace/roles/monitoring-user
```

### 4. Perform Initial Rotation

After creating a role, you must rotate at least once to set the first Vault-managed password. Until this is done, reading credentials will return an error.

**Vault CLI:**

```bash
vault write -f solace/rotate-role/monitoring-user
vault write -f solace/rotate-role/backup-user
vault write -f solace/rotate-role/monitoring-user-west
```

**HTTP API:**

```bash
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST \
  $VAULT_ADDR/v1/solace/rotate-role/monitoring-user
```

### 5. Read Credentials

Applications retrieve the current credentials from Vault.

**Vault CLI:**

```bash
vault read solace/creds/monitoring-user
# Key             Value
# ---             -----
# broker          prod-east
# cli_username    monitor
# last_rotated    2026-02-01T14:30:00Z
# password        aB3$kZ9...generated...
```

**HTTP API:**

```bash
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/solace/creds/monitoring-user | jq .data
```

```json
{
  "broker": "prod-east",
  "cli_username": "monitor",
  "last_rotated": "2026-02-01T14:30:00Z",
  "password": "aB3$kZ9...generated..."
}
```

### 6. Rotate On-Demand

Trigger an immediate rotation at any time (e.g., after a security incident).

**Vault CLI:**

```bash
vault write -f solace/rotate-role/monitoring-user
```

**HTTP API:**

```bash
curl -s \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST \
  $VAULT_ADDR/v1/solace/rotate-role/monitoring-user
```

The plugin generates a new password, pushes it to the broker via SEMP v1, and stores it in Vault only after the broker confirms success.

### 7. Automatic Rotation

Roles with a `rotation_period` are automatically rotated by Vault's periodic function. No additional setup is needed — once a role has been rotated at least once manually, the periodic function takes over.

The periodic function checks all roles on each cycle and rotates any that are past due. If a rotation fails (broker unreachable, auth error), it is logged and retried on the next cycle.

## Multi-Broker Example

A typical production setup with separate brokers per environment:

```bash
# Configure brokers
vault write solace/config/brokers/dev    semp_url="http://dev:8080"    admin_username=admin admin_password=dev-pass tls_skip_verify=true
vault write solace/config/brokers/stage  semp_url="https://stage:8080" admin_username=admin admin_password=stage-pass semp_version="soltr/10_4"
vault write solace/config/brokers/prod   semp_url="https://prod:8080"  admin_username=admin admin_password=prod-pass  semp_version="soltr/10_4"

# Create roles for each environment
vault write solace/roles/app-dev   broker=dev   cli_username=appuser
vault write solace/roles/app-stage broker=stage cli_username=appuser rotation_period=168h
vault write solace/roles/app-prod  broker=prod  cli_username=appuser rotation_period=24h

# Initial rotation
vault write -f solace/rotate-role/app-dev
vault write -f solace/rotate-role/app-stage
vault write -f solace/rotate-role/app-prod

# Applications read credentials for their environment
vault read solace/creds/app-prod
```

## ACL Policy Examples

```hcl
# Operators: configure brokers and roles
path "solace/config/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "solace/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Applications: read credentials only
path "solace/creds/*" {
  capabilities = ["read"]
}

# Admins only: trigger rotation
path "solace/rotate-role/*" {
  capabilities = ["create", "update"]
}
```

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| POST | `solace/config/brokers/:name` | Create or update a broker config |
| GET | `solace/config/brokers/:name` | Read a broker config |
| DELETE | `solace/config/brokers/:name` | Delete a broker config |
| LIST | `solace/config/brokers` | List all brokers |
| POST | `solace/roles/:name` | Create or update a role |
| GET | `solace/roles/:name` | Read a role config |
| DELETE | `solace/roles/:name` | Delete a role |
| LIST | `solace/roles` | List all roles |
| GET | `solace/creds/:role` | Read current credentials |
| POST | `solace/rotate-role/:role` | Trigger password rotation |

### Broker Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `semp_url` | string | yes | SEMP v1 endpoint URL, e.g., `https://broker:8080` |
| `admin_username` | string | yes | Admin username for SEMP authentication |
| `admin_password` | string | yes | Admin password (encrypted at rest, never returned on read) |
| `semp_version` | string | no | SEMP schema version, e.g., `soltr/10_4`. Omitted from the RPC if not set. |
| `tls_skip_verify` | bool | no | Skip TLS certificate verification. Do not use in production. |

### Role Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `broker` | string | yes | Name of a configured broker |
| `cli_username` | string | yes | CLI user account name on the broker |
| `rotation_period` | int | no | Auto-rotation interval in seconds. `0` (default) disables automatic rotation. |
| `password_length` | int | no | Length of generated passwords, 16–128. Default: `25`. |

## Development

```bash
make build    # Build plugin binary
make test     # Run tests with race detection
make fmt      # Format source code
make clean    # Remove build artifacts
```

Run a single test:

```bash
go test -v -race -run TestPathRotate_Success ./...
```

## Security Notes

- The SEMP admin account should use least privilege — only the permission needed to change CLI user passwords.
- Broker admin passwords are encrypted at rest via Vault's seal-wrap storage.
- The plugin uses SEMP v1 (XML) because SEMP v2 (REST) does not support CLI user password management.
- Rotation is atomic: the new password is stored in Vault only after the broker confirms the change. On failure, the old password remains.

## References

- [Solace: Configuring Internal CLI User Accounts](https://docs.solace.com/Admin/Configuring-Internal-CLI-User-Accounts.htm)
- [Solace: Legacy SEMP](https://docs.solace.com/Admin/SEMP/Using-Legacy-SEMP.htm)
- [HashiCorp: Building Custom Vault Secrets Engines](https://developer.hashicorp.com/vault/docs/plugins)
