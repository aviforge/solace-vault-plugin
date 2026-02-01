# Solace Vault Plugin — Design Document

## Overview

A HashiCorp Vault secrets engine plugin that manages password rotation for Solace PubSub+ CLI (management) user accounts. When a password is rotated in Vault — either on-demand or on a schedule — the plugin propagates the change to the target Solace broker via the SEMP v1 XML API.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Secrets engine pattern | Static roles | CLI accounts are long-lived management accounts; static rotation fits naturally |
| Broker relationship | Multi-broker | Real environments have multiple brokers (dev, staging, prod, regions) |
| Language | Go | Native Vault plugin SDK support, first-class community tooling |
| SEMP API | v1 (XML) | SEMP v2 does not expose CLI user password management; only SEMP v1 supports it |
| SEMP authentication | Basic auth | Covers the vast majority of on-prem and software broker deployments |
| CLI user scope | Broker-level only | CLI users are management accounts that exist at the broker level, not within a message VPN |

## Architecture

### Plugin Type

The plugin is a Vault **secrets engine backend** registered as a custom plugin. It is mounted at a configurable path (e.g., `solace/`) and exposes a REST API through Vault's standard HTTP interface. All operations work through both the Vault CLI and the Vault HTTP API.

### Data Model

**Broker Config** — Connection details for a Solace broker's SEMP v1 management interface.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `semp_url` | string | yes | SEMP v1 endpoint, e.g., `https://broker:8080` |
| `admin_username` | string | yes | Admin account for SEMP authentication |
| `admin_password` | string | yes | Admin password (encrypted at rest, never returned on read) |
| `semp_version` | string | no | Schema version string, e.g., `soltr/10_4`. Omitted from RPC if not set. |
| `tls_skip_verify` | bool | no | Skip TLS certificate verification (dev/test only) |

**Role** — Maps a Vault role name to a CLI user on a specific broker.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `broker` | string | yes | References a broker config by name |
| `cli_username` | string | yes | The CLI account name on the broker |
| `rotation_period` | duration | no | Automatic rotation interval, e.g., `24h`, `7d` |
| `password` | string | internal | Current password (managed by plugin, never set by user) |
| `last_rotated` | timestamp | internal | When the password was last rotated |

## API Paths

### Broker Configuration

| Method | Path | Description |
|--------|------|-------------|
| POST | `solace/config/brokers/:name` | Create or update a broker config |
| GET | `solace/config/brokers/:name` | Read a broker config (admin password redacted) |
| DELETE | `solace/config/brokers/:name` | Delete a broker config |
| LIST | `solace/config/brokers` | List all configured brokers |

### Static Roles

| Method | Path | Description |
|--------|------|-------------|
| POST | `solace/roles/:name` | Create or update a role |
| GET | `solace/roles/:name` | Read a role config |
| DELETE | `solace/roles/:name` | Delete a role |
| LIST | `solace/roles` | List all roles |

### Credentials and Rotation

| Method | Path | Description |
|--------|------|-------------|
| GET | `solace/creds/:role` | Read current username and password for a role |
| POST | `solace/rotate-role/:role` | Trigger on-demand password rotation |

## Password Rotation Flow

1. Vault receives the rotation request — either `POST /v1/solace/rotate-role/:role` (on-demand) or the plugin's periodic function fires (automatic based on `rotation_period`).
2. Plugin reads the role config from Vault storage to get the broker reference and CLI username.
3. Plugin reads the referenced broker config to get the SEMP URL and admin credentials.
4. Plugin generates a new password — cryptographically secure random, respecting Solace constraints (max 128 chars, excludes `:()";'<>,\`\\*&|`). Default length: 32 characters.
5. Plugin sends SEMP v1 XML RPC to change the password on the broker:
   ```xml
   <rpc semp-version="soltr/VERSION">
     <username>
       <name>cli-user-name</name>
       <change-password>
         <password>new-generated-password</password>
       </change-password>
     </username>
   </rpc>
   ```
   Sent as HTTP POST to `<semp_url>/SEMP` with basic auth (`admin_username`/`admin_password`).
6. Plugin parses the SEMP v1 XML response to confirm success.
7. On success — new password is stored in Vault, `last_rotated` timestamp updated.
8. On failure — old password remains in Vault unchanged. Error returned to caller.

## Error Handling

**SEMP v1 failures:** If the SEMP call fails (network error, auth failure, broker down), the plugin returns the error and does not update the stored password. Vault and broker stay in sync.

**XML response validation:** A successful HTTP 200 does not guarantee the SEMP command succeeded. The plugin inspects the XML body for error elements and non-ok status.

**Broker unreachable:** Rotation fails with a clear error including the broker name and SEMP URL. For periodic rotation, failed attempts are logged and retried on the next cycle.

**Stale broker reference:** If a role references a deleted broker config, credential reads and rotations return: `broker "<name>" not found`. Broker deletion does not cascade-delete roles.

**Concurrent rotation:** Vault's storage backend provides consistency. Simultaneous rotation requests are serialized — no risk of storing a password that wasn't set on the broker.

## Project Structure

```
solace-vault-plugin/
├── cmd/
│   └── solace-vault-plugin/
│       └── main.go             # Plugin entry point, serves the backend
├── backend.go                  # Backend factory, path registration, periodic func
├── backend_test.go
├── path_config_brokers.go      # Broker config CRUD paths
├── path_config_brokers_test.go
├── path_roles.go               # Role CRUD paths
├── path_roles_test.go
├── path_creds.go               # Read credentials path
├── path_creds_test.go
├── path_rotate.go              # On-demand rotation path
├── path_rotate_test.go
├── semp_client.go              # SEMP v1 HTTP client (XML build/parse)
├── semp_client_test.go
├── storage.go                  # Vault storage helpers (get/put/delete/list)
├── types.go                    # All data types (BrokerConfig, RoleEntry)
├── password.go                 # Password generation with Solace constraints
├── password_test.go
├── go.mod
├── go.sum
├── Makefile                    # build, test, dev targets
└── README.md
```

**Design principles:**
- Flat package structure following official Vault plugin conventions (`vault-plugin-secrets-*`).
- Thin `cmd/` binary — just `plugin.Serve()`.
- All types in `types.go` — single place to find data structures.
- SEMP XML concerns isolated in `semp_client.go` — mockable via interface for tests.
- Test files colocated with source (`_test.go` next to each file).
- `Makefile` for build, test, and dev targets.

## Usage Example

### Setup

```bash
# Register and enable the plugin
vault plugin register -sha256=<SHA> secret solace-vault-plugin
vault secrets enable -path=solace solace-vault-plugin

# Configure a broker
vault write solace/config/brokers/prod-east \
  semp_url="https://broker-prod-east:8080" \
  admin_username="admin" \
  admin_password="admin-secret" \
  semp_version="soltr/10_4"

# Create a role
vault write solace/roles/monitoring-user \
  broker="prod-east" \
  cli_username="monitor" \
  rotation_period="24h"

# Initial rotation (sets a Vault-managed password)
vault write -f solace/rotate-role/monitoring-user
```

### Read Credentials

```bash
vault read solace/creds/monitoring-user
# Key             Value
# ---             -----
# cli_username    monitor
# password        aB3$kZ9...generated...
# broker          prod-east
# last_rotated    2026-02-01T14:30:00Z
```

### Vault ACL Policy

```hcl
# Operators: configure brokers and roles
path "solace/config/*" {
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

## Security Considerations

- All Vault API communication should be over TLS.
- Broker admin passwords are encrypted at rest by Vault's storage backend.
- Vault audit logging can HMAC-hash sensitive fields to prevent plaintext passwords in logs.
- The SEMP admin account should use least privilege — only the permission needed to change CLI user passwords.
- Vault tokens used to configure brokers should be short-lived and narrowly scoped.

## References

- [Solace: Configuring Internal CLI User Accounts](https://docs.solace.com/Admin/Configuring-Internal-CLI-User-Accounts.htm)
- [Solace: Legacy SEMP](https://docs.solace.com/Admin/SEMP/Using-Legacy-SEMP.htm)
- [Solace: SEMP Overview](https://docs.solace.com/Admin/SEMP/Using-SEMP.htm)
- [HashiCorp: Building Custom Vault Secrets Engines](https://developer.hashicorp.com/vault/docs/plugins)
- [Solace Community: cli-to-semp discussion](https://community.solace.com/discussion/4029/cli-to-semp-is-not-working-for-adding-access-level-exception)

## Open Items

- **SEMP v1 XML validation:** The exact XML tag names for `change-password` should be verified against the `semp-rpc-soltr.xsd` schema from the target broker version (found at `/usr/sw/loads/currentload/schema/` inside the broker).
