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
	PasswordLength int           `json:"password_length,omitempty"`
	Password       string        `json:"password,omitempty"`
	LastRotated    time.Time     `json:"last_rotated,omitempty"`
}
