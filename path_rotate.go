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
			ExistenceCheck:  b.pathRotateRoleExistenceCheck,
			HelpSynopsis:    "Rotate the password for a Solace CLI user.",
			HelpDescription: "Triggers an immediate password rotation for the CLI user associated with the named role.",
		},
	}
}

func (b *solaceBackend) pathRotateRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
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
