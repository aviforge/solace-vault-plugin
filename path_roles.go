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
