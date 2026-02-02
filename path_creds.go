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

	b.roleMutex.RLock()
	defer b.roleMutex.RUnlock()

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
