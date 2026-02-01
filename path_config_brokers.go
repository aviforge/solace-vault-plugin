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
