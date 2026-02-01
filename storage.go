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
