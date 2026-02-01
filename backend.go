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
