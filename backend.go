package solacevaultplugin

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = "The Solace secrets engine rotates CLI user passwords on Solace PubSub+ brokers."

type solaceBackend struct {
	*framework.Backend
	roleMutex sync.Mutex
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
		RunningVersion: "v0.1.0",
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/brokers/*",
				"roles/*",
			},
		},
		Paths: framework.PathAppend(
            pathConfigBrokers(b),
            pathRoles(b),
            pathCreds(b),
            pathRotateRole(b),
       ),
	}

	return b
}
