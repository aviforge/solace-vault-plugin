package solacevaultplugin

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = "The Solace secrets engine rotates CLI user passwords on Solace PubSub+ brokers."

type solaceBackend struct {
	*framework.Backend
	roleMutex sync.RWMutex
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
		PeriodicFunc: b.periodicFunc,
		Paths: framework.PathAppend(
            pathConfigBrokers(b),
            pathRoles(b),
            pathCreds(b),
            pathRotateRole(b),
       ),
	}

	return b
}

func (b *solaceBackend) periodicFunc(ctx context.Context, req *logical.Request) error {
	roles, err := listRoles(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("periodic: failed to list roles", "error", err)
		return nil
	}

	for _, name := range roles {
		role, err := getRole(ctx, req.Storage, name)
		if err != nil {
			b.Logger().Error("periodic: failed to read role", "role", name, "error", err)
			continue
		}
		if role == nil || role.RotationPeriod == 0 || role.LastRotated.IsZero() {
			continue
		}
		if time.Now().UTC().After(role.LastRotated.Add(role.RotationPeriod)) {
			if _, err := b.rotateRole(ctx, req.Storage, name); err != nil {
				b.Logger().Error("periodic: failed to rotate role", "role", name, "error", err)
			}
		}
	}

	return nil
}
