package solacevaultplugin

import (
	"context"
	"time"

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
		Paths: framework.PathAppend(
			pathConfigBrokers(b),
			pathRoles(b),
			pathRotateRole(b),
			pathCreds(b),
		),
		PeriodicFunc: b.periodicFunc,
	}

	return b
}

func (b *solaceBackend) periodicFunc(ctx context.Context, req *logical.Request) error {
	logger := b.Logger()

	roleNames, err := listRoles(ctx, req.Storage)
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	for _, name := range roleNames {
		role, err := getRole(ctx, req.Storage, name)
		if err != nil {
			logger.Error("periodic: failed to read role", "role", name, "error", err)
			continue
		}
		if role == nil {
			continue
		}

		// Skip roles without automatic rotation
		if role.RotationPeriod == 0 {
			continue
		}

		// Skip roles that haven't been rotated yet (need initial manual rotation)
		if role.LastRotated.IsZero() {
			continue
		}

		// Skip roles not yet due for rotation
		if now.Before(role.LastRotated.Add(role.RotationPeriod)) {
			continue
		}

		logger.Info("periodic: rotating role", "role", name, "cli_username", role.CLIUsername, "broker", role.Broker)

		resp, err := b.rotateRole(ctx, req.Storage, name)
		if err != nil {
			logger.Error("periodic: rotation failed", "role", name, "error", err)
			continue
		}
		if resp != nil && resp.IsError() {
			logger.Error("periodic: rotation returned error", "role", name, "error", resp.Data["error"])
			continue
		}

		logger.Info("periodic: rotation complete", "role", name)
	}

	return nil
}
