package acme

import (
	"context"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
	cache *Cache
}

// Factory creates a new ACME backend implementing logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend{
		cache: NewCache(),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Secrets: []*framework.Secret{
			secretCert(&b),
		},
		Paths: []*framework.Path{
			pathListAccounts(&b),
			pathAccounts(&b),
			pathListRoles(&b),
			pathRoles(&b),
			pathCerts(&b),
			pathChallenges(&b),
			pathCache(&b),
		},
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}
