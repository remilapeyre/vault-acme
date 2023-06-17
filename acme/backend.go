package acme

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
	tidyStatusLock sync.RWMutex
	lastTidy       time.Time
	cache          *Cache
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
		Paths: framework.PathAppend(
			pathAccounts(&b),
			pathRoles(&b),
			[]*framework.Path{
				pathCerts(&b),
				pathChallenges(&b),
				pathCache(&b),
			},
		),
		PeriodicFunc: b.periodicFunc,
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	// Initiate clean-up of expired SecretID entries
	if b.System().LocalMount() || !b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary|consts.ReplicationPerformanceStandby) {
		// Check if we should run another tidy...
		now := time.Now()
		b.tidyStatusLock.RLock()
		nextOp := b.lastTidy.Add(24 * time.Hour)
		b.tidyStatusLock.RUnlock()
		if now.Before(nextOp) {
			return nil
		}

		b.tidyStatusLock.Lock()
		b.lastTidy = now
		b.tidyStatusLock.Unlock()

		b.tidyCertificates(ctx, req)
	}
	return nil
}

// TODO: run inside of a goroutine
// https://github.com/hashicorp/vault/blob/659316cff1e5a437a47447492a2a426c8222354b/builtin/logical/pki/backend.go#L443-L492
// Deletes / revokes certificate entries that don't have any users
func (b *backend) tidyCertificates(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	// As we're (below) modifying the backing storage, we need to ensure
	// we're not on a standby/secondary node.
	if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) ||
		b.System().ReplicationState().HasState(consts.ReplicationDRSecondary) {
		return nil, logical.ErrReadOnly
	}
	b.cache.Lock()
	keys, err := b.cache.List(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to list cache: %w", err), nil
	}

	var keyErrors error
	for _, key := range keys {
		ceKey := cachePrefix + key
		ce, err := b.cache.GetCacheEntry(ctx, req.Storage, ceKey)
		if err != nil {
			keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: %w", ceKey, err))
			continue
		}

		if ce.Users > 0 {
			continue
		}

		err = b.cache.Delete(ctx, req.Storage, ceKey)
		if err != nil {
			keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: failed to delete cache entry: %w", ceKey, err))
			continue
		}

		a, err := getAccount(ctx, req.Storage, ce.Account)
		if err != nil {
			keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: failed to get account: %w", ceKey, err))
			continue
		}
		if a == nil {
			keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: account not found", ceKey))
			continue
		}
		client, err := a.getClient()
		if err != nil {
			keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: failed to get lego client: %w", ceKey, err))
			continue
		}
		err = client.Certificate.Revoke(ce.Cert)
		if err != nil {
			keyErrors = multierror.Append(fmt.Errorf("failed to tidy %s: failed to revoke the certificate: %w", ceKey, err))
			continue
		}
	}

	if keyErrors != nil {
		b.Logger().Error("failed to tidy keys: %w", keyErrors)
		return logical.ErrorResponse("failed to tidy keys: %w", keyErrors), nil
	}

	resp := &logical.Response{}
	return logical.RespondWithStatusCode(resp, req, http.StatusOK)
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}
