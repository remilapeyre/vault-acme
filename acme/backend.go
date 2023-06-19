package acme

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
	tidyStatusLock sync.RWMutex
	tidyStatus     *tidyStatus
	lastTidy       time.Time
	tidyCASGuard   *uint32
	tidyCancelCAS  *uint32
	storage        logical.Storage
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

				pathTidy(&b),
				pathTidyCancel(&b),
				pathTidyStatus(&b),
			},
		),
		PeriodicFunc: b.periodicFunc,
	}

	b.tidyCASGuard = new(uint32)
	b.tidyStatus = &tidyStatus{state: tidyStatusInactive}
	b.tidyCancelCAS = new(uint32)
	b.storage = conf.StorageView
	b.lastTidy = time.Now()

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	if b.System().LocalMount() || !b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary|consts.ReplicationPerformanceStandby) {
		// Check if we should run another tidy...
		now := time.Now()
		b.tidyStatusLock.RLock()
		nextOp := b.lastTidy.Add(24 * time.Hour)
		b.tidyStatusLock.RUnlock()
		if now.Before(nextOp) {
			return nil
		}

		// Ensure a tidy isn't already running... If it is, we'll trigger
		// again when the running one finishes.
		if !atomic.CompareAndSwapUint32(b.tidyCASGuard, 0, 1) {
			return nil
		}

		b.tidyStatusLock.Lock()
		b.lastTidy = now
		b.tidyStatusLock.Unlock()

		// Because the request from the parent storage will be cleared at
		// some point (and potentially reused) -- due to tidy executing in
		// a background goroutine -- we need to copy the storage entry off
		// of the backend instead.
		backendReq := &logical.Request{
			Storage: b.storage,
		}

		b.startTidyOperation(backendReq)
		return nil
	}
	return nil
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}
