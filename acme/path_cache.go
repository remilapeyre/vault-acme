package acme

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const cachePrefix = "cache/"

func pathCache(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "cache",
		Fields: map[string]*framework.FieldSchema{
			"cached_certs": &framework.FieldSchema{
				Type: framework.TypeInt,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.cacheRead,
			logical.DeleteOperation: b.cacheFlush,
		},
	}
}

type cache struct {
	b *backend
}

func (c cache) List(ctx context.Context, storage logical.Storage) ([]string, error) {
	c.b.Logger().Debug("Listing keys from cache")
	return storage.List(ctx, cachePrefix)
}

func (c cache) Delete(ctx context.Context, storage logical.Storage, key string) error {
	c.b.Logger().Debug("Removing key from cache", "key", key)
	return storage.Delete(ctx, cachePrefix+key)
}

func (b *backend) cacheRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keys, err := b.Cache().List(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to read cache"), err
	}

	b.Logger().Debug("Read cache status", "keys", keys)

	return &logical.Response{
		Data: map[string]interface{}{
			"cached_certs": len(keys),
		},
	}, nil
}

func (b *backend) cacheFlush(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cache := b.Cache()

	keys, err := cache.List(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to read cache"), err
	}

	b.Logger().Debug("Flushing cache", "keys", keys)

	for _, key := range keys {
		err = cache.Delete(ctx, req.Storage, key)
		if err != nil {
			return logical.ErrorResponse("failed to remove entry from cache"), err
		}
	}

	return nil, nil
}
