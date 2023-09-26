package acme

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCache(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "cache",
		Fields: map[string]*framework.FieldSchema{
			"cached_certs": {
				Type: framework.TypeInt,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.cacheRead,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.cacheClear,
			},
		},
	}
}

func (b *backend) cacheRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.cache.Lock()
	defer b.cache.Unlock()
	keys, err := b.cache.List(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to read cache"), err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"cached_certs": len(keys),
		},
	}, nil
}

func (b *backend) cacheClear(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.cache.Lock()
	defer b.cache.Unlock()
	err := b.cache.Clear(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to clear cache"), err
	}
	return nil, nil
}
