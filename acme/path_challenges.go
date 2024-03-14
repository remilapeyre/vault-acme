package acme

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathChallenges(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "challenges/(http-01|tls-alpn-01)/" + framework.MatchAllRegex("path"),
		Fields: map[string]*framework.FieldSchema{
			"path": {
				Type:     framework.TypeString,
				Required: true,
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.challengeHTTP01Read,
			},
		},
	}
}

func (b *backend) challengeHTTP01Read(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("Looking up for a token", "path", req.Path)
	storageEntry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return logical.ErrorResponse("failed to find a token"), nil
	}

	var d map[string]interface{}
	err = storageEntry.DecodeJSON(&d)
	if err != nil {
		return nil, fmt.Errorf("failed to decode storage entry: %v", err)
	}

	return &logical.Response{
		Data: d,
	}, nil
}
