package acme

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretCertType = "cert"

func secretCert(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretCertType,
		Fields: map[string]*framework.FieldSchema{
			"domain": {
				Type: framework.TypeString,
			},
			"url": {
				Type: framework.TypeString,
			},
			"private_key": {
				Type: framework.TypeString,
			},
			"cert": {
				Type: framework.TypeString,
			},
			"issuer_cert": {
				Type: framework.TypeString,
			},
			"not_before": {
				Type: framework.TypeString,
			},
			"not_after": {
				Type: framework.TypeString,
			},
		},
		Renew:  b.certRenew,
		Revoke: b.certRevoke,
	}
}

func (b *backend) certRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	// I'm not really sure about this
	resp.Secret.TTL = resp.Secret.TTL + req.Secret.Increment
	return resp, nil
}

func (b *backend) certRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var users int64
	cacheKey := req.Secret.InternalData["cache_key"].(string)

	cert := req.Secret.InternalData["cert"].(string)
	b.Logger().Debug("Trying to revoke cert", "url", req.Secret.InternalData["url"].(string), "cert", cert)

	storageEntry, err := req.Storage.Get(ctx, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cache entry: %v", err)
	}
	if storageEntry != nil {
		var d map[string]interface{}
		if err = storageEntry.DecodeJSON(&d); err != nil {
			return nil, fmt.Errorf("failed to decode cache entry: %v", err)
		}
		users, err = d["users"].(json.Number).Int64()
		if err != nil {
			return nil, fmt.Errorf("failed to decode users: %v", err)
		}
		b.Logger().Debug("Looking in the cache to determine whether to revoke the cert", "users", users)
		users--
		d["users"] = users
		if users != 0 {
			storageEntry, err := logical.StorageEntryJSON(cacheKey, d)
			if err != nil {
				return nil, fmt.Errorf("failed to create cache entry: %v", err)
			}
			err = req.Storage.Put(ctx, storageEntry)
			if err != nil {
				return nil, fmt.Errorf("failed to save cache entry: %v", err)
			}
		} else {
			err = req.Storage.Delete(ctx, cacheKey)
			if err != nil {
				return nil, fmt.Errorf("failed to remove cache entry: %v", err)
			}
		}
	}

	// If the last user asked for the lease to be terminated we revoke the cert
	if users == 0 {
		accountPath := req.Secret.InternalData["account"].(string)
		a, err := getAccount(ctx, req.Storage, accountPath)
		if err != nil {
			return nil, err
		}
		if a == nil {
			return nil, fmt.Errorf("Error while revoking certificate: user not found")
		}
		client, err := a.getClient()
		if err != nil {
			return logical.ErrorResponse("Failed to get LEGO client."), err
		}
		err = client.Certificate.Revoke([]byte(cert))
		if err != nil {
			return nil, fmt.Errorf("failed to revoke cert: %v", err)
		}
	}

	return nil, nil
}
