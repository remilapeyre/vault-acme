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
			"domain": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"url": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"private_key": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"cert": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"issuer_cert": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"not_before": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"not_after": &framework.FieldSchema{
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
	cacheKey := req.Secret.InternalData["cache_key"]

	cert := req.Secret.InternalData["cert"].([]byte)
	b.Logger().Debug("Trying to revoke cert", "url", req.Secret.InternalData["url"].(string), "cert", string(cert))

	storageEntry, err := req.Storage.Get(ctx, cacheKey.(string))
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
		storageEntry, err := logical.StorageEntryJSON(cacheKey.(string), d)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache entry: %v", err)
		}
		err = req.Storage.Put(ctx, storageEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to save cache entry: %v", err)
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
		err = client.Certificate.Revoke(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to revoke cert: %v", err)
		}
	}

	return nil, nil
}
