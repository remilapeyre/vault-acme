package acme

import (
	"context"
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
	accountPath := req.Secret.InternalData["account"].(string)
	u, err := getUser(ctx, req.Storage, accountPath)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("Error while revoking certificate: user not found")
	}
	client, err := u.getClient()
	cert := req.Secret.InternalData["cert"].([]byte)
	return nil, client.Certificate.Revoke(cert)
}
