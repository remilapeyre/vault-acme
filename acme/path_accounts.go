package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/go-acme/lego/v3/registration"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAccounts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("account"),
		Fields: map[string]*framework.FieldSchema{
			"account": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
			},
			"server_url": &framework.FieldSchema{
				Type: framework.TypeString,
				// Required is only used in the documentation for now
				Required: true,
			},
			"terms_of_service_agreed": &framework.FieldSchema{
				Type:    framework.TypeBool,
				Default: false,
			},
			// TODO(remi): We should have a list of those so we can request certs
			// for domains registred to different providers
			"provider": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"enable_http_01": &framework.FieldSchema{
				Type: framework.TypeBool,
			},
			"enable_tls_alpn_01": &framework.FieldSchema{
				Type: framework.TypeBool,
			},
			"contact": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.accountCreate,
			logical.ReadOperation:   b.accountRead,
			// TODO(remi): this is not yet possible with Lego, see
			// https://github.com/go-acme/lego/issues/443
			// logical.UpdateOperation: nil,
			logical.DeleteOperation: b.accountDelete,
		},
	}
}

func (b *backend) accountCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}
	serverURL := data.Get("server_url").(string)
	contact := data.Get("contact").(string)
	termsOfServiceAgreed := data.Get("terms_of_service_agreed").(bool)
	provider := data.Get("provider").(string)
	enableHTTP01 := data.Get("enable_http_01").(bool)
	enableTLSALPN01 := data.Get("enable_tls_alpn_01").(bool)

	b.Logger().Info("Generating key pair for new account")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errwrap.Wrapf("Failed to generate account key pair: {{err}}", err)
	}

	user := account{
		Email:                contact,
		Key:                  privateKey,
		ServerURL:            serverURL,
		Provider:             provider,
		EnableHTTP01:         enableHTTP01,
		EnableTLSALPN01:      enableTLSALPN01,
		TermsOfServiceAgreed: termsOfServiceAgreed,
	}

	client, err := user.getClient()
	if err != nil {
		return nil, err
	}

	b.Logger().Info("Registring new account")
	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: termsOfServiceAgreed,
	})
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	user.Registration = reg

	if err != nil {
		return nil, errwrap.Wrapf("Failed to create storage entry: {{err}}", err)
	}

	b.Logger().Info("Saving new account")
	if err = user.save(ctx, req.Storage, req.Path, serverURL); err != nil {
		return nil, err
	}

	return b.accountRead(ctx, req, data)
}

func (b *backend) accountRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	a, err := getAccount(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"server_url":              a.ServerURL,
			"registration_uri":        a.Registration.URI,
			"contact":                 a.GetEmail(),
			"terms_of_service_agreed": a.TermsOfServiceAgreed,
			"provider":                a.Provider,
			"enable_http_01":          a.EnableHTTP01,
			"enable_tls_alpn_01":      a.EnableTLSALPN01,
		},
	}, nil
}

func (b *backend) accountDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	a, err := getAccount(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}

	client, err := a.getClient()
	if err != nil {
		return nil, errwrap.Wrapf("Failed to instanciate new client: {{err}}", err)
	}

	if err = client.Registration.DeleteRegistration(); err != nil {
		return nil, errwrap.Wrapf("Failed to deactivate registration: {{err}}", err)
	}

	err = req.Storage.Delete(ctx, req.Path)

	return nil, err
}
