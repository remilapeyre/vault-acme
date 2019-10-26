package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"

	"github.com/go-acme/lego/v3/registration"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// This list comes from https://github.com/go-acme/lego/blob/master/providers/dns/dns_providers.go#L71
// and should be updated when upgrading lego
// Some must not be added here like 'exec' or 'rfc2136'
var providers = []string{
	"acme-dns",
	"alidns",
	"azure",
	"auroradns",
	"bindman",
	"bluecat",
	"cloudflare",
	"cloudns",
	"cloudxns",
	"conoha",
	"designate",
	"digitalocean",
	"dnsimple",
	"dnsmadeeasy",
	"dnspod",
	"dode",
	"dreamhost",
	"duckdns",
	"dyn",
	"fastdns",
	"easydns",
	"exoscale",
	"gandi",
	"gandiv5",
	"glesys",
	"gcloud",
	"godaddy",
	"hostingde",
	"httpreq",
	"iij",
	"inwx",
	"joker",
	"lightsail",
	"linode",
	"linodev4",
	"liquidweb",
	"manual",
	"mydnsjp",
	"namecheap",
	"namedotcom",
	"namesilo",
	"netcup",
	"nifcloud",
	"ns1",
	"oraclecloud",
	"otc",
	"ovh",
	"pdns",
	"rackspace",
	"route53",
	"sakuracloud",
	"stackpath",
	"selectel",
	"transip",
	"vegadns",
	"versio",
	"vultr",
	"vscale",
	"zoneee",
}

func pathAccounts(b *backend) *framework.Path {
	allowedProviders := make([]interface{}, len(providers))
	for i, p := range providers {
		allowedProviders[i] = p
	}
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
				Type:          framework.TypeString,
				Required:      true,
				AllowedValues: allowedProviders,
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

	var found bool
	for _, p := range providers {
		if provider == p {
			found = true
			break
		}
	}
	if !found {
		return logical.ErrorResponse("'%s' is not a supported provider.", provider), nil
	}

	b.Logger().Info("Generating key pair for new account")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errwrap.Wrapf("Failed to generate account key pair: {{err}}", err)
	}

	user := user{
		Email:                contact,
		Key:                  privateKey,
		ServerURL:            serverURL,
		Provider:             provider,
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
	u, err := getUser(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"server_url":              u.ServerURL,
			"registration_uri":        u.Registration.URI,
			"contact":                 u.GetEmail(),
			"terms_of_service_agreed": u.TermsOfServiceAgreed,
			"provider":                u.Provider,
		},
	}, nil
}

func (b *backend) accountDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	u, err := getUser(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}

	client, err := u.getClient()
	if err != nil {
		return nil, errwrap.Wrapf("Failed to instanciate new client: {{err}}", err)
	}

	if err = client.Registration.DeleteRegistration(); err != nil {
		b.Logger().Info("foo", "private key", reflect.TypeOf(u.GetPrivateKey()))
		return nil, errwrap.Wrapf("Failed to deactivate registration: {{err}}", err)
	}

	err = req.Storage.Delete(ctx, req.Path)

	return nil, err
}
