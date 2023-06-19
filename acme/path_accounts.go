package acme

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var keyTypes = []interface{}{
	"EC256",
	"EC384",
	"RSA2048",
	"RSA4096",
	"RSA8192",
}

func pathAccounts(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "accounts/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.accountList,
			},
		},
		{
			Pattern: "accounts/" + framework.GenericNameRegex("account"),
			Fields: map[string]*framework.FieldSchema{
				"account": {
					Type:     framework.TypeString,
					Required: true,
				},
				"server_url": {
					Type: framework.TypeString,
					// Required is only used in the documentation for now
					Required: true,
				},
				"terms_of_service_agreed": {
					Type:    framework.TypeBool,
					Default: false,
				},
				"key_type": {
					Type:          framework.TypeString,
					Default:       "EC256",
					AllowedValues: keyTypes,
				},
				// TODO(remi): We should have a list of those so we can request certs
				// for domains registred to different providers
				"provider": {
					Type: framework.TypeString,
				},
				"provider_configuration": {
					Type: framework.TypeKVPairs,
				},
				"enable_http_01": {
					Type: framework.TypeBool,
				},
				"enable_tls_alpn_01": {
					Type: framework.TypeBool,
				},
				"dns_resolvers": {
					Type: framework.TypeStringSlice,
				},
				"ignore_dns_propagation": {
					Type:    framework.TypeBool,
					Default: false,
				},
				"contact": {
					Type:     framework.TypeString,
					Required: true,
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.accountWrite,
				logical.ReadOperation:   b.accountRead,
				logical.UpdateOperation: b.accountWrite,
				logical.DeleteOperation: b.accountDelete,
			},
		},
	}
}

func getKeyType(t string) (certcrypto.KeyType, error) {
	switch t {
	case "EC256":
		return certcrypto.EC256, nil
	case "EC384":
		return certcrypto.EC384, nil
	case "RSA2048":
		return certcrypto.RSA2048, nil
	case "RSA4096":
		return certcrypto.RSA4096, nil
	case "RSA8192":
		return certcrypto.RSA8192, nil
	default:
		return certcrypto.KeyType(""), fmt.Errorf("%q is not a supported key type", t)
	}
}

func (b *backend) accountWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}
	serverURL := data.Get("server_url").(string)
	contact := data.Get("contact").(string)
	termsOfServiceAgreed := data.Get("terms_of_service_agreed").(bool)
	provider := data.Get("provider").(string)
	providerConfiguration := data.Get("provider_configuration").(map[string]string)
	enableHTTP01 := data.Get("enable_http_01").(bool)
	enableTLSALPN01 := data.Get("enable_tls_alpn_01").(bool)
	dnsResolvers := data.Get("dns_resolvers").([]string)
	ignoreDNSPropagation := data.Get("ignore_dns_propagation").(bool)

	if provider != "" {
		_, err := dns.NewDNSChallengeProviderByName(provider)
		if err != nil {
			return logical.ErrorResponse(fmt.Errorf("failed to find provider: %w", err).Error()), nil
		}
	}

	var update bool
	user, err := getAccount(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}

	if user == nil {
		b.Logger().Info("Generating key pair for new account")
		keyType, err := getKeyType(data.Get("key_type").(string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		privateKey, err := certcrypto.GeneratePrivateKey(keyType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate account key pair: %w", err)
		}

		user = &account{
			ServerURL: serverURL,
			KeyType:   data.Get("key_type").(string),
			Key:       privateKey,
		}
	} else {
		update = true
		if serverURL != user.ServerURL {
			return logical.ErrorResponse("Cannot update server_url"), nil
		}
		if data.Get("key_type").(string) != user.KeyType {
			return logical.ErrorResponse("Cannot update key_type"), nil
		}
	}

	user.Email = contact
	user.Provider = provider
	user.ProviderConfiguration = providerConfiguration
	user.EnableHTTP01 = enableHTTP01
	user.EnableTLSALPN01 = enableTLSALPN01
	user.TermsOfServiceAgreed = termsOfServiceAgreed
	user.DNSResolvers = dnsResolvers
	user.IgnoreDNSPropagation = ignoreDNSPropagation

	client, err := user.getClient()
	if err != nil {
		return nil, err
	}

	var reg *registration.Resource
	options := registration.RegisterOptions{
		TermsOfServiceAgreed: termsOfServiceAgreed,
	}
	if update {
		b.Logger().Info("Updating account")
		reg, err = client.Registration.UpdateRegistration(options)
	} else {
		b.Logger().Info("Registring new account")
		reg, err = client.Registration.Register(options)
	}

	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	user.Registration = reg

	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	b.Logger().Info("Saving account")
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
			"key_type":                a.KeyType,
			"provider":                a.Provider,
			"provider_configuration":  a.ProviderConfiguration,
			"enable_http_01":          a.EnableHTTP01,
			"enable_tls_alpn_01":      a.EnableTLSALPN01,
			"dns_resolvers":           a.DNSResolvers,
			"ignore_dns_propagation":  a.IgnoreDNSPropagation,
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
		return nil, fmt.Errorf("failed to instanciate new client: %s", err)
	}

	if err = client.Registration.DeleteRegistration(); err != nil {
		return nil, fmt.Errorf("failed to deactivate registration: %w", err)
	}

	err = req.Storage.Delete(ctx, req.Path)

	return nil, err
}

func (b *backend) accountList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
