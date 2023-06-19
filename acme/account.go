package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	accountsPrefix = "accounts/"
)

type account struct {
	Email                 string
	Registration          *registration.Resource
	Key                   crypto.PrivateKey
	KeyType               string
	ServerURL             string
	Provider              string
	ProviderConfiguration map[string]string
	EnableHTTP01          bool
	EnableTLSALPN01       bool
	TermsOfServiceAgreed  bool
	DNSResolvers          []string
	IgnoreDNSPropagation  bool
}

// GetEmail returns the Email of the user
func (a *account) GetEmail() string {
	return a.Email
}

// GetRegistration returns the Email of the user
func (a *account) GetRegistration() *registration.Resource {
	return a.Registration
}

// GetPrivateKey returns the private key of the user
func (a *account) GetPrivateKey() crypto.PrivateKey {
	return a.Key
}

func (a *account) getClient() (*lego.Client, error) {
	config := lego.NewConfig(a)
	config.CADirURL = a.ServerURL

	return lego.NewClient(config)
}

func getAccount(ctx context.Context, storage logical.Storage, path string) (*account, error) {
	storageEntry, err := storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, nil
	}
	var d map[string]interface{}
	if err = storageEntry.DecodeJSON(&d); err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(d["private_key"].(string)))
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	providerConfiguration := map[string]string{}
	for k, v := range d["provider_configuration"].(map[string]interface{}) {
		providerConfiguration[k] = v.(string)
	}

	a := &account{
		Email:   d["contact"].(string),
		Key:     privateKey,
		KeyType: d["key_type"].(string),
		Registration: &registration.Resource{
			URI: d["registration_uri"].(string),
		},
		ServerURL:             d["server_url"].(string),
		Provider:              d["provider"].(string),
		ProviderConfiguration: providerConfiguration,
		TermsOfServiceAgreed:  d["terms_of_service_agreed"].(bool),
		EnableHTTP01:          d["enable_http_01"].(bool),
		EnableTLSALPN01:       d["enable_tls_alpn_01"].(bool),
	}

	if ignoreDNSPropagation, ok := d["ignore_dns_propagation"]; ok {
		a.IgnoreDNSPropagation = ignoreDNSPropagation.(bool)
	}

	a.DNSResolvers = make([]string, len(d["dns_resolvers"].([]interface{})))
	for i, resolver := range d["dns_resolvers"].([]interface{}) {
		a.DNSResolvers[i] = resolver.(string)
	}

	return a, nil
}

func (a *account) save(ctx context.Context, storage logical.Storage, path string, serverURL string) error {
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(a.Key)
	if err != nil {
		return err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	storageEntry, err := logical.StorageEntryJSON(path, map[string]interface{}{
		"server_url":              serverURL,
		"registration_uri":        a.Registration.URI,
		"contact":                 a.GetEmail(),
		"terms_of_service_agreed": a.TermsOfServiceAgreed,
		"private_key":             string(pemEncoded),
		"key_type":                a.KeyType,
		"provider":                a.Provider,
		"provider_configuration":  a.ProviderConfiguration,
		"enable_http_01":          a.EnableHTTP01,
		"enable_tls_alpn_01":      a.EnableTLSALPN01,
		"dns_resolvers":           a.DNSResolvers,
		"ignore_dns_propagation":  a.IgnoreDNSPropagation,
	})
	if err != nil {
		return err
	}

	return storage.Put(ctx, storageEntry)
}
