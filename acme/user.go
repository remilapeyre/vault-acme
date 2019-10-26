package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/hashicorp/vault/sdk/logical"
)

type user struct {
	Email                string
	Registration         *registration.Resource
	Key                  *ecdsa.PrivateKey
	ServerURL            string
	Provider             string
	TermsOfServiceAgreed bool
}

// GetEmail returns the Email of the user
func (u *user) GetEmail() string {
	return u.Email
}

// GetRegistration returns the Email of the user
func (u *user) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the private key of the user
func (u *user) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func (u *user) getClient() (*lego.Client, error) {
	config := lego.NewConfig(u)
	config.CADirURL = u.ServerURL

	return lego.NewClient(config)
}

func getUser(ctx context.Context, storage logical.Storage, path string) (*user, error) {
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
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &user{
		Email: d["contact"].(string),
		Key:   privateKey,
		Registration: &registration.Resource{
			URI: d["registration_uri"].(string),
		},
		ServerURL:            d["server_url"].(string),
		Provider:             d["provider"].(string),
		TermsOfServiceAgreed: d["terms_of_service_agreed"].(bool),
	}, nil
}

func (u *user) save(ctx context.Context, storage logical.Storage, path string, serverURL string) error {
	x509Encoded, err := x509.MarshalECPrivateKey(u.Key)
	if err != nil {
		return err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	storageEntry, err := logical.StorageEntryJSON(path, map[string]interface{}{
		"server_url":              serverURL,
		"registration_uri":        u.Registration.URI,
		"contact":                 u.GetEmail(),
		"terms_of_service_agreed": u.TermsOfServiceAgreed,
		"private_key":             string(pemEncoded),
		"provider":                u.Provider,
	})
	if err != nil {
		return err
	}

	return storage.Put(ctx, storageEntry)
}
