package acme

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hashicorp/vault/sdk/logical"
)

const cachePrefix = "cache/"

type Cache struct {
	*sync.Mutex
}

func NewCache() *Cache {
	return &Cache{
		&sync.Mutex{},
	}
}

type CacheEntry struct {
	Users   int
	Account string

	// We have to copy all fields of the cert here as the []byte ones are not
	// exported in certificate.Resource
	Domain            string
	CertURL           string
	CertStableURL     string
	PrivateKey        []byte
	Cert              []byte
	IssuerCertificate []byte
	CSR               []byte
}

func NewCacheEntry(account string, cert *certificate.Resource) *CacheEntry {
	return &CacheEntry{
		Users:             1,
		Account:           account,
		Domain:            cert.Domain,
		CertURL:           cert.CertURL,
		CertStableURL:     cert.CertStableURL,
		PrivateKey:        cert.PrivateKey,
		Cert:              cert.Certificate,
		IssuerCertificate: cert.IssuerCertificate,
		CSR:               cert.CSR,
	}
}

func (ce *CacheEntry) Certificate() *certificate.Resource {
	return &certificate.Resource{
		Domain:            ce.Domain,
		CertURL:           ce.CertURL,
		CertStableURL:     ce.CertStableURL,
		PrivateKey:        ce.PrivateKey,
		Certificate:       ce.Cert,
		IssuerCertificate: ce.IssuerCertificate,
		CSR:               ce.CSR,
	}
}

func (ce *CacheEntry) Save(ctx context.Context, storage logical.Storage, key string) error {
	storageEntry, err := logical.StorageEntryJSON(key, ce)
	if err != nil {
		return fmt.Errorf("failed to create cache entry: %v", err)
	}
	return storage.Put(ctx, storageEntry)
}

func (ce *CacheEntry) IsExpired(role *role) (bool, error) {
	cert := ce.Certificate()

	// We have a certificate, we must now check wether the entry is stale in
	// which case we can remove it and ask a new certificate.
	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		return false, err
	}

	notAfter := certs[0].NotAfter
	certTTL := notAfter.Sub(certs[0].NotBefore).Seconds()
	remaining := time.Until(notAfter).Seconds()

	if remaining < float64(role.CacheForRatio)*certTTL/100 {
		return true, nil
	}

	return false, nil
}

func (c *Cache) List(ctx context.Context, storage logical.Storage) ([]string, error) {
	return storage.List(ctx, cachePrefix)
}

func (c *Cache) Create(ctx context.Context, storage logical.Storage, role *role, key string, cert *certificate.Resource) error {
	ce := NewCacheEntry(role.Account, cert)
	return ce.Save(ctx, storage, key)
}

func (c *Cache) GetCacheEntry(ctx context.Context, storage logical.Storage, key string) (*CacheEntry, error) {
	storageEntry, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, nil
	}

	// Something was found in the cache
	ce := &CacheEntry{}
	err = storageEntry.DecodeJSON(ce)
	if err != nil {
		return nil, err
	}

	return ce, nil
}

func (c *Cache) Read(ctx context.Context, storage logical.Storage, role *role, key string) (*CacheEntry, error) {
	ce, err := c.GetCacheEntry(ctx, storage, key)
	if err != nil {
		return nil, err
	}

	if ce == nil {
		return nil, nil
	}

	// Before returning this entry, we have to make sure it is not stale
	if role != nil {
		isExpired, err := ce.IsExpired(role)
		if err != nil {
			return nil, err
		}

		if isExpired {
			// We can drop this entry from the cache since it won't be used anymore
			err = c.Delete(ctx, storage, key)
			return nil, err
		}

		ce.Users++
		err = ce.Save(ctx, storage, key)
		if err != nil {
			return nil, err
		}
	}

	return ce, nil
}

func (c *Cache) Delete(ctx context.Context, storage logical.Storage, key string) error {
	return storage.Delete(ctx, key)
}

func (c *Cache) Clear(ctx context.Context, storage logical.Storage) error {
	keys, err := c.List(ctx, storage)
	if err != nil {
		return err
	}

	for _, key := range keys {
		err = c.Delete(ctx, storage, cachePrefix+key)
		if err != nil {
			return err
		}
	}

	return nil
}
