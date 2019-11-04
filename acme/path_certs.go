package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/providers/dns"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCerts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "certs/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
			},
			"common_name": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
			},
			"alternative_names": &framework.FieldSchema{
				Type: framework.TypeCommaStringSlice,
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.certCreate,
		},
	}
}

func (b *backend) certCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}

	names := getNames(data)

	path := "roles/" + data.Get("role").(string)
	r, err := getRole(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return logical.ErrorResponse("This role does not exists."), nil
	}
	if err = validateNames(b, r, names); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	path = "accounts/" + r.Account
	u, err := getUser(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}

	// Let's first check the cache to see if a cert already exists
	if !r.DisableCache {
		// Lookup cache
		key, err := getCacheKey(r, data)
		if err != nil {
			return nil, fmt.Errorf("failed to get cache key: %v", err)
		}
		storageEntry, err := req.Storage.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		if storageEntry != nil {
			// Something was found in the cache
			var d map[string]interface{}
			storageEntry.DecodeJSON(&d)
			data := d["data"].(map[string]interface{})
			internalData := d["internal"].(map[string]interface{})

			// Check if the cached cert is stale
			layout := "2006-01-02 15:04:05.999999999 -0700 MST"
			notBefore, err := time.Parse(layout, data["not_before"].(string))
			if err != nil {
				return nil, fmt.Errorf("failed to parse not_before: %v", err)
			}
			notAfter, err := time.Parse(layout, data["not_after"].(string))
			if err != nil {
				return nil, fmt.Errorf("Failed to parse not_after: %v", err)
			}
			certTTL := notAfter.Sub(notBefore).Seconds()
			remaining := notAfter.Sub(time.Now()).Seconds()

			if remaining > float64(r.CacheForRatio)*certTTL/100 {
				b.Logger().Debug("Cached cert can be used")

				internalData["cert"] = []byte(internalData["cert"].(string))
				s := b.Secret(secretCertType).Response(data, internalData)
				s.Secret.MaxTTL = notAfter.Sub(time.Now())

				// I'm not sure how Vault handles concurrent requests and if
				// a lock should have been taken here
				users, err := d["users"].(json.Number).Int64()
				if err != nil {
					return nil, fmt.Errorf("failed to decode users: %v", err)
				}
				d["users"] = users + 1
				storageEntry, err = logical.StorageEntryJSON(key, d)
				if err != nil {
					return nil, fmt.Errorf("failed to create cache entry: %v", err)
				}
				err = req.Storage.Put(ctx, storageEntry)
				if err != nil {
					return nil, fmt.Errorf("failed to save cache entry: %v", err)
				}

				return s, nil
			}
			b.Logger().Debug("Cached cert cannot be used")
		}
	}

	client, err := u.getClient()

	provider, err := dns.NewDNSChallengeProviderByName(u.Provider)
	if err != nil {
		return nil, err
	}
	if err = client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: names,
		Bundle:  true,
	}

	b.Logger().Debug("Requesting certificate from CA")
	cert, err := client.Certificate.Obtain(request)
	b.Logger().Debug("Got response from CA", "err", err)
	if err != nil {
		return logical.ErrorResponse("Failed to validate certificate signing request."), nil
	}

	// Use the helper to create the secret
	key, err := getCacheKey(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache key: %v", err)
	}
	s, err := b.getSecret(path, key, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create the secret: %v", err)
	}

	// Save the cert to the cache
	if !r.DisableCache {
		data := map[string]interface{}{
			"users": 1,
			"data":  s.Data,
			"internal": map[string]interface{}{
				"cache_key": key,
				"account":   s.Secret.InternalData["account"],
				"url":       s.Secret.InternalData["url"],
				"cert":      s.Data["cert"],
			},
		}
		storageEntry, err := logical.StorageEntryJSON(key, data)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache entry: %v", err)
		}
		err = req.Storage.Put(ctx, storageEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to save cache entry: %v", err)
		}
	}

	return s, nil
}

func getCacheKey(r *role, data *framework.FieldData) (string, error) {
	rolePath, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("failed to marshall role: %v", err)
	}

	d := make(map[string]interface{})
	for key := range data.Schema {
		d[key] = data.Get(key)
	}
	dataPath, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("failed to marshall data: %v", err)
	}

	return string(rolePath) + string(dataPath), nil
}

func (b *backend) getSecret(accountPath, cacheKey string, cert *certificate.Resource) (*logical.Response, error) {
	// Use the helper to create the secret
	b.Logger().Debug("Preparing response")
	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		return nil, err
	}

	notBefore := certs[0].NotBefore
	notAfter := certs[0].NotAfter

	s := b.Secret(secretCertType).Response(
		map[string]interface{}{
			"domain":      cert.Domain,
			"url":         cert.CertStableURL,
			"private_key": string(cert.PrivateKey),
			"cert":        string(cert.Certificate),
			"issuer_cert": string(cert.IssuerCertificate),
			"not_before":  notBefore.String(),
			"not_after":   notAfter.String(),
		},
		// this will be used when revoking the certificate
		map[string]interface{}{
			"account":   accountPath,
			"cert":      cert.Certificate,
			"url":       cert.CertStableURL,
			"cache_key": cacheKey,
		})

	s.Secret.MaxTTL = notAfter.Sub(time.Now())

	return s, nil
}

func getNames(data *framework.FieldData) []string {
	altNames := data.Get("alternative_names").([]string)
	names := make([]string, len(altNames)+1)
	names[0] = data.Get("common_name").(string)
	for i, n := range altNames {
		names[i+1] = n
	}

	return names
}

func validateNames(b logical.Backend, r *role, names []string) error {
	b.Logger().Debug("Validate names", "role", r, "names", names)

	isSubdomain := func(domain, root string) bool {
		return strings.HasSuffix(domain, "."+root)
	}

	for _, name := range names {
		var valid bool
		for _, domain := range r.AllowedDomains {
			if (domain == name && r.AllowBareDomains) ||
				(isSubdomain(name, domain) && r.AllowSubdomains) {
				valid = true
			}
		}
		if !valid {
			return fmt.Errorf("'%s' is not an allowed domain", name)
		}
	}

	return nil
}
