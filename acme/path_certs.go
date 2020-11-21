package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"log"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCerts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:     framework.TypeString,
				Required: true,
			},
			"common_name": {
				Type:     framework.TypeString,
				Required: true,
			},
			"alt_names": {
				Type: framework.TypeCommaStringSlice,
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.certCreate,
		},
	}
}

func pathSign(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("role"),

		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:     framework.TypeString,
				Required: true,
			},
			"csr": {
				Type:        framework.TypeString,
				Description: `PEM-format CSR to be signed.`,
				Required: true,
			},

			"common_name": {
				Type: framework.TypeString,
				Description: `The requested common name; if you want more than
one, specify the alternative names in the
alt_names map. If email protection is enabled
in the role, this may be an email address.`,
			},

			"alt_names": {
				Type: framework.TypeCommaStringSlice,
				Description: `The requested Subject Alternative Names, if any,
in a comma-delimited list. If email protection
is enabled for the role, this may contain
email addresses.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "DNS/Email Subject Alternative Names (SANs)",
				},
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.certSign,
		},
	}

	return ret
}

func (b *backend) certSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}

	names := getNames(data)
	csr := []byte(data.Get("csr").(string))

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
	a, err := getAccount(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}
	// Lookup cache
	cacheKey, err := getCacheKey(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache key: %v", err)
	}

	var cert *certificate.Resource

	cert, err = signCertFromACMEProvider(ctx, b.Logger(), req, a, names, csr)
	if err != nil {
		return logical.ErrorResponse("Failed to validate certificate signing request."), err
	}
	// Save the cert in the cache for the next request
	if !r.DisableCache {
		err = b.cache.Create(ctx, req.Storage, r, cacheKey, cert)
		if err != nil {
			return nil, err
		}
	}

	s, err := b.getSecret(path, cacheKey, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create the secret: %v", err)
	}

	return s, nil
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
	a, err := getAccount(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}
	// Lookup cache
	cacheKey, err := getCacheKey(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache key: %v", err)
	}

	var cert *certificate.Resource

	// Let's first check the cache to see if a cert already exists
	if !r.DisableCache {
		b.cache.Lock()
		defer b.cache.Unlock()
		b.Logger().Debug("Look in the cache for a saved cert")
		ce, err := b.cache.Read(ctx, req.Storage, r, cacheKey)
		if err != nil {
			return nil, err
		}
		if ce == nil {
			b.Logger().Debug("Certificate not found in the cache")
		} else {
			cert = ce.Certificate()
		}
	}

	// If we did not find a cert, we have to request one
	if cert == nil {
		b.Logger().Debug("Contacting the ACME provider to get a new certificate")
		cert, err = getCertFromACMEProvider(ctx, b.Logger(), req, a, names)
		if err != nil {
			b.Logger().Error("Error: %+v", err)
			return logical.ErrorResponse("Failed to validate certificate signing request."), err
		}
		// Save the cert in the cache for the next request
		if !r.DisableCache {
			err = b.cache.Create(ctx, req.Storage, r, cacheKey, cert)
			if err != nil {
				return nil, err
			}
		}
	}

	s, err := b.getSecret(path, cacheKey, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create the secret: %v", err)
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

	return cachePrefix + string(rolePath) + string(dataPath), nil
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
			"cert":      string(cert.Certificate),
			"url":       cert.CertStableURL,
			"cache_key": cacheKey,
		})

	s.Secret.MaxTTL = notAfter.Sub(time.Now())

	return s, nil
}

func getNames(data *framework.FieldData) []string {
	log.Printf("Getting alt_names")
	altNames := data.Get("alt_names").([]string)
	log.Printf("Make names")
	names := make([]string, len(altNames)+1)
	log.Printf("Get CN")
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
