package acme

import (
	"context"
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
			"alternate_names": &framework.FieldSchema{
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
			"account": path,
			"cert":    cert.Certificate,
		})

	s.Secret.MaxTTL = notAfter.Sub(time.Now())

	return s, nil
}

func getNames(data *framework.FieldData) []string {
	altNames := data.Get("alternate_names").([]string)
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
