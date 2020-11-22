package acme

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"encoding/pem"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

func getCertFromACMEProvider(ctx context.Context, logger log.Logger, req *logical.Request, a *account, names []string) (*certificate.Resource, error) {
	client, err := a.getClient()
	if err != nil {
		return nil, err
	}

	err = setupChallengeProviders(ctx, logger, client, a, req)
	if err != nil {
		logger.Error("Failed to setup challenge provider")
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: names,
		Bundle:  true,
	}

	return client.Certificate.Obtain(request)
}

func signCertFromACMEProvider(ctx context.Context, logger log.Logger, req *logical.Request, a *account, names []string, csrBytes []byte) (*certificate.Resource, error) {
	client, err := a.getClient()
	if err != nil {
		return nil, err
	}

	err = setupChallengeProviders(ctx, logger, client, a, req)
	if err != nil {
		return nil, err
	}

	logger.Debug("Creating cert request")
	csrBlock, _ := pem.Decode(csrBytes)

	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate request")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, err
	}

	logger.Debug("obtaining cert")
	return client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:    csr,
		Bundle: true,
	})
}

func setupChallengeProviders(ctx context.Context, logger log.Logger, client *lego.Client, a *account, req *logical.Request) error {
	// DNS-01
	if a.Provider != "" {
		provider, err := dns.NewDNSChallengeProviderByName(a.Provider)
		if err != nil {
			return err
		}

		nameServer := os.Getenv("LEGO_TEST_NAMESERVER")
		isTesting := nameServer != ""
		err = client.Challenge.SetDNS01Provider(provider,
			dns01.CondOption(isTesting, dns01.AddRecursiveNameservers([]string{nameServer})),
			dns01.CondOption(a.IgnoreDNSPropagation || isTesting, dns01.DisableCompletePropagationRequirement()))
		if err != nil {
			return err
		}
	}

	// HTTP-01
	if a.EnableHTTP01 {
		provider := newVaultHTTP01Provider(ctx, logger, req)
		err := client.Challenge.SetHTTP01Provider(provider)
		if err != nil {
			return err
		}
	}

	// TLS-ALPN-01
	if a.EnableTLSALPN01 {
		provider := newVaultTLSALPN01Provider(ctx, logger, req)
		err := client.Challenge.SetTLSALPN01Provider(provider)
		if err != nil {
			return err
		}
	}

	return nil
}
