package acme

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/exec"
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
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: names,
		Bundle:  true,
	}

	return client.Certificate.Obtain(request)
}

func setupChallengeProviders(ctx context.Context, logger log.Logger, client *lego.Client, a *account, req *logical.Request) error {
	// DNS-01
	if a.Provider != "" {
		var provider challenge.Provider
		var err error
		switch a.Provider {
		case "exec":
			config := exec.NewDefaultConfig()
			values, err := env.Get(exec.EnvPath)
			if err != nil {
				return fmt.Errorf("exec: %w", err)
			}

			config.Program = values[exec.EnvPath]
			config.Mode = os.Getenv(exec.EnvMode)

			if a.ProviderConfiguration[exec.EnvMode] != "" {
				config.Mode = a.ProviderConfiguration[exec.EnvMode]
			}
			if a.ProviderConfiguration[exec.EnvPath] != "" {
				config.Program = a.ProviderConfiguration[exec.EnvPath]
			}
			if a.ProviderConfiguration[exec.EnvPropagationTimeout] != "" {
				dur, err := time.ParseDuration(a.ProviderConfiguration[exec.EnvPropagationTimeout])
				if err != nil {
					return fmt.Errorf("failed to parse '%s': %w", exec.EnvPropagationTimeout, err)
				}
				config.PropagationTimeout = dur
			}
			if a.ProviderConfiguration[exec.EnvPollingInterval] != "" {
				dur, err := time.ParseDuration(a.ProviderConfiguration[exec.EnvPollingInterval])
				if err != nil {
					return fmt.Errorf("failed to parse '%s': %w", exec.EnvPollingInterval, err)
				}
				config.PollingInterval = dur
			}
			if a.ProviderConfiguration[exec.EnvSequenceInterval] != "" {
				dur, err := time.ParseDuration(a.ProviderConfiguration[exec.EnvSequenceInterval])
				if err != nil {
					return fmt.Errorf("failed to parse '%s': %w", exec.EnvSequenceInterval, err)
				}
				config.SequenceInterval = dur
			}

			provider, err = exec.NewDNSProviderConfig(config)
			if err != nil {
				return err
			}
		case "cloudflare":
			config := cloudflare.NewDefaultConfig()
			if a.ProviderConfiguration["CLOUDFLARE_EMAIL"] != "" {
				config.AuthEmail = a.ProviderConfiguration["CF_API_EMAIL"]
			}
			if a.ProviderConfiguration["CF_API_EMAIL"] != "" {
				config.AuthEmail = a.ProviderConfiguration["CF_API_EMAIL"]
			}
			if a.ProviderConfiguration["CLOUDFLARE_API_KEY"] != "" {
				config.AuthKey = a.ProviderConfiguration["CLOUDFLARE_API_KEY"]
			}
			if a.ProviderConfiguration["CF_API_KEY"] != "" {
				config.AuthKey = a.ProviderConfiguration[""]
			}
			if a.ProviderConfiguration["CLOUDFLARE_DNS_API_TOKEN"] != "" {
				config.AuthToken = a.ProviderConfiguration["CLOUDFLARE_DNS_API_TOKEN"]
			}
			if a.ProviderConfiguration["CF_DNS_API_TOKEN"] != "" {
				config.AuthToken = a.ProviderConfiguration["CF_DNS_API_TOKEN"]
			}
			if a.ProviderConfiguration["CLOUDFLARE_ZONE_API_TOKEN"] != "" {
				config.ZoneToken = a.ProviderConfiguration["CLOUDFLARE_ZONE_API_TOKEN"]
			}
			if a.ProviderConfiguration["CF_ZONE_API_TOKEN"] != "" {
				config.ZoneToken = a.ProviderConfiguration["CF_ZONE_API_TOKEN"]
			}
			if a.ProviderConfiguration["CLOUDFLARE_HTTP_TIMEOUT"] != "" {
				dur, err := time.ParseDuration(a.ProviderConfiguration["CLOUDFLARE_HTTP_TIMEOUT"])
				if err != nil {
					return fmt.Errorf("failed to parse 'CLOUDFLARE_HTTP_TIMEOUT': %w", err)
				}
				config.HTTPClient.Timeout = dur
			}
			if a.ProviderConfiguration["CLOUDFLARE_POLLING_INTERVAL"] != "" {
				dur, err := time.ParseDuration(a.ProviderConfiguration["CLOUDFLARE_POLLING_INTERVAL"])
				if err != nil {
					return fmt.Errorf("failed to parse 'CLOUDFLARE_POLLING_INTERVAL': %w", err)
				}
				config.PollingInterval = dur
			}
			if a.ProviderConfiguration["CLOUDFLARE_PROPAGATION_TIMEOUT"] != "" {
				dur, err := time.ParseDuration(a.ProviderConfiguration["CLOUDFLARE_PROPAGATION_TIMEOUT"])
				if err != nil {
					return fmt.Errorf("failed to parse 'CLOUDFLARE_PROPAGATION_TIMEOUT': %w", err)
				}
				config.PropagationTimeout = dur
			}
			if a.ProviderConfiguration["CLOUDFLARE_TTL"] != "" {
				ttl, err := strconv.Atoi(a.ProviderConfiguration["CLOUDFLARE_TTL"])
				if err != nil {
					return fmt.Errorf("failed to parse 'CLOUDFLARE_TTL': %w", err)
				}
				config.TTL = ttl
			}

			provider, err = cloudflare.NewDNSProviderConfig(config)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("provider %s is not supported", a.Provider)
		}

		err = client.Challenge.SetDNS01Provider(
			provider,
			dns01.CondOption(len(a.DNSResolvers) > 0, dns01.AddRecursiveNameservers(a.DNSResolvers)),
			dns01.CondOption(a.IgnoreDNSPropagation, dns01.DisableCompletePropagationRequirement()),
		)
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
