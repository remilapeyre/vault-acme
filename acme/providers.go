package acme

import (
	"context"
	"fmt"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

type vaultProvider struct {
	storage logical.Storage
	ctx     context.Context
	logger  log.Logger
	getPath func(string, string, string) string
}

func newVaultHTTP01Provider(ctx context.Context, logger log.Logger, req *logical.Request) vaultProvider {
	return vaultProvider{
		storage: req.Storage,
		ctx:     ctx,
		logger:  logger,
		getPath: func(domain, token, keyAuth string) string {
			return fmt.Sprintf("challenges/http-01/%s", token)
		},
	}
}

func newVaultTLSALPN01Provider(ctx context.Context, logger log.Logger, req *logical.Request) vaultProvider {
	return vaultProvider{
		storage: req.Storage,
		ctx:     ctx,
		logger:  logger,
		getPath: func(domain, token, keyAuth string) string {
			return fmt.Sprintf("challenges/tls-alpn-01/%s", domain)
		},
	}
}

func (p vaultProvider) Present(domain, token, keyAuth string) error {
	path := p.getPath(domain, token, keyAuth)
	storageEntry, err := logical.StorageEntryJSON(path, map[string]interface{}{
		"domain": domain,
		"key":    keyAuth,
	})
	if err != nil {
		return fmt.Errorf("failed to create storage entry: %v", err)
	}
	p.logger.Debug("Saving token", "path", storageEntry.Key)
	return p.storage.Put(p.ctx, storageEntry)
}

func (p vaultProvider) CleanUp(domain, token, keyAuth string) error {
	path := p.getPath(domain, token, keyAuth)
	p.logger.Debug("Deleting token", "path", path)
	return p.storage.Delete(p.ctx, path)
}
