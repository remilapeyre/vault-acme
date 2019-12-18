package acme

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestCache(t *testing.T) {
	config, b := getTestConfig(t)
	createAccount(t, b, config.StorageView)
	createRole(t, b, config.StorageView)

	checkCreatingCerts(t, b, config.StorageView)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cache",
		Storage:   config.StorageView,
	}
	resp := makeRequest(t, b, req, "")
	if resp.Data["cached_certs"] != 2 {
		t.Fatalf("bad number of cached certs: %d", resp.Data["cached_certs"])
	}

	req.Operation = logical.DeleteOperation
	makeRequest(t, b, req, "")

	req.Operation = logical.ReadOperation
	resp = makeRequest(t, b, req, "")

	if resp.Data["cached_certs"] != 0 {
		t.Fatalf("bad number of cached certs: %d", resp.Data["cached_certs"])
	}
}
