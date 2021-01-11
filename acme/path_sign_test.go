package acme

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestSign(t *testing.T) {
	config, b := getTestConfig(t)
	createAccount(t, b, config.StorageView)
	createRole(t, b, config.StorageView)

	request := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/lenstra.fr",
		Storage:   config.StorageView,
		Data:      map[string]interface{}{"common_name": "sentry.lenstra.fr"},
	}
	makeRequest(t, b, request, "")
}
