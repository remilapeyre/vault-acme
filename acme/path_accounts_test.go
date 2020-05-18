package acme

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestAccounts(t *testing.T) {
	config, b := getTestConfig(t)

	data := map[string]interface{}{
		"server_url":              serverURL,
		"contact":                 "remi@lenstra.fr",
		"terms_of_service_agreed": true,
		"provider":                "exec",
	}
	expected := map[string]interface{}{
		"contact":                 "remi@lenstra.fr",
		"server_url":              serverURL,
		"terms_of_service_agreed": true,
		"provider":                "exec",
		"key_type":                "EC256",
		"enable_http_01":          false,
		"enable_tls_alpn_01":      false,
	}

	testCases := []struct {
		keyTypeIn  string
		keyTypeOut string
	}{
		{
			"",
			"EC256",
		},
		{
			"EC256",
			"EC256",
		},
		{
			"EC384",
			"EC384",
		},
		{
			"RSA2048",
			"RSA2048",
		},
		{
			"RSA4096",
			"RSA4096",
		},
		{
			"RSA8192",
			"RSA8192",
		},
	}

	for _, tc := range testCases {
		if tc.keyTypeIn == "" {
			delete(data, "key_type")
		} else {
			data["key_type"] = tc.keyTypeIn
		}
		expected["key_type"] = tc.keyTypeOut

		// Create account
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "accounts/lenstra",
			Storage:   config.StorageView,
			Data:      data,
		}
		resp := makeRequest(t, b, req, "")

		delete(resp.Data, "registration_uri")
		require.Equal(t, expected, resp.Data)

		// Read account
		req.Operation = logical.ReadOperation
		resp = makeRequest(t, b, req, "")
		delete(resp.Data, "registration_uri")
		require.Equal(t, expected, resp.Data)

		// Delete account
		req.Operation = logical.ReadOperation
		makeRequest(t, b, req, "")
	}

	// Unsupported key type
	data["key_type"] = "foo"
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   config.StorageView,
		Data:      data,
	}
	makeRequest(t, b, req, `"foo" is not a supported key type`)
}

func TestDeleteAccount(t *testing.T) {
	config, b := getTestConfig(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":              serverURL,
			"contact":                 "remi@lenstra.fr",
			"terms_of_service_agreed": true,
			"provider":                "exec",
		},
	}
	makeRequest(t, b, req, "")

	req.Operation = logical.DeleteOperation
	makeRequest(t, b, req, "")
	makeRequest(t, b, req, "This account does not exists")

	req.Operation = logical.ReadOperation
	makeRequest(t, b, req, "This account does not exists")
}
