package acme

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestAccounts(t *testing.T) {
	config, b := getTestConfig(t)

	data := map[string]interface{}{
		"server_url":              "https://localhost:14000/dir",
		"contact":                 "remi@lenstra.fr",
		"terms_of_service_agreed": true,
		"provider":                "exec",
	}
	expected := map[string]interface{}{
		"contact":                 "remi@lenstra.fr",
		"server_url":              "https://localhost:14000/dir",
		"terms_of_service_agreed": true,
		"provider":                "exec",
		"provider_configuration":  map[string]string{},
		"key_type":                "EC256",
		"enable_http_01":          false,
		"enable_tls_alpn_01":      false,
		"ignore_dns_propagation":  false,
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
		req.Operation = logical.DeleteOperation
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

func TestUpdateAccount(t *testing.T) {
	config, b := getTestConfig(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":              "https://localhost:14000/dir",
			"contact":                 "rem@lenstra.fr",
			"terms_of_service_agreed": true,
			"provider":                "exec",
		},
	}
	created := makeRequest(t, b, req, "")

	req.Data["contact"] = "remi@lenstra.fr"
	req.Operation = logical.UpdateOperation
	updated := makeRequest(t, b, req, "")
	require.Equal(t, created.Data["registration_uri"], updated.Data["registration_uri"])
}

func TestDeleteAccount(t *testing.T) {
	config, b := getTestConfig(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":              "https://localhost:14000/dir",
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

func TestListAccounts(t *testing.T) {
	config, b := getTestConfig(t)

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "accounts",
		Storage:   config.StorageView,
	}
	listResp := makeRequest(t, b, listReq, "")
	require.Equal(t, map[string]interface{}{}, listResp.Data)

	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":              "https://localhost:14000/dir",
			"contact":                 "remi@lenstra.fr",
			"terms_of_service_agreed": true,
			"provider":                "exec",
		},
	}
	makeRequest(t, b, createReq, "")

	listResp = makeRequest(t, b, listReq, "")
	require.Equal(t, map[string]interface{}{
		"keys": []string{"lenstra"},
	}, listResp.Data)
}
