package test

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestVault(t *testing.T) {
	config := api.DefaultConfig()
	config.Address = "http://127.0.0.1:8200"
	client, err := api.NewClient(config)
	require.NoError(t, err)
	client.SetToken("foo")

	logical := client.Logical()
	b, err := ioutil.ReadFile("../build/acme")
	require.NoError(t, err)
	sum := sha256.Sum256(b)

	_, err = logical.Write(
		"sys/plugins/catalog/secret/acme",
		map[string]interface{}{
			"sha256":  fmt.Sprintf("%x", sum),
			"command": "acme",
		},
	)
	require.NoError(t, err)

	// Enable the ACME secret engine
	_, err = logical.Write(
		"sys/mounts/acme",
		map[string]interface{}{
			"type": "acme",
		},
	)
	require.NoError(t, err)

	// Create an account
	created, err := logical.Write(
		"acme/accounts/lenstra",
		map[string]interface{}{
			"contact":                 "rem@lenstra.fr",
			"server_url":              "https://localhost:14000/dir",
			"terms_of_service_agreed": true,
			"provider":                "exec",
		},
	)
	require.NoError(t, err)

	// Update the account
	updated, err := logical.Write(
		"acme/accounts/lenstra",
		map[string]interface{}{
			"contact":                 "remi@lenstra.fr",
			"server_url":              "https://localhost:14000/dir",
			"terms_of_service_agreed": true,
			"provider":                "exec",
		},
	)
	require.NoError(t, err)

	require.Equal(t, created.Data["registration_uri"], updated.Data["registration_uri"])

	// Create a role
	_, err = logical.Write(
		"acme/roles/lenstra.fr",
		map[string]interface{}{
			"account":            "lenstra",
			"allowed_domains":    "lenstra.fr",
			"allow_bare_domains": false,
			"allow_subdomains":   true,
		},
	)
	require.NoError(t, err)

	// Request a certificate
	_, err = logical.Write(
		"acme/certs/lenstra.fr",
		map[string]interface{}{
			"common_name": "www.lenstra.fr",
		},
	)
	require.NoError(t, err)

	// Request another certificate and revoke it
	secret, err := logical.Write(
		"acme/certs/lenstra.fr",
		map[string]interface{}{
			"common_name": "lease.lenstra.fr",
		},
	)
	require.NoError(t, err)
	url := secret.Data["url"].(string)
	status := getCertificateStatus(t, url)
	require.Equal(t, "Valid", status)

	_, err = logical.Write(
		"sys/leases/revoke",
		map[string]interface{}{
			"lease_id": secret.LeaseID,
		},
	)
	require.NoError(t, err)
	status = getCertificateStatus(t, url)
	require.Equal(t, "Revoked", status)

	// Getting a new cert should not take it from the cache
	secret, err = logical.Write(
		"acme/certs/lenstra.fr",
		map[string]interface{}{
			"common_name": "lease.lenstra.fr",
		},
	)
	require.NoError(t, err)
	require.NotEqual(t, url, secret.Data["url"].(string))
	status = getCertificateStatus(t, secret.Data["url"].(string))
	require.Equal(t, "Valid", status)
}

func getCertificateStatus(t *testing.T, url string) string {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	url = strings.ReplaceAll(url, "14000/certZ", "15000/cert-status-by-serial")

	resp, err := http.Get(url)
	require.NoError(t, err)

	var data map[string]interface{}
	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(b, &data)
	require.NoError(t, err)

	return data["Status"].(string)
}
