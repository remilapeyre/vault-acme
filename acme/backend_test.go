package acme

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/remilapeyre/vault-acme/acme/sidecar"
	"github.com/stretchr/testify/require"
)

func TestValidateNames(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	tcases := []struct {
		R        role
		Domain   []string
		Expected string
	}{
		{
			R:        role{Account: "account", AllowedDomains: []string{}, AllowBareDomains: false, AllowSubdomains: false},
			Domain:   []string{"lenstra.fr"},
			Expected: "'lenstra.fr' is not an allowed domain",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{}, AllowBareDomains: false, AllowSubdomains: false},
			Domain:   []string{""},
			Expected: "'' is not an allowed domain",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{"lenstra.fr"}, AllowBareDomains: false, AllowSubdomains: false},
			Domain:   []string{"sentry.lenstra.fr"},
			Expected: "'sentry.lenstra.fr' is not an allowed domain",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{"lenstra.fr"}, AllowBareDomains: false, AllowSubdomains: false},
			Domain:   []string{"lenstra.fr"},
			Expected: "'lenstra.fr' is not an allowed domain",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{"lenstra.fr"}, AllowBareDomains: true, AllowSubdomains: false},
			Domain:   []string{"sentry.lenstra.fr"},
			Expected: "'sentry.lenstra.fr' is not an allowed domain",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{"lenstra.fr"}, AllowBareDomains: true, AllowSubdomains: false},
			Domain:   []string{"lenstra.fr"},
			Expected: "",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{"lenstra.fr"}, AllowBareDomains: false, AllowSubdomains: true},
			Domain:   []string{"sentry.lenstra.fr"},
			Expected: "",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{"lenstra.fr"}, AllowBareDomains: true, AllowSubdomains: true},
			Domain:   []string{"sentry.lenstra.fr"},
			Expected: "",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{"lenstra.fr"}, AllowBareDomains: true, AllowSubdomains: true},
			Domain:   []string{"sentry.lenstra.fr", "grafana.lenstra.fr"},
			Expected: "",
		},
		{
			R:        role{Account: "account", AllowedDomains: []string{"lenstra.fr"}, AllowBareDomains: true, AllowSubdomains: true},
			Domain:   []string{"sentry.lenstra.fr", "foobar.fr"},
			Expected: "'foobar.fr' is not an allowed domain",
		},
	}

	for _, tc := range tcases {
		t.Run(fmt.Sprintf("%s: %#v", tc.Domain, tc.R), func(t *testing.T) {
			err := validateNames(b, &tc.R, tc.Domain)

			if err == nil && tc.Expected == "" {
				// That's OK
				return
			}
			if tc.Expected == "" && err != nil {
				t.Fatalf("Was not expecting error but got '%s'", err.Error())
			}
			if err == nil && tc.Expected != "" {
				t.Fatalf("Was expecting '%s' but didn't get an error", tc.Expected)
			}
			if err.Error() != tc.Expected {
				t.Fatalf("Was expecting '%s' but got '%s'", tc.Expected, err.Error())
			}
		})
	}

}

func getTestConfig(t *testing.T) (*logical.BackendConfig, logical.Backend) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Setenv("LEGO_TEST_NAMESERVER", "127.0.0.1:8053"); err != nil {
		t.Fatal(err)
	}
	if err = os.Setenv("EXEC_PROPAGATION_TIMEOUT", "5"); err != nil {
		t.Fatal(err)
	}
	if err = os.Setenv("EXEC_PATH", wd+"/../test/test_dns.sh"); err != nil {
		t.Fatal(err)
	}
	if err = os.Setenv("LEGO_CA_CERTIFICATES", wd+"/../test/certs/pebble.minica.pem"); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PEBBLE_VA_NOSLEEP", "1"); err != nil {
		t.Fatal(err)
	}

	peeble := exec.Command("pebble", "-dnsserver", "127.0.0.1:8053", "-config", "../test/config/pebble-config.json")
	peeble.Stdout = os.Stdout
	peeble.Stderr = os.Stderr
	if err := peeble.Start(); err != nil {
		t.Fatalf("failed to start pebble: %s", err)
	}
	t.Cleanup(func() {
		if err := peeble.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		peeble.Process.Wait()
	})

	challtestsrv := exec.Command("pebble-challtestsrv", "-http01", "", "-https01", "", "-tlsalpn01", "")
	challtestsrv.Stdout = os.Stdout
	challtestsrv.Stderr = os.Stderr
	if err := challtestsrv.Start(); err != nil {
		t.Fatalf("failed to start pebble-challtestsrv: %s", err)
	}
	t.Cleanup(func() {
		if err := challtestsrv.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		challtestsrv.Process.Wait()
	})
	time.Sleep(1 * time.Second)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	return config, b
}

func createAccount(t *testing.T, b logical.Backend, storage logical.Storage) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   storage,
		Data: map[string]interface{}{
			"server_url":              "https://localhost:14000/dir",
			"contact":                 "remi@lenstra.fr",
			"terms_of_service_agreed": true,
			"provider":                "exec",
		},
	}
	makeRequest(t, b, req, "")
}

func createRole(t *testing.T, b logical.Backend, storage logical.Storage) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/lenstra.fr",
		Storage:   storage,
		Data: map[string]interface{}{
			"account":          "lenstra",
			"allow_subdomains": true,
			"allowed_domains":  []string{"lenstra.fr"},
		},
	}
	makeRequest(t, b, req, "")
}

func createXipRole(t *testing.T, b logical.Backend, storage logical.Storage) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/xip.io",
		Storage:   storage,
		Data: map[string]interface{}{
			"account":          "lenstra",
			"allow_subdomains": true,
			"allowed_domains":  []string{"xip.io"},
		},
	}
	makeRequest(t, b, req, "")
}

func TestNoChallenge(t *testing.T) {
	config, b := getTestConfig(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":              "https://localhost:14000/dir",
			"contact":                 "remi@lenstra.fr",
			"terms_of_service_agreed": true,
		},
	}
	makeRequest(t, b, req, "")

	createRole(t, b, config.StorageView)

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "certs/lenstra.fr",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"common_name": "sentry.lenstra.fr",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatalf("Did not get error")
	}
	if !strings.Contains(err.Error(), "acme: could not determine solvers") {
		t.Fatalf("Error did not contain 'acme: could not determine solvers'")
	}
	if resp == nil {
		t.Fatalf("Did not get response")
	}
	if !resp.IsError() {
		t.Fatalf("Did not get error")
	}
	expected := "Failed to validate certificate signing request: error: one or more domains had a problem:\n[sentry.lenstra.fr] [sentry.lenstra.fr] acme: could not determine solvers\n"
	require.Equal(t, expected, resp.Error().Error())
}

func TestHTTP01Challenge(t *testing.T) {
	config, b := getTestConfig(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":              "https://localhost:14000/dir",
			"contact":                 "remi@lenstra.fr",
			"terms_of_service_agreed": true,
			"enable_http_01":          true,
		},
	}
	makeRequest(t, b, req, "")

	createXipRole(t, b, config.StorageView)

	mockClient := sidecar.NewMockClient(b, config.StorageView)
	provider := sidecar.NewHTTP01Provider(mockClient, b.Logger())

	// pebble uses the 5002 port
	go provider.Listen(":5002")

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "certs/xip.io",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"common_name": "127.0.0.1.xip.io",
		},
	}
	makeRequest(t, b, req, "")
}

func TestTLSALPN01Challenge(t *testing.T) {
	config, b := getTestConfig(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"server_url":              "https://localhost:14000/dir",
			"contact":                 "remi@lenstra.fr",
			"terms_of_service_agreed": true,
			"enable_tls_alpn_01":      true,
		},
	}
	makeRequest(t, b, req, "")

	createXipRole(t, b, config.StorageView)

	mockClient := sidecar.NewMockClient(b, config.StorageView)
	provider := sidecar.NewTLSALPN01Provider(mockClient, b.Logger())

	// pebble uses the 5001 port
	go provider.Listen(":5001")

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "certs/xip.io",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"common_name": "127.0.0.1.xip.io",
		},
	}
	makeRequest(t, b, req, "")
}

func TestRoles(t *testing.T) {
	config, b := getTestConfig(t)
	createAccount(t, b, config.StorageView)

	// Test creating roles
	testCases := []testCase{
		{
			RequestData:      map[string]interface{}{"account": "lenstra"},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": false, "allowed_domains": []string{}, "cache_for_ratio": 70, "disable_cache": false},
		},
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allowed_domains": "sentry.lenstra.fr"},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": false, "allowed_domains": []string{"sentry.lenstra.fr"}, "cache_for_ratio": 70, "disable_cache": false},
		},
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allow_bare_domains": true},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": true, "allow_subdomains": false, "allowed_domains": []string{}, "cache_for_ratio": 70, "disable_cache": false},
		},
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "cache_for_ratio": 50},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "cache_for_ratio": 50, "disable_cache": false},
		},
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "disable_cache": true},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "cache_for_ratio": 70, "disable_cache": true},
		},
	}
	for _, tcase := range testCases {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/lenstra.fr",
			Storage:   config.StorageView,
			Data:      tcase.RequestData,
		}
		resp := makeRequest(t, b, req, "")
		require.Equal(t, tcase.ExpectedResponse, resp.Data)
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/lenstra.fr",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"account":          "lenstra",
			"allow_subdomains": true,
			"allowed_domains":  []string{"lenstra.fr"},
		},
	}
	makeRequest(t, b, req, "")

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/lenstra.fr",
		Storage:   config.StorageView,
	}
	resp := makeRequest(t, b, req, "")
	require.Equal(
		t,
		resp.Data,
		map[string]interface{}{
			"account":            "lenstra",
			"allow_bare_domains": false,
			"allow_subdomains":   true,
			"allowed_domains":    []string{"lenstra.fr"},
			"cache_for_ratio":    70,
			"disable_cache":      false,
		},
	)

	// Delete role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/lenstra.fr",
		Storage:   config.StorageView,
	}
	makeRequest(t, b, req, "")

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/lenstra.fr",
		Storage:   config.StorageView,
	}
	makeRequest(t, b, req, "This role does not exists")
}

func makeRequest(t *testing.T, b logical.Backend, req *logical.Request, expectedError string) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to make request:\nreq:%#v\nresp:%#v\nerr:%s", req, resp, err)
	}
	if resp != nil && resp.IsError() && expectedError == "" {
		t.Fatalf("Was not expecting error but got '%s'", resp.Error().Error())
	}
	if expectedError != "" && !resp.IsError() {
		t.Fatalf("Was expecting error '%s' but did not get one", expectedError)
	}
	if resp != nil && resp.IsError() {
		err = resp.Error()
		if err.Error() != expectedError {
			t.Fatalf("Expected error '%s' but got '%s'", expectedError, err.Error())
		}
	}
	return resp
}

type testCase struct {
	Path             string
	RequestData      map[string]interface{}
	ExpectedResponse map[string]interface{}
	Error            string
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
