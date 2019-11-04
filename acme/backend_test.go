package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"
	"strings"

	"github.com/hashicorp/vault/sdk/logical"
)

var serverURL string

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

func TestBackend(t *testing.T) {
	serverURL = getEnv("TEST_SERVER_URL", "https://localhost:14000/dir")

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Try to create accounts")
	checkCreatingAccounts(t, b, serverURL, config.StorageView)

	t.Log("Try to read accounts")
	checkReadingAccount(t, b, config.StorageView)

	t.Log("Try to create roles")
	checkCreatingRoles(t, b, config.StorageView)

	t.Log("Try to request certificates")
	firstCert, secondCert := checkCreatingCerts(t, b, config.StorageView)

	// Try to run an HTTPS server with the certificate we got and query it
	checkCertificate(t, firstCert)

	t.Log("Try to renew the lease")
	checkRenewingCert(t, b, config.StorageView, firstCert.Secret)

	t.Log("Try to revoke the lease")
	checkRevokeCert(t, b, config.StorageView, firstCert, secondCert)

	t.Log("Try to delete the role")
	checkDeletingRole(t, b, config.StorageView)

	t.Log("Try to delete the account")
	checkDeletingAccounts(t, b, config.StorageView)
}

func checkCreatingAccounts(t *testing.T, b logical.Backend, serverURL string, storage logical.Storage) {
	accountData := map[string]interface{}{
		"server_url":              serverURL,
		"contact":                 "remi@lenstra.fr",
		"terms_of_service_agreed": true,
		"provider":                "doesnotexists",
	}

	accountReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "accounts/lenstra",
		Storage:   storage,
		Data:      accountData,
	}

	makeRequest(t, b, accountReq, "'doesnotexists' is not a supported provider.")
	accountReq.Data["provider"] = "cloudflare"
	makeRequest(t, b, accountReq, "")

	accountReq.Operation = logical.ReadOperation
	resp := makeRequest(t, b, accountReq, "")
	delete(resp.Data, "registration_uri")

	expected := map[string]interface{}{
		"contact":                 "remi@lenstra.fr",
		"server_url":              serverURL,
		"terms_of_service_agreed": true,
		"provider":                "cloudflare",
	}
	assertEqual(t, expected, resp.Data)
}

func checkReadingAccount(t *testing.T, b logical.Backend, storage logical.Storage) {
	accountReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "accounts/lenstra",
		Storage:   storage,
	}
	resp := makeRequest(t, b, accountReq, "")
	delete(resp.Data, "registration_uri")
	assertEqual(
		t,
		map[string]interface{}{
			"contact":                 "remi@lenstra.fr",
			"provider":                "cloudflare",
			"server_url":              serverURL,
			"terms_of_service_agreed": true,
		},
		resp.Data,
	)
}

func checkDeletingAccounts(t *testing.T, b logical.Backend, storage logical.Storage) {
	accountReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "accounts/lenstra",
		Storage:   storage,
	}
	makeRequest(t, b, accountReq, "foo")

	accountReq.Operation = logical.ReadOperation
	makeRequest(t, b, accountReq, "This account does not exists")

	accountReq.Path = "accounts/bar"
	makeRequest(t, b, accountReq, "This account does not exists")
}

func checkCreatingRoles(t *testing.T, b logical.Backend, storage logical.Storage) {
	testCases := []testCase{
		{
			RequestData:      map[string]interface{}{"account": "lenstra"},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": false, "allowed_domains": []string(nil), "cache_for_ratio": 70, "disable_cache": false},
		},
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allowed_domains": "sentry.lenstra.fr"},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": false, "allowed_domains": []string{"sentry.lenstra.fr"}, "cache_for_ratio": 70, "disable_cache": false},
		},
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allow_bare_domains": true},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": true, "allow_subdomains": false, "allowed_domains": []string(nil), "cache_for_ratio": 70, "disable_cache": false},
		},
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "cache_for_ratio": 50},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "cache_for_ratio": 50, "disable_cache": false},
		},
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "disable_cache": true},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "cache_for_ratio": 70, "disable_cache": true},
		},
		// This one must be the last as the rest of the tests are using it
		{
			RequestData:      map[string]interface{}{"account": "lenstra", "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}},
			ExpectedResponse: map[string]interface{}{"account": "lenstra", "allow_bare_domains": false, "allow_subdomains": true, "allowed_domains": []string{"lenstra.fr"}, "cache_for_ratio": 70, "disable_cache": false},
		},
	}
	for _, tcase := range testCases {
		roleReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/lenstra.fr",
			Storage:   storage,
			Data:      tcase.RequestData,
		}
		resp := makeRequest(t, b, roleReq, "")
		assertEqual(t, tcase.ExpectedResponse, resp.Data)
	}
}

func checkCreatingCerts(t *testing.T, b logical.Backend, storage logical.Storage) (*logical.Response, *logical.Response) {
	certReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "certs/foo",
		Storage:   storage,
		Data:      map[string]interface{}{"common_name": "sentry.lenstra.fr"},
	}
	makeRequest(t, b, certReq, "This role does not exists.")

	// Try with an existing role
	certReq.Path = "certs/lenstra.fr"
	makeRequest(t, b, certReq, "")

	// Try with alternate names
	certReq.Data = map[string]interface{}{
		"common_name":     "sentry.lenstra.fr",
		"alternative_names": "grafana.lenstra.fr",
	}
	first := makeRequest(t, b, certReq, "")
	second := makeRequest(t, b, certReq, "")

	// Since caching is enabled, we should get the same cert when calling the
	// endoint twice
	assertEqual(t, first.Data, second.Data)

	return first, second
}

func checkRenewingCert(t *testing.T, b logical.Backend, storage logical.Storage, secret *logical.Secret) {
	certReq := &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "certs/lenstra.fr",
		Storage:   storage,
		Data:      map[string]interface{}{"common_name": "sentry.lenstra.fr"},
		Secret:    secret,
	}
	renewResp := makeRequest(t, b, certReq, "")

	if renewResp.Secret.TTL < secret.TTL {
		t.Fatalf("Failed to renew secret")
	}
}

func checkRevokeCert(t *testing.T, b logical.Backend, storage logical.Storage, first, second *logical.Response) {
	certReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "certs/lenstra.fr",
		Storage:   storage,
		Secret:    first.Secret,
	}
	makeRequest(t, b, certReq, "")

	certReq.Secret = second.Secret
	makeRequest(t, b, certReq, "")

	// Check the cert status
	u, err := getUser(context.Background(), storage, "accounts/lenstra")
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("User should have been found")
	}
	client, err := u.getClient()
	if err != nil {
		t.Fatal(err)
	}

	// Checking the OCSP status was not working for tests
	err = client.Certificate.Revoke([]byte(second.Data["cert"].(string)))
	if err == nil {
		t.Fatalf("Trying to revoke the cert should have failed")
	}
	if !strings.Contains(err.Error(), "Certificate has already been revoked.") {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func checkDeletingRole(t *testing.T, b logical.Backend, storage logical.Storage) {
	roleReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/lenstra.fr",
		Storage:   storage,
	}
	makeRequest(t, b, roleReq, "")
}

func checkCertificate(t *testing.T, resp *logical.Response) {
	mux := http.NewServeMux()
	mux.Handle(
		"/",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Hello world\n"))
		}),
	)
	server := &http.Server{Addr: ":4443", Handler: mux}

	config := &tls.Config{}
	config.NextProtos = []string{"http/1.1"}

	cert, err := tls.X509KeyPair(
		[]byte(resp.Data["cert"].(string)),
		[]byte(resp.Data["private_key"].(string)),
	)
	if err != nil {
		t.Fatal(err)
	}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = cert

	ln, err := net.Listen("tcp", "0.0.0.0:4443")
	if err != nil {
		t.Fatal(err)
	}

	tlsListener := tls.NewListener(ln.(*net.TCPListener), config)

	go func() {
		err := server.Serve(tlsListener)
		if err != nil {
			t.Fatal(err)
		}
	}()

	dialContext := http.DefaultTransport.(*http.Transport).DialContext

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "example.com:443" || addr == "sentry.lenstra.fr:443" {
			addr = "127.0.0.1:4443"
		}
		return dialer.DialContext(ctx, network, addr)
	}

	_, err = http.Get("https://example.com")
	if err == nil {
		t.Fatal("Was expecting error but got none.")
	}
	if err.Error() != "Get https://example.com: x509: certificate is valid for sentry.lenstra.fr, grafana.lenstra.fr, not example.com" {
		t.Fatalf("Got wrong error: %s", err.Error())
	}

	HTTPResp, err := http.Get("https://sentry.lenstra.fr")
	if err != nil {
		// This is expected as the intermediate test cert may not be installed
		if err.Error() != "Get https://sentry.lenstra.fr: x509: certificate signed by unknown authority" {
			t.Fatalf("%s", err.Error())
		}
	}
	if HTTPResp != nil {
		body, err := ioutil.ReadAll(HTTPResp.Body)
		if err != nil {
			t.Fatal(err)
		}
		expected := "Hello world\n"
		if string(body) != expected {
			t.Fatalf("Expected: '%s'\nGot: '%s'", expected, string(body))
		}
	}

	http.DefaultTransport.(*http.Transport).DialContext = dialContext
}

func makeRequest(t *testing.T, b logical.Backend, req *logical.Request, expectedError string) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to make request: resp:%#v err:%s", resp, err)
	}
	if resp != nil && resp.IsError() && expectedError == "" {
		t.Fatalf("Was not expecting error but got '%s'", resp.Error().Error())
	}
	if resp != nil && resp.IsError() {
		err = resp.Error()
		if err.Error() != expectedError {
			t.Fatalf("Expected error '%s' but got '%s'", expectedError, err.Error())
		}
	}
	return resp
}

func assertEqual(t *testing.T, expected, data map[string]interface{}) {
	if !reflect.DeepEqual(expected, data) {
		t.Fatalf("bad: expected:%#v\nactual:%#v\n", expected, data)
	}
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
