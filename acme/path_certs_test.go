package acme

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestCerts(t *testing.T) {
	config, b := getTestConfig(t)
	createAccount(t, b, config.StorageView)
	createRole(t, b, config.StorageView)

	t.Log("Try to request certificates")
	firstCert, secondCert := checkCreatingCerts(t, b, config.StorageView)

	// Try to run an HTTPS server with the certificate we got and query it
	checkCertificate(t, firstCert)

	t.Log("Try to renew the lease")
	checkRenewingCert(t, b, config.StorageView, firstCert.Secret)

	t.Log("Try to revoke the lease")
	checkRevokeCert(t, b, config.StorageView, firstCert, secondCert)
}

func TestExplicitProviderConfiguration(t *testing.T) {
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
			"provider_configuration": map[string]string{
				// We use a bad configuration on purpose so we get a failure
				// when requesting a certificate instead of the success we got
				// in the previous test
				"EXEC_PATH": "/dev/null",
			},
		},
	}
	makeRequest(t, b, req, "")
	createRole(t, b, config.StorageView)

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "certs/lenstra.fr",
		Storage:   config.StorageView,
		Data:      map[string]interface{}{"common_name": "sentry.lenstra.fr"},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err, "fork/exec /dev/null: permission denied")
	require.Equal(t, resp.Data, map[string]interface{}{
		"error": "Failed to validate certificate signing request: error: one or more domains had a problem:\n[sentry.lenstra.fr] [sentry.lenstra.fr] acme: error presenting token: fork/exec /dev/null: permission denied\n",
	})
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
		"common_name":       "sentry.lenstra.fr",
		"alternative_names": "grafana.lenstra.fr",
	}
	first := makeRequest(t, b, certReq, "")
	second := makeRequest(t, b, certReq, "")

	// Since caching is enabled, we should get the same cert when calling the
	// endoint twice
	require.Equal(t, first.Data, second.Data)

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
	a, err := getAccount(context.Background(), storage, "accounts/lenstra")
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		t.Fatal("Account should have been found")
	}
	client, err := a.getClient()
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
	if err.Error() != "Get \"https://example.com\": x509: certificate is valid for sentry.lenstra.fr, grafana.lenstra.fr, not example.com" && err.Error() != `Get "https://example.com": x509: “sentry.lenstra.fr” certificate is not standards compliant` {
		t.Fatalf("Got wrong error: %s", err.Error())
	}

	HTTPResp, err := http.Get("https://sentry.lenstra.fr")
	if err != nil {
		// This is expected as the intermediate test cert may not be installed
		if err.Error() != "Get \"https://sentry.lenstra.fr\": x509: certificate signed by unknown authority" && err.Error() != `Get "https://sentry.lenstra.fr": x509: “sentry.lenstra.fr” certificate is not standards compliant` {
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
