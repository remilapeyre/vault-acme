package sidecar

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
)

type client interface {
	Read(path string) (*api.Secret, error)
}

type MockClient struct {
	backend logical.Backend
	storage logical.Storage
}

// NewMockClient return a MockClient that can be used in tetss
func NewMockClient(b logical.Backend, storage logical.Storage) *MockClient {
	return &MockClient{
		backend: b,
		storage: storage,
	}
}

func (c MockClient) Read(path string) (*api.Secret, error) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   c.storage,
	}
	ctx := context.Background()
	resp, err := c.backend.HandleRequest(ctx, req)

	if resp == nil {
		return nil, err
	}
	return &api.Secret{
		Data: resp.Data,
	}, err
}

// Provider solves an ACME challenge
type Provider interface {
	Listen(addr string) error
}

type http01Provider struct {
	client client
	logger log.Logger
}

type acmeHandler struct {
	client client
}

func (a acmeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	path := fmt.Sprintf("challenges/http-01/%s", token)

	s, err := a.client.Read(path)
	if err != nil {
		fmt.Fprintf(w, "failed to read token: %s", err.Error())
	} else if err, ok := s.Data["error"]; ok {
		fmt.Fprintf(w, "failed to read token: %s", err)
	} else {
		headers := w.Header()
		headers.Set("host", s.Data["key"].(string))
		headers.Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		fmt.Fprintf(w, s.Data["key"].(string))
	}
}

// NewHTTP01Provider returns a provider that solves the HTTP-01 challenge
// defined in https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.8.3
func NewHTTP01Provider(client client, logger log.Logger) Provider {
	return http01Provider{
		client: client,
		logger: logger,
	}
}

func (p http01Provider) Listen(addr string) error {
	handler := acmeHandler{
		client: p.client,
	}
	http.Handle("/.well-known/acme-challenge/", handler)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("Failed to create listener: %v", err)
	}
	go http.Serve(listener, nil)

	return nil
}

func (p http01Provider) Close() error {
	return nil
}

type tlsALPN01Provider struct {
	client client
	logger log.Logger
}

// NewTLSALPN01Provider returns a provider that solves the TLS-ALPN-01 challenge
// defined in https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01
func NewTLSALPN01Provider(client client, logger log.Logger) Provider {
	return tlsALPN01Provider{
		client: client,
		logger: logger,
	}
}

func (p tlsALPN01Provider) Listen(addr string) error {
	tlsConfig := &tls.Config{
		NextProtos: []string{"acme-tls/1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			path := fmt.Sprintf("challenges/tls-alpn-01/%s", hello.ServerName)

			s, err := p.client.Read(path)
			if err != nil {
				p.logger.Error("failed to read token", "err", err)
				return nil, err
			}
			if err, ok := s.Data["error"]; ok {
				p.logger.Error(err.(string))
				return nil, fmt.Errorf("failed to read token: %s", err.(string))
			}

			if len(hello.SupportedProtos) != 1 || hello.SupportedProtos[0] != "acme-tls/1" {
				return nil, fmt.Errorf("the protocol is not correct")
			}

			return tlsalpn01.ChallengeCert(s.Data["domain"].(string), s.Data["key"].(string))
		},
	}

	p.logger.Info("Listening for TLS-ALPN-01 challenge", "addr", addr)
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				panic(err)
			}
			conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	return nil
}
