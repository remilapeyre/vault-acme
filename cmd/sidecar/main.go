package main

import (
	"flag"
	"os"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/remilapeyre/acme/acme/sidecar"
)

func main() {
	http01Bind := flag.String("challenge-http-01-bind", "", "Address for the ACME HTTP-01 challenge.")
	tlsALPN01Bind := flag.String("challenge-tls-alpn-01-bind", "", "Address for the ACME TLS-ALPN-01 challenge.")
	address := flag.String("address", "", "Address of the Vault server. The default is https://127.0.0.1:8200. This can also be specified via the VAULT_ADDR environment variable.")
	caCert := flag.String("ca-cert", "", "Path on the local disk to a single PEM-encoded CA certificate to verify the Vault server's SSL certificate. This takes precedence over -ca-path. This can also be specified via the VAULT_CACERT environment variable.")
	caPath := flag.String("ca-path", "", "Path on the local disk to a directory of PEM-encoded CA certificates to verify the Vault server's SSL certificate. This can also be specified via the VAULT_CAPATH environment variable.")
	clientCert := flag.String("client-cert", "", "Path on the local disk to a single PEM-encoded CA certificate to use for TLS authentication to the Vault server. If this flag is specified, -client-key is also required. This can also be specified via the VAULT_CLIENT_CERT environment variable.")
	clientKey := flag.String("client-key", "", "Path on the local disk to a single PEM-encoded private key matching the client certificate from -client-cert. This can also be specified via the VAULT_CLIENT_KEY environment variable.")
	tlsServerName := flag.String("tls-server-name", "", "Name to use as the SNI host when connecting to the Vault server via TLS. This can also be specified via the VAULT_TLS_SERVER_NAME environment variable.")
	tlsSkipVerify := flag.Bool("tls-skip-verify", false, "Disable verification of TLS certificates. Using this option is highly discouraged as it decreases the security of data transmissions to and from the Vault server. The default is false. This can also be specified via the VAULT_SKIP_VERIFY environment variable.")

	flag.Parse()

	config := api.DefaultConfig()

	if *address != "" {
		config.Address = *address
	}

	tlsConfig := &api.TLSConfig{}
	if *caCert != "" {
		tlsConfig.CACert = *caCert
	}
	if *caPath != "" {
		tlsConfig.CAPath = *caPath
	}
	if *clientCert != "" {
		tlsConfig.ClientCert = *clientCert
	}
	if *clientKey != "" {
		tlsConfig.ClientKey = *clientKey
	}
	if *tlsServerName != "" {
		tlsConfig.TLSServerName = *tlsServerName
	}
	if *tlsSkipVerify {
		tlsConfig.Insecure = *tlsSkipVerify
	}

	logger := log.Default()

	err := config.ConfigureTLS(tlsConfig)
	if err != nil {
		logger.Error("Failed to configure TLS", "err", err)
		os.Exit(2)
	}

	client, err := api.NewClient(config)
	if err != nil {
		logger.Error("Failed to initialize Vault client", "err", err)
		os.Exit(2)
	}

	if *http01Bind == "" && *tlsALPN01Bind == "" {
		logger.Error("One of '-challenge-http-01-bind' or '-challenge-tls-alpn-01-bind' must be set")
		os.Exit(2)
	}

	logicalClient := client.Logical()

	if *http01Bind != "" {
		provider := sidecar.NewHTTP01Provider(logicalClient, logger)
		logger.Info("Starting HTTP-01 provider.")
		err = provider.Listen(*http01Bind)
		if err != nil {
			logger.Error("Failed to start HTTP-01 provider", "err", err)
			os.Exit(2)
		}
	}

	if *tlsALPN01Bind != "" {
		provider := sidecar.NewTLSALPN01Provider(logicalClient, logger)
		logger.Info("Starting TLS-ALPN-01 provider.")
		err = provider.Listen(*tlsALPN01Bind)
		if err != nil {
			logger.Error("Failed to start TLS-ALPN-01 provider", "err", err)
			os.Exit(2)
		}
	}

	// Wait forever
	select {}
}
