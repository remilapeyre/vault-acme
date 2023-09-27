module github.com/remilapeyre/vault-acme

go 1.16

require (
	github.com/go-acme/lego/v4 v4.14.2
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/vault/api v1.10.0
	github.com/hashicorp/vault/sdk v0.10.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/remilapeyre/vault-acme/acme/sidecar v0.0.0
	github.com/stretchr/testify v1.8.4
)

replace github.com/remilapeyre/vault-acme/acme/sidecar v0.0.0 => ./acme/sidecar
