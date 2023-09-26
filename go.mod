module github.com/remilapeyre/vault-acme

go 1.16

require (
	github.com/go-acme/lego/v3 v3.9.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/vault/api v1.10.0
	github.com/hashicorp/vault/sdk v0.10.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/remilapeyre/vault-acme/acme/sidecar v0.0.0
	github.com/stretchr/testify v1.8.3
)

replace github.com/remilapeyre/vault-acme/acme/sidecar v0.0.0 => ./acme/sidecar

replace github.com/go-acme/lego/v3 v3.9.0 => github.com/remilapeyre/lego/v3 v3.1.1-0.20210516131909-f8231b178deb
