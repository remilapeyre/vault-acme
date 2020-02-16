module github.com/remilapeyre/vault-acme

go 1.13

require (
	github.com/Azure/go-autorest v12.2.0+incompatible
	github.com/akamai/AkamaiOPEN-edgegrid-golang v0.9.0
	github.com/go-acme/lego v2.7.2+incompatible // indirect
	github.com/go-acme/lego/v3 v3.3.0
	github.com/hashicorp/consul/api v1.2.0 // indirect
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/vault v1.2.3 // indirect
	github.com/hashicorp/vault/api v1.0.5-0.20190909201928-35325e2c3262
	github.com/hashicorp/vault/sdk v0.1.14-0.20190909201848-e0fbf9b652e2
	github.com/mitchellh/mapstructure v1.1.2
	github.com/remilapeyre/vault-acme/acme/sidecar v0.0.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
)

replace github.com/remilapeyre/vault-acme/acme/sidecar v0.0.0 => ./acme/sidecar

replace github.com/go-acme/lego/v3 v3.3.0 => github.com/remilapeyre/lego/v3 v3.1.1-0.20200221221332-68d344309859
