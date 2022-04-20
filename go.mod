module github.com/remilapeyre/vault-acme

go 1.16

require (
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/dnaeon/go-vcr v1.0.1 // indirect
	github.com/frankban/quicktest v1.4.1 // indirect
	github.com/go-acme/lego/v3 v3.9.0
	github.com/go-test/deep v1.0.2 // indirect
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-immutable-radix v1.1.0 // indirect
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/vault/api v1.0.5-0.20190909201928-35325e2c3262
	github.com/hashicorp/vault/sdk v0.1.14-0.20190909201848-e0fbf9b652e2
	github.com/mitchellh/mapstructure v1.3.1
	github.com/pierrec/lz4 v2.2.6+incompatible // indirect
	github.com/remilapeyre/vault-acme/acme/sidecar v0.0.0
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.6.1
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad // indirect
)

replace github.com/remilapeyre/vault-acme/acme/sidecar v0.0.0 => ./acme/sidecar

replace github.com/go-acme/lego/v3 v3.9.0 => github.com/remilapeyre/lego/v3 v3.1.1-0.20210516131909-f8231b178deb
