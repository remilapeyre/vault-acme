# Vault ACME

**This plugin has not been properly reviewed and should not be used in production.**

Vault ACME is a [Vault](https://www.vaultproject.io/) secret engine that allow
users and application to retrieve TLS certificates validated by an [ACME provider](https://tools.ietf.org/html/rfc8555)
like [Let's Encrypt](https://letsencrypt.org/) without having to give each
applications permission to modify DNS and using Vault's audit and policy systems.

Discussion: https://github.com/hashicorp/vault/issues/4950

## Download Vault ACME

Binary releases can be downloaded at https://github.com/remilapeyre/vault-acme/releases.

## Documentation

The documentation is available at [`website/source/docs/secrets/acme/index.html.md`](https://github.com/remilapeyre/vault-acme/blob/master/website/source/docs/secrets/acme/index.html.md).

## How to use this plugin

Using this plugin in Docker requires to manually set the `mlock` file capability
to both Vault and the acme plugin:

```sh
$ sudo setcap cap_ipc_lock=+ep $(readlink -f $(which vault))
$ sudo setcap cap_ipc_lock=+ep /vault/plugins/acme-plugin
```

After setting [`plugin_directory`](https://www.vaultproject.io/docs/configuration/#plugin_directory)
and setting the correct shasum in Vault (`vault write sys/plugins/catalog/secret/acme sha_256=$(sha256sum acme-plugin) command=acme-plugin`)
you can mount the plugin like any other: `vault secrets enable -path acme -plugin-name acme plugin`.


## Tests

Unit tests are run against [Pebble](https://github.com/letsencrypt/pebble):

```bash
$ export PEBBLE_VA_NOSLEEP=1
$ pebble -dnsserver 127.0.0.1:8053 &
$ pebble-challtestsrv -http01 "" -https01 "" -tlsalpn01 "" &
$ make test
```

and acceptance tests both Pebble and a running Vault server:

```bash
$ export LEGO_TEST_NAMESERVER=127.0.0.1:8053
$ export LEGO_CA_CERTIFICATES=$PWD/test/certs/pebble.minica.pem
$ export PEBBLE_VA_NOSLEEP=1
$ export EXEC_PROPAGATION_TIMEOUT=5
$ export EXEC_PATH=$PWD/test/test_dns.sh
$ pebble -dnsserver 127.0.0.1:8053 &
$ pebble-challtestsrv -http01 "" -https01 "" -tlsalpn01 "" &
$ vault server -dev -config ./test/vault.hcl -dev-root-token-id foo &
$ make testacc
```
