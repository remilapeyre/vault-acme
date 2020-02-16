# Vault ACME

**This plugin has not been properly reviewed and should not be used in production.**

Vault ACME is a [Vault](https://www.vaultproject.io/) secret engine that allow
users and application to retrieve TLS certificates validated by an [ACME provider](https://tools.ietf.org/html/rfc8555)
like [Let's Encrypt](https://letsencrypt.org/) without having to give each
applications permission to modify DNS and using Vault's audit and policy systems.

Discussion: https://github.com/hashicorp/vault/issues/4950

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

Acceptance tests are run againts [Pebble](https://github.com/letsencrypt/pebble),
a running container will be needed for them to pass:

```bash
$ docker run -d -e "PEBBLE_VA_NOSLEEP=1" -p 14000:14000 -p 15000:15000 letsencrypt/pebble pebble -dnsserver 1.1.1.1:53
$ LEGO_CA_CERTIFICATES=$PWD/test/certs/pebble.minica.pem make test
```
