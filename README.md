# Vault ACME

**This plugin has not been properly reviewed and should not be used in production.**

Vault ACME is a [Vault](https://www.vaultproject.io/) secret engine that allow
users and application to retrieve TLS certificates validated by an [ACME provider](https://tools.ietf.org/html/rfc8555)
like [Let's Encrypt](https://letsencrypt.org/) without having to give each
applications permission to modify DNS and using Vault's audit and policy systems.

Discussion: https://github.com/hashicorp/vault/issues/4950

## Documentation

The documentation is available at `website/source/docs/secrets/acme/index.html.md`.

## How to use this plugin

**This plugin currently requires `mlock` to be disabled to run in Docker.**

Enabling this plugin with `mlock` enabled currently fail with this error message:

```text
#> vault secrets enable acme
Error enabling: Error making API request.

URL: POST http://139.162.27.172:22663/v1/sys/mounts/acme
Code: 400. Errors:

* Unrecognized remote plugin message:

This usually means that the plugin is either invalid or simply
needs to be recompiled to support the latest protocol.
```

To disable `mlock`, add `disable_mlock = true` in [Vault's configuration](https://www.vaultproject.io/docs/configuration/#disable_mlock).

After setting [`plugin_directory`](https://www.vaultproject.io/docs/configuration/#plugin_directory)
and setting the correct shasum in Vault (`vault write sys/plugins/catalog/secret/acme sha_256=1b722cd0300bee3c19d72786a655d9d214b275e2c1ad1f42fc4ebd2af7c2f9d0 command=acme-plugin`)
you can mount the plugin like any other: `vault secrets enable -path acme -plugin-name acme plugin`.


## Tests

Acceptance tests are run againts [Pebble](https://github.com/letsencrypt/pebble),
a running container will be needed for them to pass:

```bash
$ docker run -d -e "PEBBLE_VA_NOSLEEP=1" -p 14000:14000 -p 15000:15000 letsencrypt/pebble pebble -dnsserver 1.1.1.1:53
$ LEGO_CA_CERTIFICATES=$PWD/test/certs/pebble.minica.pem make test
```
