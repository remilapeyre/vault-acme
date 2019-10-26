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

After setting [`plugin_directory`](https://www.vaultproject.io/docs/configuration/#plugin_directory)
and setting the correct shasum in Vault (`vault write sys/plugins/catalog/secret/acme sha_256=1b722cd0300bee3c19d72786a655d9d214b275e2c1ad1f42fc4ebd2af7c2f9d0 command=acme-plugin`)
you can mount the plugin like any other: `vault secrets enable -path acme -plugin-name acme plugin`.
