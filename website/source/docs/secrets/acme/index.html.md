---
layout: "docs"
page_title: "ACME - Secrets Engines"
sidebar_title: "ACME (Certificates)"
sidebar_current: "docs-secrets-acme"
description: |-
  The ACME secrets engine for Vault generates TLS certificates signed by an ACME CA.
---

# ACME Secrets Engine

The ACME secret engine generates X.509 certificates signed by a Certificate
Authority using the Automated Certificate Management Environment (ACME) standard.

With this secrets engine, services can get certificates that can be presented to
end users and that clients will accept. Currently only Let's Encrypt implement
the ACME standard.

Vault ACME can natively solve the DNS-01 challenges but need a [sidecar](/docs/secrets/acme/sidecar.html) for the HTTP-01 and TLS-ALPN-01 challenges.

-> **NOTE:** The directory URLs in all examples in this provider reference Let's
  Encrypt's staging server endpoint. For production use, change the directory
  URLs to the production endpoints, which can be found [here](https://letsencrypt.org/docs/acme-protocol-updates/).

## Setup

Most secrets engines must be configured in advance before they can perform their
functions. These steps are usually completed by an operator or configuration
management tool.

1. Enable the ACME secrets engine:

    ```text
    $ vault secrets enable acme
    Success! Enabled the acme secrets engine at: acme/
    ```

    By default, the secrets engine will mount at the name of the engine. To
    enable the secrets engine at a different path, use the `-path` argument.


1. Increase the TTL by tuning the secrets engine. The default value of 30 days may be too short, so increase it to 1 year:

    ```text
    $ vault secrets tune -max-lease-ttl=8760h acme
    Success! Tuned the secrets engine at: acme/
    ```

    Note that individual roles can restrict this value to be shorter on a
    per-certificate basis. This just configures the global maximum for this
    secrets engine.

1. Register an account with your ACME provider

    ```text
    $ vault write acme/accounts/lenstra \
		contact=remi@lenstra.fr \
		server_url=https://acme-staging-v02.api.letsencrypt.org/directory \
		terms_of_service_agreed=true \
		provider=cloudflare
    Success! Data written to: acme/accounts/lenstra
    ```

1. Configure a role that maps a name in Vault to a procedure for generating a
certificate. When users or machines generate credentials, they are generated
against this role:

    ```text
    $ vault write acme/roles/lenstra.fr \
        account=lenstra \
        allowed_domains=lenstra.fr \
        allow_bare_domains=false \
        allow_subdomains=true
    Success! Data written to: acme/roles/lenstra.fr
    ```

## Usage

After the secrets engine is configured and a user/machine has a Vault token with
the proper permission, it can generate credentials.

1. Generate a new credential by writing to the `/certs` endpoint with the name
of the role:

    ```text
    $ vault write acme/certs/lenstra.fr \
        common_name=www.lenstra.fr

    Key                Value
    ---                -----
    lease_id           acme/certs/lenstra.fr/A28ijF37fn9pFASIi58fonzz
    lease_duration     768h
    lease_renewable    true
    cert               -----BEGIN CERTIFICATE-----...
    domain             www.lenstra.fr
    issuer_cert        -----BEGIN CERTIFICATE-----...
    not_after          2020-01-24 15:57:02 +0000 UTC
    not_before         2019-10-26 15:57:02 +0000 UTC
    private_key        -----BEGIN RSA PRIVATE KEY-----...
    url                https://acme-v02.api.letsencrypt.org/acme/cert/03a6efdd6534b43c34e6935ca0702aed760f
    ```

    The output will include a dynamically generated private key and certificate
    which corresponds to the given role.

## Quick Start

#### Mount the backend

The first step to using the ACME backend is to mount it. Unlike the `kv`
backend, the `acme` backend is not mounted by default.

```text
$ vault secrets enable acme
Successfully mounted 'acme' at 'acme'!
```

#### Configure a role

The next step is to configure a role. A role is a logical name that maps to a
policy used to generate those credentials. For example, let's create an
"lenstra.fr" role:

```text
$ vault write acme/roles/lenstra.fr \
        account=lenstra \
        allowed_domains=lenstra.fr \
        allow_bare_domains=false \
        allow_subdomains=true
Success! Data written to: pki/roles/lenstra.fr
```

#### Issue Certificates

By writing to the `roles/lenstra.fr` path we are defining the
`lenstra.fr` role. To generate a new certificate, we simply write
to the `certs` endpoint with that role name: Vault is now configured to create
and manage certificates!

```text
$ vault write acme/certs/lenstra.fr \
    common_name=www.lenstra.fr
Key                Value
---                -----
lease_id           acme/certs/lenstra.fr/A28ijF37fn9pFASIi58fonzz
lease_duration     768h
lease_renewable    true
cert               -----BEGIN CERTIFICATE-----
MIIFVjCCBD6gAwIBAgISA6bv3WU0tDw05pNcoHAq7XYPMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
...
5leeJROsbbHq0ZJ2jCcUP5YSbBUI5KKJ0fc9TzmwGZU0SPAqrpMVelbU9rfYFd69
DlrELRiuUNNv3BvbjZ0TdZlCKbZUaT5R5y8=
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
...
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
domain             www.lenstra.fr
issuer_cert        -----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvYKd+0UVwjEak9Pg4bFCisAxcn2ms/y1aNKH98mZ/qodn1XW
ZJVA/E6XPh+PWf7CduxyeJth9XrOU6LLYt7gL28JuLcljNjBzMNVwnNOZ1/woix5
...
veolzQKBgDUxLI3ei9qEUr3eH9yjHWQYQRKYrp2wAa7qlzOv58KTR86DwmTLUedV
aFoRDncBhzItcjaJklf9uAeCP3I1miWEcgPQtg4shT5MfFcoSYu+7BKOFSb00AE9
7/JkcKRksuZpl002hHj0eeqTpD0lvgk5gFoqCC8I+lLx1TChdHRH
-----END RSA PRIVATE KEY-----
not_after          2020-01-24 15:57:02 +0000 UTC
not_before         2019-10-26 15:57:02 +0000 UTC
private_key        -----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvYKd+0UVwjEak9Pg4bFCisAxcn2ms/y1aNKH98mZ/qodn1XW
ZJVA/E6XPh+PWf7CduxyeJth9XrOU6LLYt7gL28JuLcljNjBzMNVwnNOZ1/woix5
...
aFoRDncBhzItcjaJklf9uAeCP3I1miWEcgPQtg4shT5MfFcoSYu+7BKOFSb00AE9
7/JkcKRksuZpl002hHj0eeqTpD0lvgk5gFoqCC8I+lLx1TChdHRH
-----END RSA PRIVATE KEY-----
url                https://acme-v02.api.letsencrypt.org/acme/cert/03a6efdd6534b43c34e6935ca0702aed760f
```

Vault has now generated a new set of credentials using the `lenstra.fr`
role configuration. Here we see the dynamically generated private key and
certificate.

<!-- TODO(remi): Write an example for a policy that does this -->
Using ACLs, it is possible to restrict using the pki backend such that trusted
operators can manage the role definitions, and both users and applications are
restricted in the credentials they are allowed to read.

<!-- TODO(remi): This probably does not work for now -->
If you get stuck at any time, simply run `vault path-help acme` or with a
subpath for interactive help output.

## API

The ACME secrets engine has a full HTTP API. Please see the
[ACME secrets engine API](/api/secret/acme/index.html) for more
details.
