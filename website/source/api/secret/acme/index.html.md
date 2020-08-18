---
layout: "api"
page_title: "ACME - Secrets Engines - HTTP API"
sidebar_title: "ACME (Certificates)"
sidebar_current: "api-http-secret-acme"
description: |-
  This is the API documentation for the Vault ACME secrets engine.
---

# ACME Secrets Engine (API)

This is the API documentation for the Vault ACME secrets engine. For general
information about the usage and operation of the ACME secrets engine, please see
the [ACME documentation](/docs/secrets/acme/index.html).

This documentation assumes the ACME secrets engine is enabled at the `/acme` path
in Vault. Since it is possible to enable secrets engines at any location, please
update your API calls accordingly.

## Table of Contents

* [Create or update ACME account](#create-or-update-acme-account)
* [Read ACME account](#read-acme-account)
* [Delete ACME account](#delete-acme-account)
* [Create/Update Role](#create-update-role)
* [Read Role](#read-role)
* [Delete Role](#delete-role)
* [Generate Certificate](#generate-certificate)
* [Get the token for an HTTP-01 challenge](#get-the-token-for-an-http-01-challenge)
* [Get the token for a TLS-ALPN-01 challenge](#get-the-token-for-a-tls-alpn-01-challenge)
* [Read the cache state](#read-the-cache-state)
* [Clear the cache](#clear-the-cache)

## Create or update ACME account

This endpoint register an ACME account with the provided ACME CA.

| Method   | Path                      |
| :------- | :------------------------ |
| `PUT`    | `/acme/account/:account`  |


### Parameters

- `account` `(string: <required>)` - The name of the account to create.
- `server_url` `(string: <required>)` - The ACME endpoint to use.
- `terms_of_service_agreed` `(bool: false)` - Whether to accept the terms of service of the ACME CA.
- `contact` `(string: <required>)` - The contact email address for the account.
- `key_type` `(string: <optional>)` - The type of key to use for the account key. Some key may not be supported by all ACME providers. Can be one of `EC256`, `EC384`, `RSA2048`, `RSA4096` and `RSA8192`.
- `provider` `(string: <optional>)` - Which DNS provider to use to resolve the DNS challenge. Setting this parameter will activate the DNS-01 challenge.
- `provider_configuration` `(map of strings: <optional>)` - The configuration to use for the DNS provider when not using environment variables.
- `enable_http_01` `(bool: false)` - Whether to activate the HTTP-01 challenge.
- `enable_tls_alpn_01` `(bool: false)` - Whether to activate the TLS-ALPN-01 challenge.
- `ignore_dns_propagation` `(bool: false)` - Do not wait until the DNS updates have been propagated to all DNS servers. Only relevent for DNS-01 challenges.

## Read ACME account

This endpoint retrieves the information associated with an ACME account.

| Method | Path                     |
| :----- | :----------------------- |
| `GET`  | `/acme/account/:account` |

## Delete ACME account

This endpoint deletes the registration of an ACME account. The account will not
be able to request certificates anymore.

| Method    | Path                     |
| :-------- | :----------------------- |
| `DELETE`  | `/acme/account/:account` |

## Create/Update Role

This endpoint creates or updates a role definition.

| Method | Path                 |
| :----- | :------------------- |
| `PUT`  | `/acme/roles/:role`  |

### Parameters

- `role` `(string: <required>)` - The role name.
- `account` `(string: <required>)` - The ACME account to use when validating certificates.
- `allowed_domains` `(list: [])` - A list of domains the role will be able to deliver certificates for.
- `allow_bare_domains` `(bool: false)` - Whether to accept a request for a certificate that match an allowed domain exactly.
- `allow_subdomains` `(bool: false)` - Whether to accept a request for a certificate containiing a subdomain of an allowed domain.
- `disable_cache` `(bool: false)` - Whether to disable the cache.
- `cache_for_ratio` `(int: 70)` - For how long a cached cert should be used, e.g. a value of 70 means that a cached certificate will be used until 70% of its lifetime will be reached, then a new certificate will be requested.

## Read Role

This endpoint retrieves a role definition.

| Method | Path                 |
| :----- | :------------------- |
| `GET`  | `/acme/roles/:role`  |

## Delete Role

This endpoint deletes a role definition.

| Method    | Path                 |
| :-------- | :------------------- |
| `DELETE`  | `/acme/roles/:role`  |

## Generate Certificate

This endpoints generates and validates a certificate with the ACME server based
on the request and the role definition.

| Method | Path                 |
| :----- | :------------------- |
| `PUT`  | `/acme/certs/:role`  |

### Parameters

- `role` `(string: <required>)` - The role to use to create the certificate.
- `common_name` `(string: <required>)` - The Common Name to request for the certificate.
- `alternative_names` `(list: [])` - A list of Subject Alternative Names to request for the certificate.

## Get the token for an HTTP-01 challenge

This endpoint returns the information needed to solve the HTTP-01 challenge.
This is needed by the Vault ACME sidecar when this challenge is activated.

| Method | Path                                  |
| :----- | :------------------------------------ |
| `GET`  | `/acme/challenges/http-01/:path`      |

## Get the token for a TLS-ALPN-01 challenge

This endpoint returns the information needed to solve the TLS-ALPN-01 challenge.
This is needed by the Vault ACME sidecar when this challenge is activated.

| Method | Path                                  |
| :----- | :------------------------------------ |
| `GET`  | `/acme/challenges/tls-alpn-01/:path`  |

## Read the cache state

This endpoint returns information regarding the cache status.

| Method | Path               |
| :----- | :----------------- |
| `GET`  | `/acme/cache`      |

## Clear the cache

This endpoints lets an operator clear the cache.

| Method    | Path               |
| :-------- | :----------------- |
| `DELETE`  | `/acme/cache`      |
