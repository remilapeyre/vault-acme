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

* [Create ACME account](#create-acme-account)
* [Read ACME account](#read-acme-account)
* [Delete ACME account](#delete-acme-account)
* [Create/Update Role](#create-update-role)
* [Read Role](#read-role)
* [Delete Role](#delete-role)
* [Generate Certificate](#generate-certificate)

## Create ACME account

This endpoint register an ACME account with the provided ACME CA.

| Method   | Path                      |
| :------- | :------------------------ |
| `PUT`    | `/acme/account/:account`  |


### Parameters

- `account` `(string: <required>)` - The name of the account to create.
- `server_url` `(string: <required>)` - The ACME endpoint to use.
- `terms_of_service_agreed` `(bool: false)` - Whether to accept the terms of service of the ACME CA.
- `provider` `(string: <required>)` - Which DNS provider to use to resolve the DNS challenge.
- `contact` `(string: <required>)` - The contact email address for the account.

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
