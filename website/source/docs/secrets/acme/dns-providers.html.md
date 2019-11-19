---
layout: "docs"
page_title: "ACME - Secrets Engines"
sidebar_title: "DNS Providers"
sidebar_current: "docs-secrets-acme-dns-providers"
description: |-
  The DNS providers are used to solve the DNS-01 challenge.
---

# ACME DNS Providers

When an account in the ACME secret backend is configured to use the DNS-01
challenge, credentials to access and update the DNS records must be configured.

~> **WARNING:** The DNS-01 challenge for a given domain requires to update the
   TXT record at `_acme-challenge.<YOUR_DOMAIN>`. If your DNS provider supports it, use
   credentials with permissions restricted to these records to improve security.


[//]: # (The rest of this file was produced from the lego documentation under MIT license)
[//]: # (with the following program:)
[//]: # (for provider in sorted(glob('./providers/**/*.toml', recursive=True)):)
[//]: # (    with open(provider) as f:)
[//]: # (        data = toml.load(f))
[//]: # (    print(f"## {data['Name']}"))
[//]: # (    if 'Description' in data:)
[//]: # (        print(f"{data['Description']}"))
[//]: # (    if 'Additional' in data:)
[//]: # (        print(data['Additional'].replace('##', '###')))
[//]: # (    conf = data.get('Configuration', {}))
[//]: # (    if 'Credentials' in conf:)
[//]: # (        print('### Credentials'))
[//]: # (        for k, v in conf['Credentials'].items():)
[//]: # (            print(f"  - `{k}`: {v}"))
[//]: # (    if 'Additional' in conf:)
[//]: # (        print('\n### Additional configuration'))
[//]: # (        for k, v in conf['Additional'].items():)
[//]: # (            print(f"  - `{k}`: {v}"))
[//]: # (    print())
[//]: # (    print())

## Joohoi's ACME-DNS

### Credentials
  - `ACME_DNS_API_BASE`: The ACME-DNS API address
  - `ACME_DNS_STORAGE_PATH`: The ACME-DNS JSON account data file. A per-domain account will be registered/persisted to this file and used for TXT updates.


## Alibaba Cloud DNS

### Credentials
  - `ALICLOUD_ACCESS_KEY`: Access key ID
  - `ALICLOUD_SECRET_KEY`: Access Key secret

### Additional configuration
  - `ALICLOUD_POLLING_INTERVAL`: Time between DNS propagation check
  - `ALICLOUD_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `ALICLOUD_TTL`: The TTL of the TXT record used for the DNS challenge
  - `ALICLOUD_HTTP_TIMEOUT`: API request timeout


## Aurora DNS

### Credentials
  - `AURORA_USER_ID`: User ID
  - `AURORA_KEY`: User API key
  - `AURORA_ENDPOINT`: API endpoint URL

### Additional configuration
  - `AURORA_POLLING_INTERVAL`: Time between DNS propagation check
  - `AURORA_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `AURORA_TTL`: The TTL of the TXT record used for the DNS challenge


## Autodns

### Credentials
  - `AUTODNS_API_USER`: Username
  - `AUTODNS_API_PASSWORD`: User Password

### Additional configuration
  - `AUTODNS_ENDPOINT`: API endpoint URL, defaults to https://api.autodns.com/v1/
  - `AUTODNS_CONTEXT`: API context (4 for production, 1 for testing. Defaults to 4)
  - `AUTODNS_TTL`: The TTL of the TXT record used for the DNS challenge
  - `AUTODNS_POLLING_INTERVAL`: Time between DNS propagation check
  - `AUTODNS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `AUTODNS_HTTP_TIMEOUT`: API request timeout, defaults to 30 seconds


## Azure

### Credentials
  - `AZURE_CLIENT_ID`: Client ID
  - `AZURE_CLIENT_SECRET`: Client secret
  - `AZURE_SUBSCRIPTION_ID`: Subscription ID
  - `AZURE_TENANT_ID`: Tenant ID
  - `AZURE_RESOURCE_GROUP`: Resource group
  - `instance metadata service`: If the credentials are **not** set via the environment, then it will attempt to get a bearer token via the [instance metadata service](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service).

### Additional configuration
  - `AZURE_POLLING_INTERVAL`: Time between DNS propagation check
  - `AZURE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `AZURE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `AZURE_METADATA_ENDPOINT`: Metadata Service endpoint URL


## Bindman

### Credentials
  - `BINDMAN_MANAGER_ADDRESS`: The server URL, should have scheme, hostname, and port (if required) of the Bindman-DNS Manager server

### Additional configuration
  - `BINDMAN_POLLING_INTERVAL`: Time between DNS propagation check
  - `BINDMAN_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `BINDMAN_HTTP_TIMEOUT`: API request timeout


## Bluecat

### Credentials
  - `BLUECAT_SERVER_URL`: The server URL, should have scheme, hostname, and port (if required) of the authoritative Bluecat BAM serve
  - `BLUECAT_USER_NAME`: API username
  - `BLUECAT_PASSWORD`: API password
  - `BLUECAT_CONFIG_NAME`: Configuration name
  - `BLUECAT_DNS_VIEW`: External DNS View Name

### Additional configuration
  - `BLUECAT_POLLING_INTERVAL`: Time between DNS propagation check
  - `BLUECAT_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `BLUECAT_TTL`: The TTL of the TXT record used for the DNS challenge
  - `BLUECAT_HTTP_TIMEOUT`: API request timeout


## Cloudflare

### Description

You may use `CF_API_EMAIL` and `CF_API_KEY` to authenticate, or `CF_DNS_API_TOKEN`, or `CF_DNS_API_TOKEN` and `CF_ZONE_API_TOKEN`.

#### API keys

If using API keys (`CF_API_EMAIL` and `CF_API_KEY`), the Global API Key needs to be used, not the Origin CA Key.

Please be aware, that this in principle allows Lego to read and change *everything* related to this account.

#### API tokens

With API tokens (`CF_DNS_API_TOKEN`, and optionally `CF_ZONE_API_TOKEN`),
very specific access can be granted to your resources at Cloudflare.
See this [Cloudflare announcement](https://blog.cloudflare.com/api-tokens-general-availability/) for details.

The main resources Lego cares for are the DNS entries for your Zones.
It also need to resolve a domain name to an internal Zone ID in order to manipulate DNS entries.

Hence, you should create an API token with the following permissions:

* Zone / Zone / Read
* Zone / DNS / Edit

You also need to scope the access to all your domains for this to work.
Then pass the API token as `CF_DNS_API_TOKEN` to Lego.

**Alternatively,** if you prefer a more strict set of privileges,
you can split the access tokens:

* Create one with *Zone / Zone / Read* permissions and scope it to all your zones.
  This is needed to resolve domain names to Zone IDs and can be shared among multiple Lego installations.
  Pass this API token as `CF_ZONE_API_TOKEN` to Lego.
* Create another API token with *Zone / DNS / Edit* permissions and set the scope to the domains you want to manage with a single Lego installation.
  Pass this token as `CF_DNS_API_TOKEN` to Lego.
* Repeat the previous step for each host you want to run Lego on.

This "paranoid" setup is mainly interesting for users who manage many zones/domains with a single Cloudflare account.
It follows the principle of least privilege and limits the possible damage, should one of the hosts become compromised.

### Credentials
  - `CF_API_EMAIL`: Account email
  - `CF_API_KEY`: API key
  - `CF_DNS_API_TOKEN`: API token with DNS:Edit permission (since v3.1.0)
  - `CF_ZONE_API_TOKEN`: API token with Zone:Read permission (since v3.1.0)
  - `CLOUDFLARE_EMAIL`: Alias to CF_API_EMAIL
  - `CLOUDFLARE_API_KEY`: Alias to CF_API_KEY
  - `CLOUDFLARE_DNS_API_TOKEN`: Alias to CF_DNS_API_TOKEN
  - `CLOUDFLARE_ZONE_API_TOKEN`: Alias to CF_ZONE_API_TOKEN

### Additional configuration
  - `CLOUDFLARE_POLLING_INTERVAL`: Time between DNS propagation check
  - `CLOUDFLARE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `CLOUDFLARE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `CLOUDFLARE_HTTP_TIMEOUT`: API request timeout


## ClouDNS

### Credentials
  - `CLOUDNS_AUTH_ID`: The API user ID
  - `CLOUDNS_AUTH_PASSWORD`: The password for API user ID

### Additional configuration
  - `CLOUDNS_POLLING_INTERVAL`: Time between DNS propagation check
  - `CLOUDNS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `CLOUDNS_TTL`: The TTL of the TXT record used for the DNS challenge
  - `CLOUDNS_HTTP_TIMEOUT`: API request timeout


## CloudXNS

### Credentials
  - `CLOUDXNS_API_KEY`: The API key
  - `CLOUDXNS_SECRET_KEY`: THe API secret key

### Additional configuration
  - `CLOUDXNS_POLLING_INTERVAL`: Time between DNS propagation check
  - `CLOUDXNS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `CLOUDXNS_TTL`: The TTL of the TXT record used for the DNS challenge
  - `CLOUDXNS_HTTP_TIMEOUT`: API request timeout


## ConoHa

### Credentials
  - `CONOHA_TENANT_ID`: Tenant ID
  - `CONOHA_API_USERNAME`: The API username
  - `CONOHA_API_PASSWORD`: The API password

### Additional configuration
  - `CONOHA_POLLING_INTERVAL`: Time between DNS propagation check
  - `CONOHA_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `CONOHA_TTL`: The TTL of the TXT record used for the DNS challenge
  - `CONOHA_HTTP_TIMEOUT`: API request timeout
  - `CONOHA_REGION`: The region


## Designate DNSaaS for Openstack

### Credentials
  - `OS_AUTH_URL`: Identity endpoint URL
  - `OS_USERNAME`: Username
  - `OS_PASSWORD`: Password
  - `OS_PROJECT_NAME`: Project name
  - `OS_TENANT_NAME`: Tenant name (deprecated see OS_PROJECT_NAME and OS_PROJECT_ID)
  - `OS_REGION_NAME`: Region name

### Additional configuration
  - `OS_PROJECT_ID`: Project ID
  - `DESIGNATE_POLLING_INTERVAL`: Time between DNS propagation check
  - `DESIGNATE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DESIGNATE_TTL`: The TTL of the TXT record used for the DNS challenge


## Digital Ocean

### Credentials
  - `DO_AUTH_TOKEN`: Authentication token

### Additional configuration
  - `DO_POLLING_INTERVAL`: Time between DNS propagation check
  - `DO_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DO_TTL`: The TTL of the TXT record used for the DNS challenge
  - `DO_HTTP_TIMEOUT`: API request timeout


## DNSimple

### Credentials
  - `DNSIMPLE_OAUTH_TOKEN`: OAuth token
  - `DNSIMPLE_BASE_URL`: API endpoint URL

### Additional configuration
  - `DNSIMPLE_POLLING_INTERVAL`: Time between DNS propagation check
  - `DNSIMPLE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DNSIMPLE_TTL`: The TTL of the TXT record used for the DNS challenge


## DNS Made Easy

### Credentials
  - `DNSMADEEASY_API_KEY`: The API key
  - `DNSMADEEASY_API_SECRET`: The API Secret key

### Additional configuration
  - `DNSMADEEASY_SANDBOX`: Activate the sandbox (boolean)
  - `DNSMADEEASY_POLLING_INTERVAL`: Time between DNS propagation check
  - `DNSMADEEASY_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DNSMADEEASY_TTL`: The TTL of the TXT record used for the DNS challenge
  - `DNSMADEEASY_HTTP_TIMEOUT`: API request timeout


## DNSPod

### Credentials
  - `DNSPOD_API_KEY`: The user token

### Additional configuration
  - `DNSPOD_POLLING_INTERVAL`: Time between DNS propagation check
  - `DNSPOD_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DNSPOD_TTL`: The TTL of the TXT record used for the DNS challenge
  - `DNSPOD_HTTP_TIMEOUT`: API request timeout


## Domain Offensive (do.de)

### Credentials
  - `DODE_TOKEN`: API token

### Additional configuration
  - `DODE_POLLING_INTERVAL`: Time between DNS propagation check
  - `DODE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DODE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `DODE_HTTP_TIMEOUT`: API request timeout
  - `DODE_SEQUENCE_INTERVAL`: Interval between iteration


## DreamHost

### Credentials
  - `DREAMHOST_API_KEY`: The API key

### Additional configuration
  - `DREAMHOST_POLLING_INTERVAL`: Time between DNS propagation check
  - `DREAMHOST_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DREAMHOST_TTL`: The TTL of the TXT record used for the DNS challenge
  - `DREAMHOST_HTTP_TIMEOUT`: API request timeout


## Duck DNS

### Credentials
  - `DUCKDNS_TOKEN`: Account token

### Additional configuration
  - `DUCKDNS_POLLING_INTERVAL`: Time between DNS propagation check
  - `DUCKDNS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DUCKDNS_TTL`: The TTL of the TXT record used for the DNS challenge
  - `DUCKDNS_HTTP_TIMEOUT`: API request timeout
  - `DUCKDNS_SEQUENCE_INTERVAL`: Interval between iteration


## Dyn

### Credentials
  - `DYN_CUSTOMER_NAME`: Customer name
  - `DYN_USER_NAME`: User name
  - `DYN_PASSWORD`: Paswword

### Additional configuration
  - `DYN_POLLING_INTERVAL`: Time between DNS propagation check
  - `DYN_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `DYN_TTL`: The TTL of the TXT record used for the DNS challenge
  - `DYN_HTTP_TIMEOUT`: API request timeout


## EasyDNS

To test with the sandbox environment set ```EASYDNS_ENDPOINT=https://sandbox.rest.easydns.net```

### Credentials
  - `EASYDNS_TOKEN`: API Token
  - `EASYDNS_KEY`: API Key

### Additional configuration
  - `EASYDNS_ENDPOINT`: The endpoint URL of the API Server
  - `EASYDNS_POLLING_INTERVAL`: Time between DNS propagation check
  - `EASYDNS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `EASYDNS_SEQUENCE_INTERVAL`: Time between sequential requests
  - `EASYDNS_TTL`: The TTL of the TXT record used for the DNS challenge
  - `EASYDNS_HTTP_TIMEOUT`: API request timeout


## External program
Solving the DNS-01 challenge using an external program.
### Base Configuration

| Environment Variable Name | Description                           |
|---------------------------|---------------------------------------|
| `EXEC_MODE`               | `RAW`, none                           |
| `EXEC_PATH`               | The path of the the external program. |


### Additional Configuration

| Environment Variable Name  | Description                               |
|----------------------------|-------------------------------------------|
| `EXEC_POLLING_INTERVAL`    | Time between DNS propagation check.       |
| `EXEC_PROPAGATION_TIMEOUT` | Maximum waiting time for DNS propagation. |


### Description

The file name of the external program is specified in the environment variable `EXEC_PATH`.

When it is run by lego, three command-line parameters are passed to it:
The action ("present" or "cleanup"), the fully-qualified domain name and the value for the record.

For example, requesting a certificate for the domain 'foo.example.com' can be achieved by calling lego as follows:

```bash
EXEC_PATH=./update-dns.sh lego --dns exec --domains foo.example.com --email invalid@example.com run
```

It will then call the program './update-dns.sh' with like this:

```bash
./update-dns.sh "present" "_acme-challenge.foo.example.com." "MsijOYZxqyjGnFGwhjrhfg-Xgbl5r68WPda0J9EgqqI"
```

The program then needs to make sure the record is inserted.
When it returns an error via a non-zero exit code, lego aborts.

When the record is to be removed again,
the program is called with the first command-line parameter set to `cleanup` instead of `present`.

If you want to use the raw domain, token, and keyAuth values with your program, you can set `EXEC_MODE=RAW`:

```bash
EXEC_MODE=RAW EXEC_PATH=./update-dns.sh lego --dns exec --domains foo.example.com --email invalid@example.com run
```

It will then call the program `./update-dns.sh` like this:

```bash
./update-dns.sh "present" "foo.example.com." "--" "some-token" "KxAy-J3NwUmg9ZQuM-gP_Mq1nStaYSaP9tYQs5_-YsE.ksT-qywTd8058G-SHHWA3RAN72Pr0yWtPYmmY5UBpQ8"
```

### Commands

{{% notice note %}}
The `--` is because the token MAY start with a `-`, and the called program may try and interpret a `-` as indicating a flag.
In the case of urfave, which is commonly used,
you can use the `--` delimiter to specify the start of positional arguments, and handle such a string safely.
{{% /notice %}}

#### Present

| Mode    | Command                                            |
|---------|----------------------------------------------------|
| default | `myprogram present -- <FQDN> <record>`             |
| `RAW`   | `myprogram present -- <domain> <token> <key_auth>` |

#### Cleanup

| Mode    | Command                                            |
|---------|----------------------------------------------------|
| default | `myprogram cleanup -- <FQDN> <record>`             |
| `RAW`   | `myprogram cleanup -- <domain> <token> <key_auth>` |

#### Timeout

The command have to display propagation timeout and polling interval into Stdout.

The values must be formatted as JSON, and times are in seconds.
Example: `{"timeout": 30, "interval": 5}`

If an error occurs or if the command is not provided:
the default display propagation timeout and polling interval are used.

| Mode    | Command                                            |
|---------|----------------------------------------------------|
| default | `myprogram timeout`                                |
| `RAW`   | `myprogram timeout`                                |




## Exoscale

### Credentials
  - `EXOSCALE_API_KEY`: API key
  - `EXOSCALE_API_SECRET`: API secret
  - `EXOSCALE_ENDPOINT`: API endpoint URL

### Additional configuration
  - `EXOSCALE_POLLING_INTERVAL`: Time between DNS propagation check
  - `EXOSCALE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `EXOSCALE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `EXOSCALE_HTTP_TIMEOUT`: API request timeout


## FastDNS

### Credentials
  - `AKAMAI_HOST`: API host
  - `AKAMAI_CLIENT_TOKEN`: Client token
  - `AKAMAI_CLIENT_SECRET`: Client secret
  - `AKAMAI_ACCESS_TOKEN`: Access token

### Additional configuration
  - `AKAMAI_POLLING_INTERVAL`: Time between DNS propagation check
  - `AKAMAI_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `AKAMAI_TTL`: The TTL of the TXT record used for the DNS challenge


## Gandi

### Credentials
  - `GANDI_API_KEY`: API key

### Additional configuration
  - `GANDI_POLLING_INTERVAL`: Time between DNS propagation check
  - `GANDI_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `GANDI_TTL`: The TTL of the TXT record used for the DNS challenge
  - `GANDI_HTTP_TIMEOUT`: API request timeout


## Gandi Live DNS (v5)

### Credentials
  - `GANDIV5_API_KEY`: API key

### Additional configuration
  - `GANDIV5_POLLING_INTERVAL`: Time between DNS propagation check
  - `GANDIV5_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `GANDIV5_TTL`: The TTL of the TXT record used for the DNS challenge
  - `GANDIV5_HTTP_TIMEOUT`: API request timeout


## Google Cloud

### Credentials
  - `GCE_PROJECT`: Project name
  - `Application Default Credentials`: [Documentation](https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application)
  - `GCE_SERVICE_ACCOUNT_FILE`: Account file path
  - `GCE_SERVICE_ACCOUNT`: Account

### Additional configuration
  - `GCE_POLLING_INTERVAL`: Time between DNS propagation check
  - `GCE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `GCE_TTL`: The TTL of the TXT record used for the DNS challenge


## Glesys

### Credentials
  - `GLESYS_API_USER`: API user
  - `GLESYS_API_KEY`: API key

### Additional configuration
  - `GLESYS_POLLING_INTERVAL`: Time between DNS propagation check
  - `GLESYS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `GLESYS_TTL`: The TTL of the TXT record used for the DNS challenge
  - `GLESYS_HTTP_TIMEOUT`: API request timeout


## Go Daddy

### Credentials
  - `GODADDY_API_KEY`: API key
  - `GODADDY_API_SECRET`: API secret

### Additional configuration
  - `GODADDY_POLLING_INTERVAL`: Time between DNS propagation check
  - `GODADDY_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `GODADDY_TTL`: The TTL of the TXT record used for the DNS challenge
  - `GODADDY_HTTP_TIMEOUT`: API request timeout
  - `GODADDY_SEQUENCE_INTERVAL`: Interval between iteration


## Hosting.de

### Credentials
  - `HOSTINGDE_API_KEY`: API key
  - `HOSTINGDE_ZONE_NAME`: Zone name in ACE format

### Additional configuration
  - `HOSTINGDE_POLLING_INTERVAL`: Time between DNS propagation check
  - `HOSTINGDE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `HOSTINGDE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `HOSTINGDE_HTTP_TIMEOUT`: API request timeout


## HTTP request

### Description

The server must provide:

- `POST` `/present`
- `POST` `/cleanup`

The URL of the server must be define by `HTTPREQ_ENDPOINT`.

#### Mode

There are 2 modes (`HTTPREQ_MODE`):

- default mode:
```json
{
  "fqdn": "_acme-challenge.domain.",
  "value": "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
}
```

- `RAW`
```json
{
  "domain": "domain",
  "token": "token",
  "keyAuth": "key"
}
```

#### Authentication

Basic authentication (optional) can be set with some environment variables:

- `HTTPREQ_USERNAME` and `HTTPREQ_PASSWORD`
- both values must be set, otherwise basic authentication is not defined.


### Credentials
  - `HTTPREQ_MODE`: `RAW`, none
  - `HTTPREQ_ENDPOINT`: The URL of the server

### Additional configuration
  - `HTTPREQ_USERNAME`: Basic authentication username
  - `HTTPREQ_PASSWORD`: Basic authentication password
  - `HTTPREQ_POLLING_INTERVAL`: Time between DNS propagation check
  - `HTTPREQ_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `HTTPREQ_HTTP_TIMEOUT`: API request timeout


## Internet Initiative Japan

### Credentials
  - `IIJ_API_ACCESS_KEY`: API access key
  - `IIJ_API_SECRET_KEY`: API secret key
  - `IIJ_DO_SERVICE_CODE`: DO service code

### Additional configuration
  - `IIJ_POLLING_INTERVAL`: Time between DNS propagation check
  - `IIJ_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `IIJ_TTL`: The TTL of the TXT record used for the DNS challenge


## INWX

### Credentials
  - `INWX_USERNAME`: Username
  - `INWX_PASSWORD`: Password

### Additional configuration
  - `INWX_POLLING_INTERVAL`: Time between DNS propagation check
  - `INWX_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `INWX_TTL`: The TTL of the TXT record used for the DNS challenge
  - `INWX_SANDBOX`: Activate the sandbox (boolean)


## Joker

### Credentials
  - `JOKER_API_KEY`: API key
  - `JOKER_USERNAME`: Joker.com username (email address)
  - `JOKER_PASSWORD`: Joker.com password

### Additional configuration
  - `JOKER_POLLING_INTERVAL`: Time between DNS propagation check
  - `JOKER_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `JOKER_TTL`: The TTL of the TXT record used for the DNS challenge
  - `JOKER_HTTP_TIMEOUT`: API request timeout


## Amazon Lightsail

### Credentials
  - `AWS_ACCESS_KEY_ID`: Access key ID
  - `AWS_SECRET_ACCESS_KEY`: Secret access key
  - `DNS_ZONE`: DNS zone

### Additional configuration
  - `LIGHTSAIL_POLLING_INTERVAL`: Time between DNS propagation check
  - `LIGHTSAIL_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation


## Linode (deprecated)

### Credentials
  - `LINODE_API_KEY`: API key

### Additional configuration
  - `LINODE_POLLING_INTERVAL`: Time between DNS propagation check
  - `LINODE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `LINODE_HTTP_TIMEOUT`: API request timeout


## Linode (v4)

### Credentials
  - `LINODE_TOKEN`: API token

### Additional configuration
  - `LINODE_POLLING_INTERVAL`: Time between DNS propagation check
  - `LINODE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `LINODE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `LINODE_HTTP_TIMEOUT`: API request timeout


## Liquid Web

### Credentials
  - `LIQUID_WEB_USERNAME`: Storm API Username
  - `LIQUID_WEB_PASSWORD`: Storm API Password
  - `LIQUID_WEB_ZONE`: DNS Zone

### Additional configuration
  - `LIQUID_WEB_URL`: Storm API endpoint
  - `LIQUID_WEB_TTL`: The TTL of the TXT record used for the DNS challenge
  - `LIQUID_WEB_POLLING_INTERVAL`: Time between DNS propagation check
  - `LIQUID_WEB_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `LIQUID_WEB_HTTP_TIMEOUT`: Maximum waiting time for the DNS records to be created (not verified)


## MyDNS.jp

### Credentials
  - `MYDNSJP_MASTER_ID`: Master ID
  - `MYDNSJP_PASSWORD`: Password

### Additional configuration
  - `MYDNSJP_POLLING_INTERVAL`: Time between DNS propagation check
  - `MYDNSJP_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `MYDNSJP_TTL`: The TTL of the TXT record used for the DNS challenge
  - `MYDNSJP_HTTP_TIMEOUT`: API request timeout


## Namecheap

### Credentials
  - `NAMECHEAP_API_USER`: API user
  - `NAMECHEAP_API_KEY`: API key

### Additional configuration
  - `NAMECHEAP_POLLING_INTERVAL`: Time between DNS propagation check
  - `NAMECHEAP_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `NAMECHEAP_TTL`: The TTL of the TXT record used for the DNS challenge
  - `NAMECHEAP_HTTP_TIMEOUT`: API request timeout


## Name.com

### Credentials
  - `NAMECOM_USERNAME`: Username
  - `NAMECOM_API_TOKEN`: API token

### Additional configuration
  - `NAMECOM_POLLING_INTERVAL`: Time between DNS propagation check
  - `NAMECOM_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `NAMECOM_TTL`: The TTL of the TXT record used for the DNS challenge
  - `NAMECOM_HTTP_TIMEOUT`: API request timeout


## Namesilo

### Credentials
  - `NAMESILO_API_KEY`: Client ID

### Additional configuration
  - `NAMESILO_POLLING_INTERVAL`: Time between DNS propagation check
  - `NAMESILO_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation, it is better to set larger than 15m
  - `NAMESILO_TTL`: The TTL of the TXT record used for the DNS challenge, should be in [3600, 2592000]


## Netcup

### Credentials
  - `NETCUP_CUSTOMER_NUMBER`: Customer number
  - `NETCUP_API_KEY`: API key
  - `NETCUP_API_PASSWORD`: API password

### Additional configuration
  - `NETCUP_POLLING_INTERVAL`: Time between DNS propagation check
  - `NETCUP_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `NETCUP_TTL`: The TTL of the TXT record used for the DNS challenge
  - `NETCUP_HTTP_TIMEOUT`: API request timeout


## NIFCloud

### Credentials
  - `NIFCLOUD_ACCESS_KEY_ID`: Access key
  - `NIFCLOUD_SECRET_ACCESS_KEY`: Secret access key

### Additional configuration
  - `NIFCLOUD_POLLING_INTERVAL`: Time between DNS propagation check
  - `NIFCLOUD_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `NIFCLOUD_TTL`: The TTL of the TXT record used for the DNS challenge
  - `NIFCLOUD_HTTP_TIMEOUT`: API request timeout


## NS1

### Credentials
  - `NS1_API_KEY`: API key

### Additional configuration
  - `NS1_POLLING_INTERVAL`: Time between DNS propagation check
  - `NS1_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `NS1_TTL`: The TTL of the TXT record used for the DNS challenge
  - `NS1_HTTP_TIMEOUT`: API request timeout


## Oracle Cloud

### Credentials
  - `OCI_PRIVKEY_FILE`: Private key file
  - `OCI_PRIVKEY_PASS`: Private key password
  - `OCI_TENANCY_OCID`: Tenanct OCID
  - `OCI_USER_OCID`: User OCID
  - `OCI_PUBKEY_FINGERPRINT`: Public key fingerprint
  - `OCI_REGION`: Region
  - `OCI_COMPARTMENT_OCID`: Compartment OCID

### Additional configuration
  - `OCI_POLLING_INTERVAL`: Time between DNS propagation check
  - `OCI_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `OCI_TTL`: The TTL of the TXT record used for the DNS challenge


## Open Telekom Cloud

### Credentials
  - `OTC_USER_NAME`: User name
  - `OTC_PASSWORD`: Password
  - `OTC_PROJECT_NAME`: Project name
  - `OTC_DOMAIN_NAME`: Domain name
  - `OTC_IDENTITY_ENDPOINT`: Identity endpoint URL

### Additional configuration
  - `OTC_POLLING_INTERVAL`: Time between DNS propagation check
  - `OTC_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `OTC_TTL`: The TTL of the TXT record used for the DNS challenge
  - `OTC_HTTP_TIMEOUT`: API request timeout


## OVH

### Credentials
  - `OVH_ENDPOINT`: Endpoint URL (ovh-eu or ovh-ca)
  - `OVH_APPLICATION_KEY`: Application key
  - `OVH_APPLICATION_SECRET`: Application secret
  - `OVH_CONSUMER_KEY`: Consumer key

### Additional configuration
  - `OVH_POLLING_INTERVAL`: Time between DNS propagation check
  - `OVH_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `OVH_TTL`: The TTL of the TXT record used for the DNS challenge
  - `OVH_HTTP_TIMEOUT`: API request timeout


## PowerDNS

### Information

Tested and confirmed to work with PowerDNS authoritative server 3.4.8 and 4.0.1. Refer to [PowerDNS documentation](https://doc.powerdns.com/md/httpapi/README/) instructions on how to enable the built-in API interface.

PowerDNS Notes:
- PowerDNS API does not currently support SSL, therefore you should take care to ensure that traffic between lego and the PowerDNS API is over a trusted network, VPN etc.
- In order to have the SOA serial automatically increment each time the `_acme-challenge` record is added/modified via the API, set `SOA-EDIT-API` to `INCEPTION-INCREMENT` for the zone in the `domainmetadata` table

### Credentials
  - `PDNS_API_KEY`: API key
  - `PDNS_API_URL`: API url

### Additional configuration
  - `PDNS_POLLING_INTERVAL`: Time between DNS propagation check
  - `PDNS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `PDNS_TTL`: The TTL of the TXT record used for the DNS challenge
  - `PDNS_HTTP_TIMEOUT`: API request timeout


## Rackspace

### Credentials
  - `RACKSPACE_USER`: API user
  - `RACKSPACE_API_KEY`: API key

### Additional configuration
  - `RACKSPACE_POLLING_INTERVAL`: Time between DNS propagation check
  - `RACKSPACE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `RACKSPACE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `RACKSPACE_HTTP_TIMEOUT`: API request timeout


## RFC2136

### Credentials
  - `RFC2136_TSIG_KEY`: Name of the secret key as defined in DNS server configuration. To disable TSIG authentication, leave the `RFC2136_TSIG*` variables unset.
  - `RFC2136_TSIG_SECRET`: Secret key payload. To disable TSIG authentication, leave the` RFC2136_TSIG*` variables unset.
  - `RFC2136_TSIG_ALGORITHM`: TSIG algorythm. See [miekg/dns#tsig.go](https://github.com/miekg/dns/blob/master/tsig.go) for supported values. To disable TSIG authentication, leave the `RFC2136_TSIG*` variables unset.
  - `RFC2136_NAMESERVER`: Network address in the form "host" or "host:port"

### Additional configuration
  - `RFC2136_POLLING_INTERVAL`: Time between DNS propagation check
  - `RFC2136_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `RFC2136_TTL`: The TTL of the TXT record used for the DNS challenge
  - `RFC2136_DNS_TIMEOUT`: API request timeout
  - `RFC2136_SEQUENCE_INTERVAL`: Interval between iteration


## Amazon Route 53

### Description

AWS Credentials are automatically detected in the following locations and prioritized in the following order:

1. Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, [`AWS_SESSION_TOKEN`]
2. Shared credentials file (defaults to `~/.aws/credentials`)
3. Amazon EC2 IAM role

If `AWS_HOSTED_ZONE_ID` is not set, Lego tries to determine the correct public hosted zone via the FQDN.

See also: [sessions](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/sessions.html)

### Policy

The following AWS IAM policy document describes the permissions required for lego to complete the DNS challenge.

```json
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Sid": "",
           "Effect": "Allow",
           "Action": [
               "route53:GetChange",
               "route53:ChangeResourceRecordSets",
               "route53:ListResourceRecordSets"
           ],
           "Resource": [
               "arn:aws:route53:::hostedzone/*",
               "arn:aws:route53:::change/*"
           ]
       },
       {
           "Sid": "",
           "Effect": "Allow",
           "Action": "route53:ListHostedZonesByName",
           "Resource": "*"
       }
   ]
}
```


### Credentials
  - `AWS_ACCESS_KEY_ID`: Managed by the AWS client
  - `AWS_SECRET_ACCESS_KEY`: Managed by the AWS client
  - `AWS_REGION`: Managed by the AWS client
  - `AWS_HOSTED_ZONE_ID`: Override the hosted zone ID

### Additional configuration
  - `AWS_MAX_RETRIES`: The number of maximum returns the service will use to make an individual API request
  - `AWS_POLLING_INTERVAL`: Time between DNS propagation check
  - `AWS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `AWS_TTL`: The TTL of the TXT record used for the DNS challenge


## Sakura Cloud

### Credentials
  - `SAKURACLOUD_ACCESS_TOKEN`: Access token
  - `SAKURACLOUD_ACCESS_TOKEN_SECRET`: Access token secret

### Additional configuration
  - `SAKURACLOUD_POLLING_INTERVAL`: Time between DNS propagation check
  - `SAKURACLOUD_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `SAKURACLOUD_TTL`: The TTL of the TXT record used for the DNS challenge
  - `SAKURACLOUD_HTTP_TIMEOUT`: API request timeout


## Selectel

### Credentials
  - `SELECTEL_API_TOKEN`: API token

### Additional configuration
  - `SELECTEL_BASE_URL`: API endpoint URL
  - `SELECTEL_POLLING_INTERVAL`: Time between DNS propagation check
  - `SELECTEL_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `SELECTEL_TTL`: The TTL of the TXT record used for the DNS challenge
  - `SELECTEL_HTTP_TIMEOUT`: API request timeout


## Stackpath

### Credentials
  - `STACKPATH_CLIENT_ID`: Client ID
  - `STACKPATH_CLIENT_SECRET`: Client secret
  - `STACKPATH_STACK_ID`: Stack ID

### Additional configuration
  - `STACKPATH_POLLING_INTERVAL`: Time between DNS propagation check
  - `STACKPATH_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `STACKPATH_TTL`: The TTL of the TXT record used for the DNS challenge


## TransIP

### Credentials
  - `TRANSIP_ACCOUNT_NAME`: Account name
  - `TRANSIP_PRIVATE_KEY_PATH`: Private key path

### Additional configuration
  - `TRANSIP_POLLING_INTERVAL`: Time between DNS propagation check
  - `TRANSIP_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `TRANSIP_TTL`: The TTL of the TXT record used for the DNS challenge


## VegaDNS

### Credentials
  - `SECRET_VEGADNS_KEY`: API key
  - `SECRET_VEGADNS_SECRET`: API secret
  - `VEGADNS_URL`: API endpoint URL

### Additional configuration
  - `VEGADNS_POLLING_INTERVAL`: Time between DNS propagation check
  - `VEGADNS_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `VEGADNS_TTL`: The TTL of the TXT record used for the DNS challenge


## Versio.[nl|eu|uk]

To test with the sandbox environment set ```VERSIO_ENDPOINT=https://www.versio.nl/testapi/v1/```

### Credentials
  - `VERSIO_USERNAME`: Basic authentication username
  - `VERSIO_PASSWORD`: Basic authentication password

### Additional configuration
  - `VERSIO_ENDPOINT`: The endpoint URL of the API Server
  - `VERSIO_POLLING_INTERVAL`: Time between DNS propagation check
  - `VERSIO_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `VERSIO_HTTP_TIMEOUT`: API request timeout
  - `VERSIO_SEQUENCE_INTERVAL`: Interval between iteration, default 60s
  - `VERSIO_TTL`: The TTL of the TXT record used for the DNS challenge


## Vscale

### Credentials
  - `VSCALE_API_TOKEN`: API token

### Additional configuration
  - `VSCALE_BASE_URL`: API enddpoint URL
  - `VSCALE_POLLING_INTERVAL`: Time between DNS propagation check
  - `VSCALE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `VSCALE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `VSCALE_HTTP_TIMEOUT`: API request timeout


## Vultr

### Credentials
  - `VULTR_API_KEY`: API key

### Additional configuration
  - `VULTR_POLLING_INTERVAL`: Time between DNS propagation check
  - `VULTR_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `VULTR_TTL`: The TTL of the TXT record used for the DNS challenge
  - `VULTR_HTTP_TIMEOUT`: API request timeout


## Zone.ee

### Credentials
  - `ZONEEE_API_USER`: API user
  - `ZONEEE_API_KEY`: API key

### Additional configuration
  - `ZONEEE_ENDPOINT`: API endpoint URL
  - `ZONEEE_POLLING_INTERVAL`: Time between DNS propagation check
  - `ZONEEE_PROPAGATION_TIMEOUT`: Maximum waiting time for DNS propagation
  - `ZONEEE_TTL`: The TTL of the TXT record used for the DNS challenge
  - `ZONEEE_HTTP_TIMEOUT`: API request timeout
