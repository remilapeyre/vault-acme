## 0.0.9
### April 22, 2022

NEW FEATURES:

* The `dns_resolvers` parameter can now be set to choose the DNS resolvers used to check the propagation of the ACME DNS-01 challenge.

## 0.0.8
### July 04, 2021

IMPROVEMENTS:

* Better error message are now returned when a certificate signing request fails.

## 0.0.7
### May 16, 2020

IMPROVEMENTS:

* It is now possible to update an ACME account.

## 0.0.6
### August 19, 2020

IMPROVEMENTS:

* Simultanous requests to create the same certificate will now return the same one to avoid sending multiple requests to the ACME provider.
* The `provider_configuration` parameter can now be used to set the configuration of the ACME client instead of using environment variables.

## 0.0.5
### August 12, 2020

BUG FIXES:

* Failure to retrieve the Lego client now properly return an error.

## 0.0.4
### July 22, 2020

NEW FEATURES:

* It is now possible to ignore skip waiting for the DNS propagation by setting the `ignore_dns_propagation` parameter on an account. The default is `false` and will check that the ACME DNS challenge has been properly propagated before requesting a certificate.

## 0.0.3
### May 18, 2020

NEW FEATURES:

* It is now possible to set the type of key used for an account by setting the `key_type` parameter. Possible values are `EC256`, `EC384`, `RSA2048`, `RSA4096` and `RSA8192`.


## 0.0.2
### May 07, 2020

BUG FIXES:

* The binaries are now statically built to work with Alpine Linux.


## 0.0.1
### May 06, 2020

NEW FEATURES:

* Initial release of the Vault ACME secret engine.
