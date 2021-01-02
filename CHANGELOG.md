# Changelog 

## 1.0.0

The project has been refractored and here is the first major release!

* Added a [readthedocs page](https://certificate-resolver.readthedocs.io/en/latest/) and annotated the new models and api
* Removed pyOpenSSL as a dependency. Thanks to the cryptography team for implementing the necessary functions for pkcs7 support.
* Unit and integration tests!
* More versions of python supported
* Automatically hide the root ca (if resolved) in the chain output. We can consider adding a flag to include root later.

## 0.2.2
Return False when CA:<true|false> is not found in BasicConstraints

## 0.2.0
support for pkcs7 issuers

## 0.1.0
Initial alpha release
