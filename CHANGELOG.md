# Changelog 

## 1.1.1
* Added the MIT license to the repository
* Added classifiers for supporting python 3.12
* Added six as a dependency for python 2.7 support (Maybe we have to remove support?)

## 1.1.0

* Add a method to Cert to load a cert directly with Cert.load((PEM OR DER bytes))
* Add a method to CertificateChain to load a chain from a PEM bytes CertificateChain.load_from_pem()
* Add a root property to CertificateChain

## 1.0.2

* Add support for python 3.11
* Updated python version classifiers in setup.py

## 1.0.1

* Bugfix: Support windows newlines in PEM files
* Added python version classifiers to setup.py

## 1.0.0 (deleted)

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
