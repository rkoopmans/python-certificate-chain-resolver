# Changelog 

## 1.4.0

* Extended support to python 3.13
* Cert.not_valid_before returns UTC datetime if cryptography version  >= 42
* Cert.not_valid_after returns UTC datetime if cryptography version  >= 42

## 1.3.1

* is_issued_by now raises MissingCertProperty if no hash algorithm found. Before it would silently return False

## 1.3.0

New feature and sane defaults. for the CLI the root is now by default excluded, at first it would include it if it found one, but not all certificate authorities provide a link to their root in their certs. This resulted in sometimes a root to be included and othertimes not.
* CLI
    * Root certificate is excluded by default
    * Display a warning when root is requested, but not available
    * New flags
        * --include-root (for including the root in the output IF AVAILABLE)
        * --ca-bundle-path (Find the matching root certificate using a custom path)

* API
    * New option for the resolve() api, it can now find the root certificate using a file system bundle
        resolve(cert_pem, root_ca_store=FileSystemStore('/optional/path/to/bundle.pem'))

## 1.2.1
* prevent infinite recursion caused by certificate self-referencing in ca_issuer_access_location (Thanks @trgalho)

## 1.2.0a1
* Added mypy type hints
* Introducing a new Exception (MissingCertProperty) when a property is requested and can't be found
* All exceptions now inherit from CertificateChainResolverError
* Removed six as a dependency
* Moved the readthedocs documentation to the new platform (v2)

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
