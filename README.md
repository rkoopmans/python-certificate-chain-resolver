# Resolve certificate chains

Still in development

## Dependencies

* PyOpenSSL
* pyasn1-modules

## Usage

from file:

    $ python -m cert_chain_resolver.cli certificate.crt > bundle.crt

from stdin:

    $ cat certificate.crt | python -m cert_chain_resolver.cli > bundle.crt

## Developement

bootstrap

    $ make

## Todo

* Accept ANS1 format as input
* Accept PEM format in the AuthorityInfoAccess fields
* Verbose mode
* More CLI flags
* Pypi package
* Unit tests
