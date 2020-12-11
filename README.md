# Python certificate chain resolver

[![Licence](https://img.shields.io/badge/licence-MIT-blue.svg)](https://tldrlegal.com/license/mit-license)
![Tests](https://github.com/rkoopmans/python-certificate-chain-resolver/workflows/CI%20tests/badge.svg?branch=v1)

Resolve / obtain the certificate intermediates of a x509 certificate. This tool writes the full bundle to stdout. 

## Support

* PKCS7, PEM and DER formats
* LetsEncrypt

## Dependencies

* cryptography

## Python Support

* Python 2.7
* Python 3.5, 3.6, 3.7, 3.8, 3.9, 3.10

## Install

[Pypi](https://pypi.org/project/cert-chain-resolver/)


    $ pip install cert-chain-resolver


## Usage

### Installed using PIP

    $ cert_chain_resolver certificate.crt > bundle.crt

Or read from stdin

    $ cat certificate.crt | cert_chain_resolver > bundle.crt


### After cloning the repository

Install dependencies

    $ make

from file:

    $ python -m cert_chain_resolver.cli certificate.crt > bundle.crt

from stdin:

    $ cat certificate.crt | python -m cert_chain_resolver.cli > bundle.crt


## Development

bootstrap

    $ make

### Testing

Unit testing

    $ make tests

Re-run tests on file changes:

    $ make tests TEST_ARGS="-- -f"
