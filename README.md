# Python certificate chain resolver

[![Licence](https://img.shields.io/badge/licence-MIT-blue.svg)](https://tldrlegal.com/license/mit-license)
![Build](https://github.com/rkoopmans/python-certificate-chain-resolver/workflows/CI%20tests/badge.svg?branch=master)
[![Docs](https://readthedocs.org/projects/certificate-resolver/badge/?version=latest)](https://certificate-resolver.readthedocs.io/en/latest/)
[![Downloads](https://static.pepy.tech/personalized-badge/cert-chain-resolver?period=total&units=international_system&left_color=black&right_color=blue&left_text=Downloads)](https://pepy.tech/project/cert-chain-resolver)
![Python)](https://img.shields.io/pypi/pyversions/cert-chain-resolver.svg)


Resolve / obtain the certificate intermediates of a x509 certificate. This tool writes the full bundle to stdout. 

## Support

* PKCS7, PEM and DER formats
* LetsEncrypt certificates

## Dependencies

* cryptography

## Documentation

Read more on [readthedocs](https://certificate-resolver.readthedocs.io/en/latest/)

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

### Print the details of each certificate in resolved chain

    $ cert_chain_resolver cert.pem --info

## Development

bootstrap

    $ make

### Testing

Unit testing

    $ make tests

Re-run tests on file changes:

    $ make tests TEST_ARGS="-- -f"
