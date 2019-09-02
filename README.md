# Resolve certificate chains

Still in development

## Dependencies

* cryptography
* pyOpenSSL

## Install

[Pypi](https://pypi.org/project/cert-chain-resolver/)


    $ pip install cert-chain-resolver


## Usage

from file:

    $ python -m cert_chain_resolver.cli certificate.crt > bundle.crt

from stdin:

    $ cat certificate.crt | python -m cert_chain_resolver.cli > bundle.crt


## Development

bootstrap

    $ make

## Todo

* support cross signed certificates, currently it only processes the first in a bundle
* Verbose mode
* More CLI flags
* Unit tests
* Pretty print detailed output
