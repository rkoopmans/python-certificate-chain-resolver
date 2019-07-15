# Resolve certificate chains

Still in development

*Note:* pkcs7 is not supported and it will fail to parse the letsencrypt root certificate.

## Dependencies

* cryptography

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

* support pkcs7 
* Verbose mode
* More CLI flags
* Unit tests
* Pretty print detailed output
