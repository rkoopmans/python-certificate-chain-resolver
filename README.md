# Python certificate chain resolver

[![Licence](https://img.shields.io/badge/licence-MIT-blue.svg)](https://tldrlegal.com/license/mit-license)
[![CI](https://github.com/rkoopmans/python-certificate-chain-resolver/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/rkoopmans/python-certificate-chain-resolver/actions/workflows/ci-cd.yml)
[![Docs](https://readthedocs.org/projects/certificate-resolver/badge/?version=latest)](https://certificate-resolver.readthedocs.io/en/latest/)
[![codecov](https://codecov.io/github/rkoopmans/python-certificate-chain-resolver/graph/badge.svg?token=P2K55Z1KME)](https://codecov.io/github/rkoopmans/python-certificate-chain-resolver)
[![Downloads](https://static.pepy.tech/badge/cert-chain-resolver/week)](https://pepy.tech/project/cert-chain-resolver)
[![Python)](https://img.shields.io/pypi/pyversions/cert-chain-resolver.svg)](https://pypi.org/project/cert-chain-resolver/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/cert-chain-resolver)](https://pypi.org/project/cert-chain-resolver/)
[![PyPI](https://img.shields.io/pypi/v/cert-chain-resolver)](https://pypi.org/project/cert-chain-resolver/#history)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)


Resolve and obtain the complete certificate chain from the leaf, intermediate(s) to the root of a x509 certificate using the CLI or the python API. 

The library provides an easy to use API to access each property of a certificate chain and the important metadata of a certificate. The library also exposes a CLI for resolving and inspecting certificate chains from the command line.

## Support

* PKCS7, PEM and DER formats
* LetsEncrypt certificates
* Including the root certificate using the system CA bundle or custom bundle
* Python2 (but not for much longer..)

## Installation

[Pypi package](https://pypi.org/project/cert-chain-resolver/)

    $ pip install cert-chain-resolver


## CLI Usage

For more options and examples see the [read the docs](https://certificate-resolver.readthedocs.io/en/latest/cli_usage.html) or pass the --help flag.

The bundle gets written to stdout and the chain information to stderr.

### from source:

    $ python -m cert_chain_resolver.cli --include-root certificate.crt > bundle.crt
    $ cat certificate.crt | python -m cert_chain_resolver.cli --include-root > bundle.crt

### from PIP
```
 $ cert_chain_resolver --include-root certificate.crt > bundle.crt
 1. <Cert common_name="github.com" subject="CN=github.com,O=GitHub\, Inc.,L=San Francisco,ST=California,C=US" issuer="CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US">
 2. <Cert common_name="DigiCert SHA2 High Assurance Server CA" subject="CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US" issuer="CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US">
 3. <Cert common_name="DigiCert High Assurance EV Root CA" subject="CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US" issuer="CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US">
```

## Python API

Make sure to read the [documentation](https://certificate-resolver.readthedocs.io/en/latest/api.html) for more examples and options.
```
from cert_chain_resolver.api import resolve

with open('cert.pem', 'rb') as f:
   fb = f.read()
   chain = resolve(fb)
>>>
for cert in chain:
  print(cert)
  print(cert.export())  # Export the certificate in PEM format

<Cert common_name="cert-chain-resolver.remcokoopmans.com" subject="CN=cert-chain-resolver.remcokoopmans.com" issuer="CN=R3,O=Let's Encrypt,C=US">
"-----BEGIN CERTIFICATE-----...."
<Cert common_name="R3" subject="CN=R3,O=Let's Encrypt,C=US" issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">
"-----BEGIN CERTIFICATE-----...."
<Cert common_name="DST Root CA X3" subject="CN=DST Root CA X3,O=Digital Signature Trust Co." issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">
"-----BEGIN CERTIFICATE-----...."
```

## Dependencies

* cryptography


### After cloning the repository

Install dependencies

    $ make

## Development

bootstrap

    $ make

### Testing

Unit testing

    $ make tests

Re-run tests on file changes:

    $ make tests TEST_ARGS="-- -f"

### Formatting

    $ make format