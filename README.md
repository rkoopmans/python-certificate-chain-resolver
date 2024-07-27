# Python certificate chain resolver

[![Licence](https://img.shields.io/badge/licence-MIT-blue.svg)](https://tldrlegal.com/license/mit-license)
[![CI](https://github.com/rkoopmans/python-certificate-chain-resolver/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/rkoopmans/python-certificate-chain-resolver/actions/workflows/ci-cd.yml)
[![Docs](https://readthedocs.org/projects/certificate-resolver/badge/?version=latest)](https://certificate-resolver.readthedocs.io/en/latest/)
[![Downloads](https://static.pepy.tech/personalized-badge/cert-chain-resolver?period=total&units=international_system&left_color=black&right_color=blue&left_text=Downloads)](https://pepy.tech/project/cert-chain-resolver)
[![Python)](https://img.shields.io/pypi/pyversions/cert-chain-resolver.svg)](https://pypi.org/project/cert-chain-resolver/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/cert-chain-resolver)](https://pypi.org/project/cert-chain-resolver/)
[![PyPI](https://img.shields.io/pypi/v/cert-chain-resolver)](https://pypi.org/project/cert-chain-resolver/#history)


Resolve / obtain the certificate intermediates and root of a x509 certificate using the CLI or python API. The CLI provides easy access to a certificate bundle and its metadata while the Python API can be used to inspect, iterate and complete certificate bundles.

```
from cert_chain_resolver.api import resolve
from cert_chain_resolver.root.certifi import CertifiStore

with open('cert.pem', 'rb') as f:
   fb = f.read()
   chain = resolve(fb, include_root=True, root_ca_store=CertifiStore())
>>>
for cert in chain:
  print(cert)
<Cert common_name="cert-chain-resolver.remcokoopmans.com" subject="CN=cert-chain-resolver.remcokoopmans.com" issuer="CN=R3,O=Let's Encrypt,C=US">
<Cert common_name="R3" subject="CN=R3,O=Let's Encrypt,C=US" issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">
<Cert common_name="DST Root CA X3" subject="CN=DST Root CA X3,O=Digital Signature Trust Co." issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">
```

## Support

* PKCS7, PEM and DER formats
* LetsEncrypt certificates
* Resolving the root certificate through a CA Bundle

## Dependencies

* cryptography

## Documentation

Read more on [readthedocs](https://certificate-resolver.readthedocs.io/en/latest/)

## Install

[Pypi](https://pypi.org/project/cert-chain-resolver/)



Core package

    $ pip install cert-chain-resolver


With certifi support for finding the matching root certificate

    $ pip install cert-chain-resolver[certifi]


## Usage

### Installed using PIP

Resolve without helpers, just the leaf and intermediates:

    $ cert_chain_resolver certificate.crt > bundle.crt

Resolve complete chain up to the root:

    $ cert_chain_resolver certificate.crt --include-root --use-store-certifi > bundle.crt

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
