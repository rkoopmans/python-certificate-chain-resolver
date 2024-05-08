from contextlib import closing

from cert_chain_resolver.models import CertificateChain, Cert

try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request  # type: ignore

try:
    unicode  # type: ignore
except NameError:
    unicode = str

try:
    from typing import Any, Optional
except ImportError:
    pass


def _download(url):
    # type: (str) -> Any
    req = Request(url, headers={"User-Agent": "Cert/fixer"})

    with closing(urlopen(req)) as resp:
        return resp.read()


def resolve(bytes_cert, _chain=None):
    # type: (bytes, Optional[CertificateChain]) -> CertificateChain
    """A recursive function that follows the CA issuer chain

    Args:
        bytes_cert: A DER/PKCS7/PEM certificate
        _chain: Chain to complete. Defaults to None.

    Returns:
        All resolved certificates in chain
    """
    cert = Cert.load(bytes_cert)

    if not _chain:
        _chain = CertificateChain()

    if cert in _chain:
        return _chain

    _chain += cert

    parent_cert = None
    if cert.ca_issuer_access_location:
        parent_cert = _download(cert.ca_issuer_access_location)

    if parent_cert:
        return resolve(parent_cert, _chain=_chain)

    return _chain
