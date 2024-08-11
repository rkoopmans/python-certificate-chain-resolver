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
    from cert_chain_resolver.castore.base_store import CAStore
except ImportError:  # pragma: no cover
    pass


def _download(url):
    # type: (str) -> Any
    req = Request(url, headers={"User-Agent": "Cert/fixer"})

    with closing(urlopen(req)) as resp:
        return resp.read()


def resolve(bytes_cert, _chain=None, root_ca_store=None):
    # type: (bytes, Optional[CertificateChain], Optional[CAStore]) -> CertificateChain
    """A recursive function that follows the CA issuer chain

    Args:
        bytes_cert: A DER/PKCS7/PEM certificate
        _chain: Chain to complete. Defaults to None.
        root_ca_store: A CAStore to use for completing the chain with a root certificate in case
            the intermediates do not provide a location

    Returns:
        All resolved certificates in chain
    """
    cert = Cert.load(bytes_cert)

    if not _chain:
        _chain = CertificateChain()

    if cert in _chain:
        # Prevent recursion in case the cert is self-referential
        return _chain

    _chain += cert

    parent_cert = None
    if cert.ca_issuer_access_location:
        parent_cert = _download(cert.ca_issuer_access_location)

    if parent_cert:
        return resolve(parent_cert, _chain=_chain, root_ca_store=root_ca_store)
    elif not _chain.root and root_ca_store:
        _chain += root_ca_store.find_issuer(cert)

    return _chain
