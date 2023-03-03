from contextlib import closing

from cert_chain_resolver.models import CertificateChain, Cert

try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request

try:
    unicode
except NameError:
    unicode = str


def _download(url):
    req = Request(url, headers={"User-Agent": "Cert/fixer"})
    with closing(urlopen(req)) as resp:
        return resp.read()


def resolve(bytes_cert, _chain=None):
    """A recursive function that follows the CA issuer chain

    Args:
        bytes_cert (bytes): A DER/PKCS7/PEM certificate
        _chain (:py:class:`CertificateChain <CertificateChain>`, optional): Chain to complete. Defaults to None.

    Returns:
        :py:class:`CertificateChain <CertificateChain>`: All resolved certificates in chain
    """
    cert = Cert.load(bytes_cert)

    if not _chain:
        _chain = CertificateChain()

    _chain += cert

    parent_cert = None
    if cert.ca_issuer_access_location:
        parent_cert = _download(cert.ca_issuer_access_location)

    if parent_cert:
        return resolve(parent_cert, _chain=_chain)

    return _chain
