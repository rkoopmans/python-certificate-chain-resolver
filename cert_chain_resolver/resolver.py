from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import backend as OpenSSLBackend
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from contextlib import closing
import logging
import binascii
import six

try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request

log = logging.getLogger(__name__)


class UnsuportedCertificateType(Exception):
    pass


class CertContainer(object):
    x509 = None
    details = None

    def __init__(self, x509, details):
        self.x509 = x509
        self.details = details

    def export(self, encoding=Encoding.PEM):
        return self.x509.public_bytes(encoding)


class Resolver:
    def __init__(self, cert, content_type=None):
        try:
            if cert.startswith("-----BEGIN CERTIFICATE-----"):
                log.debug("Loading file with content_type pem")
                self.cert = x509.load_pem_x509_certificate(bytes(cert), OpenSSLBackend)
            else:
                log.debug("Loading file with content_type {0}".format(content_type))
                self.cert = x509.load_der_x509_certificate(bytes(cert), OpenSSLBackend)
        except ValueError:
            raise UnsuportedCertificateType("Failed to load cert with content_type={0}".format(content_type))

    def get_details(self):
        return {
            "issuer": self.cert.issuer.rfc4514_string(),
            "subject": self.cert.subject.rfc4514_string(),
            "fingerprint_sha256": self.fingerprint(),
            "signature_algorithm": self.cert.signature_hash_algorithm.name,
            "serial": self.cert.serial_number,
            "not_before": self.cert.not_valid_before,
            "not_after": self.cert.not_valid_after,
            "san": self._get_san(),
            "ca": self._is_ca(),
        }

    def get_parent_cert(self):
        aias = self.cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for aia in aias.value:
            if AuthorityInformationAccessOID.CA_ISSUERS == aia.access_method:
                return self._download(aia.access_location.value)
        return (None, None)

    def fingerprint(self, _hash=hashes.SHA256):
        binary = self.cert.fingerprint(_hash())
        txt = binascii.hexlify(binary)
        if six.PY3:
            txt = txt.decode('ascii')
        return txt

    def _is_ca(self):
        ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        return ext.value.ca

    def _get_san(self):
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return ext.value.get_values_for_type(x509.DNSName)
        except x509.extensions.ExtensionNotFound:
            return None

    def _download(self, url):
        req = Request(url, headers={"User-Agent": "Cert/fixer"})
        log.debug("Downloading: {0}".format(url))
        with closing(urlopen(req)) as resp:
            content_type = resp.headers.getheader("Content-Type", "").split("/", 1)[-1]
            return content_type, resp.read()


class ChainResolver:

    _chain = None
    depth = None

    def __init__(self, depth=None):
        self._chain = []
        self.depth = depth

    def resolve(self, cert, content_type=None):
        r = Resolver(cert, content_type)
        self._chain.append(CertContainer(x509=r.cert, details=r.get_details()))

        if (self.depth is None or len(self._chain) <= self.depth):
            content_type, parent_cert = r.get_parent_cert()
            if parent_cert:
                return self.resolve(parent_cert, content_type=content_type)

    def list(self):
        return self._chain
