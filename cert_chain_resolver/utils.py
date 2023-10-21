from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cert_chain_resolver.exceptions import ImproperlyFormattedCert

try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from cert_chain_resolver.models import Cert

except ImportError:
    pass


def load_ascii_to_x509(bytes_input):
    # type: (bytes) -> x509.Certificate
    """Converts ASCII PKCS7 or Certificate to a :py:class:`cryptography.x509.Certificate` object"""
    first_line = bytes_input.decode("ascii").splitlines()[0]
    if first_line == "-----BEGIN PKCS7-----":
        return pkcs7.load_pem_pkcs7_certificates(bytes_input)[0]
    elif first_line == "-----BEGIN CERTIFICATE-----":
        return x509.load_pem_x509_certificate(bytes_input)
    raise ImproperlyFormattedCert("Cert can not be read! It is not a valid PEM")


def load_der_to_x509(bytes_input):
    # type: (bytes) -> x509.Certificate
    """Converts bytes formatted DER (PKCS7 or Cert) to :py:class:`cryptography.x509.Certificate` object"""
    try:
        return x509.load_der_x509_certificate(bytes_input)
    except ValueError:
        return pkcs7.load_der_pkcs7_certificates(bytes_input)[0]


def load_bytes_to_x509(bytes_input):
    # type: (bytes) -> x509.Certificate
    """Converts Certificate / PKCS7 in ASCII or DER to :py:class:`cryptography.x509.Certificate` object"""
    try:
        return load_ascii_to_x509(bytes_input)
    except UnicodeDecodeError:
        return load_der_to_x509(bytes_input)
