from cryptography import x509
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_pem_pkcs7_certificates,
    load_der_pkcs7_certificates,
)
from cert_chain_resolver.exceptions import ImproperlyFormattedCert


def load_ascii_to_x509(bytes_input, ascii_input):
    first_line = ascii_input.splitlines()[0]
    if first_line == "-----BEGIN PKCS7-----":
        return load_pem_pkcs7_certificates(bytes_input)[0]
    elif first_line == "-----BEGIN CERTIFICATE-----":
        return x509.load_pem_x509_certificate(bytes_input)
    raise ImproperlyFormattedCert("Cert can not be read! It is not a valid PEM")


def load_der_to_x509(bytes_input):
    try:
        return x509.load_der_x509_certificate(bytes_input)
    except ValueError:
        return load_der_pkcs7_certificates(bytes_input)[0]


def load_bytes_to_x509(bytes_input):
    try:
        pem = bytes_input.decode("ascii")
        return load_ascii_to_x509(bytes_input, pem)
    except UnicodeDecodeError:
        return load_der_to_x509(bytes_input)
