import pytest

from cert_chain_resolver.exceptions import ImproperlyFormattedCert
from .fixtures import TEST_CERTS_IN_VARIOUS_FORMATS
from cert_chain_resolver.utils import (
    load_ascii_to_x509,
    load_bytes_to_x509,
    load_bytes_to_x509_all,
    load_der_to_x509,
)
from cryptography.x509 import Certificate


@pytest.mark.parametrize("file_type,source_file", TEST_CERTS_IN_VARIOUS_FORMATS.items())
def test_load_bytes_to_x509(file_type, source_file):
    with open(source_file, "rb") as f:
        content = f.read()
        res = load_bytes_to_x509(content)
        assert isinstance(res, Certificate)


def test_load_other_text_raises():
    with pytest.raises(ImproperlyFormattedCert):
        load_bytes_to_x509(b"just text")


@pytest.mark.parametrize("file_type,source_file", TEST_CERTS_IN_VARIOUS_FORMATS.items())
def test_load_bytes_to_x509_all_returns_single_for_plain_cert(file_type, source_file):
    """Single-cert inputs (PEM, DER) and 1-cert P7Cs yield a 1-element list."""
    with open(source_file, "rb") as f:
        certs = load_bytes_to_x509_all(f.read())
    assert isinstance(certs, list)
    assert len(certs) == 1
    assert isinstance(certs[0], Certificate)


@pytest.mark.filterwarnings(
    "ignore:PKCS#7 certificates could not be parsed as DER:UserWarning"
)
def test_load_bytes_to_x509_all_extracts_all_from_p7c():
    """The Sectigo R46 P7C contains a self-signed root plus two cross-signs."""
    with open("tests/certs/ca/sectigo_r46.p7c", "rb") as f:
        certs = load_bytes_to_x509_all(f.read())
    assert len(certs) == 3
    for c in certs:
        assert isinstance(c, Certificate)
    # All three share the Subject "Sectigo Public Server Authentication Root R46".
    subjects = {c.subject.rfc4514_string() for c in certs}
    assert len(subjects) == 1
    # But the Issuers are distinct (self-signed + 2 cross-signers).
    issuers = {c.issuer.rfc4514_string() for c in certs}
    assert len(issuers) == 3


def test_load_bytes_to_x509_all_raises_on_junk():
    with pytest.raises(ImproperlyFormattedCert):
        load_bytes_to_x509_all(b"just text")


def test_load_ascii_to_x509_returns_first_cert():
    """The single-cert wrapper returns the first cert from a PEM input."""
    with open(TEST_CERTS_IN_VARIOUS_FORMATS["pem"], "rb") as f:
        res = load_ascii_to_x509(f.read())
    assert isinstance(res, Certificate)


def test_load_der_to_x509_returns_first_cert():
    """The single-cert wrapper returns the first cert from a DER input."""
    with open(TEST_CERTS_IN_VARIOUS_FORMATS["der"], "rb") as f:
        res = load_der_to_x509(f.read())
    assert isinstance(res, Certificate)
