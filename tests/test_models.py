from .fixtures import BUNDLE_FIXTURES, CERT_FIXTURES, certfixture_to_id
from cert_chain_resolver.models import Cert, CertificateChain
import pytest

try:
    unicode
except NameError:
    unicode = str


@pytest.mark.parametrize("cert", CERT_FIXTURES, ids=certfixture_to_id)
def test_certcontainer_x509_helper_props(cert):
    c = Cert(cert["cert_x509"])

    fixture = cert["meta"]
    assert fixture["issuer"] == c.issuer
    assert fixture["subject"] == c.subject
    assert fixture["common_name"] == c.common_name
    assert fixture["san"] == c.subject_alternative_names
    assert fixture["ca"] == c.is_ca
    assert fixture["serial"] == c.serial
    assert fixture["signature_algorithm"] == c.signature_hash_algorithm
    assert fixture["not_before"] == c.not_valid_before
    assert fixture["not_after"] == c.not_valid_after
    assert fixture["fingerprint_sha256"] == c.fingerprint
    assert fixture["ca_issuer_access_location"] == c.ca_issuer_access_location


@pytest.mark.parametrize(
    "_subject",
    ["CA - XD 9001", pytest.param("CN=github.com,O=GitHub", marks=[pytest.mark.xfail])],
)
def test_certcontainer_x509_is_root(_subject):
    class CertOverride(Cert):
        subject = _subject
        issuer = "CA - XD 9001"
        __init__ = lambda *_: None

    c = CertOverride(None)
    assert c.is_root == True


@pytest.mark.parametrize("cert", CERT_FIXTURES, ids=certfixture_to_id)
def test_certcontainer_x509_exports(cert):
    c = Cert(cert["cert_x509"])
    a = unicode(cert["cert_pem"], "ascii")
    b = c.export()

    assert a == b


def test_chaincontainer_props(mocker):
    leaf = mocker.MagicMock()
    leaf.is_ca = False
    intermediate1 = mocker.MagicMock()
    intermediate1.is_ca = True
    intermediate1.is_root = False
    intermediate2 = mocker.MagicMock()
    intermediate2.is_ca = True
    intermediate2.is_root = False
    root = mocker.MagicMock()
    root.is_ca = True
    root.is_root = True

    c = CertificateChain()
    for cert in [leaf, intermediate1, intermediate2, root]:
        c += cert

    assert leaf == c.leaf
    assert root == c.root
    assert [intermediate1, intermediate2] == list(c.intermediates)
    assert [leaf, intermediate1, intermediate2, root] == [x for x in c]
    assert [leaf, intermediate1, intermediate2, root] == list(c)
    assert 4 == len(c)


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_certificatechain_can_construct_from_pem(bundle):
    pem_bundle = b"".join([x['cert_pem'] for x in bundle])

    chain = CertificateChain.load_from_pem(pem_bundle)
    assert list(chain) == [Cert(x['cert_x509']) for x in bundle]


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_certificatechain_constructs_from_pem_in_order(bundle):
    pem_bundle = b"".join([x['cert_pem'] for x in reversed(bundle)])

    chain = CertificateChain.load_from_pem(pem_bundle)
    assert list(chain) == [Cert(x['cert_x509']) for x in bundle]