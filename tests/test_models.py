from cert_chain_resolver.exceptions import MissingCertProperty
from .fixtures import BUNDLE_FIXTURES, CERT_FIXTURES, certfixture_to_id
from cryptography import x509
from cert_chain_resolver.models import Cert, CertificateChain
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, NameOID
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature
from ._utils import make_utc_aware_if_cryptography_above_42

try:
    from contextlib import nullcontext as does_not_raise
except ImportError:
    from contextlib import contextmanager

    @contextmanager  # type: ignore[no-redef]
    def does_not_raise():
        yield


try:
    unicode  # type: ignore
except NameError:
    unicode = str


@pytest.fixture
def mock_x509(mocker):
    return mocker.Mock(spec=x509.Certificate)


@pytest.fixture
def mock_cert(mocker, mock_x509):
    cert = mocker.Mock(spec=Cert)
    cert._x509 = mock_x509
    return cert


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
    assert (
        make_utc_aware_if_cryptography_above_42(fixture["not_before"])
        == c.not_valid_before
    )
    assert (
        make_utc_aware_if_cryptography_above_42(fixture["not_after"])
        == c.not_valid_after
    )
    assert fixture["fingerprint_sha256"] == c.fingerprint
    assert fixture["ca_issuer_access_location"] == c.ca_issuer_access_location


def test_cert_constructor_requires_x509():
    with pytest.raises(TypeError, match="Argument must be a x509"):
        Cert("not a x509 obj")


def test_cert__eq__not_impl(mocker):
    assert (
        Cert(mocker.Mock(spec=x509.Certificate)).__eq__("Not a Cert") == NotImplemented
    )


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
    pem_bundle = b"".join([x["cert_pem"] for x in bundle])

    chain = CertificateChain.load_from_pem(pem_bundle)
    assert list(chain) == [Cert(x["cert_x509"]) for x in bundle]


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_certificatechain_constructs_from_pem_in_order(bundle):
    pem_bundle = b"".join([x["cert_pem"] for x in reversed(bundle)])

    chain = CertificateChain.load_from_pem(pem_bundle)
    assert list(chain) == [Cert(x["cert_x509"]) for x in bundle]


@pytest.mark.parametrize(
    "prop,extension_oid,expected",
    [
        ("ca_issuer_access_location", ExtensionOID.AUTHORITY_INFORMATION_ACCESS, None),
        ("subject_alternative_names", ExtensionOID.SUBJECT_ALTERNATIVE_NAME, []),
        ("is_ca", ExtensionOID.BASIC_CONSTRAINTS, False),
    ],
)
def test_missing_cert_extensions_return_defaults_when_missing(
    mocker, prop, extension_oid, expected
):
    m = mocker.Mock(spec=x509.Certificate)
    mock_extensions = mocker.Mock()
    mock_extensions.get_extension_for_oid.side_effect = (
        x509.extensions.ExtensionNotFound("Extension not found", extension_oid)
    )
    m.extensions = mock_extensions
    c = Cert(m)
    assert getattr(c, prop) == expected


@pytest.mark.parametrize(
    "prop,cert_prop, cert_value",
    [
        ("signature_hash_algorithm", "signature_hash_algorithm", None),
        (
            "common_name",
            "subject",
            lambda m: m.Mock(get_attributes_for_oid=m.Mock(return_value=[])),
        ),
    ],
)
def test_missing_cert_properties_raise(mocker, prop, cert_prop, cert_value):
    m = mocker.Mock(spec=x509.Certificate)
    if callable(cert_value):
        setattr(m, cert_prop, cert_value(mocker))
    else:
        setattr(m, cert_prop, cert_value)
    c = Cert(m)

    with pytest.raises(MissingCertProperty):
        getattr(c, prop)


@pytest.mark.parametrize(
    "value,expectation",
    [
        (b"Common name", does_not_raise()),
        (unicode("Common name"), does_not_raise()),
        (["unexpected type"], pytest.raises(ValueError)),
    ],
)
def test_common_name_handles_unicode_or_bytes(mocker, value, expectation):
    m = mocker.Mock(
        spec=x509.Certificate,
        subject=mocker.Mock(
            get_attributes_for_oid=mocker.Mock(
                return_value=[mocker.Mock(spec=type(value), value=value)]
            )
        ),
    )
    with expectation:
        c = Cert(m)
        assert c.common_name == "Common name"


def test_repr():
    class CertOverride(Cert):
        subject = "Subject"
        issuer = "Issuer"
        common_name = "CN"
        __init__ = lambda *_: None

    c = CertOverride()

    assert repr(c) == '<Cert common_name="CN" subject="Subject" issuer="Issuer">'


@pytest.mark.parametrize(
    "key_type,expected",
    [
        (RSAPublicKey, True),
        (RSAPublicKey, False),
        (EllipticCurvePublicKey, True),
        (EllipticCurvePublicKey, False),
        (object, False),  # Unexpected key type FIXME: Maybe this should raise??
    ],
)
def test_is_issued_by_handles_different_keys(
    mocker, mock_x509, mock_cert, key_type, expected
):
    mock_public_key = mocker.Mock(spec=key_type)
    mock_x509.public_key.return_value = mock_public_key
    mock_x509.signature_hash_algorithm = mocker.Mock(spec=hashes.SHA256)

    subject = Cert(mock_x509)

    if not expected and hasattr(key_type, "verify"):
        mock_public_key.verify.side_effect = InvalidSignature()

    assert subject.is_issued_by(mock_cert) is expected


def test_is_issued_raises_when_no_signature_hash_algo(mock_x509, mock_cert):
    mock_x509.signature_hash_algorithm = None
    mock_x509.public_key = lambda: None
    with pytest.raises(MissingCertProperty):
        Cert(mock_x509).is_issued_by(mock_cert)


def _load_sectigo_p7c_certs():
    from cryptography.hazmat.primitives.serialization import pkcs7

    with open("tests/certs/ca/sectigo_r46.p7c", "rb") as f:
        return list(pkcs7.load_der_pkcs7_certificates(f.read()))


@pytest.mark.filterwarnings(
    "ignore:PKCS#7 certificates could not be parsed as DER:UserWarning"
)
def test_public_key_fingerprint_matches_across_cross_signs():
    """Self-signed root and its cross-signs share the same Subject Public Key Info."""
    x509_certs = _load_sectigo_p7c_certs()
    fps = {Cert(c).public_key_fingerprint for c in x509_certs}
    assert len(fps) == 1


def test_public_key_fingerprint_differs_for_unrelated_cert(pem_github):
    """Different identities yield different SPKI fingerprints."""
    from cryptography import x509

    leaf = Cert(x509.load_pem_x509_certificate(pem_github[0]["cert"].encode("ascii")))
    intermediate = Cert(
        x509.load_pem_x509_certificate(pem_github[1]["cert"].encode("ascii"))
    )
    assert leaf.public_key_fingerprint != intermediate.public_key_fingerprint


def test_is_cross_sign_of():
    """Same Subject + same SPKI + distinct cert is a cross-sign; everything else is not."""

    def make(_subject, _spki, _fp):
        class _C(Cert):
            subject = _subject
            public_key_fingerprint = _spki
            fingerprint = _fp
            __init__ = lambda self: None

        return _C()

    primary = make("CN=Root", "spki1", "fp1")
    cross_sign = make("CN=Root", "spki1", "fp2")
    same_subject_different_key = make("CN=Root", "spki2", "fp3")
    different_subject = make("CN=Other", "spki1", "fp4")

    assert cross_sign.is_cross_sign_of(primary) is True
    assert same_subject_different_key.is_cross_sign_of(primary) is False
    assert different_subject.is_cross_sign_of(primary) is False
    assert primary.is_cross_sign_of(primary) is False  # not its own cross-sign


def test_chain_cross_signs_default_empty(mocker):
    chain = CertificateChain()
    assert chain.cross_signs == []


def test_chain_add_cross_sign_appends_and_dedups(mocker):
    chain = CertificateChain()
    cross = mocker.MagicMock(fingerprint="fp1")
    cross_dup = mocker.MagicMock(fingerprint="fp1")
    cross_other = mocker.MagicMock(fingerprint="fp2")

    chain.add_cross_sign(cross)
    chain.add_cross_sign(cross_dup)  # same fingerprint, ignored
    chain.add_cross_sign(cross_other)

    assert chain.cross_signs == [cross, cross_other]


def test_chain_cross_signs_dont_pollute_intermediates(mocker):
    """Cross-signs look like CA intermediates structurally but must not appear in .intermediates."""
    leaf = mocker.MagicMock(is_ca=False, is_root=False)
    intermediate = mocker.MagicMock(is_ca=True, is_root=False)
    root = mocker.MagicMock(is_ca=True, is_root=True)
    cross = mocker.MagicMock(is_ca=True, is_root=False, fingerprint="cross-fp")

    chain = CertificateChain()
    chain += leaf
    chain += intermediate
    chain += root
    chain.add_cross_sign(cross)

    assert list(chain.intermediates) == [intermediate]
    assert list(chain) == [leaf, intermediate, root]
    assert chain.cross_signs == [cross]


def test_chain_cross_signs_returns_copy(mocker):
    """Mutating the returned list must not affect the chain's internal state."""
    chain = CertificateChain()
    cross = mocker.MagicMock(fingerprint="fp1")
    chain.add_cross_sign(cross)

    out = chain.cross_signs
    out.append("garbage")

    assert chain.cross_signs == [cross]
