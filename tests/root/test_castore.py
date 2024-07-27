from cert_chain_resolver import __is_py3__
from cert_chain_resolver.models import Cert
from tests.fixtures import BUNDLE_FIXTURES, certfixture_to_id
import pytest

if not __is_py3__:
    pytest.skip(allow_module_level=True)


@pytest.fixture(scope="module")
def store():
    from cert_chain_resolver.root import certifi

    return certifi.CertifiStore()


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_find_root(bundle, store):
    intermediate, root = bundle[-2], bundle[-1]

    assert store.find_issuer(Cert.load(intermediate["cert_pem"])) == Cert.load(
        root["cert_pem"]
    )
