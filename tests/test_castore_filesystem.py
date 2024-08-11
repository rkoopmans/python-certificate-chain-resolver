from cert_chain_resolver import __is_py3__
from cert_chain_resolver.exceptions import (
    CertificateChainResolverError,
    RootCertificateNotFound,
)
from cert_chain_resolver.models import Cert
from cert_chain_resolver.castore.file_system import FileSystemStore, eligible_paths
from tests.fixtures import BUNDLE_FIXTURES, certfixture_to_id
import tempfile
import pytest


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_find_root(bundle):
    intermediate, root = bundle[-2], bundle[-1]

    assert FileSystemStore().find_issuer(
        Cert.load(intermediate["cert_pem"])
    ) == Cert.load(root["cert_pem"])


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_custom_bundle_path_that_does_not_resolve_certs(bundle):
    intermediate, root = bundle[-2], bundle[-1]
    with tempfile.NamedTemporaryFile(suffix=".pem") as f:
        f.write(b"This file is almost empty..")

        store = FileSystemStore(f.name)
        assert store.path == f.name

        with pytest.raises(RootCertificateNotFound):
            store.find_issuer(Cert.load(intermediate["cert_pem"]))


def test_bundle_path_does_not_exist():
    with pytest.raises(CertificateChainResolverError):
        store = FileSystemStore("/tmp/addd/a/sd/df/g/h/j/x/vz/a/i-dont-exist.pem")


def test_bundle_path_cannot_be_found(monkeypatch):
    monkeypatch.setattr(
        "cert_chain_resolver.castore.file_system.eligible_paths",
        ["/tmp/i-do-not-exist"],
    )
    with pytest.raises(CertificateChainResolverError, match="Can't detect CA bundle"):
        FileSystemStore()
