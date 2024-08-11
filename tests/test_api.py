from cert_chain_resolver import api
import pytest
from cert_chain_resolver.resolver import resolve
from cert_chain_resolver.models import CertificateChain, Cert
from cert_chain_resolver.castore.file_system import FileSystemStore


@pytest.mark.parametrize(
    "exported,obj",
    [
        ("resolve", resolve),
        ("CertificateChain", CertificateChain),
        ("Cert", Cert),
        ("FileSystemStore", FileSystemStore),
    ],
)
def test_api_exports_right_objects(exported, obj):
    assert getattr(api, exported) == obj
