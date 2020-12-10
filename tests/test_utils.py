import pytest
from .fixtures import TEST_CERTS_IN_VARIOUS_FORMATS
from cert_chain_resolver.utils import load_bytes_to_x509
from cert_chain_resolver.models import Cert


@pytest.mark.parametrize("file_type,source_file", TEST_CERTS_IN_VARIOUS_FORMATS.items())
def test_load_bytes_to_x509(file_type, source_file):
    with open(source_file, "rb") as f:
        content = f.read()
        res = load_bytes_to_x509(content)
        assert res.__class__ == Cert
