import pytest
from cert_chain_resolver.castore.base_store import CAStore
from cert_chain_resolver.models import Cert


def test_find_issuer_candidates_needs_impl(mocker):
    m = mocker.Mock(spec=Cert)
    with pytest.raises(NotImplementedError):
        CAStore().find_issuer_candidates(m)
