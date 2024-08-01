from cert_chain_resolver.resolver import resolve
from cert_chain_resolver.models import Cert
from cert_chain_resolver.castore.base_store import CAStore
import pytest


def test_resolve_works_recursively(monkeypatch, mocker):
    leaf = mocker.Mock()
    intermediate = mocker.Mock()
    ca = mocker.Mock()
    ca.ca_issuer_access_location = None

    resolve_mock = mocker.MagicMock()
    resolve_mock.side_effect = [leaf, intermediate, ca]
    monkeypatch.setattr(Cert, "load", resolve_mock)

    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=["intermediate", "ca"]),
    )

    chain = resolve(b"hoi")
    assert list(chain) == [leaf, intermediate, ca]


@pytest.mark.parametrize("root_ca_store", [CAStore(), None])
def test_resolve_with_castore(monkeypatch, mocker, root_ca_store):
    leaf = mocker.Mock()
    leaf.is_root = False
    intermediate = mocker.Mock()
    intermediate.ca_issuer_access_location = None
    intermediate.is_root = False

    resolve_mock = mocker.MagicMock()
    resolve_mock.side_effect = [leaf, intermediate]
    monkeypatch.setattr(Cert, "load", resolve_mock)

    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=["intermediate"]),
    )
    if root_ca_store:
        ca = mocker.Mock()
        monkeypatch.setattr(root_ca_store, "find_issuer", lambda x: ca)
        chain = resolve(b"hoi", root_ca_store=root_ca_store)
        assert list(chain) == [leaf, intermediate, ca]
    else:
        chain = resolve(b"hoi", root_ca_store=None)
        assert list(chain) == [leaf, intermediate]


def test_resolve_works_avoid_infinite_recursion(monkeypatch, mocker):
    """Ensure that a certificate with refences to itself can be resolved correctly"""
    leaf = mocker.Mock()

    resolve_mock = mocker.MagicMock()
    resolve_mock.side_effect = [leaf, leaf, leaf]
    monkeypatch.setattr(Cert, "load", resolve_mock)

    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=["leaf", "leaf"]),
    )

    chain = resolve(b"hoi")
    assert list(chain) == [leaf]
