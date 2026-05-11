from cert_chain_resolver.resolver import resolve
from cert_chain_resolver.models import Cert
from cert_chain_resolver.castore.base_store import CAStore
from cryptography.x509 import Certificate
import pytest


def _patch_loaders(monkeypatch, mocker, cert_sequence, bundle_sequence=None):
    """Helper: stub both Cert.load (recursion) and load_bytes_to_x509_all (cross-sign scan).

    cert_sequence: certs returned by successive Cert.load(...) calls.
    bundle_sequence: lists of x509 objects returned by successive load_bytes_to_x509_all
        calls. Each list's first element matches the cert at the same recursion step.
        Defaults to single-cert bundles (1-element list of Certificate-spec mocks)
        which produce no cross-signs.
    """
    cert_mock = mocker.MagicMock(side_effect=list(cert_sequence))
    monkeypatch.setattr(Cert, "load", cert_mock)

    if bundle_sequence is None:
        bundle_sequence = [[mocker.Mock(spec=Certificate)] for _ in cert_sequence]
    monkeypatch.setattr(
        "cert_chain_resolver.resolver.load_bytes_to_x509_all",
        mocker.Mock(side_effect=bundle_sequence),
    )


def test_resolve_works_recursively(monkeypatch, mocker):
    leaf = mocker.Mock()
    intermediate = mocker.Mock()
    ca = mocker.Mock()
    ca.ca_issuer_access_location = None

    _patch_loaders(monkeypatch, mocker, [leaf, intermediate, ca])
    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=[b"intermediate", b"ca"]),
    )

    chain = resolve(b"hoi")
    assert list(chain) == [leaf, intermediate, ca]
    assert chain.cross_signs == []


@pytest.mark.parametrize("root_ca_store", [CAStore(), None])
def test_resolve_with_castore(monkeypatch, mocker, root_ca_store):
    leaf = mocker.Mock()
    leaf.is_root = False
    intermediate = mocker.Mock()
    intermediate.ca_issuer_access_location = None
    intermediate.is_root = False

    _patch_loaders(monkeypatch, mocker, [leaf, intermediate])
    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=[b"intermediate"]),
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

    _patch_loaders(monkeypatch, mocker, [leaf, leaf, leaf])
    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=[b"leaf", b"leaf"]),
    )

    chain = resolve(b"hoi")
    assert list(chain) == [leaf]


def test_resolve_records_cross_signs_from_aia_bundle(monkeypatch, mocker):
    """When the AIA bundle has siblings that pass the cross-sign predicate, they land in chain.cross_signs."""
    leaf = mocker.Mock()
    intermediate = mocker.Mock(is_root=False)
    intermediate.ca_issuer_access_location = None

    primary_x509 = mocker.Mock(spec=Certificate, name="primary_x509")
    cross_a_x509 = mocker.Mock(spec=Certificate, name="cross_a_x509")
    cross_b_x509 = mocker.Mock(spec=Certificate, name="cross_b_x509")

    _patch_loaders(
        monkeypatch,
        mocker,
        [leaf, intermediate],
        bundle_sequence=[[primary_x509, cross_a_x509, cross_b_x509]],
    )
    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=[b"bundle_bytes"]),
    )

    # Wrap x509 objects into identifiable Cert mocks; the .is_cross_sign_of side-effect
    # tells the resolver which ones to record.
    def fake_cert_ctor(x509_obj):
        wrapped = mocker.Mock(name="Cert(" + x509_obj._mock_name + ")")
        wrapped._x509 = x509_obj
        wrapped.is_cross_sign_of = lambda _primary: x509_obj in (
            cross_a_x509,
            cross_b_x509,
        )
        return wrapped

    monkeypatch.setattr(
        "cert_chain_resolver.resolver.Cert",
        mocker.Mock(load=Cert.load, side_effect=fake_cert_ctor),
    )

    chain = resolve(b"hoi")

    assert list(chain) == [leaf, intermediate]
    assert [c._x509 for c in chain.cross_signs] == [cross_a_x509, cross_b_x509]


def test_resolve_dedups_cross_signs_across_hops(monkeypatch, mocker):
    """A cross-sign seen on multiple AIA hops is recorded only once."""
    leaf = mocker.Mock()
    intermediate = mocker.Mock(is_root=False)
    root = mocker.Mock()
    root.ca_issuer_access_location = None

    primary1_x509 = mocker.Mock(spec=Certificate, name="primary1")
    primary2_x509 = mocker.Mock(spec=Certificate, name="primary2")
    cross_x509 = mocker.Mock(spec=Certificate, name="cross")

    _patch_loaders(
        monkeypatch,
        mocker,
        [leaf, intermediate, root],
        bundle_sequence=[[primary1_x509, cross_x509], [primary2_x509, cross_x509]],
    )
    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=[b"b1", b"b2"]),
    )

    wrapped_cross = mocker.Mock(name="Cert(cross)", fingerprint="cross-fp")
    wrapped_cross.is_cross_sign_of = lambda _primary: True

    def fake_cert_ctor(x509_obj):
        if x509_obj is cross_x509:
            return wrapped_cross
        wrapped = mocker.Mock(_x509=x509_obj)
        wrapped.is_cross_sign_of = lambda _primary: False
        return wrapped

    monkeypatch.setattr(
        "cert_chain_resolver.resolver.Cert",
        mocker.Mock(load=Cert.load, side_effect=fake_cert_ctor),
    )

    chain = resolve(b"hoi")

    assert chain.cross_signs == [wrapped_cross]
