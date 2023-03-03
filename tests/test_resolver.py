from cert_chain_resolver.resolver import resolve
from cert_chain_resolver.models import Cert


def test_resolve_works_recursively(monkeypatch, mocker):
    leaf = mocker.Mock()
    intermediate = mocker.Mock()
    ca = mocker.Mock()
    ca.ca_issuer_access_location = None

    resolve_mock = mocker.MagicMock()
    resolve_mock.side_effect = [leaf, intermediate, ca]
    monkeypatch.setattr(Cert, 'load', resolve_mock)

    monkeypatch.setattr(
        "cert_chain_resolver.resolver._download",
        mocker.Mock(side_effect=["intermediate", "ca"]),
    )

    chain = resolve(b"hoi")
    assert list(chain) == [leaf, intermediate, ca]
