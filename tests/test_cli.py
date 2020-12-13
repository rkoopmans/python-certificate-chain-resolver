from io import BytesIO
import pytest

from cert_chain_resolver.cli import cli
from .fixtures import CERT_FIXTURES, BUNDLE_FIXTURES, certfixture_to_id

try:
    unicode
except NameError:
    unicode = str


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_cert_returns_completed_chain(capsys, bundle):
    cli(source=bundle[0]["cert_pem"])

    captured = unicode(capsys.readouterr().out)
    expected = "".join([unicode(x["cert_pem"], "ascii") for x in bundle])
    assert captured == expected
