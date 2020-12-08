from io import StringIO
import pytest

from cert_chain_resolver.cli import cli
from .fixtures import CERT_FIXTURES, BUNDLE_FIXTURES, certfixture_to_id

try:
    unicode
except NameError:
    unicode = str


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_cert_returns_completed_chain(capsys, bundle):
    f = StringIO(unicode(bundle[0]["cert_pem"]))

    cli(cert=f)

    captured = unicode(capsys.readouterr().out)
    expected = unicode("".join([x["cert_pem"] for x in bundle]))
    assert captured == expected
