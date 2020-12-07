from io import StringIO
import pytest

from cert_chain_resolver.cli import cli
from .fixtures import TEST_CERTS

try:
    unicode
except NameError:
    unicode = str


@pytest.mark.parametrize("certdata", [x for x in TEST_CERTS])
def test_cert_returns_completed_chain(capsys, certdata):
    f = StringIO(unicode(certdata[0]["cert"]))

    cli(cert=f)

    captured = capsys.readouterr()
    assert captured.out == "\n".join([x["cert"] for x in certdata]) + "\n"
