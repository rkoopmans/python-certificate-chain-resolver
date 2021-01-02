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
    cli(file_bytes=bundle[0]["cert_pem"])

    captured = unicode(capsys.readouterr().out)
    expected = "".join([unicode(x["cert_pem"], "ascii") for x in bundle])
    assert captured == expected


def test_display_flag_is_properly_formatted(capsys):
    bundle = BUNDLE_FIXTURES[0]
    cli(file_bytes=bundle[0]["cert_pem"], show_details=True)

    captured = unicode(capsys.readouterr().out)

    expected = unicode(
        """== Certificate #1 ==
Subject:            CN=github.com,O=GitHub\\, Inc.,L=San Francisco,ST=California,C=US
Issuer:             CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
NotBefore:          2020-05-05T00:00:00
NotAfter:           2022-05-10T12:00:00
Serial:             7101927171473588541993819712332065657
Sha256Fingeprint:   b6b9a6af3e866cbe0e6a307e7dda173b372b2d3ac3f06af15f97718773848008
CAIssuerLoc:        http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
Is root:            False
Is CA:              False
Domains:
  Common name:      github.com
  SANExtensions:
    github.com
    www.github.com

== Certificate #2 ==
Subject:            CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Issuer:             CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
NotBefore:          2013-10-22T12:00:00
NotAfter:           2028-10-22T12:00:00
Serial:             6489877074546166222510380951761917343
Sha256Fingeprint:   19400be5b7a31fb733917700789d2f0a2471c0c9d506c0e504c06c16d7cb17c0

Is root:            False
Is CA:              True
Domains:
  Common name:      DigiCert SHA2 High Assurance Server CA

"""
    )

    assert expected == captured
