import importlib
import sys
from tempfile import NamedTemporaryFile
import pytest
from cert_chain_resolver import __is_py3__

from cert_chain_resolver.cli import cli, main, parse_args
from cert_chain_resolver.castore.file_system import FileSystemStore
from tests._utils import CRYPTOGRAPHY_MAJOR
from .fixtures import BUNDLE_FIXTURES, certfixture_to_id

try:
    unicode  # type: ignore
except NameError:
    unicode = str


@pytest.mark.parametrize(
    "cli_args, expected",
    [
        (
            [],
            {
                "file_name": "-",
                "info": False,
                "include_root": False,
                "include_cross_signs": False,
                "ca_bundle_path": None,
            },
        ),
        (
            ["test.crt"],
            {
                "file_name": "test.crt",
                "info": False,
                "include_root": False,
                "include_cross_signs": False,
                "ca_bundle_path": None,
            },
        ),
        (
            ["-i"],
            {
                "file_name": "-",
                "info": True,
                "include_root": False,
                "include_cross_signs": False,
                "ca_bundle_path": None,
            },
        ),
        (
            ["--include-root"],
            {
                "file_name": "-",
                "info": False,
                "include_root": True,
                "include_cross_signs": False,
                "ca_bundle_path": None,
            },
        ),
        (
            ["--include-cross-signs"],
            {
                "file_name": "-",
                "info": False,
                "include_root": False,
                "include_cross_signs": True,
                "ca_bundle_path": None,
            },
        ),
        (
            ["--ca-bundle-path", "/path/to/ca/bundle"],
            {
                "file_name": "-",
                "info": False,
                "include_root": False,
                "include_cross_signs": False,
                "ca_bundle_path": "/path/to/ca/bundle",
            },
        ),
        (
            [
                "test.crt",
                "-i",
                "--include-root",
                "--include-cross-signs",
                "--ca-bundle-path",
                "/path/to/ca/bundle",
            ],
            {
                "file_name": "test.crt",
                "info": True,
                "include_root": True,
                "include_cross_signs": True,
                "ca_bundle_path": "/path/to/ca/bundle",
            },
        ),
    ],
)
def test_parse_args(cli_args, expected, monkeypatch):
    monkeypatch.setattr("sys.argv", ["script_name"] + cli_args)

    args = parse_args()

    assert args.file_name == expected["file_name"]
    assert args.info == expected["info"]
    assert args.include_root == expected["include_root"]
    assert args.include_cross_signs == expected["include_cross_signs"]
    assert args.ca_bundle_path == expected["ca_bundle_path"]


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_cert_returns_completed_chain(capsys, bundle):
    cli(file_bytes=bundle[0]["cert_pem"])

    out, err = capsys.readouterr()
    stdout, stderr = unicode(out), unicode(err)
    expected = "".join(
        [unicode(x["cert_pem"], "ascii") for x in bundle if x["type"] != "root"]
    )
    assert stdout == expected


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_cert_returns_completed_chain_with_root(capsys, bundle):
    cli(file_bytes=bundle[0]["cert_pem"], include_root=True)

    out, err = capsys.readouterr()
    stdout, stderr = unicode(out), unicode(err)

    valid_bundle = []
    for cert in bundle:
        valid_bundle.append(cert)
        if cert["meta"]["ca_issuer_access_location"] is None:
            break  # stop processing, as we cant continue resolving without a helper!

    expected = "".join([unicode(x["cert_pem"], "ascii") for x in valid_bundle])
    assert stdout == expected


@pytest.mark.parametrize("bundle", BUNDLE_FIXTURES, ids=certfixture_to_id)
def test_cert_returns_completed_chain_with_root_resolved_through_ca_store(
    capsys, bundle
):
    cli(
        file_bytes=bundle[0]["cert_pem"],
        include_root=True,
        root_ca_store=FileSystemStore(),
    )

    out, err = capsys.readouterr()
    stdout, stderr = unicode(out), unicode(err)

    expected = "".join([unicode(x["cert_pem"], "ascii") for x in bundle])
    assert stdout == expected


def test_display_flag_is_properly_formatted(capsys):
    bundle = BUNDLE_FIXTURES[0]
    cli(file_bytes=bundle[0]["cert_pem"], show_details=True)

    captured = unicode(capsys.readouterr().out)

    expected = unicode("""== Certificate #1 ==
Subject:            CN=github.com,O=GitHub\\, Inc.,L=San Francisco,ST=California,C=US
Issuer:             CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
NotBefore:          2020-05-05T00:00:00{tz}
NotAfter:           2022-05-10T12:00:00{tz}
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
NotBefore:          2013-10-22T12:00:00{tz}
NotAfter:           2028-10-22T12:00:00{tz}
Serial:             6489877074546166222510380951761917343
Sha256Fingeprint:   19400be5b7a31fb733917700789d2f0a2471c0c9d506c0e504c06c16d7cb17c0

Is root:            False
Is CA:              True
Domains:
  Common name:      DigiCert SHA2 High Assurance Server CA

""").format(tz="+00:00" if CRYPTOGRAPHY_MAJOR > 42 else "")

    assert expected == captured


def test_display_flag_includes_warning_when_root_was_requested_but_not_found(capsys):
    bundle = BUNDLE_FIXTURES[0]
    cli(file_bytes=bundle[0]["cert_pem"], show_details=True, include_root=True)
    captured = unicode(capsys.readouterr().err)
    assert captured == "WARNING: Root certificate was requested, but not found!\n"


@pytest.mark.parametrize(
    "file_name, expected_content",
    [("test.pem", b"test certificate data"), ("-", b"stdin data")],
)
def test_main_handles_different_file_input(mocker, file_name, expected_content):
    args = mocker.Mock(
        info=True,
        include_root=False,
        include_cross_signs=False,
        ca_bundle_path="/test/path",
        file_name="test.pem",
    )
    args.file_name = file_name
    mocker.patch("cert_chain_resolver.cli.parse_args", return_value=args)

    fs_store = mocker.patch("cert_chain_resolver.cli.FileSystemStore")

    if file_name == "-":
        if __is_py3__:
            mocker.patch("sys.stdin.buffer.read", return_value=expected_content)
        else:
            mocker.patch("sys.stdin.read", return_value=expected_content)
    else:
        if __is_py3__:
            mocker.patch("builtins.open", mocker.mock_open(read_data=expected_content))
        else:
            mocker.patch(
                "__builtin__.open", mocker.mock_open(read_data=expected_content)
            )

    mock_cli = mocker.patch("cert_chain_resolver.cli.cli")

    main()

    assert fs_store.call_args == mocker.call(
        "/test/path",
    )
    assert mock_cli.call_args == mocker.call(
        file_bytes=expected_content,
        show_details=True,
        include_root=False,
        include_cross_signs=False,
        root_ca_store=mocker.ANY,
    )


def test_main_no_args_tty_shows_help_and_exits(mocker):
    mocker.patch("sys.stdin.isatty", return_value=True)
    mocker.patch("sys.argv", ["script_name"])

    with pytest.raises(SystemExit):
        main()
    assert sys.argv == ["script_name", "-h"]


def _stub_resolve_with_cross_signs(mocker, leaf, intermediate, cross_signs):
    """Patch cert_chain_resolver.cli.resolve so it returns a chain populated with cross-signs."""
    from cert_chain_resolver.models import CertificateChain

    chain = CertificateChain()
    chain += leaf
    chain += intermediate
    for c in cross_signs:
        chain.add_cross_sign(c)

    mocker.patch("cert_chain_resolver.cli.resolve", return_value=chain)
    return chain


def _make_mock_cert(mocker, fingerprint, pem, is_ca, is_root, repr_str):
    c = mocker.MagicMock(
        fingerprint=fingerprint,
        is_ca=is_ca,
        is_root=is_root,
    )
    c.export.return_value = pem
    c.__repr__ = lambda _self: repr_str
    return c


def test_cli_bundle_omits_cross_signs_when_flag_off(capsys, mocker):
    leaf = _make_mock_cert(
        mocker,
        fingerprint="leaf-fp",
        pem="LEAF-PEM\n",
        is_ca=False,
        is_root=False,
        repr_str="<Cert leaf>",
    )
    intermediate = _make_mock_cert(
        mocker,
        fingerprint="int-fp",
        pem="INT-PEM\n",
        is_ca=True,
        is_root=False,
        repr_str="<Cert int>",
    )
    cross = _make_mock_cert(
        mocker,
        fingerprint="cross-fp",
        pem="CROSS-PEM\n",
        is_ca=True,
        is_root=False,
        repr_str="<Cert cross>",
    )
    _stub_resolve_with_cross_signs(mocker, leaf, intermediate, [cross])

    cli(file_bytes=b"ignored")
    out, err = capsys.readouterr()
    assert "CROSS-PEM" not in out
    assert "LEAF-PEM" in out and "INT-PEM" in out
    assert "Pass --include-cross-signs" in err


def test_cli_bundle_appends_cross_signs_when_flag_on(capsys, mocker):
    leaf = _make_mock_cert(
        mocker,
        fingerprint="leaf-fp",
        pem="LEAF-PEM\n",
        is_ca=False,
        is_root=False,
        repr_str="<Cert leaf>",
    )
    intermediate = _make_mock_cert(
        mocker,
        fingerprint="int-fp",
        pem="INT-PEM\n",
        is_ca=True,
        is_root=False,
        repr_str="<Cert int>",
    )
    cross_a = _make_mock_cert(
        mocker,
        fingerprint="cross-a-fp",
        pem="CROSS-A\n",
        is_ca=True,
        is_root=False,
        repr_str="<Cert cross_a>",
    )
    cross_b = _make_mock_cert(
        mocker,
        fingerprint="cross-b-fp",
        pem="CROSS-B\n",
        is_ca=True,
        is_root=False,
        repr_str="<Cert cross_b>",
    )
    _stub_resolve_with_cross_signs(mocker, leaf, intermediate, [cross_a, cross_b])

    cli(file_bytes=b"ignored", include_cross_signs=True)
    out, err = capsys.readouterr()

    # Bundle order: leaf, intermediate, cross_a, cross_b
    assert out == "LEAF-PEM\nINT-PEM\nCROSS-A\nCROSS-B\n"
    # No hint when flag is on
    assert "Pass --include-cross-signs" not in err


def test_cli_info_reports_cross_signs_always(capsys, mocker):
    """--info shows the Cross-sign section regardless of --include-cross-signs."""
    import datetime

    def _make_info_cert(name, fp, is_ca, is_root):
        m = mocker.MagicMock()
        m.fingerprint = fp
        m.subject = "CN=" + name
        m.issuer = "CN=Issuer"
        m.common_name = name
        m.serial = 1
        m.is_ca = is_ca
        m.is_root = is_root
        m.subject_alternative_names = []
        m.ca_issuer_access_location = None
        m.not_valid_before = datetime.datetime(2024, 1, 1)
        m.not_valid_after = datetime.datetime(2025, 1, 1)
        return m

    leaf = _make_info_cert("leaf", "leaf-fp", is_ca=False, is_root=False)
    intermediate = _make_info_cert("int", "int-fp", is_ca=True, is_root=False)
    cross = _make_info_cert("cross", "cross-fp", is_ca=True, is_root=False)
    _stub_resolve_with_cross_signs(mocker, leaf, intermediate, [cross])

    cli(file_bytes=b"ignored", show_details=True)
    out, err = capsys.readouterr()

    assert "== Cross-sign #1 ==" in out
    assert "Pass --include-cross-signs" in err
