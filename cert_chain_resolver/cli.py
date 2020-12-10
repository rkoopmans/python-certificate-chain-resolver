import argparse
import sys
from cert_chain_resolver.resolver import ChainResolver, UnsuportedCertificateType


def cli(cert=None, depth=None, info=None):
    cert = cert.read()
    cr = ChainResolver(depth=depth)
    try:
        cr.resolve(cert)
    except UnsuportedCertificateType as e:
        sys.stderr.write(repr(e) + "\n")

    if info:
        import pprint

        pprint.pprint([x.details for x in cr.list()], indent=2)
    else:
        sys.stdout.write("".join([x.export() for x in cr.list()]))


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Resolve / obtain the certificate intermediates of given x509 certificate. This tool writes the full bundle to stdout.

Examples:

    Using a file:

    $ cert_chain_resolver certificate.crt > bundle.crt

    Using stdin:

    $ cat certificate.crt | cert_chain_resolver > bundle.crt
    """,
    )
    parser.add_argument(
        "cert",
        nargs="?",
        default="-",
        type=argparse.FileType("rb"),
        help="file formatted as PEM",
    )
    parser.add_argument(
        "-d",
        "--depth",
        nargs="?",
        default=None,
        type=int,
        help="Recursion max-depth. Default is until no parent cert is found",
    )
    parser.add_argument(
        "-i", "--info", action="store_true", help="Print chain derived information"
    )
    return parser.parse_args()


if __name__ == "__main__":
    if sys.stdin.isatty() and len(sys.argv) == 1:
        sys.argv += ["-h"]

    pargs = parse_args()
    args = vars(pargs)
    cli(**args)
