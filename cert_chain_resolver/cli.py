import argparse
import sys
from resolver import ChainResolver, UnsuportedCertificateType


def cli():
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
    parser.add_argument("cert", nargs="?", default=sys.stdin, type=open, help="file formatted as PEM")
    parser.add_argument(
        "-d",
        "--depth",
        nargs="?",
        default=None,
        type=int,
        help="Recursion max-depth. Default is until no parent cert is found",
    )
    parser.add_argument("-i", "--info", action="store_true", help="Print chain derived information")

    if sys.stdin.isatty() and len(sys.argv) == 1:
        sys.argv += ["-h"]

    args = parser.parse_args()
    cert = args.cert.read()
    cr = ChainResolver(depth=args.depth)
    try:
        cr.resolve(cert)
    except UnsuportedCertificateType as e:
        sys.stderr.write(repr(e) + "\n")

    if args.info:
        import pprint
        pprint.pprint([x.details for x in cr.list()], indent=2)
    else:
        sys.stdout.writelines([x.export() for x in cr.list()])


if __name__ == "__main__":
    cli()
