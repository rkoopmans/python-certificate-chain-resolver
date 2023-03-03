import argparse
import sys
from cert_chain_resolver.resolver import resolve
from cert_chain_resolver import __is_py3__


def _print_chain_details(chain):
    for index, cert in enumerate(chain, 1):
        print("== Certificate #{0} ==".format(index))
        print("Subject:".ljust(20) + cert.subject)
        print("Issuer:".ljust(20) + cert.issuer)
        print("NotBefore:".ljust(20) + cert.not_valid_before.isoformat())
        print("NotAfter:".ljust(20) + cert.not_valid_after.isoformat())
        print("Serial:".ljust(20) + str(cert.serial))
        print("Sha256Fingeprint:".ljust(20) + str(cert.fingerprint))
        print(
            "CAIssuerLoc:".ljust(20) + cert.ca_issuer_access_location
            if cert.ca_issuer_access_location
            else ""
        )
        print("Is root:".ljust(20) + repr(cert.is_root))
        print("Is CA:".ljust(20) + repr(cert.is_ca))
        print("Domains:")
        print("  Common name:".ljust(20) + cert.common_name)
        if cert.subject_alternative_names:
            print("  SANExtensions:")
            for domain in cert.subject_alternative_names:
                print("    " + domain)
        print("")


def cli(file_bytes=None, show_details=None):
    chain = resolve(file_bytes)
    if show_details:
        _print_chain_details(chain)
    else:
        for c in [chain.leaf] + list(chain.intermediates):
            sys.stdout.write(c.export())

        for i, c in enumerate([chain.leaf] + list(chain.intermediates), 1):
            sys.stderr.write(str(i) + ". " + repr(c) + "\n")


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
        "file_name",
        nargs="?",
        default="-",
        type=str,
        help="file formatted as PEM",
    )
    parser.add_argument(
        "-i", "--info", action="store_true", help="Print chain derived information"
    )
    return parser.parse_args()


def main():
    if sys.stdin.isatty() and len(sys.argv) == 1:
        sys.argv += ["-h"]

    args = parse_args()

    cli_args = {
        "file_bytes": None,
        "show_details": args.info,
    }

    if args.file_name == "-":
        source = None
        if __is_py3__:
            source = sys.stdin.buffer
        else:
            source = sys.stdin
        cli_args["file_bytes"] = source.read()
    else:
        with open(args.file_name, "rb") as f:
            cli_args["file_bytes"] = f.read()

    cli(**cli_args)


if __name__ == "__main__":
    main()
