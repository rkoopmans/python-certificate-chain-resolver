import argparse
import ssl
import sys
from typing import Optional
from cert_chain_resolver.resolver import resolve
from cert_chain_resolver import __is_py3__
from cert_chain_resolver.castore.file_system import FileSystemStore

try:
    from typing import Optional
    from cert_chain_resolver.castore.base_store import CAStore
except ImportError:
    pass


def _print_chain_details(chain, include_root):
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

    if include_root and not chain.root:
        sys.stderr.write("WARNING: Root certificate was requested, but not found!\n")


def cli(file_bytes, show_details=False, include_root=False, root_ca_store=None):
    # type: (bytes, bool, bool, Optional[CAStore]) -> None
    chain = resolve(file_bytes, root_ca_store=root_ca_store)
    if show_details:
        _print_chain_details(chain, include_root=include_root)
    else:
        root = [chain.root] if chain.root and include_root else []
        for c in [chain.leaf] + list(chain.intermediates) + root:
            sys.stdout.write(c.export())

        for i, c in enumerate([chain.leaf] + list(chain.intermediates) + root, 1):
            sys.stderr.write(str(i) + ". " + repr(c) + "\n")

        if not root and include_root:
            sys.stderr.write(
                str(i + 1) + ". Root certificate was requested, but not found!\n"
            )
            if not root_ca_store:
                sys.stderr.write(
                    "Consider running the CLI with --use-certifi-store to find the matching root CA\n"
                )


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
    parser.add_argument(
        "--include-root",
        action="store_true",
        help="Include root certificate in the chain if available",
    )
    parser.add_argument(
        "--ca-bundle-path",
        type=str,
        default=None,
        help="Use a custom CA bundle for completing the chain",
    )
    return parser.parse_args()


def main():
    if sys.stdin.isatty() and len(sys.argv) == 1:
        sys.argv += ["-h"]

    args = parse_args()

    cli_args = {
        "file_bytes": None,
        "show_details": args.info,
        "include_root": args.include_root,
    }

    cli_args["root_ca_store"] = FileSystemStore(args.ca_bundle_path)

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
