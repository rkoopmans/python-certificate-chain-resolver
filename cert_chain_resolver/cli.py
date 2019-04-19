import argparse
import sys
from resolver import ChainResolver, UnsuportedCertificateType


def cli():
    parser = argparse.ArgumentParser(description='Ssl certificate chain resolver')
    parser.add_argument('certificate', nargs='?', default=sys.stdin, type=open, help='file formatted as PEM')
    parser.add_argument('-d', '--depth', nargs='?', default=None, type=int, help='Recursion max-depth. Default is until no parent cert is found')

    if sys.stdin.isatty() and len(sys.argv) == 1:
        sys.argv += ['-h']

    args = parser.parse_args()
    cert = args.certificate.read()
    cr = ChainResolver(depth=args.depth)
    try:
        cr.resolve(cert)
        sys.stdout.writelines([x.export() for x in cr.list()])
    except UnsuportedCertificateType as e:
        sys.stdout.write(repr(e) + '\n')


if __name__ == '__main__':
    cli()
