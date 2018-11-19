import argparse
import sys
from .resolver import ChainResolver


def cli():
    parser = argparse.ArgumentParser(description='Ssl certificate chain resolver')
    parser.add_argument('certificate', nargs='?', default=sys.stdin, type=open, help='file formatted as PEM')

    if sys.stdin.isatty() and len(sys.argv) == 1:
        sys.argv += ['-h']

    args = parser.parse_args()

    cert = args.certificate.read()
    cr = ChainResolver(cert)
    cr.resolve()
    sys.stdout.writelines(cr.get())




if __name__ == '__main__':
    cli()
