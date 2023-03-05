from cert_chain_resolver.exceptions import CertifiNotInstalled
from cert_chain_resolver.models import Cert
from collections import defaultdict


try:
    import certifi
except ImportError:
    raise CertifiNotInstalled("Install certify to use this module; install cert-chain-resolver[ca-root]")


cache = defaultdict(list)


def find_by_issuer(name):
    """ This is quite naive for finding a root certificate but practical"""
    found = cache.get(name)
    if found:
        return found

    with open(certifi.where(), 'rb') as f:

        cert_buffer = bytearray()
        found_match, cert_start = False, False
        for line in f:
            if line == b"# Subject: " + name.encode('ascii') + b"\n":
                found_match = True

            if found_match and line == b"-----BEGIN CERTIFICATE-----\n":
                cert_start = True

            if found_match and cert_start:
                cert_buffer.extend(line)
                if line == b"-----END CERTIFICATE-----\n":
                    found_match, cert_start = False, False
                    cache[name].append(Cert.load(bytes(cert_buffer)))
                    cert_buffer = bytearray()

    return cache.get(name, [])