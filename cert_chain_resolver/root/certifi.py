from cert_chain_resolver.exceptions import CertifiNotInstalled, RootCertificateNotFound
from collections import defaultdict

from cert_chain_resolver.models import Cert
from cert_chain_resolver.root.store import CAStore


try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from cert_chain_resolver.models import Cert
except ImportError:
    pass


try:
    import certifi
except ImportError:
    raise CertifiNotInstalled(
        "Install certify to use this module; install cert-chain-resolver[ca-root]"
    )


class CertifiStore(CAStore):
    cache = defaultdict(list)  # type: dict[str, list[Cert]]

    def find_issuer_candidates(self, cert):
        # type: (Cert) -> list[Cert]
        if not self.cache:
            self._populate_cache()

        return self.cache.get(cert.issuer, [])

    def _populate_cache(self):
        # type: () -> None
        with open(certifi.where(), "rb") as f:
            cert_buffer = bytearray()
            for line in f:
                if line == b"-----BEGIN CERTIFICATE-----\n":
                    cert_buffer = bytearray(line)
                elif line == b"-----END CERTIFICATE-----\n":
                    cert_buffer.extend(line)
                    root = Cert.load(bytes(cert_buffer))
                    self.cache[root.subject].append(root)
                    cert_buffer = bytearray()
                else:
                    cert_buffer.extend(line)
