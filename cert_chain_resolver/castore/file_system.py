from collections import defaultdict
import os
import ssl

from cert_chain_resolver.exceptions import (
    CertificateChainResolverError,
    RootCertificateNotFound,
)
from cert_chain_resolver.models import Cert
from cert_chain_resolver.castore.base_store import CAStore
from cert_chain_resolver import __is_py3__

try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:  # pragma: no cover
        from cert_chain_resolver.models import Cert
except ImportError:  # pragma: no cover
    pass


ssl_paths = ssl.get_default_verify_paths()
eligible_paths = [
    ssl_paths.cafile,
    ssl_paths.openssl_cafile,
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
]


class FileSystemStore(CAStore):
    """The :class:`SystemStore <SystemStore>` for finding the CA from file system bundle (PEM ONLY)."""

    _cache = None  # type: dict[str, list[Cert]]
    path = None  # type: str

    def __init__(self, path=None):
        # (None | str) -> None
        self._cache = defaultdict(list)
        if not path:
            try:
                path = next(p for p in eligible_paths if p and os.path.exists(p))
            except StopIteration:
                raise CertificateChainResolverError(
                    "Can't detect CA bundle, we searched: {}".format(eligible_paths)
                )

        if path and not os.path.isfile(path):
            raise CertificateChainResolverError(
                "Can't find bundle, or bundle is not a file: {}".format(path)
            )

        self.path = path

    def find_issuer_candidates(self, cert):
        # type: (Cert) -> list[Cert]
        if not self._cache:
            self._populate_cache()

        return self._cache.get(cert.issuer, [])

    def _populate_cache(self):
        # type: () -> None
        with open(self.path, "rb") as f:
            cert_buffer = bytearray()
            for line in f:
                if line == b"-----BEGIN CERTIFICATE-----\n":
                    cert_buffer = bytearray(line)
                elif line == b"-----END CERTIFICATE-----\n":
                    cert_buffer.extend(line)
                    root = Cert.load(bytes(cert_buffer))
                    self._cache[root.subject].append(root)
                    cert_buffer = bytearray()
                else:
                    cert_buffer.extend(line)
