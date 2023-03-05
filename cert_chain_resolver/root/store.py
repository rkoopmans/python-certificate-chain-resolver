from cert_chain_resolver.exceptions import RootCertificateNotFound
from cert_chain_resolver.models import Cert


try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from cert_chain_resolver.models import Cert
except ImportError:
    pass


class CAStore:

    store = "certifi"
    _impl = None  # type: None | CAStore

    def find_issuer(self, cert):
        # type: (Cert) -> Cert
        """
        Find root cert by signed cert.

        This function searches for certificates in the bundle that match.
        """
        certs = self.find_issuer_candidates(cert)
        try:
            return next(ca for ca in certs if cert.is_issued_by(ca))
        except StopIteration:
            raise RootCertificateNotFound(
                "Cant find root cert in {}".format(self.__class__.__name__)
            )

    def find_issuer_candidates(self, cert):
        # type: (Cert) -> list[Cert]
        raise NotImplementedError

    @property
    def impl(self):
        # type: () -> CAStore
        if self._impl:
            return self._impl

        from cert_chain_resolver.root.certifi import CertifiStore

        self._impl = CertifiStore()
        return self._impl
