from cert_chain_resolver.exceptions import RootCertificateNotFound
from cert_chain_resolver.models import Cert


try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:  # pragma: no cover
        from cert_chain_resolver.models import Cert
except ImportError:  # pragma: no cover

    pass


class CAStore:
    """The :class:`CAStore <CAStore>` base class for CA Bundle Providers"""

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
