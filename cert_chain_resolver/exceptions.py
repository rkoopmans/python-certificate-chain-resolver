class CertificateChainResolverError(Exception):
    pass


class ImproperlyFormattedCert(CertificateChainResolverError):
    pass


class MissingCertProperty(CertificateChainResolverError):
    pass


class CertificateVerificationError(CertificateChainResolverError):
    pass


class CertifiNotInstalled(CertificateChainResolverError):
    pass


class RootCertificateNotFound(CertificateChainResolverError):
    pass
