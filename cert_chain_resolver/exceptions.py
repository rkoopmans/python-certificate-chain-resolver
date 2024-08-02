class CertificateChainResolverError(Exception):
    pass


class ImproperlyFormattedCert(CertificateChainResolverError):
    pass


class MissingCertProperty(CertificateChainResolverError):
    pass


class RootCertificateNotFound(CertificateChainResolverError):
    pass


class Python2IncompatibleFeature(CertificateChainResolverError):
    pass
