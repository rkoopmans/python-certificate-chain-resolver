class CertificateChainResolverError(Exception):
    pass


class ImproperlyFormattedCert(CertificateChainResolverError):
    pass


class MissingCertProperty(CertificateChainResolverError):
    pass
