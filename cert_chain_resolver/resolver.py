from OpenSSL import crypto
from pyasn1_modules import rfc5280
from pyasn1.codec.der import decoder as der_decoder
import re
import urllib.request


class Resolver:

    ans1_spec = rfc5280.AuthorityInfoAccessSyntax()
    parent_cert_re = re.compile(r'^\s*uniformResourceIdentifier=(.*\.crt)$', re.MULTILINE)

    def __init__(self, cert):
        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    def get_extensions(self):
        return [self.cert.get_extension(x) for x in range(0, self.cert.get_extension_count())]

    def get_extension_by_name(self, name):
        for ext in self.get_extensions():
            if ext.get_short_name() == name:
                return ext

    def get_parent_cert(self):
        extension = self.get_extension_by_name(b'authorityInfoAccess')
        value, _ = der_decoder.decode(extension.get_data(), asn1Spec=self.ans1_spec)
        url = self.parent_cert_re.findall(value.prettyPrint())
        if url:
            return self._download(url[0])

    def _download(self, url):
        req = urllib.request.Request(url, headers={'User-Agent': 'Cert/fixer'})
        with urllib.request.urlopen(req) as resp:
            return crypto.load_certificate(crypto.FILETYPE_ASN1, resp.read())


class ChainResolver:

    bundle = None

    def __init__(self, start_cert):
        self.bundle = []
        self.append(start_cert)

    def append(self, cert):
        sanitized_lf = "\n".join(filter(len, cert.splitlines()))
        self.bundle.append(sanitized_lf + '\n')

    def resolve(self):
        while True:
            r = Resolver(self.bundle[-1])
            cert = r.get_parent_cert()
            if not cert:
                break
            self.bundle.append(
                crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())
        return self.bundle

    def get(self):
        return self.bundle
