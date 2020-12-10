from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
import binascii
import six

try:
    unicode
except NameError:
    unicode = str


class Cert(object):
    """The :class:`Cert <Cert>` object, which is a convenience
    wrapper for interacting with the underlying x509 object

    Args:
        x509 (x509) a cryptography.x509 object
    """

    _x509 = None

    def __init__(self, x509_obj):
        if not isinstance(x509_obj, x509.Certificate):
            raise TypeError("Argument must be a x509 Certificate object")
        self._x509 = x509_obj

    def __repr__(self):
        return '<Cert common_name="{0}" subject="{1}" issuer="{2}">'.format(
            self.common_name, self.subject, self.issuer
        )

    @property
    def issuer(self):
        return self._x509.issuer.rfc4514_string()

    @property
    def subject(self):
        return self._x509.subject.rfc4514_string()

    @property
    def common_name(self):
        for attr in self._x509.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            return attr.value

    @property
    def subject_alternative_names(self):
        names = []
        try:
            ext = self._x509.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            names = ext.value.get_values_for_type(x509.DNSName)
        except x509.extensions.ExtensionNotFound:
            pass
        return names

    @property
    def is_ca(self):
        is_ca = False
        try:
            ext = self._x509.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = True if ext.value.ca else False
        except x509.extensions.ExtensionNotFound:
            pass
        return is_ca

    @property
    def is_root(self):
        return self.subject == self.issuer

    @property
    def serial(self):
        return self._x509.serial_number

    @property
    def signature_hash_algorithm(self):
        return self._x509.signature_hash_algorithm.name

    @property
    def not_valid_before(self):
        return self._x509.not_valid_before

    @property
    def not_valid_after(self):
        return self._x509.not_valid_after

    @property
    def fingerprint(self):
        return self.get_fingerprint(hashes.SHA256)

    @property
    def ca_issuer_access_location(self):
        access_location = None
        try:
            aias = self._x509.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for aia in aias.value:
                if AuthorityInformationAccessOID.CA_ISSUERS == aia.access_method:
                    access_location = aia.access_location.value
        except x509.extensions.ExtensionNotFound:
            pass
        return access_location

    def get_fingerprint(self, _hash=hashes.SHA256):
        binary = self._x509.fingerprint(_hash())
        txt = binascii.hexlify(binary).decode("ascii")
        return txt

    def export(self, encoding=Encoding.PEM):
        encoded = unicode(self._x509.public_bytes(encoding), "ascii")
        return encoded


class CertificateChain(object):

    _chain = None

    def __init__(self, chain=None):
        self._chain = [] if not chain else chain

    def __iter__(self):
        for cert in self._chain:
            yield cert

    def __iadd__(self, x509_obj):
        self._chain.append(x509_obj)
        return self

    def __len__(self):
        return self._chain.__len__()

    @property
    def leaf(self):
        return self._chain[0]

    @property
    def intermediates(self):
        new_chain = [x for x in self._chain if (x.is_ca and not x.is_root)]
        return self.__class__(chain=new_chain)
