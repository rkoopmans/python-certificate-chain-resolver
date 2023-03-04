from cert_chain_resolver.utils import load_ascii_to_x509, load_bytes_to_x509
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
import binascii

try:
    unicode
except NameError:
    unicode = str


class Cert(object):
    """The :class:`Cert <Cert>` object, which is a convenience
    wrapper for interacting with the underlying :py:class:`cryptography.x509.Certificate` object

    Args:
        x509_obj (:py:class:`cryptography.x509.Certificate`): An instance of :py:class:`cryptography.x509.Certificate`
    Raises:
        TypeError: given type is not an instance of :py:class:`cryptography.x509.Certificate`
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

    def __eq__(self, other):
        return self.fingerprint == other.fingerprint

    @property
    def issuer(self):
        """str: RFC4515 formatted string of the issuer field from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.issuer.rfc4514_string()

    @property
    def subject(self):
        """str: RFC4515 formatted string of the subject field from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.subject.rfc4514_string()

    @property
    def common_name(self):
        """str: Extracted common name from the underlying :py:class:`cryptography.x509.Certificate` object"""
        for attr in self._x509.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            return attr.value

    @property
    def subject_alternative_names(self):
        """list(str): Extracted x509 Extensions from the :py:class:`cryptography.x509.Certificate` object"""
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
        """bool: Checks whether the Certificate Authority bit has been set"""
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
        """bool: Checks whether the certificate is a root"""
        return self.subject == self.issuer

    @property
    def serial(self):
        """str: gets the serial from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.serial_number

    @property
    def signature_hash_algorithm(self):
        """str: gets the signature hashing algorithm name from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.signature_hash_algorithm.name

    @property
    def not_valid_before(self):
        """:py:class:`datetime.datetime`: from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.not_valid_before

    @property
    def not_valid_after(self):
        """:py:class:`datetime.datetime`: from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.not_valid_after

    @property
    def fingerprint(self):
        """str: ascii encoded sha256 fingerprint by calling :py:func:`get_fingerprint`"""
        return self.get_fingerprint(hashes.SHA256)

    @property
    def ca_issuer_access_location(self):
        """str: a URL that contains the CA issuer certificate"""
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
        """Get fingerprint of the certificate

        Args:
            _hash (:py:class:`cryptography.hazmat.primitives.hashes`, optional): Hasher to use. Defaults to hashes.SHA256.

        Returns:
            str: hex representation of the fingerprint
        """
        binary = self._x509.fingerprint(_hash())
        txt = binascii.hexlify(binary).decode("ascii")
        return txt

    def export(self, encoding=Encoding.PEM):
        """Export the :py:class:`cryptography.x509.Certificate` object"

        Args:
            encoding (:py:class:`cryptography.hazmat.primitives.serialization.Encoding`, optional): The output format. Defaults to Encoding.PEM.

        Returns:
            str: ascii formatted
        """
        encoded = unicode(self._x509.public_bytes(encoding), "ascii")
        return encoded

    @classmethod
    def load(cls, bytes_input):
        """
        Create a :class:`Cert <Cert>` object

        Args:
            bytes_input :py:class:`bytes` PEM or DER

        Raises:
            :class:`ImproperlyFormattedCert <ImproperlyFormattedCert>`
        """
        x509 = load_bytes_to_x509(bytes_input)
        return Cert(x509)


class CertificateChain(object):
    """Creates an iterable that contains a list of :class:`Cert <Cert>` objects.

    Args:
        chain (:py:class:`CertificateChain <CertificateChain>`, optional): Create a new CertificateChain based on this chain. Defaults to None.
    """

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
        """First :class:`Cert <Cert>`: in the chain. Also known as the 'leaf'"""
        return self._chain[0]

    @property
    def intermediates(self):
        """A new :class:`CertificateChain <CertificateChain>` object with only intermediate certificates"""
        new_chain = [x for x in self._chain if (x.is_ca and not x.is_root)]
        return self.__class__(chain=new_chain)

    @property
    def root(self):
        """Last :class:`Cert <Cert>`: in the chain  that can be identified as root or None if no root is present"""
        if self._chain[-1].is_root:
            return self._chain[-1]

    @classmethod
    def load_from_pem(cls, input_bytes):
        """ Create a :py:class:`CertificateChain <CertificateChain>` object from a PEM formatted file """
        begin = b'-----BEGIN CERTIFICATE-----\n'
        chain = cls()
        for strip_pem in filter(len, input_bytes.split(begin)):
            pem = begin + strip_pem
            chain += Cert(load_ascii_to_x509(pem, pem.decode('ascii')))

        if chain.leaf.is_ca and not chain._chain[-1].is_ca:
            # if CA bit is not set on the last certificate, reverse the chain
            chain._chain.reverse()
        return chain


