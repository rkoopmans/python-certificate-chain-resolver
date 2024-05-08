from cert_chain_resolver.exceptions import MissingCertProperty
from cert_chain_resolver.utils import load_ascii_to_x509, load_bytes_to_x509
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
import binascii


try:
    from typing import List, Union, Optional, Type, Iterator, TYPE_CHECKING

    if TYPE_CHECKING:
        import datetime
except ImportError:
    pass

try:
    unicode  # type: ignore
except NameError:
    unicode = str


class Cert:
    """The :class:`Cert <Cert>` object, which is a convenience
    wrapper for interacting with the underlying :py:class:`cryptography.x509.Certificate` object

    Args:
        x509_obj: An instance of :py:class:`cryptography.x509.Certificate`
    Raises:
        TypeError: given type is not an instance of :py:class:`cryptography.x509.Certificate`
    """

    def __init__(self, x509_obj):
        # type: (x509.Certificate) -> None
        if not isinstance(x509_obj, x509.Certificate):
            raise TypeError("Argument must be a x509 Certificate object")
        self._x509 = x509_obj

    def __repr__(self):
        # type: () -> str
        return '<Cert common_name="{0}" subject="{1}" issuer="{2}">'.format(
            self.common_name, self.subject, self.issuer
        )

    def __eq__(self, other):
        # type: (object) -> bool
        if not isinstance(other, Cert):
            return NotImplemented
        return self.fingerprint == other.fingerprint

    @property
    def issuer(self):
        # type: () -> str
        """RFC4515 formatted string of the issuer field from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.issuer.rfc4514_string()

    @property
    def subject(self):
        # type: () -> str
        """RFC4515 formatted string of the subject field from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.subject.rfc4514_string()

    @property
    def common_name(self):
        # type: () -> str
        """Extracted common name from the underlying :py:class:`cryptography.x509.Certificate` object"""
        for attr in self._x509.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if isinstance(attr.value, unicode):
                return attr.value
            elif isinstance(attr, bytes):
                return bytes(attr.value).decode("utf-8")
            else:
                raise ValueError("Unexpected type for attr")
        raise MissingCertProperty("No COMMON_NAME attribute found")

    @property
    def subject_alternative_names(self):
        # type: () -> List[str]
        """list(str): Extracted x509 Extensions from the :py:class:`cryptography.x509.Certificate` object"""
        try:
            ext = self._x509.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            if isinstance(ext.value, x509.SubjectAlternativeName):
                # Runtime check needed to ensure proper type hinting
                return ext.value.get_values_for_type(x509.DNSName)
        except x509.extensions.ExtensionNotFound:
            pass
        return []

    @property
    def is_ca(self):
        # type: () -> bool
        """Checks whether the Certificate Authority bit has been set"""
        try:
            ext = self._x509.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            if isinstance(ext.value, x509.BasicConstraints):
                # Runtime check needed to ensure proper type hinting
                return ext.value.ca
        except x509.extensions.ExtensionNotFound:
            pass
        return False

    @property
    def is_root(self):
        # type: () -> bool
        """Checks whether the certificate is a root"""
        return self.subject == self.issuer

    @property
    def serial(self):
        # type: () -> int
        """gets the serial from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.serial_number

    @property
    def signature_hash_algorithm(self):
        # type: () -> str
        """gets the signature hashing algorithm name from the underlying :py:class:`cryptography.x509.Certificate` object"""
        if not self._x509.signature_hash_algorithm:
            raise MissingCertProperty(
                "X509 object does not have a signature hash algorithm"
            )
        return self._x509.signature_hash_algorithm.name

    @property
    def not_valid_before(self):
        # type: () -> datetime.datetime
        """Date from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.not_valid_before

    @property
    def not_valid_after(self):
        # type: () -> datetime.datetime
        """Date from the underlying :py:class:`cryptography.x509.Certificate` object"""
        return self._x509.not_valid_after

    @property
    def fingerprint(self):
        # type: () -> str
        """ascii encoded sha256 fingerprint by calling :py:func:`get_fingerprint`"""
        return self.get_fingerprint(hashes.SHA256)

    @property
    def ca_issuer_access_location(self):
        # type: () -> Union[str, None]
        """URL that contains the CA issuer certificate"""
        try:
            aias = self._x509.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            if isinstance(aias.value, x509.AuthorityInformationAccess):
                # Runtime check needed to ensure proper type hinting
                for aia in aias.value:
                    if AuthorityInformationAccessOID.CA_ISSUERS == aia.access_method:
                        access_location = aia.access_location.value  # type: str
                        return access_location
        except x509.extensions.ExtensionNotFound:
            pass
        return None

    def get_fingerprint(self, _hash=hashes.SHA256):
        # type: (Type[hashes.HashAlgorithm]) -> str
        """Get fingerprint of the certificate

        Args:
            _hash (:py:class:`cryptography.hazmat.primitives.hashes`, optional): Hasher to use. Defaults to hashes.SHA256.

        Returns:
            hex representation of the fingerprint
        """
        binary = self._x509.fingerprint(_hash())
        txt = binascii.hexlify(binary).decode("ascii")
        return txt

    def export(self, encoding=Encoding.PEM):
        # type: (Encoding) -> str
        """Export the :py:class:`cryptography.x509.Certificate` object" as text

        Args:
            encoding (:py:class:`cryptography.hazmat.primitives.serialization.Encoding`, optional): The output format. Defaults to Encoding.PEM.

        Returns:
            ascii formatted
        """
        encoded = self._x509.public_bytes(encoding)
        return encoded.decode(encoding="ascii")

    @classmethod
    def load(cls, bytes_input):
        # type: (bytes) -> Cert
        """
        Create a :class:`Cert <Cert>` object

        Args:
            bytes_input :py:class:`bytes` PEM or DER

        Raises:
            :class:`ImproperlyFormattedCert <ImproperlyFormattedCert>`
        """
        x509 = load_bytes_to_x509(bytes_input)
        return cls(x509)


class CertificateChain:
    """Creates an iterable that contains a list of :class:`Cert <Cert>` objects.

    Args:
        chain: Create a new CertificateChain based on this chain. Defaults to None.
    """

    def __init__(self, chain=None):
        # type: (Union[Optional[CertificateChain], List[Cert]]) -> None
        self._chain = [] if not chain else list(chain)  # type: List[Cert]
        self._fingerprints = set() if not chain else { x509_obj.fingerprint for x509_obj in chain }

    def __iter__(self):
        # type: () -> Iterator[Cert]
        for cert in self._chain:
            yield cert

    def __iadd__(self, x509_obj):
        # type: (Cert) -> CertificateChain
        self._chain.append(x509_obj)
        self._fingerprints.add(x509_obj.fingerprint)
        return self

    def __len__(self):
        # type: () -> int
        return self._chain.__len__()

    def __contains__(self, x509_obj):
        # type: (Cert) -> bool
        return self._fingerprints.__contains__(x509_obj.fingerprint)

    @property
    def leaf(self):
        # type: () -> Cert
        """First :class:`Cert <Cert>`: in the chain. Also known as the 'leaf'"""
        return self._chain[0]

    @property
    def intermediates(self):
        # type: () -> CertificateChain
        """A new :class:`CertificateChain <CertificateChain>` object with only intermediate certificates"""
        new_chain = [x for x in self._chain if (x.is_ca and not x.is_root)]
        return self.__class__(chain=new_chain)

    @property
    def root(self):
        # type: () -> Optional[Cert]
        """Last :class:`Cert <Cert>`: in the chain  that can be identified as root or None if no root is present"""
        if self._chain[-1].is_root:
            return self._chain[-1]
        return None

    @classmethod
    def load_from_pem(cls, input_bytes):
        # type: (bytes) -> CertificateChain
        """Create a :py:class:`CertificateChain <CertificateChain>` object from a PEM formatted file"""
        begin = b"-----BEGIN CERTIFICATE-----\n"
        chain = cls()
        for strip_pem in filter(len, input_bytes.split(begin)):
            pem = begin + strip_pem
            chain += Cert(load_ascii_to_x509(pem))

        if chain.leaf.is_ca and not chain._chain[-1].is_ca:
            # if CA bit is not set on the last certificate, reverse the chain
            chain._chain.reverse()
        return chain
