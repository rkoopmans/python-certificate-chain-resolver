import datetime
from cryptography import x509
import itertools


def _add_cert_objects_to_chain(cert):
    with open(cert["source_cert"], "rb") as f:
        cert["cert_pem"] = f.read()
    cert["cert_x509"] = x509.load_pem_x509_certificate(cert["cert_pem"])
    return cert


_TEST_BUNDLES = [
    ### github.com
    [
        {
            "name": "github.com",
            "type": "leaf",
            "source_cert": "tests/certs/github.com.pem",
            "meta": {
                "ca": False,
                "common_name": "github.com",
                "subject": "CN=github.com,O=GitHub\\, Inc.,L=San Francisco,ST=California,C=US",
                "fingerprint_sha256": "b6b9a6af3e866cbe0e6a307e7dda173b372b2d3ac3f06af15f97718773848008",
                "issuer": "CN=DigiCert SHA2 High Assurance Server "
                "CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
                "not_after": datetime.datetime(2022, 5, 10, 12, 0),
                "not_before": datetime.datetime(2020, 5, 5, 0, 0),
                "san": ["github.com", "www.github.com"],
                "serial": 7101927171473588541993819712332065657,
                "signature_algorithm": "sha256",
                "ca_issuer_access_location": "http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt",
            },
        },
        {
            "name": "DigiCert SHA2 High Assurance Server CA",
            "type": "intermediate",
            "source_cert": "tests/certs/ca/DigiCert_SHA2_High_Assurance_Server_CA.pem",
            "meta": {
                "ca": True,
                "common_name": "DigiCert SHA2 High Assurance Server CA",
                "fingerprint_sha256": "19400be5b7a31fb733917700789d2f0a2471c0c9d506c0e504c06c16d7cb17c0",
                "issuer": "CN=DigiCert High Assurance EV Root "
                "CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
                "not_after": datetime.datetime(2028, 10, 22, 12, 0),
                "not_before": datetime.datetime(2013, 10, 22, 12, 0),
                "san": [],
                "serial": 6489877074546166222510380951761917343,
                "signature_algorithm": "sha256",
                "subject": "CN=DigiCert SHA2 High Assurance Server "
                "CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
                "ca_issuer_access_location": None,
            },
        },
        {
            "name": "DigiCert High Assurance EV Root CA",
            "type": "root",
            "source_cert": "tests/certs/ca/DigiCert_High_Assurance_EV_Root_CA.pem",
            "meta": {
                "ca": True,
                "common_name": "DigiCert High Assurance EV Root CA",
                "fingerprint_sha256": "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf",
                "issuer": "CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
                "not_after": datetime.datetime(2031, 11, 10, 0, 0),
                "not_before": datetime.datetime(2006, 11, 10, 0, 0),
                "san": [],
                "serial": 3553400076410547919724730734378100087,
                "signature_algorithm": "sha1",
                "subject": "CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
                "ca_issuer_access_location": None,
            },
        },
    ],
    ### cert-chain-resolver.remcokoopmans.com
    [
        {
            "name": "cert-chain-resolver.remcokoopmans.com",
            "type": "leaf",
            "source_cert": "tests/certs/cert-chain-resolver.remcokoopmans.com.pem",
            "meta": {
                "ca": False,
                "common_name": "cert-chain-resolver.remcokoopmans.com",
                "fingerprint_sha256": "d6e4c5abdeb076b904ab948fd1982f55173a51776f8c84cd14bb1e26b73a3acc",
                "issuer": "CN=R3,O=Let's Encrypt,C=US",
                "not_after": datetime.datetime(2021, 3, 6, 23, 22, 11),
                "not_before": datetime.datetime(2020, 12, 6, 23, 22, 11),
                "san": ["cert-chain-resolver.remcokoopmans.com"],
                "serial": 263000687849867688464024588993439613763508,
                "signature_algorithm": "sha256",
                "subject": "CN=cert-chain-resolver.remcokoopmans.com",
                "ca_issuer_access_location": "http://r3.i.lencr.org/",
            },
        },
        {
            "name": "LetsEncrypt R3",
            "source_cert": "tests/certs/ca/LetsEncrypt_R3.pem",
            "type": "intermediate",
            "meta": {
                "ca": True,
                "common_name": "R3",
                "fingerprint_sha256": "67add1166b020ae61b8f5fc96813c04c2aa589960796865572a3c7e737613dfd",
                "issuer": "CN=ISRG Root X1,O=Internet Security Research Group,C=US",
                "not_before": datetime.datetime(2020, 9, 4, 0, 0),
                "not_after": datetime.datetime(2025, 9, 15, 16, 0),
                "san": [],
                "serial": 192961496339968674994309121183282847578,
                "signature_algorithm": "sha256",
                "subject": "CN=R3,O=Let's Encrypt,C=US",
                "ca_issuer_access_location": "http://x1.i.lencr.org/",
            },
        },
        {
            "name": "ISRG root X1",
            "source_cert": "tests/certs/ca/ISRG_Root_X1_O=Internet_Security_Research_Group.pem",
            "type": "root",
            "meta": {
                "ca": True,
                "common_name": "ISRG Root X1",
                "fingerprint_sha256": "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
                "issuer": "CN=ISRG Root X1,O=Internet Security Research Group,C=US",
                "not_before": datetime.datetime(2015, 6, 4, 11, 4, 38),
                "not_after": datetime.datetime(2035, 6, 4, 11, 4, 38),
                "san": [],
                "serial": 172886928669790476064670243504169061120,
                "signature_algorithm": "sha256",
                "subject": "CN=ISRG Root X1,O=Internet Security Research Group,C=US",
                "ca_issuer_access_location": None,
            },
        },
    ],
]


TEST_CERTS_IN_VARIOUS_FORMATS = {
    "pem": "./tests/certs/cert-chain-resolver.remcokoopmans.com.pem",
    "p7b-der": "./tests/certs/cert-chain-resolver.remcokoopmans.com.der.p7b",
    "p7b-pem": "./tests/certs/cert-chain-resolver.remcokoopmans.com.pem.p7b",
    "der": "./tests/certs/cert-chain-resolver.remcokoopmans.com.der",
}
BUNDLE_FIXTURES = [
    list(map(_add_cert_objects_to_chain, bundle)) for bundle in _TEST_BUNDLES
]
CERT_FIXTURES = list(itertools.chain(*BUNDLE_FIXTURES))


def certfixture_to_id(fixt):
    """pytest helper to create a human readable string when using parametrize"""
    if isinstance(fixt, dict):
        return fixt["type"] + ":" + fixt["name"]
    elif isinstance(fixt, list):
        return "bundle:" + fixt[0]["name"]
    raise Exception("Unsupported type")
