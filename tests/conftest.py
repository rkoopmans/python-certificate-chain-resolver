import pytest
import datetime


@pytest.fixture(scope="session")
def pem_github():
    chain = [{}, {}]

    with open("tests/certs/github.com.pem", "r") as f:
        chain[0] = {}
        chain[0]["cert"] = "\n".join(f.read().splitlines())
        chain[0]["meta"] = {
            "ca": False,
            "common_name": "github.com",
            "fingerprint_sha256": "b6b9a6af3e866cbe0e6a307e7dda173b372b2d3ac3f06af15f97718773848008",
            "issuer": "CN=DigiCert SHA2 High Assurance Server "
            "CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "not_after": datetime.datetime(2022, 5, 10, 12, 0),
            "not_before": datetime.datetime(2020, 5, 5, 0, 0),
            "san": ["github.com", "www.github.com"],
            "serial": 7101927171473588541993819712332065657,
            "signature_algorithm": "sha256",
            "subject": "CN=github.com,O=GitHub\\, Inc.,L=San "
            "Francisco,ST=California,C=US",
        }

    with open("tests/certs/ca/DigiCert_SHA2_High_Assurance_Server_CA.pem", "r") as f:
        chain[1] = {}
        chain[1]["cert"] = "\n".join(f.read().splitlines())
        chain[1]["meta"] = {
            "ca": True,
            "common_name": "DigiCert SHA2 High Assurance Server CA",
            "fingerprint_sha256": "19400be5b7a31fb733917700789d2f0a2471c0c9d506c0e504c06c16d7cb17c0",
            "issuer": "CN=DigiCert High Assurance EV Root "
            "CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "not_after": datetime.datetime(2028, 10, 22, 12, 0),
            "not_before": datetime.datetime(2013, 10, 22, 12, 0),
            "san": None,
            "serial": 6489877074546166222510380951761917343,
            "signature_algorithm": "sha256",
            "subject": "CN=DigiCert SHA2 High Assurance Server "
            "CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
        }

    return chain
