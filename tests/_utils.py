import cryptography
import datetime

CRYPTOGRAPHY_MAJOR = int(cryptography.__version__.split(".")[0])

def make_utc_aware_if_cryptography_above_42(dt):
    if CRYPTOGRAPHY_MAJOR >= 42:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt