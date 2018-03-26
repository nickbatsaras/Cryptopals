from binascii import unhexlify
from base64 import b64encode

def HexToBase64(s):
    """Convert hex string to base64 string

        Args:
            s (str): Hex string to convert

        Returns:
            Base64 string
    """
    raw = unhexlify(s)
    b64_raw = b64encode(raw)

    return b64_raw.decode('ascii')
