from binascii import unhexlify
from base64 import b64encode


def HexToAscii(s):
    """Convert hex string to ascii string

        Args:
            s (str): Hex string to convert

        Returns:
            Ascii string
    """
    return bytearray.fromhex(s).decode()


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


def HexXOR(s1, s2):
    """XOR two equal-sized hex strings

        Args:
            s1 (str): Hex string
            s2 (str): Hex string

        Returns:
            Hex string, result of 's1 XOR s2'
    """
    assert(len(s1) == len(s2))

    xor = int(s1, 16) ^ int(s2, 16)

    return format(xor, 'x')
