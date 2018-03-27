from binascii import unhexlify
from base64 import b64encode


def HexToAscii(s):
    """Convert hex string to ascii string

        Args:
            s (str): Hex string to convert

        Returns:
            Ascii string
    """
    try:
        return bytearray.fromhex(s).decode()
    except:
        return ""


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


def IsPlaintext(text, factor=0.95):
    """Check if text contains 'mostly' alpharithmetics

        Args:
            text     (str): Ascii string to check
            factor (float): Percentage of alphas in text in order qualify
                            as plaintext

        Returns:
            true, if number of alphas is above given percentage
            false, otherwise
    """
    text = text.strip().replace(' ', '')

    counter = 0
    for c in text:
        if c.isalpha():
            counter += 1

    return counter > factor * len(text)
