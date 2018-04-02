from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode


def HexToAscii(s):
    """Convert hex string to ascii string

        Args:
            s (str): Hex string to convert

        Returns:
            Ascii string
    """
    return bytes.fromhex(s).decode("ascii")


def HexToBase64(s):
    """Convert hex string to base64 string

        Args:
            s (str): Hex string to convert

        Returns:
            Base64 string
    """
    return b64encode(unhexlify(s)).decode("ascii")


def Base64ToHex(s):
    """Convert base64 string to hex string

        Args:
            s (str): Base64 string to convert

        Returns:
            Hex string
    """
    return hexlify(b64decode(s)).decode("ascii")


def StringToHex(s):
    """Convert ascii string to hex string

        Args:
            s (str): Ascii string to convert

        Returns:
            Hex string
    """
    hexstring = ""
    for c in s:
        r = format(ord(c), 'x')

        if len(r) == 1:
            hexstring += '0' + r
        else:
            hexstring += r

    return hexstring


def HexXOR(s1, s2):
    """XOR two equal-sized hex strings

        Args:
            s1 (str): Hex string
            s2 (str): Hex string

        Returns:
            Hex string, result of 's1 XOR s2'
    """
    xor = int(s1, 16) ^ int(s2, 16)

    if len(format(xor, 'x')) == 1:
        return '0' + format(xor, 'x')

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


def RepeatingXOR(plaintext, key):
    """XOR each byte of plaintext with a single byte of key
        When XOR'd with the last byte of key, reset key index

        Args:
            plaintext (str): Text to encrypt
            key       (str): Key used for encryption

        Returns:
            Hex string, the ciphered plaintext
    """
    index = 0
    digest = ""
    for c in plaintext:
        hexchar1 = format(ord(c), 'x')
        hexchar2 = format(ord(key[index]), 'x')

        xor = HexXOR(hexchar1, hexchar2)

        if len(xor) == 1:
            digest += '0' + xor
        else:
            digest += xor

        index += 1
        if index == len(key):
            index = 0

    return digest
