from hashlib import sha256
from math import ceil
import random

# Function names respect those in https://www.ietf.org/rfc/rfc3447.txt

# SHA-256
HASH_ID = b'010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 '

def i2osp(x : int, k : int) -> bytes:
    """
    Convert the integer x to a sequence of k bytes
    """
    return x.to_bytes(k, byteorder='big')


def os2ip(x : bytes) -> int:
    """
    Convert the sequence of bytes to an integer
    """
    return int.from_bytes(x, byteorder='big')


def emsa_pkcs1_encode(M : bytes, k : int) -> bytes:
    """
    Encode a message into k bytes for RSA signature
    """
    h = sha256(M)
    T = HASH_ID + h.digest()
    if len(T) + 11 > k:
        raise ValueError("Message Too Long")
    PS = bytes([0xff] * (k - len(T) - 3))
    EM = bytes([0x00, 0x01]) + PS + bytes([0x00]) + T
    return EM


def emsa_pkcs1_decode(EM : bytes, k : int) -> bytes:
    """
    Given an EMSA_PKCS1-encoded message, returns the Hash
    
    >>> x = emsa_pkcs1_encode("toto", 128)
    >>> emsa_pkcs1_decode(x, 128) == sha256("toto".encode()).digest()
    True
    """
    if len(EM) != k:
        raise ValueError("Incorrect Size")
    if EM[:2] != bytes([0x00, 0x01]):
        raise ValueError("Incorrect Header")
    i = 2
    while EM[i] != 0:
        if EM[i] != 0xff:
            raise ValueError("Incorrect Filler")
        i += 1
        if i == k:
            raise ValueError("Only Filler")
    if i < 10:
        raise ValueError("Not enough filler")
    T = EM[i+1:]
    if T[:len(HASH_ID)] != HASH_ID:
        raise ValueError("Bad Hash ID")
    H = T[len(HASH_ID):]
    H = H[0:32]  # hashes are 32-byte long, ignore the rest
    return H


def eme_pkcs1_encode(M : bytes, k : int) -> bytes:
    """
    Encode a message into k bytes for RSA encryption
    """
    if len(M) + 11 > k:
        raise ValueError("Message Too Long")
    PS = bytes([random.randrange(1, 256) for _ in  range(k - 3)])
    EM = bytes([0x00, 0x02]) + PS + bytes([0x00]) + M
    return EM


def eme_pkcs1_decode(EM : bytes, k : int) -> bytes:
    """
    Given an EME_PKCS1-encoded message, returns the message
    
    >>> x = eme_pkcs1_encode("toto", 128)
    >>> eme_pkcs1_decode(x, 128) == "toto"
    True
    """
    if len(EM) != k:
        raise ValueError("Incorrect Size")
    if EM[:2] != bytes([0x00, 0x02]):
        raise ValueError("Incorrect Header")
    i = 2
    while EM[i] != 0:
        i += 1
        if i == k:
            raise ValueError("Only Filler")
    if i < 10:
        raise ValueError("Not enough filler")
    M = EM[i+1:]
    return M


def key_length(n : int) -> int:
    """
    key length in bytes
    """
    return ceil(n.bit_length() / 8)


def rsa_pkcs_sign(n : int, d : int, M : bytes):
    """
    RSA Signature using PKCS#1 v1.5 encoding
    """
    k = key_length(n)
    EM = emsa_pkcs1_encode(M, k)
    m = os2ip(EM)
    s = pow(m, d, n)
    S = i2osp(s, k)
    return S


def rsa_pkcs_verify(n : int, e : int, M : bytes, S : bytes) -> bool:
    """
    Verify RSA PKCS#1 v1.5 signatures
    """
    k = key_length(n)
    if len(S) != k:
        raise ValueError("Bad length")
    s = os2ip(S)
    m = pow(s, e, n)
    EM = i2osp(m, k)
    H = emsa_pkcs1_decode(EM, k)
    return (H == sha256(M).digest())


def rsa_pkcs_encrypt(n : int, e : int, M : bytes) -> bytes:
    """
    RSA encryption using PKCS#1 v1.5 encoding
    """
    k = key_length(n)
    EM = eme_pkcs1_encode(M, k)
    m = os2ip(EM)
    c = pow(m, e, n)
    C = i2osp(c, k)
    return C


def rsa_pkcs_decrypt(n : int, d : int, C : bytes) -> bytes:
    """
    RSA decryption using PKCS#1 v1.5 encoding
    """
    k = key_length(n)
    if len(C) != k:
        raise ValueError("Bad length")
    c = os2ip(C)
    m = pow(c, d, n)
    EM = i2osp(m, k)
    M = eme_pkcs1_decode(EM, k)
    return M