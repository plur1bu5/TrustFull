"""
trustkit.core.crypto
~~~~~~~~~~~~~~~~~~~~
Kerberos encryption type implementations using only the `cryptography` library.

Supports:
  - RC4-HMAC (etype 23)       — legacy, still common
  - AES128-CTS-HMAC-SHA1-96   — etype 17
  - AES256-CTS-HMAC-SHA1-96   — etype 18

Each cipher exposes:
  encrypt(key_bytes, key_usage, plaintext) -> ciphertext
  decrypt(key_bytes, key_usage, ciphertext) -> plaintext
  checksum(key_bytes, key_usage, data) -> mac  (HMAC-SHA1-96 or HMAC-MD5)
"""

import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Key usage constants (RFC 4120 §7.5.1)
# ---------------------------------------------------------------------------
KU_AS_REP_TICKET        = 2   # TGT encrypted with service key
KU_TGS_REP_TICKET       = 2   # same usage
KU_PAC_SERVER_CHECKSUM  = 17  # PAC server signature (HMAC-MD5 ignores this)
KU_PAC_PRIVSVR_CHECKSUM = 17  # PAC KDC signature

# ---------------------------------------------------------------------------
# RC4-HMAC (etype 23)
# ---------------------------------------------------------------------------

class RC4HMAC:
    ETYPE = 23

    @staticmethod
    def _hmac_md5(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.md5).digest()

    @classmethod
    def _derive_key(cls, base_key: bytes, usage: int) -> bytes:
        """RC4-HMAC key derivation: HMAC-MD5(key, usage_le32)."""
        return cls._hmac_md5(base_key, struct.pack('<I', usage))

    @classmethod
    def encrypt(cls, key: bytes, usage: int, plaintext: bytes) -> bytes:
        """RC4-HMAC encrypt: confounder + HMAC + RC4(data)."""
        import os
        confounder = os.urandom(8)
        k1 = cls._derive_key(key, usage)
        k2 = cls._hmac_md5(k1, confounder)
        # Checksum over confounder + plaintext
        checksum = cls._hmac_md5(k1, confounder + plaintext)
        k3 = cls._hmac_md5(k2, checksum)
        # RC4 encrypt confounder + plaintext
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        cipher = Cipher(algorithms.ARC4(k3), mode=None, backend=default_backend())
        enc = cipher.encryptor()
        encrypted = enc.update(confounder + plaintext)
        return checksum + encrypted

    @classmethod
    def decrypt(cls, key: bytes, usage: int, ciphertext: bytes) -> bytes:
        """RC4-HMAC decrypt."""
        checksum = ciphertext[:16]
        encrypted = ciphertext[16:]
        k1 = cls._derive_key(key, usage)
        k2 = cls._hmac_md5(k1, checksum)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        cipher = Cipher(algorithms.ARC4(k2), mode=None, backend=default_backend())
        dec = cipher.decryptor()
        decrypted = dec.update(encrypted)
        # decrypted = confounder(8) + plaintext
        return decrypted[8:]

    @classmethod
    def checksum(cls, key: bytes, usage: int, data: bytes) -> bytes:
        """HMAC-MD5 checksum (16 bytes). RC4 ignores key_usage."""
        k1 = cls._derive_key(key, usage)
        return cls._hmac_md5(k1, data)


# ---------------------------------------------------------------------------
# AES-CTS-HMAC-SHA1-96 (etypes 17 and 18)
# ---------------------------------------------------------------------------

class AESSHA196:
    """Base class for AES128 and AES256 Kerberos encryption."""

    ETYPE    = None   # set in subclasses
    KEYSIZE  = None
    HASHMOD  = hashlib.sha1
    MACSIZE  = 12     # 96 bits

    # PRF constants
    _BLOCKSIZE = 16

    @classmethod
    def _hmac_sha1(cls, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, cls.HASHMOD).digest()

    @classmethod
    def _derive_key(cls, base_key: bytes, usage: int, purpose: bytes) -> bytes:
        """
        Kerberos AES key derivation (RFC 3962):
        DR(key, constant) = k-truncate(E(key, constant, initial-cipher-state))
        """
        # Build the constant: usage (4 bytes BE) + purpose (1 byte)
        constant = struct.pack('>I', usage) + purpose
        # Expand constant to block size using CBC with zero IV
        n_blocks = (cls.KEYSIZE + cls._BLOCKSIZE - 1) // cls._BLOCKSIZE
        result = b''
        block = constant.ljust(cls._BLOCKSIZE, b'\x00')[:cls._BLOCKSIZE]
        iv = b'\x00' * cls._BLOCKSIZE
        for _ in range(n_blocks):
            cipher = Cipher(algorithms.AES(base_key), modes.CBC(iv), backend=default_backend())
            enc = cipher.encryptor()
            block = enc.update(block) + enc.finalize()
            result += block
        return result[:cls.KEYSIZE]

    @classmethod
    def _aes_cts_encrypt(cls, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        """AES-CBC with ciphertext stealing (CTS)."""
        # Pad to block boundary
        pad_len = (-len(plaintext)) % cls._BLOCKSIZE
        padded = plaintext + b'\x00' * pad_len
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        if len(plaintext) <= cls._BLOCKSIZE:
            return ciphertext[:len(plaintext)]
        # Swap last two blocks (CTS)
        n = len(ciphertext)
        last_full = ciphertext[:-cls._BLOCKSIZE]
        last_block = ciphertext[-cls._BLOCKSIZE:]
        second_last = last_full[-cls._BLOCKSIZE:]
        result = last_full[:-cls._BLOCKSIZE] + last_block + second_last
        return result[:len(plaintext)]

    @classmethod
    def _aes_cts_decrypt(cls, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """AES-CBC with ciphertext stealing (CTS) decrypt."""
        if len(ciphertext) <= cls._BLOCKSIZE:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            dec = cipher.decryptor()
            return (dec.update(ciphertext.ljust(cls._BLOCKSIZE, b'\x00')) + dec.finalize())[:len(ciphertext)]
        # Un-swap last two blocks
        n = len(ciphertext)
        last_block = ciphertext[-cls._BLOCKSIZE:]
        second_last = ciphertext[-(2 * cls._BLOCKSIZE):-cls._BLOCKSIZE]
        prefix = ciphertext[:-(2 * cls._BLOCKSIZE)]
        # Decrypt last block with second-last as IV to get second-last plaintext
        cipher = Cipher(algorithms.AES(key), modes.CBC(second_last), backend=default_backend())
        dec = cipher.decryptor()
        p_last = dec.update(last_block) + dec.finalize()
        # Reconstruct: prefix + p_last[:remainder] + second_last_block
        remainder = n % cls._BLOCKSIZE or cls._BLOCKSIZE
        reconstructed = prefix + last_block + second_last
        cipher2 = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec2 = cipher2.decryptor()
        plaintext = dec2.update(reconstructed) + dec2.finalize()
        return plaintext[:n]

    @classmethod
    def encrypt(cls, key: bytes, usage: int, plaintext: bytes) -> bytes:
        """AES-CTS-HMAC-SHA1-96 encrypt."""
        import os
        ke = cls._derive_key(key, usage, b'\xaa')  # encryption key
        ki = cls._derive_key(key, usage, b'\x55')  # integrity key
        confounder = os.urandom(cls._BLOCKSIZE)
        data = confounder + plaintext
        iv = b'\x00' * cls._BLOCKSIZE
        ciphertext = cls._aes_cts_encrypt(ke, iv, data)
        mac = cls._hmac_sha1(ki, ciphertext)[:cls.MACSIZE]
        return ciphertext + mac

    @classmethod
    def decrypt(cls, key: bytes, usage: int, ciphertext: bytes) -> bytes:
        """AES-CTS-HMAC-SHA1-96 decrypt."""
        ke = cls._derive_key(key, usage, b'\xaa')
        encrypted = ciphertext[:-cls.MACSIZE]
        iv = b'\x00' * cls._BLOCKSIZE
        plaintext = cls._aes_cts_decrypt(ke, iv, encrypted)
        # Strip confounder
        return plaintext[cls._BLOCKSIZE:]

    @classmethod
    def checksum(cls, key: bytes, usage: int, data: bytes) -> bytes:
        """HMAC-SHA1-96 checksum (12 bytes)."""
        kc = cls._derive_key(key, usage, b'\x99')
        return cls._hmac_sha1(kc, data)[:cls.MACSIZE]


class AES128SHA196(AESSHA196):
    ETYPE   = 17
    KEYSIZE = 16


class AES256SHA196(AESSHA196):
    ETYPE   = 18
    KEYSIZE = 32


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CIPHERS = {
    RC4HMAC.ETYPE:     RC4HMAC,
    AES128SHA196.ETYPE: AES128SHA196,
    AES256SHA196.ETYPE: AES256SHA196,
}


def get_cipher(etype: int):
    if etype not in CIPHERS:
        raise ValueError('Unsupported etype: %d' % etype)
    return CIPHERS[etype]
