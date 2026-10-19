"""StreetPass CCMP session key derivation.

Reproduces the algorithm the 3DS CECD module uses, as documented on 3dbrew
(https://www.3dbrew.org/wiki/StreetPass,  the full
write-up):

    1. Assemble a 0x1C-byte "hash block" from the two consoles' StreetPass
       console IDs and MAC addresses.
    2. HMAC-SHA1 it with a 17-byte (NULL-terminated) key, retail/dev-specific.
    3. Use the first 16 bytes of that digest as an AES-CTR counter.
    4. Encrypt an all-zero 16-byte block with AES-CTR under the AES keyslot
       0x2E ("StreetPass", PS module KeyType 6 -- not raw keyslot 0x06, see
       project findings) normal key. The 16-byte output is the CCMP key.

HMAC_KEY_RETAIL_CANDIDATE below was recovered by disassembling a real
console's CECD module, and confirmed correct by
decrypting real StreetPass CCMP traffic captured from a real console and
matching its AES-CCM MIC. The keyslot-0x2E normal
key itself (the `streetpass_keyslot_key` argument to derive_ccmp_key()) is
also fully known now -- confirmed against three independent real test
vectors -- but its raw KeyX/KeyY are kept out of
this repository on purpose (see keyslot_2e.py's docstring for why and how
to supply your own). Two ways to get the actual normal key at runtime:
keyslot_2e.load_streetpass_normal_key() (a local file only you have) or
oracle.AesOracleClient (a real console on the network, no local file
needed).
"""

from __future__ import annotations

import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Util import Counter

HASH_BLOCK_SIZE = 0x1C
CONSOLE_ID_SIZE = 8
MAC_ADDRESS_SIZE = 6
CCMP_KEY_SIZE = 16

# Recovered from CECD (title 0004013000002602) on a retail console: the only
# 17-byte NULL-terminated, high-entropy string in its decompressed .code.
# Confirmed byte-for-byte identical on a second, unrelated retail console
# (same CECD binary, same offset), consistent with it being a firmware-wide
# constant rather than per-device data. Verified end-to-end against real
# StreetPass traffic on 2026-09-09 -- 
HMAC_KEY_RETAIL_CANDIDATE = b"Fsd33nrQdg0na29l\x00"


def build_hash_block(
    host_console_id: bytes,
    client_console_id: bytes,
    host_mac: bytes,
    client_mac: bytes,
) -> bytes:
    """Assemble the 0x1C-byte buffer CECD hashes to derive the CCMP key.

    Layout (3dbrew "StreetPass" article):
        0x00  host console ID     (8 bytes)
        0x08  client console ID   (8 bytes)
        0x10  host MAC address    (6 bytes)
        0x16  client MAC address  (6 bytes)

    "host" is whichever side sent the Probe Response (session.py's
    StreetPassResponder, i.e. us); "client" is the peer that was discovered
    via its broadcast Probe Request. Confirmed by this assignment (and not
    its reverse) successfully decrypting real captured traffic -- MIC
    verified against 18 real CCMP frames from a real console.
    """
    fields = (
        ("host_console_id", host_console_id, CONSOLE_ID_SIZE),
        ("client_console_id", client_console_id, CONSOLE_ID_SIZE),
        ("host_mac", host_mac, MAC_ADDRESS_SIZE),
        ("client_mac", client_mac, MAC_ADDRESS_SIZE),
    )
    for name, value, expected_size in fields:
        if len(value) != expected_size:
            raise ValueError(f"{name} must be {expected_size} bytes, got {len(value)}")

    block = host_console_id + client_console_id + host_mac + client_mac
    assert len(block) == HASH_BLOCK_SIZE
    return block


def _aes_ctr_encrypt_block(key: bytes, counter_value: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with AES-CTR (big-endian counter).

    Big-endian, whole-block counter matches both 3DS crypto conventions and
    NIST SP 800-38A's CTR test vectors (see tests/test_crypto.py).
    """
    counter = Counter.new(128, initial_value=int.from_bytes(counter_value, "big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(block)


def derive_ccmp_key(hash_block: bytes, hmac_key: bytes, streetpass_keyslot_key: bytes) -> bytes:
    """Derive the 16-byte StreetPass CCMP key from a hash block.

    Args:
        hash_block: the 0x1C-byte buffer from build_hash_block().
        hmac_key: the 17-byte NULL-terminated retail/dev HMAC key. See
            HMAC_KEY_RETAIL_CANDIDATE for a recovered-but-unverified value.
        streetpass_keyslot_key: the 16-byte AES normal key for keyslot 0x2E
            ("StreetPass"). See module docstring for how to obtain this
            (keyslot_2e.load_streetpass_normal_key() or oracle.py).
    """
    if len(hash_block) != HASH_BLOCK_SIZE:
        raise ValueError(f"hash_block must be {HASH_BLOCK_SIZE} bytes, got {len(hash_block)}")
    if len(streetpass_keyslot_key) != CCMP_KEY_SIZE:
        raise ValueError(f"streetpass_keyslot_key must be {CCMP_KEY_SIZE} bytes, got {len(streetpass_keyslot_key)}")

    digest = hmac.new(hmac_key, hash_block, hashlib.sha1).digest()
    ctr_bytes = digest[:CCMP_KEY_SIZE]

    return _aes_ctr_encrypt_block(streetpass_keyslot_key, ctr_bytes, bytes(CCMP_KEY_SIZE))
