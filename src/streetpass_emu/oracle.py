"""Client for the "StreetPass AES keyslot 0x2E oracle" homebrew.

Static extraction of keyslot 0x2E's raw key bytes hasn't succeeded (see
project findings). Since the session-specific part of the CCMP
derivation is entirely in the CTR (which this side already computes via
build_hash_block()/HMAC-SHA1, see crypto.py), a real 3DS running
homebrew/aes_oracle can just perform that one AES-CTR block operation on a
chosen CTR and hand back the result -- without either side ever needing to
know keyslot 0x2E's actual key.

See homebrew/aes_oracle/source/main.c for the on-console side (plain TCP,
ORACLE_PORT, one connection at a time, 16 bytes in -> 16 bytes out).
"""

from __future__ import annotations

import hashlib
import hmac
import socket

from .crypto import HASH_BLOCK_SIZE

ORACLE_PORT = 17491
CTR_SIZE = 16
CCMP_KEY_SIZE = 16


class OracleError(Exception):
    """The oracle connection did not behave as expected."""


class AesOracleClient:
    """A connection to a real 3DS running homebrew/aes_oracle."""

    def __init__(self, host: str, port: int = ORACLE_PORT, timeout: float = 2.0):
        self._sock = socket.create_connection((host, port), timeout=timeout)

    def derive_ccmp_key(self, ctr: bytes) -> bytes:
        """Ask the console to compute AES-CTR(zero_block) under keyslot 0x2E
        for this CTR -- i.e. the real StreetPass CCMP key for it."""
        if len(ctr) != CTR_SIZE:
            raise ValueError(f"ctr must be {CTR_SIZE} bytes, got {len(ctr)}")

        try:
            self._sock.sendall(ctr)
            return self._recv_exact(CCMP_KEY_SIZE)
        except OSError as e:
            raise OracleError(f"oracle connection failed: {e}") from e

    def derive_ccmp_key_from_hash_block(self, hash_block: bytes, hmac_key: bytes) -> bytes:
        """End-to-end version of crypto.derive_ccmp_key(): HMAC-SHA1s the
        hash block locally (see crypto.py for why that half doesn't need the
        console), then asks the oracle for the AES-CTR half. Never touches
        keyslot 0x2E's actual key bytes."""
        if len(hash_block) != HASH_BLOCK_SIZE:
            raise ValueError(f"hash_block must be {HASH_BLOCK_SIZE} bytes, got {len(hash_block)}")

        digest = hmac.new(hmac_key, hash_block, hashlib.sha1).digest()
        ctr = digest[:CTR_SIZE]
        return self.derive_ccmp_key(ctr)

    def _recv_exact(self, size: int) -> bytes:
        buf = bytearray()
        while len(buf) < size:
            chunk = self._sock.recv(size - len(buf))
            if not chunk:
                raise OracleError("connection closed before a full response arrived")
            buf.extend(chunk)
        return bytes(buf)

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> "AesOracleClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
