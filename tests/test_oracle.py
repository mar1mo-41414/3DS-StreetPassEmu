import socket
import threading

import pytest

from streetpass_emu.crypto import HMAC_KEY_RETAIL_CANDIDATE, build_hash_block
from streetpass_emu.oracle import AesOracleClient, OracleError

# Real hardware capture: a real Old3DS (serial
# <serial>) computing PS_EncryptDecryptAes(..., PS_KEYSLOT_2E, ctr) on an
# all-zero plaintext block for this exact CTR returned this exact result.
REAL_CTR = bytes.fromhex("00112233445566778899aabbccddeeff")
REAL_RESULT = bytes.fromhex("76eb64cfd81af8e7f61147970221ed25")


class _FakeOracleServer:
    """Stands in for homebrew/aes_oracle: reads a 16-byte CTR, replies with a
    canned 16-byte response, repeatedly, until the client disconnects."""

    def __init__(self, response: bytes = REAL_RESULT, requests_before_close: int = None):
        self._response = response
        self._requests_before_close = requests_before_close
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.port = self._listener.getsockname()[1]
        self.received: list[bytes] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        conn, _ = self._listener.accept()
        with conn:
            count = 0
            while True:
                if self._requests_before_close is not None and count >= self._requests_before_close:
                    break
                ctr = conn.recv(16)
                if len(ctr) != 16:
                    break
                self.received.append(ctr)
                conn.sendall(self._response)
                count += 1

    def close(self) -> None:
        self._listener.close()


@pytest.fixture
def fake_oracle():
    server = _FakeOracleServer()
    yield server
    server.close()


def test_derive_ccmp_key_round_trips_real_hardware_vector(fake_oracle):
    with AesOracleClient("127.0.0.1", fake_oracle.port) as client:
        result = client.derive_ccmp_key(REAL_CTR)

    assert result == REAL_RESULT
    assert fake_oracle.received == [REAL_CTR]


def test_derive_ccmp_key_supports_multiple_requests_on_one_connection(fake_oracle):
    with AesOracleClient("127.0.0.1", fake_oracle.port) as client:
        first = client.derive_ccmp_key(REAL_CTR)
        second = client.derive_ccmp_key(bytes(16))

    assert first == REAL_RESULT
    assert second == REAL_RESULT
    assert fake_oracle.received == [REAL_CTR, bytes(16)]


def test_derive_ccmp_key_from_hash_block_end_to_end(fake_oracle):
    hash_block = build_hash_block(bytes(8), bytes(8), bytes(6), bytes(6))

    with AesOracleClient("127.0.0.1", fake_oracle.port) as client:
        result = client.derive_ccmp_key_from_hash_block(hash_block, HMAC_KEY_RETAIL_CANDIDATE)

    assert result == REAL_RESULT  # the fake oracle always answers with this
    assert len(fake_oracle.received) == 1
    assert len(fake_oracle.received[0]) == 16  # the CTR the client computed locally


def test_derive_ccmp_key_from_hash_block_rejects_wrong_size(fake_oracle):
    with AesOracleClient("127.0.0.1", fake_oracle.port) as client:
        with pytest.raises(ValueError):
            client.derive_ccmp_key_from_hash_block(bytes(10), HMAC_KEY_RETAIL_CANDIDATE)


def test_derive_ccmp_key_rejects_wrong_ctr_size(fake_oracle):
    with AesOracleClient("127.0.0.1", fake_oracle.port) as client:
        with pytest.raises(ValueError):
            client.derive_ccmp_key(bytes(15))


def test_derive_ccmp_key_raises_on_early_disconnect():
    server = _FakeOracleServer(requests_before_close=0)
    try:
        with AesOracleClient("127.0.0.1", server.port) as client:
            with pytest.raises(OracleError):
                client.derive_ccmp_key(REAL_CTR)
    finally:
        server.close()
