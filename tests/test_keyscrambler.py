from streetpass_emu.keyscrambler import keygen_manual


def _pyctr_keygen_manual(key_x: bytes, key_y: bytes) -> bytes:
    """Reference implementation from the pyctr dependency (already used
    elsewhere in this project for NAND/OTP decryption), imported directly
    rather than reproduced by hand, so this test catches a divergence from
    the widely-used community implementation rather than just re-checking
    our own arithmetic against itself."""
    from pyctr.crypto.engine import CryptoEngine

    return CryptoEngine.keygen_manual(int.from_bytes(key_x, "big"), int.from_bytes(key_y, "big"))


def test_keygen_manual_matches_pyctr_for_arbitrary_keys():
    # Arbitrary, non-secret key material -- this only checks the public,
    # documented scrambler formula, not any particular keyslot's real key.
    key_x = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    key_y = bytes.fromhex("f0e0d0c0b0a090807060504030201000")

    assert keygen_manual(key_x, key_y) == _pyctr_keygen_manual(key_x, key_y)


def test_keygen_manual_matches_pyctr_for_all_zero_keys():
    key_x = bytes(16)
    key_y = bytes(16)

    assert keygen_manual(key_x, key_y) == _pyctr_keygen_manual(key_x, key_y)


def test_keygen_manual_matches_pyctr_for_all_ff_keys():
    key_x = b"\xff" * 16
    key_y = b"\xaa" * 16

    assert keygen_manual(key_x, key_y) == _pyctr_keygen_manual(key_x, key_y)


def test_keygen_manual_rejects_wrong_length():
    import pytest

    with pytest.raises(ValueError):
        keygen_manual(bytes(15), bytes(16))
    with pytest.raises(ValueError):
        keygen_manual(bytes(16), bytes(17))
