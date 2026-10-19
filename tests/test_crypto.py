import hashlib
import hmac

import pytest

from streetpass_emu.crypto import (
    CCMP_KEY_SIZE,
    HASH_BLOCK_SIZE,
    HMAC_KEY_RETAIL_CANDIDATE,
    _aes_ctr_encrypt_block,
    build_hash_block,
    derive_ccmp_key,
)


def test_hmac_key_retail_candidate_is_17_bytes_null_terminated():
    assert len(HMAC_KEY_RETAIL_CANDIDATE) == 17
    assert HMAC_KEY_RETAIL_CANDIDATE[-1] == 0


def test_build_hash_block_layout():
    host_console_id = bytes.fromhex("0102030405060708")
    client_console_id = bytes.fromhex("1112131415161718")
    host_mac = bytes.fromhex("aabbccddeeff")
    client_mac = bytes.fromhex("112233445566")

    block = build_hash_block(host_console_id, client_console_id, host_mac, client_mac)

    assert len(block) == HASH_BLOCK_SIZE
    assert block[0x00:0x08] == host_console_id
    assert block[0x08:0x10] == client_console_id
    assert block[0x10:0x16] == host_mac
    assert block[0x16:0x1C] == client_mac


@pytest.mark.parametrize(
    "field_name",
    ["host_console_id", "client_console_id", "host_mac", "client_mac"],
)
def test_build_hash_block_rejects_wrong_size(field_name):
    fields = {
        "host_console_id": bytes(8),
        "client_console_id": bytes(8),
        "host_mac": bytes(6),
        "client_mac": bytes(6),
    }
    fields[field_name] = fields[field_name][:-1]  # truncate by one byte

    with pytest.raises(ValueError):
        build_hash_block(**fields)


def test_aes_ctr_matches_nist_sp800_38a_vector():
    # NIST SP 800-38A, F.5.1 CTR-AES128.Encrypt, block 1.
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    counter = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_ciphertext = bytes.fromhex("874d6191b620e3261bef6864990db6ce")

    assert _aes_ctr_encrypt_block(key, counter, plaintext) == expected_ciphertext


def test_hmac_sha1_matches_rfc2202_vector():
    # RFC 2202, test case 1.
    key = bytes([0x0B] * 20)
    data = b"Hi There"
    expected_digest = bytes.fromhex("b617318655057264e28bc0b6fb378c8ef146be00")

    assert hmac.new(key, data, hashlib.sha1).digest() == expected_digest


def test_derive_ccmp_key_is_deterministic_and_correct_length():
    hash_block = build_hash_block(bytes(8), bytes(8), bytes(6), bytes(6))
    hmac_key = b"0" * 17
    streetpass_keyslot_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    key_a = derive_ccmp_key(hash_block, hmac_key, streetpass_keyslot_key)
    key_b = derive_ccmp_key(hash_block, hmac_key, streetpass_keyslot_key)

    assert len(key_a) == CCMP_KEY_SIZE
    assert key_a == key_b


def test_derive_ccmp_key_changes_with_hash_block():
    hmac_key = b"0" * 17
    streetpass_keyslot_key = bytes(16)

    block_a = build_hash_block(bytes(8), bytes(8), bytes(6), bytes(6))
    block_b = build_hash_block(bytes([1]) + bytes(7), bytes(8), bytes(6), bytes(6))

    assert derive_ccmp_key(block_a, hmac_key, streetpass_keyslot_key) != derive_ccmp_key(
        block_b, hmac_key, streetpass_keyslot_key
    )


@pytest.mark.parametrize(
    "hash_block,streetpass_keyslot_key",
    [
        (bytes(HASH_BLOCK_SIZE - 1), bytes(16)),
        (bytes(HASH_BLOCK_SIZE), bytes(15)),
    ],
)
def test_derive_ccmp_key_rejects_wrong_sizes(hash_block, streetpass_keyslot_key):
    with pytest.raises(ValueError):
        derive_ccmp_key(hash_block, b"0" * 17, streetpass_keyslot_key)
