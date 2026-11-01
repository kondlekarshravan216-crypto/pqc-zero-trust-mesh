import pytest
from cryptography.hazmat.primitives.asymmetric import x25519
from pqcrypto.kem import ml_kem_768
from pqc.hybrid_kem import (
    generate_responder_keys, encapsulate, decapsulate
)


def test_both_parties_derive_same_32_byte_key():
    x_private, kem_public, kem_secret = generate_responder_keys()
    message, initiator_key = encapsulate(x_private.public_key(), kem_public)
    responder_key = decapsulate(
        x_private, kem_secret, kem_public, message
    )
    assert len(initiator_key) == 32
    assert initiator_key == responder_key


def test_different_sessions_produce_different_keys():
    x_private, kem_public, kem_secret = generate_responder_keys()
    first, key1 = encapsulate(x_private.public_key(), kem_public)
    second, key2 = encapsulate(x_private.public_key(), kem_public)
    assert first != second
    assert key1 != key2


def test_invalid_kem_public_key_rejected():
    x_private, _, _ = generate_responder_keys()
    with pytest.raises(ValueError):
        encapsulate(x_private.public_key(), b"invalid")


def test_invalid_ciphertext_length_rejected():
    x_private, kem_public, kem_secret = generate_responder_keys()
    message, _ = encapsulate(x_private.public_key(), kem_public)
    message["kem_ciphertext"] = b"tampered"
    with pytest.raises(ValueError):
        decapsulate(x_private, kem_secret, kem_public, message)


def test_tampered_ciphertext_does_not_reproduce_initiator_key():
    x_private, kem_public, kem_secret = generate_responder_keys()
    message, initiator_key = encapsulate(x_private.public_key(), kem_public)
    damaged = dict(message)
    damaged["kem_ciphertext"] = bytes([damaged["kem_ciphertext"][0] ^ 1]) + damaged["kem_ciphertext"][1:]
    responder_key = decapsulate(x_private, kem_secret, kem_public, damaged)
    assert responder_key != initiator_key
