"""Hybrid X25519 + ML-KEM-768 key establishment prototype."""
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768

PROTOCOL = b"PQZT-HYBRID-X25519-ML-KEM-768-v1"
KEY_LEN = 32


def public_bytes(key):
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def generate_responder_keys():
    """Generate responder X25519 and ML-KEM key pairs."""
    x_private = x25519.X25519PrivateKey.generate()
    kem_public, kem_secret = ml_kem_768.keygen()
    return x_private, kem_public, kem_secret


def encapsulate(responder_x_public, responder_kem_public):
    """Initiator creates the handshake message and shared key."""
    if len(responder_kem_public) != ml_kem_768.PUBLIC_KEY_SIZE:
        raise ValueError("Invalid ML-KEM public key length")

    initiator_x_private = x25519.X25519PrivateKey.generate()
    initiator_x_public = public_bytes(initiator_x_private.public_key())
    ecdh_secret = initiator_x_private.exchange(responder_x_public)
    ciphertext, kem_secret = ml_kem_768.encaps(responder_kem_public)

    transcript = (
        PROTOCOL + public_bytes(responder_x_public) +
        responder_kem_public + initiator_x_public + ciphertext
    )
    shared_key = _derive(ecdh_secret, kem_secret, transcript)
    message = {"x25519_public": initiator_x_public, "kem_ciphertext": ciphertext}
    return message, shared_key


def decapsulate(responder_x_private, responder_kem_secret, responder_kem_public,
                message):
    """Responder derives the same key from the initiator's handshake message."""
    x_public = message["x25519_public"]
    ciphertext = message["kem_ciphertext"]
    if len(x_public) != 32:
        raise ValueError("Invalid X25519 public key length")
    if len(ciphertext) != ml_kem_768.CIPHERTEXT_SIZE:
        raise ValueError("Invalid ML-KEM ciphertext length")

    initiator_x_public = x25519.X25519PublicKey.from_public_bytes(x_public)
    ecdh_secret = responder_x_private.exchange(initiator_x_public)
    kem_secret = ml_kem_768.decaps(responder_kem_secret, ciphertext)

    transcript = (
        PROTOCOL + public_bytes(responder_x_private.public_key()) +
        responder_kem_public + x_public + ciphertext
    )
    return _derive(ecdh_secret, kem_secret, transcript)


def _derive(ecdh_secret, kem_secret, transcript):
    # Domain-separated transcript-bound KDF; never use either input secret alone.
    ikm = len(ecdh_secret).to_bytes(2, "big") + ecdh_secret
    ikm += len(kem_secret).to_bytes(2, "big") + kem_secret
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=hashlib.sha256(transcript).digest(),
        info=PROTOCOL,
    ).derive(ikm)
