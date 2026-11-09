import time
import statistics

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey
)

from pqcrypto.kem import ml_kem_768


def benchmark(name, operation, iterations=500):
    timings = []

    for _ in range(iterations):
        start = time.perf_counter_ns()
        operation()
        end = time.perf_counter_ns()

        timings.append((end - start) / 1_000_000)

    print(f"\n{name}")
    print(f"Average: {statistics.mean(timings):.4f} ms")
    print(f"Median: {statistics.median(timings):.4f} ms")
    print(f"Minimum: {min(timings):.4f} ms")
    print(f"Maximum: {max(timings):.4f} ms")


def x25519_keygen():
    X25519PrivateKey.generate()


def mlkem_keygen():
    ml_kem_768.keygen()


def mlkem_encapsulation():
    public_key, secret_key = ml_kem_768.keygen()
    ml_kem_768.encaps(public_key)


def mlkem_decapsulation():
    public_key, secret_key = ml_kem_768.keygen()
    ciphertext, shared_secret = ml_kem_768.encaps(public_key)
    ml_kem_768.decaps(secret_key, ciphertext)


benchmark("X25519 Key Generation", x25519_keygen)
benchmark("ML-KEM-768 Key Generation", mlkem_keygen)
benchmark("ML-KEM-768 Encapsulation", mlkem_encapsulation)
benchmark("ML-KEM-768 Decapsulation", mlkem_decapsulation)
