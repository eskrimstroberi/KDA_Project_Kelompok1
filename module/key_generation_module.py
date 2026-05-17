import os
import math
import base64
from collections import Counter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_secure_aes_key(bit_length: int = 256) -> bytes:
    """
    Generate cryptographically secure AES key.
    """

    if bit_length not in [128, 192, 256]:
        raise ValueError("AES hanya mendukung 128, 192, atau 256 bit.")

    return AESGCM.generate_key(bit_length=bit_length)


def generate_secure_random_bytes(length: int = 32) -> bytes:
    """
    Generate secure random bytes menggunakan OS entropy source.
    """

    return os.urandom(length)


def calculate_entropy(data: bytes) -> float:
    """
    Menghitung Shannon entropy.
    Semakin tinggi entropy, semakin random datanya.
    """

    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def validate_key_entropy(key: bytes, minimum_entropy: float = 4.0) -> dict:
    """
    Validasi entropy key.
    """

    entropy = calculate_entropy(key)

    return {
        "entropy": round(entropy, 4),
        "valid": entropy >= minimum_entropy
    }


def key_to_base64(key: bytes) -> str:
    """
    Convert key bytes ke base64 untuk storage.
    """

    return base64.b64encode(key).decode("utf-8")


def base64_to_key(encoded_key: str) -> bytes:
    """
    Convert base64 kembali ke bytes.
    """

    return base64.b64decode(encoded_key.encode("utf-8"))


def run_key_generation_test():
    """
    Testing secure key generation.
    """

    key1 = generate_secure_aes_key()
    key2 = generate_secure_aes_key()

    entropy1 = validate_key_entropy(key1)
    entropy2 = validate_key_entropy(key2)

    return {
        "key1_equals_key2": key1 == key2,
        "key1_entropy": entropy1,
        "key2_entropy": entropy2,
        "key1_base64": key_to_base64(key1),
        "key2_base64": key_to_base64(key2)
    }