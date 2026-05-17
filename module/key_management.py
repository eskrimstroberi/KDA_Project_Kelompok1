import os
import math
import base64
from collections import Counter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_secure_aes_key(bit_length=256):
   
    # Generate AES key menggunakan CSPRNG.

    return AESGCM.generate_key(
        bit_length=bit_length
    )

def calculate_entropy(data: bytes) -> float:

    # Menghitung Shannon entropy.

    if not data:
        return 0

    counter = Counter(data)
    length = len(data)

    entropy = 0

    for count in counter.values():
        probability = count / length

        entropy -= probability * math.log2(probability)

    return entropy

def key_generation_test(total_keys=5):
    
    # Test secure AES key generation.

    results = []

    for i in range(total_keys):

        key = generate_secure_aes_key()

        entropy = calculate_entropy(key)

        results.append({
            "key_number": i + 1,
            "key_base64": base64.b64encode(key).decode(),
            "entropy": round(entropy, 4),
            "key_length_bytes": len(key)
        })

    return results