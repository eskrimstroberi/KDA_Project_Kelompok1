import base64

from rsa_module import (
    rsa_encrypt_key,
    rsa_decrypt_key
)


def simulate_secure_key_distribution(aes_key: bytes):
    """
    Simulasi pengiriman AES key menggunakan RSA.
    """

    print("\n=== Secure Key Distribution Simulation ===")

    # =====================================================
    # Sender encrypt AES key menggunakan RSA public key
    # =====================================================

    encrypted_key = rsa_encrypt_key(
        aes_key
    )

    print("AES key berhasil dienkripsi RSA.")

    # =====================================================
    # Simulasi attacker/eavesdropper
    # =====================================================

    print("\n[Eavesdropper]")
    print("Attacker hanya melihat encrypted key:")

    print(
        encrypted_key[:120],
        "..."
    )

    # =====================================================
    # Receiver decrypt menggunakan RSA private key
    # =====================================================

    decrypted_key = rsa_decrypt_key(
        encrypted_key
    )

    print("\n[Receiver]")
    print("AES key berhasil didekripsi.")

    success = decrypted_key == aes_key

    print(f"Key cocok? : {success}")

    return {
        "distribution_success": success
    }


def simulate_mitm_attack(aes_key: bytes):
    """
    Simulasi Man-In-The-Middle attack.
    Attacker mengubah encrypted AES key.
    """

    print("\n=== MITM Attack Simulation ===")

    # =====================================================
    # Sender encrypt AES key
    # =====================================================

    encrypted_key = rsa_encrypt_key(
        aes_key
    )

    print("AES key asli berhasil dienkripsi.")

    # =====================================================
    # Attacker memodifikasi ciphertext
    # =====================================================

    tampered = bytearray (
        encrypted_key.encode("utf-8")
    )

    tampered[10] ^= 0xFF

    tampered = bytes(tampered)

    print("Ciphertext RSA dimodifikasi attacker.")

    # =====================================================
    # Receiver mencoba decrypt
    # =====================================================

    try:

        rsa_decrypt_key(
            tampered
        )

        print("[WARNING]")
        print("Tampered ciphertext masih bisa didekripsi!")

        return {
            "mitm_detected": False
        }

    except Exception:

        print("[SECURE]")
        print("Manipulasi ciphertext berhasil terdeteksi.")
        print("Decrypt gagal.")

        return {
            "mitm_detected": True
        }