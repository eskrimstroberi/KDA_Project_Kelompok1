import os
import json
import base64
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT_DIR = Path(__file__).resolve().parents[1]

KEYS_DIR = ROOT_DIR / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)

VAULT_KEY_PATH = KEYS_DIR / "vault_master_key.bin"
VAULT_FILE = KEYS_DIR / "aes_keys_encrypted.json"


# =====================================================
# Helper
# =====================================================

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


# =====================================================
# Master Vault Key
# =====================================================

def load_or_create_vault_key() -> bytes:

    if VAULT_KEY_PATH.exists():
        return VAULT_KEY_PATH.read_bytes()

    vault_key = AESGCM.generate_key(
        bit_length=256
    )

    VAULT_KEY_PATH.write_bytes(vault_key)

    return vault_key


# =====================================================
# Encrypt Vault
# =====================================================

def encrypt_key_registry(keys_dict: dict):

    vault_key = load_or_create_vault_key()

    aesgcm = AESGCM(vault_key)

    nonce = os.urandom(12)

    plaintext = json.dumps(
        keys_dict,
        indent=4
    ).encode("utf-8")

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        None
    )

    vault_payload = {
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext)
    }

    with open(VAULT_FILE, "w", encoding="utf-8") as file:
        json.dump(vault_payload, file, indent=4)

    print("\n=== Secure Key Vault ===")
    print("Key registry encrypted successfully.")


# =====================================================
# Decrypt Vault
# =====================================================

def decrypt_key_registry() -> dict:

    if not VAULT_FILE.exists():
        return {}

    vault_key = load_or_create_vault_key()

    with open(VAULT_FILE, "r", encoding="utf-8") as file:
        payload = json.load(file)

    nonce = b64decode(payload["nonce"])
    ciphertext = b64decode(payload["ciphertext"])

    aesgcm = AESGCM(vault_key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return json.loads(
        plaintext.decode("utf-8")
    )