import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


ROOT_DIR = Path(__file__).resolve().parents[1]
KEYS_DIR = ROOT_DIR / "keys"

PRIVATE_KEY_PATH = KEYS_DIR / "rsa_private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "rsa_public.pem"


# =========================================================
# Base64 Helper
# =========================================================

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


# =========================================================
# Generate RSA Key Pair
# =========================================================

def generate_rsa_keys():

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        print("RSA key pair already exists.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Save private key
    with open(PRIVATE_KEY_PATH, "wb") as file:
        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    with open(PUBLIC_KEY_PATH, "wb") as file:
        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("RSA key pair generated.")


# =========================================================
# Load RSA Keys
# =========================================================

def load_public_key():

    with open(PUBLIC_KEY_PATH, "rb") as file:
        return serialization.load_pem_public_key(file.read())


def load_private_key():

    with open(PRIVATE_KEY_PATH, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


# =========================================================
# RSA Encrypt AES Key
# =========================================================

def rsa_encrypt_key(aes_key: bytes) -> str:

    public_key = load_public_key()

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return b64encode(encrypted_key)


# =========================================================
# RSA Decrypt AES Key
# =========================================================

def rsa_decrypt_key(encrypted_key: str) -> bytes:

    private_key = load_private_key()

    decrypted_key = private_key.decrypt(
        b64decode(encrypted_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_key