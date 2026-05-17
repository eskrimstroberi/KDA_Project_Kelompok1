import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aes_module import b64encode


ROOT_DIR = Path(__file__).resolve().parents[1]

KEYS_DIR = ROOT_DIR / "keys"

KEYS_PATH = KEYS_DIR / "aes_keys_plain.json"


ROTATION_DAYS = 30


def load_keys():

    if not KEYS_PATH.exists():
        return {}

    with open(KEYS_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def save_keys(keys):

    with open(KEYS_PATH, "w", encoding="utf-8") as file:
        json.dump(keys, file, indent=4)


def rotate_key(table_name: str):

    keys = load_keys()

    # =====================================================
    # Cari versi terbaru
    # =====================================================

    versions = []

    for key_id in keys.keys():

        if key_id.startswith(f"{table_name}-key-v"):

            version = int(
                key_id.split("-v")[-1]
            )

            versions.append(version)

    latest_version = max(versions) if versions else 0

    new_version = latest_version + 1

    new_key_id = f"{table_name}-key-v{new_version}"

    # =====================================================
    # Nonaktifkan key lama
    # =====================================================

    for key_id in keys:

        if key_id.startswith(f"{table_name}-key-v"):

            keys[key_id]["status"] = "inactive"

    # =====================================================
    # Generate key baru
    # =====================================================

    aes_key = AESGCM.generate_key(
        bit_length=256
    )

    created_at = datetime.now(
        timezone.utc
    )

    expires_at = created_at + timedelta(
        days=ROTATION_DAYS
    )

    keys[new_key_id] = {
        "algorithm": "AES-256-GCM",
        "key_base64": b64encode(aes_key),
        "created_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "status": "active"
    }

    save_keys(keys)

    print("\n=== Key Rotation ===")

    print(f"Table        : {table_name}")
    print(f"New Key ID   : {new_key_id}")
    print(f"Rotation OK")

    return {
        "table_name": table_name,
        "new_key_id": new_key_id
    }


def auto_rotate_expired_keys():

    keys = load_keys()

    now = datetime.now(
        timezone.utc
    )

    rotated = []

    for key_id, metadata in keys.items():

        expires_at_str = metadata.get("expires_at")

        # kalau key lama belum punya expires_at
        if not expires_at_str:
            continue

        expires_at = datetime.fromisoformat(
            expires_at_str
        )

        if now > expires_at:

            table_name = key_id.split("-key-")[0]

            result = rotate_key(
                table_name
            )

            rotated.append(result)

    return rotated