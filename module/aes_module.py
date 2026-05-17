import os
import json
import hmac
import time
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from otp_module import (
    generate_otp,
    generate_otp_aes_key
)

import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT_DIR = Path(__file__).resolve().parents[1]
KEYS_DIR = ROOT_DIR / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)


SENSITIVE_COLUMNS = {
    "patients": [
        "Id", "BIRTHDATE", "DEATHDATE", "SSN", "DRIVERS", "PASSPORT",
        "PREFIX", "FIRST", "LAST", "SUFFIX", "MAIDEN", "MARITAL",
        "RACE", "ETHNICITY", "GENDER", "BIRTHPLACE", "ADDRESS",
        "CITY", "STATE", "COUNTY", "ZIP", "LAT", "LON",
        "HEALTHCARE_EXPENSES", "HEALTHCARE_COVERAGE"
    ],
    "conditions": [
        "PATIENT", "ENCOUNTER", "DESCRIPTION"
    ],
    "encounters": [
        "Id", "PATIENT", "ORGANIZATION", "PROVIDER", "PAYER",
        "DESCRIPTION", "BASE_ENCOUNTER_COST", "TOTAL_CLAIM_COST",
        "PAYER_COVERAGE", "REASONCODE", "REASONDESCRIPTION"
    ],
    "medications": [
        "PATIENT", "PAYER", "ENCOUNTER", "DESCRIPTION",
        "BASE_COST", "PAYER_COVERAGE", "DISPENSES", "TOTALCOST",
        "REASONCODE", "REASONDESCRIPTION"
    ],
    # ------------------------------------------------------------------ #
    "allergies": [
        "PATIENT", "ENCOUNTER", "DESCRIPTION", "TYPE", "CATEGORY",
        "REACTION1", "DESCRIPTION1", "REACTION2", "DESCRIPTION2"
    ],
    "careplans": [
        "Id", "PATIENT", "ENCOUNTER", "DESCRIPTION",
        "REASONCODE", "REASONDESCRIPTION"
    ],
    "claims": [
        "Id", "PATIENTID", "PROVIDERID", "PRIMARYPATIENTINSURANCEID",
        "SECONDARYPATIENTINSURANCEID", "DEPARTMENTID", "PATIENTDEPARTMENTID",
        "DIAGNOSIS1", "DIAGNOSIS2", "DIAGNOSIS3", "DIAGNOSIS4",
        "DIAGNOSIS5", "DIAGNOSIS6", "DIAGNOSIS7", "DIAGNOSIS8",
        "REFERRINGPROVIDERID", "APPOINTMENTID", "CURRENTILLNESSDATE",
        "SERVICEDATE", "SUPERVISINGPROVIDERID", "OTHERAPROVIDERID"
    ],
    "claims_transactions": [
        "ID", "CLAIMID", "PATIENTID", "PROVIDERID", "SUPERVISINGPROVIDERID",
        "FROMDATE", "TODATE", "PROCEDURECODE", "MODIFIER1", "MODIFIER2",
        "DIAGNOSISREF1", "DIAGNOSISREF2", "DIAGNOSISREF3", "DIAGNOSISREF4",
        "UNITS", "DEPARTMENTID", "NOTES", "UNITAMOUNT", "TRANSFEROUTID",
        "TRANSFERTYPE", "PAYMENTS", "ADJUSTMENTS", "TRANSFERS", "OUTSTANDING",
        "APPOINTMENTID", "LINENOTE", "PATIENTINSURANCEID", "FEESCHEDULEID",
        "PLACEOFSERVICE"
    ],
    "devices": [
        "PATIENT", "ENCOUNTER", "DESCRIPTION", "UDI"
    ],
    "imaging_studies": [
        "Id", "PATIENT", "ENCOUNTER", "BODYSITE_DESCRIPTION",
        "MODALITY_DESCRIPTION", "SOP_DESCRIPTION"
    ],
    "immunizations": [
        "PATIENT", "ENCOUNTER", "DESCRIPTION"
    ],
    "observations": [
        "PATIENT", "ENCOUNTER", "DESCRIPTION", "VALUE", "UNITS", "TYPE"
    ],
    "organizations": [
        "Id", "NAME", "ADDRESS", "CITY", "STATE", "ZIP", "LAT", "LON",
        "PHONE"
    ],
    "payer_transitions": [
        "PATIENT", "MEMBERID", "SECONDARY_MEMBERID"
    ],
    "payers": [
        "Id", "NAME", "ADDRESS", "CITY", "STATE_HEADQUARTERED", "ZIP",
        "PHONE"
    ],
    "procedures": [
        "PATIENT", "ENCOUNTER", "DESCRIPTION", "BASE_COST",
        "REASONCODE", "REASONDESCRIPTION"
    ],
    "providers": [
        "Id", "ORGANIZATION", "NAME", "GENDER", "SPECIALITY",
        "ADDRESS", "CITY", "STATE", "ZIP", "LAT", "LON"
    ],
    "supplies": [
        "PATIENT", "ENCOUNTER", "DESCRIPTION"
    ],
}


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def clean_value(value):
    if pd.isna(value):
        return None

    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass

    return value


def load_or_create_token_key() -> bytes:
    token_key_path = KEYS_DIR / "token_key.bin"

    if token_key_path.exists():
        return token_key_path.read_bytes()

    token_key = os.urandom(32)
    token_key_path.write_bytes(token_key)
    return token_key


def make_token(value, token_key: bytes) -> str:

    if pd.isna(value):
        return ""

    return hmac.new(
        token_key,
        str(value).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def load_or_create_aes_key(table_name: str):
 
    keys_path = KEYS_DIR / "aes_keys_plain.json"
    key_id = f"{table_name}-key-v1"

    if keys_path.exists():
        with open(keys_path, "r", encoding="utf-8") as file:
            keys = json.load(file)
    else:
        keys = {}

    if key_id not in keys:
        aes_key = AESGCM.generate_key(bit_length=256)

        keys[key_id] = {
            "algorithm": "AES-256-GCM",
            "key_base64": b64encode(aes_key),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "active"
        }

        with open(keys_path, "w", encoding="utf-8") as file:
            json.dump(keys, file, indent=4)

    aes_key = b64decode(keys[key_id]["key_base64"])
    return key_id, aes_key


def get_aes_key_from_plain_registry(key_id: str) -> bytes:
    keys_path = KEYS_DIR / "aes_keys_plain.json"

    with open(keys_path, "r", encoding="utf-8") as file:
        keys = json.load(file)

    if key_id not in keys:
        raise KeyError(f"Key ID tidak ditemukan: {key_id}")

    return b64decode(keys[key_id]["key_base64"])


def build_metadata(table_name: str, key_id: str, created_at: str, expires_at: str) -> dict:
    return {
        "table": table_name,
        "algorithm": "AES-256-GCM",
        "key_id": key_id,
        "created_at": created_at,
        "expires_at": expires_at
    }


def encrypt_payload(
    payload: dict,
    table_name: str,
    key_id: str,
    aes_key: bytes,
    access_minutes: int = 60
) -> dict:
   
    otp = generate_otp()

    otp_aes_key = generate_otp_aes_key(
        aes_key,
        otp
    )

    aesgcm = AESGCM(otp_aes_key)
    nonce = os.urandom(12)

    created_at_dt = datetime.now(timezone.utc)
    expires_at_dt = created_at_dt + timedelta(minutes=access_minutes)

    created_at = created_at_dt.isoformat()
    expires_at = expires_at_dt.isoformat()

    metadata = build_metadata(
        table_name=table_name,
        key_id=key_id,
        created_at=created_at,
        expires_at=expires_at,
        
    )

    aad_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    aad = aad_json.encode("utf-8")

    plaintext = json.dumps(
        payload,
        ensure_ascii=False,
        default=str
    ).encode("utf-8")

    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return {
        "key_id": key_id,
        "algorithm": "AES-256-GCM",
        "otp": otp,
        "otp_length": len(otp),
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
        "aad": aad_json,
        "created_at": created_at,
        "expires_at": expires_at
    }


def decrypt_payload(row: dict, table_name: str, aes_key=None) -> dict:
    if hasattr(row, "to_dict"):
        row = row.to_dict()

    otp_raw = row.get("otp", "")
    if pd.isna(otp_raw):
        otp_raw = ""
    otp = str(otp_raw).strip()
    # Hapus .0 jika pandas parse sebagai float
    if otp.endswith(".0"):
        otp = otp[:-2]
    # Pastikan leading zero tidak hilang
    otp_length_raw = row.get("otp_length", len(otp))
    if pd.notna(otp_length_raw):
        expected_len = int(otp_length_raw)
        if len(otp) < expected_len:
            otp = otp.zfill(expected_len)

    expires_at_raw = row.get("expires_at", "")
    if pd.isna(expires_at_raw):
        raise PermissionError("Akses ditolak: data tidak valid (expires_at kosong).")
    
    expires_at = datetime.fromisoformat(str(expires_at_raw).strip())
    now = datetime.now(timezone.utc)

    if now > expires_at:
        raise PermissionError("Akses ditolak: waktu akses sudah expired.")

    key_id = str(row.get("key_id", "")).strip()

    if aes_key is None:
        aes_key = get_aes_key_from_plain_registry(key_id)

    otp_aes_key = generate_otp_aes_key(
        aes_key,
        otp
    )

    aesgcm = AESGCM(otp_aes_key)

    nonce = b64decode(
        str(row.get("nonce", "")).strip()
    )

    ciphertext = b64decode(
        str(row.get("ciphertext", "")).strip()
    )

    aad = str(row.get("aad", "")).encode("utf-8")

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        aad
    )

    return json.loads(
        plaintext.decode("utf-8")
    )


def add_relation_tokens(
    public_df: pd.DataFrame,
    original_df: pd.DataFrame,
    table_name: str,
    token_key: bytes
) -> pd.DataFrame:
    """
    Menambahkan patient_token dan encounter_token supaya tabel tetap bisa dihubungkan.
    """
    public_df = public_df.copy()

    if table_name == "patients" and "Id" in original_df.columns:
        public_df["patient_token"] = original_df["Id"].apply(
            lambda value: make_token(value, token_key)
        )

    if "PATIENT" in original_df.columns:
        public_df["patient_token"] = original_df["PATIENT"].apply(
            lambda value: make_token(value, token_key)
        )

    if table_name == "encounters" and "Id" in original_df.columns:
        public_df["encounter_token"] = original_df["Id"].apply(
            lambda value: make_token(value, token_key)
        )

    if "ENCOUNTER" in original_df.columns:
        public_df["encounter_token"] = original_df["ENCOUNTER"].apply(
            lambda value: make_token(value, token_key)
        )

    if table_name == "organizations" and "Id" in original_df.columns:
        public_df["organization_token"] = original_df["Id"].apply(
            lambda value: make_token(value, token_key)
        )

    if "ORGANIZATION" in original_df.columns:
        public_df["organization_token"] = original_df["ORGANIZATION"].apply(
            lambda value: make_token(value, token_key)
        )

    if table_name == "payers" and "Id" in original_df.columns:
        public_df["payer_token"] = original_df["Id"].apply(
            lambda value: make_token(value, token_key)
        )

    if "PAYER" in original_df.columns:
        public_df["payer_token"] = original_df["PAYER"].apply(
            lambda value: make_token(value, token_key)
        )

    if table_name == "providers" and "Id" in original_df.columns:
        public_df["provider_token"] = original_df["Id"].apply(
            lambda value: make_token(value, token_key)
        )

    if "PROVIDER" in original_df.columns:
        public_df["provider_token"] = original_df["PROVIDER"].apply(
            lambda value: make_token(value, token_key)
        )

    if table_name == "claims" and "Id" in original_df.columns:
        public_df["claim_token"] = original_df["Id"].apply(
            lambda value: make_token(value, token_key)
        )

    if "CLAIMID" in original_df.columns:
        public_df["claim_token"] = original_df["CLAIMID"].apply(
            lambda value: make_token(value, token_key)
        )

    return public_df


def encrypt_table(
    input_file: str,
    output_file: str,
    table_name: str,
    sample_rows=None,
    access_minutes: int = 60
) -> dict:
    """
    Enkripsi kolom sensitif dari satu tabel CSV.
    sample_rows=None berarti semua data dipakai.
    """
    input_path = Path(input_file)
    output_path = Path(output_file)

    if table_name not in SENSITIVE_COLUMNS:
        raise ValueError(f"Table tidak dikenal: {table_name}")

    if not input_path.exists():
        raise FileNotFoundError(f"File input tidak ditemukan: {input_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_path)

    if sample_rows is not None:
        df = df.head(sample_rows)

    original_size_kb = input_path.stat().st_size / 1024

    token_key = load_or_create_token_key()
    key_id, aes_key = load_or_create_aes_key(table_name)

    sensitive_cols = [
        column for column in SENSITIVE_COLUMNS[table_name]
        if column in df.columns
    ]

    public_df = df.drop(columns=sensitive_cols, errors="ignore").copy()
    public_df = add_relation_tokens(public_df, df, table_name, token_key)

    encrypted_rows = []

    start_time = time.perf_counter()

    for _, row in df.iterrows():
        payload = {
            column: clean_value(row[column])
            for column in sensitive_cols
            if column in df.columns
        }

        encrypted = encrypt_payload(
            payload=payload,
            table_name=table_name,
            key_id=key_id,
            aes_key=aes_key,
            access_minutes=access_minutes
        )

        encrypted_rows.append(encrypted)

    encryption_time = time.perf_counter() - start_time

    encrypted_df = pd.concat(
        [
            public_df.reset_index(drop=True),
            pd.DataFrame(encrypted_rows)
        ],
        axis=1
    )

    if "otp" in encrypted_df.columns:
        encrypted_df["otp"] = encrypted_df["otp"].astype(str)
    if "otp_length" in encrypted_df.columns:
        encrypted_df["otp_length"] = encrypted_df["otp_length"].astype(int)

    encrypted_df.to_csv(output_path, index=False)

    encrypted_size_kb = output_path.stat().st_size / 1024

    return {
        "table_name": table_name,
        "total_rows": len(df),
        "sensitive_columns": ", ".join(sensitive_cols),
        "original_size_kb": round(original_size_kb, 2),
        "encrypted_size_kb": round(encrypted_size_kb, 2),
        "encryption_time_seconds": round(encryption_time, 6),
        "output_file": str(output_path)
    }


def test_decrypt_first_row(encrypted_file: str, table_name: str) -> dict:
    """
    Tes dekripsi baris pertama.
    """
    df = pd.read_csv(encrypted_file, dtype=str, keep_default_na=False)

    if df.empty:
        raise ValueError("File terenkripsi kosong.")

    first_row = df.iloc[0].to_dict()

    start_time = time.perf_counter()
    decrypted = decrypt_payload(first_row, table_name)
    decryption_time = time.perf_counter() - start_time

    return {
        "table_name": table_name,
        "decryption_time_seconds": round(decryption_time, 6),
        "decrypted_sample": decrypted
    }


def tamper_test(encrypted_file: str, table_name: str) -> dict:
    """
    Uji integritas.
    Ciphertext diubah sedikit. AES-GCM harus gagal decrypt.
    """
    df = pd.read_csv(encrypted_file, dtype=str, keep_default_na=False)

    if df.empty:
        raise ValueError("File terenkripsi kosong.")

    row = df.iloc[0].to_dict()
    ciphertext = row["ciphertext"]

    row["ciphertext"] = ciphertext[:-1] + ("A" if ciphertext[-1] != "A" else "B")

    try:
        decrypt_payload(row, table_name)

        return {
            "table_name": table_name,
            "tamper_detected": False,
            "message": "PERINGATAN: ciphertext yang diubah masih bisa didekripsi."
        }

    except Exception:
        return {
            "table_name": table_name,
            "tamper_detected": True,
            "message": "Berhasil: perubahan ciphertext terdeteksi dan dekripsi gagal."
        }


def randomness_test():
    payload = {
        "name": "John Doe",
        "disease": "Diabetes"
    }

    key_id, aes_key = load_or_create_aes_key("patients")

    encrypted_1 = encrypt_payload(
        payload=payload,
        table_name="patients",
        key_id=key_id,
        aes_key=aes_key
    )

    encrypted_2 = encrypt_payload(
        payload=payload,
        table_name="patients",
        key_id=key_id,
        aes_key=aes_key
    )

    same_ciphertext = (
        encrypted_1["ciphertext"] ==
        encrypted_2["ciphertext"]
    )

    return {
        "ciphertext_equal": same_ciphertext,
        "otp_1": encrypted_1["otp"],
        "otp_2": encrypted_2["otp"]
    }
