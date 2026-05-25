import os
from pathlib import Path
import json
import pandas as pd
import traceback
from access_control import (login_role)
from logging_module import (log_info,log_warning,log_error)
from aes_module import encrypt_table, test_decrypt_first_row, tamper_test, randomness_test, SENSITIVE_COLUMNS
from rsa_module import (
    generate_rsa_keys,
    rsa_encrypt_key,
    rsa_decrypt_key
)
from key_management import key_generation_test
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from key_distribution import (simulate_secure_key_distribution, simulate_mitm_attack)
from key_rotation import (rotate_key, auto_rotate_expired_keys)
from key_vault import (encrypt_key_registry, decrypt_key_registry)
from auditing_module import (
    audit_security_logs
)
from anomaly_detection import (
    detect_security_anomalies
)

from cloud_storage import (
    create_bucket,
    upload_encrypted_file,
    upload_encrypted_key,
    upload_metadata,
    download_encrypted_file,
    download_encrypted_key,
    get_metadata
)

from datetime import datetime, timedelta

ROOT_DIR = Path(__file__).resolve().parents[1]


RAW_DIR = ROOT_DIR / "data" / "raw"
ENCRYPTED_DIR = ROOT_DIR / "data" / "encrypted"
RESULTS_DIR = ROOT_DIR / "results"


ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# None = semua baris dipakai
# Kalau laptop berat, ganti jadi 1000 dulu
SAMPLE_ROWS = None
ACCESS_MINUTES = 60
CLOUD_STORAGE_DIR = ROOT_DIR / "cloud_storage"

(CLOUD_STORAGE_DIR / "encrypted").mkdir(
    parents=True,
    exist_ok=True
)

(CLOUD_STORAGE_DIR / "encrypted_keys").mkdir(
    parents=True,
    exist_ok=True
)

(CLOUD_STORAGE_DIR / "metadata").mkdir(
    parents=True,
    exist_ok=True
)

(CLOUD_STORAGE_DIR / "downloads").mkdir(
    parents=True,
    exist_ok=True
)

def main():
    user_role = login_role()
    print("\n=== Secure Key Generation Test ===")

    results = key_generation_test()

    for result in results:
        print(f"""
    Key #{result['key_number']}
    Length   : {result['key_length_bytes']} bytes
    Entropy  : {result['entropy']}
    Key(Base64):
    {result['key_base64']}
    """)
        
    print("\n=== RSA Initialization ===")

    print(
    "\n=== Secure Cloud Storage Initialization ==="
    )

    create_bucket()
    generate_rsa_keys()
    sample_key = os.urandom(32)
    encrypted_key = rsa_encrypt_key(sample_key)
    decrypted_key = rsa_decrypt_key(encrypted_key)
    rsa_ok = sample_key == decrypted_key
    print("RSA encryption test :", rsa_ok)

    if rsa_ok:
        log_info("RSA encryption/decryption success")
    else:
        log_error("RSA encryption/decryption failed")

    # key distribution
    test_aes_key = AESGCM.generate_key(
        bit_length=256
    )

    simulate_secure_key_distribution(
        test_aes_key
    )

    # simulate mitm
    simulate_mitm_attack(
        test_aes_key
    )

    # key rotation
    print("\n=== Key Rotation System ===")

    rotation_result = rotate_key(
        "patients"
    )

    rotated = auto_rotate_expired_keys()

    print("\nAuto rotation checked.")

    if rotated:

        print("Expired keys rotated:")

        for item in rotated:

            print(
                f"- {item['new_key_id']}"
            )

    else:

        print("Tidak ada key expired.")

    # Secure Key Vault
    print("\n=== Secure Key Vault System ===")

    keys_path = ROOT_DIR / "keys" / "aes_keys_plain.json"

    if keys_path.exists():

        with open(keys_path, "r", encoding="utf-8") as file:
            keys_dict = json.load(file)

        encrypt_key_registry(keys_dict)

        decrypted_registry = decrypt_key_registry()

        print(
            "Vault decrypt success :",
            len(decrypted_registry) > 0
        )

    # ── Randomness Validation ───────────────────────────
    print(f"\n{'='*50}")
    print("=== OTP Randomness Validation ===")

    random_result = randomness_test()

    print(f"OTP 1              : {random_result['otp_1']}")
    print(f"OTP 2              : {random_result['otp_2']}")
    print(f"Ciphertext sama?   : {random_result['ciphertext_equal']}")

    encryption_metrics = []
    decryption_metrics = []
    integrity_results = []
    skipped_tables = []

    success_count = 0
    failed_count = 0

    print("=== AES-256-GCM Encryption System ===")
    print(f"Raw folder       : {RAW_DIR}")
    print(f"Encrypted folder : {ENCRYPTED_DIR}")

    csv_files = sorted(RAW_DIR.glob("*.csv"))

    if not csv_files:
        print("\nTidak ada file CSV di data/raw/")
        return

    known = [f for f in csv_files if f.stem in SENSITIVE_COLUMNS]
    unknown = [f for f in csv_files if f.stem not in SENSITIVE_COLUMNS]

    if unknown:
        print(f"\n[SKIP] {len(unknown)} tabel tidak ada di SENSITIVE_COLUMNS dan akan dilewati:")
        for f in unknown:
            print(f"  - {f.name}")
            skipped_tables.append({"table_name": f.stem, "reason": "Tidak ada di SENSITIVE_COLUMNS"})

    print(f"\n[INFO] Akan diproses: {len(known)} tabel")

    for input_file in known:
        table_name = input_file.stem
        output_file = ENCRYPTED_DIR / f"{table_name}_encrypted.csv"

        print(f"\n{'='*50}")
        print(f"Tabel     : {table_name}")
        print(f"Input     : {input_file.name}")

        try:
            # ── Enkripsi ──────────────────────────────────────────────
            result = encrypt_table(
                input_file=str(input_file),
                output_file=str(output_file),
                table_name=table_name,
                sample_rows=SAMPLE_ROWS,
                access_minutes=ACCESS_MINUTES
            )

            print(f"Jumlah baris      : {result['total_rows']}")
            print(f"Ukuran awal       : {result['original_size_kb']} KB")
            print(f"Ukuran terenkripsi: {result['encrypted_size_kb']} KB")
            print(f"Waktu enkripsi    : {result['encryption_time_seconds']} s")
            log_info(
            f"AES encryption success - {table_name}"
            )

            encryption_metrics.append(result)

            # =========================================
            # RSA ENCRYPT AES KEY
            # =========================================

            aes_key = result["aes_key"]

            encrypted_aes_key = rsa_encrypt_key(
                aes_key
            )

            encrypted_key_output = (
                ROOT_DIR
                / "keys"
                / f"{table_name}_encrypted_key.bin"
            )

            with open(
                encrypted_key_output,
                "wb"
            ) as key_file:

                key_file.write(
                    encrypted_aes_key.encode("utf-8")
                )

            print(
                "[SUCCESS] AES key encrypted with RSA"
            )

            # ── Tes Dekripsi ──────────────────────────────────────────
            decrypt_result = test_decrypt_first_row(
                encrypted_file=str(output_file),
                table_name=table_name,
                user_role=user_role
            )

            print(f"Dekripsi baris 1  : berhasil ({decrypt_result['decryption_time_seconds']} s)")
            log_info(
            f"Decryption success - {table_name}"
            )

            decryption_metrics.append({
                "table_name": table_name,
                "decryption_time_seconds": decrypt_result["decryption_time_seconds"],
                "status": "success"
            })

            # ── Tes Integritas ────────────────────────────────────────
            integrity_result = tamper_test(
                encrypted_file=str(output_file),
                table_name=table_name
            )

            status_label = "AMAN" if integrity_result["tamper_detected"] else "GAGAL"
            print(f"Tes integritas    : {status_label} — {integrity_result['message']}")
            if integrity_result["tamper_detected"]:
                log_warning(
                    f"Tampering detected - {table_name}"
                )
            else:
                log_error(
                    f"Tampering NOT detected - {table_name}"
                )

            integrity_results.append(integrity_result)

            # =========================================
            # CLOUD STORAGE INTEGRATION
            # =========================================

            print("\n=== Uploading to Secure Cloud Storage ===")

            # upload encrypted dataset
            upload_encrypted_file(
                local_path=str(output_file),
                filename=f"{table_name}.enc"
            )

            # upload encrypted AES key
            encrypted_key_path = (
                ROOT_DIR
                / "keys"
                / f"{table_name}_encrypted_key.bin"
            )

            if encrypted_key_path.exists():

                upload_encrypted_key(
                    local_path=str(
                        encrypted_key_path
                    ),
                    filename=f"{table_name}_key.bin"
                )

            # create metadata
            metadata = {

                "table_name": table_name,

                "owner": "doctor_1",

                "encrypted_at":
                    str(datetime.now()),

                "expires_at":
                    str(
                        datetime.now()
                        + timedelta(
                            minutes=ACCESS_MINUTES
                        )
                    ),

                "key_version": "v1",

                "access_role": user_role,

                "integrity_status":
                    integrity_result[
                        "tamper_detected"
                    ]
            }

            upload_metadata(
                metadata_dict=metadata,
                filename=(
                    f"{table_name}"
                    "_metadata.json"
                )
            )

            print(
                "[SUCCESS] Cloud storage upload completed"
            )

            success_count += 1
            

        except Exception as error:
            failed_count += 1
            print(f"[ERROR] {table_name}:{repr(error)}")
            log_error(
            f"{table_name} - {repr(error)}"
            )
            traceback.print_exc()

            encryption_metrics.append({
                "table_name": table_name,
                "total_rows": None,
                "sensitive_columns": None,
                "original_size_kb": None,
                "encrypted_size_kb": None,
                "encryption_time_seconds": None,
                "output_file": str(output_file),
                "error": str(error)
            })

            decryption_metrics.append({
                "table_name": table_name,
                "decryption_time_seconds": None,
                "status": f"error: {error}"
            })

            integrity_results.append({
                "table_name": table_name,
                "tamper_detected": None,
                "message": f"Tidak dijalankan karena enkripsi gagal: {error}"
            })


    # ── Simpan hasil evaluasi ─────────────────────────────────────────
    pd.DataFrame(encryption_metrics).to_csv(
        RESULTS_DIR / "aes_encryption_metrics.csv", index=False
    )
    pd.DataFrame(decryption_metrics).to_csv(
        RESULTS_DIR / "aes_decryption_metrics.csv", index=False
    )
    pd.DataFrame(integrity_results).to_csv(
        RESULTS_DIR / "aes_integrity_test.csv", index=False
    
    )

    if skipped_tables:
        pd.DataFrame(skipped_tables).to_csv(
            RESULTS_DIR / "aes_skipped_tables.csv", index=False
        )

    # ── Ringkasan akhir ───────────────────────────────────────────────
    print(f"\n{'='*50}")
    print("=== Ringkasan ===")
    print(f"Berhasil dienkripsi : {success_count} tabel")
    print(f"Gagal proses     : {failed_count} tabel")
    print(f"Dilewati (skip)     : {len(skipped_tables)} tabel")
    print("\nOutput utama:")
    print("  data/encrypted/*_encrypted.csv")
    print("  keys/aes_keys_plain.json")
    print("  keys/token_key.bin")
    print("  results/aes_encryption_metrics.csv")
    print("  results/aes_decryption_metrics.csv")
    print("  results/aes_integrity_test.csv")
    print("  cloud_storage/encrypted/")
    print("  cloud_storage/encrypted_keys/")
    print("  cloud_storage/metadata/")
    if skipped_tables:
        print("  results/aes_skipped_tables.csv")

    # ── Audit System ───────────────────────────
    print(f"\n{'='*50}")
    print("=== Security Audit Report ===")

    audit_results = (
        audit_security_logs()
    )

    for item in audit_results:

        print(
            f"{item['event']}"
            f" : {item['total']}"
        )

    # ── Anomaly Detection ─────────────────────
    print(f"\n{'='*50}")
    print("=== Security Anomaly Detection ===")

    anomalies = (
        detect_security_anomalies()
    )

    if anomalies:

        for item in anomalies:

            print(
                f"[{item['severity']}] "
                f"{item['message']}"
            )

    else:

        print(
            "Tidak ada anomali "
            "terdeteksi."
        )
    
    # =========================================
    # CLOUD RETRIEVAL TEST
    # =========================================

    print(f"\n{'='*50}")
    print("=== Secure Cloud Retrieval Test ===")

    if success_count > 0:

        sample_table = known[0].stem

        print(
            f"Testing secure retrieval: "
            f"{sample_table}"
        )

        # download encrypted file
        download_encrypted_file(
            f"{sample_table}.enc"
        )

        # download encrypted key
        download_encrypted_key(
            f"{sample_table}_key.bin"
        )

        # get metadata
        metadata = get_metadata(
            f"{sample_table}_metadata.json"
        )

        print("\nCloud Metadata:")

        for key, value in metadata.items():

            print(f"{key} : {value}")
        
if __name__ == "__main__":
    main()