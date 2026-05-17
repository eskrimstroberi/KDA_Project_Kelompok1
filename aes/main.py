from pathlib import Path

import pandas as pd

from aes_module import encrypt_table, test_decrypt_first_row, tamper_test, SENSITIVE_COLUMNS


ROOT_DIR = Path(__file__).resolve().parents[1]

RAW_DIR = ROOT_DIR / "data" / "raw"
ENCRYPTED_DIR = ROOT_DIR / "data" / "encrypted"
RESULTS_DIR = ROOT_DIR / "results"

ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# None = semua baris dipakai
# Kalau laptop berat, ganti jadi 1000 dulu
SAMPLE_ROWS = None

ACCESS_MINUTES = 60


def main():
    encryption_metrics = []
    decryption_metrics = []
    integrity_results = []
    skipped_tables = []

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

            encryption_metrics.append(result)

            # ── Tes Dekripsi ──────────────────────────────────────────
            decrypt_result = test_decrypt_first_row(
                encrypted_file=str(output_file),
                table_name=table_name
            )

            print(f"Dekripsi baris 1  : berhasil ({decrypt_result['decryption_time_seconds']} s)")

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

            integrity_results.append(integrity_result)

        except Exception as error:
            print(f"[ERROR] {table_name}: {error}")

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
    print(f"Berhasil dienkripsi : {len(encryption_metrics)} tabel")
    print(f"Dilewati (skip)     : {len(skipped_tables)} tabel")
    print("\nOutput utama:")
    print("  data/encrypted/*_encrypted.csv")
    print("  keys/aes_keys_plain.json")
    print("  keys/token_key.bin")
    print("  results/aes_encryption_metrics.csv")
    print("  results/aes_decryption_metrics.csv")
    print("  results/aes_integrity_test.csv")
    if skipped_tables:
        print("  results/aes_skipped_tables.csv")


if __name__ == "__main__":
    main()