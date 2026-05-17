# KDA Project Kelompok 1

Implementasi sistem keamanan data berbasis kriptografi menggunakan:
- AES-256-GCM
- RSA Encryption
- Secure Key Distribution
- Key Rotation
- Secure Key Vault
- OTP Validation
- Integrity Verification

Project ini digunakan untuk melakukan enkripsi dataset healthcare CSV secara aman dengan mekanisme manajemen key modern dan pengujian keamanan.

---

# Features

## AES-256-GCM Encryption
- Enkripsi file CSV menggunakan AES-256-GCM
- Mendukung confidentiality + integrity
- Menggunakan nonce dan authentication tag
- Verifikasi integritas ciphertext

## RSA Encryption
- RSA public/private key generation
- Distribusi AES key secara aman
- Simulasi secure key exchange

## Secure Key Distribution
- AES key dienkripsi menggunakan RSA
- Simulasi attacker/eavesdropper
- Validasi key receiver

## MITM Attack Detection
- Simulasi manipulasi ciphertext
- Sistem mendeteksi perubahan data
- Decrypt otomatis gagal jika ciphertext dimodifikasi

## Key Rotation System
- Rotasi key otomatis per tabel
- Validasi expired key
- Registry key management

## Secure Key Vault
- Penyimpanan registry key terenkripsi
- Vault decryption validation

## OTP Randomness Validation
- Random OTP generation
- Validasi randomness ciphertext

## Metrics & Benchmark
- Waktu enkripsi
- Waktu dekripsi
- Ukuran file sebelum/sesudah
- Integrity test result

---

# Project Structure
KDA_Project_Kelompok1/
│
├── data/
│   ├── raw/                  # Dataset asli
│   └── encrypted/            # Hasil enkripsi
│
├── keys/                     # Key storage (ignored)
│
├── module/
│   ├── aes_module.py
│   ├── rsa_module.py
│   ├── otp_module.py
│   ├── key_generation_module.py
│   ├── key_distribution.py
│   ├── key_management.py
│   ├── key_rotation.py
│   ├── key_vault.py
│   └── main.py
│
├── results/
│   ├── aes_encryption_metrics.csv
│   ├── aes_decryption_metrics.csv
│   └── aes_integrity_test.csv
│
├── requirements.txt
└── .gitignore

## Installation
- Clone repository: git clone https://github.com/USERNAME/KDA_Project_Kelompok1.git
- Install dependencies: pip install -r requirements.txt
- Run Project
  - Masuk ke folder module: cd module
  - Jalankan program: python main.py
