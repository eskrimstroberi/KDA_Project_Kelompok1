# KDA Project Kelompok 1
## Secure Healthcare Data Protection System

Implementasi sistem keamanan data berbasis kriptografi untuk melindungi dataset healthcare CSV menggunakan kombinasi:

- AES-256-GCM Encryption
- RSA Encryption
- One-Time Pad (OTP)
- Secure Key Distribution
- Key Rotation
- Secure Key Vault
- Access Control
- Logging & Auditing
- Security Anomaly Detection

Project ini bertujuan untuk menjaga:

- **Confidentiality** → data tidak bisa dibaca pihak tidak sah
- **Integrity** → manipulasi ciphertext dapat terdeteksi
- **Availability** → key management terstruktur
- **Secure Monitoring** → aktivitas keamanan tercatat dan diaudit

---

# Project Objectives

Project ini dibuat untuk:
✅ Mengamankan data healthcare berbentuk CSV menggunakan hybrid cryptography  
✅ Mengimplementasikan manajemen key modern secara aman  
✅ Melakukan validasi keamanan melalui decrypt testing, tampering detection, auditing, dan anomaly detection  
✅ Mensimulasikan role-based access control dalam sistem keamanan data

---

# Project Structure

```text
KDA_Project_Kelompok1/
│
├── alerts/
│   └── security_alerts.csv
│
├── audit/
│   └── security_audit.csv
│
├── data/
│   ├── raw/                      # Original healthcare dataset
│   └── encrypted/               # Encrypted dataset output
│
├── keys/                        # Key storage
│
├── logs/
│   └── security.log
│
├── module/
│   ├── access_control.py
│   ├── aes_module.py
│   ├── anomaly_detection.py
│   ├── auditing_module.py
│   ├── key_distribution.py
│   ├── key_generation_module.py
│   ├── key_rotation.py
│   ├── key_vault.py
│   ├── logging_module.py
│   ├── main.py
│   ├── otp_module.py
│   └── rsa_module.py
│
├── results/
│   ├── aes_encryption_metrics.csv
│   ├── aes_decryption_metrics.csv
│   └── aes_integrity_test.csv
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

# Installation

- Clone repository: git clone https://github.com/USERNAME/KDA_Project_Kelompok1.git 
- Install dependencies: pip install -r requirements.txt 

# Run Project
- Masuk ke folder module: cd module 
- Jalankan program: python main.py


# Example Outputs

Generated files:

```text
data/encrypted/*_encrypted.csv
results/aes_encryption_metrics.csv
results/aes_decryption_metrics.csv
results/aes_integrity_test.csv
logs/security.log
audit/security_audit.csv
alerts/security_alerts.csv
```

