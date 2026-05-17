# 🔐 KDA Project Kelompok 1
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

# 📌 Project Objectives

Project ini dibuat untuk:

✅ Mengamankan data healthcare berbentuk CSV menggunakan hybrid cryptography  
✅ Mengimplementasikan manajemen key modern secara aman  
✅ Melakukan validasi keamanan melalui decrypt testing, tampering detection, auditing, dan anomaly detection  
✅ Mensimulasikan role-based access control dalam sistem keamanan data

---

# 🚀 Features

---

## 🔒 AES-256-GCM Encryption

Fitur:

- Enkripsi dataset CSV menggunakan AES-256-GCM
- Menjaga confidentiality + integrity
- Menggunakan nonce unik
- Authentication tag validation
- Mendukung encrypt multi-table healthcare dataset

Output:

```text
data/encrypted/*_encrypted.csv
```

---

## 🔑 RSA Encryption

Fitur:

- Generate RSA public/private key
- Secure AES key exchange
- RSA encryption/decryption validation

Tujuan:

```text
Melindungi AES key saat proses distribusi.
```

---

## 🎲 OTP Randomness Validation

Fitur:

- Generate random OTP
- Integrasi OTP dengan AES key
- Ciphertext randomness testing

Tujuan:

```text
Memastikan ciphertext berbeda walaupun plaintext sama.
```

---

## 🛡 Secure Key Distribution

Fitur:

- RSA-protected AES key transfer
- Simulasi eavesdropping
- Secure receiver validation

Simulasi:

```text
Sender
↓
RSA encrypt AES key
↓
Attacker gagal membaca key
↓
Receiver decrypt AES key
```

---

## ⚔ MITM Attack Detection

Fitur:

- Simulasi ciphertext modification
- Automatic integrity verification
- Decryption failure detection

Tujuan:

```text
Mendeteksi manipulasi ciphertext oleh attacker.
```

---

## 🔄 Key Rotation System

Fitur:

- Automatic key rotation
- Expired key checking
- Key versioning per table

Contoh:

```text
patients-key-v1
patients-key-v2
patients-key-v3
```

---

## 🔐 Secure Key Vault

Fitur:

- Encrypted key registry
- Vault decryption validation
- Secure local key storage

Output:

```text
keys/
```

---

## 👤 Access Control System

Fitur:

- Role-based access control
- Time-limited access control

Role:

| Role | Permission |
|------|------------|
| Admin | Full access |
| Doctor | Decryption allowed |
| Guest | Access denied |

Flow:

```text
Login
↓
Role detection
↓
Access validation
↓
Decrypt allowed / denied
```

---

## 📝 Security Logging System

Fitur:

- Encryption logging
- Decryption logging
- Tampering logging
- Error logging
- Access monitoring

Output:

```text
logs/security.log
```

Contoh:

```text
INFO - AES encryption success - allergies
INFO - Decryption success - allergies
WARNING - Tampering detected - allergies
ERROR - Access denied for role: guest
```

---

## 📊 Security Auditing System

Fitur:

- Automatic log analysis
- Security event summary
- Audit CSV generation

Output:

```text
audit/security_audit.csv
```

Contoh hasil:

| Event | Total |
|--------|------|
| encryption_success | 18 |
| decryption_success | 18 |
| tampering_detected | 18 |

---

## 🚨 Security Anomaly Detection

Fitur:

- High tampering detection
- Repeated denied access detection
- High error rate detection

Output:

```text
alerts/security_alerts.csv
```

Contoh:

```text
HIGH - Too many tampering events detected
MEDIUM - Repeated unauthorized access attempts
```

---

## 📈 Metrics & Benchmark

Fitur:

- Encryption time benchmarking
- Decryption time benchmarking
- File size comparison
- Integrity validation

Output:

```text
results/
```

---

# 📂 Project Structure

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

# ⚙ Installation

- Clone repository: git clone https://github.com/USERNAME/KDA_Project_Kelompok1.git - Install dependencies: pip install -r requirements.txt - Run Project - Masuk ke folder module: cd module - Jalankan program: python main.py


# 📊 Example Outputs

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

