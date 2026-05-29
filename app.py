import sys
import os
import json
import time
import base64
from pathlib import Path
from datetime import datetime, timezone, timedelta
import streamlit as st
import pandas as pd

# ── Path Setup ──────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent
MODULE_DIR = ROOT_DIR / "module"
sys.path.insert(0, str(MODULE_DIR))

RAW_DIR     = ROOT_DIR / "data" / "raw"
ENC_DIR     = ROOT_DIR / "data" / "encrypted"
RESULTS_DIR = ROOT_DIR / "results"
KEYS_DIR    = ROOT_DIR / "keys"

for d in [RAW_DIR, ENC_DIR, RESULTS_DIR, KEYS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Import modul kriptografi (TIDAK diubah sama sekali) ─────────────────────
from aes_module import (
    encrypt_table, test_decrypt_first_row,
    tamper_test, randomness_test, SENSITIVE_COLUMNS
)
from rsa_module import generate_rsa_keys, rsa_encrypt_key, rsa_decrypt_key
from key_management import key_generation_test
from key_distribution import simulate_secure_key_distribution, simulate_mitm_attack
from key_rotation import rotate_key, auto_rotate_expired_keys
from key_vault import encrypt_key_registry, decrypt_key_registry
from otp_module import generate_otp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ═══════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="KDA — Hybrid Cryptographic Framework",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════════
# CUSTOM CSS
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&family=Syne:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Syne', sans-serif;
}

/* ── Root palette ── */
:root {
    --c-bg:       #0a0c10;
    --c-surface:  #0f1218;
    --c-panel:    #141820;
    --c-border:   #1e2530;
    --c-accent:   #00e5ff;
    --c-accent2:  #7c4dff;
    --c-green:    #00e676;
    --c-amber:    #ffd740;
    --c-red:      #ff5252;
    --c-text:     #e8eaf0;
    --c-muted:    #636b80;
    --c-mono:     'JetBrains Mono', monospace;
}

/* ── App background ── */
.stApp {
    background: var(--c-bg);
    color: var(--c-text);
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: var(--c-surface) !important;
    border-right: 1px solid var(--c-border);
}
[data-testid="stSidebar"] * { color: var(--c-text) !important; }
[data-testid="stSidebar"] .stRadio label {
    font-size: 13px;
    font-family: var(--c-mono);
    padding: 6px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: background .15s;
}
[data-testid="stSidebar"] .stRadio label:hover { background: rgba(0,229,255,.07); }

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: var(--c-panel);
    border: 1px solid var(--c-border);
    border-radius: 12px;
    padding: 16px !important;
}
[data-testid="stMetricValue"] { color: var(--c-accent) !important; font-family: var(--c-mono); }
[data-testid="stMetricLabel"] { color: var(--c-muted) !important; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }

/* ── Buttons ── */
.stButton > button {
    background: transparent;
    border: 1px solid var(--c-accent);
    color: var(--c-accent);
    font-family: var(--c-mono);
    font-size: 13px;
    border-radius: 8px;
    padding: 8px 18px;
    transition: all .2s;
    letter-spacing: .04em;
}
.stButton > button:hover {
    background: rgba(0,229,255,.1);
    box-shadow: 0 0 16px rgba(0,229,255,.25);
}
.stButton > button:active { transform: scale(.97); }

/* ── Primary button variant ── */
.stButton.primary > button {
    background: var(--c-accent2);
    border-color: var(--c-accent2);
    color: #fff;
}
.stButton.primary > button:hover { box-shadow: 0 0 20px rgba(124,77,255,.4); }

/* ── Expander / containers ── */
.stExpander {
    background: var(--c-panel) !important;
    border: 1px solid var(--c-border) !important;
    border-radius: 10px !important;
}

/* ── Code / terminal blocks ── */
.stCodeBlock, [data-testid="stCode"] {
    font-family: var(--c-mono) !important;
    background: #060810 !important;
    border: 1px solid var(--c-border) !important;
    border-radius: 8px !important;
}
pre { font-family: var(--c-mono) !important; }

/* ── Success / error / warning ── */
.stAlert { border-radius: 10px !important; font-family: var(--c-mono); font-size: 13px; }
.stSuccess { border-left: 3px solid var(--c-green) !important; background: rgba(0,230,118,.07) !important; }
.stError   { border-left: 3px solid var(--c-red)   !important; background: rgba(255,82,82,.07)  !important; }
.stWarning { border-left: 3px solid var(--c-amber)  !important; background: rgba(255,215,64,.07) !important; }
.stInfo    { border-left: 3px solid var(--c-accent) !important; background: rgba(0,229,255,.07)  !important; }

/* ── DataFrame ── */
[data-testid="stDataFrame"] { border-radius: 10px !important; overflow: hidden; }

/* ── Selectbox / file uploader ── */
.stSelectbox > div > div, .stFileUploader {
    background: var(--c-panel) !important;
    border-color: var(--c-border) !important;
    border-radius: 8px !important;
    color: var(--c-text) !important;
}

/* ── Number input ── */
.stNumberInput input {
    background: var(--c-panel) !important;
    border-color: var(--c-border) !important;
    color: var(--c-text) !important;
    font-family: var(--c-mono) !important;
}

/* ── Tab strip ── */
.stTabs [data-baseweb="tab-list"] {
    background: var(--c-panel);
    border-radius: 10px;
    border: 1px solid var(--c-border);
    padding: 4px;
}
.stTabs [data-baseweb="tab"] {
    font-family: var(--c-mono);
    font-size: 13px;
    color: var(--c-muted);
    border-radius: 7px;
}
.stTabs [aria-selected="true"] {
    background: rgba(0,229,255,.12) !important;
    color: var(--c-accent) !important;
}

/* ── Divider ── */
hr { border-color: var(--c-border) !important; }

/* ── Custom badge ── */
.badge-ok   { display:inline-block;padding:2px 10px;border-radius:999px;background:rgba(0,230,118,.15);color:#00e676;font-size:11px;font-family:var(--c-mono);font-weight:600; }
.badge-warn { display:inline-block;padding:2px 10px;border-radius:999px;background:rgba(255,215,64,.15);color:#ffd740;font-size:11px;font-family:var(--c-mono);font-weight:600; }
.badge-err  { display:inline-block;padding:2px 10px;border-radius:999px;background:rgba(255,82,82,.15);color:#ff5252;font-size:11px;font-family:var(--c-mono);font-weight:600; }
.badge-info { display:inline-block;padding:2px 10px;border-radius:999px;background:rgba(0,229,255,.15);color:#00e5ff;font-size:11px;font-family:var(--c-mono);font-weight:600; }

/* ── Section header ── */
.sec-head {
    font-family:'Syne',sans-serif;
    font-size:22px;
    font-weight:700;
    letter-spacing:-.02em;
    color: var(--c-text);
    margin-bottom:4px;
}
.sec-sub {
    font-family:var(--c-mono);
    font-size:12px;
    color:var(--c-muted);
    margin-bottom:20px;
}
.terminal-box {
    background:#060810;
    border:1px solid var(--c-border);
    border-radius:10px;
    padding:16px 20px;
    font-family:var(--c-mono);
    font-size:12px;
    color:#a0b0c8;
    line-height:1.8;
    white-space:pre-wrap;
    word-break:break-all;
}
.hero-banner {
    background: linear-gradient(135deg, #0f1218 0%, #141820 50%, #0a0e18 100%);
    border: 1px solid var(--c-border);
    border-radius: 16px;
    padding: 28px 32px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.hero-banner::before {
    content:'';
    position:absolute;
    top:-40px;right:-40px;
    width:200px;height:200px;
    background:radial-gradient(circle,rgba(0,229,255,.08) 0%,transparent 70%);
    border-radius:50%;
    pointer-events:none;
}
.hero-title {
    font-family:'Syne',sans-serif;
    font-size:28px;
    font-weight:800;
    letter-spacing:-.03em;
    background:linear-gradient(90deg,#00e5ff,#7c4dff);
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
    background-clip:text;
    margin-bottom:6px;
}
.hero-sub {
    font-family:var(--c-mono);
    font-size:12px;
    color:var(--c-muted);
    margin-bottom:12px;
}
.tag-row { display:flex;gap:8px;flex-wrap:wrap; }
.tag {
    font-family:var(--c-mono);
    font-size:11px;
    padding:3px 10px;
    border-radius:999px;
    border:1px solid rgba(0,229,255,.3);
    color:#00e5ff;
    letter-spacing:.04em;
}
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:12px 0 20px;'>
        <div style='font-size:32px;margin-bottom:4px;'>🔐</div>
        <div style='font-family:"Syne",sans-serif;font-size:15px;font-weight:700;color:#00e5ff;letter-spacing:-.01em;'>KDA Crypto</div>
        <div style='font-family:"JetBrains Mono",monospace;font-size:10px;color:#636b80;margin-top:2px;'>Kelompok 1</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    page = st.radio(
        "Navigasi",
        ["🏠  Overview",
         "🔑  Key Generation",
         "🔒  AES-256-GCM Encrypt",
         "📂  Lihat Data Terenkripsi",
         "🔓  Dekripsi & Verify",
         "🛡️  RSA & Key Distribution",
         "♻️  Key Rotation",
         "🗄️  Key Vault",
         "🎲  OTP Randomness",
         "📊  Metrics & Results"],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.markdown("""
    <div style='font-family:"JetBrains Mono",monospace;font-size:10px;color:#636b80;line-height:1.8;'>
    AES-256-GCM · RSA-2048<br>
    OAEP · SHA-256 · HMAC<br>
    OTP · Time-Limited Access<br>
    Key Vault · Auto Rotation
    </div>
    """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
# HELPER
# ═══════════════════════════════════════════════════════════════════════════
def mono(text, color="#a0b0c8"):
    return f'<span style="font-family:\'JetBrains Mono\',monospace;color:{color};font-size:12px">{text}</span>'

def sec(title, sub=""):
    st.markdown(f'<div class="sec-head">{title}</div>', unsafe_allow_html=True)
    if sub:
        st.markdown(f'<div class="sec-sub">{sub}</div>', unsafe_allow_html=True)

def terminal(text):
    st.markdown(f'<div class="terminal-box">{text}</div>', unsafe_allow_html=True)

def badge(label, kind="ok"):
    return f'<span class="badge-{kind}">{label}</span>'

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════
if page == "🏠  Overview":
    st.markdown("""
    <div class="hero-banner">
        <div class="hero-title">Hybrid Cryptographic Framework</div>
        <div class="hero-sub">Data Kesehatan · Cloud Security · KDA Project Kelompok 1</div>
        <div class="tag-row">
            <div class="tag">AES-256-GCM</div>
            <div class="tag">RSA-2048</div>
            <div class="tag">OAEP+SHA256</div>
            <div class="tag">OTP</div>
            <div class="tag">Key Vault</div>
            <div class="tag">Auto Rotation</div>
            <div class="tag">HMAC-SHA256</div>
            <div class="tag">Time-Limited Access</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    csv_files = list(RAW_DIR.glob("*.csv"))
    known = [f for f in csv_files if f.stem in SENSITIVE_COLUMNS]
    enc_files = list(ENC_DIR.glob("*.csv"))
    keys_path = KEYS_DIR / "aes_keys_plain.json"
    key_count = 0
    if keys_path.exists():
        with open(keys_path) as f:
            key_count = len(json.load(f))

    c1.metric("Tabel Dikenal", len(known), help="CSV di data/raw/ yang ada di SENSITIVE_COLUMNS")
    c2.metric("Terenkripsi", len(enc_files), help="File CSV di data/encrypted/")
    c3.metric("AES Keys", key_count, help="Key aktif di keys/aes_keys_plain.json")
    c4.metric("RSA Key Size", "2048-bit", help="OAEP + MGF1(SHA-256)")

    st.markdown("---")

    col_a, col_b = st.columns(2)
    with col_a:
        sec("Arsitektur Sistem", "Alur kerja hybrid cryptography")
        terminal("""\
┌─────────────────────────────────────────┐
│         HYBRID CRYPTO PIPELINE          │
├─────────────────────────────────────────┤
│  [1] Key Generation                     │
│      AESGCM.generate_key(256-bit)       │
│      Shannon Entropy ≈ 7.99             │
│                  │                      │
│  [2] RSA Key Distribution               │
│      AES_key ──RSA(pub)──► Ciphertext   │
│      Protect key dari MITM attack       │
│                  │                      │
│  [3] AES-256-GCM Encrypt                │
│      Data + nonce(12B) + AAD            │
│      ──► ciphertext + auth_tag          │
│      OTP randomness per-row             │
│                  │                      │
│  [4] Access Control                     │
│      expires_at check (60 min)          │
│      HMAC-SHA256 relation token         │
│                  │                      │
│  [5] Key Vault                          │
│      aes_keys_plain.json                │
│      ──► aes_keys_encrypted.json        │
│      Master vault key (256-bit AES)     │
└─────────────────────────────────────────┘
""")

    with col_b:
        sec("Tabel Sensitif", "SENSITIVE_COLUMNS dari aes_module.py")
        tbl_data = []
        for tbl, cols in SENSITIVE_COLUMNS.items():
            enc_exists = (ENC_DIR / f"{tbl}_encrypted.csv").exists()
            raw_exists = (RAW_DIR / f"{tbl}.csv").exists()
            tbl_data.append({
                "Tabel": tbl,
                "Kolom Sensitif": len(cols),
                "Raw": "✓" if raw_exists else "—",
                "Encrypted": "✓" if enc_exists else "—",
            })
        st.dataframe(
            pd.DataFrame(tbl_data),
            use_container_width=True,
            hide_index=True,
            height=350,
        )

    st.markdown("---")
    sec("Struktur Proyek", "module/ tidak diubah — frontend ini wrapper Streamlit")
    terminal("""\
KDA_Project_Kelompok1/
├── app.py                     ← Frontend Streamlit (file ini)
├── requirements.txt
├── data/
│   ├── raw/                   ← Upload CSV dataset di sini
│   └── encrypted/             ← Output enkripsi
├── keys/
│   ├── aes_keys_plain.json
│   ├── aes_keys_encrypted.json
│   ├── vault_master_key.bin
│   ├── token_key.bin
│   ├── rsa_private.pem
│   └── rsa_public.pem
├── module/                    ← TIDAK DIUBAH
│   ├── main.py
│   ├── aes_module.py
│   ├── rsa_module.py
│   ├── otp_module.py
│   ├── key_generation_module.py
│   ├── key_management.py
│   ├── key_distribution.py
│   ├── key_rotation.py
│   └── key_vault.py
└── results/
    ├── aes_encryption_metrics.csv
    ├── aes_decryption_metrics.csv
    └── aes_integrity_test.csv
""")

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: KEY GENERATION
# ═══════════════════════════════════════════════════════════════════════════
elif page == "🔑  Key Generation":
    sec("Key Generation", "key_generation_module.py · key_management.py")

    n_keys = st.number_input("Jumlah key yang di-generate", min_value=1, max_value=20, value=5)

    if st.button("⚡ Generate AES Keys"):
        with st.spinner("Generating secure keys…"):
            results = key_generation_test(total_keys=int(n_keys))

        st.success(f"✓ {len(results)} AES-256 key berhasil digenerate via CSPRNG")

        out = []
        for r in results:
            out.append({
                "Key #": r["key_number"],
                "Length (bytes)": r["key_length_bytes"],
                "Entropy": round(r["entropy"], 4),
                "Key (Base64)": r["key_base64"][:32] + "…",
            })
        df = pd.DataFrame(out)
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.markdown("---")
        log = ""
        for r in results:
            bar = "█" * int(r["entropy"] / 8 * 20) + "░" * (20 - int(r["entropy"] / 8 * 20))
            log += f'Key #{r["key_number"]:02d} │ {bar} │ entropy={r["entropy"]:.4f} │ {r["key_base64"][:28]}…\n'
        terminal(log)

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: AES ENCRYPT
# ═══════════════════════════════════════════════════════════════════════════
elif page == "🔒  AES-256-GCM Encrypt":
    sec("AES-256-GCM Encryption", "aes_module.py · encrypt_table()")

    csv_files = list(RAW_DIR.glob("*.csv"))
    known_files = [f for f in csv_files if f.stem in SENSITIVE_COLUMNS]

    st.markdown("**Upload Dataset CSV**")
    uploaded = st.file_uploader(
        "Upload satu atau lebih file CSV ke data/raw/",
        type="csv", accept_multiple_files=True, label_visibility="collapsed"
    )
    if uploaded:
        for uf in uploaded:
            dest = RAW_DIR / uf.name
            dest.write_bytes(uf.read())
            st.success(f"✓ Tersimpan: data/raw/{uf.name}")
        known_files = [f for f in RAW_DIR.glob("*.csv") if f.stem in SENSITIVE_COLUMNS]

    st.markdown("---")

    if not known_files:
        st.info("Upload file CSV terlebih dahulu. Nama file harus sesuai dengan SENSITIVE_COLUMNS (misal: patients.csv, encounters.csv, dll).")
    else:
        table_names = [f.stem for f in known_files]
        sel = st.multiselect("Pilih tabel untuk dienkripsi", table_names, default=table_names[:1])
        col1, col2 = st.columns(2)
        sample_rows = col1.number_input("Sample rows (kosongkan = semua)", min_value=0, value=0)
        access_min  = col2.number_input("Access duration (menit)", min_value=1, value=60)
        sample_rows = None if sample_rows == 0 else int(sample_rows)

        if st.button("🔒 Enkripsi Tabel Terpilih") and sel:
            enc_metrics, dec_metrics, integrity = [], [], []
            prog = st.progress(0, text="Memulai enkripsi…")
            log_out = ""

            for i, tname in enumerate(sel):
                prog.progress((i) / len(sel), text=f"Enkripsi: {tname}…")
                inp = RAW_DIR / f"{tname}.csv"
                out = ENC_DIR / f"{tname}_encrypted.csv"
                try:
                    res = encrypt_table(
                        input_file=str(inp), output_file=str(out),
                        table_name=tname, sample_rows=sample_rows,
                        access_minutes=int(access_min)
                    )
                    enc_metrics.append(res)

                    dec = test_decrypt_first_row(str(out), tname)
                    dec_metrics.append({"table": tname, "decrypt_s": dec["decryption_time_seconds"], "status": "OK"})

                    integ = tamper_test(str(out), tname)
                    integrity.append(integ)

                    log_out += (
                        f"[✓] {tname}\n"
                        f"    rows={res['total_rows']} │ {res['original_size_kb']} KB → {res['encrypted_size_kb']} KB\n"
                        f"    enc={res['encryption_time_seconds']}s │ dec={dec['decryption_time_seconds']}s\n"
                        f"    integrity={'AMAN' if integ['tamper_detected'] else 'GAGAL'}\n\n"
                    )
                except Exception as e:
                    log_out += f"[✗] {tname}: {e}\n\n"

            prog.progress(1.0, text="Selesai!")
            st.success(f"✓ {len(enc_metrics)} tabel terenkripsi. Hasil disimpan di data/encrypted/")

            c1, c2, c3 = st.columns(3)
            if enc_metrics:
                avg_enc = sum(r.get("encryption_time_seconds", 0) or 0 for r in enc_metrics) / len(enc_metrics)
                c1.metric("Avg Enc Time", f"{avg_enc:.4f}s")
                total_rows = sum(r.get("total_rows", 0) or 0 for r in enc_metrics)
                c2.metric("Total Rows", f"{total_rows:,}")
                c3.metric("Tamper Detected", sum(1 for i in integrity if i.get("tamper_detected")))

            st.markdown("**Output log**")
            terminal(log_out)

            pd.DataFrame(enc_metrics).to_csv(RESULTS_DIR / "aes_encryption_metrics.csv", index=False)
            pd.DataFrame(dec_metrics).to_csv(RESULTS_DIR / "aes_decryption_metrics.csv", index=False)
            pd.DataFrame(integrity).to_csv(RESULTS_DIR / "aes_integrity_test.csv", index=False)

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: LIHAT DATA TERENKRIPSI
# ═══════════════════════════════════════════════════════════════════════════
elif page == "📂  Lihat Data Terenkripsi":
    sec("Data Terenkripsi", "Pratinjau file CSV hasil AES-256-GCM")

    enc_files = list(ENC_DIR.glob("*.csv"))
    if not enc_files:
        st.info("Belum ada data terenkripsi. Jalankan enkripsi terlebih dahulu.")
    else:
        choice = st.selectbox("Pilih file terenkripsi", [f.name for f in enc_files])
        df = pd.read_csv(ENC_DIR / choice, dtype=str, keep_default_na=False)

        st.markdown(f"**{choice}** — {len(df):,} baris · {len(df.columns)} kolom")
        st.dataframe(df.head(20), use_container_width=True, hide_index=True)

        cols_enc = [c for c in df.columns if c in ["ciphertext", "nonce", "otp", "aad", "key_id", "algorithm", "expires_at", "created_at"]]
        cols_pub = [c for c in df.columns if c not in cols_enc]

        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f'Kolom publik {badge(str(len(cols_pub)), "info")}', unsafe_allow_html=True)
            for c in cols_pub:
                st.markdown(f'`{c}`')
        with c2:
            st.markdown(f'Kolom terenkripsi {badge(str(len(cols_enc)), "ok")}', unsafe_allow_html=True)
            for c in cols_enc:
                st.markdown(f'`{c}`')

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: DEKRIPSI & VERIFY
# ═══════════════════════════════════════════════════════════════════════════
elif page == "🔓  Dekripsi & Verify":
    sec("Dekripsi & Integrity Verification", "aes_module.py · test_decrypt_first_row · tamper_test")

    enc_files = list(ENC_DIR.glob("*.csv"))
    if not enc_files:
        st.info("Belum ada data terenkripsi.")
    else:
        choice = st.selectbox("Pilih file", [f.name for f in enc_files])
        tname  = choice.replace("_encrypted.csv", "")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Uji Dekripsi (Baris Pertama)**")
            if st.button("🔓 Dekripsi Baris 1"):
                try:
                    res = test_decrypt_first_row(str(ENC_DIR / choice), tname)
                    st.success(f"✓ Dekripsi berhasil dalam {res['decryption_time_seconds']}s")
                    st.json(res["decrypted_sample"])
                except PermissionError as e:
                    st.error(f"⛔ Akses Ditolak: {e}")
                except Exception as e:
                    st.error(f"✗ Error: {e}")

        with col2:
            st.markdown("**Uji Integritas (Tamper Test)**")
            if st.button("🛡️ Jalankan Tamper Test"):
                res = tamper_test(str(ENC_DIR / choice), tname)
                if res["tamper_detected"]:
                    st.success(f"✓ AMAN — {res['message']}")
                    terminal(
                        "Tamper simulation:\n"
                        "  ciphertext[-1] di-flip (A↔B)\n"
                        "  AESGCM.decrypt() → InvalidTag\n"
                        f"  Result: {'TAMPER DETECTED ✓'}"
                    )
                else:
                    st.error(f"✗ GAGAL — {res['message']}")

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: RSA & KEY DISTRIBUTION
# ═══════════════════════════════════════════════════════════════════════════
elif page == "🛡️  RSA & Key Distribution":
    sec("RSA-2048 & Key Distribution", "rsa_module.py · key_distribution.py")

    tab1, tab2, tab3 = st.tabs(["RSA Key Pair", "Secure Distribution", "MITM Simulation"])

    with tab1:
        rsa_priv = KEYS_DIR / "rsa_private.pem"
        rsa_pub  = KEYS_DIR / "rsa_public.pem"
        if rsa_priv.exists():
            st.markdown(f'Status: {badge("RSA Key Pair sudah ada", "ok")}', unsafe_allow_html=True)
        else:
            st.markdown(f'Status: {badge("Key belum digenerate", "warn")}', unsafe_allow_html=True)

        if st.button("🔑 Generate RSA-2048 Key Pair"):
            with st.spinner("Generating RSA-2048…"):
                import io
                from contextlib import redirect_stdout
                buf = io.StringIO()
                with redirect_stdout(buf):
                    generate_rsa_keys()
            st.success("✓ RSA key pair tersimpan di keys/rsa_private.pem & rsa_public.pem")
            terminal(buf.getvalue() or "RSA key pair generated.")

        if rsa_pub.exists():
            with st.expander("📄 Lihat RSA Public Key"):
                st.code(rsa_pub.read_text(), language="text")

        st.markdown("---")
        st.markdown("**Test Enkripsi/Dekripsi AES Key via RSA**")
        if st.button("▶ Jalankan RSA Enc/Dec Test"):
            if not rsa_priv.exists():
                st.warning("Generate RSA key pair dulu.")
            else:
                sample_key = os.urandom(32)
                enc = rsa_encrypt_key(sample_key)
                dec = rsa_decrypt_key(enc)
                match = sample_key == dec
                st.success("✓ RSA encryption test: PASS") if match else st.error("✗ FAIL")
                terminal(
                    f"Original AES key : {sample_key.hex()[:32]}…\n"
                    f"Encrypted (RSA)  : {enc[:64]}…\n"
                    f"Decrypted key    : {dec.hex()[:32]}…\n"
                    f"Keys match       : {match}"
                )

    with tab2:
        st.markdown("**Simulasi Secure Key Distribution**")
        st.markdown("AES key dienkripsi RSA sebelum dikirim → attacker hanya melihat ciphertext.")
        if st.button("▶ Jalankan Secure Distribution"):
            if not (KEYS_DIR / "rsa_private.pem").exists():
                st.warning("Generate RSA key pair dulu.")
            else:
                test_key = AESGCM.generate_key(bit_length=256)
                import io; from contextlib import redirect_stdout
                buf = io.StringIO()
                with redirect_stdout(buf):
                    res = simulate_secure_key_distribution(test_key)
                st.success("✓ Key distribution berhasil") if res["distribution_success"] else st.error("✗ Gagal")
                terminal(buf.getvalue())

    with tab3:
        st.markdown("**Simulasi Man-In-The-Middle Attack**")
        st.markdown("Attacker memodifikasi RSA ciphertext → decrypt otomatis gagal (OAEP padding violation).")
        if st.button("⚠️ Jalankan MITM Simulation"):
            if not (KEYS_DIR / "rsa_private.pem").exists():
                st.warning("Generate RSA key pair dulu.")
            else:
                test_key = AESGCM.generate_key(bit_length=256)
                import io; from contextlib import redirect_stdout
                buf = io.StringIO()
                with redirect_stdout(buf):
                    res = simulate_mitm_attack(test_key)
                if res["mitm_detected"]:
                    st.success("✓ SECURE — Manipulasi ciphertext terdeteksi. Decrypt gagal.")
                else:
                    st.error("✗ WARNING — Tampered ciphertext masih terdekripsi!")
                terminal(buf.getvalue())

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: KEY ROTATION
# ═══════════════════════════════════════════════════════════════════════════
elif page == "♻️  Key Rotation":
    sec("Key Rotation", "key_rotation.py · rotate_key · auto_rotate_expired_keys")

    keys_path = KEYS_DIR / "aes_keys_plain.json"
    if keys_path.exists():
        with open(keys_path) as f:
            keys = json.load(f)
        rows = []
        now = datetime.now(timezone.utc)
        for kid, meta in keys.items():
            exp = meta.get("expires_at", "—")
            if exp != "—":
                try:
                    exp_dt = datetime.fromisoformat(exp)
                    expired = now > exp_dt
                except:
                    expired = False
            else:
                expired = False
            rows.append({
                "Key ID": kid,
                "Status": meta.get("status", "—"),
                "Algorithm": meta.get("algorithm", "—"),
                "Created": meta.get("created_at", "—")[:19],
                "Expires": exp[:19] if len(exp) > 10 else exp,
                "Expired?": "⚠️ Ya" if expired else "✓",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("Belum ada key. Jalankan enkripsi terlebih dahulu.")

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Manual Key Rotation**")
        tbl_sel = st.selectbox("Pilih tabel", list(SENSITIVE_COLUMNS.keys()))
        if st.button("♻️ Rotate Key"):
            import io; from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                res = rotate_key(tbl_sel)
            st.success(f"✓ Key baru: {res['new_key_id']}")
            terminal(buf.getvalue())

    with col2:
        st.markdown("**Auto Rotate Expired Keys**")
        if st.button("⚡ Auto Rotate"):
            import io; from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                rotated = auto_rotate_expired_keys()
            if rotated:
                st.success(f"✓ {len(rotated)} key expired dirotasi")
                for r in rotated:
                    st.markdown(f"- `{r['new_key_id']}`")
            else:
                st.info("Tidak ada key expired saat ini.")
            terminal(buf.getvalue() or "Auto rotation complete. No expired keys.")

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: KEY VAULT
# ═══════════════════════════════════════════════════════════════════════════
elif page == "🗄️  Key Vault":
    sec("Secure Key Vault", "key_vault.py · encrypt_key_registry · decrypt_key_registry")

    vault_file = KEYS_DIR / "aes_keys_encrypted.json"
    keys_path  = KEYS_DIR / "aes_keys_plain.json"

    c1, c2 = st.columns(2)
    c1.metric("Plain Registry", "Ada" if keys_path.exists() else "Belum ada")
    c2.metric("Encrypted Vault", "Ada" if vault_file.exists() else "Belum ada")

    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Enkripsi Registry ke Vault**")
        if st.button("🔒 Encrypt Key Registry"):
            if not keys_path.exists():
                st.warning("Belum ada key registry. Jalankan enkripsi terlebih dahulu.")
            else:
                with open(keys_path) as f:
                    keys_dict = json.load(f)
                import io; from contextlib import redirect_stdout
                buf = io.StringIO()
                with redirect_stdout(buf):
                    encrypt_key_registry(keys_dict)
                st.success(f"✓ {len(keys_dict)} key terenkripsi ke keys/aes_keys_encrypted.json")
                terminal(buf.getvalue())

    with col2:
        st.markdown("**Dekripsi & Validasi Vault**")
        if st.button("🔓 Decrypt & Validate Vault"):
            try:
                reg = decrypt_key_registry()
                if reg:
                    st.success(f"✓ Vault valid. {len(reg)} key berhasil didekripsi.")
                    for kid, meta in reg.items():
                        st.markdown(f'`{kid}` {badge(meta.get("status","—"), "ok" if meta.get("status")=="active" else "warn")}', unsafe_allow_html=True)
                else:
                    st.info("Vault kosong atau belum ada.")
            except Exception as e:
                st.error(f"✗ {e}")

    if vault_file.exists():
        with st.expander("📄 Lihat Encrypted Vault (raw)"):
            with open(vault_file) as f:
                raw = json.load(f)
            st.code(
                f"nonce     : {raw.get('nonce','')[:40]}…\nciphertext: {raw.get('ciphertext','')[:60]}…",
                language="text"
            )

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: OTP RANDOMNESS
# ═══════════════════════════════════════════════════════════════════════════
elif page == "🎲  OTP Randomness":
    sec("OTP Randomness Validation", "otp_module.py · aes_module.randomness_test()")

    st.markdown("Membuktikan bahwa plaintext yang sama menghasilkan ciphertext yang **berbeda** setiap kali dienkripsi (berkat OTP + nonce unik).")

    if st.button("🎲 Jalankan Randomness Test"):
        res = randomness_test()
        c1, c2, c3 = st.columns(3)
        c1.metric("OTP 1", res["otp_1"][:12] + "…")
        c2.metric("OTP 2", res["otp_2"][:12] + "…")
        same = res["ciphertext_equal"]
        c3.metric("Ciphertext Sama?", "Ya ⚠️" if same else "Tidak ✓")

        if not same:
            st.success("✓ Randomness valid — setiap enkripsi menghasilkan ciphertext unik")
        else:
            st.error("✗ OTP gagal — ciphertext identik (tidak seharusnya terjadi)")

        terminal(
            f"Payload    : {{\"name\": \"John Doe\", \"disease\": \"Diabetes\"}}\n"
            f"OTP #1     : {res['otp_1']}\n"
            f"OTP #2     : {res['otp_2']}\n"
            f"OTP sama?  : {res['otp_1'] == res['otp_2']}\n"
            f"Cipher sama: {res['ciphertext_equal']}\n"
            f"Kesimpulan : {'FAIL' if same else 'PASS — nonce & OTP unik per enkripsi'}"
        )

    st.markdown("---")
    st.markdown("**Demo OTP Manual**")
    length = st.slider("Panjang OTP (bytes)", 8, 64, 16)
    if st.button("Generate OTP"):
        otp_val = generate_otp(length=length)
        decoded = base64.b64decode(otp_val)
        terminal(
            f"OTP (Base64) : {otp_val}\n"
            f"OTP (Hex)    : {decoded.hex()}\n"
            f"Length       : {len(decoded)} bytes"
        )

# ═══════════════════════════════════════════════════════════════════════════
# PAGE: METRICS
# ═══════════════════════════════════════════════════════════════════════════
elif page == "📊  Metrics & Results":
    sec("Metrics & Benchmark Results", "results/ · aes_encryption_metrics.csv")

    enc_csv  = RESULTS_DIR / "aes_encryption_metrics.csv"
    dec_csv  = RESULTS_DIR / "aes_decryption_metrics.csv"
    integ_csv = RESULTS_DIR / "aes_integrity_test.csv"

    if not enc_csv.exists():
        st.info("Belum ada hasil. Jalankan enkripsi terlebih dahulu.")
    else:
        tab1, tab2, tab3 = st.tabs(["Encryption Metrics", "Decryption Metrics", "Integrity Test"])

        with tab1:
            df = pd.read_csv(enc_csv)
            st.dataframe(df, use_container_width=True, hide_index=True)
            if "encryption_time_seconds" in df.columns:
                df2 = df.dropna(subset=["encryption_time_seconds"])
                if not df2.empty:
                    st.bar_chart(df2.set_index("table_name")["encryption_time_seconds"])

        with tab2:
            if dec_csv.exists():
                df = pd.read_csv(dec_csv)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("Belum ada data dekripsi.")

        with tab3:
            if integ_csv.exists():
                df = pd.read_csv(integ_csv)
                for _, row in df.iterrows():
                    detected = row.get("tamper_detected")
                    if detected is True or str(detected).lower() == "true":
                        st.markdown(f'`{row["table_name"]}` {badge("AMAN ✓", "ok")} {row.get("message","")}', unsafe_allow_html=True)
                    elif detected is False or str(detected).lower() == "false":
                        st.markdown(f'`{row["table_name"]}` {badge("GAGAL ✗", "err")} {row.get("message","")}', unsafe_allow_html=True)
                    else:
                        st.markdown(f'`{row["table_name"]}` {badge("SKIP", "warn")} {row.get("message","")}', unsafe_allow_html=True)
            else:
                st.info("Belum ada hasil integrity test.")
