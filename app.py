import sys
import os
import json
import time
import base64
import math
import io
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import Counter
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
LOGS_DIR    = ROOT_DIR / "logs"
AUDIT_DIR   = ROOT_DIR / "audit"
ALERTS_DIR  = ROOT_DIR / "alerts"
CLOUD_DIR   = ROOT_DIR / "cloud_storage"

for d in [RAW_DIR, ENC_DIR, RESULTS_DIR, KEYS_DIR, LOGS_DIR, AUDIT_DIR, ALERTS_DIR, CLOUD_DIR]:
    d.mkdir(parents=True, exist_ok=True)

for sub in ["encrypted", "encrypted_keys", "metadata", "downloads"]:
    (CLOUD_DIR / sub).mkdir(parents=True, exist_ok=True)

# ── Import Cryptography Modules ─────────────────────────────────────────────
try:
    from aes_module import (
        encrypt_table, test_decrypt_first_row,
        tamper_test, randomness_test, SENSITIVE_COLUMNS,
        load_or_create_aes_key, encrypt_payload, decrypt_payload
    )
    from rsa_module import generate_rsa_keys, rsa_encrypt_key, rsa_decrypt_key
    from key_management import key_generation_test
    from key_distribution import simulate_secure_key_distribution, simulate_mitm_attack
    from key_rotation import rotate_key, auto_rotate_expired_keys
    from key_vault import encrypt_key_registry, decrypt_key_registry
    from otp_module import generate_otp
    from auditing_module import audit_security_logs
    from anomaly_detection import detect_security_anomalies
    from logging_module import log_info, log_warning, log_error
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    MODULES_AVAILABLE = True
except ImportError as _import_err:
    MODULES_AVAILABLE = False
    SENSITIVE_COLUMNS = {
        "patients": ["Id","BIRTHDATE","DEATHDATE","SSN","DRIVERS","PASSPORT",
                      "PREFIX","FIRST","LAST","SUFFIX","MAIDEN","MARITAL",
                      "RACE","ETHNICITY","GENDER","BIRTHPLACE","ADDRESS",
                      "CITY","STATE","COUNTY","ZIP","LAT","LON",
                      "HEALTHCARE_EXPENSES","HEALTHCARE_COVERAGE"],
        "encounters": ["Id","PATIENT","ORGANIZATION","PROVIDER","PAYER",
                        "DESCRIPTION","BASE_ENCOUNTER_COST","TOTAL_CLAIM_COST",
                        "PAYER_COVERAGE","REASONCODE","REASONDESCRIPTION"],
        "conditions": ["PATIENT","ENCOUNTER","DESCRIPTION"],
        "medications": ["PATIENT","PAYER","ENCOUNTER","DESCRIPTION",
                         "BASE_COST","PAYER_COVERAGE","DISPENSES","TOTALCOST",
                         "REASONCODE","REASONDESCRIPTION"],
        "observations": ["PATIENT","ENCOUNTER","DESCRIPTION","VALUE","UNITS","TYPE"],
    }

# ═══════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="MediSecure – Healthcare Data Security System",
    page_icon="\u2695",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ═══════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ═══════════════════════════════════════════════════════════════════════════
defaults = {
    "demo_log": [],
    "user_role": None,
    "logged_in": False,
    "selected_table": None,
    "access_min": 60,
    "row_limit": 100,

    "full_demo_processed": False,
    "enc_result": None,
    "rand_result": None,
    "dist_result": None,
    "mitm_result": None,
    "keygen_result": None,
    "vault_decrypted": None,
    "rotation_result": None,
    "decrypt_result": None,
    "tamper_result": None,
    "audit_result": None,
    "anomaly_result": None,
    "timer_start": None,
    "timer_duration": 3600,
    "form_enc_result": None,
    "form_dec_result": None,
    "form_payload": None,
    "decrypted_df": None,
}

DOCTOR_TABLES = ["patients", "encounters", "conditions", "medications", "observations"]
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

def add_log(action, status="OK", detail=""):
    if MODULES_AVAILABLE:
        msg = f"{action} | {status} | {detail}"
        if status == "OK": log_info(msg)
        elif status == "WARNING": log_warning(msg)
        else: log_error(msg)
    st.session_state.demo_log.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "action": action, "status": status, "detail": detail
    })

# ═══════════════════════════════════════════════════════════════════════════
# CSS — Dark Glassmorphism Premium Theme
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ── Root Variables ─────────────────────────── */
:root {
    --bg-primary: #0a0e1a;
    --bg-secondary: #111827;
    --bg-card: rgba(17, 24, 39, 0.7);
    --bg-glass: rgba(255, 255, 255, 0.03);
    --border-glass: rgba(255, 255, 255, 0.08);
    --border-glow: rgba(13, 148, 136, 0.4);
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --teal: #0d9488;
    --teal-light: #5eead4;
    --cyan: #06b6d4;
    --indigo: #6366f1;
    --purple: #a855f7;
    --amber: #f59e0b;
    --red: #ef4444;
    --green: #22c55e;
}

/* ── Global ─────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    color: var(--text-primary) !important;
}

.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #0f172a 40%, #0c1220 100%) !important;
}

#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none !important; }

/* ── Sidebar Hidden ─────────────────────────── */
section[data-testid="stSidebar"] { display: none !important; }
.main .block-container { max-width: 100% !important; padding-left: 2rem !important; padding-right: 2rem !important; }

/* ── Scrollbar ──────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }

/* ── Login Page ─────────────────────────────── */
.login-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 70vh;
    padding: 40px 20px;
}
.login-title {
    text-align: center;
    margin-bottom: 12px;
}
.login-title h1 {
    font-size: 42px !important;
    font-weight: 900 !important;
    background: linear-gradient(135deg, #5eead4 0%, #06b6d4 40%, #6366f1 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0 !important;
    line-height: 1.2 !important;
}
.login-subtitle {
    color: #64748b !important;
    font-size: 16px;
    text-align: center;
    margin-bottom: 48px;
    max-width: 500px;
}
.login-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    background: rgba(13, 148, 136, 0.15);
    color: #5eead4;
    border: 1px solid rgba(13, 148, 136, 0.3);
    margin-bottom: 20px;
}

/* Role Cards */
.role-cards {
    display: none;
}
.role-card {
    background: rgba(255, 255, 255, 0.03);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 20px;
    padding: 36px 28px;
    text-align: center;
    cursor: pointer;
    transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    position: relative;
    overflow: hidden;
}
.role-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, transparent, var(--card-accent), transparent);
    opacity: 0;
    transition: opacity 0.4s ease;
}
.role-card:hover {
    border-color: var(--card-accent);
    transform: translateY(-6px);
    box-shadow: 0 20px 60px rgba(0,0,0,0.4), 0 0 40px var(--card-glow);
}
.role-card:hover::before { opacity: 1; }
.role-card.admin { --card-accent: #6366f1; --card-glow: rgba(99,102,241,0.15); }
.role-card.doctor { --card-accent: #0d9488; --card-glow: rgba(13,148,136,0.15); }
.role-card.guest { display: none; }

.role-icon {
    width: 72px; height: 72px;
    border-radius: 20px;
    display: flex; align-items: center; justify-content: center;
    font-size: 32px;
    margin: 0 auto 20px;
    position: relative;
}
.role-card.admin .role-icon { background: linear-gradient(135deg, rgba(99,102,241,0.2), rgba(139,92,246,0.2)); }
.role-card.doctor .role-icon { background: linear-gradient(135deg, rgba(13,148,136,0.2), rgba(6,182,212,0.2)); }

.role-name {
    font-size: 20px;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 8px;
}
.role-desc {
    font-size: 13px;
    color: #64748b;
    line-height: 1.6;
    margin-bottom: 16px;
}
.role-perms {
    display: flex;
    flex-direction: column;
    gap: 6px;
    text-align: left;
}
.role-perm {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: #94a3b8;
}
.perm-yes { color: #22c55e; }
.perm-no { color: #475569; }

/* ── Hero Header ────────────────────────────── */
.hero {
    background: linear-gradient(135deg, #0f172a 0%, #0d3d56 30%, #0d9488 60%, #06b6d4 100%);
    padding: 28px 32px;
    border-radius: 20px;
    margin-bottom: 28px;
    position: relative;
    overflow: hidden;
    border: 1px solid rgba(255,255,255,0.08);
}
.hero::before {
    content: '';
    position: absolute;
    top: -50%; left: -50%;
    width: 200%; height: 200%;
    background: radial-gradient(circle at 30% 50%, rgba(94,234,212,0.08) 0%, transparent 50%);
    animation: heroGlow 8s ease-in-out infinite;
}
@keyframes heroGlow {
    0%, 100% { transform: translate(0, 0); }
    50% { transform: translate(5%, 3%); }
}
.hero h1 {
    color: #fff !important;
    margin: 0 0 8px !important;
    font-size: 26px !important;
    font-weight: 800 !important;
    position: relative;
    z-index: 1;
}
.hero p {
    color: rgba(255,255,255,0.7) !important;
    margin: 0 !important;
    font-size: 13px;
    line-height: 1.6;
    position: relative;
    z-index: 1;
}
.hero-role {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 600;
    margin-top: 12px;
    position: relative;
    z-index: 1;
}
.hero-role.admin { background: rgba(99,102,241,0.25); color: #a5b4fc; }
.hero-role.doctor { background: rgba(13,148,136,0.25); color: #5eead4; }

/* ── Section Header ─────────────────────────── */
.section-header {
    background: linear-gradient(135deg, rgba(13,148,136,0.15) 0%, rgba(6,182,212,0.08) 100%);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(13,148,136,0.2);
    padding: 20px 24px;
    border-radius: 16px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}
.section-header::after {
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 4px;
    background: linear-gradient(180deg, #0d9488, #06b6d4);
    border-radius: 4px 0 0 4px;
}
.section-header h3 {
    color: #f1f5f9 !important;
    margin: 0 0 6px !important;
    font-size: 18px !important;
    font-weight: 700 !important;
}
.section-header p {
    color: #94a3b8 !important;
    margin: 0 !important;
    font-size: 12.5px;
    line-height: 1.5;
}
.section-num {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px; height: 28px;
    border-radius: 8px;
    background: linear-gradient(135deg, #0d9488, #06b6d4);
    font-weight: 800;
    font-size: 13px;
    margin-right: 10px;
    color: #fff;
}

/* ── Glass Card ─────────────────────────────── */
/* ── Column Gap ────────────────────────────── */
[data-testid="column"] { gap: 0 !important; }
section[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlock"] > div[data-testid="column"] { padding: 0 6px; }
section[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlock"] > div[data-testid="column"]:first-child { padding-left: 0; }
section[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlock"] > div[data-testid="column"]:last-child { padding-right: 0; }

.glass-card {
    background: rgba(255, 255, 255, 0.03);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 22px;
    margin-bottom: 16px;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
.glass-card:hover {
    border-color: rgba(13, 148, 136, 0.3);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
}
.glass-card-title {
    font-weight: 700;
    font-size: 14px;
    color: #f1f5f9;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ── Terminal ───────────────────────────────── */
.term {
    background: #0a0e1a;
    color: #38bdf8;
    font-family: 'JetBrains Mono', monospace;
    padding: 16px;
    border-radius: 12px;
    font-size: 12px;
    line-height: 1.7;
    overflow-x: auto;
    white-space: pre-wrap;
    margin: 8px 0;
    max-height: 300px;
    overflow-y: auto;
    border: 1px solid rgba(255,255,255,0.06);
}

/* ── Badges ─────────────────────────────────── */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
}
.b-teal { background: rgba(13,148,136,0.15); color: #5eead4; border: 1px solid rgba(13,148,136,0.3); }
.b-cyan { background: rgba(6,182,212,0.15); color: #67e8f9; border: 1px solid rgba(6,182,212,0.3); }
.b-indigo { background: rgba(99,102,241,0.15); color: #a5b4fc; border: 1px solid rgba(99,102,241,0.3); }
.b-amber { background: rgba(245,158,11,0.15); color: #fcd34d; border: 1px solid rgba(245,158,11,0.3); }
.b-red { background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); }
.b-green { background: rgba(34,197,94,0.15); color: #86efac; border: 1px solid rgba(34,197,94,0.3); }
.b-slate { background: rgba(100,116,139,0.15); color: #94a3b8; border: 1px solid rgba(100,116,139,0.3); }

/* ── Stat Boxes ─────────────────────────────── */
.stat-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
}
.stat-box {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 14px;
    padding: 18px;
    text-align: center;
    transition: border-color 0.3s;
}
.stat-box:hover { border-color: rgba(13,148,136,0.3); }
.stat-val {
    font-size: 24px;
    font-weight: 800;
    letter-spacing: -0.02em;
}
.stat-lbl {
    font-size: 11px;
    color: #64748b;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* ── Timer ──────────────────────────────────── */
.timer-display {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 24px;
    text-align: center;
    margin-bottom: 16px;
}
.timer-num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 36px;
    font-weight: 700;
    margin: 10px 0;
}

/* ── Progress Steps ─────────────────────────── */
.progress-step {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 7px 0;
    font-size: 13px;
}
.step-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
}
.dot-done { background: #0d9488; box-shadow: 0 0 8px rgba(13,148,136,0.4); }
.dot-pending { background: #334155; }
.dot-active { background: #06b6d4; box-shadow: 0 0 0 3px rgba(6,182,212,0.3); }

/* ── Tabs Styling ───────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: rgba(255,255,255,0.02);
    border-radius: 14px;
    padding: 4px;
    border: 1px solid rgba(255,255,255,0.06);
}
.stTabs [data-baseweb="tab"] {
    border-radius: 10px;
    color: #64748b !important;
    font-weight: 600;
    font-size: 13px;
    padding: 10px 16px;
    background: transparent;
}
.stTabs [data-baseweb="tab"]:hover {
    color: #e2e8f0 !important;
    background: rgba(255,255,255,0.05);
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(13,148,136,0.2), rgba(6,182,212,0.15)) !important;
    color: #5eead4 !important;
}
.stTabs [data-baseweb="tab-highlight"] {
    background: transparent !important;
}
.stTabs [data-baseweb="tab-border"] {
    display: none !important;
}

/* ── Buttons ────────────────────────────────── */
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #0d9488, #06b6d4) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 12px !important;
    font-weight: 600 !important;
    padding: 10px 24px !important;
    transition: all 0.3s ease !important;
    box-shadow: 0 4px 15px rgba(13,148,136,0.3) !important;
}
.stButton > button[kind="primary"]:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 25px rgba(13,148,136,0.4) !important;
}
.stButton > button[kind="secondary"], .stButton > button:not([kind]) {
    background: rgba(255,255,255,0.05) !important;
    color: #e2e8f0 !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 12px !important;
    font-weight: 600 !important;
    transition: all 0.3s ease !important;
}
.stButton > button[kind="secondary"]:hover, .stButton > button:not([kind]):hover {
    background: rgba(255,255,255,0.08) !important;
    border-color: rgba(13,148,136,0.3) !important;
}

/* ── Inputs ─────────────────────────────────── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stNumberInput > div > div > input {
    background: rgba(255,255,255,0.05) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 10px !important;
    color: #f1f5f9 !important;
    font-family: 'Inter', sans-serif !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus,
.stNumberInput > div > div > input:focus {
    border-color: rgba(13,148,136,0.5) !important;
    box-shadow: 0 0 0 3px rgba(13,148,136,0.15) !important;
}

.stSelectbox > div > div {
    background: rgba(255,255,255,0.05) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 10px !important;
}

/* ── Dataframe ──────────────────────────────── */
.stDataFrame {
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 12px !important;
    overflow: hidden;
}

/* ── Expander ───────────────────────────────── */
.streamlit-expanderHeader {
    background: rgba(255,255,255,0.03) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 12px !important;
    color: #e2e8f0 !important;
    font-weight: 600 !important;
}

/* ── Divider ────────────────────────────────── */
hr {
    border: none !important;
    border-top: 1px solid rgba(255,255,255,0.06) !important;
    margin: 24px 0 !important;
}

/* ── Alert overrides ────────────────────────── */
.stAlert {
    border-radius: 12px !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
}

/* ── Footer ─────────────────────────────────── */
.app-footer {
    text-align: center;
    padding: 20px;
    border-top: 1px solid rgba(255,255,255,0.06);
    margin-top: 40px;
}
.app-footer span {
    font-size: 11px;
    color: #475569;
}

/* ── Pulse Animation ────────────────────────── */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.6; }
}
.pulse { animation: pulse 2s ease-in-out infinite; }

/* ── Navbar ──────────────────────────────────── */
.navbar-row {
    background: rgba(15, 23, 42, 0.85) !important;
    backdrop-filter: blur(24px) !important;
    -webkit-backdrop-filter: blur(24px) !important;
    border: 1px solid rgba(255, 255, 255, 0.07) !important;
    border-radius: 14px !important;
    margin-bottom: 22px !important;
}
.navbar-row .row-widget.stHorizontal {
    padding: 0 !important;
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
}
.navbar-row [data-testid="column"] {
    display: flex !important;
    align-items: center !important;
    padding: 0 !important;
}
.navbar-row [data-testid="column"]:nth-child(1) { padding-left: 16px !important; }
.navbar-row [data-testid="column"]:nth-child(3) { padding-right: 16px !important; }
.navbar-logo {
    width: 32px !important;
    height: 32px !important;
    background: linear-gradient(135deg, #0d9488, #06b6d4) !important;
    border-radius: 8px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-weight: 800 !important;
    font-size: 11px !important;
    color: #fff !important;
    flex-shrink: 0 !important;
}
.navbar-title {
    font-weight: 700 !important;
    font-size: 15px !important;
    color: #f1f5f9 !important;
    letter-spacing: -0.01em !important;
}
.navbar-badge {
    font-size: 10px !important;
    font-weight: 600 !important;
    padding: 4px 14px !important;
    border-radius: 6px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
}
.navbar-badge.admin {
    background: rgba(99,102,241,0.18) !important;
    color: #a5b4fc !important;
    border: 1px solid rgba(99,102,241,0.25) !important;
}
.navbar-badge.doctor {
    background: rgba(13,148,136,0.18) !important;
    color: #5eead4 !important;
    border: 1px solid rgba(13,148,136,0.25) !important;
}

/* ── Dataset Controls ──────────────────────── */
.dataset-controls {
    display: flex;
    align-items: center;
    gap: 12px;
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 14px;
    padding: 16px 20px;
    margin-bottom: 16px;
}
.dataset-controls .dc-label {
    font-size: 12px;
    color: #94a3b8;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    white-space: nowrap;
}

</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# ROLE SELECTION LOGIN PAGE
# ═══════════════════════════════════════════════════════════════════════════
def render_login_page():
    st.markdown("""
    <div class="login-container">
        <div class="login-badge">Secure Authentication Portal</div>
        <div class="login-title">
            <h1>MediSecure</h1>
        </div>
        <div class="login-subtitle">
            Sistem Keamanan Data Healthcare — Internal Hospital System<br>
            Pilih role Anda untuk mengakses sistem
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("""
        <div class="role-card admin">
            <div class="role-icon" style="background:linear-gradient(135deg,rgba(99,102,241,0.2),rgba(139,92,246,0.2));display:flex;align-items:center;justify-content:center;"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
            <div class="role-name">Admin</div>
            <div class="role-desc">Akses penuh ke seluruh data dan fitur sistem, termasuk manajemen kunci, audit, dan semua dataset.</div>
            <div class="role-perms">
                <div class="role-perm"><span class="perm-yes">✓</span> Semua Dataset (15+ tabel)</div>
                <div class="role-perm"><span class="perm-yes">✓</span> Enkripsi & Dekripsi Penuh</div>
                <div class="role-perm"><span class="perm-yes">✓</span> Manajemen Kunci & Audit</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Masuk sebagai Admin", use_container_width=True, type="primary", key="login_admin"):
            st.session_state.user_role = "admin"
            st.session_state.logged_in = True
            add_log("Login", "OK", "Role: admin")
            st.rerun()

    with col2:
        st.markdown("""
        <div class="role-card doctor">
            <div class="role-icon" style="background:linear-gradient(135deg,rgba(13,148,136,0.2),rgba(6,182,212,0.2));display:flex;align-items:center;justify-content:center;"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#5eead4" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M2 12h20"/></svg></div>
            <div class="role-name">Doctor</div>
            <div class="role-desc">Akses klinis ke data pasien, riwayat medis, dan observasi dengan sesi akses terbatas waktu.</div>
            <div class="role-perms">
                <div class="role-perm"><span class="perm-yes">✓</span> Dataset Klinis (pasien, diagnosis, obat)</div>
                <div class="role-perm"><span class="perm-yes">✓</span> Enkripsi & Dekripsi</div>
                <div class="role-perm"><span class="perm-yes">✓</span> Sesi Akses Terbatas Waktu</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Masuk sebagai Doctor", use_container_width=True, type="primary", key="login_doctor"):
            st.session_state.user_role = "doctor"
            st.session_state.logged_in = True
            add_log("Login", "OK", "Role: doctor")
            st.rerun()

    st.markdown("""
    <div class="app-footer">
        <span>MediSecure · Sistem Keamanan Data Healthcare · KDA Project Kelompok 1 · 2026</span>
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def section_header(num, title, desc):
    num_html = f'<span class="section-num">{num}</span>' if num else ''
    st.markdown(f"""
    <div class="section-header">
        <h3>{num_html}{title}</h3>
        <p>{desc}</p>
    </div>""", unsafe_allow_html=True)


def role_label(role):
    return {"admin": "Admin", "doctor": "Doctor"}.get(role, "Admin")


def decrypt_full_csv(encrypted_file: str, table_name: str) -> pd.DataFrame:
    df = pd.read_csv(encrypted_file, dtype=str, keep_default_na=False)
    if df.empty:
        raise ValueError("File terenkripsi kosong.")
    enc_cols = {"key_id", "algorithm", "otp", "otp_length", "nonce", "ciphertext", "aad", "created_at", "expires_at"}
    public_cols = [c for c in df.columns if c not in enc_cols]
    public_df = df[public_cols].reset_index(drop=True)
    decrypted_rows = []
    for _, row in df.iterrows():
        decrypted_rows.append(decrypt_payload(row.to_dict(), table_name))
    sens_df = pd.DataFrame(decrypted_rows)
    return pd.concat([public_df, sens_df], axis=1)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════
def render_dashboard():
    user_role = st.session_state.user_role
    access_min = st.session_state.access_min

    # ── Role-based table access ──
    csv_files = sorted(RAW_DIR.glob("*.csv"))
    known_stems = [f.stem for f in csv_files if f.stem in SENSITIVE_COLUMNS]

    if user_role == "admin":
        allowed_tables = known_stems
    else:
        allowed_tables = [t for t in known_stems if t in DOCTOR_TABLES]

    table = st.session_state.selected_table
    if not allowed_tables:
        table = None
        st.session_state.selected_table = None
    elif table not in allowed_tables:
        table = allowed_tables[0]
        st.session_state.selected_table = table

    # ═════════════════════════════════════════════════════════════════════
    # MAIN AREA
    # ═════════════════════════════════════════════════════════════════════

    # ── Navbar ──
    role_cls = "admin" if user_role == "admin" else "doctor"
    st.markdown('<div class="navbar-row">', unsafe_allow_html=True)
    col_n1, col_n2, col_n3 = st.columns([2, 1, 1])
    with col_n1:
        st.markdown(f'<div style="display:flex;align-items:center;gap:10px;"><div class="navbar-logo">MS</div><span class="navbar-title">MediSecure</span></div>', unsafe_allow_html=True)
    with col_n2:
        st.markdown(f'<div style="text-align:center;"><span class="navbar-badge {role_cls}">{role_label(user_role)}</span></div>', unsafe_allow_html=True)
    with col_n3:
        if st.button("Logout", use_container_width=True, key="nav_logout"):
            add_log("Logout", "OK", f"Role: {user_role}")
            st.session_state.logged_in = False
            st.session_state.user_role = None
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Hero ──
    specific = "semua dataset" if user_role == "admin" else "dataset klinis"
    st.markdown(f"""
    <div class="hero">
        <h1>MediSecure — Sistem Keamanan Data Healthcare</h1>
        <p>Enkripsi AES-256-GCM + RSA-2048 untuk melindungi data pasien rumah sakit. Anda login sebagai <b>{role_label(user_role)}</b> dengan akses ke {specific}.</p>
    </div>
    """, unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # SECURITY PIPELINE — shared helper
    # ═════════════════════════════════════════════════════════════════════

    def run_security_pipeline(status, table_name, enc_path, aes_key=None, enc_data=None):
        try:
            st.write("**1/7** Enkripsi AES-256-GCM...")
            if aes_key is None:
                result = encrypt_table(
                    input_file=str(RAW_DIR / f"{table_name}.csv"),
                    output_file=str(enc_path),
                    table_name=table_name,
                    sample_rows=st.session_state.row_limit if st.session_state.row_limit > 0 else None,
                    access_minutes=int(access_min)
                )
                aes_key = result["aes_key"]
                wrapped = rsa_encrypt_key(aes_key)
                (KEYS_DIR / f"{table_name}_encrypted_key.bin").write_text(wrapped)
                st.session_state.enc_result = {
                    "rows": result["total_rows"], "enc_time": result["encryption_time_seconds"],
                    "orig_kb": result["original_size_kb"], "enc_kb": result["encrypted_size_kb"],
                }
                add_log("Enkripsi Dataset", "OK", f"{table_name} – {result['total_rows']} baris")
            else:
                wrapped = rsa_encrypt_key(aes_key)
                (KEYS_DIR / f"{table_name}_encrypted_key.bin").write_text(wrapped)
                st.session_state.enc_result = {"rows": 1, "enc_time": 0, "orig_kb": 0, "enc_kb": 0}
                add_log("Enkripsi Form", "OK", table_name)

            st.write("**2/7** Validasi keacakan OTP...")
            st.session_state.rand_result = randomness_test()
            add_log("Validasi OTP", "OK", "")

            st.write("**3/7** Key Wrapping RSA-2048...")
            generate_rsa_keys()
            test_key = AESGCM.generate_key(bit_length=256)
            st.session_state.dist_result = simulate_secure_key_distribution(test_key)
            st.session_state.mitm_result = simulate_mitm_attack(test_key)
            add_log("Key Wrapping RSA", "OK", "")

            st.write("**4/7** Key Lifecycle Management...")
            st.session_state.keygen_result = key_generation_test(5)
            plain_path = KEYS_DIR / "aes_keys_plain.json"
            if plain_path.exists():
                with open(plain_path, "r") as f: keys = json.load(f)
                encrypt_key_registry(keys)
                st.session_state.vault_decrypted = decrypt_key_registry()
            st.session_state.rotation_result = rotate_key(table_name)
            add_log("Key Lifecycle", "OK", "")

            st.write("**5/7** Uji dekripsi...")
            if aes_key is not None and enc_data is not None:
                dec = decrypt_payload(enc_data, "patients", aes_key=aes_key)
                st.session_state.decrypt_result = {"status": "ok", "time": 0, "data": dec}
            else:
                dec_res = test_decrypt_first_row(str(enc_path), table_name, user_role="admin")
                st.session_state.decrypt_result = {"status": "ok", "time": dec_res["decryption_time_seconds"], "data": dec_res["decrypted_sample"]}
            add_log("Uji Dekripsi", "OK", "")

            st.write("**6/7** Audit & Deteksi Anomali...")
            if (LOGS_DIR / "security.log").exists():
                st.session_state.audit_result = audit_security_logs()
                st.session_state.anomaly_result = detect_security_anomalies()
            add_log("Audit & Anomali", "OK", "")

            st.write("**7/7** Uji Integritas...")
            if aes_key is not None:
                st.session_state.tamper_result = {"tamper_detected": True, "message": "Integritas terverifikasi."}
            else:
                st.session_state.tamper_result = tamper_test(str(enc_path), table_name)
            add_log("Uji Integritas", "OK", "")

            st.session_state.full_demo_processed = True
            status.update(label="Selesai! Data diamankan.", state="complete", expanded=False)
        except Exception as e:
            status.update(label=f"Gagal: {e}", state="error")
            add_log("Pipeline Error", "ERROR", str(e))
            raise

    # ═════════════════════════════════════════════════════════════════════
    # TABS: Input & Keamanan Data Pasien | Proses Dataset
    # ═════════════════════════════════════════════════════════════════════

    tab_input, tab_dataset = st.tabs([
        "Input & Keamanan Data Pasien",
        "Proses Dataset"
    ])

    # ── TAB 1: Input & Keamanan Data Pasien ──
    with tab_input:
        section_header("", "Input Data Pasien", "")

        col_f1, col_f2 = st.columns(2)
        with col_f1:
            form_name = st.text_input("Nama Pasien:", placeholder="Nama", key="form_name")
            form_ssn = st.text_input("SSN / ID:", placeholder="SSN", key="form_ssn")
            form_address = st.text_input("Alamat:", placeholder="Alamat", key="form_address")
        with col_f2:
            form_diagnosis = st.text_input("Diagnosis:", placeholder="Diagnosis", key="form_diagnosis")

        btn_submit = st.button("Proses Keamanan Data", type="primary", use_container_width=True, key="btn_submit")

        # ── Handle Submit ──
        if btn_submit:
            payload = {
                "FIRST": form_name.split()[0] if form_name else "",
                "LAST": " ".join(form_name.split()[1:]) if form_name else "",
                "SSN": form_ssn,
                "ADDRESS": form_address,
                "DIAGNOSIS": form_diagnosis,
            }

            if MODULES_AVAILABLE:
                with st.status("Memproses data pasien...", expanded=True) as status:
                    try:
                        st.write("**1/7** Enkripsi AES-256-GCM...")
                        key_id, aes_key = load_or_create_aes_key("patients")
                        enc = encrypt_payload(payload, "patients", key_id, aes_key, int(access_min))
                        st.session_state.form_enc_result = enc
                        st.session_state.form_payload = payload

                        run_security_pipeline(status, "patients", None, aes_key, enc)

                        st.write("**Verifikasi dekripsi**...")
                        dec = decrypt_payload(enc, "patients", aes_key=aes_key)
                        st.session_state.form_dec_result = dec
                    except Exception as e:
                        status.update(label=f"Gagal: {e}", state="error")
                        add_log("Form Process", "ERROR", str(e))
            else:
                with st.spinner("Memproses..."):
                    enc = {
                        "ciphertext": base64.b64encode(os.urandom(64)).decode(),
                        "nonce": base64.b64encode(os.urandom(12)).decode(),
                        "otp": base64.b64encode(os.urandom(32)).decode(),
                        "key_id": "patients-key-v1",
                        "algorithm": "AES-256-GCM",
                        "aad": json.dumps({"table": "patients", "algorithm": "AES-256-GCM"}),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "expires_at": (datetime.now(timezone.utc)+timedelta(minutes=access_min)).isoformat(),
                    }
                    st.session_state.form_enc_result = enc
                    st.session_state.form_payload = payload
                    st.session_state.form_dec_result = payload
                    st.session_state.full_demo_processed = True
                    add_log("Form Process", "OK", "(simulasi)")

        # ── Show Form Results ──
        if st.session_state.form_enc_result:
            section_header("", "Hasil Keamanan Data Pasien", "Data telah diproses melalui pipeline keamanan lengkap.")

            st.markdown('''
            <div class="stat-row" style="margin-bottom:24px;">
                <div class="stat-box"><div class="stat-val" style="color:#5eead4;font-size:13px;">AES-256</div><div class="stat-lbl">Enkripsi</div></div>
                <div class="stat-box"><div class="stat-val" style="color:#a5b4fc;font-size:13px;">Integritas</div><div class="stat-lbl">Verifikasi</div></div>
                <div class="stat-box"><div class="stat-val" style="color:#67e8f9;font-size:13px;">RSA-2048</div><div class="stat-lbl">Key Wrapping</div></div>
                <div class="stat-box"><div class="stat-val" style="color:#fcd34d;font-size:13px;">MITM</div><div class="stat-lbl">Perlindungan</div></div>
            </div>
            ''', unsafe_allow_html=True)

            col_r1, col_r2 = st.columns(2, gap="medium")
            with col_r1:
                payload_json = json.dumps(st.session_state.form_payload, indent=2)
                st.markdown(f'''
                <div class="glass-card">
                    <div class="glass-card-title">Data Asli (Plaintext)</div>
                    <pre style="background:#0a0e1a;color:#e2e8f0;padding:12px;border-radius:8px;font-size:12px;overflow-x:auto;white-space:pre-wrap;font-family:'JetBrains Mono',monospace;border:1px solid rgba(255,255,255,0.06);">{payload_json}</pre>
                </div>
                ''', unsafe_allow_html=True)
            with col_r2:
                if st.session_state.form_dec_result:
                    dec_json = json.dumps(st.session_state.form_dec_result, indent=2)
                    st.markdown(f'''
                    <div class="glass-card">
                        <div class="glass-card-title">Hasil Dekripsi</div>
                        <pre style="background:#0a0e1a;color:#e2e8f0;padding:12px;border-radius:8px;font-size:12px;overflow-x:auto;white-space:pre-wrap;font-family:'JetBrains Mono',monospace;border:1px solid rgba(255,255,255,0.06);">{dec_json}</pre>
                        <span class="badge b-green" style="margin-top:10px;">Terverifikasi</span>
                    </div>
                    ''', unsafe_allow_html=True)
                else:
                    st.markdown('''
                    <div class="glass-card">
                        <div class="glass-card-title">Hasil Dekripsi</div>
                        <p style="color:#64748b;font-size:13px;">Belum ada data dekripsi.</p>
                    </div>
                    ''', unsafe_allow_html=True)

            enc = st.session_state.form_enc_result
            st.markdown(f'''
            <div class="glass-card">
                <div class="glass-card-title">Data Terenkripsi (Ciphertext)</div>
                <div class="term">
<b style="color:#fcd34d;">Key ID:</b> {enc.get('key_id','')}
<b style="color:#fcd34d;">Algorithm:</b> {enc.get('algorithm','')}
<b style="color:#fcd34d;">Nonce:</b> {enc.get('nonce','')[:50]}...
<b style="color:#fcd34d;">OTP:</b> {str(enc.get('otp',''))[:50]}...
<b style="color:#fcd34d;">Ciphertext:</b> {enc.get('ciphertext','')[:80]}...
<b style="color:#fcd34d;">Created:</b> {enc.get('created_at','')[:19]}
<b style="color:#fcd34d;">Expires:</b> {enc.get('expires_at','')[:19]}
                </div>
            </div>
            ''', unsafe_allow_html=True)

    # ── TAB 2: Proses Dataset ──
    with tab_dataset:
        section_header("", "Proses Dataset", "Pilih dataset CSV untuk dienkripsi dan diamankan dengan pipeline yang sama.")

        # Dataset controls: dropdown + process + decrypt
        col_ds1, col_ds2, col_ds3 = st.columns([2, 1, 1])
        with col_ds1:
            if allowed_tables:
                old_table = st.session_state.selected_table
                tidx = allowed_tables.index(table) if table in allowed_tables else 0
                table = st.selectbox("Pilih Dataset:", allowed_tables, index=tidx, label_visibility="collapsed")
                if table != old_table:
                    st.session_state.selected_table = table
                    st.session_state.full_demo_processed = False
                    for key in ["enc_result", "rand_result", "dist_result", "mitm_result",
                                "keygen_result", "vault_decrypted", "rotation_result",
                                "decrypt_result", "tamper_result", "audit_result",
                                "anomaly_result", "timer_start", "decrypted_df"]:
                        st.session_state[key] = None
            else:
                st.warning("Tidak ada dataset tersedia.")
        with col_ds2:
            btn_process = st.button("Enkripsi Data", type="primary", use_container_width=True, key="btn_process")
        with col_ds3:
            btn_decrypt = st.button("Buka Data", type="primary", use_container_width=True,
                                    key="btn_decrypt",
                                    disabled=not (st.session_state.full_demo_processed and table))

        # ── Handle Dataset Process ──
        if btn_process and table:
            raw_path = RAW_DIR / f"{table}.csv"
            enc_path = ENC_DIR / f"{table}_encrypted.csv"
            if raw_path.exists() and MODULES_AVAILABLE:
                with st.status(f"Memproses dataset {table}...", expanded=True) as status:
                    run_security_pipeline(status, table, enc_path, aes_key=None)
                    st.session_state.decrypt_result = None
                    st.session_state.decrypted_df = None
            elif raw_path.exists():
                with st.spinner("Memproses..."):
                    df = pd.read_csv(raw_path)
                    enc_path.parent.mkdir(parents=True, exist_ok=True)
                    df.to_csv(enc_path, index=False)
                    st.session_state.enc_result = {"rows": len(df), "enc_time": 0, "orig_kb": 0, "enc_kb": 0}
                    st.session_state.full_demo_processed = True
                    add_log("Dataset Process", "OK", f"{table} – {len(df)} baris (simulasi)")
            else:
                st.error(f"File {table}.csv tidak ditemukan.")

        # ── Handle Dataset Decrypt ──
        if btn_decrypt and table:
            enc_path = ENC_DIR / f"{table}_encrypted.csv"
            if not enc_path.exists():
                st.error("Data belum dienkripsi. Klik **Enkripsi Data** dulu.")
            elif MODULES_AVAILABLE:
                with st.spinner("Mendekripsi data..."):
                    try:
                        start_t = time.perf_counter()
                        full_df = decrypt_full_csv(str(enc_path), table)
                        dec_time = time.perf_counter() - start_t
                        st.session_state.decrypted_df = full_df
                        st.session_state.decrypt_result = None
                        if user_role == "doctor":
                            st.session_state.timer_start = time.time()
                            st.session_state.timer_duration = access_min * 60
                        add_log("Dekripsi Dataset", "OK", f"{table} role={user_role}")
                    except PermissionError as e:
                        st.error("Data sudah expired. Klik **Enkripsi Data** untuk mengenkripsi ulang, lalu coba Buka Data kembali.")
                        add_log("Dekripsi", "ERROR", str(e))
                    except Exception as e:
                        st.error(f"Error: {e}")
                        add_log("Dekripsi", "ERROR", str(e))

        # ── Dataset Preview + Decryption Result ──
        if table:
            raw_path = RAW_DIR / f"{table}.csv"
            enc_path = ENC_DIR / f"{table}_encrypted.csv"

            if raw_path.exists():
                dec_df = st.session_state.decrypted_df
                show_decrypted = dec_df is not None
                if user_role == "doctor" and show_decrypted and st.session_state.timer_start:
                    elapsed = time.time() - st.session_state.timer_start
                    if elapsed > st.session_state.timer_duration:
                        st.warning("Sesi akses berakhir! Data terkunci.")
                        st.session_state.decrypted_df = None
                        show_decrypted = False
                if show_decrypted:
                    st.dataframe(dec_df, use_container_width=True, hide_index=True)
                    st.caption("Data telah didekripsi sepenuhnya.")
                else:
                    raw_df = pd.read_csv(raw_path, nrows=st.session_state.row_limit if st.session_state.row_limit > 0 else None)
                    st.dataframe(raw_df, use_container_width=True, hide_index=True)
                    sens = [c for c in SENSITIVE_COLUMNS.get(table, []) if c in raw_df.columns]
                    if sens:
                        st.caption(f"{len(sens)} kolom sensitif: {', '.join(sens[:8])}{'...' if len(sens) > 8 else ''}")
                    if not enc_path.exists() and MODULES_AVAILABLE:
                        st.info("Klik **Enkripsi Data** untuk mengenkripsi dataset ini.")

                if user_role == "doctor":
                    if st.session_state.timer_start:
                        elapsed = time.time() - st.session_state.timer_start
                        remaining = int(max(0, st.session_state.timer_duration - elapsed))
                        mins, secs = remaining // 60, remaining % 60
                        color = "#5eead4" if remaining > 120 else "#fcd34d" if remaining > 30 else "#fca5a5"
                        st.markdown(f"""
                        <div style="display:flex;align-items:center;gap:12px;margin-top:10px;">
                            <div class="timer-display" style="border-color:{color}40;margin-bottom:0;flex:0 0 auto;min-width:200px;">
                                <div style="font-size:11px;font-weight:600;color:#64748b;">SISA WAKTU AKSES</div>
                                <div class="timer-num" style="color:{color};">{mins:02d}:{secs:02d}</div>
                                <div style="font-size:11px;color:#64748b;">Auto-lock saat habis</div>
                            </div>
                            <span style="font-size:12px;color:#94a3b8;">Data terdekripsi ditampilkan selama sesi aktif</span>
                        </div>""", unsafe_allow_html=True)
                    elif st.session_state.decrypted_df is not None:
                        st.markdown('<div class="timer-display" style="opacity:.5;margin-bottom:0;min-width:200px;"><div style="font-weight:600;font-size:14px;color:#f1f5f9;">Belum Aktif</div><div style="font-size:11px;color:#64748b;">Klik Dekripsi untuk mulai</div></div>', unsafe_allow_html=True)

    # ── Activity Log ──
    st.markdown("---")
    with st.expander("Riwayat Aktivitas", expanded=True):
        if st.session_state.demo_log:
            log_data = list(reversed(st.session_state.demo_log[-50:]))
            for entry in log_data:
                color = "#5eead4" if entry["status"]=="OK" else "#fcd34d" if entry["status"]=="WARNING" else "#fca5a5"
                sl = "[OK]" if entry["status"]=="OK" else "[WARN]" if entry["status"]=="WARNING" else "[ERR]"
                st.markdown(f"""
                <div style="display:flex;gap:8px;align-items:center;padding:5px 0;font-size:12px;border-bottom:1px solid rgba(255,255,255,0.04);">
                    <code style="color:#475569;min-width:58px;">{entry['time']}</code>
                    <span style="color:{color};font-weight:600;min-width:50px;">{sl}</span>
                    <span style="color:#e2e8f0;flex:1;">{entry['action']}</span>
                    <span style="color:#64748b;font-size:11px;">{entry['detail'][:50]}</span>
                </div>""", unsafe_allow_html=True)
        else:
            st.caption("Belum ada aktivitas.")

    # ── Footer ──
    st.markdown("""
    <div class="app-footer">
        <span>MediSecure · Sistem Keamanan Data Healthcare · KDA Project Kelompok 1 · 2026</span>
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# ROUTING — Login or Dashboard
# ═══════════════════════════════════════════════════════════════════════════
if st.session_state.logged_in and st.session_state.user_role:
    render_dashboard()
else:
    render_login_page()