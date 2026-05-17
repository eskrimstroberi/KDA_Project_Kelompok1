from pathlib import Path
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parents[1]

LOG_FILE = ROOT_DIR / "logs" / "security.log"

AUDIT_DIR = ROOT_DIR / "audit"
AUDIT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


def audit_security_logs():

    if not LOG_FILE.exists():
        raise FileNotFoundError(
            "security.log tidak ditemukan."
        )

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        logs = file.readlines()

    encryption_success = 0
    decryption_success = 0
    tampering_detected = 0
    access_denied = 0
    total_errors = 0

    for line in logs:

        lower_line = line.lower()

        # AES encryption
        if (
            "aes encryption success"
            in lower_line
        ):
            encryption_success += 1

        # decrypt success
        if (
            "decryption success"
            in lower_line
        ):
            decryption_success += 1

        # tampering
        if (
            "tampering detected"
            in lower_line
        ):
            tampering_detected += 1

        # access denied
        if (
            "access denied"
            in lower_line
        ):
            access_denied += 1

        # errors
        if "error" in lower_line:
            total_errors += 1

    audit_result = [
        {
            "event":
            "encryption_success",
            "total":
            encryption_success
        },
        {
            "event":
            "decryption_success",
            "total":
            decryption_success
        },
        {
            "event":
            "tampering_detected",
            "total":
            tampering_detected
        },
        {
            "event":
            "access_denied",
            "total":
            access_denied
        },
        {
            "event":
            "errors",
            "total":
            total_errors
        }
    ]

    audit_df = pd.DataFrame(
        audit_result
    )

    output_file = (
        AUDIT_DIR
        / "security_audit.csv"
    )

    audit_df.to_csv(
        output_file,
        index=False
    )

    return audit_result