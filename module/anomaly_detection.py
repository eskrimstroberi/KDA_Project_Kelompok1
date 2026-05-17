from pathlib import Path
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parents[1]

LOG_FILE = ROOT_DIR / "logs" / "security.log"

ALERT_DIR = ROOT_DIR / "alerts"
ALERT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


def detect_security_anomalies():

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

    tampering_count = 0
    denied_count = 0
    error_count = 0

    for line in logs:

        lower_line = line.lower()

        if (
            "tampering detected"
            in lower_line
        ):
            tampering_count += 1

        if (
            "access denied"
            in lower_line
        ):
            denied_count += 1

        if (
            "error"
            in lower_line
        ):
            error_count += 1

    anomalies = []

    # Threshold rules
    if tampering_count >= 10:

        anomalies.append({
            "anomaly":
            "high_tampering",

            "severity":
            "HIGH",

            "message":
            "Too many tampering events detected."
        })

    if denied_count >= 3:

        anomalies.append({
            "anomaly":
            "repeated_denied_access",

            "severity":
            "MEDIUM",

            "message":
            "Repeated unauthorized access attempts."
        })

    if error_count >= 5:

        anomalies.append({
            "anomaly":
            "high_error_rate",

            "severity":
            "HIGH",

            "message":
            "Too many system errors detected."
        })

    anomaly_df = pd.DataFrame(
        anomalies
    )

    output_file = (
        ALERT_DIR
        / "security_alerts.csv"
    )

    anomaly_df.to_csv(
        output_file,
        index=False
    )

    return anomalies