"""Detect repeated authentication failures followed by a success."""

from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

def detect(df, threshold=5):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    failures = df[df["status"].str.lower().eq("failure")]
    alerts = []

    for (user, ip), group in failures.groupby(["user", "source_ip"]):
        group = group.sort_values("timestamp")

        if len(group) >= threshold:
            last_failure = group["timestamp"].max()

            later_success = df[
                (df["user"] == user)
                & (df["source_ip"] == ip)
                & (df["status"].str.lower().eq("success"))
                & (df["timestamp"] > last_failure)
            ]

            alerts.append({
                "user": user,
                "source_ip": ip,
                "failed_attempts": len(group),
                "success_after_failures": not later_success.empty,
                "severity": "HIGH" if not later_success.empty else "MEDIUM"
            })

    return pd.DataFrame(alerts)

def main():
    df = pd.read_csv(ROOT / "data/windows_security_logs.csv")
    alerts = detect(df)

    print("=== AUTHENTICATION DETECTION ===")
    if alerts.empty:
        print("No alerts.")
    else:
        print(alerts.to_string(index=False))

if __name__ == "__main__":
    main()
