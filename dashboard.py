"""Create a simple SOC findings dashboard."""

from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]

def main():
    output = ROOT / "reports" / "security_dashboard.png"

    windows = pd.read_csv(ROOT / "data/windows_security_logs.csv")
    web = pd.read_csv(ROOT / "data/web_access_logs.csv")

    auth_failures = int(
        (windows["status"].str.lower() == "failure").sum()
    )
    auth_successes = int(
        (windows["status"].str.lower() == "success").sum()
    )
    suspicious_web = int(
        web["path"].str.contains(
            r"(\.\./|%27|1%3D1|\.env)",
            case=False,
            regex=True,
            na=False
        ).sum()
    )

    labels = ["Auth failures", "Auth successes", "Suspicious web"]
    values = [auth_failures, auth_successes, suspicious_web]

    plt.figure(figsize=(9, 5))
    plt.bar(labels, values)
    plt.title("Synthetic SOC Investigation Summary")
    plt.ylabel("Event count")
    plt.tight_layout()
    plt.savefig(output, dpi=160)
    plt.close()

    print(f"Dashboard saved to: {output}")

if __name__ == "__main__":
    main()
