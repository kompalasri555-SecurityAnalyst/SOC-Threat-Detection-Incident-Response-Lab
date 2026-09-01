"""Basic SOC log analysis for the synthetic lab."""

from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

def main():
    windows = pd.read_csv(ROOT / "data/windows_security_logs.csv")
    linux = pd.read_csv(ROOT / "data/linux_auth_logs.csv")
    web = pd.read_csv(ROOT / "data/web_access_logs.csv")

    print("=== SOC LOG SUMMARY ===")
    print(f"Windows events: {len(windows)}")
    print(f"Linux events:   {len(linux)}")
    print(f"Web events:     {len(web)}")

    failures = windows[windows["status"].str.lower().eq("failure")]
    print("\nWindows authentication failures by source:")
    print(failures.groupby("source_ip").size().sort_values(ascending=False).to_string())

    suspicious_web = web[
        web["path"].str.contains(
            r"(\.\./|%27|1%3D1|\.env)",
            case=False,
            regex=True,
            na=False
        )
    ]
    print("\nSuspicious web requests:")
    if suspicious_web.empty:
        print("None detected.")
    else:
        print(suspicious_web[["timestamp", "source_ip", "path", "status"]].to_string(index=False))

if __name__ == "__main__":
    main()
