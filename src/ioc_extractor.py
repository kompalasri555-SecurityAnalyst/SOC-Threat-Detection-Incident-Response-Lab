"""Extract simple IOCs from synthetic security logs."""

from pathlib import Path
import re
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

def main():
    files = [
        ROOT / "data/windows_security_logs.csv",
        ROOT / "data/linux_auth_logs.csv",
        ROOT / "data/web_access_logs.csv",
    ]

    text = "\n".join(
        pd.read_csv(file).astype(str).to_csv(index=False)
        for file in files
    )

    ips = sorted(set(IP_RE.findall(text)))
    domains = sorted(set(DOMAIN_RE.findall(text)))
    hashes = sorted(set(HASH_RE.findall(text)))

    print("=== IOC EXTRACTION ===")

    print("\nIPs:")
    for item in ips:
        print(f"  - {item}")

    print("\nDomains:")
    for item in domains:
        print(f"  - {item}")

    print("\nHashes:")
    for item in hashes:
        print(f"  - {item}")

if __name__ == "__main__":
    main()
