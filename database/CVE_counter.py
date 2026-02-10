#!/usr/bin/env python3

import json
import re
import hashlib
from pathlib import Path


# ==========================================================
# CONFIG
# ==========================================================

ROOT = Path("certfr_dump")
OUTPUT_FILE = Path("certfr_unique_cves.json")

CVE_REGEX = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


# ==========================================================
# HELPERS
# ==========================================================

def stable_hash(data) -> str:
    raw = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def load_existing():
    if not OUTPUT_FILE.exists():
        return []
    try:
        return json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


# ==========================================================
# MAIN
# ==========================================================

def main():
    all_cves = set()
    total_files = 0

    for file in ROOT.rglob("*.json"):
        total_files += 1

        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[!] error reading {file}: {e}")
            continue

        blob = json.dumps(data, ensure_ascii=False)
        found = {c.upper() for c in CVE_REGEX.findall(blob)}
        all_cves.update(found)

    sorted_cves = sorted(all_cves)

    old = load_existing()

    if stable_hash(old) == stable_hash(sorted_cves):
        print("No change in CVE list.")
        print("unique CVEs:", len(sorted_cves))
        return 0

    OUTPUT_FILE.write_text(
        json.dumps(sorted_cves, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    delta = len(sorted_cves) - len(old)

    print("\n========== UPDATED ==========")
    print("files scanned :", total_files)
    print("unique CVEs   :", len(sorted_cves))
    print("new today     :", delta)
    print("output file   :", OUTPUT_FILE.resolve())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
