#!/usr/bin/env python3

import json
import re
from pathlib import Path


ROOT = Path("certfr_dump")
OUTPUT = Path("certfr_cve_first_seen.json")

CVE_REGEX = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


def extract_date(obj):
    """
    Try common CERT-FR date fields.
    """
    for k in ["date", "publication_date", "released", "timestamp"]:
        if k in obj:
            return str(obj[k])
    return None


def main():
    first_seen = {}

    files = sorted(ROOT.rglob("*.json"))
    total = len(files)

    if total == 0:
        print("No files found.")
        return

    for idx, file in enumerate(files, start=1):
        advisory_id = file.stem

        percent = int((idx / total) * 100)
        print(f"[{percent:3d}%] {advisory_id}")

        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue

        blob = json.dumps(data, ensure_ascii=False)
        cves = {c.upper() for c in CVE_REGEX.findall(blob)}

        date = extract_date(data)

        for cve in cves:
            if cve not in first_seen:
                first_seen[cve] = {
                    "first_seen_in": advisory_id,
                    "first_seen_date": date,
                }

    OUTPUT.write_text(
        json.dumps(first_seen, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("\n========== DONE ==========")
    print("files scanned:", total)
    print("CVE tracked :", len(first_seen))
    print("output      :", OUTPUT.resolve())


if __name__ == "__main__":
    main()
