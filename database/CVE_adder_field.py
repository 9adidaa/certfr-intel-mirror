import json
import re
from pathlib import Path


# Where your mirror lives
ROOT = Path("certfr_dump")

# Output file
OUTPUT_FILE = Path("certfr_unique_cves.json")

# CVE regex
CVE_REGEX = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


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

    OUTPUT_FILE.write_text(
        json.dumps(sorted_cves, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("\n========== DONE ==========")
    print("files scanned :", total_files)
    print("unique CVEs   :", len(sorted_cves))
    print("output file   :", OUTPUT_FILE.resolve())


if __name__ == "__main__":
    main()
