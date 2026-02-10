#!/usr/bin/env python3

import os
import json
import hashlib
import datetime
import requests
import re
from pathlib import Path


# ==========================================================
# CONFIG
# ==========================================================

BASE_URL = "https://www.cert.ssi.gouv.fr"
ENDPOINT = "avis"
DOCTYPE = "AVI"

TIMEOUT = 20
HEADERS = {
    "User-Agent": "CERTFR-Mirror/1.0 (+mokda project)",
    "Accept": "application/json",
}

MAX_CONSECUTIVE_MISSES = 50

# automation friendly
START_YEAR = int(os.getenv("START_YEAR", "2000"))

BASE_DIR = Path("database/raw/certfr_dump_root")
LOG_DIR = Path("logs")
TODAY = datetime.date.today().isoformat()
LOG_FILE = LOG_DIR / f"{TODAY}.txt"


# ==========================================================
# LOGGER
# ==========================================================

def log(msg: str):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(msg + "\n")


def info(msg: str):
    print(msg)
    log(msg)


# ==========================================================
# CVE REGEX (read-only usage)
# ==========================================================

CVE_REGEX = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


def count_cves(obj: dict) -> int:
    blob = json.dumps(obj, ensure_ascii=False)
    return len(set(c.upper() for c in CVE_REGEX.findall(blob)))


# ==========================================================
# ID FORMAT
# ==========================================================

def get_prefix_and_digits(year: int):
    if year <= 2013:
        return "CERTA", 3
    if year <= 2022:
        return "CERTFR", 3
    return "CERTFR", 4


# ==========================================================
# HASH / DIFF
# ==========================================================

def stable_hash(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def should_update(path: Path, new_obj: dict) -> bool:
    if not path.exists():
        return True

    try:
        old_obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return True

    return stable_hash(old_obj) != stable_hash(new_obj)


# ==========================================================
# IO
# ==========================================================

def save_json(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


# ==========================================================
# NETWORK
# ==========================================================

def fetch_json(session: requests.Session, url: str):
    try:
        r = session.get(url, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException:
        return None, "network_error"

    if r.status_code == 404:
        return None, 404

    if r.status_code != 200:
        return None, r.status_code

    if "application/json" not in r.headers.get("Content-Type", "").lower():
        return None, "not_json"

    try:
        return r.json(), 200
    except Exception:
        return None, "json_decode_error"


# ==========================================================
# DOWNLOAD PER YEAR
# ==========================================================

def download_year(base_dir: Path, year: int, session: requests.Session):
    prefix, digits = get_prefix_and_digits(year)

    info(f"\n===== YEAR {year} ({prefix}, {digits} digits) =====")

    year_dir = base_dir / str(year)
    year_dir.mkdir(parents=True, exist_ok=True)

    consecutive_misses = 0
    i = 1

    downloaded = 0
    updated = 0
    skipped = 0
    errors = 0

    while consecutive_misses < MAX_CONSECUTIVE_MISSES:
        ref = f"{prefix}-{year}-{DOCTYPE}-{i:0{digits}d}"
        url = f"{BASE_URL}/{ENDPOINT}/{ref}/json/"
        out_file = year_dir / f"{ref}.json"

        obj, status = fetch_json(session, url)

        if status in (404, "not_json"):
            consecutive_misses += 1
            i += 1
            continue

        if status != 200:
            errors += 1
            info(f"[!] {ref} -> ERROR {status}")
            consecutive_misses = 0
            i += 1
            continue

        consecutive_misses = 0

        cve_count = count_cves(obj)

        if should_update(out_file, obj):
            if out_file.exists():
                updated += 1
                msg = f"[U] {ref} | {cve_count} CVE"
            else:
                downloaded += 1
                msg = f"[+] {ref} | {cve_count} CVE"

            save_json(out_file, obj)
        else:
            skipped += 1
            msg = f"[=] {ref} (no change) | {cve_count} CVE"

        info(msg)
        i += 1

    summary = (
        f"Done {year}: new={downloaded}, "
        f"updated={updated}, skipped={skipped}, errors={errors}"
    )

    info(summary)

    return downloaded, updated


# ==========================================================
# MAIN
# ==========================================================

def main():
    current_year = datetime.datetime.now().year

    if START_YEAR < 2000 or START_YEAR > current_year:
        info(f"Start year must be between 2000 and {current_year}")
        return 1

    info(f"Dumping CERT-FR AVI JSON from {START_YEAR} to {current_year}")
    info(f"Output dir: {BASE_DIR.resolve()}")

    total_new = 0
    total_updated = 0

    with requests.Session() as session:
        for year in range(START_YEAR, current_year + 1):
            d, u = download_year(BASE_DIR, year, session)
            total_new += d
            total_updated += u

    info(
        f"\nGLOBAL SUMMARY: new={total_new}, updated={total_updated}"
    )

    # useful for CI: return success but indicate change via stdout
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
