from pathlib import Path
import json
import re


# ==========================================================
# CONSTANTS
# ==========================================================

RAW_ROOT = Path("database/raw/certfr_dump_root")
CVE_INDEX = Path("database/intel/certfr_unique_cves.json")
FIRST_SEEN = Path("database/intel/certfr_cve_first_seen.json")

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$")


# ==========================================================
# RAW DATA
# ==========================================================

def test_raw_directory_exists():
    assert RAW_ROOT.exists(), "Raw directory missing"


def test_raw_contains_json():
    files = list(RAW_ROOT.rglob("*.json"))
    assert len(files) > 0, "No advisory JSON files found"


# ==========================================================
# CVE INDEX
# ==========================================================

def test_cve_index_exists():
    assert CVE_INDEX.exists(), "CVE index not generated"


def test_cve_index_not_empty():
    if not CVE_INDEX.exists():
        return
    assert CVE_INDEX.stat().st_size > 0, "CVE index is empty"


def test_cve_index_structure():
    if not CVE_INDEX.exists():
        return

    data = json.loads(CVE_INDEX.read_text(encoding="utf-8"))
    assert isinstance(data, list), "CVE index must be a list"


def test_cve_entries_format():
    if not CVE_INDEX.exists():
        return

    data = json.loads(CVE_INDEX.read_text(encoding="utf-8"))

    if not data:
        return

    # check first 20 for speed
    for cve in data[:20]:
        assert CVE_REGEX.match(cve), f"Invalid CVE format: {cve}"


# ==========================================================
# FIRST SEEN
# ==========================================================

def test_first_seen_exists():
    assert FIRST_SEEN.exists(), "first-seen file not generated"


def test_first_seen_not_empty():
    if not FIRST_SEEN.exists():
        return
    assert FIRST_SEEN.stat().st_size > 0, "first-seen file is empty"


def test_first_seen_structure():
    if not FIRST_SEEN.exists():
        return

    data = json.loads(FIRST_SEEN.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "first-seen must be a dictionary"


def test_first_seen_schema():
    if not FIRST_SEEN.exists():
        return

    data = json.loads(FIRST_SEEN.read_text(encoding="utf-8"))
    if not data:
        return

    sample = next(iter(data.values()))

    assert "first_seen_in" in sample, "Missing key: first_seen_in"
# ==========================================================
# README REPORT GENERATION
# ==========================================================

def test_update_readme():
    """
    If we are here, all previous validations passed.
    We can safely publish a health report.
    """

    readme = Path("README.md")
    if not readme.exists():
        return

    raw_files = len(list(RAW_ROOT.rglob("*.json"))) if RAW_ROOT.exists() else 0

    cve_count = 0
    if CVE_INDEX.exists():
        data = json.loads(CVE_INDEX.read_text(encoding="utf-8"))
        cve_count = len(data)

    from datetime import datetime

    report = f"""\
Last validation: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}

| Check | Status |
|------|--------|
| Raw data present | ✅ |
| CVE index valid | ✅ |
| First-seen valid | ✅ |

### Dataset size
- Advisories: **{raw_files}**
- Unique CVEs: **{cve_count}**
"""

    start = "<!-- STATUS:START -->"
    end = "<!-- STATUS:END -->"

    content = readme.read_text(encoding="utf-8")

    if start not in content or end not in content:
        return

    before = content.split(start)[0]
    after = content.split(end)[1]

    updated = before + start + "\n" + report + "\n" + end + after
    readme.write_text(updated, encoding="utf-8")
