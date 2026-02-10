import subprocess
import sys


STEPS = [
    ("Mirror CERT-FR", "python database/scraper.py"),
    ("Build CVE list", "python database/CVE_counter.py"),
    ("Build first-seen intel", "python database/build_first_seen.py"),
]


def run():
    for name, cmd in STEPS:
        print(f"\n===== {name} =====")
        r = subprocess.run(cmd, shell=True)
        if r.returncode != 0:
            print(f"Step failed: {name}")
            return r.returncode

    print("\nPipeline complete.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
