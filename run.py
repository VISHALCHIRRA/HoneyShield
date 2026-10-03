import shutil
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

COWRIE_LOG = Path("/home/cowrie/var/log/cowrie/cowrie.json")
HONEYSHIELD_LOG = BASE_DIR / "logs" / "cowrie.json"


def run_command(command):
    print(f"\n>>> {' '.join(command)}")
    result = subprocess.run(command, cwd=BASE_DIR)

    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)


def main():
    print("=" * 60)
    print("HoneyShield Processing Pipeline")
    print("=" * 60)

    if not COWRIE_LOG.exists():
        print("Cowrie log not found:")
        print(COWRIE_LOG)
        sys.exit(1)

    HONEYSHIELD_LOG.parent.mkdir(parents=True, exist_ok=True)

    print("\n[1/4] Copying live Cowrie log...")
    shutil.copy2(COWRIE_LOG, HONEYSHIELD_LOG)
    print(f"Copied log to {HONEYSHIELD_LOG}")

    print("\n[2/4] Parsing Cowrie logs...")
    run_command([
        sys.executable,
        "parser/log_parser.py"
    ])

    print("\n[3/4] Running detection, MITRE and Threat Intelligence...")
    run_command([
        sys.executable,
        "detection/detector.py"
    ])

    print("\n[4/4] Updating SQLite database...")
    run_command([
        sys.executable,
        "-c",
        "from backend.models import insert_attacks, insert_alerts; "
        "insert_attacks(); insert_alerts()"
    ])

    print("\n" + "=" * 60)
    print("HoneyShield pipeline completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()
