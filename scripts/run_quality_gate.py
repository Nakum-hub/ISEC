"""
Run test and coverage quality gates for ISEC release readiness.
"""
import os
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UI_DIR = PROJECT_ROOT / "ui"


def run(command, cwd=None):
    print(f"> {' '.join(command)}")
    result = subprocess.run(command, cwd=cwd)
    return result.returncode


def main():
    rc = run([sys.executable, "-m", "pip_audit", "-r", "requirements.txt"], cwd=str(PROJECT_ROOT))
    if rc != 0:
        return rc

    if not UI_DIR.exists():
        print("ui directory not found; cannot execute npm audit.")
        return 1

    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    rc = run([npm_cmd, "audit", "--audit-level=moderate"], cwd=str(UI_DIR))
    if rc != 0:
        return rc

    rc = run([sys.executable, "-m", "pytest"])
    if rc != 0:
        return rc

    return run([sys.executable, "scripts/enforce_coverage.py"])


if __name__ == "__main__":
    raise SystemExit(main())
