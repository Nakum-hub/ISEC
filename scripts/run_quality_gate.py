"""
Run test and coverage quality gates for ISEC release readiness.
"""
import subprocess
import sys


def run(command):
    print(f"> {' '.join(command)}")
    result = subprocess.run(command)
    return result.returncode


def main():
    rc = run([sys.executable, "-m", "pytest"])
    if rc != 0:
        return rc

    return run([sys.executable, "scripts/enforce_coverage.py"])


if __name__ == "__main__":
    raise SystemExit(main())
