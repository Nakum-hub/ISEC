"""
Release build workflow with production enforcement and signature verification.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys


FORBIDDEN_ENV_VARS = (
    "ISEC_ALLOW_UNLICENSED",
    "ISEC_DEV_ALLOW_UNLICENSED",
    "ISEC_ROLE_AUTH_BYPASS",
)


def run(command, cwd=None, env=None):
    resolved = list(command)
    executable = resolved[0]
    if executable.lower() in {"npm", "npx"}:
        cmd_name = executable.lower()
        preferred = f"{cmd_name}.cmd"
        cmd_exec = shutil.which(preferred) or shutil.which(cmd_name)
        if not cmd_exec:
            raise RuntimeError(f"{cmd_name} executable not found (expected {preferred} on Windows).")
        resolved[0] = cmd_exec

    print(f"> {' '.join(resolved)}")
    result = subprocess.run(resolved, cwd=cwd, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(resolved)}")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_environment():
    active = [name for name in FORBIDDEN_ENV_VARS if os.environ.get(name)]
    if active:
        raise RuntimeError(
            "Release build blocked: insecure environment flags present: "
            + ", ".join(active)
        )


def write_checksum_index(dist_dir, manifest_path):
    checksums_path = os.path.join(dist_dir, "SHA256SUMS.txt")
    manifest = json.loads(open(manifest_path, "r", encoding="utf-8").read())
    lines = []
    for artifact in manifest.get("artifacts", []):
        name = artifact.get("file")
        checksum = artifact.get("sha256")
        if name == "SHA256SUMS.txt":
            continue
        if name and checksum:
            lines.append(f"{checksum}  {name}")
    manifest_hash = sha256_file(manifest_path)
    lines.append(f"{manifest_hash}  {os.path.basename(manifest_path)}")
    with open(checksums_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Checksum index generated: {checksums_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Run production release build and verification.")
    parser.add_argument("--ui-dir", default="ui", help="Electron UI directory.")
    parser.add_argument("--dist-dir", default=os.path.join("ui", "dist"), help="Build output directory.")
    parser.add_argument("--manifest", default="build_manifest.json", help="Output build manifest path.")
    parser.add_argument("--skip-npm-ci", action="store_true", help="Skip npm ci step.")
    return parser.parse_args()


def main():
    args = parse_args()
    validate_environment()

    env = os.environ.copy()
    env["ISEC_ENV"] = "production"
    for key in FORBIDDEN_ENV_VARS:
        env.pop(key, None)

    if not args.skip_npm_ci:
        run(["npm", "ci"], cwd=args.ui_dir, env=env)
    run(["npx", "electron-builder"], cwd=args.ui_dir, env=env)

    run(
        [
            sys.executable,
            "scripts/create_build_manifest.py",
            "--dist-dir",
            args.dist_dir,
            "--output",
            args.manifest,
            "--project-root",
            ".",
            "--require-signed",
        ],
        env=env,
    )

    write_checksum_index(args.dist_dir, args.manifest)
    print("Release build completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
