"""
Generate a signed-release traceability manifest for build artifacts.
"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone


INSTALLER_EXTENSIONS = {".exe", ".msi", ".dmg", ".pkg", ".appimage", ".deb", ".rpm"}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(command, cwd=None):
    proc = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


def get_git_commit(project_root):
    rc, out, _ = run_command(["git", "rev-parse", "HEAD"], cwd=project_root)
    return out if rc == 0 and out else "unknown"


def parse_requirements(requirements_path):
    deps = []
    if not os.path.exists(requirements_path):
        return deps
    with open(requirements_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "==" not in line:
                continue
            name, version = line.split("==", 1)
            deps.append({
                "name": name.strip(),
                "version": version.strip()
            })
    return deps


def parse_node_dependency_meta(ui_dir):
    package_json_path = os.path.join(ui_dir, "package.json")
    lock_path = os.path.join(ui_dir, "package-lock.json")

    package_json = {}
    if os.path.exists(package_json_path):
        with open(package_json_path, "r", encoding="utf-8") as f:
            package_json = json.load(f)

    lock_info = {}
    if os.path.exists(lock_path):
        with open(lock_path, "r", encoding="utf-8") as f:
            lock = json.load(f)
        lock_info = {
            "lockfileVersion": lock.get("lockfileVersion"),
            "name": lock.get("name"),
            "version": lock.get("version"),
        }

    return {
        "version": package_json.get("version"),
        "dependencies": package_json.get("dependencies", {}),
        "devDependencies": package_json.get("devDependencies", {}),
        "lock": lock_info,
    }


def verify_windows_signature(path):
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        f"(Get-AuthenticodeSignature -FilePath '{path}').Status.ToString()",
    ]
    rc, out, err = run_command(command)
    status = out if out else "Unknown"
    if rc != 0:
        return False, "authenticode", "Unknown", err or "Get-AuthenticodeSignature failed."
    return status.lower() == "valid", "authenticode", status, ""


def verify_darwin_signature(path):
    rc, _, err = run_command(["codesign", "--verify", "--deep", "--strict", path])
    if rc == 0:
        return True, "codesign", "valid", ""
    return False, "codesign", "invalid", err or "codesign verification failed."


def verify_signature(path):
    ext = os.path.splitext(path)[1].lower()
    system = platform.system()

    if ext in {".exe", ".msi"} and system == "Windows":
        return verify_windows_signature(path)
    if ext in {".dmg", ".pkg"} and system == "Darwin":
        return verify_darwin_signature(path)
    return False, "unsupported", "unsupported", "No signature verifier for this platform/artifact."


def collect_artifacts(dist_dir, require_signed):
    if not os.path.isdir(dist_dir):
        raise FileNotFoundError(f"Build output directory not found: {dist_dir}")

    artifacts = []
    installer_count = 0
    for name in sorted(os.listdir(dist_dir)):
        full_path = os.path.join(dist_dir, name)
        if not os.path.isfile(full_path):
            continue

        ext = os.path.splitext(name)[1].lower()
        is_installer = ext in INSTALLER_EXTENSIONS
        signature_ok = None
        signature_method = None
        signature_status = None
        signature_error = None

        if is_installer:
            installer_count += 1
            signature_ok, signature_method, signature_status, signature_error = verify_signature(full_path)
            if require_signed and not signature_ok:
                raise RuntimeError(
                    f"Unsigned installer blocked: {name} ({signature_method}: {signature_status}) {signature_error}".strip()
                )

        artifacts.append({
            "file": name,
            "size_bytes": os.path.getsize(full_path),
            "sha256": sha256_file(full_path),
            "is_installer": is_installer,
            "signature": {
                "method": signature_method,
                "status": signature_status,
                "verified": signature_ok,
                "error": signature_error or "",
            },
        })

    if require_signed and installer_count == 0:
        raise RuntimeError("Signed installer validation failed: no installer artifacts found.")

    return artifacts


def parse_args():
    parser = argparse.ArgumentParser(description="Generate release build_manifest.json with signature checks.")
    parser.add_argument("--dist-dir", default=os.path.join("ui", "dist"), help="Directory with built installers/artifacts.")
    parser.add_argument("--output", default="build_manifest.json", help="Output manifest path.")
    parser.add_argument("--project-root", default=".", help="Project root for git metadata.")
    parser.add_argument("--require-signed", action="store_true", help="Fail if an installer is unsigned or unverifiable.")
    return parser.parse_args()


def main():
    args = parse_args()
    project_root = os.path.abspath(args.project_root)
    dist_dir = os.path.abspath(args.dist_dir)
    output_path = os.path.abspath(args.output)

    artifacts = collect_artifacts(dist_dir, require_signed=args.require_signed)
    node_meta = parse_node_dependency_meta(os.path.join(project_root, "ui"))
    manifest = {
        "schema": "ISEC_BUILD_MANIFEST_v1",
        "version": (node_meta.get("version") or "1.0.0"),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "isec_env": os.environ.get("ISEC_ENV", "development"),
        "git_commit_hash": get_git_commit(project_root),
        "python_version": sys.version.split()[0],
        "python_dependencies": parse_requirements(os.path.join(project_root, "requirements.txt")),
        "node_dependencies": node_meta,
        "artifacts": artifacts,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    print(f"Build manifest generated: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
