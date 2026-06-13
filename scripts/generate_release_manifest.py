#!/usr/bin/env python3
"""Generate a release checksum manifest for ISEC build artifacts.

Walks a directory of release artifacts and emits:
  * SHA256SUMS            -- coreutils-compatible ``<sha256>  <relpath>`` lines
                             (verify with ``sha256sum -c SHA256SUMS``).
  * release-manifest.json -- structured manifest with size + SHA-256/SHA-512
                             per file.

Standard library only. Deterministic output (artifacts sorted by path).

Usage:
  python scripts/generate_release_manifest.py dist/
  python scripts/generate_release_manifest.py dist/ --app-version 2.0.0
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import os
import json
import sys
from pathlib import Path

_CHUNK = 1024 * 1024


def _hash_file(path):
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            sha256.update(chunk)
            sha512.update(chunk)
    return sha256.hexdigest(), sha512.hexdigest()


def _iso_timestamp():
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            stamp = _dt.datetime.fromtimestamp(int(epoch), tz=_dt.timezone.utc)
            return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OverflowError):
            pass
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect(dist_dir, skip_names):
    dist = Path(dist_dir)
    files = []
    for path in sorted(dist.rglob("*"), key=lambda p: p.as_posix()):
        if not path.is_file():
            continue
        rel = path.relative_to(dist).as_posix()
        if rel in skip_names:
            continue
        sha256, sha512 = _hash_file(path)
        files.append(
            {
                "path": rel,
                "bytes": path.stat().st_size,
                "sha256": sha256,
                "sha512": sha512,
            }
        )
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate a release checksum manifest."
    )
    parser.add_argument("dist_dir", help="Directory containing release artifacts.")
    parser.add_argument("--app-version", default="2.0.0")
    parser.add_argument("--sums-name", default="SHA256SUMS")
    parser.add_argument("--manifest-name", default="release-manifest.json")
    args = parser.parse_args(argv)

    dist = Path(args.dist_dir)
    if not dist.is_dir():
        print(f"error: not a directory: {dist}", file=sys.stderr)
        return 2

    skip_names = {args.sums_name, args.manifest_name}
    files = collect(dist, skip_names)
    if not files:
        print(f"error: no artifacts found in {dist}", file=sys.stderr)
        return 1

    sums_path = dist / args.sums_name
    sums_path.write_text(
        "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in files),
        encoding="utf-8",
    )

    manifest = {
        "product": "ISEC",
        "version": args.app_version,
        "generated": _iso_timestamp(),
        "algorithms": ["sha256", "sha512"],
        "artifact_count": len(files),
        "artifacts": files,
    }
    manifest_path = dist / args.manifest_name
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {sums_path} and {manifest_path} ({len(files)} artifacts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
