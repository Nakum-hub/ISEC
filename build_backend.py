#!/usr/bin/env python3
"""
ISEC Backend Builder — Creates a standalone Python binary using PyInstaller
Run this before electron-builder to bundle the Python backend into the app.

Usage:
    python build_backend.py
    python build_backend.py --platform windows
    python build_backend.py --platform mac
    python build_backend.py --platform linux
"""

import subprocess
import sys
import shutil
import os
import argparse

ROOT = os.path.dirname(os.path.abspath(__file__))

def run(cmd, **kwargs):
    print(f'  Running: {" ".join(cmd)}')
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        print(f'  ERROR: Command failed with code {result.returncode}')
        sys.exit(1)
    return result

def build_backend(platform_name):
    print(f'\n[1/4] Installing PyInstaller...')
    run([sys.executable, '-m', 'pip', 'install', 'pyinstaller', '--quiet'])

    print(f'\n[2/4] Installing ISEC requirements...')
    req_file = os.path.join(ROOT, 'requirements.txt')
    run([sys.executable, '-m', 'pip', 'install', '-r', req_file, '--quiet'])

    print(f'\n[3/4] Building standalone backend binary...')
    dist_dir  = os.path.join(ROOT, 'ui', 'backend_dist')
    work_dir  = os.path.join(ROOT, '_pyinstaller_work')
    spec_dir  = os.path.join(ROOT, '_pyinstaller_spec')
    main_py   = os.path.join(ROOT, 'main.py')

    # Collect all src/ modules for PyInstaller
    hidden_imports = [
        'cryptography', 'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        'cryptography.hazmat.backends',
        'reportlab', 'reportlab.pdfgen', 'reportlab.lib',
        'sqlite3', 'hmac', 'hashlib', 'json', 'zipfile',
        'src.collectors.system_logs',
        'src.collectors.browser_history',
        'src.collectors.network_connections',
        'src.collectors.file_metadata',
        'src.core.collector',
        'src.storage.database',
        'src.reporting.report_generator',
        'src.utils.license_manager',
        'src.utils.role_manager',
        'src.utils.retention_engine',
        'src.utils.consent_manager',
        'src.utils.digital_signer',
        'src.utils.paths',
        'src.utils.helpers',
        'src.utils.logging_setup',
        'src.utils.runtime_config',
        'src.utils.startup_validator',
    ]

    hidden_args = []
    for h in hidden_imports:
        hidden_args += ['--hidden-import', h]

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--onefile',
        '--name', 'isec-backend',
        '--distpath', dist_dir,
        '--workpath', work_dir,
        '--specpath', spec_dir,
        '--noconfirm',
        '--log-level', 'WARN',
    ] + hidden_args + [main_py]

    run(cmd, cwd=ROOT)

    # Verify output
    suffix = '.exe' if platform_name == 'windows' else ''
    binary = os.path.join(dist_dir, f'isec-backend{suffix}')
    if os.path.exists(binary):
        size = os.path.getsize(binary) / 1024 / 1024
        print(f'\n  ✅ Binary created: {binary} ({size:.1f} MB)')
    else:
        print(f'\n  ❌ Binary not found at: {binary}')
        sys.exit(1)

    # Cleanup
    shutil.rmtree(work_dir,  ignore_errors=True)
    shutil.rmtree(spec_dir,  ignore_errors=True)

    print(f'\n[4/4] Copying keys to backend_dist...')
    keys_dst = os.path.join(dist_dir, 'keys')
    os.makedirs(keys_dst, exist_ok=True)
    pub_key = os.path.join(ROOT, 'keys', 'license_public_key.pem')
    if os.path.exists(pub_key):
        shutil.copy2(pub_key, keys_dst)
        print(f'  ✅ License public key copied')

    print(f'\n✅ Backend build complete — binary at: {binary}')
    print(f'   Now run: cd ui && npm install && npx electron-builder\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build ISEC backend binary')
    parser.add_argument('--platform', choices=['windows', 'mac', 'linux'],
                        default='linux', help='Target platform')
    args = parser.parse_args()
    build_backend(args.platform)
