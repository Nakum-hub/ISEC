#!/usr/bin/env python3
"""
ISEC License Generator — For sellers to generate per-customer licenses.

Usage:
    python generate_license.py --customer "Acme Corp" --plan Enterprise
    python generate_license.py --customer "ACME" --plan Professional --days 365
    python generate_license.py --fingerprint "abc123..." --customer "ACME"

The buyer provides their machine fingerprint (shown in ISEC setup wizard).
You run this script and send them back the license.json file.
"""

import argparse
import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone, timedelta

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print('ERROR: Run: pip install cryptography')
    sys.exit(1)

ROOT = os.path.dirname(os.path.abspath(__file__))

PLANS = {
    'Starter':      ['view', 'collect'],
    'Professional': ['view', 'collect', 'export', 'report'],
    'Enterprise':   ['view', 'collect', 'export', 'report', 'admin',
                     'advanced_analytics', 'threat_intel', 'assign_role',
                     'set_retention', 'modify'],
}


def get_local_fingerprint():
    """Get THIS machine's fingerprint — for generating dev/test licenses."""
    info = {
        'hostname':   platform.node(),
        'system':     platform.system(),
        'release':    platform.release(),
        'machine':    platform.machine(),
        'processor':  platform.processor(),
    }
    return hashlib.sha256(
        json.dumps(info, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()


def load_private_key(key_path):
    if not os.path.exists(key_path):
        print(f'ERROR: Private key not found at: {key_path}')
        print('       Run the initial setup to generate keys/')
        sys.exit(1)
    with open(key_path) as f:
        pem = f.read()
    return serialization.load_pem_private_key(pem.encode(), password=None)


def generate_license(customer, plan, fingerprint, days, private_key_path, output_path):
    priv = load_private_key(private_key_path)

    license_id = f'ISEC-{plan[:3].upper()}-{datetime.now().strftime("%Y%m%d")}-{os.urandom(4).hex().upper()}'

    payload = {
        'license_id':         license_id,
        'customer':           customer,
        'plan':               plan,
        'features':           PLANS.get(plan, PLANS['Enterprise']),
        'issued_at':          datetime.now(timezone.utc).isoformat(),
        'expires_at':         (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(),
        'system_fingerprint': fingerprint,
    }

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature     = priv.sign(payload_bytes).hex()

    license_data = {'payload': payload, 'signature': signature}

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(license_data, f, indent=2)

    return license_id, output_path


def main():
    parser = argparse.ArgumentParser(description='ISEC License Generator')
    parser.add_argument('--customer',    required=True, help='Customer / company name')
    parser.add_argument('--plan',        default='Enterprise',
                        choices=['Starter', 'Professional', 'Enterprise'],
                        help='License plan (default: Enterprise)')
    parser.add_argument('--days',        type=int, default=365, help='Validity in days (default: 365)')
    parser.add_argument('--fingerprint', default=None,
                        help='Buyer machine fingerprint (shown in ISEC setup wizard). '
                             'Omit to use THIS machine fingerprint (for testing).')
    parser.add_argument('--private-key', default=os.path.join(ROOT, 'keys', 'license_private_key.pem'),
                        help='Path to Ed25519 private key (default: keys/license_private_key.pem)')
    parser.add_argument('--output',     default=os.path.join(ROOT, 'license.json'),
                        help='Output path for license file (default: license.json)')
    args = parser.parse_args()

    fingerprint = args.fingerprint or get_local_fingerprint()
    print(f'\n=== ISEC License Generator ===')
    print(f'Customer    : {args.customer}')
    print(f'Plan        : {args.plan}')
    print(f'Valid for   : {args.days} days')
    print(f'Fingerprint : {fingerprint[:20]}...')
    print(f'Features    : {", ".join(PLANS.get(args.plan, []))}')

    license_id, output_path = generate_license(
        customer=args.customer,
        plan=args.plan,
        fingerprint=fingerprint,
        days=args.days,
        private_key_path=args.private_key,
        output_path=args.output,
    )

    print(f'\n✅ License generated!')
    print(f'   ID     : {license_id}')
    print(f'   File   : {output_path}')
    print(f'\n📧 Send the buyer: {output_path}')
    print(f'   They paste it in the ISEC Setup Wizard → Step 2 "License Activation"')


if __name__ == '__main__':
    main()
