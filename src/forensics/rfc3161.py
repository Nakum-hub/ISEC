"""
Minimal, dependency-light RFC 3161 trusted-timestamping client for ISEC.

A transparency-log checkpoint records *what* the evidence state was and links
it into an append-only ledger, but the ledger's own timestamps are taken from
the local clock. An RFC 3161 token from an independent Time-Stamp Authority
(TSA) adds trusted, third-party proof of *when* a checkpoint existed -- making
rollback/backdating arguments much harder to sustain.

Reputable public TSAs provide this service for free (no account required),
for example:

    * http://timestamp.digicert.com   (default)
    * http://timestamp.sectigo.com
    * https://freetsa.org/tsr

This module hand-builds the small, well-defined TimeStampReq structure in DER
using only the standard library, and posts it with ``requests`` (already a
project dependency). The TSA's reply (a DER TimeStampResp containing the
signed token) is returned base64-encoded and stored opaquely; it can be
verified independently later with ``openssl ts -verify`` or any RFC 3161
library, so ISEC does not need to parse ASN.1 responses itself.

Every network entry point is exception-safe and returns ``None`` on failure,
so timestamping is always optional and never disrupts collection or CI.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from typing import Callable, Optional

# Default free, public Time-Stamp Authority. Free to use; no account required.
# Override via the ISEC_TSA_URL environment variable or make_timestamper(url=...).
DEFAULT_TSA_URL = "http://timestamp.digicert.com"

# DER content octets of the SHA-256 OID (2.16.840.1.101.3.4.2.1).
_SHA256_OID_CONTENT = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


# --- minimal DER encoder (sufficient for a TimeStampReq) ----------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("only non-negative integers are supported")
    if value == 0:
        body = b"\x00"
    else:
        out = bytearray()
        n = value
        while n:
            out.insert(0, n & 0xFF)
            n >>= 8
        if out[0] & 0x80:
            out.insert(0, 0x00)
        body = bytes(out)
    return _tlv(0x02, body)


def _der_octet_string(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _der_boolean(value: bool) -> bytes:
    return _tlv(0x01, b"\xff" if value else b"\x00")


def _der_null() -> bytes:
    return _tlv(0x05, b"")


def _der_oid(content: bytes) -> bytes:
    return _tlv(0x06, content)


def _der_sequence(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def build_timestamp_request(
    digest: bytes,
    nonce: Optional[int] = None,
    cert_req: bool = True,
) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq for a SHA-256 ``digest``.

    ``digest`` must be the 32-byte SHA-256 hash of the data being timestamped.
    A random ``nonce`` is generated when none is supplied (replay protection).
    ``cert_req=True`` asks the TSA to include its certificate in the reply so
    the token can be verified offline later.
    """
    if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
        raise ValueError("digest must be a 32-byte SHA-256 hash")
    if nonce is None:
        nonce = secrets.randbits(64)

    algorithm_identifier = _der_sequence(_der_oid(_SHA256_OID_CONTENT), _der_null())
    message_imprint = _der_sequence(
        algorithm_identifier, _der_octet_string(bytes(digest))
    )

    return _der_sequence(
        _der_integer(1),          # version v1
        message_imprint,          # messageImprint
        _der_integer(nonce),      # nonce (optional, recommended)
        _der_boolean(cert_req),   # certReq
    )


def _http_post(url: str, data: bytes, timeout: int) -> bytes:
    """POST a timestamp query and return the raw TimeStampResp bytes."""
    import requests  # imported lazily so the module loads without the dep present

    response = requests.post(
        url,
        data=data,
        headers={"Content-Type": "application/timestamp-query"},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.content


def request_timestamp_token(
    digest: bytes,
    tsa_url: str = DEFAULT_TSA_URL,
    timeout: int = 10,
    nonce: Optional[int] = None,
    poster: Optional[Callable[[str, bytes, int], bytes]] = None,
) -> Optional[str]:
    """Request an RFC 3161 timestamp token over ``digest`` from ``tsa_url``.

    Returns the base64-encoded TimeStampResp (DER) on success, or ``None`` on
    any failure (offline, TSA error, empty/malformed response). Never raises,
    so it is safe to call opportunistically from the evidence pipeline.

    ``poster`` is an injectable transport ``(url, data, timeout) -> bytes`` used
    for testing; production calls use ``requests`` via ``_http_post``.
    """
    try:
        request_der = build_timestamp_request(digest, nonce=nonce)
        post = poster or _http_post
        token = post(tsa_url, request_der, timeout)
        if not token:
            return None
        return base64.b64encode(token).decode("ascii")
    except Exception:
        return None


def make_timestamper(
    tsa_url: Optional[str] = None,
    timeout: int = 10,
    poster: Optional[Callable[[str, bytes, int], bytes]] = None,
) -> Callable[[Optional[str]], Optional[str]]:
    """Return a ``timestamper(tip_hash) -> token_b64`` callable.

    The callable timestamps ``sha256(tip_hash_ascii)`` against the configured
    TSA (argument, else ISEC_TSA_URL, else the default free TSA). It returns
    ``None`` (never raises) whenever a token cannot be obtained, so enabling
    timestamping never disrupts collection.
    """
    url = tsa_url or os.environ.get("ISEC_TSA_URL") or DEFAULT_TSA_URL

    def _timestamper(tip_hash: Optional[str]) -> Optional[str]:
        if not tip_hash:
            return None
        digest = hashlib.sha256(str(tip_hash).encode("utf-8")).digest()
        return request_timestamp_token(
            digest, tsa_url=url, timeout=timeout, poster=poster
        )

    return _timestamper
