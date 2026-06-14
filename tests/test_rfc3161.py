"""
Offline tests for the RFC 3161 trusted-timestamping client and its wiring into
transparency-log checkpoints.

No network I/O occurs: the client transport (``poster``) and the checkpoint
``timestamper`` are injected with fakes, so these tests are deterministic and
CI-safe.
"""
import base64
import hashlib

import pytest

from src.forensics import rfc3161
from src.forensics.transparency_log import TransparencyLog, checkpoint_from_database


def test_der_integer_encoding():
    assert rfc3161._der_integer(0) == b"\x02\x01\x00"
    assert rfc3161._der_integer(1) == b"\x02\x01\x01"
    # High bit set -> a leading zero byte is prepended (DER positive integer).
    assert rfc3161._der_integer(128) == b"\x02\x02\x00\x80"
    with pytest.raises(ValueError):
        rfc3161._der_integer(-1)


def test_der_length_long_form():
    # Lengths >= 0x80 use the long form: 0x81 then the length byte.
    assert rfc3161._der_len(0x7F) == b"\x7f"
    assert rfc3161._der_len(0x80) == b"\x81\x80"
    assert rfc3161._der_len(0x0102) == b"\x82\x01\x02"


def test_build_timestamp_request_structure():
    digest = hashlib.sha256(b"hello world").digest()
    req = rfc3161.build_timestamp_request(digest, nonce=0x1234)
    # Outer structure is a DER SEQUENCE.
    assert req[0] == 0x30
    # The SHA-256 algorithm OID and the digest are both embedded.
    assert rfc3161._SHA256_OID_CONTENT in req
    assert digest in req
    # certReq BOOLEAN TRUE is present (0x01 0x01 0xff).
    assert b"\x01\x01\xff" in req


def test_build_timestamp_request_rejects_bad_digest():
    with pytest.raises(ValueError):
        rfc3161.build_timestamp_request(b"too-short")
    with pytest.raises(ValueError):
        rfc3161.build_timestamp_request("not-bytes")  # type: ignore[arg-type]


def test_request_timestamp_token_with_fake_poster():
    digest = hashlib.sha256(b"data").digest()
    captured = {}

    def poster(url, data, timeout):
        captured["url"] = url
        captured["data"] = data
        captured["timeout"] = timeout
        return b"FAKE-TSR-BYTES"

    token = rfc3161.request_timestamp_token(
        digest, tsa_url="http://tsa.example", timeout=7, poster=poster
    )
    assert token == base64.b64encode(b"FAKE-TSR-BYTES").decode("ascii")
    assert captured["url"] == "http://tsa.example"
    assert captured["timeout"] == 7
    # The transport receives a DER-encoded request (SEQUENCE tag).
    assert captured["data"][0] == 0x30


def test_request_timestamp_token_is_offline_safe():
    digest = hashlib.sha256(b"data").digest()

    def boom(url, data, timeout):
        raise OSError("network down")

    # Network failure -> None, never raises.
    assert rfc3161.request_timestamp_token(digest, poster=boom) is None
    # Empty/falsy response -> None.
    assert rfc3161.request_timestamp_token(digest, poster=lambda u, d, t: b"") is None


def test_make_timestamper_returns_token_and_handles_empty_tip():
    def poster(url, data, timeout):
        return b"TSR"

    timestamper = rfc3161.make_timestamper(tsa_url="http://tsa.example", poster=poster)
    assert timestamper("deadbeef") == base64.b64encode(b"TSR").decode("ascii")
    # No tip hash -> no token requested.
    assert timestamper(None) is None
    assert timestamper("") is None


def test_checkpoint_embeds_timestamp_token(tmp_path):
    from src.storage.database import EvidenceDatabase

    storage = EvidenceDatabase(str(tmp_path / "evidence.db"))
    storage.store_evidence("system_logs", {"line": "x"}, "actor", "ws", "10.0.0.1")

    log = TransparencyLog(str(tmp_path / "ledger.jsonl"))
    record = checkpoint_from_database(
        log, storage, timestamper=lambda tip: "TOKEN-B64"
    )
    # The token is embedded in (and thus protected by) the entry core.
    assert record["entry"]["timestamp_token"] == "TOKEN-B64"
    assert log.verify()["valid"] is True


def test_checkpoint_timestamper_failure_is_safe(tmp_path):
    from src.storage.database import EvidenceDatabase

    storage = EvidenceDatabase(str(tmp_path / "evidence.db"))
    log = TransparencyLog(str(tmp_path / "ledger.jsonl"))

    def boom(tip):
        raise RuntimeError("tsa unreachable")

    record = checkpoint_from_database(log, storage, timestamper=boom)
    # No token recorded, but the checkpoint is still written and verifies.
    assert "timestamp_token" not in record["entry"]
    assert log.verify()["valid"] is True


def test_checkpoint_without_timestamper_is_unchanged(tmp_path):
    from src.storage.database import EvidenceDatabase

    storage = EvidenceDatabase(str(tmp_path / "evidence.db"))
    log = TransparencyLog(str(tmp_path / "ledger.jsonl"))

    record = checkpoint_from_database(log, storage)
    assert "timestamp_token" not in record["entry"]
    assert log.verify()["valid"] is True
