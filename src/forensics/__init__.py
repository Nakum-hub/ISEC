"""Forensic-soundness building blocks for ISEC (feature-flagged).

Currently provides the append-only transparency log used to detect rollback
or substitution of the evidence database over time. Importing this package
has no side effects on evidence collection.
"""
from src.forensics.transparency_log import (
    LEDGER_SCHEMA,
    TransparencyLog,
    checkpoint_from_database,
)

__all__ = [
    "LEDGER_SCHEMA",
    "TransparencyLog",
    "checkpoint_from_database",
]
