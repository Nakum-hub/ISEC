"""
Tests for the collector plugin framework (src/collectors/base.py).

These verify that the BaseCollector interface and registry work end-to-end
and that the first migrated collector (FileMetadataCollector) is correctly
registered and conforms to the interface. No real filesystem scanning is
performed here -- collect() is intentionally not invoked.
"""
import pytest

from src.collectors.base import (
    BaseCollector,
    register_collector,
    get_collector_class,
    registered_evidence_types,
    iter_collector_classes,
    build_collectors,
)

# Importing the module triggers @register_collector as a side effect.
import src.collectors.file_metadata  # noqa: F401
from src.collectors.file_metadata import FileMetadataCollector


def test_file_metadata_is_registered():
    assert get_collector_class("file_metadata") is FileMetadataCollector
    assert "file_metadata" in registered_evidence_types()
    assert FileMetadataCollector in set(iter_collector_classes())


def test_file_metadata_conforms_to_interface():
    assert issubclass(FileMetadataCollector, BaseCollector)
    assert FileMetadataCollector.evidence_type == "file_metadata"
    assert FileMetadataCollector.requires_consent is False
    # label() falls back through display_label -> evidence_type -> class name.
    assert FileMetadataCollector.label() == "Collecting file metadata..."


def test_shared_constructor_sets_context():
    inst = FileMetadataCollector("storage", "actor", "ws-1", "10.0.0.1")
    assert inst.storage == "storage"
    assert inst.actor == "actor"
    assert inst.workstation_id == "ws-1"
    assert inst.ip_address == "10.0.0.1"
    assert hasattr(inst, "collect")


def test_build_collectors_instantiates_registered():
    collectors = build_collectors("s", "a", "w", "ip")
    assert "file_metadata" in collectors
    fm = collectors["file_metadata"]
    assert isinstance(fm, FileMetadataCollector)
    assert fm.storage == "s"
    assert fm.ip_address == "ip"


def test_registry_rejects_non_basecollector():
    with pytest.raises(TypeError):

        @register_collector
        class NotACollector:  # not a BaseCollector subclass
            evidence_type = "not_a_collector"


def test_registry_rejects_missing_evidence_type():
    with pytest.raises(ValueError):

        @register_collector
        class MissingType(BaseCollector):
            evidence_type = ""

            def collect(self):
                return None

    # The rejected class must not have polluted the registry.
    assert "" not in registered_evidence_types()
