"""
Tests for the collector plugin framework (src/collectors/base.py).

Verifies that the BaseCollector interface and registry work end-to-end and
that all migrated collectors register and conform to the interface.

Most tests deliberately avoid instantiating collectors with fake storage --
BrowserHistoryCollector, for example, wires up a consent manager in __init__
and needs real storage. Only FileMetadataCollector (whose __init__ has no
side effects) is instantiated with placeholders. The build_collectors test
uses a real on-disk EvidenceDatabase so every collector -- including the
consent-gated ones -- can be constructed. collect() is never invoked.
"""
import pytest

from src.collectors.base import (
    BaseCollector,
    build_collectors,
    register_collector,
    get_collector_class,
    registered_evidence_types,
    iter_collector_classes,
)

# Importing the collector modules triggers @register_collector as a side effect.
import src.collectors.file_metadata  # noqa: F401
import src.collectors.system_logs  # noqa: F401
import src.collectors.network_connections  # noqa: F401
import src.collectors.browser_history  # noqa: F401
from src.collectors.file_metadata import FileMetadataCollector
from src.collectors.system_logs import SystemLogsCollector
from src.collectors.network_connections import NetworkConnectionsCollector
from src.collectors.browser_history import BrowserHistoryCollector


# evidence_type -> (class, requires_consent, expected label)
ALL_COLLECTORS = {
    "file_metadata": (FileMetadataCollector, False, "Collecting file metadata..."),
    "system_logs": (SystemLogsCollector, False, "Collecting system logs..."),
    "network_connections": (
        NetworkConnectionsCollector,
        False,
        "Collecting network connections...",
    ),
    "browser_history": (
        BrowserHistoryCollector,
        True,
        "Collecting browser history metadata...",
    ),
}


@pytest.mark.parametrize("evidence_type", sorted(ALL_COLLECTORS))
def test_collector_is_registered(evidence_type):
    expected_cls = ALL_COLLECTORS[evidence_type][0]
    assert get_collector_class(evidence_type) is expected_cls
    assert evidence_type in registered_evidence_types()


@pytest.mark.parametrize("evidence_type", sorted(ALL_COLLECTORS))
def test_collector_conforms_to_interface(evidence_type):
    expected_cls, expected_consent, expected_label = ALL_COLLECTORS[evidence_type]
    assert issubclass(expected_cls, BaseCollector)
    assert expected_cls.evidence_type == evidence_type
    assert expected_cls.requires_consent is expected_consent
    assert expected_cls.label() == expected_label


def test_all_collectors_present_and_iterable():
    registered = set(registered_evidence_types())
    assert registered >= set(ALL_COLLECTORS)
    iterated = set(iter_collector_classes())
    for expected_cls, _, _ in ALL_COLLECTORS.values():
        assert expected_cls in iterated


def test_shared_constructor_sets_context():
    # FileMetadataCollector has a side-effect-free constructor (inherited from
    # BaseCollector), so it is safe to instantiate with placeholder values.
    inst = FileMetadataCollector("storage", "actor", "ws-1", "10.0.0.1")
    assert inst.storage == "storage"
    assert inst.actor == "actor"
    assert inst.workstation_id == "ws-1"
    assert inst.ip_address == "10.0.0.1"
    assert hasattr(inst, "collect")


def test_build_collectors_instantiates_all_with_real_storage(tmp_path):
    # build_collectors() backs the orchestrator: it constructs every registered
    # collector with the shared (storage, actor, workstation_id, ip_address)
    # signature. A real storage backend is required because consent-gated
    # collectors (browser history) wire up a consent manager in __init__.
    from src.storage.database import EvidenceDatabase

    storage = EvidenceDatabase(str(tmp_path / "evidence.db"))
    collectors = build_collectors(storage, "actor", "ws-1", "10.0.0.1")

    # Every registered collector is present and built once.
    assert set(collectors) == set(registered_evidence_types())
    assert set(collectors) >= set(ALL_COLLECTORS)

    for evidence_type, (expected_cls, _, _) in ALL_COLLECTORS.items():
        instance = collectors[evidence_type]
        assert isinstance(instance, expected_cls)
        assert isinstance(instance, BaseCollector)
        assert instance.evidence_type == evidence_type
        assert instance.storage is storage
        assert instance.actor == "actor"
        assert instance.workstation_id == "ws-1"
        assert instance.ip_address == "10.0.0.1"
        assert hasattr(instance, "collect")


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
