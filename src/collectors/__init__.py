"""ISEC evidence collectors package.

Importing this package registers every built-in collector with the plugin
registry defined in :mod:`src.collectors.base` (via each collector module's
``@register_collector`` decorator). The orchestrator can then construct
collectors dynamically through :func:`build_collectors` instead of importing
each collector class by hand.

Registration is idempotent: importing a collector module more than once (e.g.
through this package and via a direct ``import``) re-registers the same class
without error.
"""
from src.collectors.base import (
    BaseCollector,
    build_collectors,
    get_collector_class,
    iter_collector_classes,
    register_collector,
    registered_evidence_types,
)

# Importing each collector module triggers its @register_collector decorator as
# an import side effect. Order here matches the orchestrator's canonical
# collection order for readability; actual collection order is enforced in the
# orchestrator.
from src.collectors import system_logs  # noqa: F401
from src.collectors import browser_history  # noqa: F401
from src.collectors import network_connections  # noqa: F401
from src.collectors import file_metadata  # noqa: F401

__all__ = [
    "BaseCollector",
    "build_collectors",
    "get_collector_class",
    "iter_collector_classes",
    "register_collector",
    "registered_evidence_types",
]
