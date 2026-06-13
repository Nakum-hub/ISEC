"""
Collector plugin framework for ISEC.

Defines a common interface (:class:`BaseCollector`) and a lightweight registry
so evidence collectors can be discovered and orchestrated uniformly instead of
being hard-wired one by one in the core orchestrator.

This module is additive and behaviour-preserving: collectors keep their
constructor signature ``(storage, actor, workstation_id, ip_address)`` and
their ``collect()`` method, so existing call sites continue to work while
collectors migrate onto the interface one at a time.
"""
from __future__ import annotations

import abc
from typing import Dict, Iterator, List, Optional, Type


class BaseCollector(abc.ABC):
    """Common base class for all evidence collectors.

    Subclasses must:
      * set the class attribute ``evidence_type`` -- the stable identifier used
        by the orchestrator's selection map and stored evidence rows; and
      * implement :meth:`collect`.

    Optional class attributes:
      * ``display_label`` -- human-readable status string shown while running.
      * ``requires_consent`` -- True if the collector gates on an explicit
        consent grant before collecting (e.g. browser history).
    """

    #: Stable identifier, e.g. "system_logs". Must be set by subclasses.
    evidence_type: str = ""
    #: Human-readable status label shown while collecting.
    display_label: str = ""
    #: Whether this collector gates on an explicit consent grant.
    requires_consent: bool = False

    def __init__(self, storage, actor, workstation_id, ip_address):
        self.storage = storage
        self.actor = actor
        self.workstation_id = workstation_id
        self.ip_address = ip_address

    @abc.abstractmethod
    def collect(self):
        """Collect evidence and persist it via ``self.storage``."""
        raise NotImplementedError

    @classmethod
    def label(cls) -> str:
        """Best-effort human-readable label for status output."""
        return cls.display_label or cls.evidence_type or cls.__name__


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_REGISTRY: Dict[str, Type[BaseCollector]] = {}


def register_collector(cls: Type[BaseCollector]) -> Type[BaseCollector]:
    """Class decorator that registers a collector by its ``evidence_type``.

    Raises ``TypeError`` if applied to a non-:class:`BaseCollector`, and
    ``ValueError`` if the collector has no ``evidence_type`` or collides with a
    different already-registered collector.
    """
    if not (isinstance(cls, type) and issubclass(cls, BaseCollector)):
        raise TypeError(f"{cls!r} is not a BaseCollector subclass")
    evidence_type = getattr(cls, "evidence_type", "") or ""
    if not evidence_type:
        raise ValueError(f"{cls.__name__} must define a non-empty evidence_type")
    existing = _REGISTRY.get(evidence_type)
    if existing is not None and existing is not cls:
        raise ValueError(
            f"evidence_type {evidence_type!r} already registered to "
            f"{existing.__name__}"
        )
    _REGISTRY[evidence_type] = cls
    return cls


def get_collector_class(evidence_type: str) -> Optional[Type[BaseCollector]]:
    """Return the registered collector class for ``evidence_type`` or None."""
    return _REGISTRY.get(evidence_type)


def registered_evidence_types() -> List[str]:
    """Return the sorted list of registered evidence-type identifiers."""
    return sorted(_REGISTRY)


def iter_collector_classes() -> Iterator[Type[BaseCollector]]:
    """Iterate registered collector classes in stable (sorted) order."""
    for evidence_type in sorted(_REGISTRY):
        yield _REGISTRY[evidence_type]
