"""CASE/UCO evidence export.

Serialize ISEC evidence records into a CASE/UCO JSON-LD bundle
(Cyber-investigation Analysis Standard Expression / Unified Cyber Ontology) so
that evidence collected by ISEC can be ingested by other forensic tooling that
speaks the CASE/UCO interchange format.

Design goals:
- **Offline & dependency-free.** Uses only the Python standard library; it never
  performs network access and adds no new pinned dependency.
- **Integrity-preserving.** Every record carries its SHA-256 record hash, HMAC
  signature, previous-record-hash link, and a live integrity-verified flag, so
  the chain of custody travels with the export.
- **Privacy-safe by default.** Decrypted evidence payloads are only embedded
  when ``include_payload=True`` is explicitly requested.
- **Deterministic.** Object ``@id`` values are derived from record ids, so two
  exports of the same database diff cleanly.

The mapping is intentionally pragmatic rather than exhaustive: each evidence
record becomes a ``uco-observable:ObservableObject`` plus a collection
``uco-action:Action`` plus a ``case-investigation:ProvenanceRecord``. Tool and
actor identities are emitted once and referenced by ``@id``.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# JSON-LD context binding the prefixes we use. The UCO/CASE IRIs are the
# canonical ontology namespaces; ``isec`` is our clearly-namespaced extension
# for chain-of-custody fields that have no exact UCO equivalent.
CASE_CONTEXT: Dict[str, str] = {
    "kb": "http://example.org/kb/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
    "uco-tool": "https://ontology.unifiedcyberontology.org/uco/tool/",
    "uco-vocabulary": "https://ontology.unifiedcyberontology.org/uco/vocabulary/",
    "case-investigation": "https://ontology.caseontology.org/case/investigation/",
    "isec": "http://ontology.internalsecurity.local/isec/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}

TOOL_ID = "kb:isec-tool"
BUNDLE_ID = "kb:isec-evidence-bundle"


def _iso_utc(value: Any) -> Optional[str]:
    """Best-effort normalization of a stored timestamp to xsd:dateTime (UTC).

    SQLite ``CURRENT_TIMESTAMP`` stores ``YYYY-MM-DD HH:MM:SS`` in UTC. We turn
    that into ISO-8601 with a ``Z`` suffix without guessing sub-second or
    timezone data we do not have.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "T" not in text and " " in text:
        text = text.replace(" ", "T", 1)
    if not text.endswith("Z") and "+" not in text and not re.search(r"[+-]\d{2}:\d{2}$", text):
        text = text + "Z"
    return text


def _slug(value: Any) -> str:
    text = str(value).strip().lower() if value else "unknown"
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "unknown"


def _clean(node: Dict[str, Any]) -> Dict[str, Any]:
    """Drop keys whose value is None so the bundle stays tidy."""
    return {key: val for key, val in node.items() if val is not None}


def _hash_node(method: str, value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    return {
        "@type": "uco-types:Hash",
        "uco-types:hashMethod": {
            "@type": "uco-vocabulary:HashNameVocab",
            "@value": method,
        },
        "uco-types:hashValue": {
            "@type": "xsd:hexBinary",
            "@value": value,
        },
    }


def _identity_node(actor: Any) -> Dict[str, Any]:
    slug = _slug(actor)
    return {
        "@id": f"kb:identity-{slug}",
        "@type": "uco-identity:Identity",
        "uco-core:hasFacet": [
            {
                "@id": f"kb:identity-{slug}-name",
                "@type": "uco-identity:SimpleNameFacet",
                "uco-identity:givenName": str(actor) if actor else "unknown",
            }
        ],
    }


def _tool_node(tool_version: str) -> Dict[str, Any]:
    return {
        "@id": TOOL_ID,
        "@type": "uco-tool:Tool",
        "uco-core:name": "ISEC - Internal Security Evidence Collector",
        "uco-tool:toolType": "Evidence Collection",
        "uco-tool:version": str(tool_version),
    }


def _observable_node(detail: Dict[str, Any], include_payload: bool) -> Dict[str, Any]:
    rec_id = detail["id"]
    size_bytes = detail.get("sizeBytes")
    hashes = [h for h in [_hash_node("SHA256", detail.get("currentRecordHash"))] if h]

    facet: Dict[str, Any] = {
        "@id": f"kb:evidence-{rec_id}-content",
        "@type": "uco-observable:ContentDataFacet",
    }
    if size_bytes is not None:
        facet["uco-observable:sizeInBytes"] = {
            "@type": "xsd:integer",
            "@value": str(size_bytes),
        }
    if hashes:
        facet["uco-observable:hash"] = hashes
    if include_payload and detail.get("data") is not None:
        facet["uco-observable:dataPayload"] = json.dumps(detail.get("data"), sort_keys=True)

    return {
        "@id": f"kb:evidence-{rec_id}",
        "@type": "uco-observable:ObservableObject",
        "isec:evidenceType": detail.get("type"),
        "uco-core:hasFacet": [facet],
    }


def _action_node(detail: Dict[str, Any]) -> Dict[str, Any]:
    rec_id = detail["id"]
    iso = _iso_utc(detail.get("timestamp"))
    actor_slug = _slug(detail.get("actor"))

    action_facet: Dict[str, Any] = {
        "@id": f"kb:action-collect-{rec_id}-facet",
        "@type": "uco-action:ActionFacet",
        "uco-action:performer": {"@id": f"kb:identity-{actor_slug}"},
        "uco-action:instrument": {"@id": TOOL_ID},
        "uco-action:result": [{"@id": f"kb:evidence-{rec_id}"}],
    }
    if iso is not None:
        action_facet["uco-action:startTime"] = {"@type": "xsd:dateTime", "@value": iso}
        action_facet["uco-action:endTime"] = {"@type": "xsd:dateTime", "@value": iso}

    return {
        "@id": f"kb:action-collect-{rec_id}",
        "@type": "uco-action:Action",
        "uco-core:name": f"Collect {detail.get('type')} evidence",
        "isec:workstationId": detail.get("workstationId"),
        "isec:ipAddress": detail.get("ipAddress"),
        "uco-core:hasFacet": [_clean(action_facet)],
    }


def _provenance_node(detail: Dict[str, Any]) -> Dict[str, Any]:
    rec_id = detail["id"]
    integrity_ok = bool(detail.get("integrityOk"))
    node: Dict[str, Any] = {
        "@id": f"kb:provenance-{rec_id}",
        "@type": "case-investigation:ProvenanceRecord",
        "uco-core:description": (
            f"Chain-of-custody provenance for evidence record {rec_id} "
            f"({detail.get('type')})."
        ),
        "case-investigation:exhibitNumber": str(rec_id),
        "uco-core:object": [{"@id": f"kb:evidence-{rec_id}"}],
        "isec:integrityVerified": {
            "@type": "xsd:boolean",
            "@value": "true" if integrity_ok else "false",
        },
        "isec:retentionStatus": detail.get("retentionStatus"),
        "isec:recordHash": _hash_node("SHA256", detail.get("currentRecordHash")),
        "isec:previousRecordHash": _hash_node("SHA256", detail.get("prevRecordHash")),
        "isec:hmacSignature": _hash_node("HMAC-SHA256", detail.get("hmacSignature")),
    }
    return _clean(node)


def build_case_bundle(
    storage,
    *,
    tool_version: str = "1.0.0",
    include_payload: bool = False,
    include_expired: bool = False,
    include_deleted: bool = False,
    created_time: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a CASE/UCO JSON-LD bundle from evidence in ``storage``.

    :param storage: an :class:`EvidenceDatabase`-like object exposing
        ``get_all_evidence`` and ``get_evidence_detail``.
    :param tool_version: version string recorded on the tool node.
    :param include_payload: when True, embed the decrypted evidence payload in
        each observable's content facet. Off by default for privacy.
    :param include_expired/include_deleted: forwarded to ``get_all_evidence``.
    :param created_time: optional ISO timestamp for the bundle creation time;
        defaults to the current UTC time.
    """
    rows = storage.get_all_evidence(
        include_expired=include_expired, include_deleted=include_deleted
    )
    # Export in insertion (id) order so the provenance chain reads naturally
    # and repeated exports are stable.
    record_ids = sorted({row[0] for row in rows})

    objects: List[Dict[str, Any]] = [_tool_node(tool_version)]
    seen_actor_slugs = set()

    for rec_id in record_ids:
        detail = storage.get_evidence_detail(rec_id)
        if not detail:
            continue

        actor_slug = _slug(detail.get("actor"))
        if actor_slug not in seen_actor_slugs:
            seen_actor_slugs.add(actor_slug)
            objects.append(_identity_node(detail.get("actor")))

        objects.append(_clean(_observable_node(detail, include_payload)))
        objects.append(_clean(_action_node(detail)))
        objects.append(_provenance_node(detail))

    bundle_created = created_time or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    return {
        "@context": CASE_CONTEXT,
        "@id": BUNDLE_ID,
        "@type": "uco-core:Bundle",
        "uco-core:name": "ISEC Evidence Export",
        "uco-core:description": (
            "CASE/UCO export of ISEC-collected evidence with chain-of-custody "
            "provenance and integrity metadata."
        ),
        "uco-core:objectCreatedTime": {
            "@type": "xsd:dateTime",
            "@value": bundle_created,
        },
        "uco-core:object": objects,
    }


def export_case_bundle(storage, output_path: str, **kwargs) -> str:
    """Build a CASE/UCO bundle and write it to ``output_path`` as JSON-LD.

    Returns the path written. Creates the parent directory if needed.
    """
    bundle = build_case_bundle(storage, **kwargs)
    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)
    return output_path
