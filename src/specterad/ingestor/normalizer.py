"""Normalizer — transform raw SharpHound JSON dicts into ADNode objects.

Handles:
- ObjectIdentifier → SID format validation
- Properties extraction and name normalization
- Aces list preservation for Phase 2
- Extra relations (Members, LocalAdmins, Sessions, etc.) preservation
- IsDeleted filtering
- Timestamp normalization (Unix epoch → ISO string)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from specterad.ingestor.exceptions import IngestionError
from specterad.models.node import ADNode, META_TYPE_MAP, NodeType

logger = logging.getLogger(__name__)

# Fields that contain relationship data for Phase 2 edge building.
# These are extracted separately from Properties to keep data clean.
_RELATION_FIELDS: frozenset[str] = frozenset({
    "Members",
    "LocalAdmins",
    "RemoteDesktopUsers",
    "DcomUsers",
    "PSRemoteUsers",
    "Sessions",
    "ChildObjects",
    "Links",          # GPO links
    "AllowedToAct",
    "AllowedToDelegate",
    "HasSIDHistory",
    "SPNTargets",
    "TrustedBy",
    "Trusts",
})

# SharpHound timestamp properties stored as Unix epoch (ticks or seconds)
_TIMESTAMP_FIELDS: frozenset[str] = frozenset({
    "pwdlastset",
    "lastlogon",
    "lastlogontimestamp",
    "whencreated",
})


def _validate_sid(object_id: str | None, filename: str = "") -> str:
    """Validate that an ObjectIdentifier is present and non-empty.

    Note: We accept any non-empty string as valid since ObjectIDs can be
    SIDs (S-1-5-...), Azure ObjectIDs (GUIDs), or well-known identifiers.
    """
    if not object_id or not isinstance(object_id, str):
        raise IngestionError(
            f"Missing or invalid ObjectIdentifier in {filename}"
        )
    return object_id.strip().upper()


def _normalize_timestamps(
    properties: dict[str, Any],
) -> dict[str, Any]:
    """Convert Unix epoch timestamps to ISO 8601 strings in-place."""
    for key in _TIMESTAMP_FIELDS:
        value = properties.get(key)
        if value is None or value == -1 or value == 0:
            continue

        try:
            # SharpHound uses Windows FileTime (100-ns ticks since 1601)
            # or Unix epoch seconds — detect by magnitude
            if isinstance(value, (int, float)):
                if value > 1e16:
                    # Windows FileTime ticks → Unix timestamp
                    unix_ts = (value / 1e7) - 11644473600
                elif value > 1e12:
                    # Milliseconds
                    unix_ts = value / 1000
                else:
                    # Already seconds
                    unix_ts = value

                dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                properties[key] = dt.isoformat()
        except (OSError, OverflowError, ValueError):
            # Keep original value if conversion fails
            logger.debug("Could not convert timestamp %s=%r", key, value)

    return properties


def _extract_relations(
    raw_obj: dict[str, Any],
) -> dict[str, Any]:
    """Extract relationship fields from the raw object for Phase 2.

    Returns a dict of {relation_name: relation_data} for fields that exist.
    """
    relations: dict[str, Any] = {}
    for field_name in _RELATION_FIELDS:
        value = raw_obj.get(field_name)
        if value is not None:
            # Some fields are dicts with a Results key, others are lists
            if isinstance(value, dict) and "Results" in value:
                relations[field_name] = value["Results"]
            else:
                relations[field_name] = value
    return relations


def normalize_single_object(
    raw_obj: dict[str, Any],
    node_type: NodeType,
) -> ADNode | None:
    """Convert a single raw SharpHound dict into an ADNode.

    Args:
        raw_obj: A single element from the SharpHound ``data`` array.
        node_type: The type of node as determined from ``meta.type``.

    Returns:
        An ADNode instance, or None if the object should be skipped
        (e.g. IsDeleted=True).
    """
    # Skip deleted objects
    if raw_obj.get("IsDeleted", False):
        logger.debug("Skipping deleted object: %s", raw_obj.get("ObjectIdentifier"))
        return None

    # Extract ObjectIdentifier
    object_id = _validate_sid(raw_obj.get("ObjectIdentifier"))

    # Extract and normalize properties
    properties = dict(raw_obj.get("Properties", {}))
    properties = _normalize_timestamps(properties)

    # Get display name
    name = properties.get("name", "")
    if not name:
        # Fallback: use ObjectIdentifier if no name
        name = object_id

    # Extract ACEs
    aces = list(raw_obj.get("Aces", []))

    # Extract relationship data for Phase 2
    extra_relations = _extract_relations(raw_obj)

    return ADNode(
        object_id=object_id,
        node_type=node_type,
        name=name,
        properties=properties,
        aces=aces,
        extra_relations=extra_relations,
    )


def normalize_objects(
    raw_data: dict[str, list[dict]],
) -> dict[str, ADNode]:
    """Normalize all raw SharpHound objects into a dict of ADNode.

    This is the main entry point for Phase 1 normalization.

    Args:
        raw_data: Output from ``load_sharphound_data()`` — dict of
            {meta_type: [raw_objects]}.

    Returns:
        Dict of {object_id: ADNode} for all valid (non-deleted) objects.

    Raises:
        IngestionError: If a meta_type is unknown.
    """
    nodes: dict[str, ADNode] = {}
    skipped = 0

    for meta_type, objects in raw_data.items():
        node_type = META_TYPE_MAP.get(meta_type)
        if node_type is None:
            logger.warning(
                "Unknown meta.type '%s' — skipping %d objects",
                meta_type,
                len(objects),
            )
            continue

        for raw_obj in objects:
            node = normalize_single_object(raw_obj, node_type)
            if node is None:
                skipped += 1
                continue

            if node.object_id in nodes:
                logger.warning(
                    "Duplicate ObjectIdentifier: %s (keeping first)",
                    node.object_id,
                )
                continue

            nodes[node.object_id] = node

    logger.info(
        "Normalized %d nodes (%d skipped/deleted)", len(nodes), skipped
    )
    return nodes
