"""Azure / Entra ID ingestor — skeleton parser for AzureHound JSON data.

This module provides the foundation for ingesting AzureHound collection
data. It can detect Azure JSON files, parse their basic structure, and
route them through the standard normalizer pipeline.

NOTE: This is a SKELETON implementation. Full Azure parsing requires
real AzureHound JSON samples to validate edge derivation. The current
implementation handles node ingestion and basic relationship mapping.

AzureHound JSON structure (per-file):
    {
        "meta": {"type": "azusers", "count": N, "version": 5},
        "data": [
            {
                "ObjectIdentifier": "guid-string",
                "Properties": {...},
                "Aces": [...],           # may be absent for some types
                "MemberOf": [...],       # group memberships
                "Roles": [...],          # role assignments
                ...
            }
        ]
    }
"""

from __future__ import annotations

import logging
from typing import Any

from specterad.models.edge import EdgeType
from specterad.models.node import ADNode, NodeType

logger = logging.getLogger(__name__)

# AzureHound relationship fields → SpecterAD EdgeType mapping
_AZ_EDGE_MAP: dict[str, EdgeType] = {
    "GlobalAdmin": EdgeType.AZ_GLOBAL_ADMIN,
    "PrivilegedRoleAdmin": EdgeType.AZ_PRIVILEGED_ROLE_ADMIN,
    "Owner": EdgeType.AZ_OWNER,
    "Contributor": EdgeType.AZ_CONTRIBUTOR,
    "UserAccessAdministrator": EdgeType.AZ_USER_ACCESS_ADMIN,
    "AppAdmin": EdgeType.AZ_APP_ADMIN,
    "CloudAppAdmin": EdgeType.AZ_CLOUD_APP_ADMIN,
    "RunsAs": EdgeType.AZ_RUN_AS,
    "KeyVaultContributor": EdgeType.AZ_KEY_VAULT_CONTRIBUTOR,
    "VMAdminLogin": EdgeType.AZ_VM_ADMIN_LOGIN,
    "VMContributor": EdgeType.AZ_VM_CONTRIBUTOR,
    "AddSecret": EdgeType.AZ_ADD_SECRET,
    "ExecuteCommand": EdgeType.AZ_EXEC_COMMAND,
    "ResetPassword": EdgeType.AZ_RESET_PASSWORD,
    "AddMembers": EdgeType.AZ_ADD_MEMBERS,
    "AddOwner": EdgeType.AZ_ADD_OWNER,
    "Grant": EdgeType.AZ_GRANT_ROLE,
    "ManagedIdentity": EdgeType.AZ_MANAGED_IDENTITY,
}

# Azure meta.type prefixes that identify AzureHound data
_AZ_META_PREFIXES: frozenset[str] = frozenset({
    "aztenants",
    "azusers",
    "azgroups",
    "azapps",
    "azserviceprincipals",
    "azsubscriptions",
    "azresourcegroups",
    "azvms",
    "azkeyvaults",
    "azdevices",
    "azmanagementgroups",
    "azroles",
})


def is_azure_meta_type(meta_type: str) -> bool:
    """Check if a meta.type string belongs to AzureHound data."""
    return meta_type.lower() in _AZ_META_PREFIXES


def extract_azure_relations(raw_obj: dict[str, Any]) -> dict[str, Any]:
    """Extract Azure-specific relationship fields from a raw object.

    AzureHound uses different relationship field names than SharpHound.
    This function extracts them into a normalized dict for edge building.

    Returns:
        Dict of {relation_name: relation_data}.
    """
    _AZ_RELATION_FIELDS = {
        "Roles",            # Role assignments
        "MemberOf",         # Group memberships
        "Owners",           # Ownership relations
        "Members",          # Group members (same as AD)
        "InboundControl",   # Who can control this object
        "OutboundControl",  # What this object can control
        "RunsAs",           # Service principal identity
    }

    relations: dict[str, Any] = {}
    for field_name in _AZ_RELATION_FIELDS:
        value = raw_obj.get(field_name)
        if value is not None:
            if isinstance(value, dict) and "Results" in value:
                relations[field_name] = value["Results"]
            else:
                relations[field_name] = value

    return relations


def normalize_azure_object(
    raw_obj: dict[str, Any],
    node_type: NodeType,
) -> ADNode | None:
    """Convert a single raw AzureHound object into an ADNode.

    Azure objects use GUIDs as ObjectIdentifier instead of SIDs.

    Args:
        raw_obj: A single element from AzureHound ``data`` array.
        node_type: The Azure NodeType (e.g. AZ_USER, AZ_GROUP).

    Returns:
        An ADNode instance, or None if the object should be skipped.
    """
    object_id = raw_obj.get("ObjectIdentifier", "")
    if not object_id or not isinstance(object_id, str):
        logger.debug("Azure object missing ObjectIdentifier — skipped")
        return None

    object_id = object_id.strip().upper()

    # Extract properties
    properties = dict(raw_obj.get("Properties", {}))

    # Display name
    name = properties.get("displayname", "") or properties.get("name", "")
    if not name:
        name = object_id

    # Mark as Azure for downstream processing
    properties["_azure"] = True

    # Extract ACEs (Azure uses different ACE format but same field name)
    aces = list(raw_obj.get("Aces", []))

    # Extract Azure-specific relations
    extra_relations = extract_azure_relations(raw_obj)

    return ADNode(
        object_id=object_id,
        node_type=node_type,
        name=name,
        properties=properties,
        aces=aces,
        extra_relations=extra_relations,
    )


def build_azure_edges_skeleton(
    nodes: dict[str, ADNode],
) -> list[tuple[str, str, str]]:
    """Skeleton: derive Azure edges from parsed nodes.

    Scans Azure nodes' extra_relations for known relationship types
    and returns a list of (source, target, edge_type) tuples.

    NOTE: This is a skeleton. Real edge derivation requires AzureHound
    sample data to validate the exact JSON structure of each relation.

    Returns:
        List of (source_sid, target_sid, edge_type_value) tuples.
    """
    edges: list[tuple[str, str, str]] = []

    for sid, node in nodes.items():
        props = node.properties
        if not props.get("_azure"):
            continue

        # Roles → AZHasRole edges
        roles = node.extra_relations.get("Roles", [])
        for role in roles:
            role_id = role.get("ObjectIdentifier", "").strip().upper()
            if role_id and role_id in nodes:
                edges.append((sid, role_id, EdgeType.AZ_HAS_ROLE.value))

        # MemberOf → AZMemberOf edges
        memberships = node.extra_relations.get("MemberOf", [])
        for group in memberships:
            group_id = group.get("ObjectIdentifier", "").strip().upper()
            if group_id and group_id in nodes:
                edges.append((sid, group_id, EdgeType.AZ_MEMBER_OF.value))

        # Owners → AZOwner edges
        owners = node.extra_relations.get("Owners", [])
        for owner in owners:
            owner_id = owner.get("ObjectIdentifier", "").strip().upper()
            if owner_id and owner_id in nodes:
                edges.append((owner_id, sid, EdgeType.AZ_OWNER.value))

        # Members → AZMemberOf edges (reverse: member -> group)
        members = node.extra_relations.get("Members", [])
        for member in members:
            member_id = member.get("ObjectIdentifier", "").strip().upper()
            if member_id and member_id in nodes:
                edges.append((member_id, sid, EdgeType.AZ_MEMBER_OF.value))

        # RunsAs → AZRunsAs edges
        runs_as = node.extra_relations.get("RunsAs", [])
        for identity in runs_as:
            identity_id = identity.get("ObjectIdentifier", "").strip().upper()
            if identity_id and identity_id in nodes:
                edges.append((sid, identity_id, EdgeType.AZ_RUN_AS.value))

    logger.info(
        "Azure skeleton: derived %d edge candidates (requires validation)",
        len(edges),
    )
    return edges
