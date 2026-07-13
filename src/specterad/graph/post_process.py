"""Post-processor — derive composite edges and mark high-value targets.

Composite edges are edges that cannot be directly mapped from a single ACE
but require combining multiple conditions:

- DCSync: requires both GetChanges AND GetChangesAll on the Domain object.
- ADCS ESC1: CertTemplate with Enroll + client auth EKU + enrollee supplies subject.
- ADCS ESC3: CertTemplate with enrollment agent EKU.
- ADCS ESC4: Principal has WriteDacl/WriteOwner/GenericAll on a CertTemplate.

High-Value Targets (HVT): Domain Admins, Enterprise Admins, Administrators,
Domain Controllers, and any group with SID ending in well-known RIDs.
"""

from __future__ import annotations

import logging

import networkx as nx

from specterad.models.edge import EdgeType
from specterad.models.node import ADNode, NodeType

logger = logging.getLogger(__name__)

# Well-known SID suffixes for high-value groups
_HVT_RID_SUFFIXES: frozenset[str] = frozenset({
    "-512",   # Domain Admins
    "-519",   # Enterprise Admins
    "-544",   # Administrators (Builtin)
    "-516",   # Domain Controllers
    "-518",   # Schema Admins
    "-498",   # Enterprise Domain Controllers
    "-521",   # Read-only Domain Controllers
})

# Well-known group name patterns (case-insensitive match)
_HVT_NAME_PATTERNS: frozenset[str] = frozenset({
    "domain admins",
    "enterprise admins",
    "administrators",
    "domain controllers",
    "schema admins",
})


def derive_dcsync_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Derive DCSync composite edges.

    DCSync requires a principal to have BOTH:
    - GetChanges (DS-Replication-Get-Changes)
    - GetChangesAll (DS-Replication-Get-Changes-All)
    on a Domain object.

    We scan all Domain nodes' ACEs, group by PrincipalSID, and create
    a DCSync edge only when both rights are present.
    """
    count = 0
    domain_sids = [
        sid for sid, node in nodes.items()
        if node.node_type == NodeType.DOMAIN
    ]

    for domain_sid in domain_sids:
        domain_node = nodes[domain_sid]

        # Group ACE rights by principal
        principal_rights: dict[str, set[str]] = {}
        for ace in domain_node.aces:
            psid = ace.get("PrincipalSID", "").strip().upper()
            right = ace.get("RightName", "")
            if psid and right:
                principal_rights.setdefault(psid, set()).add(right)

        # Check for GetChanges + GetChangesAll combination
        for psid, rights in principal_rights.items():
            has_get_changes = "GetChanges" in rights
            has_get_changes_all = "GetChangesAll" in rights

            if has_get_changes and has_get_changes_all:
                if psid in graph and domain_sid in graph:
                    graph.add_edge(
                        psid,
                        domain_sid,
                        edge_type=EdgeType.DCSYNC.value,
                    )
                    count += 1
                    logger.debug(
                        "DCSync edge: %s -> %s", psid, domain_sid
                    )

    logger.info("Derived %d DCSync composite edges", count)
    return count


def derive_adcs_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Derive ADCS attack path edges (MVP: ESC1, ESC3, ESC4).

    Scans CertTemplate nodes and their ACEs to create composite edges.
    """
    count = 0
    cert_templates = {
        sid: node for sid, node in nodes.items()
        if node.node_type == NodeType.CERTTEMPLATE
    }

    if not cert_templates:
        logger.debug("No CertTemplate nodes found — skipping ADCS post-processing")
        return 0

    for ct_sid, ct_node in cert_templates.items():
        props = ct_node.properties

        # ── ESC1: Enroll + Client Auth EKU + Enrollee Supplies Subject ──
        enrollee_supplies_subject = props.get("enrolleesuppliessubject", False)

        # Check for client auth EKU
        ekus = props.get("ekus", [])
        client_auth_oids = {
            "1.3.6.1.5.5.7.3.2",     # Client Authentication
            "1.3.6.1.4.1.311.20.2.2", # Smart Card Logon
            "2.5.29.37.0",            # Any Purpose
        }
        has_client_auth = (
            not ekus  # No EKUs = SubCA = any purpose
            or any(eku in client_auth_oids for eku in ekus)
        )

        # Find principals with Enroll rights
        for ace in ct_node.aces:
            psid = ace.get("PrincipalSID", "").strip().upper()
            right = ace.get("RightName", "")

            if not psid or psid not in graph or ct_sid not in graph:
                continue

            # ESC1 check
            if (
                right in ("Enroll", "GenericAll", "AllExtendedRights")
                and enrollee_supplies_subject
                and has_client_auth
            ):
                graph.add_edge(
                    psid, ct_sid,
                    edge_type=EdgeType.ADCSESC1.value,
                )
                count += 1

            # ESC3: Enrollment Agent EKU (1.3.6.1.4.1.311.20.2.1)
            enrollment_agent_oid = "1.3.6.1.4.1.311.20.2.1"
            if (
                right in ("Enroll", "GenericAll", "AllExtendedRights")
                and enrollment_agent_oid in ekus
            ):
                graph.add_edge(
                    psid, ct_sid,
                    edge_type=EdgeType.ADCSESC3.value,
                )
                count += 1

            # ESC4: Write privileges on CertTemplate
            if right in ("WriteDacl", "WriteOwner", "GenericAll"):
                graph.add_edge(
                    psid, ct_sid,
                    edge_type=EdgeType.ADCSESC4.value,
                )
                count += 1

    logger.info("Derived %d ADCS edges (ESC1/3/4)", count)
    return count


def mark_high_value_targets(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> set[str]:
    """Identify and mark High-Value Targets in the graph.

    HVTs are nodes that represent critical assets an attacker would
    target: Domain Admins, Enterprise Admins, Domain Controllers, etc.

    Returns:
        Set of SIDs that are high-value targets.
    """
    hvt_sids: set[str] = set()

    for sid, node in nodes.items():
        is_hvt = False

        # Check by SID suffix (well-known RIDs)
        for suffix in _HVT_RID_SUFFIXES:
            if sid.endswith(suffix):
                is_hvt = True
                break

        # Check by name pattern
        if not is_hvt and node.name:
            name_lower = node.name.lower().split("@")[0]
            if name_lower in _HVT_NAME_PATTERNS:
                is_hvt = True

        # Domain Controllers (computers that are DCs)
        if not is_hvt and node.node_type == NodeType.COMPUTER:
            if node.properties.get("isdc", False):
                is_hvt = True

        if is_hvt and sid in graph:
            graph.nodes[sid]["high_value"] = True
            hvt_sids.add(sid)

    logger.info("Marked %d high-value targets", len(hvt_sids))
    return hvt_sids


def post_process_graph(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> set[str]:
    """Run all post-processing steps on the graph.

    1. Derive DCSync composite edges
    2. Derive ADCS ESC1/ESC3/ESC4 edges
    3. Mark high-value targets

    Args:
        graph: The nx.DiGraph built by build_graph().
        nodes: The original ADNode dict for property access.

    Returns:
        Set of SIDs that are high-value targets.
    """
    derive_dcsync_edges(graph, nodes)
    derive_adcs_edges(graph, nodes)
    hvt_sids = mark_high_value_targets(graph, nodes)
    return hvt_sids
