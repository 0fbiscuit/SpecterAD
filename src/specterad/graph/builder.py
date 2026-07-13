"""Graph Builder — construct nx.DiGraph from dict[str, ADNode].

Builds nodes and edges from:
1. ADNode properties → graph node attributes
2. ADNode.aces → ACL-based edges (GenericAll, WriteDacl, etc.)
3. ADNode.extra_relations → structural edges (MemberOf, AdminTo, HasSession, etc.)

Design decision: Only direct MemberOf edges are created (A→B, B→C).
Nested group chains are NOT flattened — BFS/Dijkstra in Phase 3 will
traverse intermediate nodes automatically.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from specterad.models.edge import ACE_RIGHT_TO_EDGE, EdgeType
from specterad.models.node import ADNode, NodeType

logger = logging.getLogger(__name__)


def _add_nodes(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> None:
    """Add all ADNode objects as graph nodes with their properties."""
    # Keys set explicitly — exclude from properties to avoid conflicts
    _RESERVED_KEYS = {"name", "node_type"}

    for sid, node in nodes.items():
        extra_props = {
            k: v for k, v in node.properties.items()
            if _is_serializable(v) and k not in _RESERVED_KEYS
        }
        graph.add_node(
            sid,
            node_type=node.node_type.value,
            name=node.name,
            **extra_props,
        )

    logger.info("Added %d nodes to graph", graph.number_of_nodes())


def _is_serializable(value: Any) -> bool:
    """Check if a value is safe to store as a graph node attribute."""
    return isinstance(value, (str, int, float, bool, type(None)))


def _add_ace_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create edges from ACE (Access Control Entry) data.

    For each ACE on a node:
        - PrincipalSID → source (who has the right)
        - ObjectIdentifier of the node → target (what they have rights on)
        - RightName → EdgeType

    Returns:
        Number of edges created.
    """
    count = 0
    for target_sid, node in nodes.items():
        for ace in node.aces:
            right_name = ace.get("RightName", "")
            principal_sid = ace.get("PrincipalSID", "")

            if not right_name or not principal_sid:
                continue

            # Normalize SID to uppercase (consistent with normalizer)
            principal_sid = principal_sid.strip().upper()

            # Map RightName to EdgeType
            edge_type = ACE_RIGHT_TO_EDGE.get(right_name)
            if edge_type is None:
                logger.debug(
                    "Unknown ACE RightName '%s' on %s — skipped",
                    right_name,
                    target_sid,
                )
                continue

            # Only add edge if both nodes exist in the graph
            if principal_sid not in graph or target_sid not in graph:
                logger.debug(
                    "Edge %s -[%s]-> %s skipped: node not in graph",
                    principal_sid,
                    edge_type.value,
                    target_sid,
                )
                continue

            # Avoid duplicate edges of the same type
            if graph.has_edge(principal_sid, target_sid):
                existing = graph[principal_sid][target_sid]
                if existing.get("edge_type") == edge_type.value:
                    continue

            graph.add_edge(
                principal_sid,
                target_sid,
                edge_type=edge_type.value,
            )
            count += 1

    logger.info("Added %d ACE-based edges", count)
    return count


def _add_member_of_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create MemberOf edges from Group.Members data.

    SharpHound stores membership as: Group.Members = [{ObjectIdentifier, ObjectType}]
    Edge direction: Member -[MemberOf]-> Group

    NOTE: Only direct memberships are created. Nested groups are NOT flattened.
    """
    count = 0
    for group_sid, node in nodes.items():
        if node.node_type != NodeType.GROUP:
            continue

        members = node.extra_relations.get("Members", [])
        for member in members:
            member_sid = member.get("ObjectIdentifier", "").strip().upper()
            if not member_sid:
                continue

            if member_sid not in graph or group_sid not in graph:
                continue

            graph.add_edge(
                member_sid,
                group_sid,
                edge_type=EdgeType.MEMBER_OF.value,
            )
            count += 1

    logger.info("Added %d MemberOf edges (direct only, no flattening)", count)
    return count


def _add_admin_to_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create AdminTo edges from Computer.LocalAdmins data.

    SharpHound stores: Computer.LocalAdmins = [{ObjectIdentifier, ObjectType}]
    Edge direction: Admin -[AdminTo]-> Computer
    """
    count = 0
    for comp_sid, node in nodes.items():
        if node.node_type != NodeType.COMPUTER:
            continue

        admins = node.extra_relations.get("LocalAdmins", [])
        for admin in admins:
            admin_sid = admin.get("ObjectIdentifier", "").strip().upper()
            if not admin_sid or admin_sid not in graph:
                continue

            graph.add_edge(
                admin_sid,
                comp_sid,
                edge_type=EdgeType.ADMIN_TO.value,
            )
            count += 1

    logger.info("Added %d AdminTo edges", count)
    return count


def _add_session_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create HasSession edges from Computer.Sessions data.

    Edge direction: Computer -[HasSession]-> User
    (The computer HAS a session OF the user — means user creds are in memory)
    """
    count = 0
    for comp_sid, node in nodes.items():
        if node.node_type != NodeType.COMPUTER:
            continue

        sessions = node.extra_relations.get("Sessions", [])
        for session in sessions:
            user_sid = session.get("ObjectIdentifier", "").strip().upper()
            if not user_sid or user_sid not in graph:
                continue

            graph.add_edge(
                comp_sid,
                user_sid,
                edge_type=EdgeType.HAS_SESSION.value,
            )
            count += 1

    logger.info("Added %d HasSession edges", count)
    return count


def _add_rdp_dcom_psremote_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create CanRDP, ExecuteDCOM, CanPSRemote edges from Computer relations."""
    mapping: dict[str, EdgeType] = {
        "RemoteDesktopUsers": EdgeType.CAN_RDP,
        "DcomUsers": EdgeType.EXECUTE_DCOM,
        "PSRemoteUsers": EdgeType.CAN_PS_REMOTE,
    }

    count = 0
    for comp_sid, node in nodes.items():
        if node.node_type != NodeType.COMPUTER:
            continue

        for field_name, edge_type in mapping.items():
            entries = node.extra_relations.get(field_name, [])
            for entry in entries:
                entry_sid = entry.get("ObjectIdentifier", "").strip().upper()
                if not entry_sid or entry_sid not in graph:
                    continue

                graph.add_edge(
                    entry_sid,
                    comp_sid,
                    edge_type=edge_type.value,
                )
                count += 1

    logger.info("Added %d RDP/DCOM/PSRemote edges", count)
    return count


def _add_delegation_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create AllowedToDelegate and AllowedToAct edges."""
    count = 0
    for sid, node in nodes.items():
        # AllowedToDelegate
        delegates = node.extra_relations.get("AllowedToDelegate", [])
        for target in delegates:
            target_sid = target.get("ObjectIdentifier", "").strip().upper()
            if target_sid and target_sid in graph:
                graph.add_edge(
                    sid, target_sid,
                    edge_type=EdgeType.ALLOWED_TO_DELEGATE.value,
                )
                count += 1

        # AllowedToAct (Resource-Based Constrained Delegation)
        actors = node.extra_relations.get("AllowedToAct", [])
        for actor in actors:
            actor_sid = actor.get("ObjectIdentifier", "").strip().upper()
            if actor_sid and actor_sid in graph:
                graph.add_edge(
                    actor_sid, sid,
                    edge_type=EdgeType.ALLOWED_TO_ACT.value,
                )
                count += 1

    logger.info("Added %d delegation edges", count)
    return count


def _add_sid_history_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create HasSIDHistory edges."""
    count = 0
    for sid, node in nodes.items():
        history = node.extra_relations.get("HasSIDHistory", [])
        for entry in history:
            target_sid = entry.get("ObjectIdentifier", "").strip().upper()
            if target_sid and target_sid in graph:
                graph.add_edge(
                    sid, target_sid,
                    edge_type=EdgeType.HAS_SID_HISTORY.value,
                )
                count += 1

    logger.info("Added %d HasSIDHistory edges", count)
    return count


def _add_contains_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create Contains edges from Domain/OU ChildObjects."""
    count = 0
    for sid, node in nodes.items():
        if node.node_type not in (NodeType.DOMAIN, NodeType.OU, NodeType.CONTAINER):
            continue

        children = node.extra_relations.get("ChildObjects", [])
        for child in children:
            child_sid = child.get("ObjectIdentifier", "").strip().upper()
            if child_sid and child_sid in graph:
                graph.add_edge(
                    sid, child_sid,
                    edge_type=EdgeType.CONTAINS.value,
                )
                count += 1

    logger.info("Added %d Contains edges", count)
    return count


def _add_gplink_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Create GPLink edges from OU/Domain Links."""
    count = 0
    for sid, node in nodes.items():
        links = node.extra_relations.get("Links", [])
        for link in links:
            gpo_sid = link.get("ObjectIdentifier", "").strip().upper()
            if gpo_sid and gpo_sid in graph:
                graph.add_edge(
                    gpo_sid, sid,
                    edge_type=EdgeType.GP_LINK.value,
                )
                count += 1

    logger.info("Added %d GPLink edges", count)
    return count


def build_graph(nodes: dict[str, ADNode]) -> nx.DiGraph:
    """Build a complete nx.DiGraph from parsed ADNode objects.

    This is the main entry point for Phase 2 graph construction.

    Args:
        nodes: Dict of {object_id: ADNode} from Phase 1 normalization.

    Returns:
        A NetworkX DiGraph with all nodes and edges populated.
    """
    graph = nx.DiGraph()

    # Step 1: Add all nodes
    _add_nodes(graph, nodes)

    # Step 2: Add edges from various sources
    _add_ace_edges(graph, nodes)
    _add_member_of_edges(graph, nodes)
    _add_admin_to_edges(graph, nodes)
    _add_session_edges(graph, nodes)
    _add_rdp_dcom_psremote_edges(graph, nodes)
    _add_delegation_edges(graph, nodes)
    _add_sid_history_edges(graph, nodes)
    _add_contains_edges(graph, nodes)
    _add_gplink_edges(graph, nodes)

    logger.info(
        "Graph built: %d nodes, %d edges",
        graph.number_of_nodes(),
        graph.number_of_edges(),
    )
    return graph
