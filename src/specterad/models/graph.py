"""ADGraph wrapper — enriched graph with reverse lookup maps and utilities.

Wraps nx.DiGraph with:
- nodes_by_type: quick lookup by NodeType
- high_value_targets: set of HVT SIDs
- domain_sids: domain name → domain SID
- sid_to_name / name_to_sid: bidirectional lookup maps
- resolve(): fuzzy name/SID resolution for CLI input
- display_name(): SID → human-readable name for output
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import networkx as nx

from specterad.graph.builder import build_graph
from specterad.graph.post_process import post_process_graph
from specterad.models.edge import EdgeType
from specterad.models.node import ADNode, NodeType

logger = logging.getLogger(__name__)


@dataclass
class ADGraph:
    """Enriched Active Directory graph with lookup utilities.

    This is the primary data structure passed to Phase 3 (Pathfinding)
    and Phase 4 (CLI output).
    """

    graph: nx.DiGraph
    nodes_by_type: dict[NodeType, list[str]] = field(default_factory=dict)
    high_value_targets: set[str] = field(default_factory=set)
    domain_sids: dict[str, str] = field(default_factory=dict)

    # Reverse lookup maps
    sid_to_name: dict[str, str] = field(default_factory=dict)
    name_to_sid: dict[str, str] = field(default_factory=dict)

    def resolve(self, identifier: str) -> str | None:
        """Resolve a name or SID to a canonical SID.

        Supports:
        - Exact SID: "S-1-5-21-..." → returns as-is
        - Exact full name: "D.QUAN@LAB.LOCAL" → looks up in name_to_sid
        - Partial name: "D.QUAN" → searches for names containing this string
        - Case-insensitive matching

        Args:
            identifier: A SID string or (partial) display name.

        Returns:
            The resolved SID, or None if no match is found.
        """
        # Normalize input
        identifier = identifier.strip()
        identifier_upper = identifier.upper()

        # 1. Direct SID match
        if identifier_upper.startswith("S-1-") and identifier_upper in self.sid_to_name:
            return identifier_upper

        # 2. Exact full name match (case-insensitive)
        if identifier_upper in self.name_to_sid:
            return self.name_to_sid[identifier_upper]

        # 3. Partial name match — find names containing the input
        matches: list[tuple[str, str]] = []
        for name_upper, sid in self.name_to_sid.items():
            # Match on the part before @ (short name)
            short_name = name_upper.split("@")[0]
            if short_name == identifier_upper or identifier_upper in name_upper:
                matches.append((name_upper, sid))

        if len(matches) == 1:
            return matches[0][1]
        elif len(matches) > 1:
            logger.warning(
                "Ambiguous identifier '%s' matched %d nodes: %s",
                identifier,
                len(matches),
                ", ".join(m[0] for m in matches[:5]),
            )
            # Return first match but warn
            return matches[0][1]

        logger.warning("Could not resolve identifier: '%s'", identifier)
        return None

    def display_name(self, sid: str) -> str:
        """Get the human-readable display name for a SID.

        Falls back to the SID itself if no name is found.
        """
        return self.sid_to_name.get(sid, sid)

    def summary(self) -> dict:
        """Generate summary statistics of the graph.

        Returns a dict with counts of nodes by type, edge counts by type,
        and high-value target info.
        """
        # Node counts by type
        node_counts: dict[str, int] = {
            nt.value: len(sids) for nt, sids in self.nodes_by_type.items()
        }

        # Edge counts by type
        edge_counts: dict[str, int] = {}
        for _, _, data in self.graph.edges(data=True):
            etype = data.get("edge_type", "Unknown")
            edge_counts[etype] = edge_counts.get(etype, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "nodes_by_type": node_counts,
            "edges_by_type": edge_counts,
            "high_value_targets": len(self.high_value_targets),
            "domains": list(self.domain_sids.keys()),
        }


def create_ad_graph(nodes: dict[str, ADNode]) -> ADGraph:
    """Factory function: build a complete ADGraph from ADNode data.

    Orchestrates the full Phase 2 pipeline:
    1. Build nx.DiGraph (nodes + edges)
    2. Post-process (DCSync, ADCS, HVT marking)
    3. Build lookup maps

    Args:
        nodes: Dict of {object_id: ADNode} from Phase 1.

    Returns:
        A fully populated ADGraph ready for Phase 3.
    """
    # Step 1: Build the base graph
    graph = build_graph(nodes)

    # Step 2: Post-process (composite edges + HVT)
    hvt_sids = post_process_graph(graph, nodes)

    # Step 3: Build lookup maps
    nodes_by_type: dict[NodeType, list[str]] = {}
    sid_to_name: dict[str, str] = {}
    name_to_sid: dict[str, str] = {}
    domain_sids: dict[str, str] = {}

    for sid, node in nodes.items():
        # Nodes by type
        nodes_by_type.setdefault(node.node_type, []).append(sid)

        # Bidirectional name maps (uppercase for case-insensitive lookup)
        sid_to_name[sid] = node.name
        name_upper = node.name.upper()
        if name_upper:
            name_to_sid[name_upper] = sid

        # Domain SID map
        if node.node_type == NodeType.DOMAIN:
            domain_name = node.properties.get("name", node.name)
            if domain_name:
                domain_sids[domain_name.upper()] = sid

    ad_graph = ADGraph(
        graph=graph,
        nodes_by_type=nodes_by_type,
        high_value_targets=hvt_sids,
        domain_sids=domain_sids,
        sid_to_name=sid_to_name,
        name_to_sid=name_to_sid,
    )

    stats = ad_graph.summary()
    logger.info(
        "ADGraph created: %d nodes, %d edges, %d HVTs, domains: %s",
        stats["total_nodes"],
        stats["total_edges"],
        stats["high_value_targets"],
        stats["domains"],
    )

    return ad_graph
