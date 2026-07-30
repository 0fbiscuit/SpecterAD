"""Remediation engine — choke point analysis and edge removal recommendations.

Analyzes the attack graph to identify:
- Busiest edges: edges that appear in the most attack paths to HVTs
- Choke points: removing which edges would cut the most attack paths
- Actionable remediation recommendations per edge
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from specterad.engine.pathfinder import Pathfinder
from specterad.models.edge import EdgeType, TRAVERSABLE_EDGES
from specterad.models.graph import ADGraph
from specterad.models.node import NodeType

logger = logging.getLogger(__name__)

# Remediation action templates keyed by edge type
_REMEDIATION_ACTIONS: dict[str, str] = {
    "GenericAll": "Remove GenericAll ACE — review if full control is actually needed",
    "GenericWrite": "Remove GenericWrite ACE — restrict to specific property writes",
    "WriteDacl": "Remove WriteDacl — prevents DACL modification on the target object",
    "WriteOwner": "Remove WriteOwner — prevents ownership takeover",
    "ForceChangePassword": "Remove ForceChangePassword — restrict password reset rights",
    "AddMember": "Remove AddMember — restrict group membership management",
    "AdminTo": "Remove local admin rights — use LAPS or dedicated admin accounts",
    "CanRDP": "Restrict RDP access — remove from Remote Desktop Users group",
    "CanPSRemote": "Restrict PSRemote — remove from Remote Management Users",
    "ExecuteDCOM": "Restrict DCOM — remove from Distributed COM Users group",
    "HasSession": "Clear session — sign out privileged user or reboot computer",
    "AllowedToDelegate": "Remove constrained delegation — use RBCD instead",
    "AllowedToAct": "Clear msDS-AllowedToActOnBehalfOfOtherIdentity attribute",
    "AddKeyCredentialLink": "Remove AddKeyCredentialLink — prevent shadow credential abuse",
    "WriteAccountRestrictions": "Remove WriteAccountRestrictions — prevents RBCD configuration",
    "ReadLAPSPassword": "Restrict LAPS read — limit to designated admin groups only",
    "DCSync": "Remove Replicating Directory Changes rights from non-DC principals",
    "MemberOf": "Review group membership — is this user/group still needed in this group?",
    "ADCSESC1": "Fix CertTemplate: disable enrollee-supplies-subject or restrict enrollment",
    "ADCSESC4": "Remove write ACEs on CertTemplate — restrict template modification",
    "CanConfigureRBCD": "Remove write rights on computer — prevents RBCD configuration",
}


@dataclass(slots=True)
class EdgeFrequency:
    """Frequency analysis for a single edge in attack paths."""

    source_sid: str
    source_name: str
    target_sid: str
    target_name: str
    edge_type: str
    path_count: int
    remediation: str


@dataclass(slots=True)
class RemediationReport:
    """Complete remediation analysis report."""

    busiest_edges: list[EdgeFrequency]
    total_paths_analyzed: int
    total_unique_edges: int


class RemediationEngine:
    """Choke point analysis and remediation recommendation engine."""

    def __init__(self, ad_graph: ADGraph, pathfinder: Pathfinder) -> None:
        self.ad_graph = ad_graph
        self._graph = ad_graph.graph
        self.pathfinder = pathfinder

    def busiest_path_ranking(
        self,
        top_n: int = 20,
        source_types: tuple[str, ...] | None = None,
    ) -> RemediationReport:
        """Find edges that appear most frequently in attack paths to HVTs.

        For each non-HVT node of the specified types, finds the shortest path
        to each HVT, then counts how often each edge appears across all paths.

        Args:
            top_n: Number of top busiest edges to return.
            source_types: Node types to use as sources.
                          Defaults to Users and Computers.

        Returns:
            RemediationReport with ranked edge frequencies.
        """
        if source_types is None:
            source_types = (NodeType.USER.value, NodeType.COMPUTER.value)

        hvt_sids = self.ad_graph.high_value_targets
        if not hvt_sids:
            logger.warning("No HVTs found — remediation analysis requires HVTs")
            return RemediationReport(
                busiest_edges=[], total_paths_analyzed=0, total_unique_edges=0,
            )

        # Collect source nodes
        source_sids: list[str] = []
        for sid, data in self._graph.nodes(data=True):
            if data.get("node_type") in source_types and sid not in hvt_sids:
                source_sids.append(sid)

        # Count edge frequency across all shortest paths
        edge_counter: Counter[tuple[str, str, str]] = Counter()
        total_paths = 0

        for src_sid in source_sids:
            for hvt_sid in hvt_sids:
                try:
                    # Use networkx shortest_path directly for speed
                    path_nodes = nx.shortest_path(
                        self.pathfinder._traversable_view, src_sid, hvt_sid
                    )
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

                total_paths += 1
                # Count each edge in the path
                for i in range(len(path_nodes) - 1):
                    u, v = path_nodes[i], path_nodes[i + 1]
                    edge_data = self._graph[u][v]
                    etype = edge_data.get("edge_type", "Unknown")
                    edge_counter[(u, v, etype)] += 1

        # Build ranked results
        busiest: list[EdgeFrequency] = []
        for (src, dst, etype), count in edge_counter.most_common(top_n):
            remediation = _REMEDIATION_ACTIONS.get(etype, f"Review {etype} edge and assess risk")
            busiest.append(EdgeFrequency(
                source_sid=src,
                source_name=self.ad_graph.display_name(src),
                target_sid=dst,
                target_name=self.ad_graph.display_name(dst),
                edge_type=etype,
                path_count=count,
                remediation=remediation,
            ))

        return RemediationReport(
            busiest_edges=busiest,
            total_paths_analyzed=total_paths,
            total_unique_edges=len(edge_counter),
        )

    def edge_removal_recommendations(
        self, top_n: int = 10,
    ) -> list[dict[str, Any]]:
        """Generate actionable edge removal recommendations.

        Wrapper around busiest_path_ranking that formats results
        as actionable recommendations with estimated impact.
        """
        report = self.busiest_path_ranking(top_n=top_n)

        recommendations: list[dict[str, Any]] = []
        for i, edge in enumerate(report.busiest_edges, 1):
            pct = (
                (edge.path_count / report.total_paths_analyzed * 100)
                if report.total_paths_analyzed > 0
                else 0
            )
            recommendations.append({
                "rank": i,
                "source": edge.source_name,
                "target": edge.target_name,
                "edge_type": edge.edge_type,
                "paths_affected": edge.path_count,
                "pct_of_all_paths": f"{pct:.1f}%",
                "action": edge.remediation,
            })

        return recommendations
