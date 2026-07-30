"""Dossier engine — per-node comprehensive analysis reports.

Generates detailed reports for individual AD objects including:
- Outbound MemberOf chain (BFS forward on MemberOf edges)
- Inbound edges breakdown (AdminTo, RDP, ACL abuse counts)
- Nested group membership (recursive MemberOf)
- Auto-discovery of paths to HVTs
- Bulk AdminTo host enumeration
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from specterad.engine.pathfinder import Pathfinder
from specterad.models.edge import EdgeType, TRAVERSABLE_EDGES
from specterad.models.graph import ADGraph
from specterad.models.node import NodeType

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DossierReport:
    """Comprehensive report for a single AD object."""

    sid: str
    name: str
    node_type: str
    properties: dict[str, Any]
    group_memberships: list[dict[str, Any]]
    inbound_edges: dict[str, list[dict[str, Any]]]
    outbound_edges: dict[str, list[dict[str, Any]]]
    admin_to_hosts: list[dict[str, Any]]
    paths_to_hvt: list[Any]
    inbound_summary: dict[str, int]


class DossierEngine:
    """Per-node analysis engine for generating AD object reports."""

    def __init__(self, ad_graph: ADGraph, pathfinder: Pathfinder) -> None:
        self.ad_graph = ad_graph
        self._graph = ad_graph.graph
        self.pathfinder = pathfinder

    def _bfs_memberof_chain(self, sid: str) -> list[dict[str, Any]]:
        """BFS forward on MemberOf edges to find all group memberships (direct + nested)."""
        memberships: list[dict[str, Any]] = []
        visited: set[str] = {sid}
        queue: list[tuple[str, int]] = [(sid, 0)]

        while queue:
            current, depth = queue.pop(0)
            for succ in self._graph.successors(current):
                edge_data = self._graph[current][succ]
                if edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                    if succ not in visited:
                        visited.add(succ)
                        succ_data = self._graph.nodes.get(succ, {})
                        memberships.append({
                            "sid": succ,
                            "name": self.ad_graph.display_name(succ),
                            "type": succ_data.get("node_type", "Unknown"),
                            "depth": depth + 1,
                            "is_direct": depth == 0,
                        })
                        # Continue BFS if it's a group
                        if succ_data.get("node_type") == NodeType.GROUP.value:
                            queue.append((succ, depth + 1))

        return sorted(memberships, key=lambda x: x["depth"])

    def _get_inbound_edges(self, sid: str) -> dict[str, list[dict[str, Any]]]:
        """Get all inbound edges grouped by edge type."""
        inbound: dict[str, list[dict[str, Any]]] = {}
        for pred in self._graph.predecessors(sid):
            edge_data = self._graph[pred][sid]
            edge_type = edge_data.get("edge_type", "Unknown")
            if edge_type not in inbound:
                inbound[edge_type] = []
            inbound[edge_type].append({
                "sid": pred,
                "name": self.ad_graph.display_name(pred),
                "node_type": self._graph.nodes.get(pred, {}).get("node_type", "Unknown"),
            })
        return inbound

    def _get_outbound_edges(self, sid: str) -> dict[str, list[dict[str, Any]]]:
        """Get all outbound edges grouped by edge type."""
        outbound: dict[str, list[dict[str, Any]]] = {}
        for succ in self._graph.successors(sid):
            edge_data = self._graph[sid][succ]
            edge_type = edge_data.get("edge_type", "Unknown")
            if edge_type not in outbound:
                outbound[edge_type] = []
            outbound[edge_type].append({
                "sid": succ,
                "name": self.ad_graph.display_name(succ),
                "node_type": self._graph.nodes.get(succ, {}).get("node_type", "Unknown"),
            })
        return outbound

    def _bulk_admin_to(self, sid: str) -> list[dict[str, Any]]:
        """Find all computers the principal has AdminTo (direct or via group membership).

        BFS forward on MemberOf to collect all group SIDs the user belongs to,
        then find AdminTo edges from any of those SIDs.
        """
        # Collect all SIDs this principal effectively "is" (self + group memberships)
        effective_sids: set[str] = {sid}
        queue: list[str] = [sid]
        visited: set[str] = {sid}

        while queue:
            current = queue.pop(0)
            for succ in self._graph.successors(current):
                edge_data = self._graph[current][succ]
                if edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                    if succ not in visited:
                        visited.add(succ)
                        effective_sids.add(succ)
                        queue.append(succ)

        # Find AdminTo edges from any effective SID
        hosts: list[dict[str, Any]] = []
        seen: set[str] = set()
        for eff_sid in effective_sids:
            for succ in self._graph.successors(eff_sid):
                edge_data = self._graph[eff_sid][succ]
                if edge_data.get("edge_type") == EdgeType.ADMIN_TO.value:
                    if succ not in seen:
                        seen.add(succ)
                        hosts.append({
                            "sid": succ,
                            "name": self.ad_graph.display_name(succ),
                            "via": "direct" if eff_sid == sid
                                   else f"via {self.ad_graph.display_name(eff_sid)}",
                        })

        return sorted(hosts, key=lambda x: x["name"])

    def node_dossier(self, identifier: str) -> DossierReport:
        """Generate a comprehensive dossier for a single AD object.

        Args:
            identifier: SID, name, or partial name of the target object.

        Returns:
            DossierReport with full analysis.

        Raises:
            ValueError: If the identifier cannot be resolved.
        """
        sid = self.ad_graph.resolve(identifier)
        if sid is None:
            raise ValueError(f"Cannot resolve identifier: {identifier}")

        node_data = self._graph.nodes.get(sid, {})
        name = self.ad_graph.display_name(sid)
        node_type = node_data.get("node_type", "Unknown")

        # Extract relevant properties
        props = {
            k: v for k, v in node_data.items()
            if k not in ("name", "node_type", "high_value", "rbcd_configurable_by")
            and not k.startswith("_")
        }

        # Group memberships (MemberOf chain)
        memberships = self._bfs_memberof_chain(sid)

        # Inbound edges
        inbound = self._get_inbound_edges(sid)

        # Outbound edges
        outbound = self._get_outbound_edges(sid)

        # AdminTo hosts
        admin_hosts = self._bulk_admin_to(sid)

        # Paths to HVT (limited to avoid long computation)
        try:
            hvt_paths = self.pathfinder.paths_to_hvt(identifier, max_paths=5)
        except Exception:
            hvt_paths = []

        # Inbound summary
        inbound_summary: dict[str, int] = {}
        for etype, entries in inbound.items():
            inbound_summary[etype] = len(entries)

        return DossierReport(
            sid=sid,
            name=name,
            node_type=node_type,
            properties=props,
            group_memberships=memberships,
            inbound_edges=inbound,
            outbound_edges=outbound,
            admin_to_hosts=admin_hosts,
            paths_to_hvt=hvt_paths,
            inbound_summary=inbound_summary,
        )

    def bulk_admin_to_hosts(self, identifier: str) -> list[dict[str, Any]]:
        """Get all computers a principal has AdminTo access to.

        Convenience wrapper around _bulk_admin_to with name resolution.
        """
        sid = self.ad_graph.resolve(identifier)
        if sid is None:
            raise ValueError(f"Cannot resolve identifier: {identifier}")
        return self._bulk_admin_to(sid)
