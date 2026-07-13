"""Pre-built security queries for common AD attack patterns.

Provides quick-access queries that security analysts commonly need:
- Kerberoastable users (hasspn=true)
- AS-REP Roastable users (dontreqpreauth=true)
- Unconstrained delegation computers
- DCSync principals
- Domain Admin sessions
- Shortest paths to Domain Admins
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import networkx as nx

from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import NodeType

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class QueryResult:
    """Result of a pre-built query.

    Attributes:
        query_name: Human-readable name of the query.
        description: What this query finds.
        results: List of result dicts with details for each finding.
        count: Total number of findings.
    """

    query_name: str
    description: str
    results: list[dict[str, Any]]
    count: int


class QueryEngine:
    """Pre-built query templates for common AD security analysis."""

    def __init__(self, ad_graph: ADGraph) -> None:
        self.ad_graph = ad_graph
        self._graph = ad_graph.graph

    def _get_nodes_with_property(
        self,
        node_type: NodeType,
        property_name: str,
        expected_value: Any = True,
    ) -> list[dict[str, Any]]:
        """Find nodes of a given type where a property matches expected value."""
        results: list[dict[str, Any]] = []
        sids = self.ad_graph.nodes_by_type.get(node_type, [])

        for sid in sids:
            node_data = self._graph.nodes.get(sid, {})
            if node_data.get(property_name) == expected_value:
                results.append({
                    "sid": sid,
                    "name": self.ad_graph.display_name(sid),
                    "node_type": node_type.value,
                    property_name: expected_value,
                })

        return results

    def kerberoastable_users(self) -> QueryResult:
        """Find users with SPNs set (vulnerable to Kerberoasting).

        Attack: Request TGS ticket for SPN → offline crack the hash.
        """
        results = self._get_nodes_with_property(
            NodeType.USER, "hasspn", True
        )

        return QueryResult(
            query_name="Kerberoastable Users",
            description="Users with SPNs set — vulnerable to offline TGS ticket cracking",
            results=results,
            count=len(results),
        )

    def asrep_roastable_users(self) -> QueryResult:
        """Find users that don't require Kerberos pre-authentication.

        Attack: Request AS-REP without password → offline crack the hash.
        """
        results = self._get_nodes_with_property(
            NodeType.USER, "dontreqpreauth", True
        )

        return QueryResult(
            query_name="AS-REP Roastable Users",
            description="Users not requiring Kerberos pre-auth — vulnerable to AS-REP offline cracking",
            results=results,
            count=len(results),
        )

    def unconstrained_delegation(self) -> QueryResult:
        """Find computers with unconstrained delegation enabled.

        Attack: Any user authenticating to this machine will have their
        TGT cached, allowing impersonation.
        """
        results = self._get_nodes_with_property(
            NodeType.COMPUTER, "unconstraineddelegation", True
        )

        return QueryResult(
            query_name="Unconstrained Delegation",
            description="Computers that cache TGTs of all authenticating users",
            results=results,
            count=len(results),
        )

    def dcsync_principals(self) -> QueryResult:
        """Find principals that have DCSync rights on any domain.

        Looks for edges of type DCSync from any node to a Domain node.
        """
        results: list[dict[str, Any]] = []
        domain_sids = self.ad_graph.nodes_by_type.get(NodeType.DOMAIN, [])

        for domain_sid in domain_sids:
            # Find all predecessors with DCSync edges to this domain
            for pred in self._graph.predecessors(domain_sid):
                edge_data = self._graph[pred][domain_sid]
                if edge_data.get("edge_type") == EdgeType.DCSYNC.value:
                    results.append({
                        "sid": pred,
                        "name": self.ad_graph.display_name(pred),
                        "target_domain": self.ad_graph.display_name(domain_sid),
                        "edge_type": "DCSync",
                    })

        return QueryResult(
            query_name="DCSync Principals",
            description="Principals with replication rights (GetChanges + GetChangesAll) on domain",
            results=results,
            count=len(results),
        )

    def da_sessions(self) -> QueryResult:
        """Find computers where Domain Admin has an active session.

        Attack: Compromise the computer → dump DA credentials from memory.
        """
        results: list[dict[str, Any]] = []

        # Get all DA group SIDs (RID -512)
        da_sids: set[str] = set()
        for sid in self.ad_graph.nodes_by_type.get(NodeType.GROUP, []):
            if sid.endswith("-512"):
                da_sids.add(sid)

        # Get direct members of DA groups
        da_members: set[str] = set()
        for da_sid in da_sids:
            for pred in self._graph.predecessors(da_sid):
                edge_data = self._graph[pred][da_sid]
                if edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                    da_members.add(pred)

        # Find HasSession edges: Computer → DA_User
        for comp_sid in self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, []):
            for successor in self._graph.successors(comp_sid):
                edge_data = self._graph[comp_sid][successor]
                if (
                    edge_data.get("edge_type") == EdgeType.HAS_SESSION.value
                    and successor in da_members
                ):
                    results.append({
                        "computer_sid": comp_sid,
                        "computer_name": self.ad_graph.display_name(comp_sid),
                        "user_sid": successor,
                        "user_name": self.ad_graph.display_name(successor),
                    })

        return QueryResult(
            query_name="Domain Admin Sessions",
            description="Computers with active Domain Admin sessions — credential dump targets",
            results=results,
            count=len(results),
        )

    def high_value_targets(self) -> QueryResult:
        """List all identified High-Value Targets."""
        results: list[dict[str, Any]] = []

        for sid in sorted(self.ad_graph.high_value_targets):
            node_data = self._graph.nodes.get(sid, {})
            results.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "node_type": node_data.get("node_type", "Unknown"),
            })

        return QueryResult(
            query_name="High-Value Targets",
            description="All identified high-value targets (DA, EA, DC, Schema Admins, etc.)",
            results=results,
            count=len(results),
        )

    def all_users(self) -> QueryResult:
        """List all users in the graph."""
        results = []
        for sid in sorted(self.ad_graph.nodes_by_type.get(NodeType.USER, [])):
            results.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "node_type": "User",
            })
        return QueryResult(
            query_name="All Users",
            description="All user objects identified in the graph",
            results=results,
            count=len(results),
        )

    def all_groups(self) -> QueryResult:
        """List all groups in the graph."""
        results = []
        for sid in sorted(self.ad_graph.nodes_by_type.get(NodeType.GROUP, [])):
            results.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "node_type": "Group",
            })
        return QueryResult(
            query_name="All Groups",
            description="All group objects identified in the graph",
            results=results,
            count=len(results),
        )

    def all_computers(self) -> QueryResult:
        """List all computers in the graph."""
        results = []
        for sid in sorted(self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, [])):
            results.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "node_type": "Computer",
            })
        return QueryResult(
            query_name="All Computers",
            description="All computer objects identified in the graph",
            results=results,
            count=len(results),
        )

    def run_all(self) -> list[QueryResult]:
        """Run all pre-built queries and return results."""
        return [
            self.kerberoastable_users(),
            self.asrep_roastable_users(),
            self.unconstrained_delegation(),
            self.dcsync_principals(),
            self.da_sessions(),
            self.high_value_targets(),
            self.all_users(),
            self.all_groups(),
            self.all_computers(),
        ]
